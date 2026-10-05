package caesarlink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public Caesar Link instance.
	DefaultBaseURL = "https://link.bshk.app"

	// UnlimitedViews, as CreateOptions.Views, lets a share be opened until it expires.
	UnlimitedViews = -1

	// DefaultMaxBlobSize caps downloads when Client.MaxBlobSize is zero. It matches the
	// server's default upload limit.
	DefaultMaxBlobSize = 100 << 20

	minTTL         = time.Minute
	maxJSONBody    = 64 << 10
	maxErrorBody   = 4 << 10
	maxErrorText   = 200
	userAgent      = "caesar-link-go"
	deleteTokenHdr = "X-Delete-Token"
)

// Client talks to a Link server. All encryption happens locally: the server only ever
// receives ciphertext, the public IV and (for password shares) the scrypt parameters.
type Client struct {
	// BaseURL of the server used by Create, Info and Delete. Open ignores it and talks to
	// the host in the link itself, the way a browser would.
	BaseURL string
	// HTTPClient defaults to http.DefaultClient. Use the context for deadlines.
	HTTPClient *http.Client
	// MaxBlobSize caps how many bytes Open will download. Zero means DefaultMaxBlobSize.
	MaxBlobSize int64
}

// NewClient returns a client for the server at baseURL (e.g. DefaultBaseURL).
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL}
}

// CreateOptions controls the lifetime of a new share.
type CreateOptions struct {
	// TTL is required: at least one minute, truncated to whole seconds. The server rejects
	// anything above its configured maximum (30 days by default) with a 400.
	TTL time.Duration
	// Views is how many times the share may be opened. Zero means 1 (burn after reading);
	// UnlimitedViews removes the limit.
	Views int
	// Password, when set, wraps the key under scrypt so the link alone cannot open the
	// share. Deliver it over a separate channel.
	Password string
}

// Created is a freshly uploaded share.
type Created struct {
	ID string
	// DeleteToken revokes the share early via Client.Delete.
	DeleteToken string
	// URL is the full share link with the key in its fragment — the only copy of the key.
	// Do not log it.
	URL string
}

// Info is what the server knows about a share. Fetching it does not consume a view.
type Info struct {
	Size              int64
	ViewsLeft         *int // nil = unlimited
	ExpiresAt         time.Time
	PasswordProtected bool
}

type shareMeta struct {
	IV  string   `json:"iv"`
	KDF *KdfMeta `json:"kdf,omitempty"`
}

type metaResponse struct {
	Meta      shareMeta `json:"meta"`
	Size      int64     `json:"size"`
	ViewsLeft *int      `json:"viewsLeft"`
	ExpiresAt int64     `json:"expiresAt"` // unix milliseconds
}

// Create seals the payload locally, uploads the ciphertext and returns the share link.
func (c *Client) Create(ctx context.Context, p Payload, opts CreateOptions) (*Created, error) {
	form, err := formFields(opts)
	if err != nil {
		return nil, err
	}
	bundle, err := Seal(p, opts.Password)
	if err != nil {
		return nil, err
	}
	return c.upload(ctx, bundle, form)
}

func (c *Client) upload(ctx context.Context, bundle *Bundle, form []formField) (*Created, error) {
	meta, err := json.Marshal(shareMeta{IV: b64encode(bundle.Blob.IV), KDF: bundle.KDF})
	if err != nil {
		return nil, err
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("meta", string(meta)); err != nil {
		return nil, err
	}
	for _, f := range form {
		if err := mw.WriteField(f.name, f.value); err != nil {
			return nil, err
		}
	}
	part, err := mw.CreateFormFile("blob", "blob.bin") // application/octet-stream
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(bundle.Blob.Ciphertext); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	req, err := c.newRequest(ctx, http.MethodPost, c.BaseURL, "/api/shares", &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	var resp struct {
		ID          string `json:"id"`
		DeleteToken string `json:"deleteToken"`
	}
	if err := c.doJSON(req, &resp); err != nil {
		return nil, err
	}
	if !idPattern.MatchString(resp.ID) || resp.DeleteToken == "" {
		return nil, malformed("unexpected create response")
	}
	return &Created{
		ID:          resp.ID,
		DeleteToken: resp.DeleteToken,
		URL:         BuildURL(c.BaseURL, resp.ID, bundle.Fragment),
	}, nil
}

type formField struct{ name, value string }

// formFields builds the non-blob, non-meta form fields. Unlimited views are expressed by
// omitting `views`: the server treats a missing field as unlimited but rejects an empty one.
func formFields(opts CreateOptions) ([]formField, error) {
	if opts.TTL < minTTL {
		return nil, fmt.Errorf("caesarlink: TTL must be at least %s, got %s", minTTL, opts.TTL)
	}
	fields := []formField{{"ttl", strconv.FormatInt(int64(opts.TTL/time.Second), 10)}}
	switch {
	case opts.Views == UnlimitedViews:
	case opts.Views == 0:
		fields = append(fields, formField{"views", "1"})
	case opts.Views > 0:
		fields = append(fields, formField{"views", strconv.Itoa(opts.Views)})
	default:
		return nil, fmt.Errorf("caesarlink: Views must be positive, 0 or UnlimitedViews, got %d", opts.Views)
	}
	return fields, nil
}

// Info returns a share's metadata from Client.BaseURL. It does not consume a view.
func (c *Client) Info(ctx context.Context, id string) (*Info, error) {
	m, err := c.fetchMeta(ctx, c.BaseURL, id)
	if err != nil {
		return nil, err
	}
	return &Info{
		Size:              m.Size,
		ViewsLeft:         m.ViewsLeft,
		ExpiresAt:         time.UnixMilli(m.ExpiresAt),
		PasswordProtected: m.Meta.KDF != nil,
	}, nil
}

// Open fetches and decrypts a share link from the server named in the link.
//
// Opening **consumes a view**. Everything that can be checked without spending one is
// checked first, from the link and the (free) metadata: the fragment, the IV, the declared
// size against MaxBlobSize, and for `p.` links the password itself — verified against the
// wrapped key, so a wrong password costs nothing.
func (c *Client) Open(ctx context.Context, link, password string) (Payload, error) {
	u, err := ParseURL(link)
	if err != nil {
		return Payload{}, err
	}
	frag, err := decodeFragment(u.Fragment)
	if err != nil {
		return Payload{}, err
	}
	if frag.passwordProtected() && password == "" {
		return Payload{}, ErrPasswordRequired
	}

	m, err := c.fetchMeta(ctx, u.Base, u.ID)
	if err != nil {
		return Payload{}, err
	}
	iv, err := b64decode(m.Meta.IV)
	if err != nil {
		return Payload{}, err
	}
	if len(iv) != ivLen {
		return Payload{}, malformed("IV must be %d bytes, got %d", ivLen, len(iv))
	}
	limit := c.maxBlobSize()
	if m.Size > limit {
		return Payload{}, blobTooLarge(limit)
	}
	dek, err := resolveDEK(frag, password, m.Meta.KDF)
	if err != nil {
		return Payload{}, err
	}

	// Point of no return: the server spends a view on this request.
	ciphertext, err := c.fetchBlob(ctx, u.Base, u.ID, limit)
	if err != nil {
		return Payload{}, err
	}
	return openEnvelope(SealedBlob{Ciphertext: ciphertext, IV: iv}, dek)
}

// Delete revokes a share early using the token returned by Create.
func (c *Client) Delete(ctx context.Context, id, deleteToken string) error {
	if !idPattern.MatchString(id) {
		return malformed("bad share id %q", id)
	}
	req, err := c.newRequest(ctx, http.MethodDelete, c.BaseURL, "/api/shares/"+id, nil)
	if err != nil {
		return err
	}
	req.Header.Set(deleteTokenHdr, deleteToken)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return checkStatus(resp)
}

func (c *Client) fetchMeta(ctx context.Context, base, id string) (*metaResponse, error) {
	if !idPattern.MatchString(id) {
		return nil, malformed("bad share id %q", id)
	}
	req, err := c.newRequest(ctx, http.MethodGet, base, "/api/shares/"+id, nil)
	if err != nil {
		return nil, err
	}
	var m metaResponse
	if err := c.doJSON(req, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *Client) fetchBlob(ctx context.Context, base, id string, limit int64) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, base, "/api/shares/"+id+"/blob", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	// Read one byte past the limit to detect an oversized body, without overflowing.
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, blobTooLarge(limit)
	}
	return data, nil
}

func (c *Client) maxBlobSize() int64 {
	if c.MaxBlobSize > 0 {
		return c.MaxBlobSize
	}
	return DefaultMaxBlobSize
}

func blobTooLarge(limit int64) error {
	return fmt.Errorf("caesarlink: blob exceeds MaxBlobSize (%d bytes)", limit)
}

func (c *Client) newRequest(ctx context.Context, method, base, path string, body io.Reader) (*http.Request, error) {
	if base == "" {
		return nil, fmt.Errorf("caesarlink: empty base URL")
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return err
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody)).Decode(out); err != nil {
		return malformed("unexpected response from %s: %v", req.URL.Path, err)
	}
	return nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	return &ServerError{Status: resp.StatusCode, Body: errorMessage(resp.Header.Get("Content-Type"), raw)}
}

// errorMessage extracts something worth showing from an error body: the server's JSON
// `{"error": "…"}`, or short plain text. HTML pages (proxy 404s) are dropped.
func errorMessage(contentType string, raw []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Error != "" {
		return body.Error
	}
	text := strings.TrimSpace(string(raw))
	if strings.Contains(contentType, "html") || strings.HasPrefix(text, "<") {
		return ""
	}
	if len(text) > maxErrorText {
		text = strings.ToValidUTF8(text[:maxErrorText], "") + "…"
	}
	return text
}
