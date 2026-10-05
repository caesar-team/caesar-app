package caesarlink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeServer struct {
	mu        sync.Mutex
	shares    map[string]*fakeShare
	next      int
	blobReads int
	requests  int
}

type fakeShare struct {
	blob      []byte
	meta      json.RawMessage
	viewsLeft *int
	expiresAt int64
	token     string
	fakeSize  *int
}

func newFakeServer(t *testing.T) (*fakeServer, *httptest.Server) {
	fs := &fakeServer{shares: map[string]*fakeShare{}}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	return fs, srv
}

func (fs *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.requests++

	notFound := func() { http.Error(w, `{"error":"Not found"}`, http.StatusNotFound) }
	bad := func(msg string) { http.Error(w, `{"error":"`+msg+`"}`, http.StatusBadRequest) }

	path := strings.TrimPrefix(r.URL.Path, "/api/shares")
	switch {
	case r.Method == http.MethodPost && path == "":
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			bad("bad form")
			return
		}
		file, _, err := r.FormFile("blob")
		if err != nil {
			bad("Missing or invalid blob")
			return
		}
		blob, _ := io.ReadAll(file)
		meta := r.FormValue("meta")
		if !json.Valid([]byte(meta)) {
			bad("meta must be valid JSON")
			return
		}
		ttl, err := strconv.Atoi(r.FormValue("ttl"))
		if err != nil || ttl < 60 || ttl > 30*24*3600 {
			bad("ttl out of range")
			return
		}
		share := &fakeShare{blob: blob, meta: json.RawMessage(meta), expiresAt: time.Now().Add(time.Duration(ttl) * time.Second).UnixMilli()}
		if raw, present := r.MultipartForm.Value["views"]; present {
			v, err := strconv.Atoi(raw[0])
			if err != nil || v <= 0 || strconv.Itoa(v) != raw[0] {
				bad("views must be a positive integer")
				return
			}
			share.viewsLeft = &v
		}
		fs.next++
		id := fmt.Sprintf("id%d", fs.next)
		share.token = "tok-" + id
		fs.shares[id] = share
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": id, "deleteToken": share.token})

	case r.Method == http.MethodGet && strings.HasSuffix(path, "/blob"):
		fs.blobReads++
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/blob")
		share, ok := fs.shares[id]
		if !ok {
			notFound()
			return
		}
		if share.viewsLeft != nil {
			*share.viewsLeft--
			if *share.viewsLeft == 0 {
				delete(fs.shares, id)
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(share.blob)

	case r.Method == http.MethodGet:
		share, ok := fs.shares[strings.TrimPrefix(path, "/")]
		if !ok {
			notFound()
			return
		}
		size := len(share.blob)
		if share.fakeSize != nil {
			size = *share.fakeSize
		}
		json.NewEncoder(w).Encode(map[string]any{
			"meta": share.meta, "size": size, "viewsLeft": share.viewsLeft, "expiresAt": share.expiresAt,
		})

	case r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/")
		share, ok := fs.shares[id]
		if !ok || r.Header.Get("X-Delete-Token") != share.token {
			notFound()
			return
		}
		delete(fs.shares, id)
		w.WriteHeader(http.StatusNoContent)

	default:
		notFound()
	}
}

func (fs *fakeServer) counts() (requests, blobReads int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.requests, fs.blobReads
}

func TestClientBurnAfterReading(t *testing.T) {
	_, srv := newFakeServer(t)
	c := NewClient(srv.URL)
	ctx := context.Background()

	created, err := c.Create(ctx, TextPayload("top secret"), CreateOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.URL, srv.URL+"/s/"+created.ID+"#k.") {
		t.Fatalf("URL = %s", created.URL)
	}

	info, err := c.Info(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.ViewsLeft == nil || *info.ViewsLeft != 1 || info.PasswordProtected || info.Size == 0 {
		t.Fatalf("info = %+v", info)
	}
	if until := time.Until(info.ExpiresAt); until < 59*time.Minute || until > time.Hour {
		t.Fatalf("expiresAt %v is not ~1h away", info.ExpiresAt)
	}

	got, err := c.Open(ctx, created.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Text) != "top secret" {
		t.Fatalf("text = %q", got.Text)
	}
	if _, err := c.Open(ctx, created.URL, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second open: err = %v, want ErrNotFound", err)
	}
}

func TestClientUnlimitedViewsAndDelete(t *testing.T) {
	_, srv := newFakeServer(t)
	c := NewClient(srv.URL + "/")
	ctx := context.Background()

	files := FilePayload(File{Name: "a.txt", MIME: "text/plain", Data: []byte("a")})
	created, err := c.Create(ctx, files, CreateOptions{TTL: time.Hour, Views: UnlimitedViews})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := c.Info(ctx, created.ID); err != nil || info.ViewsLeft != nil {
		t.Fatalf("info = %+v, %v; want unlimited", info, err)
	}
	for i := 0; i < 3; i++ {
		got, err := c.Open(ctx, created.URL, "")
		if err != nil || len(got.Files) != 1 || string(got.Files[0].Data) != "a" {
			t.Fatalf("open #%d = %+v, %v", i, got, err)
		}
	}

	if err := c.Delete(ctx, created.ID, "wrong"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete with wrong token: err = %v, want ErrNotFound", err)
	}
	if err := c.Delete(ctx, created.ID, created.DeleteToken); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ctx, created.URL, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open after delete: err = %v, want ErrNotFound", err)
	}
}

func TestClientPasswordDoesNotWasteViews(t *testing.T) {
	fs, srv := newFakeServer(t)
	c := NewClient(srv.URL)
	ctx := context.Background()

	created, err := c.Create(ctx, TextPayload("guarded"), CreateOptions{TTL: time.Hour, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(created.URL, "#p.") {
		t.Fatalf("URL = %s, want a p. fragment", created.URL)
	}
	if info, _ := c.Info(ctx, created.ID); !info.PasswordProtected {
		t.Fatal("info does not report password protection")
	}

	before, _ := fs.counts()
	if _, err := c.Open(ctx, created.URL, ""); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("no password: err = %v", err)
	}
	if after, _ := fs.counts(); after != before {
		t.Fatal("missing password must fail before any request")
	}

	if _, err := c.Open(ctx, created.URL, "nope"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: err = %v", err)
	}
	if _, reads := fs.counts(); reads != 0 {
		t.Fatalf("wrong password downloaded the blob %d time(s)", reads)
	}

	got, err := c.Open(ctx, created.URL, "pw")
	if err != nil || string(got.Text) != "guarded" {
		t.Fatalf("open = %q, %v", got.Text, err)
	}
}

func TestClientServerErrors(t *testing.T) {
	_, srv := newFakeServer(t)
	c := NewClient(srv.URL)
	ctx := context.Background()

	_, err := c.Create(ctx, TextPayload("x"), CreateOptions{TTL: 31 * 24 * time.Hour})
	var serr *ServerError
	if !errors.As(err, &serr) || serr.Status != http.StatusBadRequest || serr.Body != "ttl out of range" {
		t.Fatalf("err = %v, want 400 ttl out of range", err)
	}
	if _, err := c.Info(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := c.Info(ctx, "../etc"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed for a hostile id", err)
	}
}

func TestErrorMessage(t *testing.T) {
	long := strings.Repeat("x", 500)
	cases := []struct{ contentType, body, want string }{
		{"application/json", `{"error":"Not found"}`, "Not found"},
		{"text/plain", `{"error":"ttl out of range"}`, "ttl out of range"},
		{"text/html", "<!DOCTYPE html><h1>404</h1>", ""},
		{"", "\n  <html>oops</html>", ""},
		{"text/plain", "  bad gateway \n", "bad gateway"},
		{"text/plain", long, long[:maxErrorText] + "…"},
	}
	for _, c := range cases {
		if got := errorMessage(c.contentType, []byte(c.body)); got != c.want {
			t.Errorf("errorMessage(%q, %.30q) = %q, want %q", c.contentType, c.body, got, c.want)
		}
	}
	if got := (&ServerError{Status: 404}).Error(); got != "caesarlink: server returned 404 (share not found, expired or already viewed)" {
		t.Errorf("404 message = %q", got)
	}
}

func TestClientMaxBlobSizeDoesNotWasteView(t *testing.T) {
	fs, srv := newFakeServer(t)
	c := NewClient(srv.URL)
	ctx := context.Background()

	created, err := c.Create(ctx, TextPayload(strings.Repeat("x", 4096)), CreateOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	c.MaxBlobSize = 1024
	if _, err := c.Open(ctx, created.URL, ""); err == nil || !strings.Contains(err.Error(), "MaxBlobSize") {
		t.Fatalf("err = %v, want MaxBlobSize error", err)
	}
	if _, reads := fs.counts(); reads != 0 {
		t.Fatalf("oversized share was downloaded %d time(s)", reads)
	}

	c.MaxBlobSize = math.MaxInt64
	if got, err := c.Open(ctx, created.URL, ""); err != nil || len(got.Text) != 4096 {
		t.Fatalf("open with MaxInt64 limit = %d bytes, %v", len(got.Text), err)
	}
}

func TestClientBlobLargerThanDeclared(t *testing.T) {
	fs, srv := newFakeServer(t)
	c := NewClient(srv.URL)
	ctx := context.Background()

	created, err := c.Create(ctx, TextPayload("x"), CreateOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	small := 10
	fs.shares[created.ID].blob = make([]byte, 4096)
	fs.shares[created.ID].fakeSize = &small
	fs.mu.Unlock()
	c.MaxBlobSize = 1024
	if _, err := c.Open(ctx, created.URL, ""); err == nil || !strings.Contains(err.Error(), "MaxBlobSize") {
		t.Fatalf("err = %v, want MaxBlobSize error", err)
	}
	if _, reads := fs.counts(); reads != 1 {
		t.Fatalf("blob reads = %d, want 1 (the body cutoff path)", reads)
	}
}

func TestClientBadIVDoesNotWasteView(t *testing.T) {
	fs, srv := newFakeServer(t)
	c := NewClient(srv.URL)
	ctx := context.Background()

	created, err := c.Create(ctx, TextPayload("x"), CreateOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	fs.shares[created.ID].meta = json.RawMessage(`{"iv":"` + b64encode(make([]byte, 8)) + `"}`)
	fs.mu.Unlock()
	if _, err := c.Open(ctx, created.URL, ""); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if _, reads := fs.counts(); reads != 0 {
		t.Fatalf("bad IV share was downloaded %d time(s)", reads)
	}
}

func TestClientOpenUsesTheLinkHost(t *testing.T) {
	_, srv := newFakeServer(t)
	created, err := NewClient(srv.URL).Create(context.Background(), TextPayload("x"), CreateOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient("http://127.0.0.1:1").Open(context.Background(), created.URL, ""); err != nil {
		t.Fatal(err)
	}
}
