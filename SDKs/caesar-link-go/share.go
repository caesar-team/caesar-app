package caesarlink

import (
	"crypto/rand"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Bundle is a sealed share, ready to upload. Blob goes to the server, Fragment must not.
// KDF is set only for password-protected shares and must be stored server-side.
type Bundle struct {
	Blob     SealedBlob
	Fragment string
	KDF      *KdfMeta
}

// Seal generates a fresh 256-bit data key and seals the payload under it — no network.
//
// With an empty password the key is returned inline as a `k.` fragment: whoever has the link
// can read the secret. With a password the key is wrapped under a scrypt-derived KEK (`p.`
// fragment), so the link alone is useless; deliver the password over another channel.
func Seal(p Payload, password string) (*Bundle, error) {
	return seal(p, password, defaultScryptParams)
}

func seal(p Payload, password string, params scryptParams) (*Bundle, error) {
	dek := make([]byte, keyLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	blob, err := sealEnvelope(p, dek)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return &Bundle{Blob: blob, Fragment: encodeKeyFragment(dek)}, nil
	}
	frag, kdf, err := encodePasswordFragment(dek, password, params)
	if err != nil {
		return nil, err
	}
	return &Bundle{Blob: blob, Fragment: frag, KDF: kdf}, nil
}

// Unseal decrypts a blob with the key carried by fragment — no network. password and kdf
// are only needed for `p.` fragments.
func Unseal(blob SealedBlob, fragment, password string, kdf *KdfMeta) (Payload, error) {
	frag, err := decodeFragment(fragment)
	if err != nil {
		return Payload{}, err
	}
	dek, err := resolveDEK(frag, password, kdf)
	if err != nil {
		return Payload{}, err
	}
	return openEnvelope(blob, dek)
}

// ShareURL is a parsed `<base>/s/<id>#<fragment>` link.
type ShareURL struct {
	Base     string // scheme://host plus any path prefix before /s/
	ID       string
	Fragment string
}

// String rebuilds the full share URL.
func (u ShareURL) String() string {
	return BuildURL(u.Base, u.ID, u.Fragment)
}

// BuildURL returns `<base>/s/<id>#<fragment>`.
func BuildURL(base, id, fragment string) string {
	return strings.TrimSuffix(base, "/") + "/s/" + id + "#" + fragment
}

// Server IDs are nanoids. Rejecting anything else keeps a crafted link from steering
// requests to other paths (`..`, `?`, `/`).
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ParseURL splits a share link into base, id and fragment. The fragment may be empty — that
// is enough for Info or Delete — but Open rejects such a link: nothing to decrypt with.
//
// Errors never quote the link: its fragment is the decryption key.
func ParseURL(raw string) (ShareURL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // drop the echoed URL, keep the cause
		}
		return ShareURL{}, malformed("not a URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ShareURL{}, malformed("share URL must be http(s), got %q", u.Scheme)
	}
	// The id is the last segment, right after the last `/s/`, so a base path may itself
	// contain an `s` segment. The escaped path, like the TS SDK's URL.pathname, keeps an
	// encoded `/` inside the id, where the id check then rejects it.
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	cut := strings.LastIndex(path, "/s/")
	if cut == -1 || cut+len("/s/") == len(path) {
		return ShareURL{}, malformed("share URL has no /s/<id> path")
	}
	id := path[cut+len("/s/"):]
	if !idPattern.MatchString(id) {
		// Not quoted: with an encoded `#` (`abc%23k.<key>`) the "id" carries the key.
		return ShareURL{}, malformed("share id has unexpected characters")
	}
	return ShareURL{Base: u.Scheme + "://" + u.Host + path[:cut], ID: id, Fragment: u.Fragment}, nil
}
