package caesarlink

import (
	"crypto/rand"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

type Bundle struct {
	Blob     SealedBlob
	Fragment string
	KDF      *KdfMeta
}

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

type ShareURL struct {
	Base     string
	ID       string
	Fragment string
}

func (u ShareURL) String() string {
	return BuildURL(u.Base, u.ID, u.Fragment)
}

func BuildURL(base, id, fragment string) string {
	return strings.TrimSuffix(base, "/") + "/s/" + id + "#" + fragment
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func ParseURL(raw string) (ShareURL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return ShareURL{}, malformed("not a URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ShareURL{}, malformed("share URL must be http(s), got %q", u.Scheme)
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	cut := strings.LastIndex(path, "/s/")
	if cut == -1 || cut+len("/s/") == len(path) {
		return ShareURL{}, malformed("share URL has no /s/<id> path")
	}
	id := path[cut+len("/s/"):]
	if !idPattern.MatchString(id) {
		return ShareURL{}, malformed("share id has unexpected characters")
	}
	return ShareURL{Base: u.Scheme + "://" + u.Host + path[:cut], ID: id, Fragment: u.Fragment}, nil
}
