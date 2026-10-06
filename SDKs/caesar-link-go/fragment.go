package caesarlink

import (
	"crypto/rand"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	saltLen        = 16
	wrappedLen     = ivLen + keyLen + tagLen
	maxScryptN     = 1 << 20
	maxScryptMem   = 1 << 30
	defaultScryptN = 1 << 17
)

type KdfMeta struct {
	KDF   string `json:"kdf"`
	Salt  string `json:"salt"`
	N     int    `json:"N"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dkLen"`
}

type scryptParams struct{ N, R, P int }

var defaultScryptParams = scryptParams{N: defaultScryptN, R: 8, P: 1}

func (k *KdfMeta) validate() error {
	switch {
	case k.KDF != "scrypt":
		return malformed("unsupported KDF %q", k.KDF)
	case k.DKLen != keyLen:
		return malformed("unsupported scrypt dkLen %d", k.DKLen)
	case k.N < 2 || k.N > maxScryptN || k.N&(k.N-1) != 0:
		return malformed("scrypt N out of bounds: %d", k.N)
	case k.R < 1 || k.R > 32:
		return malformed("scrypt r out of bounds: %d", k.R)
	case k.P < 1 || k.P > 16:
		return malformed("scrypt p out of bounds: %d", k.P)
	case 128*k.N*k.R > maxScryptMem:
		return malformed("scrypt cost too high: N=%d r=%d", k.N, k.R)
	}
	return nil
}

func deriveKEK(password string, kdf *KdfMeta) ([]byte, error) {
	if err := kdf.validate(); err != nil {
		return nil, err
	}
	salt, err := b64decode(kdf.Salt)
	if err != nil {
		return nil, err
	}
	if len(salt) < saltLen {
		return nil, malformed("scrypt salt must be at least %d bytes", saltLen)
	}
	return scrypt.Key([]byte(password), salt, kdf.N, kdf.R, kdf.P, kdf.DKLen)
}

type fragment struct {
	dek     []byte
	wrapped []byte
}

func (f fragment) passwordProtected() bool { return f.wrapped != nil }

func decodeFragment(s string) (fragment, error) {
	mode, body, ok := strings.Cut(s, ".")
	if !ok {
		return fragment{}, malformed("fragment has no mode prefix")
	}
	raw, err := b64decode(body)
	if err != nil {
		return fragment{}, err
	}
	switch mode {
	case "k":
		if len(raw) != keyLen {
			return fragment{}, malformed("bad DEK length %d", len(raw))
		}
		return fragment{dek: raw}, nil
	case "p":
		if len(raw) != wrappedLen {
			return fragment{}, malformed("bad wrapped DEK length %d", len(raw))
		}
		return fragment{wrapped: raw}, nil
	default:
		return fragment{}, malformed("unknown fragment mode %q", mode)
	}
}

func encodeKeyFragment(dek []byte) string {
	return "k." + b64encode(dek)
}

func encodePasswordFragment(dek []byte, password string, params scryptParams) (string, *KdfMeta, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", nil, err
	}
	kdf := &KdfMeta{KDF: "scrypt", Salt: b64encode(salt), N: params.N, R: params.R, P: params.P, DKLen: keyLen}
	kek, err := deriveKEK(password, kdf)
	if err != nil {
		return "", nil, err
	}
	iv, wrapped, err := gcmSeal(kek, dek)
	if err != nil {
		return "", nil, err
	}
	return "p." + b64encode(append(iv, wrapped...)), kdf, nil
}

func unwrapPasswordFragment(wrapped []byte, password string, kdf *KdfMeta) ([]byte, error) {
	kek, err := deriveKEK(password, kdf)
	if err != nil {
		return nil, err
	}
	dek, err := gcmOpen(kek, wrapped[:ivLen], wrapped[ivLen:])
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

func resolveDEK(f fragment, password string, kdf *KdfMeta) ([]byte, error) {
	if !f.passwordProtected() {
		return f.dek, nil
	}
	if password == "" {
		return nil, ErrPasswordRequired
	}
	if kdf == nil {
		return nil, ErrMissingKdf
	}
	return unwrapPasswordFragment(f.wrapped, password, kdf)
}
