package caesarlink

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrPasswordRequired: a password-protected (`p.`) link was opened without a password.
	// Returned before the blob is fetched, so no view is spent.
	ErrPasswordRequired = errors.New("caesarlink: share is password-protected, a password is required")

	// ErrWrongPassword: the password did not unwrap the data key. Indistinguishable from a
	// corrupted `p.` fragment by design.
	ErrWrongPassword = errors.New("caesarlink: wrong password or corrupted link")

	// ErrMissingKdf: a password share arrived without server-side KDF metadata.
	ErrMissingKdf = errors.New("caesarlink: password share has no KDF metadata")

	// ErrDecryptionFailed: wrong key, or the ciphertext was tampered with.
	ErrDecryptionFailed = errors.New("caesarlink: decryption failed (wrong key or tampered ciphertext)")

	// ErrNotFound: the share never existed, expired, ran out of views or was revoked. The
	// server deliberately does not tell these apart.
	ErrNotFound = errors.New("caesarlink: share not found, expired or already viewed")

	// ErrMalformed wraps every parse/validation failure: bad base64url, bad fragment,
	// hostile KDF parameters, unexpected JSON.
	ErrMalformed = errors.New("caesarlink: malformed")
)

// UnsupportedVersionError: the envelope comes from a protocol revision this SDK does not know.
type UnsupportedVersionError struct {
	Version int
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("caesarlink: unsupported envelope version %d", e.Version)
}

// ServerError is any non-2xx response from the Link server. A 404 also matches ErrNotFound
// via errors.Is. Body is the server's `error` message when it sent JSON; HTML error pages
// from proxies in front of the server are dropped.
type ServerError struct {
	Status int
	Body   string
}

func (e *ServerError) Error() string {
	msg := fmt.Sprintf("caesarlink: server returned %d", e.Status)
	if e.Status == http.StatusNotFound {
		msg += " (share not found, expired or already viewed)"
	}
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

func (e *ServerError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}
