package caesarlink

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrPasswordRequired = errors.New("caesarlink: share is password-protected, a password is required")

	ErrWrongPassword = errors.New("caesarlink: wrong password or corrupted link")

	ErrMissingKdf = errors.New("caesarlink: password share has no KDF metadata")

	ErrDecryptionFailed = errors.New("caesarlink: decryption failed (wrong key or tampered ciphertext)")

	ErrNotFound = errors.New("caesarlink: share not found, expired or already viewed")

	ErrMalformed = errors.New("caesarlink: malformed")
)

type UnsupportedVersionError struct {
	Version int
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("caesarlink: unsupported envelope version %d", e.Version)
}

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
