package caesarlink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const EnvelopeVersion = 2

const (
	keyLen = 32
	ivLen  = 12
	tagLen = 16
)

type PayloadType string

const (
	TypeText PayloadType = "text"
	TypeFile PayloadType = "file"
)

type File struct {
	Name string
	MIME string
	Data []byte
}

type Payload struct {
	Type  PayloadType
	Text  []byte
	Files []File
}

func TextPayload(text string) Payload {
	return Payload{Type: TypeText, Text: []byte(text)}
}

func FilePayload(files ...File) Payload {
	return Payload{Type: TypeFile, Files: files}
}

type SealedBlob struct {
	Ciphertext []byte
	IV         []byte
}

type wireFile struct {
	Name string `json:"name"`
	Mime string `json:"mime"`
	Data string `json:"data"`
}

type wireEnvelope struct {
	V     int        `json:"v"`
	Type  string     `json:"type"`
	Data  *string    `json:"data,omitempty"`
	Files []wireFile `json:"files,omitempty"`
}

func sealEnvelope(p Payload, dek []byte) (SealedBlob, error) {
	wire := wireEnvelope{V: EnvelopeVersion, Type: string(p.Type)}
	switch p.Type {
	case TypeText:
		data := b64encode(p.Text)
		wire.Data = &data
	case TypeFile:
		if len(p.Files) == 0 {
			return SealedBlob{}, malformed("file payload has no files")
		}
		wire.Files = make([]wireFile, len(p.Files))
		for i, f := range p.Files {
			wire.Files[i] = wireFile{Name: f.Name, Mime: f.MIME, Data: b64encode(f.Data)}
		}
	default:
		return SealedBlob{}, malformed("unknown payload type %q", p.Type)
	}

	plaintext, err := json.Marshal(wire)
	if err != nil {
		return SealedBlob{}, err
	}
	iv, ciphertext, err := gcmSeal(dek, plaintext)
	if err != nil {
		return SealedBlob{}, err
	}
	return SealedBlob{Ciphertext: ciphertext, IV: iv}, nil
}

func openEnvelope(blob SealedBlob, dek []byte) (Payload, error) {
	if len(blob.IV) != ivLen {
		return Payload{}, malformed("IV must be %d bytes, got %d", ivLen, len(blob.IV))
	}
	if len(blob.Ciphertext) <= tagLen {
		return Payload{}, malformed("ciphertext shorter than the GCM tag")
	}
	plaintext, err := gcmOpen(dek, blob.IV, blob.Ciphertext)
	if err != nil {
		return Payload{}, ErrDecryptionFailed
	}

	var wire wireEnvelope
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		return Payload{}, malformed("envelope is not valid JSON")
	}
	if wire.V != EnvelopeVersion {
		return Payload{}, &UnsupportedVersionError{Version: wire.V}
	}

	switch PayloadType(wire.Type) {
	case TypeText:
		if wire.Data == nil {
			return Payload{}, malformed("text envelope has no data field")
		}
		text, err := b64decode(*wire.Data)
		if err != nil {
			return Payload{}, err
		}
		return Payload{Type: TypeText, Text: text}, nil
	case TypeFile:
		if wire.Files == nil {
			return Payload{}, malformed("file envelope has no files field")
		}
		files := make([]File, len(wire.Files))
		for i, f := range wire.Files {
			data, err := b64decode(f.Data)
			if err != nil {
				return Payload{}, err
			}
			files[i] = File{Name: f.Name, MIME: f.Mime, Data: data}
		}
		return Payload{Type: TypeFile, Files: files}, nil
	default:
		return Payload{}, malformed("unknown envelope type %q", wire.Type)
	}
}

func gcmSeal(key, plaintext []byte) (iv, ciphertext []byte, err error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	iv = make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	return iv, aead.Seal(nil, iv, plaintext, nil), nil
}

func gcmOpen(key, iv, ciphertext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, iv, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func b64encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64decode(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, malformed("bad base64url: %v", err)
	}
	return b, nil
}
