package caesarlink

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var vectorsPath = filepath.Join("..", "..", "packages", "link-sdk", "vectors", "v2.json")

type vectorFile struct {
	Version int      `json:"version"`
	Vectors []vector `json:"vectors"`
}

type vector struct {
	Name     string   `json:"name"`
	Password *string  `json:"password"`
	Fragment string   `json:"fragment"`
	KDF      *KdfMeta `json:"kdf"`
	Blob     struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
	} `json:"blob"`
	Expected struct {
		Type  string     `json:"type"`
		Data  string     `json:"data"`
		Files []wireFile `json:"files"`
	} `json:"expected"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if vf.Version != EnvelopeVersion {
		t.Fatalf("vectors are v%d, SDK speaks v%d", vf.Version, EnvelopeVersion)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return vf.Vectors
}

func (v vector) blob(t *testing.T) SealedBlob {
	t.Helper()
	ct, err := b64decode(v.Blob.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := b64decode(v.Blob.IV)
	if err != nil {
		t.Fatal(err)
	}
	return SealedBlob{Ciphertext: ct, IV: iv}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectorsOpen(t *testing.T) {
	sawPassword := false
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			password := ""
			if v.Password != nil {
				password = *v.Password
				sawPassword = true
			}
			got, err := Unseal(v.blob(t), v.Fragment, password, v.KDF)
			if err != nil {
				t.Fatalf("Unseal: %v", err)
			}
			if string(got.Type) != v.Expected.Type {
				t.Fatalf("type = %q, want %q", got.Type, v.Expected.Type)
			}
			switch got.Type {
			case TypeText:
				if want := mustB64(t, v.Expected.Data); !bytes.Equal(got.Text, want) {
					t.Fatalf("text = %q, want %q", got.Text, want)
				}
			case TypeFile:
				if len(got.Files) != len(v.Expected.Files) {
					t.Fatalf("got %d files, want %d", len(got.Files), len(v.Expected.Files))
				}
				for i, want := range v.Expected.Files {
					f := got.Files[i]
					if f.Name != want.Name || f.MIME != want.Mime || !bytes.Equal(f.Data, mustB64(t, want.Data)) {
						t.Fatalf("file %d = %+v, want %+v", i, f, want)
					}
				}
			}
		})
	}
	if !sawPassword {
		t.Fatal("vector set has no password vector; scrypt compatibility is unproven")
	}
}

func TestVectorsPasswordFailures(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.Password == nil {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			if _, err := Unseal(v.blob(t), v.Fragment, "", v.KDF); !errors.Is(err, ErrPasswordRequired) {
				t.Fatalf("no password: err = %v, want ErrPasswordRequired", err)
			}
			if _, err := Unseal(v.blob(t), v.Fragment, *v.Password, nil); !errors.Is(err, ErrMissingKdf) {
				t.Fatalf("no kdf: err = %v, want ErrMissingKdf", err)
			}
			if _, err := Unseal(v.blob(t), v.Fragment, "wrong-"+*v.Password, v.KDF); !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("wrong password: err = %v, want ErrWrongPassword", err)
			}
		})
	}
}

func TestVectorsWrongKey(t *testing.T) {
	vs := loadVectors(t)
	var keyed []vector
	for _, v := range vs {
		if v.Password == nil {
			keyed = append(keyed, v)
		}
	}
	if len(keyed) < 2 {
		t.Skip("need two link-only vectors")
	}
	if _, err := Unseal(keyed[0].blob(t), keyed[1].Fragment, "", nil); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("err = %v, want ErrDecryptionFailed", err)
	}
}
