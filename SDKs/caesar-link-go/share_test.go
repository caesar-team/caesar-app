package caesarlink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var fastScrypt = scryptParams{N: 1 << 10, R: 8, P: 1}

func TestSealUnsealRoundTrip(t *testing.T) {
	cases := map[string]Payload{
		"text":    TextPayload("hello link"),
		"unicode": TextPayload("привет 🔐"),
		"empty":   TextPayload(""),
		"files": FilePayload(
			File{Name: "one.txt", MIME: "text/plain", Data: []byte("one")},
			File{Name: "two.bin", MIME: "application/octet-stream", Data: []byte{0, 1, 0xfe, 0xff}},
		),
	}
	for name, p := range cases {
		for _, password := range []string{"", "correct horse"} {
			t.Run(name+"/password="+password, func(t *testing.T) {
				b, err := seal(p, password, fastScrypt)
				if err != nil {
					t.Fatal(err)
				}
				wantMode := "k."
				if password != "" {
					wantMode = "p."
					if b.KDF == nil {
						t.Fatal("password bundle has no KDF")
					}
				} else if b.KDF != nil {
					t.Fatal("link-only bundle has a KDF")
				}
				if !strings.HasPrefix(b.Fragment, wantMode) {
					t.Fatalf("fragment %q, want %s prefix", b.Fragment, wantMode)
				}
				if len(b.Blob.IV) != ivLen {
					t.Fatalf("IV is %d bytes", len(b.Blob.IV))
				}

				got, err := Unseal(b.Blob, b.Fragment, password, b.KDF)
				if err != nil {
					t.Fatal(err)
				}
				assertPayloadEqual(t, got, p)
			})
		}
	}
}

func assertPayloadEqual(t *testing.T, got, want Payload) {
	t.Helper()
	if got.Type != want.Type || !bytes.Equal(got.Text, want.Text) || len(got.Files) != len(want.Files) {
		t.Fatalf("payload = %+v, want %+v", got, want)
	}
	for i := range want.Files {
		g, w := got.Files[i], want.Files[i]
		if g.Name != w.Name || g.MIME != w.MIME || !bytes.Equal(g.Data, w.Data) {
			t.Fatalf("file %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestSealFreshKeyAndIVEachTime(t *testing.T) {
	a, _ := Seal(TextPayload("same"), "")
	b, _ := Seal(TextPayload("same"), "")
	if a.Fragment == b.Fragment || bytes.Equal(a.Blob.IV, b.Blob.IV) || bytes.Equal(a.Blob.Ciphertext, b.Blob.Ciphertext) {
		t.Fatal("two seals of the same payload must not share key, IV or ciphertext")
	}
}

func TestSealRejectsBadPayloads(t *testing.T) {
	for name, p := range map[string]Payload{
		"no type":  {Text: []byte("x")},
		"no files": FilePayload(),
	} {
		if _, err := Seal(p, ""); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestEnvelopeWireShape(t *testing.T) {
	b, err := Seal(TextPayload("hi"), "")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := decodeFragment(b.Fragment)
	plain, err := gcmOpen(f.dek, b.Blob.IV, b.Blob.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(plain), `{"v":2,"type":"text","data":"aGk"}`; got != want {
		t.Fatalf("envelope = %s, want %s", got, want)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	b, _ := Seal(TextPayload("integrity"), "")
	b.Blob.Ciphertext[0] ^= 1
	if _, err := Unseal(b.Blob, b.Fragment, "", nil); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("err = %v, want ErrDecryptionFailed", err)
	}
}

func TestUnsupportedEnvelopeVersion(t *testing.T) {
	dek := bytes.Repeat([]byte{7}, keyLen)
	plain, _ := json.Marshal(map[string]any{"v": 1, "type": "text", "data": "aGk"})
	iv, ct, err := gcmSeal(dek, plain)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Unseal(SealedBlob{Ciphertext: ct, IV: iv}, encodeKeyFragment(dek), "", nil)
	var verr *UnsupportedVersionError
	if !errors.As(err, &verr) || verr.Version != 1 {
		t.Fatalf("err = %v, want UnsupportedVersionError{1}", err)
	}
}

func TestDecodeFragmentRejectsGarbage(t *testing.T) {
	for _, frag := range []string{
		"",
		"nodot",
		"x." + b64encode(make([]byte, keyLen)),
		"k." + b64encode(make([]byte, keyLen-1)),
		"p." + b64encode(make([]byte, wrappedLen+1)),
		"k.!!!not-base64!!!",
	} {
		if _, err := decodeFragment(frag); !errors.Is(err, ErrMalformed) {
			t.Errorf("decodeFragment(%q) err = %v, want ErrMalformed", frag, err)
		}
	}
}

func TestKdfValidationRejectsHostileParams(t *testing.T) {
	salt := b64encode(make([]byte, saltLen))
	ok := KdfMeta{KDF: "scrypt", Salt: salt, N: 1 << 17, R: 8, P: 1, DKLen: 32}
	if err := ok.validate(); err != nil {
		t.Fatalf("default params rejected: %v", err)
	}
	mutate := func(f func(*KdfMeta)) KdfMeta { k := ok; f(&k); return k }
	bad := map[string]KdfMeta{
		"argon2":         mutate(func(k *KdfMeta) { k.KDF = "argon2id" }),
		"dkLen 16":       mutate(func(k *KdfMeta) { k.DKLen = 16 }),
		"N not pow2":     mutate(func(k *KdfMeta) { k.N = 100_000 }),
		"N too big":      mutate(func(k *KdfMeta) { k.N = 1 << 21 }),
		"N=1":            mutate(func(k *KdfMeta) { k.N = 1 }),
		"r=0":            mutate(func(k *KdfMeta) { k.R = 0 }),
		"r=33":           mutate(func(k *KdfMeta) { k.R = 33 }),
		"p=17":           mutate(func(k *KdfMeta) { k.P = 17 }),
		"4 GiB product":  mutate(func(k *KdfMeta) { k.N = 1 << 20; k.R = 32 }),
		"just over 1GiB": mutate(func(k *KdfMeta) { k.N = 1 << 20; k.R = 9 }),
	}
	for name, k := range bad {
		if _, err := deriveKEK("pw", &k); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
	short := mutate(func(k *KdfMeta) { k.Salt = b64encode(make([]byte, 8)); k.N = 1 << 10 })
	if _, err := deriveKEK("pw", &short); !errors.Is(err, ErrMalformed) {
		t.Errorf("short salt: err = %v, want ErrMalformed", err)
	}
}

func TestParseURL(t *testing.T) {
	cases := []struct {
		in   string
		want ShareURL
	}{
		{"https://link.bshk.app/s/abc_DEF-123#k.xyz", ShareURL{"https://link.bshk.app", "abc_DEF-123", "k.xyz"}},
		{"  https://link.bshk.app/s/abc#k.xyz\n", ShareURL{"https://link.bshk.app", "abc", "k.xyz"}},
		{"http://localhost:3000/s/abc/#p.xyz", ShareURL{"http://localhost:3000", "abc", "p.xyz"}},
		{"https://example.com/tools/link/s/abc#k.xyz", ShareURL{"https://example.com/tools/link", "abc", "k.xyz"}},
		{"https://example.com/tools/s/link/s/abc#k.xyz", ShareURL{"https://example.com/tools/s/link", "abc", "k.xyz"}},
		{"https://example.com/s/s/abc#k.xyz", ShareURL{"https://example.com/s", "abc", "k.xyz"}},
		{"https://link.bshk.app/s/abc", ShareURL{"https://link.bshk.app", "abc", ""}},
	}
	for _, c := range cases {
		got, err := ParseURL(c.in)
		if err != nil {
			t.Errorf("ParseURL(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseURL(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}

	for _, in := range []string{
		"https://link.bshk.app/x/abc#k.xyz",
		"https://link.bshk.app/s/#k.xyz",
		"https://link.bshk.app/s/abc/x#k.xyz",
		"https://link.bshk.app/s/..#k.xyz",
		"https://link.bshk.app/s/a%2Fb#k.x",
		"ftp://link.bshk.app/s/abc#k.xyz",
		"/s/abc#k.xyz",
	} {
		if _, err := ParseURL(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseURL(%q) err = %v, want ErrMalformed", in, err)
		}
	}
}

func TestParseURLErrorsNeverLeakTheKey(t *testing.T) {
	const key = "FMQtdiRTW8OZfNd9SZiqdQ6dntyjZ1kGDirmbdOsR0g"
	for _, in := range []string{
		"https://link.bshk.app/s/abc#k." + key + "%",
		"https://link.bshk.app/s/abc#k." + key + "%zz",
		"https://link.bshk.app:bad/s/abc#k." + key,
		"https://link.bshk.app/x/abc#k." + key,
		"ftp://link.bshk.app/s/abc#k." + key,
		"https://link.bshk.app/s/a%2Fb#k." + key,
		"https://link.bshk.app/s/abc%23k." + key,
	} {
		_, err := ParseURL(in)
		if err == nil {
			t.Errorf("ParseURL(%q): expected an error", in)
			continue
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("error leaks the key: %v", err)
		}
	}
	ctx := context.Background()
	for _, link := range []string{
		"https://link.bshk.app/s/abc#k." + key + "%",
		"https://link.bshk.app/s/abc%23k." + key,
	} {
		if _, err := (&Client{}).Open(ctx, link, ""); err == nil || strings.Contains(err.Error(), key) {
			t.Errorf("Open error leaks the key or is nil: %v", err)
		}
	}
	c := NewClient("http://127.0.0.1:1")
	if _, err := c.Info(ctx, "abc#k."+key); err == nil || strings.Contains(err.Error(), key) {
		t.Errorf("Info error leaks the key or is nil: %v", err)
	}
	if err := c.Delete(ctx, "abc#k."+key, "tok"); err == nil || strings.Contains(err.Error(), key) {
		t.Errorf("Delete error leaks the key or is nil: %v", err)
	}
}

func TestOpenRejectsLinkWithoutFragment(t *testing.T) {
	for _, link := range []string{"http://127.0.0.1:1/s/abc", "http://127.0.0.1:1/s/abc#"} {
		if _, err := (&Client{}).Open(context.Background(), link, ""); !errors.Is(err, ErrMalformed) {
			t.Errorf("Open(%q) err = %v, want ErrMalformed", link, err)
		}
	}
}

func TestBuildURLRoundTrip(t *testing.T) {
	for _, base := range []string{"https://link.bshk.app", "https://link.bshk.app/"} {
		if got := BuildURL(base, "abc123", "k.xyz"); got != "https://link.bshk.app/s/abc123#k.xyz" {
			t.Errorf("BuildURL(%q) = %s", base, got)
		}
	}
	for _, u := range []ShareURL{
		{"https://example.com/link", "abc", "k.xyz"},
		{"https://example.com/tools/s/link", "-dashed_ID", "p.xyz"},
	} {
		got, err := ParseURL(u.String())
		if err != nil || got != u {
			t.Fatalf("round trip %+v = %+v, %v", u, got, err)
		}
	}
}

func TestFormFields(t *testing.T) {
	get := func(opts CreateOptions) map[string]string {
		t.Helper()
		fields, err := formFields(opts)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, f := range fields {
			m[f.name] = f.value
		}
		return m
	}

	if f := get(CreateOptions{TTL: time.Hour}); f["ttl"] != "3600" || f["views"] != "1" {
		t.Errorf("zero Views must mean burn-after-reading: %v", f)
	}
	if f := get(CreateOptions{TTL: time.Hour, Views: UnlimitedViews}); len(f) != 1 {
		t.Errorf("unlimited must omit views entirely: %v", f)
	} else if _, has := f["views"]; has {
		t.Errorf("unlimited must omit views entirely: %v", f)
	}
	if f := get(CreateOptions{TTL: time.Hour, Views: 7}); f["views"] != "7" {
		t.Errorf("views = %q", f["views"])
	}
	if f := get(CreateOptions{TTL: 90*time.Second + 500*time.Millisecond}); f["ttl"] != "90" {
		t.Errorf("ttl must truncate to whole seconds: %q", f["ttl"])
	}

	for name, opts := range map[string]CreateOptions{
		"no ttl":       {},
		"ttl < 1m":     {TTL: 59 * time.Second},
		"negative ttl": {TTL: -time.Hour},
		"views -2":     {TTL: time.Hour, Views: -2},
	} {
		if _, err := formFields(opts); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
