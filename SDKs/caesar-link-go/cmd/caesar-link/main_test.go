package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	caesarlink "github.com/caesar-team/caesar-app/SDKs/caesar-link-go"
)

// Share ids and delete tokens are nanoids; about one in 64 starts with "-". The live smoke
// test hit `-TGQLWN8KSoELuLTPHpcW`, which the stock flag package rejects as an unknown flag.
func TestParseFlagsKeepsDashedIDsPositional(t *testing.T) {
	cases := []struct {
		args       []string
		wantPos    []string
		wantServer string
		wantBool   bool
	}{
		{[]string{"-TGQLWN8KSoELuLTPHpcW"}, []string{"-TGQLWN8KSoELuLTPHpcW"}, "default", false},
		{[]string{"-server", "https://x", "-id", "--tok"}, []string{"-id", "--tok"}, "https://x", false},
		{[]string{"-id", "-server=https://y", "tok"}, []string{"-id", "tok"}, "https://y", false},
		{[]string{"--server", "https://z", "--", "-server"}, []string{"-server"}, "https://z", false},
		{[]string{"-b", "-abc"}, []string{"-abc"}, "default", true}, // bool flag must not eat the id
		{[]string{"-", "x"}, []string{"-", "x"}, "default", false},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("t", flag.ExitOnError)
		server := fs.String("server", "default", "")
		b := fs.Bool("b", false, "")
		pos := parseFlags(fs, c.args)
		if !reflect.DeepEqual(pos, c.wantPos) || *server != c.wantServer || *b != c.wantBool {
			t.Errorf("parseFlags(%q) = %q server=%q b=%v; want %q server=%q b=%v",
				c.args, pos, *server, *b, c.wantPos, c.wantServer, c.wantBool)
		}
	}
}

// info/delete accept a share URL: it names its own server (like `open`) and needs no key.
func TestShareTarget(t *testing.T) {
	cases := []struct{ arg, wantBase, wantID string }{
		{"-dashedID", "https://default", "-dashedID"},
		{"https://link.bshk.app/s/abc#k.key", "https://link.bshk.app", "abc"},
		{"https://example.com/tools/s/link/s/abc", "https://example.com/tools/s/link", "abc"},
	}
	for _, c := range cases {
		client, id, err := shareTarget(c.arg, "https://default")
		if err != nil || client.BaseURL != c.wantBase || id != c.wantID {
			t.Errorf("shareTarget(%q) = %q, %q, %v; want %q, %q", c.arg, client.BaseURL, id, err, c.wantBase, c.wantID)
		}
	}
	if _, _, err := shareTarget("https://link.bshk.app/x/abc", "https://default"); err == nil {
		t.Error("a URL without /s/<id> must be rejected")
	}
}

// File names come from whoever created the share, so they must not escape -out or clobber
// existing files.
func TestSaveFileIsConfinedToOutDir(t *testing.T) {
	for _, name := range []string{"../../etc/passwd", "/abs/path.txt", "..", "", "a/b/c.txt"} {
		dir := t.TempDir()
		path, err := saveFile(dir, caesarlink.File{Name: name, Data: []byte("x")})
		if err != nil {
			t.Fatalf("saveFile(%q): %v", name, err)
		}
		if filepath.Dir(path) != dir {
			t.Fatalf("saveFile(%q) wrote %s, outside %s", name, path, dir)
		}
		if _, err := saveFile(dir, caesarlink.File{Name: name, Data: []byte("again")}); !os.IsExist(err) {
			t.Fatalf("saveFile(%q) twice: err = %v, want exists (no overwrite)", name, err)
		}
	}
}
