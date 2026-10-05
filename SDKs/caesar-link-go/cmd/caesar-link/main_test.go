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
