package caesarlink

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestLive(t *testing.T) {
	base := os.Getenv("CAESAR_LINK_LIVE")
	if base == "" {
		t.Skip("set CAESAR_LINK_LIVE=<server URL> to run against a live server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := NewClient(base)

	t.Run("burn after reading", func(t *testing.T) {
		created, err := c.Create(ctx, TextPayload("caesar-link-go live test"), CreateOptions{TTL: 5 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		info, err := c.Info(ctx, created.ID)
		if err != nil || info.ViewsLeft == nil || *info.ViewsLeft != 1 {
			t.Fatalf("info = %+v, %v", info, err)
		}
		got, err := c.Open(ctx, created.URL, "")
		if err != nil || string(got.Text) != "caesar-link-go live test" {
			t.Fatalf("open = %q, %v", got.Text, err)
		}
		if _, err := c.Open(ctx, created.URL, ""); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second open: err = %v, want ErrNotFound", err)
		}
	})

	t.Run("password, wrong password keeps the view", func(t *testing.T) {
		created, err := c.Create(ctx, TextPayload("guarded"), CreateOptions{TTL: 5 * time.Minute, Password: "live-pw"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Open(ctx, created.URL, "wrong"); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("wrong password: err = %v", err)
		}
		got, err := c.Open(ctx, created.URL, "live-pw")
		if err != nil || string(got.Text) != "guarded" {
			t.Fatalf("open = %q, %v", got.Text, err)
		}
	})

	t.Run("unlimited files, then delete", func(t *testing.T) {
		files := FilePayload(File{Name: "hello.txt", MIME: "text/plain", Data: []byte("hi")})
		created, err := c.Create(ctx, files, CreateOptions{TTL: 5 * time.Minute, Views: UnlimitedViews})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			got, err := c.Open(ctx, created.URL, "")
			if err != nil || len(got.Files) != 1 || got.Files[0].Name != "hello.txt" {
				t.Fatalf("open #%d = %+v, %v", i, got, err)
			}
		}
		if err := c.Delete(ctx, created.ID, created.DeleteToken); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Info(ctx, created.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("info after delete: err = %v, want ErrNotFound", err)
		}
	})
}
