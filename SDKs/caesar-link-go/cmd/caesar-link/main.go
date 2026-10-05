// Command caesar-link shares secrets through Caesar Link from the terminal. It doubles as
// the reference integration of the caesarlink package.
//
//	echo -n 's3cret' | caesar-link create -ttl 1h            # prints the share URL
//	caesar-link create -ttl 24h -views 3 -file report.pdf
//	caesar-link create -password -file key.pem               # prompts for a password
//	caesar-link create -json -file a.txt                     # {"url","id","deleteToken"}
//	caesar-link open 'https://link.bshk.app/s/<id>#k.<key>'   # text → stdout, files → -out
//	caesar-link info <id|url>
//	caesar-link delete <id|url> <delete-token>
//
// Passwords are never accepted as command-line values: argv is visible in the process list
// and shell history. They come, in order of precedence, from -password-file, an interactive
// no-echo prompt on the terminal, or $CAESAR_LINK_PASSWORD. `open` prompts on its own when
// the link turns out to be password-protected.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	caesarlink "github.com/caesar-team/caesar-app/SDKs/caesar-link-go"
)

const passwordEnv = "CAESAR_LINK_PASSWORD"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	exitOnInterrupt()
	ctx := context.Background()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "create":
		err = create(ctx, args)
	case "open":
		err = open(ctx, args)
	case "info":
		err = info(ctx, args)
	case "delete":
		err = del(ctx, args)
	case "-h", "-help", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "caesar-link:", strings.TrimPrefix(err.Error(), "caesarlink: "))
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: caesar-link <create|open|info|delete> [flags] — run a command with -h for its flags")
}

// exitOnInterrupt makes Ctrl-C work even while blocked on stdin or a password prompt,
// neither of which can observe a context. It exits at once, after undoing the no-echo mode
// a prompt may have left on the terminal.
func exitOnInterrupt() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signals
		restoreTerminal()
		fmt.Fprintln(os.Stderr)
		if sig == syscall.SIGTERM {
			os.Exit(143)
		}
		os.Exit(130)
	}()
}

// ttyState is the terminal mode saved before a no-echo prompt, so an interrupt can restore it.
var ttyState struct {
	sync.Mutex
	fd    int
	state *term.State
}

func restoreTerminal() {
	ttyState.Lock()
	defer ttyState.Unlock()
	if ttyState.state != nil {
		_ = term.Restore(ttyState.fd, ttyState.state)
	}
}

// parseFlags parses only the flags fs defines and returns everything else as positional
// arguments, in order. Share ids and delete tokens are nanoids and may start with "-", which
// the flag package would take for an unknown flag. `--` still ends flag parsing.
func parseFlags(fs *flag.FlagSet, args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		f := fs.Lookup(name)
		if !strings.HasPrefix(arg, "-") || (f == nil && name != "h" && name != "help") {
			pos = append(pos, arg)
			continue
		}
		flags = append(flags, arg)
		if f != nil && !hasValue && i+1 < len(args) {
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	fs.Parse(flags) // ExitOnError: bad values and -h exit here
	return pos
}

type fileList []string

func (f *fileList) String() string     { return fmt.Sprint(*f) }
func (f *fileList) Set(v string) error { *f = append(*f, v); return nil }

func create(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	server := fs.String("server", caesarlink.DefaultBaseURL, "Link server")
	ttl := fs.Duration("ttl", 24*time.Hour, "lifetime (1m … 720h)")
	views := fs.Int("views", 1, "reads before self-destruct; 0 = unlimited")
	prompt := fs.Bool("password", false, "protect with a password, prompted on the terminal without echo")
	passwordFile := fs.String("password-file", "", "protect with the password on the first line of this file")
	asJSON := fs.Bool("json", false, `print {"url","id","deleteToken"} as JSON instead of the bare URL`)
	var files fileList
	fs.Var(&files, "file", "attach a file (repeatable); without it, stdin is shared as text")
	if extra := parseFlags(fs, args); len(extra) > 0 {
		return fmt.Errorf("create: unexpected arguments %q (use -file for files, stdin for text)", extra)
	}

	// Ask before reading stdin, so an interactive user is not prompted mid-paste.
	password, err := resolvePassword(*passwordFile, *prompt, true)
	if err != nil {
		return err
	}
	payload, err := readPayload(files)
	if err != nil {
		return err
	}
	if *views == 0 {
		*views = caesarlink.UnlimitedViews
	}
	created, err := caesarlink.NewClient(*server).Create(ctx, payload, caesarlink.CreateOptions{
		TTL: *ttl, Views: *views, Password: password,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(struct {
			URL         string `json:"url"`
			ID          string `json:"id"`
			DeleteToken string `json:"deleteToken"`
		}{created.URL, created.ID, created.DeleteToken})
	}
	fmt.Println(created.URL)
	fmt.Fprintf(os.Stderr, "id: %s\ndelete token: %s\n", created.ID, created.DeleteToken)
	return nil
}

func readPayload(files []string) (caesarlink.Payload, error) {
	if len(files) == 0 {
		text, err := io.ReadAll(os.Stdin)
		if err != nil {
			return caesarlink.Payload{}, err
		}
		return caesarlink.Payload{Type: caesarlink.TypeText, Text: text}, nil
	}
	out := make([]caesarlink.File, 0, len(files))
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return caesarlink.Payload{}, err
		}
		mimeType := mime.TypeByExtension(filepath.Ext(path))
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
		out = append(out, caesarlink.File{Name: filepath.Base(path), MIME: mimeType, Data: data})
	}
	return caesarlink.FilePayload(out...), nil
}

func open(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	passwordFile := fs.String("password-file", "", "read the password from the first line of this file")
	outDir := fs.String("out", ".", "directory for received files")
	pos := parseFlags(fs, args)
	if len(pos) != 1 {
		return errors.New("open: expected exactly one share URL")
	}
	link := pos[0]

	password, err := resolvePassword(*passwordFile, false, false)
	if err != nil {
		return err
	}
	// Open talks to the server named in the link; BaseURL is not needed.
	c := &caesarlink.Client{}
	payload, err := c.Open(ctx, link, password)
	// ErrPasswordRequired comes back before any request is made, so prompting and retrying
	// costs nothing.
	if errors.Is(err, caesarlink.ErrPasswordRequired) {
		if password, err = promptPassword(false); err != nil {
			return err
		}
		payload, err = c.Open(ctx, link, password)
	}
	if errors.Is(err, caesarlink.ErrWrongPassword) {
		// Checked against the wrapped key before the download, so nothing was consumed.
		return fmt.Errorf("%w (no view was spent, try again)", err)
	}
	if err != nil {
		return err
	}
	if payload.Type == caesarlink.TypeText {
		_, err := os.Stdout.Write(payload.Text)
		return err
	}
	for _, f := range payload.Files {
		path, err := saveFile(*outDir, f)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "saved", path)
	}
	return nil
}

// saveFile writes a received file without trusting its name: the sender chose it, so it is
// reduced to a bare base name and never overwrites anything.
func saveFile(dir string, f caesarlink.File) (string, error) {
	name := filepath.Base(filepath.Clean("/" + f.Name))
	if name == "/" || name == "." || name == ".." {
		name = "file.bin"
	}
	path := filepath.Join(dir, name)
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := out.Write(f.Data); err != nil {
		out.Close()
		return "", err
	}
	return path, out.Close()
}

// shareTarget resolves an <id|url> argument. A share URL carries its own server, as with
// `open`, and its fragment is not needed; a bare id goes to -server.
func shareTarget(arg, server string) (*caesarlink.Client, string, error) {
	if !strings.Contains(arg, "://") {
		return caesarlink.NewClient(server), arg, nil
	}
	u, err := caesarlink.ParseURL(arg)
	if err != nil {
		return nil, "", err
	}
	return caesarlink.NewClient(u.Base), u.ID, nil
}

func info(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	server := fs.String("server", caesarlink.DefaultBaseURL, "Link server, for a bare id")
	pos := parseFlags(fs, args)
	if len(pos) != 1 {
		return errors.New("info: expected a share id or URL")
	}
	c, id, err := shareTarget(pos[0], *server)
	if err != nil {
		return err
	}
	i, err := c.Info(ctx, id)
	if err != nil {
		return err
	}
	views := "unlimited"
	if i.ViewsLeft != nil {
		views = fmt.Sprint(*i.ViewsLeft)
	}
	fmt.Printf("size: %d bytes\nviews left: %s\nexpires: %s\npassword: %t\n",
		i.Size, views, i.ExpiresAt.Local().Format(time.RFC3339), i.PasswordProtected)
	return nil
}

func del(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	server := fs.String("server", caesarlink.DefaultBaseURL, "Link server, for a bare id")
	pos := parseFlags(fs, args)
	if len(pos) != 2 {
		return errors.New("delete: expected <id|url> <delete-token>")
	}
	c, id, err := shareTarget(pos[0], *server)
	if err != nil {
		return err
	}
	if err := c.Delete(ctx, id, pos[1]); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "deleted", id)
	return nil
}

// resolvePassword picks the password source: -password-file, then an interactive prompt,
// then $CAESAR_LINK_PASSWORD. Empty means no password.
func resolvePassword(file string, prompt, confirm bool) (string, error) {
	switch {
	case file != "" && prompt:
		return "", errors.New("use either -password or -password-file, not both")
	case file != "":
		return readPasswordFile(file)
	case prompt:
		return promptPassword(confirm)
	default:
		return os.Getenv(passwordEnv), nil
	}
}

func readPasswordFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", fmt.Errorf("password file %s is empty", path)
	}
	return password, nil
}

// promptPassword reads a password without echo from the controlling terminal rather than
// stdin, which stays free to carry the payload (`echo secret | caesar-link create -password`).
func promptPassword(confirm bool) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal to prompt for a password; use -password-file or $%s", passwordEnv)
	}
	defer tty.Close()

	read := func(label string) (string, error) {
		fd := int(tty.Fd())
		// Remember the echoing mode so an interrupt mid-prompt can put it back.
		if state, err := term.GetState(fd); err == nil {
			ttyState.Lock()
			ttyState.fd, ttyState.state = fd, state
			ttyState.Unlock()
			defer func() {
				ttyState.Lock()
				ttyState.state = nil
				ttyState.Unlock()
			}()
		}
		fmt.Fprint(tty, label)
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(tty)
		return string(pw), err
	}
	password, err := read("Password: ")
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("empty password")
	}
	if confirm {
		again, err := read("Repeat password: ")
		if err != nil {
			return "", err
		}
		if again != password {
			return "", errors.New("passwords do not match")
		}
	}
	return password, nil
}
