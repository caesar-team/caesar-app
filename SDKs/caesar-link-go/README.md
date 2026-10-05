# caesar-link-go

Go client for [Caesar Link](https://link.bshk.app), a zero-knowledge secret-sharing service.

Everything is encrypted locally. The server stores ciphertext and a public IV. It never
sees the plaintext, file names or the key. The key travels in the URL `#fragment`, which is
never sent to a server.

The wire format matches the TypeScript (`@caesar/link-sdk`) and Swift (`CaesarLinkKit`)
SDKs. The shared golden vectors prove this. Shares sealed by this package were also opened
with the TypeScript SDK once by hand; that check is not in CI.

## Installation

```bash
go get github.com/caesar-team/caesar-app/SDKs/caesar-link-go@main
```

The module lives in a subdirectory of the monorepo, so its release tags carry a path prefix:
`SDKs/caesar-link-go/vX.Y.Z`. Until the first such tag exists, `@main` resolves to a
pseudo-version. Requires Go 1.26+ (from `golang.org/x/crypto`).

## Quick start

```go
import caesarlink "github.com/caesar-team/caesar-app/SDKs/caesar-link-go"

c := caesarlink.NewClient(caesarlink.DefaultBaseURL)

created, err := c.Create(ctx, caesarlink.TextPayload(secret), caesarlink.CreateOptions{
	TTL:   time.Hour, // required, 1m … 30 days
	Views: 1,         // 0 also means 1 (burn after reading); caesarlink.UnlimitedViews for no limit
})
fmt.Println(created.URL) // https://link.bshk.app/s/<id>#k.<key>
```

`created.URL` is the **only** copy of the key. The server cannot recover it, so do not log
it. `created.DeleteToken` revokes the share early with `c.Delete(ctx, created.ID, token)`.

### Files

```go
c.Create(ctx, caesarlink.FilePayload(
	caesarlink.File{Name: "report.pdf", MIME: "application/pdf", Data: pdf},
	caesarlink.File{Name: "notes.md", MIME: "text/markdown", Data: notes},
), caesarlink.CreateOptions{TTL: 24 * time.Hour, Views: caesarlink.UnlimitedViews})
```

Names and MIME types are sealed inside the ciphertext.

### Password mode

```go
created, err := c.Create(ctx, payload, caesarlink.CreateOptions{
	TTL: time.Hour, Password: "correct horse battery",
})
```

The key is wrapped under scrypt (N=2¹⁷, r=8, p=1, about 128 MiB and a fraction of a
second), so the link alone is useless. Deliver the password over another channel.

### Reading

```go
payload, err := c.Open(ctx, link, password) // password "" for k. links
switch payload.Type {
case caesarlink.TypeText:
	os.Stdout.Write(payload.Text)
case caesarlink.TypeFile:
	for _, f := range payload.Files { /* f.Name, f.MIME, f.Data */ }
}
```

`Open` **consumes a view**. It talks to the host named in the link, not `Client.BaseURL`.
Anything it can check without spending a view, it checks first:

| Situation | Result | View spent? |
|---|---|---|
| `p.` link, empty password | `ErrPasswordRequired`, no request made | no |
| wrong password | `ErrWrongPassword`, detected against the wrapped key from the link | **no** |
| declared size above `MaxBlobSize`, or a malformed IV | error from the metadata alone | no |
| expired, used up, deleted or never existed | `ErrNotFound` | n/a |
| ciphertext tampered with | `ErrDecryptionFailed` | yes |

The TypeScript and Swift SDKs download the blob before they test the password, so there a
wrong password costs a view. Here it does not.

`c.Info(ctx, id)` returns size, views left, expiry and whether a password is needed, without
consuming a view.

### Offline

`Seal` and `Unseal` do the crypto with no network. Use them if you handle transport yourself:

```go
bundle, _ := caesarlink.Seal(payload, password)
// bundle.Blob.Ciphertext + bundle.Blob.IV → upload; bundle.KDF → store server-side
// bundle.Fragment                         → keep out of every request
url := caesarlink.BuildURL(base, id, bundle.Fragment)
```

## Errors

Check them with `errors.Is` / `errors.As`:

| Error | Meaning |
|---|---|
| `ErrPasswordRequired` | a `p.` link was opened without a password |
| `ErrWrongPassword` | the password did not unwrap the key |
| `ErrMissingKdf` | password share without server-side KDF metadata |
| `ErrDecryptionFailed` | wrong key, or the ciphertext was tampered with |
| `ErrNotFound` | 404. Gone and never-existed look the same, by design |
| `ErrMalformed` | bad URL, fragment, base64url or hostile KDF parameters |
| `*UnsupportedVersionError` | envelope from a newer protocol revision |
| `*ServerError` | any other non-2xx; `Body` holds the server's `error` message |

## Security notes

- **KDF parameters come from an untrusted server.** They are bounded before anything is
  allocated: N must be a power of two ≤ 2²⁰, r ≤ 32, p ≤ 16, and 128·N·r ≤ 1 GiB.
- **Share IDs are validated** (`[A-Za-z0-9_-]+`), so a crafted link cannot steer requests
  to other paths.
- **Downloads are capped** at `Client.MaxBlobSize` (100 MiB by default).
- **File names in a received share are chosen by its sender.** Reduce them to a base name
  before writing to disk. The example CLI shows how.

## Example CLI

[`cmd/caesar-link`](cmd/caesar-link) is a working CLI and the reference integration:

![caesar-link demo: burn after reading, then a password share where a wrong guess spends no view](demo/demo.gif)

The recording above is made against the live server from [`demo/demo.tape`](demo/demo.tape).
Re-render it with `vhs demo/demo.tape` from this directory.

```bash
go install github.com/caesar-team/caesar-app/SDKs/caesar-link-go/cmd/caesar-link@main

echo -n 's3cret' | caesar-link create -ttl 1h        # prints the URL; id + delete token go to stderr
caesar-link create -password -file key.pem            # prompts for a password, no echo
caesar-link open 'https://link.bshk.app/s/<id>#k.<key>'
caesar-link open -out ./received '<url>'              # files; never overwrites
caesar-link info <id>
caesar-link delete <id> <delete-token>
```

The CLI never takes a password as a command-line value, because argv shows up in `ps` and in
shell history. It reads `-password-file`, then a no-echo prompt on `/dev/tty`, then
`$CAESAR_LINK_PASSWORD`. `open` prompts by itself when a link turns out to need a password.

Share IDs and delete tokens can start with `-`. The CLI treats them as arguments, not flags.

## Tests

```bash
go test ./...                                               # vectors, protocol, fake server
CAESAR_LINK_LIVE=https://link.bshk.app go test -run TestLive -v   # against a real server
```

`TestVectorsOpen` opens **every** golden vector produced by the TypeScript SDK, both `k.`
and `p.`. It reads `packages/link-sdk/vectors/v2.json` straight from this repo, so there is
no vendored copy to drift. CI re-runs it whenever the package *or* the vectors change.

The protocol is specified in [PROTOCOL.md](../caesar-link-swift/PROTOCOL.md).
