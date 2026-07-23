# CaesarLinkKit

Swift client for [Caesar Link](https://link.bshk.app) — zero-knowledge secret sharing.

Everything is encrypted on-device. The server stores ciphertext and a public IV, nothing
else: not the plaintext, not file names, not the key. The data key travels in the URL
`#fragment`, which browsers never send to a server — that is the whole trick.

Wire-compatible with the TypeScript SDK (`@caesar/link-sdk`), proven by shared test vectors.

## Requirements

macOS 13+ / iOS 16+, Swift 6.0+.

`CryptoKit` and `Foundation`, plus libsodium (via
[swift-sodium](https://github.com/jedisct1/swift-sodium)) for scrypt — the one primitive
CryptoKit lacks. Only the raw `Clibsodium` product is linked; the Sodium Swift wrapper is
not used.

## Installation

Depend on the monorepo itself — the root `Package.swift` vends this target:

```swift
.package(url: "https://github.com/caesar-team/caesar-app.git", from: "0.1.0")
```

```swift
.target(name: "YourApp", dependencies: [
    .product(name: "CaesarLinkKit", package: "caesar-app")
])
```

### Why the manifest is at the repo root

`.package(url:)` has no subdirectory parameter — SwiftPM always reads `Package.swift` from
the root of the cloned repository. A root manifest whose target uses
`path: "SDKs/caesar-link-swift/Sources/CaesarLinkKit"` sidesteps that entirely, so this kit
ships from the monorepo with **no second repository and no release tooling**.

That is what keeps the Swift and TypeScript SDKs honest: they sit side by side with the
protocol vectors they must both satisfy, and a protocol change lands in one commit.

Two things to know: consumers clone the whole monorepo into their SwiftPM checkout (a few
extra megabytes, otherwise harmless), and `from:` needs semver tags on **caesar-app**, whose
version therefore doubles as the SDK version.

## Quick start

```swift
import CaesarLinkKit

let client = LinkClient(baseURL: URL(string: "https://link.bshk.app")!)

let created = try await client.createShare(
    .text(transcript),
    ttlSeconds: 3600,   // server clamps to its configured maximum
    views: 1            // 1 = self-destructs after one read; nil = unlimited
)
print(created.url)      // https://link.bshk.app/s/<id>#k.<key>
```

`created.url` is the **only** copy of the key — it cannot be recovered from the server.
Hand it to the user to share. `created.deleteToken` revokes the share early.

### Files

```swift
try await client.createShare(
    .files([
        SharedFile(name: "transcript.md", mime: "text/markdown", data: markdown),
        SharedFile(name: "audio.m4a", mime: "audio/mp4", data: audio),
    ]),
    ttlSeconds: 86_400,
    views: nil
)
```

Names and mime types are sealed inside the ciphertext, so the server cannot see them.

### Password mode

Without a password, whoever holds the link can read the secret. With one, the key is
wrapped under a scrypt-derived KEK, so the link alone is useless — deliver the password
over a separate channel.

```swift
let created = try await client.createShare(
    .text(secret), ttlSeconds: 3600, views: 1,
    password: "correct horse battery"
)
```

### Reading back

```swift
let payload = try await client.openShare(url: shareURL, password: nil)
switch payload {
case .text(let data):  print(String(decoding: data, as: UTF8.self))
case .files(let files): files.forEach { print($0.name, $0.data.count) }
}
```

This **consumes a view** — the server decrements the counter when the blob is fetched.

### Offline use

`LinkClient` is a thin convenience layer. To handle transport yourself:

```swift
let bundle = try Share.create(.text(secret), password: nil)
// bundle.blob.ciphertext + bundle.blob.iv → upload
// bundle.fragment                          → keep out of the request
// bundle.kdf                               → store server-side (password mode only)
let url = ShareURL.build(baseURL: "https://link.bshk.app", id: id, fragment: bundle.fragment)
```

## Errors

| Case | Meaning |
|---|---|
| `.passwordRequired` | a `p.` link was opened without a password |
| `.wrongPassword` | the password did not unwrap the key |
| `.missingKdf` | password share without server-side KDF metadata |
| `.decryptionFailed` | wrong key, or the ciphertext was tampered with |
| `.unsupportedVersion` | envelope from a newer protocol revision |
| `.malformed` | bad base64url, missing field, hostile KDF parameters |
| `.server(status:body:)` | non-2xx from the Link server |

## Security notes

- **The key never leaves the device** except inside the fragment of the URL you hand to the
  user. Do not log `created.url`, and be careful about analytics that capture URLs.
- **KDF parameters come from an untrusted server.** `KdfMeta.validate()` rejects hostile
  values before allocating: N must be a power of two ≤ 2²⁰, and 128·N·r is capped at 1 GiB.
  Without that bound, a crafted share could exhaust memory before decryption even starts.
- **A wrong password still costs a view** — the blob must be fetched before the key can be
  tested. Surface that in your UI.
- Password mode with the default cost (N=2¹⁷ ≈ 128 MiB) takes a noticeable moment; run it
  off the main thread and show progress.

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for the exact wire format — envelope, fragments and the HTTP
contract — enough to write another implementation from scratch.

## Tests

```bash
swift test
```

`VectorsTests` opens **every** golden vector produced by the TypeScript SDK — both `k.` and
`p.`. The password vector proves libsodium's scrypt derives the same KEK as `@noble/hashes`
for identical parameters. If these pass, the two implementations provably speak the same
protocol.

The test reads `packages/link-sdk/vectors/v2.json` straight from this repo — there is no
vendored copy to drift. Regenerating the vectors upstream breaks this test immediately,
which is the point. CI re-runs it on any change to the kit *or* the vectors.

## Releasing

There is no release step. Consumers depend on a tagged commit of the monorepo; tag
caesar-app (`vX.Y.Z`) and they pick it up. The tag's version doubles as this SDK's version.

Both directions have also been checked against the live service: shares sealed by this kit,
link-only and password-protected alike, decrypt correctly in the web app.
