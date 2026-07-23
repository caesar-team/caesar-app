# Caesar Link protocol

Wire format shared by `@caesar/link-sdk` (TypeScript) and `CaesarLinkKit` (Swift).
Everything below is enough to write a third implementation and validate it against the
golden vectors.

## Model

The server is untrusted. It receives:

- the **ciphertext** (opaque bytes),
- the **IV** (public, needed to decrypt),
- optionally the **KDF parameters** for password-protected shares,
- the TTL and remaining view count.

It never receives the data key, the plaintext, or file names. The key lives in the URL
`#fragment`, which user agents do not transmit.

## Envelope (v2)

The plaintext sealed under the data key (DEK) is a UTF-8 JSON document:

```json
{"v":2,"type":"text","data":"<base64url>"}
```

```json
{"v":2,"type":"file","files":[{"name":"a.txt","mime":"text/plain","data":"<base64url>"}]}
```

- `v` — envelope version. Readers **must** reject anything other than `2`.
- `type` — `text` or `file`. Absent fields are omitted, not null.
- `data` (text) and `files[].data` — base64url of the raw bytes.
- File names and mime types are inside the ciphertext by design.

> **v1 → v2.** v1 carried a single file as flat `name`/`mime`/`data` fields alongside
> `type:"file"`. v2 replaces that with the `files` array. There is no back-compat path:
> a v1 blob fails the version check.

### Cipher

| Parameter | Value |
|---|---|
| Algorithm | AES-256-GCM |
| Key (DEK) | 32 bytes |
| IV / nonce | 12 bytes, random per seal |
| Tag | 16 bytes, **appended to the ciphertext** |

The appended tag matches WebCrypto's `SubtleCrypto.encrypt` output. Implementations whose
AEAD API returns the tag separately (CryptoKit, libsodium) must concatenate on seal and
split the trailing 16 bytes on open.

No additional authenticated data (AAD) is used.

## Fragment

The fragment is `<mode>.<base64url(body)>`.

### `k.` — link-only

`body` is the raw 32-byte DEK. Anyone with the link can decrypt.

```
k.<base64url(32 bytes)>
```

### `p.` — password-protected

`body` is `iv ‖ ciphertext`, 60 bytes total:

| Offset | Size | Content |
|---|---|---|
| 0 | 12 | IV for the key-wrap |
| 12 | 48 | AES-256-GCM(KEK, DEK) — 32-byte key + 16-byte tag |

The wrapping key is derived from the password:

```
KEK = scrypt(password, salt, N, r, p, dkLen = 32)
```

`salt`, `N`, `r`, `p`, `dkLen` come from the share's server-side KDF metadata (below), not
from the fragment. Default cost: `N = 2^17`, `r = 8`, `p = 1`, salt 16 bytes.

Unwrapping failure means a wrong password — it is indistinguishable from a corrupted
fragment and must be reported as such.

### KDF metadata validation

These parameters arrive from an untrusted server, so a reader **must** bound them before
deriving:

- `kdf == "scrypt"`, `dkLen == 32`
- `N` a power of two, `2 ≤ N ≤ 2^20`
- `1 ≤ r ≤ 32`, `1 ≤ p ≤ 16`
- `128 · N · r ≤ 2^30` (1 GiB)

The product bound matters: `N = 2^20` with `r = 32` is individually in range but needs
≈ 4 GiB and would kill the client before any decryption happens.

## Share URL

```
<base>/s/<id>#<fragment>
```

Readers must reject a URL with no fragment — there is nothing to decrypt with.

## HTTP API

### `POST /api/shares`

`multipart/form-data`:

| Field | Content |
|---|---|
| `blob` | ciphertext bytes (file part, `application/octet-stream`) |
| `meta` | JSON string: `{"iv":"<base64url>"}`, plus `"kdf":{…}` for password shares |
| `ttl` | lifetime in seconds; the server clamps to its maximum |
| `views` | positive integer, or empty for unlimited |

→ `201 {"id":"…","deleteToken":"…"}`. Over-sized blobs get `413`.

### `GET /api/shares/:id`

→ `{"meta":{…},"size":…,"viewsLeft":…,"expiresAt":…}`. Does **not** consume a view.

### `GET /api/shares/:id/blob`

→ raw ciphertext, `application/octet-stream`. **Consumes a view**; the share is destroyed
when the counter reaches zero. Gone or expired shares return `404` — deliberately
indistinguishable from "never existed", so the server leaks nothing about which IDs were
real.

### `DELETE /api/shares/:id`

Revokes early, using the `deleteToken` from creation.

## Encodings

base64url per RFC 4648 §5: `+`→`-`, `/`→`_`, padding stripped. Decoders must re-pad.

## Test vectors

`packages/link-sdk/vectors/v2.json` in the caesar-app repo. Each entry carries the
fragment, KDF metadata, the sealed blob, and the expected payload. Opening all of them is
the compatibility bar for any implementation.
