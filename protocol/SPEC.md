# Caesar Core Protocol Spec — v1

**Status:** Normative for envelope v1 / suite 1 / item schema v1
**Reference implementation:** `crates/caesar-core` in the caesar-app monorepo
**Test vectors:** `protocol/vectors.json` — **normative** (see §12)

This document specifies every byte Caesar writes to disk or to the server, so that a
client written in Swift, Kotlin or TypeScript interoperates with the Rust core
byte-for-byte **without reading the Rust**. Sections marked *(normative)* are binding;
*(informative)* sections give context.

Key words MUST, MUST NOT, SHOULD, MAY are used per RFC 2119.

Where this document and `protocol/vectors.json` disagree, **the vectors win** — they are
generated from the reference implementation on every build and gated in CI. Where the
vectors are silent, this document is binding.

---

## 1. Overview (informative)

Caesar is zero-knowledge: the server stores ciphertext and non-secret metadata, never a
key that opens it. Everything below happens on the client.

Four things are sealed, all with the same AEAD and the same envelope:

| What | Key | Where the key comes from |
| --- | --- | --- |
| User key pair (private half) | KEK | password → Argon2id → HKDF |
| Vault key | KEK | same |
| Vault key, shared to a teammate | per-record key | X25519 ECDH → HKDF |
| Item plaintext | vault key | unwrapped from one of the above |

The server sees: the encoded `KdfParams`, the user's X25519 public key, the wrapped
blobs, and the length of every envelope (bucketed, see §8.2). The server does **not**
see: the password, the master key, the KEK, any vault key, any item field.

---

## 2. Constants (normative)

### 2.1 The three version axes

Three independent version numbers exist. They are **not** locked together and MUST NOT be
assumed equal, even though all three are `1` today.

| Constant | Value | Governs | Bumped when |
| --- | --- | --- | --- |
| `PROTOCOL_VERSION` | `1` | Envelope byte layout (§5) | The envelope framing changes |
| `SUITE_ID` | `1` | The primitive set: Argon2id + XChaCha20-Poly1305 + X25519 | A primitive is replaced |
| `ITEM_SCHEMA_VERSION` | `1` | The item JSON schema (§8) | A field is added or removed |

A fourth pair versions the KDF parameter blob specifically, and is likewise independent:

| Constant | Value | Governs |
| --- | --- | --- |
| `KDF_VERSION` | `1` | `KdfParams` encoding (§4.1) |
| `KDF_ALGO_ARGON2ID` | `1` | The KDF algorithm identifier inside that encoding |

`PROTOCOL_VERSION` and `SUITE_ID` travel in every envelope header. `KDF_VERSION` and
`KDF_ALGO_ARGON2ID` travel in every encoded `KdfParams`. `ITEM_SCHEMA_VERSION` travels as
the `v` field **inside** the encrypted item JSON, so the server never learns it.

### 2.2 Lengths and identifiers

| Name | Value | Note |
| --- | --- | --- |
| `HEADER_LEN` | 2 | version byte + suite byte |
| `NONCE_LEN` | 24 | XChaCha20 nonce |
| `TAG_LEN` | 16 | Poly1305 tag |
| `MIN_ENVELOPE_LEN` | 42 | `2 + 24 + 16`, i.e. an envelope over empty plaintext |
| `SALT_LEN` | 16 | Argon2id salt |
| `KDF_PARAMS_LEN` | 30 | `2 + 3×4 + 16` |
| `DERIVED_KEY_LEN` | 32 | Argon2id output **and** every HKDF output |
| `EPHEMERAL_PUBLIC_LEN` | 32 | X25519 public key |
| `LEN_PREFIX_LEN` | 4 | item length prefix, `u32` little-endian |
| `MIN_BUCKET` | 512 | smallest item padding bucket (§8.2) |

Every multi-byte integer in a binary layout is **little-endian**. Hex in
`protocol/vectors.json` is lowercase, unseparated.

---

## 3. Key hierarchy (normative)

```
                         master password (UTF-8, NFC — §4.3)
                                    |
                        Argon2id(salt, m, t, p) → 32 bytes
                                    |
                              Master Key (MK)
                    ______________/        \______________
                   |                                      |
   HKDF-SHA256(info="caesar/auth/v1")     HKDF-SHA256(info="caesar/wrap/v1")
                   |                                      |
             Auth Key (AK)                     Key Encryption Key (KEK)
       sent to the server as the                never leaves the device
       Better Auth password                              |
                                        ________________/ \________________
                                       |                                   |
                          wrap_user_key(KEK, UK_priv)        wrap_vault_key(KEK, VK)
                                       |                                   |
                             encryptedUserKey                    encryptedVaultKey
                                       |                                   |
                                 UK (X25519 pair)                    VK (32 bytes)
                                       |                                   |
                       open_vault_key_for(UK, sealed) ←──── seal_vault_key_for(UK_pub, VK)
                                                                           |
                                                              seal_item(item, VK)
```

A **Recovery Key** (RK, 32 random bytes) is a *second, parallel* wrapping path: the same
`UK_priv` and the same `VK` are additionally sealed under RK with the plain envelope
(§5), so a user who lost the password can still reach both. RK is what the Emergency Kit
(§9) prints. RK is not derived from anything — it is generated by the CSPRNG.

The five 32-byte secret key types (MK, AK, KEK, VK, RK) are distinct types in the
reference implementation, but that is a guard against swapped arguments, **not** a
cryptographic guarantee. The guarantee that AK cannot be turned into KEK comes from HKDF
domain separation (§4.4) alone.

---

## 4. Password to keys (normative)

### 4.1 `KdfParams` — 30-byte layout

Stored on the server, in the clear, once per user.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 1 | `KDF_VERSION` = `0x01` |
| 1 | 1 | `KDF_ALGO_ARGON2ID` = `0x01` |
| 2 | 4 | `m_cost`, `u32` LE, in **KiB** |
| 6 | 4 | `t_cost`, `u32` LE, iterations |
| 10 | 4 | `p_cost`, `u32` LE, lanes |
| 14 | 16 | `salt`, raw bytes (not base64, not PHC-encoded) |

Total 30 bytes. A decoder MUST reject a blob whose length is not exactly 30
(`Truncated`), whose byte 0 is not `1` (`UnsupportedVersion`), or whose byte 1 is not `1`
(`UnsupportedSuite`), in that order, **before** validating the cost parameters.

Defaults for a new account: `m_cost = 65536` (64 MiB), `t_cost = 3`, `p_cost = 4`, salt
from the platform CSPRNG.

### 4.2 Parameter floor and ceiling

A decoder MUST reject parameters outside this range with `KdfParamsOutOfRange`. The same
check MUST run again at derivation time, not only at decode time — parameters can reach
the deriver without passing through `decode`.

| | min | max |
| --- | --- | --- |
| `m_cost` | 19456 (19 MiB) | 4194304 (4 GiB) |
| `t_cost` | 2 | 16 |
| `p_cost` | 1 | 16 |

**Why these bounds cannot be replaced by authentication.** `KdfParams` arrive from the
server in the clear and are covered by no MAC. They cannot be: verifying a tag requires a
key, and the only key available at that point is derived *from the parameters* being
checked. There is no ordering that fixes this. The floor is therefore the only defence
against a hostile server that sends `m_cost = 8`, gets an `auth_key` derived in
milliseconds, and brute-forces it offline.

The ceiling is not primarily an attack defence: `m_cost = 0xFFFFFFFF` makes a client ask
the allocator for ~4 TiB and abort — under WASM that kills the module, under UniFFI it
kills the host application — and `t_cost = 0xFFFFFFFF` computes for roughly fifty days
with no error at all. A migration that wrote `m_cost` in MiB instead of KiB produces
exactly this. The bound turns both into a diagnosable `Err`.

### 4.3 Argon2id

| Parameter | Value |
| --- | --- |
| Algorithm | Argon2**id** |
| Version | `0x13` (= 19 decimal, "Argon2 1.3"). Version `0x10` yields a **different** key for the same inputs and MUST NOT be used. |
| Output length | 32 bytes |
| Password | the NFC-normalized password, encoded as raw UTF-8 bytes |
| Salt | the 16 raw salt bytes from `KdfParams`, used directly |
| Secret / associated data | empty (absent) |
| `m_cost` / `t_cost` / `p_cost` | from `KdfParams` |

**NFC normalization is the core's job, not the caller's.** The core normalizes the
password to Unicode NFC as its first step, then encodes the result as UTF-8. Callers MUST
NOT normalize the password themselves.

The reason is that `String` in Swift and a string in JavaScript both hold "é" either as
U+00E9 or as U+0065 U+0301, depending on the keyboard, the platform and the source of the
string. The user types the same password, different bytes arrive, a different master key
comes out, and a vault created on one platform will not open on another. Nothing
diagnoses this: the client shows an ordinary "wrong password", and CI stays green because
each platform is self-consistent. Normalizing in one place is the entire point of having
one core.

NFC is idempotent, so a caller who normalizes anyway does no harm — but a caller who
*forgets* reintroduces exactly the failure above, so the rule is stated as an absolute:
pass the password through unchanged.

Vector `kdf.passwordNormalization` pins this: `"café au lait"` in NFC
(`636166c3a9206175206c616974`) and in NFD (`63616665cc81206175206c616974`) MUST produce
the same master key.

**Password lifetime is the caller's job.** The core cannot wipe the caller's memory. It
guarantees only that the password is not copied out, does not appear in any error, and
that its own NFC copy is zeroized. The caller SHOULD hold the password for as short a
time as possible and wipe it where the platform allows.

### 4.4 HKDF domain separation

Both the auth key and the wrap key come from the master key by HKDF, differing **only**
in `info`:

| | |
| --- | --- |
| Function | HKDF (RFC 5869) with SHA-256 |
| Salt | **absent** — per RFC 5869 §2.2 this is 32 zero bytes for SHA-256 |
| IKM | the 32-byte master key |
| Output length (`L`) | 32 bytes |
| `info` for the auth key | ASCII `caesar/auth/v1` (14 bytes, `6361657361722f617574682f7631`) |
| `info` for the wrap key | ASCII `caesar/wrap/v1` (14 bytes, `6361657361722f777261702f7631`) |

Concretely: `AK = HKDF-Expand(HKDF-Extract(zeros(32), MK), "caesar/auth/v1", 32)` and
`KEK = HKDF-Expand(HKDF-Extract(zeros(32), MK), "caesar/wrap/v1", 32)`.

Implementations whose HKDF API takes an optional salt MUST pass "no salt" or 32 zero
bytes — these are the same thing. Passing an empty *byte string* is also the same thing
in RFC 5869 terms, but a library that treats `salt = []` as "skip Extract entirely" is
**not** conforming; check the library before trusting it, and confirm against
`kdf.knownAnswer` in the vectors.

The `info` strings are the whole domain separation. Changing one byte of either makes
every existing vault unreadable.

A third domain, `caesar/share/v1`, exists for team sharing and is specified in §7.2. It
is the only one of the three that uses a non-empty salt.

---

## 5. Envelope (normative)

Every symmetric ciphertext in Caesar is an Envelope.

```
+--------+--------+--------------------+---------------------------------+
| ver(1) | suite(1)|      nonce(24)     |  ciphertext ‖ tag(16)  (≥16)    |
+--------+--------+--------------------+---------------------------------+
0        1        2                   26                                 n
```

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 1 | `PROTOCOL_VERSION` = `0x01` |
| 1 | 1 | `SUITE_ID` = `0x01` |
| 2 | 24 | XChaCha20 nonce, fresh from the CSPRNG on every seal |
| 26 | ≥16 | XChaCha20-Poly1305 ciphertext with the 16-byte Poly1305 tag **appended** |

Minimum total length 42 bytes, which is a valid envelope over empty plaintext.

**AEAD:** XChaCha20-Poly1305, 32-byte key, 24-byte nonce, 16-byte tag.

**AAD:** the two header bytes, i.e. `0x01 0x01`, are passed to the AEAD as additional
authenticated data. Nothing else is.

**Sealing:**
1. Draw 24 fresh CSPRNG bytes as the nonce. A nonce repeat under the same key destroys
   confidentiality for both messages and forges tags; if the CSPRNG fails, an
   implementation MUST return an error and MUST NOT fall back to anything.
2. `ct = XChaCha20-Poly1305-Encrypt(key, nonce, aad = [0x01, 0x01], plaintext)`.
3. Emit `[0x01, 0x01] ‖ nonce ‖ ct`.

**Opening,** in this exact order, failing closed at each step:
1. If `len < 42` → `Truncated { got, need: 42 }`.
2. If `bytes[0] != 1` → `UnsupportedVersion { found, supported: 1 }`.
3. If `bytes[1] != 1` → `UnsupportedSuite { found, supported: 1 }`.
4. Decrypt with `nonce = bytes[2..26]`, `ct = bytes[26..]`, `aad = bytes[0..2]`.
   Any failure → `DecryptionFailed`.

A client MUST reject an unknown version or suite rather than guess a layout. The reason
for the explicit checks in steps 2–3, given that the header is also the AAD, is
diagnostics: a tag failure says only `DecryptionFailed`, which is deliberately
indistinguishable between "wrong key" and "tampered ciphertext" — telling those apart
answers an attacker's questions. `UnsupportedVersion` says something a user can act on.
Implementations MUST keep both the explicit checks and the AAD.

**What the AAD does today versus at v2 (informative).** Today the header is a constant
`[1, 1]`, and every rejection of a swapped header comes from the explicit checks, not
from the tag; the AAD is doing no work that the checks are not already doing. It exists
for version 2. When `decode` starts accepting more than one version, the tag will be what
binds a ciphertext to the header it was sealed under, and stripping the AAD then would
allow a downgrade that the explicit checks cannot see. Implementing v1 without the AAD
produces envelopes that this spec's own vectors reject, so it is not an option — but the
*reason* to keep it is v2.

`envelope.valid` and `envelope.invalid` in the vectors cover all of the above, including
`emptyPlaintext` at exactly 42 bytes.

---

## 6. Wrapping keys under the KEK (normative)

No new format: both are plain Envelopes over 32 bytes of key material, so both are 74
bytes on the wire (`42 + 32`).

| Record | Plaintext | Key |
| --- | --- | --- |
| `encryptedUserKey` | `UK_priv`, 32 raw bytes | KEK |
| `encryptedVaultKey` | `VK`, 32 raw bytes | KEK |

After opening, an implementation MUST check the recovered length is exactly 32 and return
`InvalidKeyLength { got, expected: 32 }` otherwise. Poly1305 does not do this for you: the
plaintext length is whatever was sealed.

### 6.1 The user key MUST be verified against the published public key

Two entry points exist for unwrapping the user key. Clients MUST use the verifying one
wherever `UK_pub` comes from the server:

```
unwrap_user_key_verified(KEK, wrapped, expected_public):
    priv    = open(KEK, wrapped)              → must be 32 bytes
    derived = X25519_base_mult(priv)
    if derived != expected_public: error UserKeyMismatch
```

The comparison is an ordinary (non-constant-time) one: both sides are public.

**Why the tag is not enough.** After clamping, *any* 32 bytes are a valid X25519 secret,
and the public half is recomputed from whatever was decrypted — so a corrupted private key
still produces a self-consistent pair. Poly1305 catches corruption but not **rollback**: a
hostile server that replays the user's own previous, honestly-wrapped `encryptedUserKey`
passes the tag cleanly. Comparing against the published `UK_pub` is the only thing that
distinguishes the current identity from a stale one. Vector
`keyWrapping.invalid.rolledBackUserKey` pins this.

---

## 7. `SealedForRecipient` — sharing a vault key (normative)

### 7.1 Layout

```
+-----------------------------+-------------------------------------------+
|   ephemeralPublic (32)      |   Envelope (§5, ≥42)                      |
+-----------------------------+-------------------------------------------+
0                            32                                          n
```

The envelope's plaintext is the 32-byte vault key, so a well-formed record is
`32 + 42 + 32 = 106` bytes.

### 7.2 Deriving the record key

```
shared          = X25519(ephemeralSecret, recipientPublic)      -- 32 bytes
salt            = ephemeralPublic ‖ recipientPublic             -- 64 bytes
recordKey       = HKDF-SHA256(salt = salt, ikm = shared,
                              info = "caesar/share/v1", L = 32)
```

`caesar/share/v1` is 15 ASCII bytes, `6361657361722f73686172652f7631`. Unlike the auth and
wrap domains (§4.4), this one has a **non-empty** salt.

**Sealing:**
1. Draw a fresh 32-byte ephemeral secret and a fresh 24-byte nonce from the CSPRNG.
2. `ephemeralPublic = X25519_base_mult(ephemeralSecret)`.
3. Compute `shared`. If `shared` is all zeros — equivalently, if the X25519 result is
   non-contributory — **abort** with `DegenerateRecipientKey` (§7.3).
4. Derive `recordKey`, seal the vault key into an Envelope under it.
5. Emit `ephemeralPublic ‖ envelope`.

**Opening:**
1. If `len < 32` → `Truncated { got, need: 32 }`.
2. `ephemeralPublic = sealed[0..32]`.
3. `shared = X25519(recipientSecret, ephemeralPublic)`.
4. `salt = ephemeralPublic ‖ recipientPublic` — the recipient's **own** public key, not
   one taken from the record.
5. Derive `recordKey`, open `sealed[32..]` as an Envelope, require exactly 32 bytes out.

### 7.3 Degenerate recipient keys MUST be rejected on seal

A low-order point as `recipientPublic` yields an all-zero shared secret for *every*
ephemeral key. Both halves of the HKDF salt are public — the ephemeral key sits in the
record itself, the recipient key is published by the server — so with a zero IKM **every
input to the KDF is public**, and anyone who ever sees the record recovers the vault key:
passively, without a single secret byte, from a database dump or a year-old backup.

This is not only an attack. An empty, default, truncated or not-yet-populated `UK_pub`
column produces the identical total leak with no adversary present. Like the Argon2id
floor in §4.2, the check does not detect a malicious party — it bounds the damage from a
degenerate parameter.

Sealing therefore MUST reject it. Opening MUST NOT: a degenerate *ephemeral* key in an
incoming record is harmless (the sender at least held a secret; the recipient's key is
still needed for the salt), and rejecting it would only break interop.

Vector `x25519.invalidRecipients` pins five such keys, including all-zeros, `1`, both
order-8 points and `p−1`.

**Why the recipient's public key is in the salt at all.** X25519 alone binds a ciphertext
to its addressee only while the *ephemeral* key has large order. A small-order point in
the record prefix gives a zero shared secret against any private key, and without the
recipient in the salt one such record would open for every member at once.

### 7.4 The sender is not authenticated (informative)

This is an anonymous sealed box. Anyone who knows a member's `UK_pub` — the server
publishes it — can place a well-formed record in that member's slot, and `open` will
return an attacker-chosen vault key with no error. The member then encrypts new items
under a key the server knows. Rollback merely replays a genuine record; forgery creates a
new one, and nothing in v1 detects it. The fix is a sender signature, which is client
milestone work and deliberately not in this version. Implementations MUST NOT describe
`SealedForRecipient` as authenticated.

---

## 8. `ItemSecret` — the item plaintext (normative)

### 8.1 JSON schema

The plaintext is UTF-8 JSON, no BOM, no trailing newline, **no insignificant whitespace**.

| JSON key | Rust field | Type | Presence |
| --- | --- | --- | --- |
| `v` | `v` | integer 0–255 | required |
| `kind` | `kind` | `"login"` \| `"secureNote"` \| `"creditCard"` | required |
| `title` | `title` | string | required |
| `username` | `username` | string | optional |
| `password` | `password` | string | optional |
| `totpUri` | `totp_uri` | string | optional |
| `website` | `website` | string | optional |
| `notes` | `notes` | string | optional |
| `customFields` | `custom_fields` | array of CustomField | optional |
| `tags` | `tags` | array of string | optional |

CustomField:

| JSON key | Type | Presence |
| --- | --- | --- |
| `label` | string | required |
| `value` | string | required |
| `hidden` | boolean | **always emitted**, defaults to `false` when absent on read |

`v` MUST be written as `ITEM_SCHEMA_VERSION` (= 1).

**Unknown fields are rejected.** Both `ItemSecret` and `CustomField` reject any key not
listed above (`MalformedPlaintext`). A client that met a field from a future version and
silently dropped it would erase that field on the next save. Deserialization stops at the
first unknown key.

### 8.2 Canonicalization — `open_item` then re-serialize MUST be byte-identical

An implementation MUST be able to open an item and write it back producing **the exact
same envelope bytes** given the same nonce. Three rules make that true; all three are easy
to get wrong in a language whose JSON encoder sorts keys or emits nulls.

1. **Field order is the declaration order above, not alphabetical.** Emit exactly:
   `v`, `kind`, `title`, `username`, `password`, `totpUri`, `website`, `notes`,
   `customFields`, `tags`; and inside a custom field: `label`, `value`, `hidden`. A
   TypeScript object literal built in this order round-trips through `JSON.stringify`
   correctly (V8 and JavaScriptCore preserve string-key insertion order); a `Map` or a
   sorted encoder does not. Swift's `JSONEncoder` sorts keys unless
   `outputFormatting` omits `.sortedKeys` **and** the `CodingKeys` order is respected —
   verify against a vector rather than assuming.

2. **Absent optional fields are omitted, never emitted as `null`.** `username`,
   `password`, `totpUri`, `website` and `notes` are omitted when unset. `customFields`
   and `tags` are omitted when the array is **empty**, not emitted as `[]`. Reading
   treats an absent key and an empty array as the same thing — but writing MUST omit,
   because `{"tags":[]}` is four bytes longer and changes the envelope. `hidden` is the
   exception: it is always written, including `"hidden":false`.

3. **String escaping is the JSON minimum.** Escape `"` as `\"`, `\` as `\\`, and the
   C0 control characters; use the short forms `\b \t \n \f \r` where they exist and
   `\u00XX` for the rest. Do **not** escape `/`, and do **not** escape non-ASCII: `Ж` and
   `🔐` are emitted as raw UTF-8, not as `Ж` / a surrogate pair. Vector
   `item.valid.jsonEscaping` pins all of this in one string.

Compare against `item.valid[*].plaintextJson` and `paddedPlaintext` before trusting an
encoder.

### 8.3 Padding

```
plaintext = declaredLength (u32 LE) ‖ json ‖ zero padding
```

`declaredLength` is the length of `json` **in bytes**, not in UTF-16 code units — `.length`
in JavaScript and `.count` in Swift give a different number for any emoji or Cyrillic
character.

The total plaintext length is the **bucket**: the smallest power of two that is at least
512 and at least `4 + len(json)`.

```
bucket(n) = smallest power of two ≥ max(n, 512)
total     = bucket(4 + len(json))
```

Valid totals are therefore 512, 1024, 2048, 4096, … A JSON body of up to 508 bytes lands
in the 512 bucket; 509 bytes lands in 1024. Vector `item.bucketBoundaries` pins both sides
of the 507/508/509 boundary.

**Why 512 and not 256 (informative).** Measured JSON lengths: a bare secure note is 39
bytes, a minimal login 135, a card with two custom fields 220, a full login with TOTP and
notes 266, a login with a complete `otpauth://` URI 334. With a 256-byte minimum the
bucket boundary falls at 252 bytes of JSON — inside the spread of an ordinary login — so
the server would learn "empty or filled" and, worse, would see the *transition*: adding
TOTP or a paragraph of notes moves a specific item from 298 to 554 bytes on a specific
day. 512 covers all five in one bucket. The cost is 554 KiB instead of 298 KiB for a
1000-item vault.

Attachments do not belong in this structure: a two-times-granular bucket is often a unique
fingerprint for a 10 MiB file against a known corpus. They need fixed-size chunking, which
is out of scope here.

**Unpadding** MUST reject, all as `MalformedPlaintext`:
- a plaintext whose length is not a bucket (not a power of two, or smaller than 512);
- a `declaredLength` that exceeds `len(plaintext) - 4`;
- a padding tail containing any non-zero byte.

The zero-tail check is not about a covert channel — the server holds no key, and whoever
can append to the tail already holds the whole plaintext. It catches a *diverging
implementation*: a Swift or TypeScript client that pads with PKCS#7 or random bytes would
otherwise interoperate silently and drift. The cost is one pass over a couple of
kilobytes. The consequence is that any future use of the tail for data is a breaking
format change.

`item.invalid` pins all three rejections.

### 8.4 Two-pass schema-version diagnosis (normative)

This is required behaviour, not an optimization, and a client that reports "malformed" on
the first failure **fails vector `item.invalid.futureSchemaVersion`** with no way to learn
why.

```
open_item(sealed, VK):
    padded = envelope_open(VK, sealed)          -- §5
    json   = unpad(padded)                      -- §8.3
    try strict_parse(json)                      -- deny_unknown_fields, §8.1
        on success -> return the item
        on failure(err):
            probe = lenient_parse(json)         -- a struct with ONLY `v: u8`,
                                                --   unknown fields ALLOWED
            if probe succeeded and probe.v > ITEM_SCHEMA_VERSION:
                return UnsupportedItemSchema { found: probe.v, supported: 1 }
            return MalformedPlaintext(redacted(err))
```

**Why the second pass is unavoidable.** Strict parsing aborts at the first unknown key. If
that key sorts before `v` in the document — and a future field named `attachmentRef` does
— the parser never reaches `v`, so the version is simply not available at the point of
failure. Reading it requires re-parsing the same bytes with a permissive decoder that
looks at nothing but `v`.

**The version number is not redacted.** `MalformedPlaintext` details are redacted (§10),
but `UnsupportedItemSchema.found` carries the raw number. Without it, a client that meets
a newer item reports a redacted string indistinguishable from data corruption, about an
item whose title the user cannot even read. The number is not a secret: it is identical
for every item of that format version.

**Boundary case.** A document with a future `v` that nevertheless parses strictly — because
the newer version only added optional fields and this item has none — is accepted as an
ordinary item. Vector `item.valid.forwardCompatibleSchemaVersion` pins `v: 2` being
accepted; `item.invalid.futureSchemaVersion` pins `v: 2` *plus* an unknown field being
rejected as `UnsupportedItemSchema`. Both must hold at once.

### 8.5 Sealing an item

`seal_item(item, VK)` = `Envelope(VK, pad(serialize(item)))`. An item whose JSON exceeds
`u32::MAX` bytes, or whose bucket exceeds the platform's address space, MUST be rejected
with `PlaintextTooLarge` rather than truncated or panicked on.

---

## 9. Emergency Kit (normative)

The Emergency Kit is the Recovery Key printed for a human to copy off paper.

### 9.1 Encoding

```
payload = RK (32 bytes) ‖ SHA-256(RK)[0..3] (3 bytes)   = 35 bytes = 280 bits
symbols = base32(payload), MSB-first, 5 bits per symbol = 56 symbols
printed = symbols in 8 groups of 7, joined by "-"       = 63 characters
```

The bit packing is big-endian across the payload: accumulate bytes most-significant-first
and emit the top 5 bits at a time. 280 is exactly divisible by 5, so there is no padding
and **every one of the 56 symbols is load-bearing**.

**Alphabet (Crockford Base32):**

```
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

Index 0–31 in that order. `I`, `L`, `O` and `U` are absent — they are misread off paper.

**Checksum.** The trailing 24 bits are the first three bytes of `SHA-256(RK)`. They are
not filler. Without them a typo in any of the 51 key-bearing symbols would decode as `Ok`
with a wrong key, and the failure would surface later as a Poly1305 rejection —
indistinguishable from a corrupted envelope or from the wrong account entirely. On the one
path back into an account, this is the difference between "check group 4" and a blank
refusal. These 24 bits are printed on paper, so their meaning is permanent.

### 9.2 Parsing

1. **Strip separators.** ASCII and Unicode whitespace, `-` (U+002D), the dash range
   U+2010–U+2015, and the minus sign U+2212. A kit pasted out of a word processor arrives
   with non-breaking spaces and autocorrected en-dashes; rejecting those on length would
   report "expected 56 symbols, got 77" to someone who just counted 56 by eye.
2. **Reject non-ASCII.** Any remaining non-ASCII character → `InvalidEmergencyKit`, with
   the character and its group/position. Vector `emergencyKit.rejected.nonLatinLookalike`
   uses a Cyrillic `О` in place of a zero.
3. **Upper-case** the remaining characters. Input is case-insensitive.
4. **Length.** Exactly 56 symbols after stripping, else `InvalidEmergencyKit`.
5. **Substitutions**, applied per symbol before alphabet lookup:

   | Typed | Read as |
   | --- | --- |
   | `I` | `1` |
   | `L` | `1` |
   | `O` | `0` |
   | `U` | *no substitution — rejected* |

   The encoder never emits `I`, `L` or `O`, so they can only come from a human or an OCR
   reading a digit off paper. Rejecting them would show "invalid character" to someone
   holding a correct printout. The substitution is deterministic and cannot turn one valid
   kit into a different valid kit; a genuinely wrong letter is caught by the checksum.
   `U` is deliberately excluded by Crockford with no substitution assigned, and Caesar
   does not invent one — vector `emergencyKit.rejected.letterU`.
6. **Decode** 56 × 5 bits MSB-first into 35 bytes.
7. **Verify** `SHA-256(bytes[0..32])[0..3] == bytes[32..35]`. On mismatch return
   `EmergencyKitChecksumMismatch` — a **distinct** error from `InvalidEmergencyKit`.
   Bindings need to tell "you mistyped" apart from "this key is not for this vault"
   (which surfaces later as `DecryptionFailed`); the kit is syntactically perfect in both
   cases. A mismatch slips through with probability ≈ 1 in 16.7 million.

Pinned kits:

```
RK = 00…00   0000000-0000000-0000000-0000000-0000000-0000000-0000000-006CT3T
RK = FF…FF   ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZTZ5GK
```

---

## 10. Errors (normative)

`protocol/vectors.json` pins the *variant name*, not the message text. A conforming
implementation MUST surface a distinguishable identity for each of these.

| Variant | Raised when |
| --- | --- |
| `UnsupportedVersion { found, supported }` | Envelope byte 0, or `KdfParams` byte 0, is not 1 |
| `UnsupportedSuite { found, supported }` | Envelope byte 1, or `KdfParams` byte 1, is not 1 |
| `Truncated { got, need }` | Buffer shorter than the layout requires |
| `DecryptionFailed` | Poly1305 rejected — wrong key **or** tampering, deliberately not distinguished |
| `PlaintextTooLarge` | Plaintext beyond the ChaCha20 counter (~256 GiB) or an unaddressable bucket |
| `KeyDerivation(String)` | Argon2 itself failed. Detail is **not** redacted: it describes only public server parameters |
| `MalformedPlaintext(String)` | Item JSON or padding is structurally wrong. Detail **is** redacted (below) |
| `UnsupportedItemSchema { found, supported }` | §8.4. `found` is **not** redacted |
| `InvalidKeyLength { got, expected }` | A decrypted key blob is not 32 bytes |
| `InvalidEmergencyKit(String)` | Kit length or alphabet is wrong |
| `EmergencyKitChecksumMismatch` | Kit is well-formed but the checksum disagrees |
| `RandomSourceUnavailable` | Platform CSPRNG failed |
| `UserKeyMismatch` | §6.1 |
| `DegenerateRecipientKey` | §7.3 |
| `KdfParamsOutOfRange { m_cost, t_cost, p_cost }` | §4.2 |

**Redaction.** serde's parse errors name vault fields (`unknown field 'totpSecret'`), and
that string crosses the FFI boundary into host logs. In a zero-knowledge product it MUST
NOT. Release builds therefore replace the detail of `MalformedPlaintext` with a fixed
string. The reference implementation gates the unredacted form behind a non-default
`debug-errors` cargo feature; CI asserts that feature is off. An implementation in another
language MUST redact by default and MUST NOT make the verbose form reachable in a shipped
build.

**Failing closed.** Every failure above MUST return an error. None may fall back, guess a
layout, return a partial item, or panic/abort — under WASM a panic takes the module down,
under UniFFI it takes the host application down.

Three variants cannot be covered by a vector and are deliberately absent from the file:
`PlaintextTooLarge` (needs a ≥4 GiB item), `KeyDerivation` (an internal Argon2 failure;
out-of-range parameters are caught earlier by `KdfParamsOutOfRange`) and
`RandomSourceUnavailable` (a platform CSPRNG failure).

---

## 11. Memory hygiene (normative where stated)

The core zeroizes on drop: all five 32-byte key types, the `KdfParams`-derived material,
the NFC copy of the password, decrypted buffers returned by `open`, every string field of
an item, and the printed Emergency Kit (it *is* the recovery key, in another notation).
Buffers are pre-sized so that a growing `Vec` never leaves a half-written copy of a
password in a freed block.

Three boundaries where the guarantee stops. Implementations MUST document the same
boundaries rather than claim more:

1. **The caller's password buffer.** The core cannot reach it. See §4.3.

2. **serde's unescaping scratch buffer.** On the read path, a JSON string containing any
   escape sequence — `"`, `\`, or a newline — is unescaped into an internal scratch
   `Vec<u8>` owned by the JSON library, which is dropped un-wiped. This is reachable with
   ordinary data: recovery codes one per line in a note, or a password containing a
   backslash. It is a buffer inside a third-party crate and cannot be reached from safe
   Rust; removing it requires a custom reader. The write path has no such buffer.

3. **The FFI boundary.** `Zeroizing` types do not cross UniFFI or wasm-bindgen. Secrets
   are copied once, at the boundary, into memory owned by Swift ARC or the JavaScript GC,
   neither of which wipes. The original is still zeroized on the Rust side; the copy is
   not.

---

## 12. Test vectors (normative)

`protocol/vectors.json` is generated by `cargo run -p caesar-core --bin gen-vectors` and
MUST NOT be edited by hand. CI regenerates it and fails on any diff, and runs it through
four independent runners: Rust, WASM/Bun, Swift, and the UniFFI crate.

Conventions inside the file:

- Every byte field is lowercase hex, no separators.
- Every `invalid` list MUST be **rejected**; `error` is the variant name from §10.
- Envelopes are byte-reproducible given the stated `nonce`. An implementation that cannot
  inject a nonce (both bindings deliberately refuse to expose that door) MUST at minimum
  open each envelope and compare the plaintext.
- `deriveSafe: false` means **do not derive a key from these parameters**:
  `kdf.paramsEncoding.atCeiling` asks Argon2id for 4 GiB and will take down a CI machine
  rather than a test.
- All lengths (`jsonLength`, `paddedLength`, `envelopeLength`) are in **bytes**, never in
  UTF-16 code units.

Sections: `constants`, `kdf` (`knownAnswer`, `paramsEncoding`, `passwordNormalization`,
`invalid`), `envelope` (`layout`, `valid`, `invalid`), `keyWrapping`, `x25519`
(`keyPairs`, `sealVaultKeyFor`, `invalidRecipients`, `invalidSealed`), `item` (`padding`,
`valid`, `invalid`, `bucketBoundaries`), `emergencyKit` (`layout`, `formatted`,
`accepted`, `rejected`).

`x25519.keyPairs.rfc7748Alice` is taken from RFC 7748 §6.1 and lets an implementation
confirm its X25519 against a source outside this project.

---

## 13. Conformance checklist (informative)

A new implementation is conforming when it:

- [ ] derives `kdf.knownAnswer.masterKey`, `.authKey` and `.keyEncryptionKey` from the
      stated password and parameters;
- [ ] gets the same master key from `passwordNormalization.passwordNfc` and `.passwordNfd`;
- [ ] rejects all ten `kdf.invalid` blobs with the stated error;
- [ ] reproduces every `envelope.valid` byte-for-byte given the nonce, or at least opens
      each one, and rejects all six `envelope.invalid`;
- [ ] reproduces `x25519.sealVaultKeyFor.sealed`, opens it, rejects all five
      `invalidRecipients` on seal and all three `invalidSealed` on open;
- [ ] rejects `keyWrapping.invalid.rolledBackUserKey` via the `UK_pub` comparison;
- [ ] serializes every `item.valid` to exactly `plaintextJson` and pads to exactly
      `paddedPlaintext`, and returns `UnsupportedItemSchema` — not `MalformedPlaintext` —
      for `item.invalid.futureSchemaVersion`;
- [ ] lands on the right side of all five `item.bucketBoundaries`;
- [ ] formats all three `emergencyKit.formatted`, accepts all six `accepted`, and rejects
      all five `rejected` with the stated error;
- [ ] fails closed everywhere, and redacts `MalformedPlaintext` detail by default.
