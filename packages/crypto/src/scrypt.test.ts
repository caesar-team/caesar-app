import { describe, expect, test } from "bun:test";
import { DEFAULT_SCRYPT_PARAMS, deriveKey, deriveKeyWithMetadata } from "./scrypt.js";
import { decrypt, encrypt } from "./symmetric.js";
import type { SymmetricKey } from "./types.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

// Low CPU/memory cost keeps derivation fast in tests; production uses DEFAULT_SCRYPT_PARAMS.
const FAST_PARAMS = { N: 1024, r: 8, p: 1, dkLen: 32 };
const newSalt = () => crypto.getRandomValues(new Uint8Array(16));

// Wraps the raw derived CryptoKey so it can be exercised through encrypt/decrypt. Derived keys are
// non-extractable, so behavioral round-tripping is the only way to assert two derivations match.
function asSymmetricKey(key: CryptoKey): SymmetricKey {
  return { key, algorithm: "AES-GCM", length: 256 };
}

describe("scrypt key derivation", () => {
  test("DEFAULT_SCRYPT_PARAMS matches the OWASP-recommended preset", () => {
    expect(DEFAULT_SCRYPT_PARAMS.N).toBe(131072);
    expect(DEFAULT_SCRYPT_PARAMS.r).toBe(8);
    expect(DEFAULT_SCRYPT_PARAMS.p).toBe(1);
    expect(DEFAULT_SCRYPT_PARAMS.dkLen).toBe(32);
  });

  test("derives an AES-GCM key usable for encryption", async () => {
    const key = asSymmetricKey(await deriveKey("correct horse", newSalt(), FAST_PARAMS));
    const encrypted = await encrypt(key, enc.encode("battery staple"));
    if (!encrypted.success) throw encrypted.error;
    const decrypted = await decrypt(key, encrypted.data);
    if (!decrypted.success) throw decrypted.error;
    expect(dec.decode(decrypted.data)).toBe("battery staple");
  });

  test("is deterministic for the same password, salt and params", async () => {
    const salt = newSalt();
    const first = asSymmetricKey(await deriveKey("pw", salt, FAST_PARAMS));
    const second = asSymmetricKey(await deriveKey("pw", salt, FAST_PARAMS));
    const encrypted = await encrypt(first, enc.encode("shared"));
    if (!encrypted.success) throw encrypted.error;
    const decrypted = await decrypt(second, encrypted.data);
    if (!decrypted.success) throw decrypted.error;
    expect(dec.decode(decrypted.data)).toBe("shared");
  });

  test("different passwords derive different keys", async () => {
    const salt = newSalt();
    const first = asSymmetricKey(await deriveKey("password-1", salt, FAST_PARAMS));
    const second = asSymmetricKey(await deriveKey("password-2", salt, FAST_PARAMS));
    const encrypted = await encrypt(first, enc.encode("secret"));
    if (!encrypted.success) throw encrypted.error;
    const result = await decrypt(second, encrypted.data);
    expect(result.success).toBe(false);
  });

  test("rejects an empty password", async () => {
    await expect(deriveKey("", newSalt(), FAST_PARAMS)).rejects.toThrow("Password cannot be empty");
  });

  test("rejects a salt shorter than 16 bytes", async () => {
    await expect(deriveKey("pw", new Uint8Array(8), FAST_PARAMS)).rejects.toThrow(
      "Salt must be at least 16 bytes"
    );
  });

  test("rejects an N that is not a power of two", async () => {
    await expect(deriveKey("pw", newSalt(), { ...FAST_PARAMS, N: 1000 })).rejects.toThrow(
      "N must be a power of 2"
    );
  });

  test("deriveKeyWithMetadata returns the derivation parameters", async () => {
    const salt = newSalt();
    const result = await deriveKeyWithMetadata("pw", salt, FAST_PARAMS);
    expect(result.algorithm).toBe("scrypt");
    expect(result.params.N).toBe(FAST_PARAMS.N);
    expect(result.params.dkLen).toBe(32);
    expect(result.params.salt).toEqual(salt);
  });
});
