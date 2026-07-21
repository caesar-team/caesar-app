import { describe, expect, test } from "bun:test";
import { generateKey } from "@caesar/crypto";
import {
  decodeFragment,
  encodeKeyFragment,
  encodePasswordFragment,
  unwrapPasswordFragment,
} from "./fragment.js";

async function freshKey() {
  const result = await generateKey();
  if (!result.success) throw new Error(result.error.message);
  return result.data;
}

describe("fragment k. mode", () => {
  test("roundtrips the DEK through the fragment", async () => {
    const dek = await freshKey();
    const fragment = await encodeKeyFragment(dek);
    expect(fragment).toMatch(/^k\.[A-Za-z0-9_-]{43}$/); // 32 bytes → 43 chars
    const decoded = await decodeFragment(fragment);
    if (decoded.mode !== "key") throw new Error("expected key mode");
    const rawA = await crypto.subtle.exportKey("raw", dek.key);
    const rawB = await crypto.subtle.exportKey("raw", decoded.dek.key);
    expect(new Uint8Array(rawB)).toEqual(new Uint8Array(rawA));
  });

  test("rejects malformed fragments", async () => {
    await expect(decodeFragment("x.abc")).rejects.toThrow();
    await expect(decodeFragment("k.tooshort")).rejects.toThrow();
  });
});

describe("fragment p. mode", () => {
  // scrypt N=2^17 takes ~1s per derivation — keep the password fixed, derive sparingly
  test("wraps and unwraps the DEK with a password", async () => {
    const dek = await freshKey();
    const { fragment, kdf } = await encodePasswordFragment(dek, "correct horse");
    expect(fragment).toMatch(/^p\.[A-Za-z0-9_-]+$/);
    expect(kdf.kdf).toBe("scrypt");
    const decoded = await decodeFragment(fragment);
    if (decoded.mode !== "password") throw new Error("expected password mode");
    const unwrapped = await unwrapPasswordFragment(decoded.wrapped, "correct horse", kdf);
    const rawA = await crypto.subtle.exportKey("raw", dek.key);
    const rawB = await crypto.subtle.exportKey("raw", unwrapped.key);
    expect(new Uint8Array(rawB)).toEqual(new Uint8Array(rawA));
  }, 30000);

  test("fails with the wrong password", async () => {
    const dek = await freshKey();
    const { fragment, kdf } = await encodePasswordFragment(dek, "правильный пароль");
    const decoded = await decodeFragment(fragment);
    if (decoded.mode !== "password") throw new Error("expected password mode");
    await expect(unwrapPasswordFragment(decoded.wrapped, "wrong", kdf)).rejects.toThrow();
  }, 30000);

  test("honors custom scrypt params and still roundtrips", async () => {
    const dek = await freshKey();
    const { fragment, kdf } = await encodePasswordFragment(dek, "fast vector pw", { N: 16384 });
    expect(kdf.N).toBe(16384);
    const decoded = await decodeFragment(fragment);
    if (decoded.mode !== "password") throw new Error("expected password mode");
    const unwrapped = await unwrapPasswordFragment(decoded.wrapped, "fast vector pw", kdf);
    const rawA = await crypto.subtle.exportKey("raw", dek.key);
    const rawB = await crypto.subtle.exportKey("raw", unwrapped.key);
    expect(new Uint8Array(rawB)).toEqual(new Uint8Array(rawA));
  }, 30000);

  test("rejects an untrusted KdfMeta with an out-of-bounds scrypt N (fail fast, no DoS)", async () => {
    // A malicious server could return a huge N to exhaust the recipient's memory
    // during scrypt. The bound must reject BEFORE any derivation is attempted.
    const dek = await freshKey();
    const { fragment, kdf } = await encodePasswordFragment(dek, "pw");
    const decoded = await decodeFragment(fragment);
    if (decoded.mode !== "password") throw new Error("expected password mode");
    const hostileKdf = { ...kdf, N: 2 ** 30 };
    await expect(unwrapPasswordFragment(decoded.wrapped, "pw", hostileKdf)).rejects.toThrow(
      /N out of bounds/
    );
  }, 30000);
});
