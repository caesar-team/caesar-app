import { describe, expect, test } from "bun:test";
import { generateKey } from "@caesar/crypto";
import { decodeFragment, encodeKeyFragment } from "./fragment.js";

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
