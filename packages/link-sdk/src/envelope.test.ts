import { describe, expect, test } from "bun:test";
import { generateKey } from "@caesar/crypto";
import { openEnvelope, sealEnvelope } from "./envelope.js";
import type { SharePayload } from "./types.js";

async function freshKey() {
  const result = await generateKey();
  if (!result.success) throw new Error(result.error.message);
  return result.data;
}

describe("envelope", () => {
  test("roundtrips a text payload", async () => {
    const dek = await freshKey();
    const payload: SharePayload = { type: "text", data: new TextEncoder().encode("привет") };
    const sealed = await sealEnvelope(payload, dek);
    const opened = await openEnvelope(sealed, dek);
    expect(opened.type).toBe("text");
    expect(new TextDecoder().decode(opened.data)).toBe("привет");
  });

  test("roundtrips a file payload preserving name and mime", async () => {
    const dek = await freshKey();
    const payload: SharePayload = {
      type: "file",
      name: "report.pdf",
      mime: "application/pdf",
      data: new Uint8Array([1, 2, 3, 255]),
    };
    const opened = await openEnvelope(await sealEnvelope(payload, dek), dek);
    expect(opened).toEqual(payload);
  });

  test("fails with a wrong key", async () => {
    const sealed = await sealEnvelope({ type: "text", data: new Uint8Array([1]) }, await freshKey());
    await expect(openEnvelope(sealed, await freshKey())).rejects.toThrow();
  });

  test("rejects unknown envelope version", async () => {
    // sealEnvelope with a doctored serializer is overkill: encrypt a bogus envelope directly
    const dek = await freshKey();
    const { encrypt } = await import("@caesar/crypto");
    const bogus = new TextEncoder().encode(JSON.stringify({ v: 99, type: "text", data: "" }));
    const enc = await encrypt(dek, bogus);
    if (!enc.success) throw new Error("encrypt failed");
    await expect(
      openEnvelope({ ciphertext: enc.data.ciphertext, iv: enc.data.iv }, dek)
    ).rejects.toThrow(/version/i);
  });

  test("rejects a malformed but authenticated payload (fail closed)", async () => {
    const dek = await freshKey();
    const { encrypt } = await import("@caesar/crypto");
    const bogus = new TextEncoder().encode(JSON.stringify({ v: 1, type: "evil", data: "" }));
    const enc = await encrypt(dek, bogus);
    if (!enc.success) throw new Error("encrypt failed");
    await expect(
      openEnvelope({ ciphertext: enc.data.ciphertext, iv: enc.data.iv }, dek)
    ).rejects.toThrow(/unknown type/i);
  });
});
