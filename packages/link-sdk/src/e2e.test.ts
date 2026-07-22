import { describe, expect, test } from "bun:test";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import { buildShareUrl, parseShareUrl } from "./link.js";
import { createShare, openShare } from "./share.js";
import type { KdfMeta, SealedBlob, ShareBundle } from "./types.js";

const encode = (text: string): Uint8Array => new TextEncoder().encode(text);
const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** The only fields a real, zero-knowledge server ever sees for a share. */
interface StoredShare {
  id: string;
  ciphertext: string; // base64url
  iv: string; // base64url
  kdf: KdfMeta | null;
}

const BASE_URL = "https://link.example";

/** Models the sender "uploading" a share: stores only server-visible fields. */
function upload(server: Map<string, StoredShare>, id: string, bundle: ShareBundle): string {
  server.set(id, {
    id,
    ciphertext: toBase64Url(bundle.blob.ciphertext),
    iv: toBase64Url(bundle.blob.iv),
    kdf: bundle.kdf ?? null,
  });
  return buildShareUrl(BASE_URL, id, bundle.fragment);
}

/** Models the recipient reconstructing the sealed blob from the stored record. */
function toBlob(stored: StoredShare): SealedBlob {
  return { ciphertext: fromBase64Url(stored.ciphertext), iv: fromBase64Url(stored.iv) };
}

describe("end-to-end sender → store → recipient", () => {
  test("link-only (k.) full roundtrip", async () => {
    const server = new Map<string, StoredShare>();
    const bundle = await createShare({ type: "text", data: encode("meet at 6") });
    const url = upload(server, "abc123", bundle);

    const { id, fragment } = parseShareUrl(url);
    const stored = server.get(id);
    if (stored === undefined) throw new Error("share not found on server");
    const payload = await openShare({
      blob: toBlob(stored),
      fragment,
      kdf: stored.kdf ?? undefined,
    });

    expect(decode(payload.data)).toBe("meet at 6");
  });

  test("password (p.) full roundtrip with password over a separate channel", async () => {
    const server = new Map<string, StoredShare>();
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const bundle = await createShare(
      { type: "file", name: "secret.txt", mime: "text/plain", data: bytes },
      { password: "hunter2" }
    );
    const url = upload(server, "pw001", bundle);
    expect(server.get("pw001")?.kdf).not.toBeNull();

    const { id, fragment } = parseShareUrl(url);
    const stored = server.get(id);
    if (stored === undefined || stored.kdf === null) throw new Error("share not found on server");
    const payload = await openShare({
      blob: toBlob(stored),
      fragment,
      password: "hunter2",
      kdf: stored.kdf,
    });

    expect(payload.name).toBe("secret.txt");
    expect(payload.mime).toBe("text/plain");
    expect(new Uint8Array(payload.data)).toEqual(bytes);

    await expect(openShare({ blob: toBlob(stored), fragment, kdf: stored.kdf })).rejects.toThrow();
  }, 60000);

  test("zero-knowledge invariant: stored record leaks no plaintext or secret", async () => {
    const server = new Map<string, StoredShare>();
    const bundle = await createShare(
      { type: "file", name: "payroll.xlsx", data: encode("SSN:12345") },
      { password: "hunter2" }
    );
    upload(server, "zk001", bundle);

    const stored = server.get("zk001");
    if (stored === undefined) throw new Error("share not found on server");
    const serialized = JSON.stringify(stored);

    expect(serialized).not.toContain("payroll.xlsx");
    expect(serialized).not.toContain("SSN:12345");
    // The fragment is the zero-knowledge secret and must never reach the server.
    expect(serialized).not.toContain(bundle.fragment);
  }, 60000);
});
