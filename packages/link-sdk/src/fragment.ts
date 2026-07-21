import type { SymmetricKey } from "@caesar/crypto";
import { fromBase64Url, toBase64Url } from "./base64url.js";

const DEK_LENGTH = 32;

export type DecodedFragment =
  | { mode: "key"; dek: SymmetricKey }
  | { mode: "password"; wrapped: Uint8Array };

async function importDek(raw: Uint8Array): Promise<SymmetricKey> {
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
  return { key, algorithm: "AES-GCM", length: 256 };
}

export async function encodeKeyFragment(dek: SymmetricKey): Promise<string> {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", dek.key));
  return `k.${toBase64Url(raw)}`;
}

export async function decodeFragment(fragment: string): Promise<DecodedFragment> {
  const dot = fragment.indexOf(".");
  if (dot === -1) throw new Error("Malformed fragment: missing mode prefix");
  const mode = fragment.slice(0, dot);
  const body = fromBase64Url(fragment.slice(dot + 1));
  if (mode === "k") {
    if (body.length !== DEK_LENGTH) throw new Error("Malformed fragment: bad DEK length");
    return { mode: "key", dek: await importDek(body) };
  }
  throw new Error(`Malformed fragment: unknown mode "${mode}"`);
}
