import { DEFAULT_SCRYPT_PARAMS, decrypt, deriveKey, encrypt, type SymmetricKey } from "@caesar/crypto";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import type { KdfMeta } from "./types.js";

const DEK_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

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
  if (mode === "p") {
    if (body.length !== IV_LENGTH + 48) throw new Error("Malformed fragment: bad wrapped DEK length");
    return { mode: "password", wrapped: body };
  }
  throw new Error(`Malformed fragment: unknown mode "${mode}"`);
}

async function deriveKek(password: string, saltB64: string, params: KdfMeta): Promise<SymmetricKey> {
  const salt = fromBase64Url(saltB64);
  const key = await deriveKey(password, salt, {
    N: params.N,
    r: params.r,
    p: params.p,
    dkLen: params.dkLen,
  });
  return { key, algorithm: "AES-GCM", length: 256 };
}

export async function encodePasswordFragment(
  dek: SymmetricKey,
  password: string
): Promise<{ fragment: string; kdf: KdfMeta }> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const kdf: KdfMeta = { kdf: "scrypt", salt: toBase64Url(salt), ...DEFAULT_SCRYPT_PARAMS };
  const kek = await deriveKek(password, kdf.salt, kdf);
  const rawDek = new Uint8Array(await crypto.subtle.exportKey("raw", dek.key));
  const result = await encrypt(kek, rawDek);
  if (!result.success) throw new Error(`DEK wrap failed: ${result.error.message}`);
  const body = new Uint8Array(result.data.iv.length + result.data.ciphertext.length);
  body.set(result.data.iv, 0);
  body.set(result.data.ciphertext, result.data.iv.length);
  return { fragment: `p.${toBase64Url(body)}`, kdf };
}

export async function unwrapPasswordFragment(
  wrapped: Uint8Array,
  password: string,
  kdf: KdfMeta
): Promise<SymmetricKey> {
  const kek = await deriveKek(password, kdf.salt, kdf);
  const iv = wrapped.slice(0, IV_LENGTH);
  const ciphertext = wrapped.slice(IV_LENGTH);
  const result = await decrypt(kek, { ciphertext, iv, algorithm: "AES-GCM" });
  if (!result.success) throw new Error("DEK unwrap failed: wrong password or corrupted fragment");
  return importDek(result.data);
}
