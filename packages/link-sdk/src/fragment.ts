import {
  DEFAULT_SCRYPT_PARAMS,
  type SymmetricKey,
  decrypt,
  deriveKey,
  encrypt,
} from "@caesar/crypto";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import type { KdfMeta } from "./types.js";

const DEK_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const GCM_TAG_LENGTH = 16;
const WRAPPED_DEK_LENGTH = DEK_LENGTH + GCM_TAG_LENGTH;

/** Absolute sanity ceiling on the scrypt cost parameter N (must also be a power of two). */
const MAX_SCRYPT_N = 2 ** 20;

/**
 * Ceiling on scrypt's working-memory footprint, ≈ 128 * N * r bytes. In the
 * zero-knowledge model the server is untrusted; a crafted KdfMeta could pick
 * in-range-but-hostile factors (e.g. N=2^20, r=32 ≈ 4 GiB) to OOM the
 * recipient's tab before any decryption runs. Bounding the *product* — not
 * each factor alone — caps memory at 1 GiB while leaving the honest default
 * (N=2^17, r=8 ≈ 128 MiB) ample headroom.
 */
const MAX_SCRYPT_MEMORY_BYTES = 2 ** 30;

/**
 * Validates scrypt parameters supplied by the (untrusted) server so a crafted
 * KdfMeta fails fast with a thrown error rather than exhausting client memory.
 */
function assertSaneKdf(kdf: KdfMeta): void {
  if (kdf.kdf !== "scrypt") throw new Error(`Unsupported KDF: ${kdf.kdf}`);
  if (kdf.dkLen !== DEK_LENGTH) throw new Error(`Unsupported scrypt dkLen: ${kdf.dkLen}`);
  if (!Number.isInteger(kdf.N) || kdf.N < 2 || kdf.N > MAX_SCRYPT_N || (kdf.N & (kdf.N - 1)) !== 0) {
    throw new Error(`scrypt N out of bounds: ${kdf.N}`);
  }
  if (!Number.isInteger(kdf.r) || kdf.r < 1 || kdf.r > 32) {
    throw new Error(`scrypt r out of bounds: ${kdf.r}`);
  }
  if (!Number.isInteger(kdf.p) || kdf.p < 1 || kdf.p > 16) {
    throw new Error(`scrypt p out of bounds: ${kdf.p}`);
  }
  if (128 * kdf.N * kdf.r > MAX_SCRYPT_MEMORY_BYTES) {
    throw new Error(`scrypt cost too high: N=${kdf.N} r=${kdf.r} exceeds memory ceiling`);
  }
}

export type DecodedFragment =
  | { mode: "key"; dek: SymmetricKey }
  | { mode: "password"; wrapped: Uint8Array };

async function importDek(raw: Uint8Array): Promise<SymmetricKey> {
  // A Uint8Array is a valid BufferSource at runtime; the cast bridges the TS lib.dom
  // widening (Uint8Array<ArrayBufferLike> vs the ArrayBuffer-backed BufferSource).
  const key = await crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, true, [
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
    if (body.length !== IV_LENGTH + WRAPPED_DEK_LENGTH) {
      throw new Error("Malformed fragment: bad wrapped DEK length");
    }
    return { mode: "password", wrapped: body };
  }
  throw new Error(`Malformed fragment: unknown mode "${mode}"`);
}

async function deriveKek(
  password: string,
  saltB64: string,
  params: KdfMeta
): Promise<SymmetricKey> {
  assertSaneKdf(params);
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
  password: string,
  params?: Partial<Pick<KdfMeta, "N" | "r" | "p">>
): Promise<{ fragment: string; kdf: KdfMeta }> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const kdf: KdfMeta = {
    kdf: "scrypt",
    salt: toBase64Url(salt),
    ...DEFAULT_SCRYPT_PARAMS,
    ...params,
  };
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
