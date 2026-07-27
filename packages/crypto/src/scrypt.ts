/**
 * Scrypt key derivation implementation
 * Uses @noble/hashes for secure key derivation from passwords
 */

import { scrypt } from "@noble/hashes/scrypt.js";
import type { DerivedKey, ScryptParams } from "./types.js";

/**
 * Default scrypt parameters for key derivation
 * Based on OWASP recommendations for 2024+
 *
 * - N=2^17 (131072): CPU/memory cost parameter
 * - r=8: Block size parameter
 * - p=1: Parallelization parameter
 * - dkLen=32: 256-bit derived key length
 *
 * These provide strong security while being reasonable on modern hardware.
 * Takes ~100-500ms on typical devices.
 */
export const DEFAULT_SCRYPT_PARAMS = {
  N: 131072, // 2^17
  r: 8,
  p: 1,
  dkLen: 32,
} as const;

/**
 * Derives a cryptographic key from a password using scrypt algorithm
 *
 * @param password - User password (will be UTF-8 encoded)
 * @param salt - Cryptographic salt (recommended: 16+ bytes from crypto.getRandomValues)
 * @param params - Optional scrypt parameters (defaults to secure preset)
 * @returns Promise resolving to CryptoKey suitable for encryption
 *
 * @throws {Error} If parameters are invalid or key derivation fails
 *
 * @example
 * ```ts
 * const salt = crypto.getRandomValues(new Uint8Array(16));
 * const key = await deriveKey("user-password", salt);
 * // Use key for AES-GCM encryption
 * ```
 *
 * @example Custom parameters for higher security
 * ```ts
 * const key = await deriveKey("password", salt, {
 *   N: 262144, // 2^18, slower but more secure
 *   r: 8,
 *   p: 1,
 *   dkLen: 32
 * });
 * ```
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  params?: Partial<Omit<ScryptParams, "salt">>
): Promise<CryptoKey> {
  // Validate inputs
  if (!password || password.length === 0) {
    throw new Error("Password cannot be empty");
  }

  if (!salt || salt.length < 16) {
    throw new Error("Salt must be at least 16 bytes");
  }

  // Merge with defaults
  const { N, r, p, dkLen } = {
    ...DEFAULT_SCRYPT_PARAMS,
    ...params,
  };

  // Validate scrypt parameters
  if (!Number.isInteger(N) || N <= 0 || (N & (N - 1)) !== 0) {
    throw new Error("N must be a power of 2");
  }

  if (!Number.isInteger(r) || r <= 0) {
    throw new Error("r must be a positive integer");
  }

  if (!Number.isInteger(p) || p <= 0) {
    throw new Error("p must be a positive integer");
  }

  if (!Number.isInteger(dkLen) || dkLen <= 0) {
    throw new Error("dkLen must be a positive integer");
  }

  try {
    // Encode password as UTF-8
    const passwordBytes = new TextEncoder().encode(password);

    // Derive key material using scrypt
    const derivedKeyMaterial = scrypt(passwordBytes, salt, {
      N,
      r,
      p,
      dkLen,
    });

    // Import as CryptoKey for Web Crypto API usage
    // Cast bridges the TS lib.dom widening (Uint8Array<ArrayBufferLike> vs the ArrayBuffer-backed BufferSource).
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      derivedKeyMaterial as BufferSource,
      { name: "AES-GCM" },
      false, // Not extractable for security
      ["encrypt", "decrypt"]
    );

    return cryptoKey;
  } catch (error) {
    throw new Error(
      `Key derivation failed: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}

/**
 * Derives key and returns full metadata for storage/verification
 *
 * @param password - User password
 * @param salt - Cryptographic salt
 * @param params - Optional scrypt parameters
 * @returns Promise resolving to DerivedKey with metadata
 *
 * @example
 * ```ts
 * const salt = crypto.getRandomValues(new Uint8Array(16));
 * const result = await deriveKeyWithMetadata("password", salt);
 *
 * // Store result.params with encrypted data for later verification
 * // result.key can be used for encryption
 * ```
 */
export async function deriveKeyWithMetadata(
  password: string,
  salt: Uint8Array,
  params?: Partial<Omit<ScryptParams, "salt">>
): Promise<DerivedKey> {
  const mergedParams = {
    ...DEFAULT_SCRYPT_PARAMS,
    ...params,
  };

  const key = await deriveKey(password, salt, params);

  return {
    key,
    algorithm: "scrypt",
    params: {
      salt,
      ...mergedParams,
    },
  };
}
