/**
 * Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
 *
 * Provides ECDH key agreement using Web Crypto API.
 * Default configuration: P-256 curve (NIST secp256r1)
 *
 * @module ecdh
 */

import type {
  EcdhKeyPair,
  EcKeyGenParams,
  SharedSecret,
  EcdhParams,
} from "./types.js";

/**
 * Default ECDH curve (P-256 / secp256r1)
 */
const DEFAULT_CURVE = "P-256" as const;

/**
 * Generates an ECDH key pair for key exchange
 *
 * @param curve - Named curve to use (P-256, P-384, or P-521). Default: P-256
 * @returns Promise resolving to ECDH key pair
 *
 * @example
 * ```ts
 * // Alice generates her key pair
 * const aliceKeyPair = await generateEcdhKeyPair();
 *
 * // Bob generates his key pair
 * const bobKeyPair = await generateEcdhKeyPair();
 *
 * // They exchange public keys and derive shared secret
 * const aliceSecret = await deriveSharedSecret(
 *   aliceKeyPair.privateKey,
 *   bobKeyPair.publicKey
 * );
 * const bobSecret = await deriveSharedSecret(
 *   bobKeyPair.privateKey,
 *   aliceKeyPair.publicKey
 * );
 * // aliceSecret.key === bobSecret.key
 * ```
 *
 * @remarks
 * Curve security levels:
 * - P-256: ~128-bit security (recommended for most use cases)
 * - P-384: ~192-bit security
 * - P-521: ~256-bit security
 */
export async function generateEcdhKeyPair(
  curve: "P-256" | "P-384" | "P-521" = DEFAULT_CURVE,
): Promise<EcdhKeyPair> {
  try {
    const algorithm: EcKeyGenParams = {
      name: "ECDH",
      namedCurve: curve,
    };

    const cryptoKeyPair = await crypto.subtle.generateKey(
      algorithm,
      true, // extractable
      ["deriveKey", "deriveBits"],
    );

    return {
      publicKey: cryptoKeyPair.publicKey,
      privateKey: cryptoKeyPair.privateKey,
      algorithm: "ECDH",
      namedCurve: curve,
    };
  } catch (error) {
    throw new Error(
      `Failed to generate ECDH key pair: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Derives a shared secret from your private key and their public key
 *
 * @param privateKey - Your ECDH private key
 * @param publicKey - Their ECDH public key
 * @returns Promise resolving to shared secret
 *
 * @throws Error if keys are incompatible or derivation fails
 *
 * @example
 * ```ts
 * const sharedSecret = await deriveSharedSecret(
 *   myKeyPair.privateKey,
 *   theirPublicKey
 * );
 *
 * // Use shared secret to derive symmetric encryption key
 * const aesKey = await deriveAesKeyFromSecret(sharedSecret.key);
 * ```
 *
 * @security
 * The shared secret should NOT be used directly for encryption.
 * Use it with a KDF (like HKDF) to derive encryption keys.
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<SharedSecret> {
  try {
    const algorithm: EcdhParams = {
      name: "ECDH",
      public: publicKey,
    };

    // Extract curve from the private key
    const keyAlgorithm = privateKey.algorithm as EcKeyAlgorithm;
    const curve = keyAlgorithm.namedCurve as "P-256" | "P-384" | "P-521";

    // Derive raw shared secret bits
    const sharedKey = await crypto.subtle.deriveKey(
      algorithm,
      privateKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      true, // extractable
      ["encrypt", "decrypt"],
    );

    return {
      key: sharedKey,
      algorithm: "ECDH",
      namedCurve: curve,
    };
  } catch (error) {
    throw new Error(
      `Failed to derive shared secret: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Derives raw shared secret bits (for custom KDF)
 *
 * @param privateKey - Your ECDH private key
 * @param publicKey - Their ECDH public key
 * @param length - Number of bits to derive (optional, defaults to curve size)
 * @returns Promise resolving to raw shared secret as Uint8Array
 *
 * @example
 * ```ts
 * const sharedBits = await deriveSharedSecretBits(
 *   myKeyPair.privateKey,
 *   theirPublicKey
 * );
 *
 * // Use with your own KDF
 * const derivedKey = await hkdf(sharedBits, salt, info);
 * ```
 */
export async function deriveSharedSecretBits(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  length?: number,
): Promise<Uint8Array> {
  try {
    const algorithm: EcdhParams = {
      name: "ECDH",
      public: publicKey,
    };

    // Determine bit length from curve if not specified
    const keyAlgorithm = privateKey.algorithm as EcKeyAlgorithm;
    const curve = keyAlgorithm.namedCurve;
    const defaultLength = getCurveBitLength(curve);

    const bits = await crypto.subtle.deriveBits(
      algorithm,
      privateKey,
      length ?? defaultLength,
    );

    return new Uint8Array(bits);
  } catch (error) {
    throw new Error(
      `Failed to derive shared secret bits: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Exports an ECDH public key to raw format (base64-encoded)
 *
 * @param publicKey - ECDH public key to export
 * @returns Promise resolving to base64-encoded raw key
 *
 * @example
 * ```ts
 * const exportedKey = await exportEcdhPublicKey(keyPair.publicKey);
 * // Share exportedKey with peer for key exchange
 * ```
 */
export async function exportEcdhPublicKey(
  publicKey: CryptoKey,
): Promise<string> {
  try {
    const exported = await crypto.subtle.exportKey("raw", publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
    return base64;
  } catch (error) {
    throw new Error(
      `Failed to export ECDH public key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Exports an ECDH private key to PKCS#8 format (base64-encoded)
 *
 * @param privateKey - ECDH private key to export
 * @returns Promise resolving to base64-encoded PKCS#8 key
 *
 * @example
 * ```ts
 * const exportedKey = await exportEcdhPrivateKey(keyPair.privateKey);
 * // Store exportedKey securely (encrypted)
 * ```
 *
 * @security
 * Private keys should be encrypted before storage
 */
export async function exportEcdhPrivateKey(
  privateKey: CryptoKey,
): Promise<string> {
  try {
    const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
    return base64;
  } catch (error) {
    throw new Error(
      `Failed to export ECDH private key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Imports an ECDH public key from raw format
 *
 * @param keyData - Base64-encoded raw public key
 * @param curve - Named curve. Default: P-256
 * @returns Promise resolving to CryptoKey
 *
 * @example
 * ```ts
 * const publicKey = await importEcdhPublicKey(exportedKey);
 * const sharedSecret = await deriveSharedSecret(
 *   myPrivateKey,
 *   publicKey
 * );
 * ```
 */
export async function importEcdhPublicKey(
  keyData: string,
  curve: "P-256" | "P-384" | "P-521" = DEFAULT_CURVE,
): Promise<CryptoKey> {
  try {
    const binaryData = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));

    const publicKey = await crypto.subtle.importKey(
      "raw",
      binaryData,
      {
        name: "ECDH",
        namedCurve: curve,
      },
      true,
      [],
    );

    return publicKey;
  } catch (error) {
    throw new Error(
      `Failed to import ECDH public key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Imports an ECDH private key from PKCS#8 format
 *
 * @param keyData - Base64-encoded PKCS#8 private key
 * @param curve - Named curve. Default: P-256
 * @returns Promise resolving to CryptoKey
 *
 * @example
 * ```ts
 * const privateKey = await importEcdhPrivateKey(exportedKey);
 * const sharedSecret = await deriveSharedSecret(
 *   privateKey,
 *   theirPublicKey
 * );
 * ```
 */
export async function importEcdhPrivateKey(
  keyData: string,
  curve: "P-256" | "P-384" | "P-521" = DEFAULT_CURVE,
): Promise<CryptoKey> {
  try {
    const binaryData = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));

    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      binaryData,
      {
        name: "ECDH",
        namedCurve: curve,
      },
      true,
      ["deriveKey", "deriveBits"],
    );

    return privateKey;
  } catch (error) {
    throw new Error(
      `Failed to import ECDH private key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Helper to get curve bit length
 */
function getCurveBitLength(curve: string): number {
  switch (curve) {
    case "P-256":
      return 256;
    case "P-384":
      return 384;
    case "P-521":
      return 521;
    default:
      return 256; // default to P-256
  }
}
