/**
 * RSA-OAEP Asymmetric Encryption
 *
 * Provides RSA-OAEP encryption/decryption using Web Crypto API.
 * Default configuration: 4096-bit keys with SHA-256 hash.
 *
 * @module asymmetric
 */

import type {
  RsaKeyPair,
  RsaKeyGenParams,
  RsaOaepParams,
  CryptoResult,
  HashAlgorithm,
} from "./types.js";

/**
 * Default RSA key generation parameters
 */
const DEFAULT_RSA_PARAMS = {
  modulusLength: 4096 as const,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
  hash: "SHA-256" as HashAlgorithm,
};

/**
 * Generates an RSA-OAEP key pair for asymmetric encryption
 *
 * @param modulusLength - Key size in bits (2048, 3072, or 4096). Default: 4096
 * @param hash - Hash algorithm to use. Default: SHA-256
 * @returns Promise resolving to RSA key pair
 *
 * @example
 * ```ts
 * const keyPair = await generateRsaKeyPair(4096);
 * // Use keyPair.publicKey for encryption
 * // Use keyPair.privateKey for decryption
 * ```
 */
export async function generateRsaKeyPair(
  modulusLength: 2048 | 3072 | 4096 = DEFAULT_RSA_PARAMS.modulusLength,
  hash: HashAlgorithm = DEFAULT_RSA_PARAMS.hash,
): Promise<RsaKeyPair> {
  try {
    const algorithm: RsaKeyGenParams = {
      name: "RSA-OAEP",
      modulusLength,
      publicExponent: DEFAULT_RSA_PARAMS.publicExponent,
      hash,
    };

    const cryptoKeyPair = await crypto.subtle.generateKey(
      algorithm,
      true, // extractable
      ["encrypt", "decrypt"],
    );

    return {
      publicKey: cryptoKeyPair.publicKey,
      privateKey: cryptoKeyPair.privateKey,
      algorithm: "RSA-OAEP",
      modulusLength,
    };
  } catch (error) {
    throw new Error(
      `Failed to generate RSA key pair: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Encrypts data with an RSA public key using RSA-OAEP
 *
 * @param publicKey - RSA public key for encryption
 * @param data - Data to encrypt (Uint8Array)
 * @param hash - Hash algorithm (must match key generation). Default: SHA-256
 * @returns Promise resolving to encrypted ciphertext
 *
 * @throws Error if encryption fails or data exceeds key size limits
 *
 * @example
 * ```ts
 * const plaintext = new TextEncoder().encode("Secret message");
 * const ciphertext = await encryptWithPublicKey(publicKey, plaintext);
 * ```
 *
 * @remarks
 * Maximum data size depends on key size and hash algorithm:
 * - 2048-bit key with SHA-256: ~190 bytes
 * - 3072-bit key with SHA-256: ~318 bytes
 * - 4096-bit key with SHA-256: ~446 bytes
 * For larger data, encrypt a symmetric key instead (hybrid encryption)
 */
export async function encryptWithPublicKey(
  publicKey: CryptoKey,
  data: Uint8Array,
  hash: HashAlgorithm = DEFAULT_RSA_PARAMS.hash,
): Promise<Uint8Array> {
  try {
    const algorithm: RsaOaepParams = {
      name: "RSA-OAEP",
      hash,
    };

    const ciphertext = await crypto.subtle.encrypt(
      algorithm,
      publicKey,
      data,
    );

    return new Uint8Array(ciphertext);
  } catch (error) {
    throw new Error(
      `Failed to encrypt with public key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Decrypts data with an RSA private key using RSA-OAEP
 *
 * @param privateKey - RSA private key for decryption
 * @param ciphertext - Encrypted data to decrypt
 * @param hash - Hash algorithm (must match encryption). Default: SHA-256
 * @returns Promise resolving to decrypted plaintext
 *
 * @throws Error if decryption fails or ciphertext is invalid
 *
 * @example
 * ```ts
 * const plaintext = await decryptWithPrivateKey(privateKey, ciphertext);
 * const message = new TextDecoder().decode(plaintext);
 * ```
 */
export async function decryptWithPrivateKey(
  privateKey: CryptoKey,
  ciphertext: Uint8Array,
  hash: HashAlgorithm = DEFAULT_RSA_PARAMS.hash,
): Promise<Uint8Array> {
  try {
    const algorithm: RsaOaepParams = {
      name: "RSA-OAEP",
      hash,
    };

    const plaintext = await crypto.subtle.decrypt(
      algorithm,
      privateKey,
      ciphertext,
    );

    return new Uint8Array(plaintext);
  } catch (error) {
    throw new Error(
      `Failed to decrypt with private key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Exports an RSA public key to SPKI format (base64-encoded)
 *
 * @param publicKey - RSA public key to export
 * @returns Promise resolving to base64-encoded SPKI key
 *
 * @example
 * ```ts
 * const exportedKey = await exportPublicKey(keyPair.publicKey);
 * // Share exportedKey with others for encryption
 * ```
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  try {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
    return base64;
  } catch (error) {
    throw new Error(
      `Failed to export public key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Exports an RSA private key to PKCS#8 format (base64-encoded)
 *
 * @param privateKey - RSA private key to export
 * @returns Promise resolving to base64-encoded PKCS#8 key
 *
 * @example
 * ```ts
 * const exportedKey = await exportPrivateKey(keyPair.privateKey);
 * // Store exportedKey securely (encrypted)
 * ```
 *
 * @security
 * Private keys should be encrypted before storage using symmetric encryption
 */
export async function exportPrivateKey(privateKey: CryptoKey): Promise<string> {
  try {
    const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
    const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
    return base64;
  } catch (error) {
    throw new Error(
      `Failed to export private key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Imports an RSA public key from SPKI format
 *
 * @param keyData - Base64-encoded SPKI public key
 * @param hash - Hash algorithm. Default: SHA-256
 * @returns Promise resolving to CryptoKey
 *
 * @example
 * ```ts
 * const publicKey = await importPublicKey(exportedKey);
 * const ciphertext = await encryptWithPublicKey(publicKey, data);
 * ```
 */
export async function importPublicKey(
  keyData: string,
  hash: HashAlgorithm = DEFAULT_RSA_PARAMS.hash,
): Promise<CryptoKey> {
  try {
    const binaryData = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));

    const publicKey = await crypto.subtle.importKey(
      "spki",
      binaryData,
      {
        name: "RSA-OAEP",
        hash,
      },
      true,
      ["encrypt"],
    );

    return publicKey;
  } catch (error) {
    throw new Error(
      `Failed to import public key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Imports an RSA private key from PKCS#8 format
 *
 * @param keyData - Base64-encoded PKCS#8 private key
 * @param hash - Hash algorithm. Default: SHA-256
 * @returns Promise resolving to CryptoKey
 *
 * @example
 * ```ts
 * const privateKey = await importPrivateKey(exportedKey);
 * const plaintext = await decryptWithPrivateKey(privateKey, ciphertext);
 * ```
 */
export async function importPrivateKey(
  keyData: string,
  hash: HashAlgorithm = DEFAULT_RSA_PARAMS.hash,
): Promise<CryptoKey> {
  try {
    const binaryData = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));

    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      binaryData,
      {
        name: "RSA-OAEP",
        hash,
      },
      true,
      ["decrypt"],
    );

    return privateKey;
  } catch (error) {
    throw new Error(
      `Failed to import private key: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}
