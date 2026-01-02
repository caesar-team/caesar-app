/**
 * AES-GCM symmetric encryption implementation
 * Uses Web Crypto API for secure encryption/decryption
 *
 * @module symmetric
 */

import type {
  AesGcmParams,
  AesKeyGenParams,
  CryptoError,
  CryptoResult,
  EncryptedData,
  SymmetricKey,
} from "./types.js";

/**
 * Default AES key length (256 bits for maximum security)
 */
const DEFAULT_KEY_LENGTH = 256;

/**
 * Default IV length for AES-GCM (12 bytes as recommended by NIST)
 */
const IV_LENGTH = 12;

/**
 * Default authentication tag length (128 bits)
 */
const DEFAULT_TAG_LENGTH = 128;

/**
 * Generate a new AES-256-GCM symmetric key
 *
 * @param length - Key length in bits (128, 192, or 256). Defaults to 256.
 * @returns Promise resolving to a SymmetricKey
 *
 * @example
 * ```ts
 * const key = await generateKey();
 * console.log(key.length); // 256
 * ```
 */
export async function generateKey(
  length: 128 | 192 | 256 = DEFAULT_KEY_LENGTH
): Promise<CryptoResult<SymmetricKey>> {
  try {
    const params: AesKeyGenParams = {
      name: "AES-GCM",
      length,
    };

    const cryptoKey = await crypto.subtle.generateKey(
      params,
      true, // extractable
      ["encrypt", "decrypt"]
    );

    return {
      success: true,
      data: {
        key: cryptoKey,
        algorithm: "AES-GCM",
        length,
      },
    };
  } catch (error) {
    const cryptoError: CryptoError = {
      code: "INVALID_PARAMS",
      message: `Failed to generate AES key: ${error instanceof Error ? error.message : String(error)}`,
      cause: error instanceof Error ? error : undefined,
    };
    return {
      success: false,
      error: cryptoError,
    };
  }
}

/**
 * Generate a random initialization vector (IV)
 *
 * @returns Uint8Array containing random IV (12 bytes)
 */
function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
}

/**
 * Encrypt plaintext using AES-256-GCM
 *
 * @param key - Symmetric key for encryption
 * @param plaintext - Data to encrypt
 * @param aad - Optional additional authenticated data (not encrypted but authenticated)
 * @returns Promise resolving to EncryptedData containing ciphertext and metadata
 *
 * @example
 * ```ts
 * const keyResult = await generateKey();
 * if (!keyResult.success) throw keyResult.error;
 *
 * const plaintext = new TextEncoder().encode("secret message");
 * const encrypted = await encrypt(keyResult.data, plaintext);
 *
 * if (encrypted.success) {
 *   console.log(encrypted.data.ciphertext);
 *   console.log(encrypted.data.iv);
 * }
 * ```
 */
export async function encrypt(
  key: SymmetricKey,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<CryptoResult<EncryptedData>> {
  try {
    const iv = generateIV();

    const params: AesGcmParams = {
      name: "AES-GCM",
      iv,
      additionalData: aad,
      tagLength: DEFAULT_TAG_LENGTH,
    };

    const ciphertext = await crypto.subtle.encrypt(params, key.key, plaintext);

    const result: EncryptedData = {
      ciphertext: new Uint8Array(ciphertext),
      iv,
      algorithm: "AES-GCM",
      aad,
    };

    return {
      success: true,
      data: result,
    };
  } catch (error) {
    const cryptoError: CryptoError = {
      code: "ENCRYPTION_FAILED",
      message: `AES-GCM encryption failed: ${error instanceof Error ? error.message : String(error)}`,
      cause: error instanceof Error ? error : undefined,
    };
    return {
      success: false,
      error: cryptoError,
    };
  }
}

/**
 * Decrypt ciphertext using AES-256-GCM
 *
 * @param key - Symmetric key for decryption
 * @param encrypted - Encrypted data containing ciphertext, IV, and optional AAD
 * @returns Promise resolving to decrypted plaintext
 *
 * @example
 * ```ts
 * const keyResult = await generateKey();
 * if (!keyResult.success) throw keyResult.error;
 *
 * const plaintext = new TextEncoder().encode("secret message");
 * const encryptResult = await encrypt(keyResult.data, plaintext);
 * if (!encryptResult.success) throw encryptResult.error;
 *
 * const decryptResult = await decrypt(keyResult.data, encryptResult.data);
 * if (decryptResult.success) {
 *   const decrypted = new TextDecoder().decode(decryptResult.data);
 *   console.log(decrypted); // "secret message"
 * }
 * ```
 */
export async function decrypt(
  key: SymmetricKey,
  encrypted: EncryptedData
): Promise<CryptoResult<Uint8Array>> {
  try {
    if (encrypted.algorithm !== "AES-GCM") {
      const error: CryptoError = {
        code: "INVALID_PARAMS",
        message: `Unsupported algorithm: ${encrypted.algorithm}. Expected AES-GCM.`,
      };
      return {
        success: false,
        error,
      };
    }

    const params: AesGcmParams = {
      name: "AES-GCM",
      iv: encrypted.iv,
      additionalData: encrypted.aad,
      tagLength: DEFAULT_TAG_LENGTH,
    };

    const plaintext = await crypto.subtle.decrypt(params, key.key, encrypted.ciphertext);

    return {
      success: true,
      data: new Uint8Array(plaintext),
    };
  } catch (error) {
    const cryptoError: CryptoError = {
      code: "DECRYPTION_FAILED",
      message: `AES-GCM decryption failed: ${error instanceof Error ? error.message : String(error)}`,
      cause: error instanceof Error ? error : undefined,
    };
    return {
      success: false,
      error: cryptoError,
    };
  }
}
