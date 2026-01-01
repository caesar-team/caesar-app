/**
 * Cryptography type definitions for Caesar App
 * Based on Web Crypto API standards
 */

// ============================================================================
// Key Derivation (Scrypt)
// ============================================================================

/**
 * Scrypt algorithm parameters for key derivation
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
 */
export interface ScryptParams {
  /** Salt for key derivation (recommended: 16 bytes minimum) */
  salt: Uint8Array;
  /** CPU/memory cost parameter (power of 2, e.g., 2^14 = 16384) */
  N: number;
  /** Block size parameter (typically 8) */
  r: number;
  /** Parallelization parameter (typically 1) */
  p: number;
  /** Derived key length in bytes */
  dkLen: number;
}

/**
 * Result of key derivation operation
 */
export interface DerivedKey {
  /** The derived key material */
  key: CryptoKey;
  /** Algorithm used for derivation */
  algorithm: "scrypt";
  /** Parameters used for derivation */
  params: ScryptParams;
}

// ============================================================================
// Symmetric Encryption (AES-GCM)
// ============================================================================

/**
 * AES-GCM encryption algorithm parameters
 * @see https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
 */
export interface AesGcmParams {
  /** Algorithm name */
  name: "AES-GCM";
  /** Initialization vector (recommended: 12 bytes for GCM) */
  iv: Uint8Array;
  /** Additional authenticated data (optional) */
  additionalData?: Uint8Array;
  /** Authentication tag length in bits (default: 128) */
  tagLength?: 96 | 104 | 112 | 120 | 128;
}

/**
 * AES key generation parameters
 */
export interface AesKeyGenParams {
  /** Algorithm name */
  name: "AES-GCM";
  /** Key length in bits (128, 192, or 256) */
  length: 128 | 192 | 256;
}

/**
 * Encrypted data with metadata
 */
export interface EncryptedData {
  /** Encrypted ciphertext */
  ciphertext: Uint8Array;
  /** Initialization vector used */
  iv: Uint8Array;
  /** Authentication tag (included in ciphertext for AES-GCM) */
  tag?: Uint8Array;
  /** Algorithm used */
  algorithm: "AES-GCM";
  /** Additional authenticated data (if used) */
  aad?: Uint8Array;
}

/**
 * Symmetric encryption key
 */
export interface SymmetricKey {
  /** The CryptoKey object */
  key: CryptoKey;
  /** Algorithm used */
  algorithm: "AES-GCM";
  /** Key length in bits */
  length: 128 | 192 | 256;
}

// ============================================================================
// Asymmetric Encryption (RSA-OAEP)
// ============================================================================

/**
 * RSA-OAEP encryption algorithm parameters
 * @see https://developer.mozilla.org/en-US/docs/Web/API/RsaOaepParams
 */
export interface RsaOaepParams {
  /** Algorithm name */
  name: "RSA-OAEP";
  /** Hash function to use */
  hash: "SHA-256" | "SHA-384" | "SHA-512";
  /** Optional label (rarely used) */
  label?: Uint8Array;
}

/**
 * RSA key generation parameters
 */
export interface RsaKeyGenParams {
  /** Algorithm name */
  name: "RSA-OAEP";
  /** Modulus length in bits (2048, 3072, or 4096) */
  modulusLength: 2048 | 3072 | 4096;
  /** Public exponent (typically 65537) */
  publicExponent: Uint8Array;
  /** Hash algorithm */
  hash: "SHA-256" | "SHA-384" | "SHA-512";
}

/**
 * RSA key pair
 */
export interface RsaKeyPair {
  /** Public key for encryption/verification */
  publicKey: CryptoKey;
  /** Private key for decryption/signing */
  privateKey: CryptoKey;
  /** Algorithm used */
  algorithm: "RSA-OAEP";
  /** Key size in bits */
  modulusLength: 2048 | 3072 | 4096;
}

// ============================================================================
// Elliptic Curve Diffie-Hellman (ECDH)
// ============================================================================

/**
 * ECDH algorithm parameters
 * @see https://developer.mozilla.org/en-US/docs/Web/API/EcdhKeyDeriveParams
 */
export interface EcdhParams {
  /** Algorithm name */
  name: "ECDH";
  /** Public key of the other party */
  public: CryptoKey;
}

/**
 * Elliptic curve parameters
 */
export interface EcKeyGenParams {
  /** Algorithm name */
  name: "ECDH";
  /** Named curve (P-256, P-384, or P-521) */
  namedCurve: "P-256" | "P-384" | "P-521";
}

/**
 * ECDH key pair
 */
export interface EcdhKeyPair {
  /** Public key to share */
  publicKey: CryptoKey;
  /** Private key to keep secret */
  privateKey: CryptoKey;
  /** Algorithm used */
  algorithm: "ECDH";
  /** Named curve */
  namedCurve: "P-256" | "P-384" | "P-521";
}

/**
 * Shared secret derived from ECDH
 */
export interface SharedSecret {
  /** The shared secret key */
  key: CryptoKey;
  /** Algorithm used for derivation */
  algorithm: "ECDH";
  /** Curve used */
  namedCurve: "P-256" | "P-384" | "P-521";
}

// ============================================================================
// Key Import/Export
// ============================================================================

/**
 * Supported key formats for import/export
 */
export type KeyFormat = "raw" | "pkcs8" | "spki" | "jwk";

/**
 * Key usage types
 */
export type KeyUsage =
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "deriveKey"
  | "deriveBits"
  | "wrapKey"
  | "unwrapKey";

/**
 * Exported key data
 */
export interface ExportedKey {
  /** Key data in specified format */
  data: ArrayBuffer | JsonWebKey;
  /** Format used */
  format: KeyFormat;
  /** Algorithm */
  algorithm: string;
  /** Key usages */
  usages: KeyUsage[];
}

// ============================================================================
// Utility Types
// ============================================================================

/**
 * Base64 encoded string
 */
export type Base64String = string;

/**
 * Hexadecimal encoded string
 */
export type HexString = string;

/**
 * Cryptographic hash algorithms
 */
export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";

/**
 * Error types for crypto operations
 */
export interface CryptoError {
  /** Error code */
  code:
    | "INVALID_KEY"
    | "INVALID_PARAMS"
    | "ENCRYPTION_FAILED"
    | "DECRYPTION_FAILED"
    | "KEY_DERIVATION_FAILED"
    | "IMPORT_FAILED"
    | "EXPORT_FAILED";
  /** Error message */
  message: string;
  /** Original error (if any) */
  cause?: Error;
}

/**
 * Crypto operation result
 */
export type CryptoResult<T> =
  | { success: true; data: T }
  | { success: false; error: CryptoError };
