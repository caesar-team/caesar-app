/**
 * @caesar/crypto
 * Shared cryptography package for Caesar App
 *
 * This package provides type-safe wrappers around Web Crypto API
 * for key derivation, symmetric/asymmetric encryption, and key exchange.
 *
 * @packageDocumentation
 */

// Export all type definitions
export type {
  // Key Derivation
  ScryptParams,
  DerivedKey,
  // Symmetric Encryption (AES-GCM)
  AesGcmParams,
  AesKeyGenParams,
  EncryptedData,
  SymmetricKey,
  // Asymmetric Encryption (RSA-OAEP)
  RsaOaepParams,
  RsaKeyGenParams,
  RsaKeyPair,
  // Elliptic Curve Diffie-Hellman
  EcdhParams,
  EcKeyGenParams,
  EcdhKeyPair,
  SharedSecret,
  // Key Import/Export
  KeyFormat,
  KeyUsage,
  ExportedKey,
  // Utility Types
  Base64String,
  HexString,
  HashAlgorithm,
  CryptoError,
  CryptoResult,
} from "./types.js";

// Export WebWorker API
export {
  initCryptoWorker,
  terminateCryptoWorker,
  getCryptoWorker,
  type CryptoWorkerApi,
} from "./worker/index.js";
