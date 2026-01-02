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

// Export asymmetric encryption functions (RSA-OAEP)
export {
  generateRsaKeyPair,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
} from "./asymmetric.js";

// Export ECDH key exchange functions
export {
  generateEcdhKeyPair,
  deriveSharedSecret,
  deriveSharedSecretBits,
  exportEcdhPublicKey,
  exportEcdhPrivateKey,
  importEcdhPublicKey,
  importEcdhPrivateKey,
} from "./ecdh.js";
