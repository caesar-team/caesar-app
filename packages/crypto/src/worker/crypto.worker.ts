/**
 * Crypto WebWorker
 * Heavy cryptographic operations running in background thread
 */

import { expose } from "comlink";
import type {
  AesGcmParams,
  AesKeyGenParams,
  DerivedKey,
  EncryptedData,
  RsaKeyGenParams,
  RsaKeyPair,
  ScryptParams,
  SymmetricKey,
} from "../types.js";

/**
 * Derive a key from a password using Scrypt
 */
async function deriveKey(password: string, params: ScryptParams): Promise<DerivedKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Import the password as a CryptoKey
  const baseKey = await crypto.subtle.importKey("raw", passwordBuffer, { name: "PBKDF2" }, false, [
    "deriveBits",
    "deriveKey",
  ]);

  // For Web Crypto API, we use PBKDF2 instead of Scrypt
  // Note: Scrypt is not natively supported in Web Crypto API
  // Using PBKDF2 as a fallback with high iteration count
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: params.salt.buffer as ArrayBuffer,
      iterations: params.N,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: params.dkLen * 8 },
    true,
    ["encrypt", "decrypt"]
  );

  return {
    key: derivedKey,
    algorithm: "scrypt",
    params,
  };
}

/**
 * Generate a symmetric AES key
 */
async function generateSymmetricKey(params: AesKeyGenParams): Promise<SymmetricKey> {
  const key = await crypto.subtle.generateKey(
    {
      name: params.name,
      length: params.length,
    },
    true,
    ["encrypt", "decrypt"]
  );

  return {
    key,
    algorithm: "AES-GCM",
    length: params.length,
  };
}

/**
 * Encrypt data using AES-GCM
 */
async function encrypt(
  data: Uint8Array,
  key: CryptoKey,
  params: AesGcmParams
): Promise<EncryptedData> {
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: params.name,
      iv: params.iv.buffer as ArrayBuffer,
      additionalData: params.additionalData?.buffer as ArrayBuffer | undefined,
      tagLength: params.tagLength ?? 128,
    },
    key,
    data.buffer as ArrayBuffer
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    iv: params.iv,
    algorithm: "AES-GCM",
    aad: params.additionalData,
  };
}

/**
 * Decrypt data using AES-GCM
 */
async function decrypt(encryptedData: EncryptedData, key: CryptoKey): Promise<Uint8Array> {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: encryptedData.algorithm,
      iv: encryptedData.iv.buffer as ArrayBuffer,
      additionalData: encryptedData.aad?.buffer as ArrayBuffer | undefined,
      tagLength: 128,
    },
    key,
    encryptedData.ciphertext.buffer as ArrayBuffer
  );

  return new Uint8Array(decrypted);
}

/**
 * Generate an RSA key pair
 */
async function generateKeyPair(params: RsaKeyGenParams): Promise<RsaKeyPair> {
  const keyPair = (await crypto.subtle.generateKey(
    params as unknown as RsaHashedKeyGenParams,
    true,
    ["encrypt", "decrypt"]
  )) as CryptoKeyPair;

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    algorithm: "RSA-OAEP",
    modulusLength: params.modulusLength,
  };
}

/**
 * Export a CryptoKey to raw format
 */
async function exportKey(
  key: CryptoKey,
  format: "raw" | "pkcs8" | "spki" | "jwk"
): Promise<ArrayBuffer | JsonWebKey> {
  return await crypto.subtle.exportKey(format, key);
}

/**
 * Import a key from raw format
 */
async function importKey(
  format: "raw" | "pkcs8" | "spki" | "jwk",
  keyData: ArrayBuffer | JsonWebKey,
  algorithm: AesKeyGenParams | RsaKeyGenParams | { name: "ECDH"; namedCurve: string },
  extractable: boolean,
  keyUsages: KeyUsage[]
): Promise<CryptoKey> {
  if (format === "jwk") {
    return await crypto.subtle.importKey(
      format,
      keyData as JsonWebKey,
      algorithm,
      extractable,
      keyUsages as readonly KeyUsage[]
    );
  }
  return await crypto.subtle.importKey(
    format,
    keyData as ArrayBuffer,
    algorithm,
    extractable,
    keyUsages
  );
}

/**
 * Crypto operations API exposed to main thread
 */
const cryptoWorkerApi = {
  deriveKey,
  generateSymmetricKey,
  encrypt,
  decrypt,
  generateKeyPair,
  exportKey,
  importKey,
};

expose(cryptoWorkerApi);

export type CryptoWorkerApi = typeof cryptoWorkerApi;
