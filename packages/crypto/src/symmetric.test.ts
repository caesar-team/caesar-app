import { describe, expect, test } from "bun:test";
import { decrypt, encrypt, generateKey } from "./symmetric.js";
import type { EncryptedData, SymmetricKey } from "./types.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

async function makeKey(length: 128 | 192 | 256 = 256): Promise<SymmetricKey> {
  const result = await generateKey(length);
  if (!result.success) throw new Error(result.error.message);
  return result.data;
}

describe("symmetric (AES-GCM)", () => {
  describe("generateKey", () => {
    test("defaults to a 256-bit AES-GCM secret key", async () => {
      const key = await makeKey();
      expect(key.algorithm).toBe("AES-GCM");
      expect(key.length).toBe(256);
      expect(key.key.type).toBe("secret");
    });

    test("honors an explicit key length", async () => {
      const key = await makeKey(128);
      expect(key.length).toBe(128);
    });
  });

  describe("encrypt / decrypt", () => {
    test("round-trips plaintext", async () => {
      const key = await makeKey();
      const encrypted = await encrypt(key, enc.encode("attack at dawn"));
      if (!encrypted.success) throw encrypted.error;
      const decrypted = await decrypt(key, encrypted.data);
      if (!decrypted.success) throw decrypted.error;
      expect(dec.decode(decrypted.data)).toBe("attack at dawn");
    });

    test("round-trips empty plaintext", async () => {
      const key = await makeKey();
      const encrypted = await encrypt(key, new Uint8Array(0));
      if (!encrypted.success) throw encrypted.error;
      const decrypted = await decrypt(key, encrypted.data);
      if (!decrypted.success) throw decrypted.error;
      expect(decrypted.data.length).toBe(0);
    });

    test("uses a fresh random IV for every call", async () => {
      const key = await makeKey();
      const message = enc.encode("same message");
      const a = await encrypt(key, message);
      const b = await encrypt(key, message);
      if (!a.success || !b.success) throw new Error("encryption failed");
      expect(a.data.iv).not.toEqual(b.data.iv);
      expect(a.data.ciphertext).not.toEqual(b.data.ciphertext);
    });

    test("round-trips with additional authenticated data", async () => {
      const key = await makeKey();
      const encrypted = await encrypt(key, enc.encode("payload"), enc.encode("header-v1"));
      if (!encrypted.success) throw encrypted.error;
      const decrypted = await decrypt(key, encrypted.data);
      if (!decrypted.success) throw decrypted.error;
      expect(dec.decode(decrypted.data)).toBe("payload");
    });

    test("fails to decrypt tampered ciphertext", async () => {
      const key = await makeKey();
      const encrypted = await encrypt(key, enc.encode("secret"));
      if (!encrypted.success) throw encrypted.error;
      const tampered = new Uint8Array(encrypted.data.ciphertext);
      tampered[0] ^= 0xff;
      const corrupted: EncryptedData = { ...encrypted.data, ciphertext: tampered };
      const result = await decrypt(key, corrupted);
      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error.code).toBe("DECRYPTION_FAILED");
    });

    test("fails to decrypt when the AAD does not match", async () => {
      const key = await makeKey();
      const encrypted = await encrypt(key, enc.encode("secret"), enc.encode("aad-A"));
      if (!encrypted.success) throw encrypted.error;
      const wrongAad: EncryptedData = { ...encrypted.data, aad: enc.encode("aad-B") };
      const result = await decrypt(key, wrongAad);
      expect(result.success).toBe(false);
    });

    test("fails to decrypt with a different key", async () => {
      const key = await makeKey();
      const otherKey = await makeKey();
      const encrypted = await encrypt(key, enc.encode("secret"));
      if (!encrypted.success) throw encrypted.error;
      const result = await decrypt(otherKey, encrypted.data);
      expect(result.success).toBe(false);
    });
  });
});
