import { describe, expect, test } from "bun:test";
import {
  decryptWithPrivateKey,
  encryptWithPublicKey,
  exportPrivateKey,
  exportPublicKey,
  generateRsaKeyPair,
  importPrivateKey,
  importPublicKey,
} from "./asymmetric.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

// 2048-bit keys keep RSA generation fast enough for the test suite; production defaults to 4096.
const TEST_MODULUS = 2048;

describe("asymmetric (RSA-OAEP)", () => {
  test("generates a key pair with distinct public and private keys", async () => {
    const keyPair = await generateRsaKeyPair(TEST_MODULUS);
    expect(keyPair.algorithm).toBe("RSA-OAEP");
    expect(keyPair.modulusLength).toBe(TEST_MODULUS);
    expect(keyPair.publicKey.type).toBe("public");
    expect(keyPair.privateKey.type).toBe("private");
  });

  test("round-trips plaintext through the public/private key pair", async () => {
    const { publicKey, privateKey } = await generateRsaKeyPair(TEST_MODULUS);
    const ciphertext = await encryptWithPublicKey(publicKey, enc.encode("hello RSA"));
    const plaintext = await decryptWithPrivateKey(privateKey, ciphertext);
    expect(dec.decode(plaintext)).toBe("hello RSA");
  });

  test("produces different ciphertext each call (OAEP randomization)", async () => {
    const { publicKey } = await generateRsaKeyPair(TEST_MODULUS);
    const message = enc.encode("same message");
    const a = await encryptWithPublicKey(publicKey, message);
    const b = await encryptWithPublicKey(publicKey, message);
    expect(a).not.toEqual(b);
  });

  test("exports and re-imports keys that still round-trip", async () => {
    const original = await generateRsaKeyPair(TEST_MODULUS);
    const spki = await exportPublicKey(original.publicKey);
    const pkcs8 = await exportPrivateKey(original.privateKey);
    expect(typeof spki).toBe("string");
    expect(typeof pkcs8).toBe("string");

    const publicKey = await importPublicKey(spki);
    const privateKey = await importPrivateKey(pkcs8);
    const ciphertext = await encryptWithPublicKey(publicKey, enc.encode("via imported keys"));
    const plaintext = await decryptWithPrivateKey(privateKey, ciphertext);
    expect(dec.decode(plaintext)).toBe("via imported keys");
  });

  test("rejects decryption with a mismatched private key", async () => {
    const alice = await generateRsaKeyPair(TEST_MODULUS);
    const bob = await generateRsaKeyPair(TEST_MODULUS);
    const ciphertext = await encryptWithPublicKey(alice.publicKey, enc.encode("for alice"));
    await expect(decryptWithPrivateKey(bob.privateKey, ciphertext)).rejects.toThrow();
  });
});
