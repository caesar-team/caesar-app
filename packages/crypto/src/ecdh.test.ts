import { describe, expect, test } from "bun:test";
import {
  deriveSharedSecret,
  deriveSharedSecretBits,
  exportEcdhPrivateKey,
  exportEcdhPublicKey,
  generateEcdhKeyPair,
  importEcdhPrivateKey,
  importEcdhPublicKey,
} from "./ecdh.js";
import { decrypt, encrypt } from "./symmetric.js";
import type { SymmetricKey } from "./types.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

function asSymmetricKey(key: CryptoKey): SymmetricKey {
  return { key, algorithm: "AES-GCM", length: 256 };
}

describe("ecdh key exchange", () => {
  test("generates a P-256 key pair by default", async () => {
    const keyPair = await generateEcdhKeyPair();
    expect(keyPair.algorithm).toBe("ECDH");
    expect(keyPair.namedCurve).toBe("P-256");
    expect(keyPair.publicKey.type).toBe("public");
    expect(keyPair.privateKey.type).toBe("private");
  });

  test("both parties derive the same shared AES-GCM key", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();
    const aliceSecret = await deriveSharedSecret(alice.privateKey, bob.publicKey);
    const bobSecret = await deriveSharedSecret(bob.privateKey, alice.publicKey);
    expect(aliceSecret.namedCurve).toBe("P-256");

    const encrypted = await encrypt(asSymmetricKey(aliceSecret.key), enc.encode("hi bob"));
    if (!encrypted.success) throw encrypted.error;
    const decrypted = await decrypt(asSymmetricKey(bobSecret.key), encrypted.data);
    if (!decrypted.success) throw decrypted.error;
    expect(dec.decode(decrypted.data)).toBe("hi bob");
  });

  test("both parties derive identical raw secret bits", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();
    const aliceBits = await deriveSharedSecretBits(alice.privateKey, bob.publicKey);
    const bobBits = await deriveSharedSecretBits(bob.privateKey, alice.publicKey);
    expect(aliceBits).toEqual(bobBits);
  });

  test("exported keys re-import and still agree on the shared secret", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();

    const alicePub = await importEcdhPublicKey(await exportEcdhPublicKey(alice.publicKey));
    const bobPriv = await importEcdhPrivateKey(await exportEcdhPrivateKey(bob.privateKey));

    const fromOriginal = await deriveSharedSecretBits(alice.privateKey, bob.publicKey);
    const fromImported = await deriveSharedSecretBits(bobPriv, alicePub);
    expect(fromImported).toEqual(fromOriginal);
  });
});
