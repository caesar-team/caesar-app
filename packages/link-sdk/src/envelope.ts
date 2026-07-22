import { type SymmetricKey, decrypt, encrypt } from "@caesar/crypto";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import { ENVELOPE_VERSION, type SealedBlob, type SharePayload } from "./types.js";

interface EnvelopeWire {
  v: number;
  type: SharePayload["type"];
  name?: string;
  mime?: string;
  data: string;
}

export async function sealEnvelope(payload: SharePayload, dek: SymmetricKey): Promise<SealedBlob> {
  const wire: EnvelopeWire = {
    v: ENVELOPE_VERSION,
    type: payload.type,
    ...(payload.name !== undefined && { name: payload.name }),
    ...(payload.mime !== undefined && { mime: payload.mime }),
    data: toBase64Url(payload.data),
  };
  const plaintext = new TextEncoder().encode(JSON.stringify(wire));
  const result = await encrypt(dek, plaintext);
  if (!result.success) throw new Error(`Envelope encryption failed: ${result.error.message}`);
  return { ciphertext: result.data.ciphertext, iv: result.data.iv };
}

export async function openEnvelope(blob: SealedBlob, dek: SymmetricKey): Promise<SharePayload> {
  const result = await decrypt(dek, {
    ciphertext: blob.ciphertext,
    iv: blob.iv,
    algorithm: "AES-GCM",
  });
  if (!result.success) throw new Error(`Envelope decryption failed: ${result.error.message}`);
  const wire = JSON.parse(new TextDecoder().decode(result.data)) as EnvelopeWire;
  if (wire.v !== ENVELOPE_VERSION) throw new Error(`Unsupported envelope version: ${wire.v}`);
  if (wire.type !== "text" && wire.type !== "file") {
    throw new Error(`Malformed envelope: unknown type "${wire.type}"`);
  }
  if (typeof wire.data !== "string") throw new Error("Malformed envelope: missing data field");
  return {
    type: wire.type,
    ...(wire.name !== undefined && { name: wire.name }),
    ...(wire.mime !== undefined && { mime: wire.mime }),
    data: fromBase64Url(wire.data),
  };
}
