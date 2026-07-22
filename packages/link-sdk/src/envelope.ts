import { type SymmetricKey, decrypt, encrypt } from "@caesar/crypto";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import { ENVELOPE_VERSION, type SealedBlob, type SharePayload } from "./types.js";

interface WireFile {
  name: string;
  mime: string;
  data: string;
}

interface EnvelopeWire {
  v: number;
  type: SharePayload["type"];
  /** text payloads only */
  data?: string;
  /** file payloads only */
  files?: WireFile[];
}

export async function sealEnvelope(payload: SharePayload, dek: SymmetricKey): Promise<SealedBlob> {
  const wire: EnvelopeWire =
    payload.type === "text"
      ? { v: ENVELOPE_VERSION, type: "text", data: toBase64Url(payload.data) }
      : {
          v: ENVELOPE_VERSION,
          type: "file",
          files: payload.files.map((f) => ({
            name: f.name,
            mime: f.mime,
            data: toBase64Url(f.data),
          })),
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
  if (wire.type === "text") {
    if (typeof wire.data !== "string") throw new Error("Malformed envelope: missing data field");
    return { type: "text", data: fromBase64Url(wire.data) };
  }
  if (wire.type === "file") {
    if (!Array.isArray(wire.files)) throw new Error("Malformed envelope: missing files field");
    return {
      type: "file",
      files: wire.files.map((f) => {
        if (
          typeof f?.name !== "string" ||
          typeof f?.mime !== "string" ||
          typeof f?.data !== "string"
        ) {
          throw new Error("Malformed envelope: bad file entry");
        }
        return { name: f.name, mime: f.mime, data: fromBase64Url(f.data) };
      }),
    };
  }
  throw new Error(`Malformed envelope: unknown type "${wire.type}"`);
}
