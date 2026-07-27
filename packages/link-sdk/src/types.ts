/** One attachment. Name and mime travel inside the ciphertext, never visible to the server. */
export interface SharedFile {
  name: string;
  mime: string;
  data: Uint8Array;
}

export type SharePayload =
  | { type: "text"; data: Uint8Array }
  | { type: "file"; files: SharedFile[] };

export interface SealedBlob {
  /** AES-GCM ciphertext with appended tag — the only thing uploaded as the blob */
  ciphertext: Uint8Array;
  /** Public metadata, stored server-side */
  iv: Uint8Array;
}

export const ENVELOPE_VERSION = 2;

export interface KdfMeta {
  kdf: "scrypt";
  /** base64url, 16 bytes */
  salt: string;
  N: number;
  r: number;
  p: number;
  dkLen: number;
}
