export interface SharePayload {
  type: "text" | "file";
  /** Original file name — travels inside the ciphertext, never visible to the server */
  name?: string;
  mime?: string;
  data: Uint8Array;
}

export interface SealedBlob {
  /** AES-GCM ciphertext with appended tag — the only thing uploaded as the blob */
  ciphertext: Uint8Array;
  /** Public metadata, stored server-side */
  iv: Uint8Array;
}

export const ENVELOPE_VERSION = 1;

export interface KdfMeta {
  kdf: "scrypt";
  /** base64url, 16 bytes */
  salt: string;
  N: number;
  r: number;
  p: number;
  dkLen: number;
}
