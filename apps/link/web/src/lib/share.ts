/**
 * End-to-end share flow: composes @caesar/link-sdk (client-side crypto) with the
 * server API. The DEK lives only in the URL fragment; the server never receives it.
 */
import {
  type SharePayload,
  buildShareUrl,
  createShare,
  fromBase64Url,
  openShare,
  parseShareUrl,
  toBase64Url,
} from "@caesar/link-sdk";
import { type MetaResult, getShareBlob, getShareMeta, postShare } from "./api.js";

export type CreatePhase = "encrypting" | "uploading";

export interface CreateOptions {
  password?: string;
  ttlSeconds: number;
  /** null = unlimited views */
  views: number | null;
  /** defaults to window.location.origin */
  origin?: string;
  /** phase notifications so the UI can show encrypting → uploading */
  onPhase?: (phase: CreatePhase) => void;
}

export interface CreatedShare {
  id: string;
  /** full share URL including the #fragment (the fragment never reaches the server) */
  url: string;
  deleteToken: string;
  /** echoed back only when a password was set, so the UI can show it once */
  password?: string;
}

/** Encrypts the payload, uploads only the ciphertext, and returns the shareable URL. */
export async function createAndUpload(
  payload: SharePayload,
  opts: CreateOptions
): Promise<CreatedShare> {
  const origin = opts.origin ?? window.location.origin;
  opts.onPhase?.("encrypting");
  const bundle = await createShare(
    payload,
    opts.password !== undefined ? { password: opts.password } : {}
  );
  opts.onPhase?.("uploading");
  const { id, deleteToken } = await postShare(
    bundle.blob.ciphertext,
    { iv: toBase64Url(bundle.blob.iv), kdf: bundle.kdf ?? null },
    opts.ttlSeconds,
    opts.views
  );
  const created: CreatedShare = {
    id,
    url: buildShareUrl(origin, id, bundle.fragment),
    deleteToken,
  };
  if (opts.password !== undefined) {
    created.password = opts.password;
  }
  return created;
}

/** Reads a share's public metadata without consuming a view. */
export async function fetchMeta(url: string): Promise<{ id: string; meta: MetaResult }> {
  const { id } = parseShareUrl(url);
  return { id, meta: await getShareMeta(id) };
}

/** Whether a share requires a password (p. fragment). Cheap, from the URL alone. */
export function isPasswordProtected(url: string): boolean {
  return parseShareUrl(url).fragment.startsWith("p.");
}

/** Downloads the ciphertext (consuming one view) and decrypts it in the browser. */
export async function fetchAndOpen(
  url: string,
  meta: MetaResult,
  password?: string
): Promise<SharePayload> {
  const { id, fragment } = parseShareUrl(url);
  const ciphertext = await getShareBlob(id);
  return openShare({
    blob: { ciphertext, iv: fromBase64Url(meta.meta.iv) },
    fragment,
    ...(password !== undefined && { password }),
    ...(meta.meta.kdf ? { kdf: meta.meta.kdf } : {}),
  });
}
