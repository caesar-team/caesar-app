/**
 * Typed HTTP client for the Link server API. The server stores opaque ciphertext
 * plus non-secret metadata; it never sees keys or plaintext. Same-origin in prod;
 * Vite proxies /api to the server in dev.
 */
import type { KdfMeta } from "@caesar/link-sdk";

const BASE = "/api";

/** Public, non-secret metadata stored alongside a share's ciphertext. */
export interface ShareMeta {
  /** base64url blob IV */
  iv: string;
  /** present only for password-protected shares */
  kdf?: KdfMeta | null;
}

export interface CreateResult {
  id: string;
  deleteToken: string;
}

export interface MetaResult {
  meta: ShareMeta;
  size: number;
  viewsLeft: number | null;
  expiresAt: number;
}

/** Thrown for any non-OK response. `notFound` maps expired/missing/exhausted (all 404). */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
  get notFound(): boolean {
    return this.status === 404;
  }
}

async function fail(res: Response): Promise<never> {
  let message = res.statusText;
  try {
    const body = (await res.json()) as { error?: string };
    if (body.error) message = body.error;
  } catch {
    // non-JSON body; keep statusText
  }
  throw new ApiError(res.status, message);
}

export async function postShare(
  ciphertext: Uint8Array,
  meta: ShareMeta,
  ttlSeconds: number,
  views: number | null
): Promise<CreateResult> {
  const form = new FormData();
  form.append("blob", new Blob([ciphertext as BlobPart]), "blob");
  form.append("meta", JSON.stringify(meta));
  form.append("ttl", String(ttlSeconds));
  if (views !== null) {
    form.append("views", String(views));
  }
  const res = await fetch(`${BASE}/shares`, { method: "POST", body: form });
  if (!res.ok) {
    return fail(res);
  }
  return (await res.json()) as CreateResult;
}

export async function getShareMeta(id: string): Promise<MetaResult> {
  const res = await fetch(`${BASE}/shares/${encodeURIComponent(id)}`);
  if (!res.ok) {
    return fail(res);
  }
  return (await res.json()) as MetaResult;
}

export async function getShareBlob(id: string): Promise<Uint8Array> {
  const res = await fetch(`${BASE}/shares/${encodeURIComponent(id)}/blob`);
  if (!res.ok) {
    return fail(res);
  }
  return new Uint8Array(await res.arrayBuffer());
}

export async function deleteShare(id: string, deleteToken: string): Promise<void> {
  const res = await fetch(`${BASE}/shares/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { "X-Delete-Token": deleteToken },
  });
  if (!res.ok) {
    return fail(res);
  }
}
