import { generateKey } from "@caesar/crypto";
import { openEnvelope, sealEnvelope } from "./envelope.js";
import {
  decodeFragment,
  encodeKeyFragment,
  encodePasswordFragment,
  unwrapPasswordFragment,
} from "./fragment.js";
import type { KdfMeta, SealedBlob, SharePayload } from "./types.js";

export interface ShareBundle {
  blob: SealedBlob;
  fragment: string;
  kdf?: KdfMeta;
}

export async function createShare(
  payload: SharePayload,
  options: { password?: string; kdfParams?: Partial<Pick<KdfMeta, "N" | "r" | "p">> } = {}
): Promise<ShareBundle> {
  const keyResult = await generateKey();
  if (!keyResult.success) throw new Error(keyResult.error.message);
  const dek = keyResult.data;
  const blob = await sealEnvelope(payload, dek);
  if (options.password !== undefined) {
    const { fragment, kdf } = await encodePasswordFragment(
      dek,
      options.password,
      options.kdfParams
    );
    return { blob, fragment, kdf };
  }
  return { blob, fragment: await encodeKeyFragment(dek) };
}

export async function openShare(input: {
  blob: SealedBlob;
  fragment: string;
  password?: string;
  kdf?: KdfMeta;
}): Promise<SharePayload> {
  const decoded = await decodeFragment(input.fragment);
  if (decoded.mode === "key") return openEnvelope(input.blob, decoded.dek);
  if (input.password === undefined || input.kdf === undefined) {
    throw new Error("This share is password-protected: password and kdf metadata are required");
  }
  const dek = await unwrapPasswordFragment(decoded.wrapped, input.password, input.kdf);
  return openEnvelope(input.blob, dek);
}
