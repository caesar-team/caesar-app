import { describe, expect, test } from "bun:test";
import vectorsFileJson from "../vectors/v1.json";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import { openShare } from "./share.js";
import type { KdfMeta, SharePayload } from "./types.js";

interface Vector {
  name: string;
  password: string | null;
  fragment: string;
  kdf: KdfMeta | null;
  blob: { ciphertext: string; iv: string };
  expected: {
    type: SharePayload["type"];
    name: string | null;
    mime: string | null;
    data: string;
  };
}

interface VectorsFile {
  version: number;
  vectors: Vector[];
}

const vectorsFile = vectorsFileJson as VectorsFile;

describe("v1 test vectors", () => {
  for (const v of vectorsFile.vectors) {
    test(v.name, async () => {
      const payload = await openShare({
        blob: {
          ciphertext: fromBase64Url(v.blob.ciphertext),
          iv: fromBase64Url(v.blob.iv),
        },
        fragment: v.fragment,
        password: v.password ?? undefined,
        kdf: v.kdf ?? undefined,
      });
      expect(payload.type).toBe(v.expected.type);
      expect(payload.name ?? null).toEqual(v.expected.name);
      expect(payload.mime ?? null).toEqual(v.expected.mime);
      expect(toBase64Url(payload.data)).toBe(v.expected.data);
    }, 30000);
  }
});
