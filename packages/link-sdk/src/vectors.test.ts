import { describe, expect, test } from "bun:test";
import vectorsFileJson from "../vectors/v2.json";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import { openShare } from "./share.js";
import type { KdfMeta } from "./types.js";

type ExpectedPayload =
  | { type: "text"; data: string }
  | { type: "file"; files: Array<{ name: string; mime: string; data: string }> };

interface Vector {
  name: string;
  password: string | null;
  fragment: string;
  kdf: KdfMeta | null;
  blob: { ciphertext: string; iv: string };
  expected: ExpectedPayload;
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
      if (payload.type === "text" && v.expected.type === "text") {
        expect(toBase64Url(payload.data)).toBe(v.expected.data);
      } else if (payload.type === "file" && v.expected.type === "file") {
        expect(
          payload.files.map((f) => ({ name: f.name, mime: f.mime, data: toBase64Url(f.data) }))
        ).toEqual(v.expected.files);
      } else {
        throw new Error(`type mismatch for vector ${v.name}`);
      }
    }, 30000);
  }
});
