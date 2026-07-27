/** Generates vectors/v2.json. Run once: bun run scripts/generate-vectors.ts
 *  Committed output is canonical — regenerating breaks cross-impl compatibility. */
import { toBase64Url } from "../src/base64url.js";
import { createShare } from "../src/share.js";
import type { SharePayload } from "../src/types.js";

const VECTOR_SCRYPT_N = 16384;

function expectedOf(payload: SharePayload) {
  if (payload.type === "text") {
    return { type: "text" as const, data: toBase64Url(payload.data) };
  }
  return {
    type: "file" as const,
    files: payload.files.map((f) => ({ name: f.name, mime: f.mime, data: toBase64Url(f.data) })),
  };
}

async function vector(name: string, payload: SharePayload, password?: string) {
  const bundle = await createShare(
    payload,
    password === undefined ? {} : { password, kdfParams: { N: VECTOR_SCRYPT_N } }
  );
  return {
    name,
    password: password ?? null,
    fragment: bundle.fragment,
    kdf: bundle.kdf ?? null,
    blob: {
      ciphertext: toBase64Url(bundle.blob.ciphertext),
      iv: toBase64Url(bundle.blob.iv),
    },
    expected: expectedOf(payload),
  };
}

const vectors = [
  await vector("text-plain", { type: "text", data: new TextEncoder().encode("hello link") }),
  await vector("text-unicode", { type: "text", data: new TextEncoder().encode("привет 🔗") }),
  await vector("file-binary", {
    type: "file",
    files: [
      { name: "data.bin", mime: "application/octet-stream", data: new Uint8Array([0, 1, 2, 254, 255]) },
    ],
  }),
  await vector("file-multi", {
    type: "file",
    files: [
      { name: "one.txt", mime: "text/plain", data: new TextEncoder().encode("one") },
      { name: "two.bin", mime: "application/octet-stream", data: new Uint8Array([254, 255]) },
    ],
  }),
  await vector(
    "text-password",
    { type: "text", data: new TextEncoder().encode("guarded") },
    "vector-password"
  ),
];

await Bun.write("vectors/v2.json", `${JSON.stringify({ version: 2, vectors }, null, 2)}\n`);
// biome-ignore lint/suspicious/noConsoleLog: this is a CLI generator; stdout is its interface
console.log(`Wrote ${vectors.length} vectors`);
