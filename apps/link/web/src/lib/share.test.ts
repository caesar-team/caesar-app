import { afterEach, describe, expect, test } from "bun:test";
import { ApiError } from "./api.js";
import { createAndUpload, fetchAndOpen, fetchMeta, isPasswordProtected } from "./share.js";

const ORIGIN = "https://link.example";
const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

interface Stored {
  bytes: Uint8Array;
  meta: string;
  viewsLeft: number | null;
}

function jsonRes(status: number, obj: unknown): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Installs an in-memory fake of the Link server on globalThis.fetch. */
function installServer(): () => void {
  const store = new Map<string, Stored>();
  let seq = 0;
  const real = globalThis.fetch;
  // biome-ignore lint/complexity/noExcessiveCognitiveComplexity: in-memory fake server routes several endpoints
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const method = init?.method ?? "GET";

    if (url.endsWith("/api/shares") && method === "POST") {
      const fd = init?.body as FormData;
      const blob = fd.get("blob") as Blob;
      const views = fd.get("views");
      const id = `id${++seq}`;
      store.set(id, {
        bytes: new Uint8Array(await blob.arrayBuffer()),
        meta: fd.get("meta") as string,
        viewsLeft: views === null ? null : Number(views),
      });
      return jsonRes(201, { id, deleteToken: `tok${seq}` });
    }

    const match = url.match(/\/api\/shares\/([^/?#]+)(\/blob)?$/);
    if (match) {
      const rec = store.get(match[1] as string);
      if (!rec) {
        return jsonRes(404, { error: "Not found" });
      }
      if (match[2]) {
        // consume one view like the real server
        if (rec.viewsLeft !== null) {
          if (rec.viewsLeft <= 0) {
            store.delete(match[1] as string);
            return jsonRes(404, { error: "Not found" });
          }
          rec.viewsLeft -= 1;
          if (rec.viewsLeft === 0) {
            store.delete(match[1] as string);
          }
        }
        return new Response(rec.bytes, { status: 200 });
      }
      return jsonRes(200, {
        meta: JSON.parse(rec.meta),
        size: rec.bytes.length,
        viewsLeft: rec.viewsLeft,
        expiresAt: 4102444800000,
      });
    }
    return jsonRes(404, { error: "Not found" });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

let restore: () => void;
afterEach(() => restore?.());

describe("share flow", () => {
  test("link-only: create → upload → fetch → decrypt roundtrip", async () => {
    restore = installServer();
    const created = await createAndUpload(
      { type: "text", data: enc("meet at 6") },
      { ttlSeconds: 3600, views: 1, origin: ORIGIN }
    );
    expect(created.url.startsWith(`${ORIGIN}/s/`)).toBe(true);
    expect(created.password).toBeUndefined();
    expect(isPasswordProtected(created.url)).toBe(false);

    const { meta } = await fetchMeta(created.url);
    expect(meta.viewsLeft).toBe(1);
    const payload = await fetchAndOpen(created.url, meta);
    expect(dec(payload.data)).toBe("meet at 6");
  });

  test("password: roundtrip and wrong password fails", async () => {
    restore = installServer();
    const created = await createAndUpload(
      { type: "file", name: "a.txt", mime: "text/plain", data: enc("secret") },
      { ttlSeconds: 3600, views: null, password: "hunter2", origin: ORIGIN }
    );
    expect(created.password).toBe("hunter2");
    expect(isPasswordProtected(created.url)).toBe(true);

    const { meta } = await fetchMeta(created.url);
    const ok = await fetchAndOpen(created.url, meta, "hunter2");
    expect(ok.name).toBe("a.txt");
    expect(dec(ok.data)).toBe("secret");

    const meta2 = await fetchMeta(created.url);
    await expect(fetchAndOpen(created.url, meta2.meta, "WRONG")).rejects.toThrow();
  }, 30000);

  test("one-time share: second view is gone (404 → ApiError.notFound)", async () => {
    restore = installServer();
    const created = await createAndUpload(
      { type: "text", data: enc("burn") },
      { ttlSeconds: 3600, views: 1, origin: ORIGIN }
    );
    const { meta } = await fetchMeta(created.url);
    await fetchAndOpen(created.url, meta); // consumes the only view
    let err: unknown;
    try {
      await fetchAndOpen(created.url, meta);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).notFound).toBe(true);
  });
});
