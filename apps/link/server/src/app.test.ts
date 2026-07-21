import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "./app";
import type { Config } from "./config";
import { ShareStore } from "./store";

function makeConfig(overrides: Partial<Config> = {}): Config {
  return {
    port: 3000,
    dataDir: "./data",
    maxBlobSize: 1024,
    rateLimitMax: 1000,
    rateLimitWindowMs: 3_600_000,
    minTtl: 60,
    maxTtl: 2_592_000,
    trustProxy: false,
    maxMetaSize: 16_384,
    ...overrides,
  };
}

let dataDir: string;
let store: ShareStore;
let app: ReturnType<typeof createApp>;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "link-app-"));
  store = new ShareStore(":memory:", dataDir);
  app = createApp(store, makeConfig());
});

afterEach(() => {
  store.close();
  rmSync(dataDir, { recursive: true, force: true });
});

function postForm(fields: {
  blob?: Blob;
  meta?: string;
  ttl?: string;
  views?: string;
}): Promise<Response> {
  const form = new FormData();
  if (fields.blob !== undefined) {
    form.set("blob", fields.blob, "cipher.bin");
  }
  if (fields.meta !== undefined) {
    form.set("meta", fields.meta);
  }
  if (fields.ttl !== undefined) {
    form.set("ttl", fields.ttl);
  }
  if (fields.views !== undefined) {
    form.set("views", fields.views);
  }
  return app.request("/api/shares", { method: "POST", body: form });
}

describe("createApp routes", () => {
  test("GET /api/health returns ok", async () => {
    const res = await app.request("/api/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  test("POST valid multipart returns 201, then GET meta matches", async () => {
    const meta = JSON.stringify({ iv: "abc", name: "secret" });
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const res = await postForm({
      blob: new Blob([bytes]),
      meta,
      ttl: "3600",
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; deleteToken: string };
    expect(body.id).toBeString();
    expect(body.deleteToken).toBeString();
    expect(body.id.length).toBeGreaterThan(0);
    expect(body.deleteToken.length).toBeGreaterThan(0);

    const metaRes = await app.request(`/api/shares/${body.id}`);
    expect(metaRes.status).toBe(200);
    const metaBody = (await metaRes.json()) as {
      meta: unknown;
      size: number;
      viewsLeft: number | null;
      expiresAt: number;
    };
    expect(metaBody.size).toBe(5);
    expect(metaBody.meta).toEqual({ iv: "abc", name: "secret" });
    expect(metaBody.viewsLeft).toBeNull();
    expect(metaBody.expiresAt).toBeGreaterThan(Date.now());
  });

  test("GET blob returns exact bytes; one-time share second GET is 404", async () => {
    const bytes = new Uint8Array([10, 20, 30, 40]);
    const res = await postForm({
      blob: new Blob([bytes]),
      meta: JSON.stringify({ iv: "x" }),
      ttl: "3600",
      views: "1",
    });
    expect(res.status).toBe(201);
    const { id } = (await res.json()) as { id: string };

    const blobRes = await app.request(`/api/shares/${id}/blob`);
    expect(blobRes.status).toBe(200);
    expect(blobRes.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(blobRes.headers.get("Content-Length")).toBe("4");
    const received = new Uint8Array(await blobRes.arrayBuffer());
    expect(Array.from(received)).toEqual([10, 20, 30, 40]);

    const secondRes = await app.request(`/api/shares/${id}/blob`);
    expect(secondRes.status).toBe(404);
    expect(await secondRes.json()).toEqual({ error: "Not found" });
  });

  test("POST non-JSON meta returns 400", async () => {
    const res = await postForm({
      blob: new Blob([new Uint8Array([1])]),
      meta: "not json{",
      ttl: "3600",
    });
    expect(res.status).toBe(400);
    expect((await res.json()) as { error: string }).toHaveProperty("error");
  });

  test("POST ttl below min returns 400", async () => {
    const res = await postForm({
      blob: new Blob([new Uint8Array([1])]),
      meta: JSON.stringify({ iv: "x" }),
      ttl: "30",
    });
    expect(res.status).toBe(400);
  });

  test("POST blob larger than maxBlobSize returns 413", async () => {
    const smallApp = createApp(store, makeConfig({ maxBlobSize: 8 }));
    const form = new FormData();
    form.set("blob", new Blob([new Uint8Array(16)]), "big.bin");
    form.set("meta", JSON.stringify({ iv: "x" }));
    form.set("ttl", "3600");
    const res = await smallApp.request("/api/shares", {
      method: "POST",
      body: form,
    });
    expect(res.status).toBe(413);
  });

  test("POST meta longer than maxMetaSize returns 400", async () => {
    const tinyMetaApp = createApp(store, makeConfig({ maxMetaSize: 8 }));
    const form = new FormData();
    form.set("blob", new Blob([new Uint8Array([1])]), "cipher.bin");
    form.set("meta", JSON.stringify({ iv: "0123456789abcdef" }));
    form.set("ttl", "3600");
    const res = await tinyMetaApp.request("/api/shares", {
      method: "POST",
      body: form,
    });
    expect(res.status).toBe(400);
  });

  test("POST with Content-Length exceeding maxBlobSize returns 413 before buffering", async () => {
    const smallApp = createApp(store, makeConfig({ maxBlobSize: 8 }));
    const form = new FormData();
    form.set("blob", new Blob([new Uint8Array(4)]), "cipher.bin");
    form.set("meta", JSON.stringify({ iv: "x" }));
    form.set("ttl", "3600");
    const res = await smallApp.request("/api/shares", {
      method: "POST",
      body: form,
      headers: { "content-length": String(8 + 4096 + 1) },
    });
    expect(res.status).toBe(413);
  });

  test("POST without blob returns 400", async () => {
    const res = await postForm({
      meta: JSON.stringify({ iv: "x" }),
      ttl: "3600",
    });
    expect(res.status).toBe(400);
  });

  test("unknown id: GET meta, GET blob, DELETE all return identical 404 body", async () => {
    const notFound = { error: "Not found" };

    const metaRes = await app.request("/api/shares/nope");
    expect(metaRes.status).toBe(404);
    expect(await metaRes.json()).toEqual(notFound);

    const blobRes = await app.request("/api/shares/nope/blob");
    expect(blobRes.status).toBe(404);
    expect(await blobRes.json()).toEqual(notFound);

    const delRes = await app.request("/api/shares/nope", {
      method: "DELETE",
      headers: { "X-Delete-Token": "whatever" },
    });
    expect(delRes.status).toBe(404);
    expect(await delRes.json()).toEqual(notFound);
  });

  test("DELETE correct token 204 then GET 404; wrong token 404", async () => {
    const res = await postForm({
      blob: new Blob([new Uint8Array([1, 2])]),
      meta: JSON.stringify({ iv: "x" }),
      ttl: "3600",
    });
    const { id, deleteToken } = (await res.json()) as {
      id: string;
      deleteToken: string;
    };

    const wrongRes = await app.request(`/api/shares/${id}`, {
      method: "DELETE",
      headers: { "X-Delete-Token": "wrong" },
    });
    expect(wrongRes.status).toBe(404);
    expect(await wrongRes.json()).toEqual({ error: "Not found" });

    const okRes = await app.request(`/api/shares/${id}`, {
      method: "DELETE",
      headers: { "X-Delete-Token": deleteToken },
    });
    expect(okRes.status).toBe(204);

    const metaRes = await app.request(`/api/shares/${id}`);
    expect(metaRes.status).toBe(404);
  });

  test("DELETE without token header returns 404", async () => {
    const res = await postForm({
      blob: new Blob([new Uint8Array([1, 2])]),
      meta: JSON.stringify({ iv: "x" }),
      ttl: "3600",
    });
    const { id } = (await res.json()) as { id: string };

    const delRes = await app.request(`/api/shares/${id}`, { method: "DELETE" });
    expect(delRes.status).toBe(404);
    expect(await delRes.json()).toEqual({ error: "Not found" });
  });
});

describe("POST /api/shares rate limiting", () => {
  let rlDataDir: string;
  let rlStore: ShareStore;
  let rlApp: ReturnType<typeof createApp>;

  beforeEach(() => {
    rlDataDir = mkdtempSync(join(tmpdir(), "link-rl-"));
    rlStore = new ShareStore(":memory:", rlDataDir);
    rlApp = createApp(rlStore, makeConfig({ rateLimitMax: 2 }));
  });

  afterEach(() => {
    rlStore.close();
    rmSync(rlDataDir, { recursive: true, force: true });
  });

  function postFrom(ip: string): Promise<Response> {
    const form = new FormData();
    form.set("blob", new Blob([new Uint8Array([1])]), "cipher.bin");
    form.set("meta", JSON.stringify({ iv: "x" }));
    form.set("ttl", "3600");
    return rlApp.request("/api/shares", {
      method: "POST",
      body: form,
      headers: { "x-forwarded-for": ip },
    });
  }

  test("limits by x-forwarded-for: 3rd POST from same ip is 429", async () => {
    const first = await postFrom("1.1.1.1");
    expect(first.status).toBe(201);
    const second = await postFrom("1.1.1.1");
    expect(second.status).toBe(201);
    const third = await postFrom("1.1.1.1");
    expect(third.status).toBe(429);
  });

  test("a different x-forwarded-for keeps its own bucket", async () => {
    await postFrom("1.1.1.1");
    await postFrom("1.1.1.1");
    const limited = await postFrom("1.1.1.1");
    expect(limited.status).toBe(429);

    const other = await postFrom("2.2.2.2");
    expect(other.status).toBe(201);
  });

  test("takes the first hop of a comma-separated x-forwarded-for", async () => {
    await postFrom("3.3.3.3, 10.0.0.1");
    await postFrom("3.3.3.3, 10.0.0.2");
    const limited = await postFrom("3.3.3.3, 10.0.0.3");
    expect(limited.status).toBe(429);
  });

  test("without XFF and trustProxy false, requests share the 'unknown' bucket", async () => {
    function postNoHeader(): Promise<Response> {
      const form = new FormData();
      form.set("blob", new Blob([new Uint8Array([1])]), "cipher.bin");
      form.set("meta", JSON.stringify({ iv: "x" }));
      form.set("ttl", "3600");
      return rlApp.request("/api/shares", { method: "POST", body: form });
    }
    expect((await postNoHeader()).status).toBe(201);
    expect((await postNoHeader()).status).toBe(201);
    expect((await postNoHeader()).status).toBe(429);
  });
});
