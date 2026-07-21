import { Hono } from "hono";
import type { Context } from "hono";
import type { Config } from "./config.js";
import type { ShareStore } from "./store.js";

type FormValue = ReturnType<FormData["get"]>;

// Returns the parsed positive int, null when absent, or undefined when invalid.
function parseViews(raw: FormValue): number | null | undefined {
  if (raw === null) {
    return null;
  }
  if (typeof raw !== "string") {
    return undefined;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0 || String(parsed) !== raw) {
    return undefined;
  }
  return parsed;
}

export function createApp(store: ShareStore, config: Config): Hono {
  const app = new Hono();

  const notFound = (c: Context) => c.json({ error: "Not found" }, 404);

  app.get("/api/health", (c) => c.json({ ok: true }));

  app.post("/api/shares", async (c) => {
    const form = await c.req.formData();

    const blob = form.get("blob");
    if (!(blob instanceof Blob)) {
      return c.json({ error: "Missing or invalid blob" }, 400);
    }

    const meta = form.get("meta");
    if (typeof meta !== "string") {
      return c.json({ error: "Missing meta" }, 400);
    }
    try {
      JSON.parse(meta);
    } catch {
      return c.json({ error: "meta must be valid JSON" }, 400);
    }

    const ttlRaw = form.get("ttl");
    const ttl = typeof ttlRaw === "string" ? Number.parseInt(ttlRaw, 10) : Number.NaN;
    if (!Number.isInteger(ttl) || ttl < config.minTtl || ttl > config.maxTtl) {
      return c.json({ error: "ttl out of range" }, 400);
    }

    const views = parseViews(form.get("views"));
    if (views === undefined) {
      return c.json({ error: "views must be a positive integer" }, 400);
    }

    if (blob.size > config.maxBlobSize) {
      return c.json({ error: "Blob too large" }, 413);
    }

    const bytes = new Uint8Array(await blob.arrayBuffer());
    const { id, deleteToken } = store.create({
      blob: bytes,
      meta,
      ttlSeconds: ttl,
      views,
      now: Date.now(),
    });
    return c.json({ id, deleteToken }, 201);
  });

  app.get("/api/shares/:id", (c) => {
    const rec = store.getMeta(c.req.param("id"), Date.now());
    if (rec === null) {
      return notFound(c);
    }
    return c.json({
      meta: JSON.parse(rec.meta),
      size: rec.size,
      viewsLeft: rec.viewsLeft,
      expiresAt: rec.expiresAt,
    });
  });

  app.get("/api/shares/:id/blob", (c) => {
    const bytes = store.consumeBlob(c.req.param("id"), Date.now());
    if (bytes === null) {
      return notFound(c);
    }
    return new Response(bytes, {
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(bytes.byteLength),
      },
    });
  });

  app.delete("/api/shares/:id", (c) => {
    const token = c.req.header("X-Delete-Token");
    if (token === undefined) {
      return notFound(c);
    }
    if (!store.remove(c.req.param("id"), token)) {
      return notFound(c);
    }
    return c.body(null, 204);
  });

  return app;
}
