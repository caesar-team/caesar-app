import { Hono } from "hono";
import type { Context } from "hono";
import { rateLimiter } from "hono-rate-limiter";
import type { Config } from "./config.js";
import type { ShareStore } from "./store.js";

// First (leftmost) hop of X-Forwarded-For, trimmed; empty string when absent/blank.
function firstForwardedHop(c: Context): string {
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded === undefined) {
    return "";
  }
  return forwarded.split(",")[0]?.trim() ?? "";
}

// Rate-limit key. Client-supplied XFF is only honored when the operator opts in
// via trustProxy; otherwise the Bun peer IP is authoritative, falling back to
// XFF (tests) then a shared "unknown" bucket.
function clientKey(config: Config, c: Context): string {
  if (config.trustProxy) {
    const forwarded = firstForwardedHop(c);
    if (forwarded.length > 0) {
      return forwarded;
    }
  }

  const server = c.env as { requestIP?: (r: Request) => { address: string } | null } | undefined;
  const ip = server?.requestIP?.(c.req.raw)?.address;
  if (ip) {
    return ip;
  }

  const forwarded = firstForwardedHop(c);
  return forwarded.length > 0 ? forwarded : "unknown";
}

type FormValue = ReturnType<FormData["get"]>;

// True when the declared body size clearly exceeds the blob limit (+ multipart slack),
// letting us reject before buffering the whole upload.
function exceedsDeclaredSize(c: Context, config: Config): boolean {
  const cl = Number(c.req.header("content-length"));
  return Number.isFinite(cl) && cl > config.maxBlobSize + 4096;
}

// Returns the in-range ttl, or undefined when absent/out of range/invalid.
function parseTtl(raw: FormValue, config: Config): number | undefined {
  const ttl = typeof raw === "string" ? Number.parseInt(raw, 10) : Number.NaN;
  if (!Number.isInteger(ttl) || ttl < config.minTtl || ttl > config.maxTtl) {
    return undefined;
  }
  return ttl;
}

// Returns an error message when meta is oversized or non-JSON, else null.
function metaError(meta: string, config: Config): string | null {
  if (meta.length > config.maxMetaSize) {
    return "meta too large";
  }
  try {
    JSON.parse(meta);
  } catch {
    return "meta must be valid JSON";
  }
  return null;
}

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

  app.post(
    "/api/shares",
    rateLimiter({
      windowMs: config.rateLimitWindowMs,
      limit: config.rateLimitMax,
      standardHeaders: "draft-6",
      keyGenerator: (c) => clientKey(config, c),
    })
  );

  app.post("/api/shares", async (c) => {
    if (exceedsDeclaredSize(c, config)) {
      return c.json({ error: "Blob too large" }, 413);
    }

    const form = await c.req.formData();

    const blob = form.get("blob");
    if (!(blob instanceof Blob)) {
      return c.json({ error: "Missing or invalid blob" }, 400);
    }

    const meta = form.get("meta");
    if (typeof meta !== "string") {
      return c.json({ error: "Missing meta" }, 400);
    }
    const metaErr = metaError(meta, config);
    if (metaErr !== null) {
      return c.json({ error: metaErr }, 400);
    }

    const ttl = parseTtl(form.get("ttl"), config);
    if (ttl === undefined) {
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

  // Serve the built web SPA when configured. Real assets (with an extension) are
  // served from disk; every other GET falls back to index.html so client routes
  // like /s/:id load the app. API routes are matched above and win.
  if (config.webDir) {
    const webDir = config.webDir;
    const indexHtml = `${webDir}/index.html`;
    app.get("*", async (c) => {
      const pathname = new URL(c.req.url).pathname;
      if (pathname.startsWith("/api/")) {
        return notFound(c);
      }
      const isAsset = pathname !== "/" && pathname.includes(".");
      if (isAsset) {
        const file = Bun.file(`${webDir}${pathname}`);
        if (await file.exists()) {
          return new Response(file);
        }
      }
      return new Response(Bun.file(indexHtml), { headers: { "content-type": "text/html" } });
    });
  }

  return app;
}
