# syntax=docker/dockerfile:1
# Build context is the monorepo root (see docker-compose.yml `context: .`).
FROM oven/bun:1.2.20 AS base
WORKDIR /app

# The server (@caesar/link-server) has NO @caesar/* runtime dependency — it only
# uses hono, hono-rate-limiter, nanoid and Bun built-ins. So we keep the copy
# minimal: the root manifests + this one workspace package. No packages/ copy is
# needed for the production runtime install.
COPY package.json bun.lock ./
COPY apps/link/server/package.json apps/link/server/package.json

# Try a frozen, production-only install first. The frozen check can fail because
# the lockfile describes the whole workspace while we only copied a slice of it;
# fall back to a non-frozen production install in that case.
RUN bun install --frozen-lockfile --production || bun install --production

# App source (src/main.ts is the entrypoint; Bun runs TypeScript directly).
COPY apps/link/server ./apps/link/server

ENV NODE_ENV=production
ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 3000

# Base image ships neither curl nor wget, so probe health via Bun's fetch.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "fetch('http://localhost:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

WORKDIR /app/apps/link/server
CMD ["bun", "run", "src/main.ts"]
