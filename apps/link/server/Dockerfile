# syntax=docker/dockerfile:1
# Build context is the monorepo root (see docker-compose.yml `context: .`).

# --- builder: full install + build the web SPA (and workspace deps for its typecheck) ---
FROM oven/bun:1.2.20 AS builder
WORKDIR /app
# Full context; the repo .dockerignore trims node_modules, dist, tests, .git, .worktrees, data.
COPY . .
RUN bun install --frozen-lockfile
# Produce the SPA bundle only. Vite aliases @caesar/link-sdk and @caesar/crypto to
# their TS source, so no workspace dist is needed and tsc/type-checking (a separate
# CI gate) is skipped here — the image just needs the built assets to serve.
RUN cd apps/link/web && bunx vite build

# --- runtime: production deps + server source + built SPA ---
FROM oven/bun:1.2.20 AS runtime
WORKDIR /app
COPY . .
RUN bun install --frozen-lockfile --production
COPY --from=builder /app/apps/link/web/dist ./apps/link/web/dist

ENV NODE_ENV=production
ENV DATA_DIR=/data
ENV WEB_DIR=/app/apps/link/web/dist
VOLUME ["/data"]
EXPOSE 3000

# Base image ships neither curl nor wget, so probe health via Bun's fetch.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "fetch('http://localhost:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

WORKDIR /app/apps/link/server
CMD ["bun", "run", "src/main.ts"]
