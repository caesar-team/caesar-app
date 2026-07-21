# syntax=docker/dockerfile:1
# Build context is the monorepo root (see docker-compose.yml `context: .`).
FROM oven/bun:1.2.20 AS base
WORKDIR /app

# This is a Bun workspace: `bun install --frozen-lockfile` validates the WHOLE
# workspace graph against bun.lock, so a partial copy fails. We copy the full
# context (the .dockerignore at the repo root trims node_modules, dist, tests,
# data, .git, .worktrees), then install. The server itself has no @caesar/*
# runtime dependency, but the frozen lockfile still needs every member present.
COPY . .

RUN bun install --frozen-lockfile --production

ENV NODE_ENV=production
ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 3000

# Base image ships neither curl nor wget, so probe health via Bun's fetch.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "fetch('http://localhost:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

WORKDIR /app/apps/link/server
CMD ["bun", "run", "src/main.ts"]
