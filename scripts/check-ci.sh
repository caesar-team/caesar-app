#!/usr/bin/env bash
# Everything CI runs for Link, in CI's order. The workflow calls this script rather than
# repeating the steps, so `bun run check:ci` locally cannot drift from what gates a PR.
#
# Assumes dependencies are installed (CI does `bun install --frozen-lockfile` first).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Biome is pinned to the version matching this repo's config schema.
BIOME="@biomejs/biome@1.9.4"
LINT_PATHS=(
    packages/crypto/src
    packages/link-sdk/src
    apps/link/server/src
    apps/link/web/src
)

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

# The crypto/sdk dist feeds the web typecheck and the sdk/web tests. --build --force
# guarantees emit even when a composite .tsbuildinfo is stale.
step "Build workspace packages"
(cd packages/crypto && bunx tsc --build --force)
(cd packages/link-sdk && bunx tsc --build --force)

step "Build web bundle"
(cd apps/link/web && bunx vite build)

step "Typecheck server"
bun run --filter @caesar/link-server build

step "Test"
(cd packages/crypto && bun test)
(cd packages/link-sdk && bun test)
(cd apps/link/server && bun test)
(cd apps/link/web && bun test src/lib)

step "Lint"
bunx "$BIOME" check "${LINT_PATHS[@]}"

printf '\n\033[32mAll checks passed.\033[0m\n'
