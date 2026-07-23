#!/usr/bin/env bash
# Publishes CaesarLinkKit to its standalone GitHub repo, which is what consumers
# (tish-mac) depend on via .package(url:..., from: "<version>").
#
# The monorepo is the source of truth; the standalone repo is a build product. The one
# thing this script adds is the protocol vectors: in-repo the tests read
# packages/link-sdk/vectors/v2.json directly, but a published package must stand alone,
# so the canonical file is copied to Tests/CaesarLinkKitTests/Vectors/v2.json here.
# Copying at release time (not in git) means the two can never drift while developing.
#
# Usage: Scripts/release.sh 0.1.0 [--dry-run]

set -euo pipefail

VERSION="${1:-}"
DRY_RUN="${2:-}"
REPO="${CAESAR_LINK_SWIFT_REPO:-git@github.com:caesar-team/caesar-link-swift.git}"

if [[ -z "$VERSION" ]]; then
    echo "usage: Scripts/release.sh <version> [--dry-run]" >&2
    exit 1
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: version must be semver, got '$VERSION'" >&2
    exit 1
fi

SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONOREPO_ROOT="$(cd "$SDK_DIR/../.." && pwd)"
VECTORS="$MONOREPO_ROOT/packages/link-sdk/vectors/v2.json"

if [[ ! -f "$VECTORS" ]]; then
    echo "error: canonical vectors not found at $VECTORS" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/pkg"

echo "==> Staging $VERSION from $SDK_DIR"
mkdir -p "$STAGE"
# Ship sources, tests and docs; skip build artefacts and this script.
rsync -a --exclude '.build' --exclude '.swiftpm' --exclude 'Scripts' \
    "$SDK_DIR/" "$STAGE/"

echo "==> Bundling protocol vectors"
mkdir -p "$STAGE/Tests/CaesarLinkKitTests/Vectors"
cp "$VECTORS" "$STAGE/Tests/CaesarLinkKitTests/Vectors/v2.json"

echo "==> Verifying the standalone package is self-contained"
# Runs outside the monorepo, so the vector tests must fall back to the bundled copy.
# If they skip or fail here, the published package would ship untested.
( cd "$STAGE" && swift test 2>&1 | tail -5 )

if [[ "$DRY_RUN" == "--dry-run" ]]; then
    echo "==> Dry run: staged at $STAGE (not pushed)"
    cp -R "$STAGE" "${TMPDIR:-/tmp}/caesar-link-swift-$VERSION"
    echo "    copy kept at ${TMPDIR:-/tmp}/caesar-link-swift-$VERSION"
    exit 0
fi

echo "==> Publishing to $REPO"
CLONE="$WORK/repo"
git clone --quiet "$REPO" "$CLONE" 2>/dev/null || {
    echo "error: cannot clone $REPO — create the repository first" >&2
    exit 1
}

# Mirror the staged tree into the clone, dropping files removed upstream.
rsync -a --delete --exclude '.git' "$STAGE/" "$CLONE/"

cd "$CLONE"
if git diff --quiet && git diff --cached --quiet && [[ -z "$(git status --porcelain)" ]]; then
    echo "==> No content change; tagging existing HEAD"
else
    git add -A
    git commit -q -S -m "release: $VERSION

Generated from caesar-app SDKs/caesar-link-swift at $(git -C "$SDK_DIR" rev-parse --short HEAD).
Protocol vectors bundled from packages/link-sdk/vectors/v2.json."
fi

git tag -s "v$VERSION" -m "v$VERSION"
git push --quiet origin HEAD
git push --quiet origin "v$VERSION"

echo "==> Released v$VERSION"
echo "    .package(url: \"https://github.com/caesar-team/caesar-link-swift.git\", from: \"$VERSION\")"
