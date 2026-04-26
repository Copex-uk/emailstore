#!/usr/bin/env bash
# release.sh — tag a new version and push it to trigger the CI release pipeline.
#
# Usage:
#   ./scripts/release.sh v1.2.3
#
# GitHub Actions then runs tests, builds and pushes a versioned Docker image,
# and creates a GitHub Release with auto-generated changelog.

set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 v<major>.<minor>.<patch>"
  echo "  e.g. $0 v1.2.3"
  exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "Error: version must match vX.Y.Z (e.g. v1.2.3 or v1.2.3-rc1)"
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: working tree is not clean — commit or stash changes first"
  git status --short
  exit 1
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" != "main" ]]; then
  echo "Warning: not on 'main' (current: $BRANCH)"
  read -rp "Continue? [y/N] " yn
  [[ "$yn" =~ ^[Yy]$ ]] || exit 1
fi

git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"

echo ""
echo "✓ Tagged and pushed $VERSION"
echo "  Watch the build at: $(git remote get-url origin | sed 's|git@github.com:|https://github.com/|;s|\.git$||')/actions"
