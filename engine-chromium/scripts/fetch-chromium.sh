#!/usr/bin/env bash
# fetch-chromium.sh — fetch/sync the pinned Chromium source via depot_tools.
#
# REQUIRES DEDICATED BUILD INFRA: ~100 GB disk, depot_tools on PATH, good network.
# This does not run inside the planning environment; it is the real first step of
# the build farm (docs/tdd/05 §2). It is intentionally strict (set -euo pipefail)
# and idempotent.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# Read the pinned baseline.
# shellcheck disable=SC1091
source "$ROOT/CHROMIUM_BASELINE"
: "${CHROMIUM_STABLE:?CHROMIUM_BASELINE must define CHROMIUM_STABLE}"

SRC_DIR="${PROTEUS_CHROMIUM_SRC:-$ROOT/src}"

echo "==> Proteus: fetching Chromium ${CHROMIUM_STABLE} into ${SRC_DIR}"

if ! command -v fetch >/dev/null 2>&1; then
  echo "ERROR: depot_tools not on PATH. Install from:" >&2
  echo "  https://commondatastorage.googleapis.com/chrome-infra-docs/flat/depot_tools/docs/html/depot_tools_tutorial.html" >&2
  exit 1
fi

mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

if [ ! -d "src" ]; then
  echo "==> initial fetch (this downloads tens of GB)…"
  fetch --nohooks chromium
fi

cd src
echo "==> checking out tag ${CHROMIUM_STABLE}…"
git fetch --tags origin
git checkout "tags/${CHROMIUM_STABLE}" -B "proteus-${CHROMIUM_STABLE}"

echo "==> gclient sync to the pinned tag…"
gclient sync -D --force --reset --with_branch_heads

echo "==> done. Source at ${SRC_DIR}/src @ ${CHROMIUM_STABLE}"
