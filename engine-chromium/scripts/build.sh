#!/usr/bin/env bash
# build.sh — gn gen + ninja build of the Proteus Chromium engine.
# REQUIRES BUILD INFRA (docs/tdd/05 §2). Uses the reproducible args in build/args.gn
# and whatever compile cache (sccache/reclient) the host provides via cc_wrapper.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC_DIR="${PROTEUS_CHROMIUM_SRC:-$ROOT/src}/src"
OUT_DIR="out/Proteus"

if [ ! -d "$SRC_DIR" ]; then
  echo "ERROR: no Chromium tree at $SRC_DIR. Run fetch-chromium.sh + apply-patches.mjs first." >&2
  exit 1
fi
cd "$SRC_DIR"

echo "==> gn gen ${OUT_DIR} with reproducible args"
mkdir -p "$OUT_DIR"
cp "$ROOT/build/args.gn" "$OUT_DIR/args.gn"
# Allow the host to append a cc_wrapper line for cache without editing the tracked file.
if [ -n "${PROTEUS_CC_WRAPPER:-}" ]; then
  echo "cc_wrapper = \"${PROTEUS_CC_WRAPPER}\"" >> "$OUT_DIR/args.gn"
fi
gn gen "$OUT_DIR"

echo "==> ninja build (this is the multi-hour step)"
autoninja -C "$OUT_DIR" chrome

echo "==> build complete. Artifact under $SRC_DIR/$OUT_DIR"
CHROMIUM_COMMIT="$(git rev-parse HEAD)"
echo "==> source commit: $CHROMIUM_COMMIT"
echo "==> next: scripts/provenance.mjs --artifact <file> --chromium-commit $CHROMIUM_COMMIT --platform <id> --invocation-id <run-id>"
echo "==> then run the artifact-driven verify-lab gate"
