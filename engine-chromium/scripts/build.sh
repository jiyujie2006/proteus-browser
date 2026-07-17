#!/usr/bin/env bash
# build.sh — gn gen + ninja build of the Proteus Chromium engine.
# REQUIRES BUILD INFRA (docs/tdd/05 §2). Uses the reproducible args in build/args.gn
# with cache wrappers deliberately disabled by the immutable M0 build contract.
set -euo pipefail

# Do not let ambient Git repository/config overrides redirect source checks.
for name in ${!GIT_@}; do
  unset "$name"
done
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC_DIR="${PROTEUS_CHROMIUM_SRC:-$ROOT/src}/src"
DEPOT_TOOLS_DIR="${PROTEUS_DEPOT_TOOLS_DIR:-$ROOT/depot_tools}"
OUT_DIR="out/Proteus"

if [ ! -d "$SRC_DIR" ]; then
  echo "ERROR: no Chromium tree at $SRC_DIR. Run fetch-chromium.sh + apply-patches.mjs first." >&2
  exit 1
fi
if [ -n "${PROTEUS_CC_WRAPPER:-}" ]; then
  echo "ERROR: PROTEUS_CC_WRAPPER is not part of the locked M0 build contract" >&2
  exit 1
fi
if [ ! -d "$DEPOT_TOOLS_DIR" ]; then
  echo "ERROR: no pinned depot_tools checkout at $DEPOT_TOOLS_DIR" >&2
  exit 1
fi

node "$ROOT/scripts/depot-tools-checkout.mjs" \
  --root "$DEPOT_TOOLS_DIR" >/dev/null
node "$ROOT/scripts/chromium-checkout.mjs" \
  --source "$SRC_DIR" \
  --state patched >/dev/null

export DEPOT_TOOLS_UPDATE=0
export DEPOT_TOOLS_METRICS=0
PATH="$DEPOT_TOOLS_DIR:$PATH"
export PATH

if [ ! -x "$DEPOT_TOOLS_DIR/gn" ] || [ ! -x "$DEPOT_TOOLS_DIR/autoninja" ]; then
  echo "ERROR: pinned depot_tools lacks executable gn/autoninja entrypoints" >&2
  exit 1
fi

cd "$SRC_DIR"

echo "==> gn gen ${OUT_DIR} with reproducible args"
mkdir -p "$OUT_DIR"
cp "$ROOT/build/args.gn" "$OUT_DIR/args.gn"
"$DEPOT_TOOLS_DIR/gn" gen "$OUT_DIR" --fail-on-unused-args

echo "==> ninja build (this is the multi-hour step)"
"$DEPOT_TOOLS_DIR/autoninja" -C "$OUT_DIR" chrome components_unittests

NETWORK_TIME_TEST="$SRC_DIR/$OUT_DIR/components_unittests"
if [ ! -f "$NETWORK_TIME_TEST" ] || [ -L "$NETWORK_TIME_TEST" ] || \
   [ ! -x "$NETWORK_TIME_TEST" ]; then
  echo "ERROR: components_unittests was not produced as an ordinary executable" >&2
  exit 1
fi
echo "==> verifying the Network Time feature disable/explicit-enable paths"
"$NETWORK_TIME_TEST" \
  --gtest_filter=NetworkTimeTrackerTest.NoNetworkQueryWhileFeatureDisabled \
  --test-launcher-bot-mode

echo "==> build complete. Artifact under $SRC_DIR/$OUT_DIR"
CHROMIUM_COMMIT="$(git rev-parse HEAD)"
echo "==> source commit: $CHROMIUM_COMMIT"
echo "==> effective GN args: $SRC_DIR/$OUT_DIR/args.gn"
echo "==> next: scripts/provenance.mjs --artifact <file> --effective-gn-args $SRC_DIR/$OUT_DIR/args.gn --chromium-commit $CHROMIUM_COMMIT --platform <id> --invocation-id <run-id>"
echo "==> then run the artifact-driven verify-lab gate"
