#!/usr/bin/env bash
# End-to-end macOS universal entrypoint. Builds independent x64 and arm64
# Chromium.app trees, then merges them with the official script from the pinned
# Chromium checkout.
set -euo pipefail

for name in ${!GIT_@}; do
  unset "$name"
done
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BASELINE="$ROOT/CHROMIUM_BASELINE"
SRC_ROOT="${PROTEUS_CHROMIUM_SRC:-$ROOT/src}"
DEPOT_TOOLS_ROOT="${PROTEUS_DEPOT_TOOLS_DIR:-$ROOT/depot_tools}"

usage() {
  echo "usage: build-macos.sh [--baseline <file>] [--source-root <absolute-directory>] [--depot-tools-root <absolute-directory>]" >&2
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --baseline)
      [ "$#" -ge 2 ] || usage
      BASELINE="$2"
      shift 2
      ;;
    --source-root)
      [ "$#" -ge 2 ] || usage
      SRC_ROOT="$2"
      shift 2
      ;;
    --depot-tools-root)
      [ "$#" -ge 2 ] || usage
      DEPOT_TOOLS_ROOT="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "ERROR: build-macos.sh must run on macOS" >&2
  exit 1
fi
case "$SRC_ROOT" in
  /*) ;;
  *) echo "ERROR: --source-root must be absolute" >&2; exit 1 ;;
esac
case "$DEPOT_TOOLS_ROOT" in
  /*) ;;
  *) echo "ERROR: --depot-tools-root must be absolute" >&2; exit 1 ;;
esac

normalize_fresh_root() {
  local input="$1"
  local label="$2"
  local parent="${input%/*}"
  local name="${input##*/}"
  local canonical_parent
  case "$input" in
    *$'\n'*|*$'\r'*|*$'\t'*)
      echo "ERROR: $label contains a control character" >&2
      exit 1
      ;;
  esac
  if [ -z "$parent" ]; then parent="/"; fi
  if [ -z "$name" ] || [ "$name" = "." ] || [ "$name" = ".." ]; then
    echo "ERROR: $label must name a non-root directory" >&2
    exit 1
  fi
  if [ ! -d "$parent" ]; then
    echo "ERROR: parent of $label does not exist: $parent" >&2
    exit 1
  fi
  canonical_parent="$(cd "$parent" && pwd -P)"
  printf '%s/%s\n' "${canonical_parent%/}" "$name"
}

SRC_ROOT="$(normalize_fresh_root "$SRC_ROOT" source-root)"
DEPOT_TOOLS_ROOT="$(normalize_fresh_root "$DEPOT_TOOLS_ROOT" depot-tools-root)"

if [ -n "${PROTEUS_CC_WRAPPER:-}" ]; then
  echo "ERROR: PROTEUS_CC_WRAPPER is not part of the locked M0 build contract" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for Chromium's universalizer.py" >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js is required" >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: Git is required" >&2
  exit 1
fi
if [ ! -x /usr/bin/lipo ]; then
  echo "ERROR: /usr/bin/lipo is required to validate the universal app" >&2
  exit 1
fi
NODE_BIN="$(command -v node)"
GIT_BIN="$(command -v git)"
PYTHON_BIN="$(command -v python3)"
case "$NODE_BIN:$GIT_BIN:$PYTHON_BIN" in
  /*:/*:/*) ;;
  *) echo "ERROR: Node.js, Git, and Python must resolve to absolute executable paths" >&2; exit 1 ;;
esac

export PROTEUS_CHROMIUM_SRC="$SRC_ROOT"
export PROTEUS_DEPOT_TOOLS_DIR="$DEPOT_TOOLS_ROOT"
export PROTEUS_GIT_BIN="$GIT_BIN"

dependency_lock() {
  local command="$1"
  local state="$2"
  local script="$ROOT/scripts/dependency-lock.mjs"
  if [ ! -f "$script" ]; then
    echo "ERROR: required dependency-lock.mjs is absent; cannot $command the $state dependency state" >&2
    exit 1
  fi
  if [ -L "$script" ]; then
    echo "ERROR: dependency-lock.mjs must be an ordinary non-symlink file" >&2
    exit 1
  fi
  "$NODE_BIN" "$script" "$command" \
    --client-root "$SRC_ROOT" \
    --depot-tools "$DEPOT_TOOLS_ROOT" \
    --chromium-state "$state"
}

capture_effective_args() {
  local relative_out="$1"
  local destination="$2"
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    echo "ERROR: effective GN args output already exists: $destination" >&2
    exit 1
  fi
  (
    set -o noclobber
    "$GN" args "$relative_out" --list --short >"$destination"
  )
  if [ ! -s "$destination" ] || [ -L "$destination" ]; then
    echo "ERROR: expanded GN args were not captured safely: $destination" >&2
    exit 1
  fi
}

echo "==> provisioning the pinned macOS checkout"
"$ROOT/scripts/fetch-chromium.sh" --baseline "$BASELINE"

dependency_lock capture clean
dependency_lock verify clean

echo "==> applying the active M0 patch series"
"$NODE_BIN" "$ROOT/scripts/apply-patches.mjs"

dependency_lock verify patched

SOURCE="$SRC_ROOT/src"
GN="$DEPOT_TOOLS_ROOT/gn"
AUTONINJA="$DEPOT_TOOLS_ROOT/autoninja"
BASE_ARGS="$ROOT/build/args.gn"
OUT_X64="$SOURCE/out/Proteus-x64"
OUT_ARM64="$SOURCE/out/Proteus-arm64"
OUT_UNIVERSAL="$SOURCE/out/Proteus-universal"
X64_APP="$OUT_X64/Chromium.app"
ARM64_APP="$OUT_ARM64/Chromium.app"
UNIVERSAL_APP="$OUT_UNIVERSAL/Chromium.app"
UNIVERSALIZER="$SOURCE/chrome/installer/mac/universalizer.py"

"$NODE_BIN" "$ROOT/scripts/depot-tools-checkout.mjs" \
  --root "$DEPOT_TOOLS_ROOT" >/dev/null
"$NODE_BIN" "$ROOT/scripts/chromium-checkout.mjs" \
  --source "$SOURCE" \
  --state patched >/dev/null

if [ ! -x "$GN" ] || [ -L "$GN" ]; then
  echo "ERROR: pinned depot_tools lacks an ordinary executable gn entrypoint" >&2
  exit 1
fi
if [ ! -x "$AUTONINJA" ] || [ -L "$AUTONINJA" ]; then
  echo "ERROR: pinned depot_tools lacks an ordinary executable autoninja entrypoint" >&2
  exit 1
fi
if [ ! -f "$UNIVERSALIZER" ] || [ -L "$UNIVERSALIZER" ]; then
  echo "ERROR: pinned Chromium checkout lacks an ordinary official universalizer.py" >&2
  exit 1
fi
"$GIT_BIN" -C "$SOURCE" ls-files --error-unmatch \
  chrome/installer/mac/universalizer.py >/dev/null

for out in "$OUT_X64" "$OUT_ARM64" "$OUT_UNIVERSAL"; do
  if [ -e "$out" ] || [ -L "$out" ]; then
    echo "ERROR: build output directory must not already exist: $out" >&2
    exit 1
  fi
done

TARGET_CPU_LINES="$(grep -Fxc 'target_cpu = "x64"' "$BASE_ARGS" || true)"
if [ "$TARGET_CPU_LINES" -ne 1 ]; then
  echo "ERROR: locked args.gn must contain exactly one x64 target_cpu assignment" >&2
  exit 1
fi

if [ -e "$SOURCE/out" ] || [ -L "$SOURCE/out" ]; then
  if [ ! -d "$SOURCE/out" ] || [ -L "$SOURCE/out" ]; then
    echo "ERROR: Chromium out path must be an ordinary directory" >&2
    exit 1
  fi
else
  mkdir "$SOURCE/out"
fi
mkdir "$OUT_X64" "$OUT_ARM64" "$OUT_UNIVERSAL"
cp "$BASE_ARGS" "$OUT_X64/args.gn"
sed 's/^target_cpu = "x64"$/target_cpu = "arm64"/' \
  "$BASE_ARGS" >"$OUT_ARM64/args.gn"
if [ "$(grep -Fxc 'target_cpu = "arm64"' "$OUT_ARM64/args.gn" || true)" -ne 1 ]; then
  echo "ERROR: failed to derive the locked arm64 GN args" >&2
  exit 1
fi

# Revalidate the resolved graph and patched source immediately before invoking
# either architecture's build tools.
dependency_lock verify patched
"$NODE_BIN" "$ROOT/scripts/chromium-checkout.mjs" \
  --source "$SOURCE" \
  --state patched >/dev/null

cd "$SOURCE"
echo "==> gn gen out/Proteus-x64"
"$GN" gen out/Proteus-x64 --fail-on-unused-args
echo "==> capturing expanded GN args for macOS x64"
capture_effective_args \
  out/Proteus-x64 \
  "$OUT_X64/effective-args.gn"
echo "==> autoninja macOS x64 chrome + Network Time unit-test host"
"$AUTONINJA" -C out/Proteus-x64 chrome components_unittests

dependency_lock verify patched
"$NODE_BIN" "$ROOT/scripts/chromium-checkout.mjs" \
  --source "$SOURCE" \
  --state patched >/dev/null

echo "==> gn gen out/Proteus-arm64"
"$GN" gen out/Proteus-arm64 --fail-on-unused-args
echo "==> capturing expanded GN args for macOS arm64"
capture_effective_args \
  out/Proteus-arm64 \
  "$OUT_ARM64/effective-args.gn"
echo "==> autoninja macOS arm64 chrome + Network Time unit-test host"
"$AUTONINJA" -C out/Proteus-arm64 chrome components_unittests

case "$(uname -m)" in
  x86_64) NETWORK_TIME_TEST="$OUT_X64/components_unittests" ;;
  arm64) NETWORK_TIME_TEST="$OUT_ARM64/components_unittests" ;;
  *)
    echo "ERROR: unsupported macOS builder architecture: $(uname -m)" >&2
    exit 1
    ;;
esac
if [ ! -f "$NETWORK_TIME_TEST" ] || [ -L "$NETWORK_TIME_TEST" ] || \
   [ ! -x "$NETWORK_TIME_TEST" ]; then
  echo "ERROR: native components_unittests is missing or unsafe" >&2
  exit 1
fi
echo "==> verifying the Network Time default-off and explicit override paths"
"$NETWORK_TIME_TEST" \
  --gtest_filter=NetworkTimeFeatureDefaultTest.QueryingIsDisabledByDefault:NetworkTimeTrackerTest.NoNetworkQueryWhileFeatureDisabled \
  --test-launcher-bot-mode

for app in "$X64_APP" "$ARM64_APP"; do
  if [ ! -d "$app" ] || [ -L "$app" ]; then
    echo "ERROR: single-architecture Chromium.app was not produced: $app" >&2
    exit 1
  fi
done

X64_BINARY="$X64_APP/Contents/MacOS/Chromium"
ARM64_BINARY="$ARM64_APP/Contents/MacOS/Chromium"
for binary in "$X64_BINARY" "$ARM64_BINARY"; do
  if [ ! -f "$binary" ] || [ -L "$binary" ] || [ ! -x "$binary" ]; then
    echo "ERROR: single-architecture Chromium executable is missing or unsafe: $binary" >&2
    exit 1
  fi
done
if [ "$(/usr/bin/lipo -archs "$X64_BINARY")" != "x86_64" ]; then
  echo "ERROR: x64 build is not a single x86_64 Chromium executable" >&2
  exit 1
fi
if [ "$(/usr/bin/lipo -archs "$ARM64_BINARY")" != "arm64" ]; then
  echo "ERROR: arm64 build is not a single arm64 Chromium executable" >&2
  exit 1
fi

echo "==> merging x64 + arm64 with pinned Chromium universalizer.py"
"$PYTHON_BIN" "$UNIVERSALIZER" "$X64_APP" "$ARM64_APP" "$UNIVERSAL_APP"

if [ ! -d "$UNIVERSAL_APP" ] || [ -L "$UNIVERSAL_APP" ]; then
  echo "ERROR: official universalizer.py did not produce Chromium.app" >&2
  exit 1
fi
UNIVERSAL_BINARY="$UNIVERSAL_APP/Contents/MacOS/Chromium"
if [ ! -f "$UNIVERSAL_BINARY" ] || [ -L "$UNIVERSAL_BINARY" ] || \
   [ ! -x "$UNIVERSAL_BINARY" ]; then
  echo "ERROR: universal Chromium executable is missing or unsafe" >&2
  exit 1
fi
UNIVERSAL_ARCHS="$(/usr/bin/lipo -archs \
  "$UNIVERSAL_BINARY")"
case " $UNIVERSAL_ARCHS " in
  *" x86_64 "*) ;;
  *) echo "ERROR: universal Chromium executable lacks x86_64" >&2; exit 1 ;;
esac
case " $UNIVERSAL_ARCHS " in
  *" arm64 "*) ;;
  *) echo "ERROR: universal Chromium executable lacks arm64" >&2; exit 1 ;;
esac
if [ "$(printf '%s\n' "$UNIVERSAL_ARCHS" | wc -w | tr -d ' ')" -ne 2 ]; then
  echo "ERROR: universal Chromium executable has an unexpected architecture set: $UNIVERSAL_ARCHS" >&2
  exit 1
fi

echo "==> macOS universal build complete"
echo "    x64 app: $X64_APP"
echo "    arm64 app: $ARM64_APP"
echo "    universal app: $UNIVERSAL_APP"
echo "    x64 effective GN args: $OUT_X64/effective-args.gn"
echo "    arm64 effective GN args: $OUT_ARM64/effective-args.gn"
