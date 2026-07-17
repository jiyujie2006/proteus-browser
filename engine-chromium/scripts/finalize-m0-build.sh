#!/usr/bin/env bash
# Turn one completed Linux/macOS Chromium build into the complete hard-M0
# bundle and records consumed by the Sigstore builder workflow.
set -euo pipefail

for name in ${!GIT_@}; do
  unset "$name"
done
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$ENGINE_ROOT/.." && pwd)"

PLATFORM=""
SLOT=""
SRC_ROOT=""
DEPOT_TOOLS_ROOT=""
ARTIFACT_ROOT=""
GIT_BIN=""
PYTHON_BIN=""
LINUX_SANDBOX=""

usage() {
  echo "usage: finalize-m0-build.sh --platform <linux-x64|macos-universal> --slot <A|B> --source-root <absolute-dir> --depot-tools-root <absolute-dir> --artifact-root <absolute-dir> --git <absolute-file> --python <absolute-file> [--linux-sandbox <absolute-file>]" >&2
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform) [ "$#" -ge 2 ] || usage; PLATFORM="$2"; shift 2 ;;
    --slot) [ "$#" -ge 2 ] || usage; SLOT="$2"; shift 2 ;;
    --source-root) [ "$#" -ge 2 ] || usage; SRC_ROOT="$2"; shift 2 ;;
    --depot-tools-root) [ "$#" -ge 2 ] || usage; DEPOT_TOOLS_ROOT="$2"; shift 2 ;;
    --artifact-root) [ "$#" -ge 2 ] || usage; ARTIFACT_ROOT="$2"; shift 2 ;;
    --git) [ "$#" -ge 2 ] || usage; GIT_BIN="$2"; shift 2 ;;
    --python) [ "$#" -ge 2 ] || usage; PYTHON_BIN="$2"; shift 2 ;;
    --linux-sandbox) [ "$#" -ge 2 ] || usage; LINUX_SANDBOX="$2"; shift 2 ;;
    *) usage ;;
  esac
done

case "$PLATFORM" in
  linux-x64)
    [ "$(uname -s)" = "Linux" ] || {
      echo "ERROR: linux-x64 finalization requires Linux" >&2
      exit 1
    }
    [ -n "$LINUX_SANDBOX" ] || usage
    ;;
  macos-universal)
    [ "$(uname -s)" = "Darwin" ] || {
      echo "ERROR: macos-universal finalization requires macOS" >&2
      exit 1
    }
    [ -z "$LINUX_SANDBOX" ] || usage
    ;;
  *) usage ;;
esac
case "$SLOT" in A|B) ;; *) usage ;; esac
for value in "$SRC_ROOT" "$DEPOT_TOOLS_ROOT" "$ARTIFACT_ROOT" "$GIT_BIN" "$PYTHON_BIN"; do
  case "$value" in /*) ;; *) usage ;; esac
done
if [ -n "$LINUX_SANDBOX" ]; then
  case "$LINUX_SANDBOX" in /*) ;; *) usage ;; esac
fi
for executable in "$GIT_BIN" "$PYTHON_BIN"; do
  if [ ! -f "$executable" ] || [ -L "$executable" ] || [ ! -x "$executable" ]; then
    echo "ERROR: required tool is not an ordinary executable: $executable" >&2
    exit 1
  fi
done

SOURCE="$SRC_ROOT/src"
DEPENDENCY_LOCK="$SRC_ROOT/.proteus-dependencies.json"
GN="$DEPOT_TOOLS_ROOT/gn"
BUILD_ROOT="$ARTIFACT_ROOT/builds/$PLATFORM/$SLOT"
RECORDS="$BUILD_ROOT/records"
BUNDLE="$BUILD_ROOT/bundle"

if [ ! -d "$SOURCE" ] || [ -L "$SOURCE" ]; then
  echo "ERROR: Chromium source root is missing or unsafe: $SOURCE" >&2
  exit 1
fi
if [ ! -f "$DEPENDENCY_LOCK" ] || [ -L "$DEPENDENCY_LOCK" ]; then
  echo "ERROR: resolved dependency lock is missing or unsafe" >&2
  exit 1
fi
if [ ! -x "$GN" ] || [ -L "$GN" ]; then
  echo "ERROR: pinned gn entrypoint is missing or unsafe" >&2
  exit 1
fi
if [ -e "$BUILD_ROOT" ] || [ -L "$BUILD_ROOT" ]; then
  echo "ERROR: M0 build-record root must be fresh: $BUILD_ROOT" >&2
  exit 1
fi
mkdir -p "$RECORDS"

EFFECTIVE_RECORD="$RECORDS/effective-gn-args.json"
TOOLCHAIN_LOCK="$RECORDS/complete-toolchain-lock.json"
RUNTIME_DEPS="$RECORDS/runtime-deps.txt"
MANIFEST="$RECORDS/bundle-manifest.json"
LIVE_REPORT="$RECORDS/live-report.json"
SBOM="$RECORDS/build-sbom.cdx.json"

if [ "$PLATFORM" = "linux-x64" ]; then
  OUT_RELATIVE="out/Proteus"
  OUT_DIR="$SOURCE/$OUT_RELATIVE"
  ENTRYPOINT="$BUNDLE/chrome"
  EFFECTIVE_ARGS=(--configuration x86_64 "$OUT_RELATIVE" "$OUT_DIR/effective-args.gn")
  TOOLCHAIN_CONFIG=(--configuration x86_64 "$OUT_DIR")
  CREDITS_ARGS=(--credits-out-dir "$OUT_DIR")
  UNIVERSAL_ARGS=()
else
  OUT_RELATIVE="out/Proteus-universal"
  OUT_DIR="$SOURCE/$OUT_RELATIVE"
  OUT_X64="$SOURCE/out/Proteus-x64"
  OUT_ARM64="$SOURCE/out/Proteus-arm64"
  ENTRYPOINT="$BUNDLE/Chromium.app/Contents/MacOS/Chromium"
  EFFECTIVE_ARGS=(
    --configuration x86_64 out/Proteus-x64 "$OUT_X64/effective-args.gn"
    --configuration arm64 out/Proteus-arm64 "$OUT_ARM64/effective-args.gn"
  )
  TOOLCHAIN_CONFIG=(
    --configuration x86_64 "$OUT_X64"
    --configuration arm64 "$OUT_ARM64"
  )
  CREDITS_ARGS=(
    --credits-out-dir "$OUT_X64"
    --credits-out-dir "$OUT_ARM64"
  )
  UNIVERSAL_ARGS=(--universal-out-dir "$OUT_DIR")
fi

for path in "$OUT_DIR" "${ENTRYPOINT/$BUNDLE/$OUT_DIR}"; do
  if [ ! -e "$path" ]; then
    echo "ERROR: expected build output is missing: $path" >&2
    exit 1
  fi
done

echo "==> recording expanded GN arguments"
(
  set -o noclobber
  node "$HERE/effective-gn-args.mjs" create \
    --platform "$PLATFORM" \
    "${EFFECTIVE_ARGS[@]}" >"$EFFECTIVE_RECORD"
)

echo "==> capturing the complete platform toolchain"
node "$HERE/toolchain-lock.mjs" capture \
  --platform "$PLATFORM" \
  "${TOOLCHAIN_CONFIG[@]}" \
  --client-root "$SRC_ROOT" \
  --depot-tools "$DEPOT_TOOLS_ROOT" \
  --dependency-lock "$DEPENDENCY_LOCK" \
  --effective-args-record "$EFFECTIVE_RECORD" \
  --git "$GIT_BIN" \
  --python "$PYTHON_BIN" \
  "${UNIVERSAL_ARGS[@]}" \
  --lock "$TOOLCHAIN_LOCK" >/dev/null

cp "$DEPENDENCY_LOCK" "$RECORDS/resolved-dependency-lock.json"

echo "==> resolving the GN runtime dependency closure"
RUNTIME_OUT="$OUT_RELATIVE"
if [ "$PLATFORM" = "macos-universal" ]; then
  # universalizer.py mirrors the x64 runtime tree and merges architecture
  # binaries. The x64 GN graph remains the authoritative runtime closure.
  RUNTIME_OUT="out/Proteus-x64"
fi
(
  set -o noclobber
  cd "$SOURCE"
  "$GN" desc "$RUNTIME_OUT" chrome runtime_deps >"$RUNTIME_DEPS"
)

echo "==> packaging the complete engine runtime bundle"
(
  set -o noclobber
  node "$HERE/package-engine.mjs" \
    --out-dir "$OUT_DIR" \
    --out-dir-relative "$OUT_RELATIVE" \
    --bundle-dir "$BUNDLE" \
    --platform "$PLATFORM" \
    --runtime-deps "$RUNTIME_DEPS" \
    --dependency-lock "$RECORDS/resolved-dependency-lock.json" \
    --effective-gn-args "$EFFECTIVE_RECORD" \
    --toolchain-lock "$TOOLCHAIN_LOCK" \
    "${CREDITS_ARGS[@]}" >"$MANIFEST"
)

if [ ! -f "$ENTRYPOINT" ] || [ -L "$ENTRYPOINT" ] || [ ! -x "$ENTRYPOINT" ]; then
  echo "ERROR: packaged M0 entrypoint is missing or unsafe: $ENTRYPOINT" >&2
  exit 1
fi

echo "==> running the artifact-driven V1-V5 verification ruler"
DRIVE_ARGS=()
if [ "$PLATFORM" = "linux-x64" ]; then
  DRIVE_ARGS=(--linux-sandbox "$LINUX_SANDBOX")
fi
(
  set -o noclobber
  node "$REPO_ROOT/verify-lab/tools/drive-chrome.mjs" \
    --json \
    --external-containment \
    --chrome "$ENTRYPOINT" \
    --platform "$PLATFORM" \
    "${DRIVE_ARGS[@]}" >"$LIVE_REPORT"
)

CREATED_AT="$(node -e 'process.stdout.write(new Date().toISOString())')"
echo "==> generating the build-derived CycloneDX SBOM"
(
  set -o noclobber
  node "$HERE/build-sbom.mjs" \
    --bundle-dir "$BUNDLE" \
    --bundle-manifest "$MANIFEST" \
    --dependency-lock "$RECORDS/resolved-dependency-lock.json" \
    --toolchain-lock "$TOOLCHAIN_LOCK" \
    --effective-gn-args "$EFFECTIVE_RECORD" \
    --platform "$PLATFORM" \
    --slot "$SLOT" \
    --created-at "$CREATED_AT" >"$SBOM"
)

echo "==> complete M0 build records ready under $BUILD_ROOT"
