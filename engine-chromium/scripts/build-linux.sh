#!/usr/bin/env bash
# End-to-end Linux x64 entrypoint for the pinned M0 Chromium build.
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
  echo "usage: build-linux.sh [--baseline <file>] [--source-root <absolute-directory>] [--depot-tools-root <absolute-directory>]" >&2
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

if [ "$(uname -s)" != "Linux" ]; then
  echo "ERROR: build-linux.sh must run on Linux" >&2
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

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js is required" >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: Git is required" >&2
  exit 1
fi
NODE_BIN="$(command -v node)"
GIT_BIN="$(command -v git)"
case "$NODE_BIN:$GIT_BIN" in
  /*:/*) ;;
  *) echo "ERROR: Node.js and Git must resolve to absolute executable paths" >&2; exit 1 ;;
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

echo "==> provisioning the pinned Linux checkout"
"$ROOT/scripts/fetch-chromium.sh" --baseline "$BASELINE"

if [ "${PROTEUS_INSTALL_BUILD_DEPS:-0}" = "1" ]; then
  INSTALL_DEPS="$SRC_ROOT/src/build/install-build-deps.sh"
  if [ ! -f "$INSTALL_DEPS" ] || [ -L "$INSTALL_DEPS" ] || [ ! -x "$INSTALL_DEPS" ]; then
    echo "ERROR: pinned Chromium checkout lacks an ordinary executable install-build-deps.sh" >&2
    exit 1
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: PROTEUS_INSTALL_BUILD_DEPS=1 requires sudo" >&2
    exit 1
  fi
  echo "==> installing Chromium's declared Linux host build prerequisites"
  sudo -- "$INSTALL_DEPS" --no-prompt
elif [ "${PROTEUS_INSTALL_BUILD_DEPS:-0}" != "0" ]; then
  echo "ERROR: PROTEUS_INSTALL_BUILD_DEPS must be exactly 0 or 1" >&2
  exit 1
fi

dependency_lock capture clean
dependency_lock verify clean

echo "==> applying the active M0 patch series"
"$NODE_BIN" "$ROOT/scripts/apply-patches.mjs"

dependency_lock verify patched

echo "==> building Linux x64 through the shared pinned build entrypoint"
"$ROOT/scripts/build.sh"

OUT_DIR="$SRC_ROOT/src/out/Proteus"
ARTIFACT="$OUT_DIR/chrome"
GN="$DEPOT_TOOLS_ROOT/gn"
EFFECTIVE_ARGS="$OUT_DIR/effective-args.gn"
if [ ! -f "$ARTIFACT" ] || [ -L "$ARTIFACT" ] || [ ! -x "$ARTIFACT" ]; then
  echo "ERROR: Linux Chromium executable was not produced as an ordinary executable: $ARTIFACT" >&2
  exit 1
fi
if [ ! -x "$GN" ] || [ -L "$GN" ]; then
  echo "ERROR: pinned depot_tools lacks an ordinary executable gn entrypoint" >&2
  exit 1
fi
if [ -e "$EFFECTIVE_ARGS" ] || [ -L "$EFFECTIVE_ARGS" ]; then
  echo "ERROR: effective GN args output already exists: $EFFECTIVE_ARGS" >&2
  exit 1
fi
echo "==> capturing expanded GN args from the generated Linux build"
(
  set -o noclobber
  cd "$SRC_ROOT/src"
  "$GN" args out/Proteus --list --short >"$EFFECTIVE_ARGS"
)
if [ ! -s "$EFFECTIVE_ARGS" ] || [ -L "$EFFECTIVE_ARGS" ]; then
  echo "ERROR: expanded Linux GN args were not captured safely" >&2
  exit 1
fi

echo "==> Linux x64 build complete"
echo "    build output directory: $OUT_DIR"
echo "    executable: $ARTIFACT"
echo "    effective GN args: $EFFECTIVE_ARGS"
