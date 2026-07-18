#!/usr/bin/env bash
# Fetch/sync the exact Chromium and depot_tools commits declared by the strict
# baseline. This is a Unix/macOS build-farm entrypoint; Windows gets a native
# entrypoint in the hard-M0 workflow slice.
set -euo pipefail

# Repository/config overrides can make `git -C <verified path>` operate on a
# different repository. Start from a clean Git environment before discovering
# the bootstrap executable. Public upstreams do not need global credentials.
for name in ${!GIT_@}; do
  unset "$name"
done
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BASELINE_PATH="$ROOT/CHROMIUM_BASELINE"

if [ "${1:-}" = "--baseline" ]; then
  if [ "$#" -ne 2 ]; then
    echo "ERROR: usage: fetch-chromium.sh [--baseline <file>]" >&2
    exit 64
  fi
  BASELINE_PATH="$2"
elif [ "$#" -ne 0 ]; then
  echo "ERROR: usage: fetch-chromium.sh [--baseline <file>]" >&2
  exit 64
fi

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js is required to validate CHROMIUM_BASELINE" >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: Git is required to provision the pinned sources" >&2
  exit 1
fi
GIT_BIN="$(command -v git)"
case "$GIT_BIN" in
  /*) ;;
  *) echo "ERROR: Git must resolve to an absolute executable path" >&2; exit 1 ;;
esac
PROTEUS_GIT_BIN="$GIT_BIN"
export PROTEUS_GIT_BIN

BASELINE_PARSER="$ROOT/scripts/baseline.mjs"
baseline_value() {
  node "$BASELINE_PARSER" --file "$BASELINE_PATH" --get "$1"
}

# Parsing happens before any network or checkout mutation.
node "$BASELINE_PARSER" --file "$BASELINE_PATH" --check >/dev/null
CHROMIUM_REPOSITORY="$(baseline_value CHROMIUM_REPOSITORY)"
CHROMIUM_STABLE="$(baseline_value CHROMIUM_STABLE)"
CHROMIUM_COMMIT="$(baseline_value CHROMIUM_COMMIT)"
DEPOT_TOOLS_REPOSITORY="$(baseline_value DEPOT_TOOLS_REPOSITORY)"
DEPOT_TOOLS_COMMIT="$(baseline_value DEPOT_TOOLS_COMMIT)"

normalize_fresh_root() {
  local input="$1"
  local label="$2"
  local parent
  local name
  local canonical_parent
  case "$input" in
    /*) ;;
    *) echo "ERROR: $label must be an absolute path" >&2; exit 1 ;;
  esac
  case "$input" in
    *$'\n'*|*$'\r'*|*$'\t'*)
      echo "ERROR: $label contains a control character" >&2
      exit 1
      ;;
  esac
  parent="${input%/*}"
  name="${input##*/}"
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
  printf '%s/%s\n' "$canonical_parent" "$name"
}

SRC_DIR="$(normalize_fresh_root "${PROTEUS_CHROMIUM_SRC:-$ROOT/src}" PROTEUS_CHROMIUM_SRC)"
DEPOT_TOOLS_DIR="$(normalize_fresh_root "${PROTEUS_DEPOT_TOOLS_DIR:-$ROOT/depot_tools}" PROTEUS_DEPOT_TOOLS_DIR)"
SOURCE="$SRC_DIR/src"

case "$SRC_DIR/" in
  "$DEPOT_TOOLS_DIR/"*) echo "ERROR: source root is inside depot_tools root" >&2; exit 1 ;;
esac
case "$DEPOT_TOOLS_DIR/" in
  "$SRC_DIR/"*) echo "ERROR: depot_tools root is inside source root" >&2; exit 1 ;;
esac
if [ -e "$SRC_DIR" ] || [ -e "$DEPOT_TOOLS_DIR" ]; then
  echo "ERROR: fetch requires fresh, non-existent source and depot_tools roots" >&2
  echo "       provision a new ephemeral build directory for every invocation" >&2
  exit 1
fi

# depot_tools otherwise updates itself during normal commands. Disable that
# before the first depot_tools invocation, then put only the verified checkout
# first on PATH so its wrappers resolve the same toolset.
export DEPOT_TOOLS_UPDATE=0
export DEPOT_TOOLS_METRICS=0

echo "==> cloning pinned depot_tools into $DEPOT_TOOLS_DIR"
"$GIT_BIN" clone --filter=blob:none --no-checkout -- \
  "$DEPOT_TOOLS_REPOSITORY" "$DEPOT_TOOLS_DIR"
"$GIT_BIN" -C "$DEPOT_TOOLS_DIR" fetch origin "$DEPOT_TOOLS_COMMIT"
"$GIT_BIN" -C "$DEPOT_TOOLS_DIR" checkout --detach "$DEPOT_TOOLS_COMMIT"

assert_depot_tools() {
  local origin
  local head
  local dirty
  origin="$("$GIT_BIN" -C "$DEPOT_TOOLS_DIR" remote get-url origin)"
  head="$("$GIT_BIN" -C "$DEPOT_TOOLS_DIR" rev-parse --verify HEAD)"
  dirty="$("$GIT_BIN" -C "$DEPOT_TOOLS_DIR" status --porcelain --untracked-files=all)"
  if [ "$origin" != "$DEPOT_TOOLS_REPOSITORY" ]; then
    echo "ERROR: depot_tools origin is not the pinned canonical repository" >&2
    exit 1
  fi
  if [ "$head" != "$DEPOT_TOOLS_COMMIT" ]; then
    echo "ERROR: depot_tools HEAD $head != pinned $DEPOT_TOOLS_COMMIT" >&2
    echo "       provision a fresh checkout; this script will not rewrite an existing one" >&2
    exit 1
  fi
  if [ -n "$dirty" ]; then
    echo "ERROR: depot_tools checkout is dirty" >&2
    exit 1
  fi
  for tool in gclient; do
    if [ ! -f "$DEPOT_TOOLS_DIR/$tool" ]; then
      echo "ERROR: pinned depot_tools does not contain $tool" >&2
      exit 1
    fi
    "$GIT_BIN" -C "$DEPOT_TOOLS_DIR" ls-files --error-unmatch "$tool" >/dev/null
  done
}

assert_depot_tools
PATH="$DEPOT_TOOLS_DIR:$PATH"
export PATH
assert_depot_tools

mkdir "$SRC_DIR"

# Generate the only accepted .gclient file with the pinned gclient itself.
# Comparing exact bytes prevents an existing source parent from adding another
# solution outside the Chromium commit contract.
GCLIENT_FIXTURE_DIR="$SRC_DIR/.proteus-gclient-config"
mkdir "$GCLIENT_FIXTURE_DIR"
cleanup() {
  rm -rf "$GCLIENT_FIXTURE_DIR"
}
trap cleanup EXIT HUP INT TERM
(
  cd "$GCLIENT_FIXTURE_DIR"
  "$DEPOT_TOOLS_DIR/gclient" config \
    --name src \
    --unmanaged \
    "$CHROMIUM_REPOSITORY" >/dev/null
)
assert_depot_tools

cp "$GCLIENT_FIXTURE_DIR/.gclient" "$SRC_DIR/.gclient"
cleanup
trap - EXIT HUP INT TERM

echo "==> initial gclient sync of Chromium $CHROMIUM_STABLE @ $CHROMIUM_COMMIT"
(
  cd "$SRC_DIR"
  "$DEPOT_TOOLS_DIR/gclient" sync \
    -D \
    --force \
    --reset \
    --with_branch_heads \
    --revision "src@$CHROMIUM_COMMIT"
)
assert_depot_tools

if [ ! -d "$SOURCE/.git" ]; then
  echo "ERROR: gclient did not produce a Chromium Git checkout at $SOURCE" >&2
  exit 1
fi

assert_chromium_origin() {
  local origin
  origin="$("$GIT_BIN" -C "$SOURCE" remote get-url origin)"
  if [ "$origin" != "$CHROMIUM_REPOSITORY" ]; then
    echo "ERROR: Chromium origin is not the pinned canonical repository" >&2
    exit 1
  fi
}

assert_chromium_clean() {
  local dirty
  dirty="$("$GIT_BIN" -C "$SOURCE" status --porcelain --untracked-files=all)"
  if [ -n "$dirty" ]; then
    echo "ERROR: Chromium checkout is dirty; refusing a destructive sync" >&2
    exit 1
  fi
}

assert_chromium_origin
assert_chromium_clean

echo "==> verifying official tag $CHROMIUM_STABLE resolves to the pinned commit"
"$GIT_BIN" -C "$SOURCE" fetch --force origin \
  "refs/tags/$CHROMIUM_STABLE:refs/tags/$CHROMIUM_STABLE"
TAG_COMMIT="$("$GIT_BIN" -C "$SOURCE" rev-parse --verify "refs/tags/$CHROMIUM_STABLE^{commit}")"
if [ "$TAG_COMMIT" != "$CHROMIUM_COMMIT" ]; then
  echo "ERROR: Chromium tag resolves to $TAG_COMMIT, expected $CHROMIUM_COMMIT" >&2
  exit 1
fi

"$GIT_BIN" -C "$SOURCE" checkout --detach "$CHROMIUM_COMMIT"
if [ "$("$GIT_BIN" -C "$SOURCE" rev-parse --verify HEAD)" != "$CHROMIUM_COMMIT" ]; then
  echo "ERROR: failed to detach Chromium at the pinned commit" >&2
  exit 1
fi

echo "==> syncing DEPS exactly at $CHROMIUM_COMMIT"
(
  cd "$SRC_DIR"
  "$DEPOT_TOOLS_DIR/gclient" sync \
    -D \
    --force \
    --reset \
    --with_branch_heads \
    --revision "src@$CHROMIUM_COMMIT"
)

assert_depot_tools
assert_chromium_origin
assert_chromium_clean
FINAL_COMMIT="$("$GIT_BIN" -C "$SOURCE" rev-parse --verify HEAD)"
if [ "$FINAL_COMMIT" != "$CHROMIUM_COMMIT" ]; then
  echo "ERROR: gclient moved Chromium HEAD to $FINAL_COMMIT" >&2
  exit 1
fi

node "$ROOT/scripts/depot-tools-checkout.mjs" \
  --root "$DEPOT_TOOLS_DIR" >/dev/null
node "$ROOT/scripts/chromium-checkout.mjs" \
  --source "$SOURCE" \
  --state clean >/dev/null

echo "==> done: $SOURCE"
echo "    Chromium $CHROMIUM_STABLE @ $CHROMIUM_COMMIT"
echo "    depot_tools @ $DEPOT_TOOLS_COMMIT (auto-update disabled)"
