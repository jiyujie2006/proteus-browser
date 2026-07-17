#!/usr/bin/env bash
# Compatibility entry point. The cross-platform Node implementation is
# canonical; keep this wrapper for existing POSIX build-farm invocations.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$HERE/apply-patches.mjs" "$@"
