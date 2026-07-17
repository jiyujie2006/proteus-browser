#!/usr/bin/env bash
# Compatibility entry point. The cross-platform Node test is canonical.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$HERE/scaffold-honesty.mjs" "$@"
