#!/bin/bash
# Compatibility launcher for the deterministic Ralph control plane.

set -euo pipefail
PATH='/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
export PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
exec python3 -m ralph_hardened "$@"
