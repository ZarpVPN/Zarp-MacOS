#!/bin/bash
# User-run WARP checks. --help and --self-test never start a daemon or change the system.
set -euo pipefail
PARITY_REPO=$(cd "$(dirname "$0")/.." && pwd)
exec python3 "$PARITY_REPO/scripts/parity_manual.py" "$@"
