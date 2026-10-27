#!/bin/bash
# Only --loopback-check is safe for autonomous execution. --run is user-run only.
set -euo pipefail
PARITY_ADAPTER_REPO=$(cd "$(dirname "$0")/.." && pwd)
exec python3 -I -B "$PARITY_ADAPTER_REPO/scripts/test-parity-system-adapter.py" "$@"
