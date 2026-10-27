#!/bin/bash
# Fixed read-only metadata inspection. No production IPC or system changes.
set -euo pipefail
PARITY_INSPECT_REPO=$(cd "$(dirname "$0")/.." && pwd)
exec python3 -I -B "$PARITY_INSPECT_REPO/scripts/test-parity-production-inspect.py" "$@"
