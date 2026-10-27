#!/bin/bash
# --run is user-run only: passive lo0 BPF, with no TUN or system network changes.
set -euo pipefail
PARITY_PACKET_REPO=$(cd "$(dirname "$0")/.." && pwd)
exec python3 -I -B "$PARITY_PACKET_REPO/scripts/test-parity-outer-packets.py" "$@"
