#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
load_installation
python3 "$INSTALL_ROOT/scripts/maintenance.py" certificates "${1:-renew}"
