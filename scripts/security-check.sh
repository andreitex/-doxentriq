#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
load_installation
validate_pins
verify_runtime_storage
python3 "$INSTALL_ROOT/scripts/maintenance.py" security "${1:-daily}"
