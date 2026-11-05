#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
load_installation
[[ $(wc -l < /proc/swaps) -le 1 ]] || die 'Swap must remain disabled before service startup.'
[[ $(findmnt -n -o FSTYPE --target "$DATA_DIR") = xfs ]] || die 'Expected encrypted XFS storage is unavailable.'
xfs_quota -x -c 'state -p' "$DATA_DIR" | grep -q 'Enforcement: ON' || die 'Kernel project quota enforcement is unavailable.'
mountpoint -q /var/log/journal || die 'Encrypted persistent journal is not mounted.'
[[ $(stat -c %d /var/log/journal) = $(stat -c %d "$DATA_DIR/journal") ]] || die 'Persistent journal is outside encrypted storage.'
