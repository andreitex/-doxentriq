#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if [[ "${1:-}" = --help || "${1:-}" = -h || "${1:-}" = help ]]; then
  cat <<'HELP'
Usage: sudo autosoft COMMAND [ARGUMENT]

Use the administration website for everyday application management.
These host commands are for the IT operator of an existing installation.

  status                         Show service, disk and scheduled-task status
  installation-status [--json]    Inspect partial installation records without starting services
  check                          Verify startup requirements and configuration
  start | stop                   Start or stop platform services
  recover-mount                  Unlock and mount existing encrypted storage
  grow TOTAL_GIB                 Enlarge encrypted storage; shrinking is refused
  security                       Check platform and host security
  certificates                   Renew HTTPS certificates
  backup                         Create a recovery point
  backup-recovery-status         Inspect an interrupted backup operation
  backup-recovery-resume         Continue a recoverable backup operation
  restore-verify FILE.gpg         Verify a supplied backup
  restore-chain-verify REQUEST.json  Verify a recovery-chain request
  restore-verify-latest           Verify the latest recovery point
  prune-logs                     Apply diagnostic-log retention
  owner-recovery                 Recover the local platform owner

No command defaults to restoring business data or resetting an account.
With no COMMAND, status is used. Help does not require root or an installation.
HELP
  exit 0
fi
if [[ -L "${BASH_SOURCE[0]}" ]]; then SELF=$(readlink -f -- "${BASH_SOURCE[0]}"); else SELF=${BASH_SOURCE[0]}; fi
SCRIPT_DIR=$(cd -- "$(dirname -- "$SELF")" && pwd)
if [[ ! -f "$SCRIPT_DIR/lib.sh" ]]; then
  INSTALL_ROOT=$(python3 -c 'import json;print(json.load(open("/etc/autosoft/installation.json"))["install_root"])')
  SCRIPT_DIR="$INSTALL_ROOT/scripts"
fi
if [[ "${1:-}" = installation-status ]]; then
  shift
  exec python3 -I -B "$SCRIPT_DIR/installation-status.py" "$@"
fi
source "$SCRIPT_DIR/lib.sh"
require_root
case "${1:-status}" in
  recover-mount)
    [[ -f /etc/autosoft/installation.json && -f /etc/autosoft/storage.key ]] || die 'Metadata and exported recovery key are required.'
    DATA_DIR=$(python3 -c 'import json;print(json.load(open("/etc/autosoft/installation.json"))["data_dir"])')
    STORAGE_FILE=$(python3 -c 'import json;print(json.load(open("/etc/autosoft/installation.json"))["storage_file"])')
    [[ -f "$STORAGE_FILE" && ! -L "$STORAGE_FILE" ]] || die 'Existing LUKS file is missing or linked.'
    cryptsetup isLuks "$STORAGE_FILE" || die 'Storage is not LUKS. It will never be formatted by recovery.'
    if ! cryptsetup status autosoft-data >/dev/null; then cryptsetup open --key-file /etc/autosoft/storage.key "$STORAGE_FILE" autosoft-data; fi
    if ! mountpoint -q "$DATA_DIR"; then mount -o prjquota,nosuid,nodev /dev/mapper/autosoft-data "$DATA_DIR"; fi
    assert_encrypted
    printf 'Existing encrypted data mounted. Run autosoft check before starting a completed installation. An incomplete installation requires IT review of its retained stage records.\n'
    ;;
  *)
    load_installation
    case "${1:-status}" in
      start) validate_startup; compose up -d --wait --wait-timeout 300 ;;
      stop) compose stop ;;
      status) verify_runtime_storage; compose ps; df -h "$DATA_DIR"; systemctl list-timers 'autosoft-*' --no-pager ;;
      check) validate_startup; compose config --quiet ;;
      security) /bin/bash "$INSTALL_ROOT/scripts/security-check.sh" ;;
      certificates) /bin/bash "$INSTALL_ROOT/scripts/certificates.sh" renew ;;
      backup|backup-recovery-status|backup-recovery-resume|restore-verify|restore-chain-verify|restore-verify-latest|prune-logs|owner-recovery) python3 "$INSTALL_ROOT/scripts/maintenance.py" "${1:-status}" "${2:-}" ;;
      grow)
        CAPACITY=${2:-}
        [[ "$CAPACITY" =~ ^[0-9]+$ ]] || die 'Usage: autosoft grow TOTAL_GIB (only enlargement is supported).'
        STORAGE_FILE=$(python3 -c 'import json;print(json.load(open("/etc/autosoft/installation.json"))["storage_file"])')
        [[ -f "$STORAGE_FILE" && ! -L "$STORAGE_FILE" ]] || die 'Unsafe storage path.'
        CURRENT=$(stat -c %s -- "$STORAGE_FILE")
        TARGET=$((CAPACITY * 1024 * 1024 * 1024))
        [[ "$TARGET" -gt "$CURRENT" ]] || die 'Requested size must be larger; shrinking is forbidden.'
        fallocate -l "$TARGET" -- "$STORAGE_FILE"
        LOOP=$(cryptsetup status autosoft-data | awk '$1=="device:" {print $2}')
        [[ "$LOOP" = /dev/loop[0-9]* ]] || die 'Expected LUKS loop backing device.'
        losetup -c "$LOOP"
        cryptsetup resize autosoft-data --key-file /etc/autosoft/storage.key
        [[ $(findmnt -n -o FSTYPE --target "$DATA_DIR") = xfs ]] || die 'Only the provisioned XFS filesystem can be grown automatically.'
        xfs_growfs "$DATA_DIR"
        df -h "$DATA_DIR"
        ;;
      *) die 'Commands: status, check, start, stop, recover-mount, grow TOTAL_GIB, security, certificates, backup, backup-recovery-status, backup-recovery-resume, restore-verify FILE.gpg, restore-chain-verify REQUEST.json, restore-verify-latest, prune-logs, owner-recovery.' ;;
    esac
    ;;
esac
