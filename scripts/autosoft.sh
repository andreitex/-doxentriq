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
# This installed host command must recover storage before loading any library
# from that storage. Keep this small recovery path independent of INSTALL_ROOT.
if [[ "${1:-}" = recover-mount ]]; then
  [[ $# = 1 ]] || { printf '%s\n' 'Usage: sudo autosoft recover-mount' >&2; exit 1; }
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { printf '%s\n' 'Run as root (sudo).' >&2; exit 1; }
  exec python3 -I -B - <<'DOXENTRIQ_STORAGE_RECOVERY'
import json, os, re, stat, subprocess, sys, uuid
from pathlib import Path

HOST = Path('/etc/autosoft')
MAPPER = Path('/dev/mapper/autosoft-data')
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C', LC_ALL='C')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')

def require(value, message):
    if not value:
        raise ValueError(message)

def identity(info):
    return tuple(getattr(info, field) for field in FIELDS)

def directory(path):
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, 'Recovery path has an unsafe directory.')

def protected(path, *, read=False, limit=8192):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and not before.st_mode & 0o077,
                'Recovery requires protected root-owned files.')
        raw = None
        if read:
            require(0 < before.st_size <= limit, 'Recovery metadata has an invalid size.')
            raw = os.read(fd, limit + 1)
            require(len(raw) == before.st_size, 'Recovery metadata could not be read completely.')
        require(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
                'Recovery input changed while being read.')
        return raw if read else identity(before)
    finally:
        os.close(fd)

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'Recovery metadata has duplicate fields.')
        result[key] = value
    return result

def absolute(value):
    require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            and str(Path(value)) == value and '..' not in Path(value).parts and value != '/',
            'Recovery metadata has an invalid path.')
    return Path(value)

def state():
    raw = protected(HOST / 'installation.json', read=True)
    receipt_raw = protected(HOST / 'installation.storage-receipt.json', read=True)
    value = json.loads(raw, object_pairs_hook=pairs)
    receipt = json.loads(receipt_raw, object_pairs_hook=pairs)
    keys = {'data_dir', 'install_root', 'storage_file', 'installation_id'}
    require(type(value) is dict and set(value) == keys and type(receipt) is dict
            and set(receipt) == keys | {'creation_stage', 'luks_uuid'}
            and {key: receipt[key] for key in keys} == value
            and receipt['creation_stage'] == 'new-luks-created',
            'Installation metadata and storage receipt do not agree; ask IT to reconcile them.')
    for name in ('installation_id', 'luks_uuid'):
        require(type(receipt[name]) is str and str(uuid.UUID(receipt[name])) == receipt[name],
                'Recovery metadata has an invalid storage identity.')
    data, root, backing = (absolute(value[key]) for key in ('data_dir', 'install_root', 'storage_file'))
    require(data in root.parents and data != backing and data not in backing.parents,
            'Recovery metadata has an unsupported storage layout.')
    directory(data)
    # Mounting XFS changes backing-file times; retain inode/mode/owner/size.
    backing_identity = protected(backing)[:7]
    key_identity = protected(HOST / 'storage.key')
    require(backing_identity[6] > 0 and 0 < key_identity[6] <= 4096, 'Recovery storage or key is empty.')
    return value, receipt, (raw, receipt_raw, backing_identity, key_identity)

def command(argv, accepted=(0,)):
    result = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    require(result.returncode in accepted and len(result.stdout) + len(result.stderr) <= 65536,
            'Storage recovery command failed; existing storage was preserved. Check the host journal.')
    return result.returncode, result.stdout

def mounted(data, run):
    code, raw = run(['findmnt', '--json', '--mountpoint', str(data), '--output', 'SOURCE,TARGET,FSTYPE,OPTIONS'], (0, 1))
    if code == 1:
        require(not raw, 'Data mount status is ambiguous.')
        return None
    payload = json.loads(raw)
    require(type(payload) is dict, 'Data mount status is ambiguous.')
    rows = payload.get('filesystems')
    require(type(rows) is list and len(rows) == 1, 'Data mount status is ambiguous.')
    row = rows[0]
    require(type(row) is dict and all(type(row.get(key)) is str for key in ('target', 'fstype', 'source', 'options')),
            'Data mount status is ambiguous.')
    require(row['target'] == str(data) and row['fstype'] == 'xfs'
            and Path(row['source']).resolve(strict=True) == MAPPER.resolve(strict=True),
            'Data directory contains another mount; nothing will be hidden or replaced.')
    options = set(row['options'].split(','))
    require({'nosuid', 'nodev'} <= options and bool({'prjquota', 'pquota'} & options),
            'Encrypted mount lacks its required storage options; ask IT to reconcile it.')
    return row

def verify_mapper(backing, run):
    require(stat.S_ISBLK(MAPPER.stat().st_mode), 'Expected encrypted mapping is unavailable.')
    _, raw = run(['cryptsetup', 'status', 'autosoft-data'])
    require(re.search(rb'^\s*type:\s*LUKS2\s*$', raw, re.MULTILINE), 'Expected LUKS2 mapping is unavailable.')
    match = re.search(rb'^\s*device:\s*(/dev/loop[0-9]+)\s*$', raw, re.MULTILINE)
    require(match is not None, 'Expected file-backed encrypted mapping is unavailable.')
    loop = match[1].decode('ascii')
    _, raw = run(['losetup', '--json', '--list', '--output', 'NAME,BACK-FILE', loop])
    require(json.loads(raw) == {'loopdevices': [{'name': loop, 'back-file': str(backing)}]},
            'Active encrypted mapping belongs to another backing file; it was left unchanged.')

def recover(run=command):
    value, receipt, before = state()
    data, backing = Path(value['data_dir']), Path(value['storage_file'])
    current = mounted(data, run)
    if current is None:
        require(not any(data.iterdir()), 'Unmounted data directory contains files; recovery will not hide them.')
    _, raw = run(['cryptsetup', 'luksUUID', str(backing)])
    require(raw.decode('ascii').strip() == receipt['luks_uuid'], 'Backing-file identity differs from the storage receipt.')
    if not os.path.lexists(MAPPER):
        run(['cryptsetup', 'open', '--key-file', str(HOST / 'storage.key'), str(backing), 'autosoft-data'])
    verify_mapper(backing, run)
    if current is None:
        run(['mount', '-t', 'xfs', '-o', 'prjquota,nosuid,nodev', '--', str(MAPPER), str(data)])
    require(mounted(data, run) is not None, 'Encrypted storage did not become mounted.')
    require(state() == (value, receipt, before), 'Recovery inputs changed; retain the current state for IT review.')
    marker = data / '.autosoft-encrypted'
    require(protected(marker)[0] == data.stat().st_dev, 'Encrypted installation marker is missing or outside the data mount.')
    print('Existing encrypted data mounted. Run autosoft check before starting a completed installation. '
          'An incomplete installation requires IT review of its retained stage records. No services were started.')

if __name__ == '__main__':
    try:
        recover()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: Storage recovery stopped. No formatting or service startup was requested. ' +
              (str(error) if isinstance(error, ValueError) else 'Ask IT to inspect the retained storage and host journal.'), file=sys.stderr)
        raise SystemExit(1)
DOXENTRIQ_STORAGE_RECOVERY
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
