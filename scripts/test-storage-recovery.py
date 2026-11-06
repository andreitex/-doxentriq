#!/usr/bin/env python3
"""Storage-only fault qualification; never changes keys, mappings or host mounts.

The two source digests must come from an independently verified company release.
Supplying a digest is NOT release authentication. This operator test is not an
installer authority, repository-resume test, or failed-unlock reboot test.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import uuid

ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/', LANG='C', LC_ALL='C', TZ='UTC')
MISMATCH = b'ERROR: Data directory is not the expected encrypted mapping.\n'
TOOLS = ('cryptsetup', 'findmnt', 'losetup', 'unshare', 'mount', 'bash', 'python3', 'sha256sum')
LIMITATIONS = [
    'No boot key, host mount or active mapping was changed; failed-unlock reboot recovery was not tested.',
    'Repository seed, resume, service restart and complete installation acceptance were not tested.',
    'Source hashes must be supplied from a separately authenticated release; this harness does not authenticate a release.',
]


class Refused(Exception):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(value):
    require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            and str(Path(value)) == value and '..' not in Path(value).parts
            and value != '/', 'invalid-absolute-path')
    return Path(value)


def protected_parents(path):
    for parent in reversed((path, *path.parents)):
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'unprotected-directory')


def file_identity(path):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
            and not s.st_mode & 0o022, 'unprotected-regular-file')
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size)


def read_file(path, maximum=1048576):
    protected_parents(path.parent)
    before = file_identity(path)
    require(before[-1] <= maximum, 'file-too-large')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        require((s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size) == before,
                'file-open-identity-changed')
        raw = os.read(fd, maximum + 1)
        require(len(raw) == before[-1] and file_identity(path) == before, 'file-changed')
        return raw
    finally:
        os.close(fd)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'short-write')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    write_new(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def native_run(argv, timeout=30):
    # Every command is trusted and read-only except namespace-local bind mounts.
    with subprocess.Popen(argv, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise
        return subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)


def checked(run, argv):
    result = run(argv)
    require(result.returncode == 0 and len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
            'observation-command-failed')
    return result.stdout


def tools():
    result = {}
    for name in TOOLS:
        found = shutil.which(name, path=ENV['PATH'])
        require(found is not None, 'missing-tool-' + name)
        resolved = Path(found).resolve(strict=True)
        protected_parents(resolved.parent)
        file_identity(resolved)
        result[name] = str(resolved)
    return result


def metadata(host=Path('/etc/autosoft')):
    require(not os.path.lexists(host / 'installation.complete'), 'accepted-installation-refused')
    raw = read_file(host / 'installation.json', 8192)
    receipt_raw = read_file(host / 'installation.storage-receipt.json', 8192)
    value, receipt = json.loads(raw), json.loads(receipt_raw)
    keys = {'data_dir', 'install_root', 'storage_file', 'installation_id'}
    require(type(value) is dict and set(value) == keys and type(receipt) is dict
            and set(receipt) == keys | {'creation_stage', 'luks_uuid'}
            and {k: receipt[k] for k in keys} == value
            and receipt['creation_stage'] == 'new-luks-created', 'invalid-foundation-records')
    for key in ('installation_id', 'luks_uuid'):
        require(type(receipt[key]) is str and str(uuid.UUID(receipt[key])) == receipt[key], 'invalid-uuid')
    data, root, backing = (safe_path(value[k]) for k in ('data_dir', 'install_root', 'storage_file'))
    require(data in root.parents and data not in backing.parents, 'unsupported-foundation-layout')
    protected_parents(data)
    protected_parents(root)
    protected_parents(backing.parent)
    file_identity(backing)
    return value, receipt, dict(installation=digest(raw), storageReceipt=digest(receipt_raw))


def snapshot(value, receipt, tool, run=native_run):
    data, backing = Path(value['data_dir']), Path(value['storage_file'])
    mount_raw = checked(run, [tool['findmnt'], '--json', '--mountpoint', str(data),
                              '--output', 'SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN'])
    rows = json.loads(mount_raw).get('filesystems')
    require(type(rows) is list and len(rows) == 1, 'ambiguous-data-mount')
    mount = rows[0]
    mapper = Path('/dev/mapper/autosoft-data')
    ms = mapper.stat()
    require(stat.S_ISBLK(ms.st_mode) and mount['target'] == str(data) and mount['fstype'] == 'xfs'
            and Path(mount['source']).resolve(strict=True) == mapper.resolve(strict=True), 'wrong-data-mount')
    status = checked(run, [tool['cryptsetup'], 'status', 'autosoft-data'])
    match = re.search(rb'^\s*device:\s*(/dev/loop[0-9]+)\s*$', status, flags=re.MULTILINE)
    require(match is not None, 'expected-file-backed-mapper')
    device = match[1].decode('ascii')
    loop = json.loads(checked(run, [tool['losetup'], '--json', '--list', '--output', 'NAME,BACK-FILE', device]))
    require(loop == {'loopdevices': [{'name': device, 'back-file': str(backing)}]}, 'mapper-backing-mismatch')
    actual_uuid = checked(run, [tool['cryptsetup'], 'luksUUID', str(backing)]).decode('ascii').strip()
    require(actual_uuid == receipt['luks_uuid'], 'luks-uuid-mismatch')
    return dict(mount=mount, mapper=dict(device=ms.st_dev, inode=ms.st_ino, rdev=ms.st_rdev),
                mapperStatusSha256=digest(status), loop=loop, luksUuid=actual_uuid,
                backingIdentity=file_identity(backing), mountNamespace=os.readlink('/proc/self/ns/mnt'))


def wrong_key_probe(tool, backing, key, run=native_run):
    result = run([tool['cryptsetup'], 'open', '--test-passphrase', '--key-file', str(key), str(backing)], timeout=90)
    # Missing tool/permission/invalid header is not a wrong-passphrase success.
    require(result.returncode == 2 and result.stdout == b''
            and result.stderr == b'No key available with this passphrase.\n', 'wrong-key-outcome-not-proven')
    return dict(returnCode=2, diagnostic='wrong-passphrase-rejected', testPassphraseOnly=True)


# All arguments are positional paths and verified digests. No eval or source of
# ambient profile files. The guard code bind exists BEFORE DATA_DIR is hidden.
NAMESPACE_SCRIPT = r'''set -Eeuo pipefail
[[ "$(readlink /proc/self/ns/mnt)" != "$1" ]] || exit 81
mount --bind "$2" "$3"
mount -o remount,bind,ro "$3"
mount --bind "$4" "$5"
[[ ! -e "$6/scripts/storage-guard.sh" ]] || exit 82
printf '%s  %s\n%s  %s\n' "$7" "$3/storage-guard.sh" "$8" "$3/lib.sh" | sha256sum --check --status
printf 'authenticated-guard-bytes-reachable\n'
exec bash --noprofile --norc "$3/storage-guard.sh"
'''


def guard_probe(tool, data, root, source, outside, empty, pins, run=native_run):
    result = run([tool['unshare'], '--mount', '--propagation', 'private', tool['bash'],
                  '--noprofile', '--norc', '-c', NAMESPACE_SCRIPT, 'storage-fault',
                  os.readlink('/proc/self/ns/mnt'), str(source), str(outside), str(empty),
                  str(data), str(root), pins['storage-guard.sh'], pins['lib.sh']], timeout=30)
    require(result.returncode == 1 and result.stdout == b'authenticated-guard-bytes-reachable\n'
            and result.stderr == MISMATCH, 'mount-guard-outcome-not-proven')
    return dict(returnCode=1, diagnostic='original-guard-mount-mismatch',
                sourceReachableAfterOverlay=True, privateMountNamespace=True)


def qualify(pins):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'linux-root-required')
    require(set(pins) == {'storage-guard.sh', 'lib.sh'} and all(re.fullmatch('[0-9a-f]{64}', h) for h in pins.values()),
            'invalid-source-digests')
    os.umask(0o077)
    tool = tools()
    value, receipt, metadata_pins = metadata()
    data, root, backing = (Path(value[k]) for k in ('data_dir', 'install_root', 'storage_file'))
    sources = {name: read_file(root / 'scripts' / name) for name in pins}
    require({name: digest(raw) for name, raw in sources.items()} == pins, 'guard-source-digest-mismatch')
    before = snapshot(value, receipt, tool)
    # All prerequisites above are read-only. Every test gets new evidence names.
    identifier = uuid.uuid4().hex
    evidence = data / ('storage-fault-' + identifier)
    outside = Path('/run') / ('doxentriq-storage-fault-' + identifier)
    protected_parents(outside.parent)
    evidence.mkdir(mode=0o700)
    source = evidence / 'source'; source.mkdir(mode=0o700)
    empty = evidence / 'empty'; empty.mkdir(mode=0o700)
    for name, raw in sources.items():
        write_new(source / name, raw)
    write_json(evidence / 'intent.json', dict(schemaVersion=1, testId=identifier,
        scope='storage-only-fault-qualification', sourceDigests=pins, metadataDigests=metadata_pins,
        before=before, limitations=LIMITATIONS, startedAt=datetime.now(timezone.utc).isoformat()))
    # Contains no credentials or copied key; only a bind mountpoint in the child.
    outside.mkdir(mode=0o700)
    key = evidence / 'wrong-test-key'
    report = dict(schemaVersion=1, testId=identifier, status='failed', checks=[], limitations=LIMITATIONS,
                  evidenceDirectory=str(evidence), sourceDigests=pins, modelApiCalls=0)
    try:
        write_new(key, secrets.token_bytes(64))
        report['checks'].append(wrong_key_probe(tool, backing, key))
        key.unlink()
        report['checks'].append(guard_probe(tool, data, root, source, outside, empty, pins))
        require({name: digest(read_file(root / 'scripts' / name)) for name in pins} == pins, 'source-changed')
        report['status'] = 'passed'
    except Exception as error:
        report['error'] = str(error) if type(error) is Refused else type(error).__name__
    finally:
        try:
            _, _, after_metadata = metadata()
            after = snapshot(value, receipt, tool)
            report['after'] = after
            require(after == before and after_metadata == metadata_pins, 'host-state-changed')
            report['hostStateUnchanged'] = True
        except Exception as error:
            report['status'] = 'failed'
            report['hostStateUnchanged'] = False
            report['finalObservationError'] = str(error) if type(error) is Refused else type(error).__name__
        if os.path.lexists(key):
            key.unlink()
        # Never recursively remove: unexpected contents are retained as failure.
        try:
            outside.rmdir()
        except OSError:
            report['status'] = 'failed'
            report['outsideCleanup'] = 'retained-unexpected-state'
        report['finishedAt'] = datetime.now(timezone.utc).isoformat()
        write_json(evidence / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guard-sha256', required=True)
    parser.add_argument('--lib-sha256', required=True)
    args = parser.parse_args()
    try:
        report = qualify({'storage-guard.sh': args.guard_sha256, 'lib.sh': args.lib_sha256})
    except Exception as error:
        print('Storage qualification refused before result: ' + (str(error) if type(error) is Refused else type(error).__name__), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
