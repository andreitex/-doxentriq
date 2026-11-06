"""Emit an independently delivered company retention worker, never sign/install.

Run on a trusted root-owned company checkout. The printed digest must travel
through the company's authenticated delivery channel; it cannot authenticate
itself. Candidate release bytes never select their verifier or native worker.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType

PROGRAMS = {
    'cli': 'deploy/installer/company_full_cli.py',
    'delivery': 'deploy/installer/build-full-cli-package.py',
    'record': 'deploy/installer/company_cli_record.py',
    'store': 'deploy/installer/company_cli_executed_record_store.py',
    'crypto': 'deploy/installer/company_release_crypto.py',
    'station': 'deploy/installer/company_native_station.py',
    'request': 'deploy/installer/company_full_cli_request.py',
    'records': 'deploy/installer/company_retention_records.py',
    'configuration': 'deploy/installer/company_configuration.py',
    'configuration_worker': 'deploy/installer/company_configuration_worker.py',
    'repository_io': 'deploy/installer/company_repository_io.py',
    'repository_worker': 'deploy/installer/company_repository_worker.py',
}
MAX_WORKER = 2*1024**2
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def pin(raw): return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
def encoded(raw): return dict(**pin(raw), base64=base64.b64encode(raw).decode('ascii'))


def protected_read(path, maximum=131072):
    """Producer bootstrap read before executing any helper from the checkout."""
    path = Path(path)
    if not path.is_absolute(): raise ValueError('absolute-producer-path-required')
    ancestors = {parent: parent.lstat() for parent in path.parents}
    before = path.lstat()
    for info in ancestors.values():
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError('protected-company-source-ancestor-required')
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or before.st_mode & 0o022 or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
        raise ValueError('protected-company-source-required')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        expected = tuple(getattr(before, key) for key in FIELDS)
        if tuple(getattr(os.fstat(fd), key) for key in FIELDS) != expected:
            raise ValueError('company-source-changed')
        raw = bytearray()
        while len(raw) < before.st_size:
            part = os.pread(fd, min(65536, before.st_size-len(raw)), len(raw))
            if not part: raise ValueError('company-source-short-read')
            raw.extend(part)
        if os.pread(fd, 1, len(raw)) or tuple(getattr(os.fstat(fd), key) for key in FIELDS) != expected or tuple(getattr(path.lstat(), key) for key in FIELDS) != expected:
            raise ValueError('company-source-changed')
        for parent, info in ancestors.items():
            if any(getattr(parent.lstat(), key) != getattr(info, key) for key in FIELDS):
                raise ValueError('company-source-ancestor-changed')
        return bytes(raw)
    finally:
        os.close(fd)


def module(name, raw):
    value = ModuleType(name)
    value.__file__ = '<company producer ' + name + '>'
    if name in sys.modules: raise ValueError('duplicate-producer-module')
    sys.modules[name] = value
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def assemble(root, fingerprint, *, reader):
    root = Path(root)
    read = lambda name: reader(root/name, 131072)
    PB = module('native_retention_package_builder', read('deploy/installer/build-full-package.py'))
    D = module('native_retention_delivery_builder', read(PROGRAMS['delivery']))
    # All captures come from the trusted producer checkout. The signed source
    # verifier must later match the operational catalog exactly on the client.
    captures = {name: read(name) for name in set(PB.PACKAGE_PATHS) | set(D.LAUNCH_PATHS) | set(PB.OPERATIONAL_PATHS) | set(PROGRAMS.values())}
    package_pins = {name: pin(captures[name]) for name in PB.PACKAGE_PATHS}
    launch_pins = {name: pin(captures[name]) for name in D.LAUNCH_PATHS}
    catalog = {name: dict(**pin(captures[name]), gitMode='100644') for name in PB.OPERATIONAL_PATHS}
    captured_reader = lambda path, maximum: captures[path.relative_to(root).as_posix()]
    full = PB.assemble(root, fingerprint, package_pins=package_pins,
        operational_catalog=catalog, reader=captured_reader)
    delivery = D.assemble(root, launch_pins=launch_pins, package_pins=package_pins,
        operational_catalog=catalog, fingerprint=fingerprint, full_package_raw=full,
        full_package_pin=pin(full), reader=captured_reader)
    bootstrap = ('scripts/verify-release.py', 'scripts/installer_parent.py')
    package = dict(programs={label: encoded(captures[path]) for label, path in PROGRAMS.items()},
        delivery=base64.b64encode(delivery).decode('ascii'), authentication=dict(
            delivery_pin=pin(delivery), launch_pins=launch_pins, package_pins=package_pins,
            operational_catalog=catalog, fingerprint=fingerprint, full_package_pin=pin(full),
            bootstrap_records={path: base64.b64encode(captures[path]).decode('ascii') for path in bootstrap},
            bootstrap_pins={path: package_pins[path] for path in bootstrap}))
    worker = read('deploy/installer/company_native_retention.py')
    marker = b'PACKAGE = None  # @NATIVE_RETENTION_PACKAGE@'
    if worker.count(marker) != 1: raise ValueError('native-worker-template-unavailable')
    worker = worker.replace(marker, b'PACKAGE = '+repr(package).encode('ascii'))
    if len(worker) > MAX_WORKER: raise ValueError('native-worker-package-limit')
    return worker


def assemble_entry(root, worker, *, reader, configuration=False, repository=False):
    root = Path(root)
    if type(configuration) is not bool or type(repository) is not bool or configuration and repository:
        raise ValueError('exact-companion-entry-scope-required')
    path = 'company-repository.sh' if repository else 'company-configure.sh' if configuration else 'company-retention.sh'
    entry = reader(root/('deploy/installer/'+path),32768)
    lock = reader(root/'scripts/install-lock.sh',32768)
    if entry.count(b'# @EMBED_INSTALL_LOCK@') != 1 or entry.count(b'@WORKER_SHA256@') != 1:
        raise ValueError('retention-entry-template-unavailable')
    entry = entry.replace(b'# @EMBED_INSTALL_LOCK@',lock).replace(b'@WORKER_SHA256@',pin(worker)['sha256'].encode('ascii'))
    if len(entry) > 32768: raise ValueError('retention-entry-package-limit')
    return entry


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('destination', type=Path)
    p.add_argument('--fingerprint', required=True)
    p.add_argument('--entry', type=Path, help='Optional companion company-retention.sh beside company-native-retention.py')
    p.add_argument('--configuration-entry', type=Path, help='Optional companion company-configure.sh; prepares a verified quiet foundation before retention')
    p.add_argument('--repository-entry', type=Path, help='Optional companion company-repository.sh; seeds a quiet configured foundation without activating services')
    a = p.parse_args(argv)
    if os.name != 'posix' or os.geteuid() != os.getegid() or os.geteuid() != 0:
        raise ValueError('company-linux-root-producer-required')
    worker = assemble(a.root, a.fingerprint, reader=protected_read)
    entry = assemble_entry(a.root, worker, reader=protected_read) if a.entry else None
    configuration_entry = assemble_entry(a.root, worker, reader=protected_read, configuration=True) if a.configuration_entry else None
    repository_entry = assemble_entry(a.root, worker, reader=protected_read, repository=True) if a.repository_entry else None
    if a.entry and (a.entry.parent != a.destination.parent or a.entry.name != 'company-retention.sh' or a.destination.name != 'company-native-retention.py' or a.entry.exists() or a.entry.is_symlink()):
        raise ValueError('fresh-exact-companion-entry-required')
    if a.configuration_entry and (a.configuration_entry.parent != a.destination.parent or a.configuration_entry.name != 'company-configure.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.configuration_entry)):
        raise ValueError('fresh-exact-configuration-entry-required')
    if a.repository_entry and (a.repository_entry.parent != a.destination.parent or a.repository_entry.name != 'company-repository.sh' or a.destination.name != 'company-native-retention.py' or os.path.lexists(a.repository_entry)):
        raise ValueError('fresh-exact-repository-entry-required')
    destination = a.destination
    if not destination.is_absolute(): raise ValueError('absolute-output-required')
    for parent in destination.parents:
        current = parent.lstat()
        if not stat.S_ISDIR(current.st_mode) or current.st_uid != current.st_gid or current.st_uid != 0 or current.st_mode & 0o022:
            raise ValueError('protected-output-ancestor-required')
    fd = os.open(destination, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o400)
    try:
        offset = 0
        while offset < len(worker):
            count = os.write(fd, worker[offset:offset+65536])
            if count <= 0: raise ValueError('short-package-write')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(destination.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    if protected_read(destination, MAX_WORKER) != worker: raise ValueError('package-readback-mismatch')
    for entry_path, entry_raw in ((a.entry, entry), (a.configuration_entry, configuration_entry), (a.repository_entry, repository_entry)):
        if entry_raw is None: continue
        fd = os.open(entry_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
        try:
            offset = 0
            while offset < len(entry_raw):
                count = os.write(fd,entry_raw[offset:offset+65536])
                if count <= 0: raise ValueError('short-entry-write')
                offset += count
            os.fsync(fd)
        finally: os.close(fd)
        parent_fd = os.open(entry_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
        if protected_read(entry_path,32768) != entry_raw: raise ValueError('entry-readback-mismatch')
    print(json.dumps(dict(scope='COMPANY_RETENTION_WORKER_ONLY', path=str(destination),
        **pin(worker), entry=dict(path=str(a.entry),**pin(entry)) if entry is not None else None,
        configurationEntry=dict(path=str(a.configuration_entry),**pin(configuration_entry)) if configuration_entry is not None else None,
        repositoryEntry=dict(path=str(a.repository_entry),**pin(repository_entry)) if repository_entry is not None else None,
        fullInstallerAvailable=False), sort_keys=True))


if __name__ == '__main__':
    main()
