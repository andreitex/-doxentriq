"""Bounded company source bytes; signature trust and caller activation are external."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCOPE = 'COMPANY_SOURCE_BYTES_ONLY'
MAX_FILES = 128
MAX_FILE_BYTES = 1024**2
MAX_TOTAL_BYTES = 16 * 1024**2
MAX_DIRECTORIES = 64
MAX_MANIFEST_BYTES = 32768
MAX_PATH_BYTES = 128
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
DIRECTORY_FIELDS = FIELDS[:5]
UNRELEASED_HANDLES = []

# Explicit company catalog, never a recursive discovery of scripts/fixtures.
# Imports inside immutable container images remain a separate signed-image scope.
INSTALLER_RUNTIME_SOURCES = tuple(sorted((
    'scripts/autosoft.sh', 'scripts/backup_quiescence.py', 'scripts/backup_recovery.py',
    'scripts/bootstrap.py', 'scripts/build-company-release.sh',
    'scripts/certificates.sh', 'scripts/checkpoint_admission.py',
    'scripts/company_source.py', 'scripts/host_kernel_security.py', 'scripts/identity.py',
    'scripts/host_package_inventory.py', 'scripts/install-lock.sh',
    'scripts/install-runtime-gate.sh', 'scripts/install.sh',
    'scripts/installation_identity.py', 'scripts/installer_parent.py',
    'scripts/keycloak-provision.mjs', 'scripts/keycloak-start.sh', 'scripts/lib.sh',
    'scripts/maintenance-broker-security.mjs', 'scripts/maintenance.py',
    'scripts/maintenance_broker_security.py', 'scripts/maintenance_image_export.py',
    'scripts/maintenance_scanner.py', 'scripts/qualify-filesystem.py',
    'scripts/qualify-samba.py', 'scripts/quota-helper.py',
    'scripts/quota_allocation.py', 'scripts/quota_runtime.py',
    'scripts/recovery_catalog.py', 'scripts/recovery_chain.py',
    'scripts/recovery_services.py', 'scripts/recovery_tools.py',
    'scripts/refresh-sources.py', 'scripts/registry_manifest.py',
    'scripts/release-manifest.py', 'scripts/resolve-images.py',
    'scripts/runtime_layout.py', 'scripts/runtime_pair_init.py',
    'scripts/security-check.sh', 'scripts/sign-company-release.sh',
    'scripts/startup_binding.py', 'scripts/storage-guard.sh', 'scripts/verify-release.py',
)))


class SourceUnavailable(ValueError):
    """Fixed failure; no private path, source bytes or external error is exposed."""


def require(value):
    if not value:
        raise SourceUnavailable('company-source-unavailable')


def relative_path(value):
    require(type(value) is str and 0 < len(value) <= MAX_PATH_BYTES)
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]*', value) is not None)
    parts = value.split('/')
    require(1 <= len(parts) <= 8 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9_-])?', part) for part in parts))
    return value


def catalog(paths):
    require(type(paths) in (tuple, list) and 0 < len(paths) <= MAX_FILES)
    result = tuple(sorted(relative_path(path) for path in paths))
    require(len(set(result)) == len(result))
    # A declared source file cannot also be an ancestor of another source file.
    require(not any(b.startswith(a + '/') for a in result for b in result if a != b))
    return result


def validate(manifest, *, paths=INSTALLER_RUNTIME_SOURCES):
    expected = catalog(paths)
    require(type(manifest) is dict and set(manifest) == {'schemaVersion', 'scope', 'files'})
    require(type(manifest['schemaVersion']) is int and manifest['schemaVersion'] == 1
            and type(manifest['scope']) is str and manifest['scope'] == SCOPE)
    rows = manifest['files']
    require(type(rows) is list and len(rows) == len(expected))
    total = 0
    for row, path in zip(rows, expected):
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'})
        require(relative_path(row['path']) == path)
        require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE_BYTES)
        require(type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']) is not None)
        total += row['bytes']
        require(total <= MAX_TOTAL_BYTES)
    return manifest


def encode(manifest, *, paths=INSTALLER_RUNTIME_SOURCES):
    validate(manifest, paths=paths)
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    require(len(raw) <= MAX_MANIFEST_BYTES)
    return raw


def decode(raw, *, paths=INSTALLER_RUNTIME_SOURCES):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST_BYTES)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    try:
        result = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                            parse_constant=lambda _: require(False))
        validate(result, paths=paths)
        require(raw == encode(result, paths=paths))
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise SourceUnavailable('company-source-unavailable') from None


class NativeFiles:
    """POSIX read-only openat/nofollow backend; no source import or write API."""

    def __init__(self):
        require(os.name == 'posix' and all(hasattr(os, name) for name in
                ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK', 'pread')))

    def lstat(self, path):
        return os.stat(path, follow_symlinks=False)

    def open(self, parent, name, directory):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        flags |= os.O_DIRECTORY if directory else os.O_NONBLOCK
        return os.open(name, flags, dir_fd=parent)

    def fstat(self, fd):
        return os.fstat(fd)

    def cloexec(self, fd):
        return not os.get_inheritable(fd)

    def read(self, fd, amount, offset):
        return os.pread(fd, amount, offset)

    def close(self, fd):
        os.close(fd)


def identity(value, directory=False):
    fields = DIRECTORY_FIELDS if directory else FIELDS
    require(all(type(getattr(value, field)) is int for field in fields))
    return tuple(getattr(value, field) for field in fields)


class _Snapshot:
    def __init__(self, root, paths, files, uid, gid):
        require(not UNRELEASED_HANDLES)
        require(type(uid) is int and type(gid) is int and 0 <= uid < 2**31 and 0 <= gid < 2**31)
        require(type(root) is str or isinstance(root, Path))
        self.root = Path(root)
        require(self.root.is_absolute() and self.root != Path(self.root.anchor)
                and self.root == Path(os.path.normpath(str(self.root))))
        self.paths, self.files, self.owner = catalog(paths), files, (uid, gid)
        self.handles, self.directories, self.records = [], {}, {}

    def protected(self, value, directory=False, ancestor=False):
        identity(value, directory)
        require(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
        require(not stat.S_IMODE(value.st_mode) & 0o022)
        allowed = {(0, 0), self.owner} if ancestor else {self.owner}
        require((value.st_uid, value.st_gid) in allowed)
        if not directory:
            require(value.st_nlink == 1 and 0 < value.st_size <= MAX_FILE_BYTES)
        return value

    def own(self, fd):
        require(type(fd) is int and fd >= 0 and fd not in self.handles)
        self.handles.append(fd)  # Register before any subsequent backend check.
        require(self.files.cloexec(fd))
        return fd

    def directory(self, path, parent, name, ancestor):
        if path in self.directories:
            return self.directories[path][0]
        require(len(self.directories) < MAX_DIRECTORIES)
        before = self.protected(self.files.lstat(path), True, ancestor)
        fd = self.own(self.files.open(parent, name, True))
        require(identity(before, True) == identity(self.files.fstat(fd), True)
                == identity(self.files.lstat(path), True))
        self.directories[path] = fd, before, ancestor
        return fd

    def guard(self):
        for path, (fd, before, ancestor) in self.directories.items():
            require(self.files.cloexec(fd))
            require(identity(self.protected(self.files.lstat(path), True, ancestor), True)
                    == identity(before, True) == identity(self.files.fstat(fd), True))
        for path, (fd, before) in self.records.items():
            require(self.files.cloexec(fd))
            require(identity(self.protected(self.files.lstat(path))) == identity(before)
                    == identity(self.files.fstat(fd)))

    def hash(self, fd, size):
        result, offset = hashlib.sha256(), 0
        while offset <= size:
            raw = self.files.read(fd, min(65536, size + 1 - offset), offset)
            require(type(raw) is bytes and len(raw) <= min(65536, size + 1 - offset))
            if not raw:
                break
            result.update(raw)
            offset += len(raw)
        require(offset == size)
        return result.hexdigest()

    def acquire(self):
        root_path = Path(self.root.anchor)
        parent = self.directory(root_path, None, str(root_path), True)
        current = root_path
        for part in self.root.parts[1:]:
            current /= part
            parent = self.directory(current, parent, part, current != self.root)
        rows, total = [], 0
        for relative in self.paths:
            parent, current = self.directories[self.root][0], self.root
            parts = relative.split('/')
            for part in parts[:-1]:
                current /= part
                parent = self.directory(current, parent, part, False)
            path = current / parts[-1]
            self.guard()
            before = self.protected(self.files.lstat(path))
            total += before.st_size
            require(total <= MAX_TOTAL_BYTES)
            fd = self.own(self.files.open(parent, parts[-1], False))
            require(identity(before) == identity(self.files.fstat(fd)) == identity(self.files.lstat(path)))
            self.records[path] = fd, before
            digest = self.hash(fd, before.st_size)
            self.guard()
            rows.append(dict(path=relative, bytes=before.st_size, sha256=digest))
        return dict(schemaVersion=1, scope=SCOPE, files=rows)

    def recheck(self, manifest):
        for row in manifest['files']:
            self.guard()
            fd, before = self.records[self.root / row['path']]
            require(row['bytes'] == before.st_size and self.hash(fd, before.st_size) == row['sha256'])
            self.guard()

    def close(self):
        failed = False
        handles, self.handles = self.handles, []
        for fd in reversed(handles):
            try:
                self.files.close(fd)
            except BaseException:
                # Never retry a numeric FD whose close outcome is uncertain.
                UNRELEASED_HANDLES.append((self.files, fd))
                failed = True
        require(not failed)


@contextmanager
def _snapshot(root, paths, files, owner_uid, owner_gid):
    held = None
    try:
        held = _Snapshot(root, paths, files or NativeFiles(), owner_uid, owner_gid)
        yield held
    except Exception:
        raise SourceUnavailable('company-source-unavailable') from None
    finally:
        if held is not None:
            held.close()


def create(root, *, paths=INSTALLER_RUNTIME_SOURCES, files=None, owner_uid=0, owner_gid=0):
    """Return canonical-signable source records; performs no output-file writes."""
    paths = catalog(paths)
    with _snapshot(root, paths, files, owner_uid, owner_gid) as held:
        manifest = held.acquire()
        encode(manifest, paths=paths)
        held.recheck(manifest)
    return manifest


def verify(root, manifest, *, paths=INSTALLER_RUNTIME_SOURCES, files=None, owner_uid=0, owner_gid=0):
    """Compare an externally authenticated manifest to an independent catalog."""
    paths = catalog(paths)
    # Own the canonical input snapshot before any backend work or callbacks.
    raw = manifest if type(manifest) is bytes else encode(manifest, paths=paths)
    declared = decode(raw, paths=paths)
    with _snapshot(root, paths, files, owner_uid, owner_gid) as held:
        measured = held.acquire()
        require(measured == declared)
        held.recheck(declared)
    raw = encode(declared, paths=paths)
    return dict(scope=SCOPE, status='verified', manifestSha256=hashlib.sha256(raw).hexdigest(),
                fileCount=len(declared['files']), changed=False, companyTrustEstablished=False,
                signatureVerified=False, nativeAuthorized=False, backupReady=False)
