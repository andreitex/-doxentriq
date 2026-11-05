"""Complete company Git-source bytes, without signing, extraction or activation.

The caller independently chooses the release revision and trusted Git command
runner. A signed manifest authenticates bytes; it does not establish company
trust or prove producer completeness without the clean Git capture protocol.
Capacity limits and native filesystem/runner operation need separate qualification.
"""
from collections.abc import Mapping
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
from types import MappingProxyType
import zlib

SCOPE = 'COMPANY_FULL_PLATFORM_SOURCE_BYTES_ONLY'
POLICY_VERSION = 1
MAX_FILES = 2048
MAX_DIRECTORIES = 512
MAX_FILE_BYTES = 8 * 1024**2
MAX_TOTAL_BYTES = 64 * 1024**2
MAX_MANIFEST_BYTES = 1024**2
MAX_GZIP_BYTES = 32 * 1024**2
MAX_EXPANDED_BYTES = 96 * 1024**2
MAX_PATH_BYTES = 256
MAX_GIT_OUTPUT_BYTES = 1024**2
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
UNRELEASED_HANDLES = []
RUNTIME_ROOT_FILES = frozenset(('package.json', 'package-lock.json', 'tsconfig.json',
                               'README.md', '.dockerignore', '.gitignore', '.gitattributes'))
# Publication metadata is signed as inert source data, never installer authority.
# It is optional so earlier complete-source manifests keep their required roots.
ROOT_FILES = RUNTIME_ROOT_FILES | frozenset(('LICENSE', 'LICENSE.md', 'LICENSE.txt',
    'COPYING', 'NOTICE', 'NOTICE.md', 'CONTRIBUTING.md', 'SECURITY.md',
    'RELEASING.md', 'PUBLIC-SOURCE.json'))
OPTIONAL_SOURCE_ROOTS = ('.github',)
SOURCE_ROOTS = ('apps/admin', 'apps/control', 'packages', 'services', 'database',
                'models', 'deploy', 'scripts', 'tests', 'docs', 'templates', 'tools', 'test')
FORBIDDEN_PARTS = frozenset(('.git', '.local', '.aws', '.codex', '.agents',
    'node_modules', '__pycache__', 'dist', 'build', 'coverage', 'releases',
    'reports', 'verification', '.cache', '.local-data', 'artifacts', 'data', 'bin',
    'generated', 'logs', 'secrets', 'credentials', 'generated-apps', 'generated-mcps'))
REQUIRED_ANCHORS = frozenset((*RUNTIME_ROOT_FILES, 'apps/admin/src/main.tsx',
    'apps/control/src/main.ts', 'packages/core/package.json', 'database/001-platform.sql',
    'services/runtime/go.mod', 'services/runtime/go.sum', 'models/catalog.json',
    'deploy/compose.yaml', 'scripts/platform_source.py', 'scripts/installation-status.py'))
GZIP_HEADER = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff'


class SourceUnavailable(ValueError):
    """Fixed public failure, excluding paths, source data and external errors."""


def require(value):
    if not value:
        raise SourceUnavailable('platform-source-unavailable')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'


def _decode(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                            parse_constant=lambda _: require(False))
        require(raw == canonical(result))
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise SourceUnavailable('platform-source-unavailable') from None


def digest(value, size=64):
    return type(value) is str and re.fullmatch('[a-f0-9]{' + str(size) + '}', value) is not None


def relative_path(value):
    require(type(value) is str and 0 < len(value) <= MAX_PATH_BYTES and value.isascii())
    parts = value.split('/')
    require(len(parts) <= 16 and all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) and p not in ('.', '..')
                                   and not p.endswith('.') for p in parts))
    require(not any(p.lower() in FORBIDDEN_PARTS or p.lower().startswith('policy-test-') for p in parts))
    require(not any(p.lower().startswith('.env') or p.lower().endswith(('.key', '.pem', '.p12', '.pfx', '.pyc', '.ppk', '.luks', '.log')) for p in parts))
    require(value in ROOT_FILES or any(value.startswith(root + '/') for root in SOURCE_ROOTS + OPTIONAL_SOURCE_ROOTS))
    return value


def _paths(values):
    require(type(values) in (tuple, list) and 0 < len(values) <= MAX_FILES)
    paths = tuple(relative_path(value) for value in values)
    require(paths == tuple(sorted(paths, key=lambda p: p.encode('ascii'))))
    folded = {p.lower() for p in paths}
    require(len(folded) == len(paths))
    directories = {p.rsplit('/', 1)[0] for p in paths if '/' in p}
    directories |= {p[:i] for p in paths for i, char in enumerate(p) if char == '/'}
    require(len(directories) <= MAX_DIRECTORIES and len({d.lower() for d in directories}) == len(directories)
            and not folded.intersection(d.lower() for d in directories))
    require(REQUIRED_ANCHORS.issubset(paths))
    require(all(any(p.startswith(root + '/') for p in paths) for root in SOURCE_ROOTS))
    return paths


def _header(row):
    try:
        info = tarfile.TarInfo(row['path'])
        info.size = row['bytes']
        info.mode = 0o755 if row['gitMode'] == '100755' else 0o644
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ''
        info.type = tarfile.REGTYPE
        return info.tobuf(tarfile.USTAR_FORMAT, 'ascii', 'strict')
    except (ValueError, UnicodeError):
        raise SourceUnavailable('platform-source-unavailable') from None


def _validate(value):
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'policyVersion',
        'sourceRevision', 'sourceTree', 'fileCount', 'totalBytes', 'archive', 'files'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1)
    require(type(value['policyVersion']) is int and value['policyVersion'] == POLICY_VERSION)
    require(type(value['scope']) is str and value['scope'] == SCOPE)
    require(digest(value['sourceRevision'], 40) and digest(value['sourceTree'], 40))
    rows = value['files']
    require(type(rows) is list and 0 < len(rows) <= MAX_FILES)
    require(type(value['fileCount']) is int and value['fileCount'] == len(rows))
    require(type(value['totalBytes']) is int and 0 <= value['totalBytes'] <= MAX_TOTAL_BYTES)
    total, geometry = 0, 0
    for row in rows:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'gitMode'})
        relative_path(row['path'])
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE_BYTES)
        require(digest(row['sha256']))
        require(type(row['gitMode']) is str and row['gitMode'] in ('100644', '100755'))
        total += row['bytes']; geometry += 512 + ((row['bytes'] + 511) // 512) * 512
        require(total <= MAX_TOTAL_BYTES)
        _header(row)
    _paths([row['path'] for row in rows])
    require(total == value['totalBytes'] and _tar_size(geometry) <= MAX_EXPANDED_BYTES)
    pin = value['archive']
    require(type(pin) is dict and set(pin) == {'bytes', 'sha256'})
    require(type(pin['bytes']) is int and 18 < pin['bytes'] <= MAX_GZIP_BYTES and digest(pin['sha256']))
    return value


def validate_manifest(raw):
    """Validate canonical bytes and fixed source policy, without touching files."""
    value = _decode(raw, MAX_MANIFEST_BYTES)
    return _validate(value)


def _tar_size(geometry):
    return ((geometry + 1024 + 10239) // 10240) * 10240


def _gzip(raw):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    result = GZIP_HEADER + compressor.compress(raw) + compressor.flush()
    result += struct.pack('<II', zlib.crc32(raw), len(raw))
    require(len(result) <= MAX_GZIP_BYTES)
    return result


def _inflate(raw):
    require(type(raw) is bytes and 18 < len(raw) <= MAX_GZIP_BYTES and raw.startswith(GZIP_HEADER))
    try:
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        expanded = inflater.decompress(raw[10:], MAX_EXPANDED_BYTES + 1)
        require(len(expanded) <= MAX_EXPANDED_BYTES and not inflater.unconsumed_tail and inflater.eof)
        tail = inflater.unused_data
        require(len(tail) == 8 and struct.unpack('<II', tail) == (zlib.crc32(expanded), len(expanded)))
        return expanded
    except (zlib.error, struct.error):
        raise SourceUnavailable('platform-source-unavailable') from None


def _cross_bind(rows, raw, expected_paths, scope, count):
    require(type(expected_paths) in (tuple, list) and len(expected_paths) == count)
    expected = tuple(sorted(relative_path(p) for p in expected_paths))
    require(len(set(expected)) == count)
    value = _decode(raw, MAX_MANIFEST_BYTES)
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'files'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and value['scope'] == scope)
    require(type(value['files']) is list and len(value['files']) == count)
    for row, path in zip(value['files'], expected):
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and row['path'] == path)
        require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE_BYTES and digest(row['sha256']))
        require(path in rows and all(rows[path][key] == row[key] for key in ('bytes', 'sha256')))


class ValidatedPlatform:
    __slots__ = ('files', 'git_modes', 'manifest_bytes', 'archive_bytes', 'archive_sha256',
                 'archive_bytes_count', 'source_revision', 'source_tree')
    def __init__(self, manifest, archive, files, modes, revision, tree):
        for key, value in dict(files=MappingProxyType(dict(files)), git_modes=MappingProxyType(dict(modes)),
            manifest_bytes=manifest, archive_bytes=archive, archive_sha256=hashlib.sha256(archive).hexdigest(),
            archive_bytes_count=len(archive), source_revision=revision, source_tree=tree).items():
            object.__setattr__(self, key, value)
    def __setattr__(self, key, value):
        raise AttributeError('Immutable platform source bytes')


def verify_archive(manifest_raw, archive_raw, *, host_manifest_raw, deployment_manifest_raw,
                   host_paths, deployment_paths):
    """Verify signed byte snapshots and independent44/10 cross-binding in memory.

    The release verifier owns signature trust and held-original archive lifecycle.
    This function performs no source execution, filesystem extraction or writes.
    """
    manifest = validate_manifest(manifest_raw)
    require(type(archive_raw) is bytes and len(archive_raw) == manifest['archive']['bytes']
            and hashlib.sha256(archive_raw).hexdigest() == manifest['archive']['sha256'])
    by_path = {row['path']: row for row in manifest['files']}
    _cross_bind(by_path, host_manifest_raw, host_paths, 'COMPANY_SOURCE_BYTES_ONLY', 44)
    _cross_bind(by_path, deployment_manifest_raw, deployment_paths, 'COMPANY_DEPLOYMENT_BYTES_ONLY', 10)
    files, offset = {}, 0
    expanded = _inflate(archive_raw)
    for row in manifest['files']:
        require(expanded[offset:offset + 512] == _header(row))
        offset += 512
        data = expanded[offset:offset + row['bytes']]
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'])
        files[row['path']] = data
        offset += row['bytes']
        padding = (-row['bytes']) % 512
        require(expanded[offset:offset + padding] == b'\0' * padding)
        offset += padding
    require(len(expanded) == _tar_size(offset) and expanded[offset:] == b'\0' * (len(expanded) - offset))
    require(_tree([(row['path'], row['gitMode'], _blob(files[row['path']])) for row in manifest['files']]) == manifest['sourceTree'])
    return ValidatedPlatform(manifest_raw, archive_raw, files,
        {row['path']: row['gitMode'] for row in manifest['files']}, manifest['sourceRevision'], manifest['sourceTree'])


def _build(revision, tree, files, modes):
    paths = _paths(tuple(sorted(files)))
    require(set(modes) == set(paths) and digest(revision, 40) and digest(tree, 40))
    rows, pieces, total = [], [], 0
    for path in paths:
        data = files[path]
        require(type(data) is bytes and len(data) <= MAX_FILE_BYTES)
        require(type(modes[path]) is str and modes[path] in ('100644', '100755'))
        total += len(data); require(total <= MAX_TOTAL_BYTES)
        row = dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), gitMode=modes[path])
        rows.append(row); pieces.extend((_header(row), data, b'\0' * ((-len(data)) % 512)))
    geometry = sum(len(piece) for piece in pieces)
    require(_tar_size(geometry) <= MAX_EXPANDED_BYTES)
    pieces.append(b'\0' * (_tar_size(geometry) - geometry))
    require(_tree([(path, modes[path], _blob(files[path])) for path in paths]) == tree)
    archive = _gzip(b''.join(pieces))
    manifest = canonical(dict(schemaVersion=1, scope=SCOPE, policyVersion=1, sourceRevision=revision,
        sourceTree=tree, fileCount=len(rows), totalBytes=total,
        archive=dict(bytes=len(archive), sha256=hashlib.sha256(archive).hexdigest()), files=rows))
    validate_manifest(manifest)
    return ValidatedPlatform(manifest, archive, files, modes, revision, tree)


def _blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def _tree(entries):
    root = {}
    for path, mode, blob in entries:
        current = root
        parts = path.split('/')
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            require(type(current) is dict)
        require(parts[-1] not in current)
        current[parts[-1]] = (mode, blob)
    def hashed(node):
        rows = []
        for name, child in node.items():
            directory = type(child) is dict
            mode, blob = ('40000', hashed(child)) if directory else child
            rows.append((name + ('/' if directory else ''), mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(blob)))
        raw = b''.join(row for _, row in sorted(rows, key=lambda item: item[0].encode()))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return hashed(root)


class NativeGit:
    """Fixed read-only Git protocol through an explicit trusted bounded runner.

    runner(argv, env=..., limit=..., timeout=30) must return exact captured bytes,
    fail on command failure/overflow and own/reap its subprocess. This module does
    not create a launcher, infer native authority or execute code from the tree.
    """
    def __init__(self, binary, runner):
        require(type(binary) is str and Path(binary).is_absolute() and callable(runner))
        self.binary, self.runner = binary, runner
    def inspect(self, root, revision, guard=None):
        require(digest(revision, 40))
        prefix = (self.binary, '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch',
            '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
            '-c', 'core.untrackedCache=false', '-c', 'core.attributesFile=/dev/null', '-C', str(root))
        env = dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LANG='C', LC_ALL='C', TZ='UTC',
                   GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                   GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
        def run(*args):
            if guard is not None: guard()
            raw = self.runner((*prefix, *args), env=dict(env), limit=MAX_GIT_OUTPUT_BYTES, timeout=30)
            if guard is not None: guard()
            require(type(raw) is bytes and len(raw) <= MAX_GIT_OUTPUT_BYTES)
            return raw
        require(run('rev-parse', '--show-toplevel') == str(root).encode('ascii') + b'\n')
        require(run('rev-parse', '--verify', 'HEAD^{commit}') == revision.encode() + b'\n')
        tree = run('rev-parse', '--verify', revision + '^{tree}')
        require(len(tree) == 41 and tree.endswith(b'\n') and digest(tree[:-1].decode('ascii'), 40))
        # Name/index listing never asks Git to clean, diff or hash workingtree
        # content through configured filters. Held raw blob reads do that check.
        require(run('ls-files', '--others', '--exclude-standard', '-z') == b'')
        require(run('ls-files', '--others', '--ignored', '--exclude-standard', '-z') == b'')
        raw = run('ls-tree', '-rz', '--full-tree', revision)
        require(raw.endswith(b'\0') and raw.count(b'\0') <= MAX_FILES)
        entries = []
        try:
            for line in raw[:-1].split(b'\0'):
                metadata, path = line.split(b'\t')
                mode, kind, blob = metadata.decode('ascii').split(' ')
                require(mode in ('100644', '100755') and kind == 'blob' and digest(blob, 40))
                entries.append((relative_path(path.decode('ascii')), mode, blob))
        except (ValueError, UnicodeError):
            raise SourceUnavailable('platform-source-unavailable') from None
        entries.sort(key=lambda row: row[0].encode())
        _paths(tuple(row[0] for row in entries))
        require(_tree(entries) == tree[:-1].decode())
        index = run('ls-files', '--stage', '--full-name', '-z')
        expected_index = b''.join((mode + ' ' + blob + ' 0\t' + path).encode() + b'\0'
                                  for path, mode, blob in entries)
        require(index == expected_index)
        return tree[:-1].decode(), tuple(entries)


class NativeFiles:
    def __init__(self):
        require(os.name == 'posix' and all(hasattr(os, name) for name in
            ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC', 'O_NONBLOCK', 'pread')))
    def lstat(self, path): return os.stat(path, follow_symlinks=False)
    def fstat(self, fd): return os.fstat(fd)
    def cloexec(self, fd): return not os.get_inheritable(fd)
    def open(self, parent, name, directory):
        return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
            (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=parent)
    def read(self, fd, size, offset): return os.pread(fd, size, offset)
    def close(self, fd): os.close(fd)


def _identity(value):
    require(all(type(getattr(value, key)) is int for key in FIELDS))
    return tuple(getattr(value, key) for key in FIELDS)


class _Held:
    def __init__(self, root, backend, uid, gid):
        require(not UNRELEASED_HANDLES and type(uid) is int and type(gid) is int and 0 <= uid < 2**31 and 0 <= gid < 2**31)
        self.root = Path(root)
        require(self.root.is_absolute() and self.root != Path(self.root.anchor)
                and len(self.root.parts) <= 16 and str(self.root) == os.path.normpath(str(self.root)))
        self.backend, self.owner = backend, (uid, gid)
        self.handles, self.directories, self.records = [], {}, {}
    def protected(self, value, directory, ancestor=False):
        _identity(value)
        require(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
        require(not stat.S_IMODE(value.st_mode) & 0o022)
        require((value.st_uid, value.st_gid) in ({(0, 0), self.owner} if ancestor else {self.owner}))
        if not directory: require(value.st_nlink == 1 and 0 <= value.st_size <= MAX_FILE_BYTES)
        return value
    def own(self, fd):
        require(type(fd) is int and fd >= 0 and fd not in self.handles)
        self.handles.append(fd)
        require(self.backend.cloexec(fd))
        return fd
    def directory(self, path, parent, name, ancestor):
        if path in self.directories: return self.directories[path][0]
        require(len(self.directories) < MAX_DIRECTORIES + 16)
        before = self.protected(self.backend.lstat(path), True, ancestor)
        fd = self.own(self.backend.open(parent, name, True))
        require(_identity(before) == _identity(self.backend.fstat(fd)) == _identity(self.backend.lstat(path)))
        self.directories[path] = (fd, before, ancestor)
        return fd
    def guard(self):
        for path, (fd, before, ancestor) in self.directories.items():
            require(self.backend.cloexec(fd) and _identity(before) ==
                _identity(self.protected(self.backend.lstat(path), True, ancestor)) == _identity(self.backend.fstat(fd)))
        for path, (fd, before) in self.records.items():
            require(self.backend.cloexec(fd) and _identity(before) ==
                _identity(self.protected(self.backend.lstat(path), False)) == _identity(self.backend.fstat(fd)))
    def read(self, fd, size):
        parts, offset = [], 0
        while offset <= size:
            amount = min(65536, size + 1 - offset)
            raw = self.backend.read(fd, amount, offset)
            require(type(raw) is bytes and len(raw) <= amount)
            if not raw: break
            parts.append(raw); offset += len(raw)
        require(offset == size)
        return b''.join(parts)
    def acquire_root(self):
        path = Path(self.root.anchor)
        parent = self.directory(path, None, str(path), True)
        for part in self.root.parts[1:]:
            path /= part
            parent = self.directory(path, parent, part, path != self.root)
        self.guard()
    def acquire(self, entries):
        self.acquire_root()
        files, modes, total = {}, {}, 0
        for relative, mode, blob in entries:
            self.guard()
            path, parent = self.root, self.directories[self.root][0]
            for part in relative.split('/')[:-1]:
                path /= part
                parent = self.directory(path, parent, part, False)
            path /= relative.split('/')[-1]
            before = self.protected(self.backend.lstat(path), False)
            total += before.st_size; require(total <= MAX_TOTAL_BYTES)
            require(stat.S_IMODE(before.st_mode) == (0o755 if mode == '100755' else 0o644))
            fd = self.own(self.backend.open(parent, path.name, False))
            require(_identity(before) == _identity(self.backend.fstat(fd)) == _identity(self.backend.lstat(path)))
            self.records[path] = (fd, before)
            raw = self.read(fd, before.st_size)
            require(_blob(raw) == blob)
            self.guard(); files[relative], modes[relative] = raw, mode
        return files, modes
    def recheck(self, files):
        self.guard()
        for relative, expected in files.items():
            fd, before = self.records[self.root / relative]
            require(self.read(fd, before.st_size) == expected)
            self.guard()
    def close(self):
        failed = False
        for fd in reversed(self.handles):
            try:
                require(self.backend.close(fd) is None)
            except BaseException:
                UNRELEASED_HANDLES.append((self.backend, fd)); failed = True
        self.handles = []
        require(not failed)


class _GuardedMap(Mapping):
    __slots__ = ('held', 'values')
    def __init__(self, held, values):
        object.__setattr__(self, 'held', held); object.__setattr__(self, 'values', values)
    def __setattr__(self, key, value): raise AttributeError('Immutable captured source map')
    def __getitem__(self, key): self.held.check_active(); return self.values[key]
    def __iter__(self):
        self.held.check_active()
        for key in self.values:
            self.held.check_active(); yield key
    def __len__(self): self.held.check_active(); return len(self.values)


class CapturedPlatform:
    def __init__(self, bundle, held, git, root, revision, inventory):
        self._bundle, self._held, self._git, self._root = bundle, held, git, root
        self._revision, self._inventory, self._active = revision, inventory, True
        self._files, self._modes = _GuardedMap(self, bundle.files), _GuardedMap(self, bundle.git_modes)
    def check_active(self): require(self._active and not UNRELEASED_HANDLES)
    def recheck(self):
        try:
            self.check_active()
            require(self._git.inspect(self._root, self._revision, self._held.guard) == self._inventory)
            self._held.recheck(self._bundle.files)
        except BaseException:
            self._active = False
            raise SourceUnavailable('platform-source-unavailable') from None
    @property
    def files(self): self.check_active(); return self._files
    @property
    def git_modes(self): self.check_active(); return self._modes
    @property
    def manifest_bytes(self): self.check_active(); return self._bundle.manifest_bytes
    @property
    def archive_bytes(self): self.check_active(); return self._bundle.archive_bytes
    @property
    def archive_sha256(self): self.check_active(); return self._bundle.archive_sha256
    @property
    def archive_bytes_count(self): self.check_active(); return self._bundle.archive_bytes_count
    @property
    def source_revision(self): self.check_active(); return self._bundle.source_revision
    @property
    def source_tree(self): self.check_active(); return self._bundle.source_tree


@contextmanager
def capture_git_revision(root, revision, *, git, backend=None, uid=0, gid=0):
    """Capture every tracked non-secret regular file from one clean Git revision.

    No path manifest selects completeness. Unknown tracked inputs are refused,
    not silently excluded. GitSHA1 tree/blob evidence and held bytes must agree.
    No release output, signing, extraction, repository seeding or native grant.
    """
    held, captured = None, None
    try:
        require(type(git) is NativeGit and digest(revision, 40) and not UNRELEASED_HANDLES)
        root = Path(root)
        require(root.is_absolute())
        held = _Held(root, backend or NativeFiles(), uid, gid)
        held.acquire_root()
        inventory = git.inspect(root, revision, held.guard)
        files, modes = held.acquire(inventory[1])
        bundle = _build(revision, inventory[0], files, modes)
        captured = CapturedPlatform(bundle, held, git, root, revision, inventory)
        captured.recheck()
        yield captured
        captured.recheck()
    except Exception:
        if captured is not None: captured._active = False
        raise SourceUnavailable('platform-source-unavailable') from None
    finally:
        if captured is not None: captured._active = False
        if held is not None: held.close()
