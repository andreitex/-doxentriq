#!/usr/bin/env python3
"""Authenticate schema2 release bytes; installer activation is a separate boundary."""
import argparse
import base64
from contextlib import ExitStack, contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import MappingProxyType, ModuleType

RELEASE_LIMIT = 16384
PUBLIC_KEY_LIMIT = 4096
CONFIG_LIMIT = 1024 ** 2
SOURCE_MANIFEST_LIMIT = 32768
DEPLOYMENT_MANIFEST_LIMIT = 8192
DEPLOYMENT_TOTAL_LIMIT = 4 * 1024 ** 2
SOURCE_TOTAL_LIMIT = 16 * 1024 ** 2
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
UNRELEASED_HANDLES = []
DEPLOYMENT_FILES = ('approved-mirrors.json', 'images.lock.json', 'runtime-manifest.json')
SIGNED_FILES = (*DEPLOYMENT_FILES, 'company-sources.json')
SIGNED_DEPLOYMENT_FILES = (*SIGNED_FILES, 'company-deployment.json')
COMPANY_DEPLOYMENT = (
    'deploy/compose.yaml', 'deploy/config/grafana-datasources.yml',
    'deploy/config/loki.yml', 'deploy/config/mysql.cnf', 'deploy/config/otel.yml',
    'deploy/config/prometheus-web.yml', 'deploy/config/prometheus.yml',
    'deploy/config/rabbitmq.conf', 'deploy/config/redis.conf', 'deploy/config/squid.conf',
)
# Independent, explicit catalog. Never accept a candidate module's discovery.
COMPANY_SOURCES = tuple(sorted((
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

class ReleaseUnavailable(ValueError):
    pass

def require(value):
    if not value:
        raise ReleaseUnavailable('company-release-unavailable')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False, ensure_ascii=True).encode('ascii') + b'\n'

def decode(raw, limit, *, canonical_only=False):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result); result[key] = value
        return result
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False))
        if canonical_only: require(raw == canonical(value))
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ReleaseUnavailable('company-release-unavailable') from None

def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None

def architecture(value):
    require(type(value) is str and value == 'x86_64')
    return value

def validate_release(value, expected_architecture, *, schema=2):
    architecture(expected_architecture)
    require(type(schema) is int and schema in (1, 2, 3))
    require(type(value) is dict and set(value) ==
            {'schemaVersion', 'version', 'createdAt', 'architecture', 'files'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == schema)
    require(type(value['version']) is str and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', value['version']) is not None)
    timestamp = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z' if schema in (2, 3) else r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)'
    require(type(value['createdAt']) is str and re.fullmatch(timestamp, value['createdAt']) is not None)
    try: datetime.fromisoformat(value['createdAt'].replace('Z', '+00:00'))
    except ValueError: require(False)
    require(architecture(value['architecture']) == expected_architecture)
    names = SIGNED_DEPLOYMENT_FILES if schema == 3 else SIGNED_FILES if schema == 2 else DEPLOYMENT_FILES
    require(type(value['files']) is dict and set(value['files']) == set(names))
    for name, row in value['files'].items():
        if schema == 1: require(digest(row))
        else:
            require(type(row) is dict and set(row) == {'bytes', 'sha256'})
            limit = SOURCE_MANIFEST_LIMIT if name == 'company-sources.json' else DEPLOYMENT_MANIFEST_LIMIT if name == 'company-deployment.json' else CONFIG_LIMIT
            require(type(row['bytes']) is int and 0 < row['bytes'] <= limit and digest(row['sha256']))
    return value

def source_manifest(raw):
    value = decode(raw, SOURCE_MANIFEST_LIMIT, canonical_only=True)
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'files'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and type(value['scope']) is str and value['scope'] == 'COMPANY_SOURCE_BYTES_ONLY')
    rows = value['files']; require(type(rows) is list and len(rows) == len(COMPANY_SOURCES) == 44)
    total = 0
    for row, name in zip(rows, COMPANY_SOURCES):
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'})
        require(type(row['path']) is str and row['path'] == name)
        require(type(row['bytes']) is int and 0 < row['bytes'] <= CONFIG_LIMIT and digest(row['sha256']))
        total += row['bytes']; require(total <= SOURCE_TOTAL_LIMIT)
    return value

def deployment_manifest(raw):
    """Independent exact template coverage; a manifest cannot choose its catalog."""
    value = decode(raw, DEPLOYMENT_MANIFEST_LIMIT, canonical_only=True)
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'files'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and type(value['scope']) is str and value['scope'] == 'COMPANY_DEPLOYMENT_BYTES_ONLY')
    rows = value['files']; require(type(rows) is list and len(rows) == len(COMPANY_DEPLOYMENT) == 10)
    total = 0
    for row, name in zip(rows, COMPANY_DEPLOYMENT):
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'})
        require(type(row['path']) is str and row['path'] == name)
        require(type(row['bytes']) is int and 0 < row['bytes'] <= CONFIG_LIMIT and digest(row['sha256']))
        total += row['bytes']; require(total <= DEPLOYMENT_TOTAL_LIMIT)
    return value

def public_der(raw):
    require(type(raw) is bytes and 0 < len(raw) <= PUBLIC_KEY_LIMIT)
    match = re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----\r?\n', raw)
    require(match is not None)
    try: der = base64.b64decode(match[1].replace(b'\r', b'').replace(b'\n', b''), validate=True)
    except ValueError: require(False)
    # RFC 8410 Ed25519 SubjectPublicKeyInfo: absent parameters, 32-byte key.
    require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100'))
    return der

class NativeFiles:
    """POSIX nofollow held descriptors; injected profiles do not qualify Linux."""
    def __init__(self):
        require(os.name == 'posix' and all(hasattr(os, name) for name in
                ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK', 'pread')))
    def lstat(self, path): return os.stat(path, follow_symlinks=False)
    def open(self, parent, name, directory):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        return os.open(name, flags | (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=parent)
    def fstat(self, fd): return os.fstat(fd)
    def cloexec(self, fd): return not os.get_inheritable(fd)
    def read(self, fd, amount, offset): return os.pread(fd, amount, offset)
    def close(self, fd): os.close(fd)

class Snapshot:
    """Retain immutable byte copies and guard their actual original handles."""
    def __init__(self, root, files, owner_uid, owner_gid):
        require(not UNRELEASED_HANDLES)
        require(type(owner_uid) is int and type(owner_gid) is int
                and 0 <= owner_uid < 2**31 and 0 <= owner_gid < 2**31)
        self.root = Path(root)
        require(self.root.is_absolute() and self.root != Path(self.root.anchor)
                and self.root == Path(os.path.normpath(str(self.root))) and len(self.root.parts) <= 32)
        self.files, self.owner = files, (owner_uid, owner_gid)
        self.held, self.directories, self.records, self.total = [], {}, {}, 0
    def identity(self, info, directory=False):
        fields = FIELDS[:5] if directory else FIELDS
        require(all(type(getattr(info, field)) is int for field in fields))
        return tuple(getattr(info, field) for field in fields)
    def protected(self, info, directory=False, ancestor=False):
        self.identity(info, directory)
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        require(not stat.S_IMODE(info.st_mode) & 0o022)
        require((info.st_uid, info.st_gid) in ({(0, 0), self.owner} if ancestor else {self.owner}))
        if not directory: require(info.st_nlink == 1)
        return info
    def own(self, fd):
        require(type(fd) is int and fd >= 0 and fd not in self.held)
        self.held.append(fd); require(self.files.cloexec(fd)); return fd
    def directory(self, path, parent, name, ancestor):
        if path in self.directories: return self.directories[path][0]
        require(len(self.directories) < 80)
        before = self.protected(self.files.lstat(path), True, ancestor)
        fd = self.own(self.files.open(parent, name, True))
        require(self.identity(before, True) == self.identity(self.files.fstat(fd), True)
                == self.identity(self.files.lstat(path), True))
        self.directories[path] = fd, before, ancestor; return fd
    def guard(self):
        for path, (fd, before, ancestor) in self.directories.items():
            require(self.files.cloexec(fd) and self.identity(before, True) ==
                    self.identity(self.protected(self.files.lstat(path), True, ancestor), True)
                    == self.identity(self.files.fstat(fd), True))
        for path, (fd, before, _) in self.records.items():
            require(self.files.cloexec(fd) and self.identity(before) ==
                    self.identity(self.protected(self.files.lstat(path))) == self.identity(self.files.fstat(fd)))
    def read_fd(self, fd, size):
        parts, offset = [], 0
        while offset <= size:
            amount = min(65536, size + 1 - offset); raw = self.files.read(fd, amount, offset)
            require(type(raw) is bytes and len(raw) <= amount)
            if not raw: break
            parts.append(raw); offset += len(raw)
        require(offset == size); return b''.join(parts)
    def root_directory(self):
        path = Path(self.root.anchor); parent = self.directory(path, None, str(path), True)
        for part in self.root.parts[1:]:
            path /= part; parent = self.directory(path, parent, part, path != self.root)
        return parent
    def read(self, name, limit):
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,127}', name)
                and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', part) for part in name.split('/')))
        require(len(self.records) < 128)
        path = self.root; parent = self.root_directory()
        for part in name.split('/')[:-1]:
            path /= part; parent = self.directory(path, parent, part, False)
        path /= name.split('/')[-1]; require(path not in self.records); self.guard()
        before = self.protected(self.files.lstat(path)); require(0 < before.st_size <= limit)
        self.total += before.st_size; require(self.total <= SOURCE_TOTAL_LIMIT + 4 * CONFIG_LIMIT + RELEASE_LIMIT)
        fd = self.own(self.files.open(parent, path.name, False))
        require(self.identity(before) == self.identity(self.files.fstat(fd)) == self.identity(self.files.lstat(path)))
        raw = self.read_fd(fd, before.st_size); self.records[path] = fd, before, raw
        self.guard(); return raw
    def recheck(self):
        # No code is compiled or operation dispatched inside this read phase.
        # Guard the complete set on both sides, instead of rescanning every
        # held path twice for each file. Metadata and bytes remain mandatory.
        records, directories = self.records, self.directories
        rows, parents = tuple(records.items()), tuple(directories.items())
        self.guard()
        for path, row in rows:
            require(records.get(path) is row)
            fd, before, raw = row
            require(self.read_fd(fd, before.st_size) == raw)
        require(self.records is records and self.directories is directories and
                len(records) == len(rows) and len(directories) == len(parents) and
                all(records.get(path) is row for path, row in rows) and
                all(directories.get(path) is row for path, row in parents))
        self.guard()
    def __enter__(self): return self
    def __exit__(self, *_):
        failed = False; held, self.held = self.held, []
        for fd in reversed(held):
            try: self.files.close(fd)
            except BaseException:
                UNRELEASED_HANDLES.append((self.files, fd)); failed = True
        require(not failed)

class SealedInputs:
    """Linux-only sealed memfd inputs, with no disk scratch or mutable reparse."""
    def __init__(self):
        require(os.name == 'posix' and all(hasattr(os, name) for name in
                ('memfd_create', 'MFD_CLOEXEC', 'MFD_ALLOW_SEALING', 'pread')))
        import fcntl
        self.fcntl = fcntl
        require(all(hasattr(fcntl, name) for name in ('F_ADD_SEALS', 'F_GET_SEALS',
                'F_SEAL_SEAL', 'F_SEAL_SHRINK', 'F_SEAL_GROW', 'F_SEAL_WRITE')))
        self.seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    def new(self, name):
        return os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    def seal(self, fd, raw):
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:]); require(type(written) is int and 0 < written <= len(raw) - offset)
            offset += written
        self.fcntl.fcntl(fd, self.fcntl.F_ADD_SEALS, self.seals)
        self.check(fd, raw)
    def check(self, fd, raw):
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 0 and before.st_size == len(raw)
                and not os.get_inheritable(fd) and self.fcntl.fcntl(fd, self.fcntl.F_GET_SEALS) == self.seals)
        require(os.pread(fd, len(raw) + 1, 0) == raw)
        current = os.stat('/proc/self/fd/' + str(fd))
        require(all(getattr(before, field) == getattr(current, field) for field in FIELDS))
    def close(self, fd):
        os.close(fd)


class NativeCrypto:
    """Exact sealed bytes passed only to a fixed system OpenSSL verifier."""
    def __init__(self, *, inputs=None, run=None):
        self.inputs, self.run = inputs, run
    def verify(self, message, signature, key):
        require(not UNRELEASED_HANDLES and type(message) is bytes and 0 < len(message) <= RELEASE_LIMIT
                and type(signature) is bytes and len(signature) == 64
                and type(key) is bytes and 0 < len(key) <= PUBLIC_KEY_LIMIT)
        inputs, run = self.inputs or SealedInputs(), self.run or subprocess.run
        held = []
        try:
            for name, raw in (('company-release-message', message), ('company-release-signature', signature), ('company-release-public', key)):
                fd = inputs.new(name)
                require(type(fd) is int and fd >= 0 and fd not in [item[0] for item in held])
                held.append((fd, raw))  # Register before writes, sealing and checks.
                inputs.seal(fd, raw)
            message_fd, signature_fd, key_fd = [item[0] for item in held]
            for fd, raw in held: inputs.check(fd, raw)
            result = run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-rawin', '-pubin',
                '-inkey', '/proc/self/fd/' + str(key_fd), '-in', '/proc/self/fd/' + str(message_fd),
                '-sigfile', '/proc/self/fd/' + str(signature_fd)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                pass_fds=tuple(item[0] for item in held),
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, timeout=15, check=False)
            for fd, raw in held: inputs.check(fd, raw)
            require(type(result.returncode) is int and result.returncode == 0)
        finally:
            failed = False
            for fd, _ in reversed(held):
                try: inputs.close(fd)
                except BaseException:
                    UNRELEASED_HANDLES.append((inputs, fd)); failed = True
            require(not failed)
        return True

def authenticate(bundle, key, fingerprint, crypto):
    require(digest(fingerprint)); public = key.read(key.public_name, PUBLIC_KEY_LIMIT)
    require(hashlib.sha256(public_der(public)).hexdigest() == fingerprint)
    raw = bundle.read('release.json', RELEASE_LIMIT); signature = bundle.read('release.sig', 64)
    require(len(signature) == 64); bundle.recheck(); key.recheck()
    require(crypto.verify(raw, signature, public) is True)
    bundle.recheck(); key.recheck(); return raw

def signed_configs(bundle, release):
    result = {}
    for name in release['files']:
        raw = bundle.read(name, SOURCE_MANIFEST_LIMIT if name == 'company-sources.json' else DEPLOYMENT_MANIFEST_LIMIT if name == 'company-deployment.json' else CONFIG_LIMIT)
        row = release['files'][name]; expected = row if type(row) is str else row['sha256']
        require(hashlib.sha256(raw).hexdigest() == expected)
        if type(row) is dict: require(len(raw) == row['bytes'])
        result[name] = raw
    return result

def verified_resolver(raw):
    # Only called after all independent catalog rows and captured bytes match.
    module = ModuleType('company_authenticated_image_resolver')
    module.__file__ = '<authenticated scripts/resolve-images.py>'
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    require(callable(getattr(module, 'validate', None))); return module

def verify(directory, public_key, fingerprint, *, expected_architecture,
           source_root=None, files=None, crypto=None, owner_uid=0, owner_gid=0):
    """Default schema2 authentication; does not authorize installer activation."""
    architecture(expected_architecture); require(digest(fingerprint))
    backend = files or NativeFiles()
    root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[1]
    public_key = Path(public_key)
    with ExitStack() as stack:
        bundle = stack.enter_context(Snapshot(directory, backend, owner_uid, owner_gid))
        key = stack.enter_context(Snapshot(public_key.parent, backend, owner_uid, owner_gid))
        key.public_name = public_key.name
        raw = authenticate(bundle, key, fingerprint, crypto or NativeCrypto())
        release = validate_release(decode(raw, RELEASE_LIMIT, canonical_only=True), expected_architecture)
        configs = signed_configs(bundle, release); declared = source_manifest(configs['company-sources.json'])
        sources = stack.enter_context(Snapshot(root, backend, owner_uid, owner_gid)); captured = {}
        for row in declared['files']:
            data = sources.read(row['path'], CONFIG_LIMIT)
            require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'])
            captured[row['path']] = data
        bundle.recheck(); key.recheck(); sources.recheck()
        images = decode(configs['images.lock.json'], CONFIG_LIMIT); require(type(images) is dict)
        require(type(decode(configs['runtime-manifest.json'], CONFIG_LIMIT)) is dict
                and type(decode(configs['approved-mirrors.json'], CONFIG_LIMIT)) is list)
        verified_resolver(captured['scripts/resolve-images.py']).validate(images)
        bundle.recheck(); key.recheck(); sources.recheck()
    return dict(status='SCHEMA2_SOURCE_AND_IMAGE_BYTES_AUTHENTICATED', release=release,
        releaseSha256=hashlib.sha256(raw).hexdigest(), sourceFileCount=44,
        signatureVerified=True, sourceAuthenticated=True, productionAuthorized=False,
        nativeAuthorized=False, installerActivated=False, trustContinuesAfterReturn=False)

def verify_deployment(directory, public_key, fingerprint, *, expected_architecture,
                      source_root=None, files=None, crypto=None, owner_uid=0, owner_gid=0):
    """Explicit schema3 byte authentication, with no installer activation grant."""
    architecture(expected_architecture); require(digest(fingerprint))
    backend = files or NativeFiles()
    root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[1]
    public_key = Path(public_key)
    with ExitStack() as stack:
        bundle = stack.enter_context(Snapshot(directory, backend, owner_uid, owner_gid))
        key = stack.enter_context(Snapshot(public_key.parent, backend, owner_uid, owner_gid))
        key.public_name = public_key.name
        raw = authenticate(bundle, key, fingerprint, crypto or NativeCrypto())
        release = validate_release(decode(raw, RELEASE_LIMIT, canonical_only=True), expected_architecture, schema=3)
        configs = signed_configs(bundle, release)
        declared = source_manifest(configs['company-sources.json'])
        deployment = deployment_manifest(configs['company-deployment.json'])
        rows = declared['files'] + deployment['files']
        require(sum(row['bytes'] for row in rows) <= SOURCE_TOTAL_LIMIT)
        sources = stack.enter_context(Snapshot(root, backend, owner_uid, owner_gid)); captured = {}
        for row in rows:
            data = sources.read(row['path'], CONFIG_LIMIT)
            require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'])
            captured[row['path']] = data
        bundle.recheck(); key.recheck(); sources.recheck()
        images = decode(configs['images.lock.json'], CONFIG_LIMIT); require(type(images) is dict)
        require(type(decode(configs['runtime-manifest.json'], CONFIG_LIMIT)) is dict
                and type(decode(configs['approved-mirrors.json'], CONFIG_LIMIT)) is list)
        verified_resolver(captured['scripts/resolve-images.py']).validate(images)
        bundle.recheck(); key.recheck(); sources.recheck()
    return dict(status='SCHEMA3_SOURCE_DEPLOYMENT_AND_IMAGE_BYTES_AUTHENTICATED', release=release,
        releaseSha256=hashlib.sha256(raw).hexdigest(), sourceFileCount=44, deploymentFileCount=10,
        signatureVerified=True, sourceAuthenticated=True, deploymentAuthenticated=True,
        productionAuthorized=False, nativeAuthorized=False, installerActivated=False,
        trustContinuesAfterReturn=False)

def _immutable_deployment(value):
    if type(value) is dict:
        return MappingProxyType({key: _immutable_deployment(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_immutable_deployment(item) for item in value)
    require(type(value) in (bytes, str, int, bool, type(None)))
    return value


class HeldDeployment:
    """Immutable authenticated bytes; held trust expires on every context exit."""
    __slots__ = ('__values', '__recheck', '__active')
    def __init__(self, sources, templates, configs, metadata, recheck, *, provenance=None):
        require(set(sources) == set(COMPANY_SOURCES) and set(templates) == set(COMPANY_DEPLOYMENT)
                and set(configs) == set(SIGNED_DEPLOYMENT_FILES) and callable(recheck))
        require(all(type(raw) is bytes for rows in (sources, templates, configs) for raw in rows.values()))
        values = dict(sources=sources, templates=templates, configs=configs, metadata=metadata)
        if provenance is not None:
            require(type(provenance) is dict and set(provenance) ==
                    {'release.json', 'release.sig', 'company-signing-public-key.pem'}
                    and all(type(raw) is bytes for raw in provenance.values()))
            values['provenance'] = provenance
        self.__values = _immutable_deployment(values)
        self.__recheck, self.__active = recheck, True
    @property
    def active(self): return self.__active
    def value(self, name):
        require(self.__active); return self.__values[name]
    @property
    def sources(self): return self.value('sources')
    @property
    def templates(self): return self.value('templates')
    @property
    def configs(self): return self.value('configs')
    @property
    def metadata(self): return self.value('metadata')
    @property
    def provenance(self): return self.value('provenance')
    def recheck(self):
        try:
            require(self.__active and not UNRELEASED_HANDLES)
            self.__recheck()
        except BaseException:
            self.__active = False
            raise
    def _expire(self): self.__active = False


@contextmanager
def authenticated_deployment(directory, public_key, fingerprint, *, expected_architecture,
                             source_root=None, files=None, crypto=None, owner_uid=0, owner_gid=0):
    """Hold schema3 trust through caller work, without granting installer effects."""
    architecture(expected_architecture); require(digest(fingerprint))
    backend = files or NativeFiles()
    root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[1]
    public_key = Path(public_key)
    with ExitStack() as stack:
        bundle = stack.enter_context(Snapshot(directory, backend, owner_uid, owner_gid))
        key = stack.enter_context(Snapshot(public_key.parent, backend, owner_uid, owner_gid))
        key.public_name = public_key.name
        raw = authenticate(bundle, key, fingerprint, crypto or NativeCrypto())
        release = validate_release(decode(raw, RELEASE_LIMIT, canonical_only=True), expected_architecture, schema=3)
        configs = signed_configs(bundle, release)
        declared = source_manifest(configs['company-sources.json'])
        deployment = deployment_manifest(configs['company-deployment.json'])
        rows = declared['files'] + deployment['files']
        require(sum(row['bytes'] for row in rows) <= SOURCE_TOTAL_LIMIT)
        sources = stack.enter_context(Snapshot(root, backend, owner_uid, owner_gid)); captured = {}
        for row in rows:
            data = sources.read(row['path'], CONFIG_LIMIT)
            require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'])
            captured[row['path']] = data
        bundle.recheck(); key.recheck(); sources.recheck()
        images = decode(configs['images.lock.json'], CONFIG_LIMIT); require(type(images) is dict)
        require(type(decode(configs['runtime-manifest.json'], CONFIG_LIMIT)) is dict
                and type(decode(configs['approved-mirrors.json'], CONFIG_LIMIT)) is list)
        verified_resolver(captured['scripts/resolve-images.py']).validate(images)
        bundle.recheck(); key.recheck(); sources.recheck()
        def recheck():
            bundle.recheck(); key.recheck(); sources.recheck()
        metadata = dict(status='SCHEMA3_SOURCE_DEPLOYMENT_AND_IMAGE_BYTES_AUTHENTICATED', release=release,
            releaseSha256=hashlib.sha256(raw).hexdigest(), sourceFileCount=44, deploymentFileCount=10,
            signatureVerified=True, sourceAuthenticated=True, deploymentAuthenticated=True,
            productionAuthorized=False, nativeAuthorized=False, installerActivated=False,
            trustContinuesAfterReturn=False)
        provenance = {name:bundle.records[bundle.root / name][2] for name in ('release.json', 'release.sig')}
        provenance['company-signing-public-key.pem'] = key.records[key.root / key.public_name][2]
        require(provenance['release.json'] is raw and len(provenance['release.sig']) == 64
                and hashlib.sha256(public_der(provenance['company-signing-public-key.pem'])).hexdigest() == fingerprint)
        held = HeldDeployment({name:captured[name] for name in COMPANY_SOURCES},
                              {name:captured[name] for name in COMPANY_DEPLOYMENT}, configs, metadata, recheck,
                              provenance=provenance)
        try:
            held.recheck()
            yield held
        finally:
            try: held.recheck()
            finally: held._expire()


def inspect_legacy_images(directory, public_key, fingerprint, *, expected_architecture,
                          files=None, crypto=None, owner_uid=0, owner_gid=0):
    """Explicit schema1 inspection; never import unsigned company source."""
    architecture(expected_architecture); require(digest(fingerprint))
    backend = files or NativeFiles(); public_key = Path(public_key)
    with Snapshot(directory, backend, owner_uid, owner_gid) as bundle, \
            Snapshot(public_key.parent, backend, owner_uid, owner_gid) as key:
        key.public_name = public_key.name
        raw = authenticate(bundle, key, fingerprint, crypto or NativeCrypto())
        release = validate_release(decode(raw, RELEASE_LIMIT), expected_architecture, schema=1)
        configs = signed_configs(bundle, release); images = decode(configs['images.lock.json'], CONFIG_LIMIT)
        expected = {'mysql', 'redis', 'rabbitmq', 'keycloak', 'registry', 'caddy', 'lego',
                    'prometheus', 'loki', 'grafana', 'otel', 'trivy', 'node', 'python',
                    'platform', 'runtime', 'dependency_proxy'}
        optional = {'samba_connector', 'filesystem_connector', 'mysql_recovery'}
        require(type(images) is dict and expected.issubset(images) and not set(images) - expected - optional)
        require(all(type(ref) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}', ref) for ref in images.values()))
        require(type(decode(configs['runtime-manifest.json'], CONFIG_LIMIT)) is dict
                and type(decode(configs['approved-mirrors.json'], CONFIG_LIMIT)) is list)
        bundle.recheck(); key.recheck()
    return dict(status='LEGACY_IMAGE_BUNDLE_INSPECTION_ONLY', release=release,
        signatureVerified=True, sourceAuthenticated=False, productionAuthorized=False,
        nativeAuthorized=False, installerActivated=False)

def inspect_unsigned_schema2(directory, *, files=None, owner_uid=0, owner_gid=0):
    """Company signing preparation only; grants no signature trust."""
    with Snapshot(directory, files or NativeFiles(), owner_uid, owner_gid) as bundle:
        raw = bundle.read('release.json', RELEASE_LIMIT)
        release = validate_release(decode(raw, RELEASE_LIMIT, canonical_only=True), 'x86_64')
        configs = signed_configs(bundle, release); source_manifest(configs['company-sources.json'])
        bundle.recheck()
    return raw, configs

def inspect_unsigned_deployment(directory, *, files=None, owner_uid=0, owner_gid=0):
    """Trusted schema3 signing preparation; manifests confer no signature trust."""
    with Snapshot(directory, files or NativeFiles(), owner_uid, owner_gid) as bundle:
        raw = bundle.read('release.json', RELEASE_LIMIT)
        release = validate_release(decode(raw, RELEASE_LIMIT, canonical_only=True), 'x86_64', schema=3)
        configs = signed_configs(bundle, release)
        sources = source_manifest(configs['company-sources.json'])
        deployment = deployment_manifest(configs['company-deployment.json'])
        require(sum(row['bytes'] for row in sources['files'] + deployment['files']) <= SOURCE_TOTAL_LIMIT)
        bundle.recheck()
    return raw, configs

class StationWrites:
    def __init__(self):
        require(os.name == 'posix')
    def inventory(self, parent): return os.listdir(parent)
    def create(self, parent, name):
        return os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=parent)
    def write(self, fd, raw): return os.write(fd, raw)
    def sync(self, fd): os.fsync(fd)


def signing_snapshot(directory, target, *, files=None, writer=None, owner_uid=0, owner_gid=0):
    """Trusted native station only; exclusive held-directory snapshot writes."""
    backend, writer = files or NativeFiles(), writer or StationWrites()
    raw, configs = inspect_unsigned_schema2(directory, files=backend, owner_uid=owner_uid, owner_gid=owner_gid)
    with Snapshot(target, backend, owner_uid, owner_gid) as output:
        parent = output.root_directory()
        require(stat.S_IMODE(backend.fstat(parent).st_mode) == 0o700 and writer.inventory(parent) == [])
        for name, data in {'release.json': raw, **configs}.items():
            output.guard()
            fd = writer.create(parent, name)
            output.own(fd)
            offset = 0
            while offset < len(data):
                written = writer.write(fd, data[offset:]); require(type(written) is int and 0 < written <= len(data)-offset)
                offset += written
            writer.sync(fd)
            path = output.root / name
            before = output.protected(backend.fstat(fd))
            require(output.identity(before) == output.identity(backend.lstat(path)))
            output.records[path] = fd, before, data
            output.recheck()
        writer.sync(parent); output.recheck()

def deployment_signing_snapshot(directory, target, *, files=None, writer=None, owner_uid=0, owner_gid=0):
    """Explicit complete-deployment snapshot; preserve the schema2 API unchanged."""
    backend, writer = files or NativeFiles(), writer or StationWrites()
    raw, configs = inspect_unsigned_deployment(directory, files=backend, owner_uid=owner_uid, owner_gid=owner_gid)
    with Snapshot(target, backend, owner_uid, owner_gid) as output:
        parent = output.root_directory()
        require(stat.S_IMODE(backend.fstat(parent).st_mode) == 0o700 and writer.inventory(parent) == [])
        for name, data in {'release.json': raw, **configs}.items():
            output.guard()
            fd = writer.create(parent, name)
            output.own(fd)
            offset = 0
            while offset < len(data):
                written = writer.write(fd, data[offset:]); require(type(written) is int and 0 < written <= len(data)-offset)
                offset += written
            writer.sync(fd)
            path = output.root / name
            before = output.protected(backend.fstat(fd))
            require(output.identity(before) == output.identity(backend.lstat(path)))
            output.records[path] = fd, before, data
            output.recheck()
        writer.sync(parent); output.recheck()

# Schema4 is separate from the fixed schema2/3 and foundation62 contracts.
PLATFORM_MANIFEST_LIMIT = 1024 ** 2
PLATFORM_ARCHIVE_LIMIT = 32 * 1024 ** 2
SIGNED_PLATFORM_FILES = (*SIGNED_DEPLOYMENT_FILES, 'platform-sources.json', 'platform-sources.tar.gz')
# Identity membership proves issuance by this exact trusted verifier instance.
_ISSUED_PLATFORM_SOURCES = set()


def validate_platform_release(value, expected_architecture):
    require(type(value) is dict and set(value) == {'schemaVersion', 'version', 'createdAt', 'architecture', 'files'}
            and type(value['schemaVersion']) is int and value['schemaVersion'] == 4
            and type(value['files']) is dict and set(value['files']) == set(SIGNED_PLATFORM_FILES))
    base = dict(value, schemaVersion=3, files={name:value['files'][name] for name in SIGNED_DEPLOYMENT_FILES})
    validate_release(base, expected_architecture, schema=3)
    for name, limit in (('platform-sources.json', PLATFORM_MANIFEST_LIMIT), ('platform-sources.tar.gz', PLATFORM_ARCHIVE_LIMIT)):
        row = value['files'][name]
        require(type(row) is dict and set(row) == {'bytes','sha256'}
                and type(row['bytes']) is int and 0 < row['bytes'] <= limit and digest(row['sha256']))
    return value


def platform_manifest_header(raw):
    """Independent bounded signed shape before opening or executing the helper."""
    value = decode(raw, PLATFORM_MANIFEST_LIMIT, canonical_only=True)
    require(type(value) is dict and set(value) == {'schemaVersion','scope','policyVersion','sourceRevision','sourceTree','fileCount','totalBytes','archive','files'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and value['scope'] == 'COMPANY_FULL_PLATFORM_SOURCE_BYTES_ONLY'
            and type(value['policyVersion']) is int and value['policyVersion'] == 1)
    require(all(type(value[key]) is str and re.fullmatch('[a-f0-9]{40}',value[key]) is not None for key in ('sourceRevision','sourceTree')))
    require(type(value['fileCount']) is int and 0 < value['fileCount'] <= 2048
            and type(value['totalBytes']) is int and 0 <= value['totalBytes'] <= 64*1024**2)
    pin = value['archive']
    require(type(pin) is dict and set(pin) == {'bytes','sha256'} and type(pin['bytes']) is int
            and 0 < pin['bytes'] <= PLATFORM_ARCHIVE_LIMIT and digest(pin['sha256']))
    rows = value['files']; require(type(rows) is list and len(rows) == value['fileCount'])
    previous = None; total = 0; aliases = set(); directories = set()
    for row in rows:
        require(type(row) is dict and set(row) == {'path','bytes','sha256','gitMode'})
        name = row['path']
        require(type(name) is str and 0 < len(name) <= 256 and name.isascii()
                and all(re.fullmatch('[A-Za-z0-9_.-]+',part) is not None and part not in ('.','..') for part in name.split('/')))
        require(previous is None or previous.encode('ascii') < name.encode('ascii'))
        require(name.lower() not in aliases); aliases.add(name.lower()); previous = name
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= 8*1024**2 and digest(row['sha256'])
                and type(row['gitMode']) is str and row['gitMode'] in ('100644','100755'))
        total += row['bytes']; require(total <= 64*1024**2)
        directories.update(str(p) for p in Path(name).parents if str(p) != '.')
        require(len(directories) <= 512)
    require(total == value['totalBytes'] and not set(row['path'] for row in rows).intersection(directories))
    return value


class PlatformInputSnapshot(Snapshot):
    """Read-only schema4 input ancestry retains all nine metadata fields."""
    def identity(self, info, directory=False):
        return super().identity(info, directory=False)


class PlatformArchiveSnapshot(PlatformInputSnapshot):
    """One fixed large blob; no change to the small Snapshot record/byte caps."""
    def read_archive(self):
        require(not self.records and self.total == 0)
        parent = self.root_directory(); path = self.root / 'platform-sources.tar.gz'; self.guard()
        before = self.protected(self.files.lstat(path)); require(0 < before.st_size <= PLATFORM_ARCHIVE_LIMIT)
        fd = self.own(self.files.open(parent,path.name,False))
        require(self.identity(before) == self.identity(self.files.fstat(fd)) == self.identity(self.files.lstat(path)))
        raw = self.read_fd(fd,before.st_size); self.records[path] = fd,before,raw; self.total = len(raw)
        self.guard(); return raw


class PlatformArchiveOutputSnapshot(Snapshot):
    """Intentional fresh writes retain the existing five-field directory policy."""


class _StoredPlatformPhysicalPolicy:
    """Actual stored file protection; signed Git modes remain logical archive data."""
    def protected(self, info, directory=False, ancestor=False):
        super().protected(info,directory,ancestor)
        require(info.st_uid == info.st_gid == 0)
        if not directory:
            require(stat.S_IMODE(info.st_mode) == 0o400)
        elif not ancestor:
            require(stat.S_IMODE(info.st_mode) == 0o500)
        return info


class StoredPlatformInputSnapshot(_StoredPlatformPhysicalPolicy,PlatformInputSnapshot):
    """Full-nine original stored bundle/parser observations, no metadata conversion."""


class StoredPlatformArchiveSnapshot(_StoredPlatformPhysicalPolicy,PlatformArchiveSnapshot):
    """Fixed original32MiB archive, physical0400; same read/close/cap behavior."""


def verified_platform_helper(raw):
    """Execute only exact signed helper bytes, with stdlib-only direct imports."""
    import ast
    require(type(raw) is bytes and 0 < len(raw) <= CONFIG_LIMIT)
    tree = ast.parse(raw)
    allowed = {'ast','base64','collections','contextlib','copy','dataclasses','datetime','errno','fcntl','gzip','hashlib','io','json','math','os','pathlib','re','secrets','signal','stat','struct','subprocess','sys','tarfile','time','types','typing','uuid','zlib','__future__'}
    for node in ast.walk(tree):
        if isinstance(node,ast.Import): require(all(alias.name.split('.')[0] in allowed for alias in node.names))
        if isinstance(node,ast.ImportFrom): require(node.level == 0 and type(node.module) is str and node.module.split('.')[0] in allowed)
    module = ModuleType('company_authenticated_platform_helper'); module.__file__ = '<captured authenticated scripts/platform_source.py>'
    # dataclass declarations need their exact definition module during execution.
    previous = sys.modules.get(module.__name__); sys.modules[module.__name__] = module
    try: exec(compile(tree,module.__file__,'exec'),module.__dict__)
    finally:
        if previous is None: sys.modules.pop(module.__name__,None)
        else: sys.modules[module.__name__] = previous
    require(callable(getattr(module,'verify_archive',None)))
    return module


def _platform_inputs(stack, directory, source_root, backend, owner_uid, owner_gid, release, bundle, *, platform_module=None, physical_policy='producer'):
    require(type(physical_policy) is str and physical_policy in ('producer','stored'))
    if physical_policy == 'stored':
        require(type(owner_uid) is int and type(owner_gid) is int and owner_uid == owner_gid == 0
                and platform_module is None)
    configs = {}
    for name in SIGNED_PLATFORM_FILES:
        if name == 'platform-sources.tar.gz': continue
        limit = PLATFORM_MANIFEST_LIMIT if name == 'platform-sources.json' else SOURCE_MANIFEST_LIMIT if name == 'company-sources.json' else DEPLOYMENT_MANIFEST_LIMIT if name == 'company-deployment.json' else CONFIG_LIMIT
        data = bundle.read(name,limit); row = release['files'][name]
        require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']); configs[name] = data
    declared = source_manifest(configs['company-sources.json']); deployment = deployment_manifest(configs['company-deployment.json'])
    header = platform_manifest_header(configs['platform-sources.json'])
    require(header['archive'] == release['files']['platform-sources.tar.gz'])
    archive_type = StoredPlatformArchiveSnapshot if physical_policy == 'stored' else PlatformArchiveSnapshot
    archive = stack.enter_context(archive_type(directory,backend,owner_uid,owner_gid))
    blob = archive.read_archive(); require(len(blob) == header['archive']['bytes'] and hashlib.sha256(blob).hexdigest() == header['archive']['sha256'])
    require(source_root is not None)
    helper_type = StoredPlatformInputSnapshot if physical_policy == 'stored' else PlatformInputSnapshot
    helper = stack.enter_context(helper_type(source_root,backend,owner_uid,owner_gid))
    rows = {row['path']:row for row in header['files']}; require('scripts/platform_source.py' in rows)
    row = rows['scripts/platform_source.py']; data = helper.read('scripts/platform_source.py',CONFIG_LIMIT)
    require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'])
    info = helper.records[helper.root/'scripts/platform_source.py'][1]
    if physical_policy == 'stored':
        require(stat.S_IMODE(info.st_mode) == 0o400)
        source_release = helper.root.parent
        require(source_release in helper.directories
                and stat.S_IMODE(helper.directories[source_release][1].st_mode) == 0o500)
    else:
        require(stat.S_IMODE(info.st_mode) == (0o755 if row['gitMode'] == '100755' else 0o644))
    bundle.recheck(); archive.recheck(); helper.recheck()
    if platform_module is None:
        platform = verified_platform_helper(data)
    else:
        # Only the explicit unsigned trusted-station API can supply this module.
        require(getattr(platform_module,'captured_source_bytes',None) == data
                and callable(getattr(platform_module,'verify_archive',None)))
        platform = platform_module
    captured = platform.verify_archive(configs['platform-sources.json'],blob,
        host_manifest_raw=configs['company-sources.json'],deployment_manifest_raw=configs['company-deployment.json'],
        host_paths=COMPANY_SOURCES,deployment_paths=COMPANY_DEPLOYMENT)
    # Independently assert the complete rows/maps and both finite catalogs too.
    require(set(captured.files) == set(rows) and set(captured.git_modes) == set(rows))
    for name,row in rows.items():
        data = captured.files[name]
        require(type(data) is bytes and len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'] and captured.git_modes[name] == row['gitMode'])
    for row in declared['files']+deployment['files']:
        data = captured.files.get(row['path']); require(type(data) is bytes and len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'])
    require(captured.manifest_bytes == configs['platform-sources.json'] and captured.archive_bytes == blob
            and captured.archive_sha256 == header['archive']['sha256'] and captured.archive_bytes_count == len(blob)
            and captured.source_revision == header['sourceRevision'])
    images = decode(configs['images.lock.json'],CONFIG_LIMIT); require(type(images) is dict
        and type(decode(configs['runtime-manifest.json'],CONFIG_LIMIT)) is dict
        and type(decode(configs['approved-mirrors.json'],CONFIG_LIMIT)) is list)
    verified_resolver(captured.files['scripts/resolve-images.py']).validate(images)
    bundle.recheck(); archive.recheck(); helper.recheck()
    return configs,header,captured,archive,helper


class HeldPlatformSource:
    """Captured bytes/modes only; every access rechecks live original ownership."""
    __slots__ = ('__values','__recheck','__active')
    def __init__(self,files,git_modes,configs,provenance,metadata,recheck,*,archive_bytes=None):
        require(type(files) is dict and type(git_modes) is dict and set(files) == set(git_modes)
                and all(type(raw) is bytes for raw in files.values()) and callable(recheck)
                and (archive_bytes is None or type(archive_bytes) is bytes))
        self.__values = _immutable_deployment(dict(files=files,git_modes=git_modes,configs=configs,provenance=provenance,metadata=metadata,archive_bytes=archive_bytes))
        self.__recheck,self.__active = recheck,True
    @property
    def active(self): return self.__active
    def recheck(self):
        try: require(self.__active and not UNRELEASED_HANDLES); self.__recheck()
        except BaseException: self._expire(); raise
    def value(self,name): self.recheck(); return self.__values[name]
    @property
    def files(self): return self.value('files')
    @property
    def git_modes(self): return self.value('git_modes')
    @property
    def configs(self): return self.value('configs')
    @property
    def provenance(self): return self.value('provenance')
    @property
    def metadata(self): return self.value('metadata')
    def _verified_archive(self):
        raw,metadata = self.__values['archive_bytes'],self.__values['metadata']
        require(type(raw) is bytes and 0 < len(raw) <= PLATFORM_ARCHIVE_LIMIT
                and type(metadata.get('archiveBytes')) is int and metadata['archiveBytes'] == len(raw)
                and digest(metadata.get('archiveSha256'))
                and hashlib.sha256(raw).hexdigest() == metadata['archiveSha256'])
        return raw
    @property
    def archive_bytes(self):
        try: require_platform_source(self); return self._verified_archive()
        except BaseException: self._expire(); raise
    def _expire(self):
        self.__active = False
        _ISSUED_PLATFORM_SOURCES.discard(self)


def require_platform_source(value):
    """Validate this verifier's live issued capability, never caller flags."""
    require(type(value) is HeldPlatformSource)
    issued = value in _ISSUED_PLATFORM_SOURCES
    try:
        require(issued and value.active and not UNRELEASED_HANDLES)
        value._verified_archive()
        value.recheck()
        require(value in _ISSUED_PLATFORM_SOURCES and value.active and not UNRELEASED_HANDLES)
        value._verified_archive()
    except BaseException:
        if issued: value._expire()
        raise
    return value


def capture_platform_source_maps(value):
    """One full original-source check, then the exact immutable captured maps.

    This is a bounded read of captured DATA. It grants no continuing disk
    witness, execution permission or authority after the source context ends.
    Legacy source getters and require_platform_source retain full rechecks.
    """
    require_platform_source(value)
    try:
        values = value._HeldPlatformSource__values
        require(type(values) is MappingProxyType)
        result = tuple(values[name] for name in ('files', 'git_modes', 'metadata'))
        require(all(type(item) is MappingProxyType for item in result))
        require(value in _ISSUED_PLATFORM_SOURCES and value.active and not UNRELEASED_HANDLES)
        return result
    except BaseException:
        value._expire()
        raise


@contextmanager
def authenticated_platform_source(directory,public_key,fingerprint,*,expected_architecture,
                                  source_root,files=None,crypto=None,owner_uid=0,owner_gid=0):
    """Schema4 complete-source bytes; no seeding or installer activation."""
    architecture(expected_architecture); require(digest(fingerprint) and source_root is not None)
    backend = files or NativeFiles(); public_key = Path(public_key); held = None
    try:
        with ExitStack() as stack:
            bundle = stack.enter_context(PlatformInputSnapshot(directory,backend,owner_uid,owner_gid))
            key = stack.enter_context(PlatformInputSnapshot(public_key.parent,backend,owner_uid,owner_gid)); key.public_name = public_key.name
            raw = authenticate(bundle,key,fingerprint,crypto or NativeCrypto())
            release = validate_platform_release(decode(raw,RELEASE_LIMIT,canonical_only=True),expected_architecture)
            configs,header,captured,archive,helper = _platform_inputs(stack,directory,source_root,backend,owner_uid,owner_gid,release,bundle)
            def recheck(): bundle.recheck(); key.recheck(); archive.recheck(); helper.recheck()
            metadata = dict(status='SCHEMA4_COMPLETE_PLATFORM_SOURCE_BYTES_AUTHENTICATED',release=release,
                releaseSha256=hashlib.sha256(raw).hexdigest(),platformManifestSha256=hashlib.sha256(configs['platform-sources.json']).hexdigest(),
                sourceRevision=header['sourceRevision'],sourceTree=header['sourceTree'],fileCount=header['fileCount'],totalBytes=header['totalBytes'],
                archiveSha256=header['archive']['sha256'],archiveBytes=header['archive']['bytes'],signingKeyFingerprint=fingerprint,sourceFileCount=44,deploymentFileCount=10,
                signatureVerified=True,sourceAuthenticated=True,deploymentAuthenticated=True,platformSourceAuthenticated=True,
                producerCompletenessIndependentlyProven=False,productionAuthorized=False,nativeAuthorized=False,installerActivated=False,trustContinuesAfterReturn=False)
            provenance = {name:bundle.records[bundle.root/name][2] for name in ('release.json','release.sig')}
            provenance['company-signing-public-key.pem'] = key.records[key.root/key.public_name][2]
            held = HeldPlatformSource(dict(captured.files),dict(captured.git_modes),configs,provenance,metadata,recheck,archive_bytes=captured.archive_bytes)
            try:
                held._verified_archive()
                held.recheck()
                _ISSUED_PLATFORM_SOURCES.add(held)
                yield held
            finally:
                try: held.recheck()
                finally: held._expire()
    finally:
        if held is not None: held._expire()


def _stored_platform_path(value):
    """Explicit native canonical path syntax, before any stored helper execution."""
    require(type(value) in (str,type(Path('.'))))
    text = str(value)
    require(0 < len(text) <= 2048 and text.isascii() and '\0' not in text)
    path = Path(text)
    require(path.is_absolute() and path != Path(path.anchor) and len(path.parts) <= 32
            and text == str(path) and path == Path(os.path.normpath(text))
            and all(re.fullmatch('[A-Za-z0-9_.-]+',part) and part not in ('.','..') for part in path.parts[1:]))
    return path


def _stored_platform_roots(directory,source_root,release_sha256):
    require(digest(release_sha256))
    bundle = _stored_platform_path(directory); source = _stored_platform_path(source_root)
    require(bundle.name == release_sha256 and bundle.parent.name == 'platform-releases'
            and bundle.parent.parent.name == 'company')
    require(source == bundle.parent.parent / 'source-releases' / release_sha256 / 'source')
    return bundle,source


@contextmanager
def authenticated_stored_platform_source(directory,public_key,fingerprint,*,expected_architecture,
                                         source_root,files=None,crypto=None):
    """Authenticate stored schema4 bytes/parser; selection/full-tree guard is external.

    The original trusted caller must independently select an exact confirmed
    Store/materialization stage, retain live encrypted storage and complete
    physical source-tree guards before executing operational code. Unsigned
    journals/flags do not grant that authority. This API checks only captured
    signed artifacts plus their exact parser; it does not adopt partial trees.
    """
    architecture(expected_architecture); require(digest(fingerprint) and source_root is not None)
    directory = _stored_platform_path(directory); source_root = _stored_platform_path(source_root)
    public_key = _stored_platform_path(public_key)
    backend = files or NativeFiles(); held = None
    try:
        with ExitStack() as stack:
            bundle = stack.enter_context(StoredPlatformInputSnapshot(directory,backend,0,0))
            # An external independently fingerprint-bound key may have0700 parent.
            # Preserve the original full-nine policy instead of stored-root0500.
            key = stack.enter_context(PlatformInputSnapshot(public_key.parent,backend,0,0)); key.public_name = public_key.name
            raw = authenticate(bundle,key,fingerprint,crypto or NativeCrypto())
            release = validate_platform_release(decode(raw,RELEASE_LIMIT,canonical_only=True),expected_architecture)
            release_sha256 = hashlib.sha256(raw).hexdigest()
            _stored_platform_roots(directory,source_root,release_sha256)
            configs,header,captured,archive,helper = _platform_inputs(stack,directory,source_root,backend,0,0,release,bundle,physical_policy='stored')
            def recheck(): bundle.recheck(); key.recheck(); archive.recheck(); helper.recheck()
            metadata = dict(status='SCHEMA4_COMPLETE_PLATFORM_SOURCE_BYTES_AUTHENTICATED',release=release,
                releaseSha256=release_sha256,platformManifestSha256=hashlib.sha256(configs['platform-sources.json']).hexdigest(),
                sourceRevision=header['sourceRevision'],sourceTree=header['sourceTree'],fileCount=header['fileCount'],totalBytes=header['totalBytes'],
                archiveSha256=header['archive']['sha256'],archiveBytes=header['archive']['bytes'],signingKeyFingerprint=fingerprint,sourceFileCount=44,deploymentFileCount=10,
                physicalSourcePolicy='IMMUTABLE_STORED_PLATFORM_SOURCE_V1',
                signatureVerified=True,sourceAuthenticated=True,deploymentAuthenticated=True,platformSourceAuthenticated=True,
                producerCompletenessIndependentlyProven=False,productionAuthorized=False,nativeAuthorized=False,installerActivated=False,trustContinuesAfterReturn=False)
            provenance = {name:bundle.records[bundle.root/name][2] for name in ('release.json','release.sig')}
            provenance['company-signing-public-key.pem'] = key.records[key.root/key.public_name][2]
            held = HeldPlatformSource(dict(captured.files),dict(captured.git_modes),configs,provenance,metadata,recheck,archive_bytes=captured.archive_bytes)
            try:
                held._verified_archive()
                held.recheck()
                _ISSUED_PLATFORM_SOURCES.add(held)
                yield held
            finally:
                try: held.recheck()
                finally: held._expire()
    finally:
        if held is not None: held._expire()


@contextmanager
def signing_station_platform_module(*,files=None,owner_uid=0,owner_gid=0):
    """Fixed externally trusted station code; ownership alone is not provenance."""
    backend = files or NativeFiles()
    with PlatformInputSnapshot(Path(__file__).parent,backend,owner_uid,owner_gid) as station:
        raw = station.read('platform_source.py',CONFIG_LIMIT); station.recheck()
        module = verified_platform_helper(raw); module.captured_source_bytes = raw
        station.recheck()
        try: yield module
        finally: station.recheck()


def platform_signing_snapshot(directory,target,*,source_root,platform_module,files=None,writer=None,owner_uid=0,owner_gid=0):
    """Explicit unsigned snapshot with trusted injected station code held by caller."""
    backend,writer = files or NativeFiles(),writer or StationWrites()
    require(platform_module is not None)
    with ExitStack() as stack:
        bundle = stack.enter_context(PlatformInputSnapshot(directory,backend,owner_uid,owner_gid))
        raw = bundle.read('release.json',RELEASE_LIMIT)
        release = validate_platform_release(decode(raw,RELEASE_LIMIT,canonical_only=True),'x86_64')
        configs,_,captured,archive,helper = _platform_inputs(stack,directory,source_root,backend,owner_uid,owner_gid,release,bundle,platform_module=platform_module)
        output = stack.enter_context(Snapshot(target,backend,owner_uid,owner_gid))
        large_output = stack.enter_context(PlatformArchiveOutputSnapshot(target,backend,owner_uid,owner_gid))
        parent = output.root_directory(); large_parent = large_output.root_directory()
        require(stat.S_IMODE(backend.fstat(parent).st_mode) == 0o700 and writer.inventory(parent) == [])
        records = {'release.json':raw,**configs,'platform-sources.tar.gz':captured.archive_bytes}
        written_names = set()
        def inventory():
            output.guard(); large_output.guard()
            names = writer.inventory(parent)
            require(type(names) is list and len(names) <= 8 and all(type(name) is str for name in names)
                    and len(names) == len(set(names)) and set(names) == written_names)
            output.guard(); large_output.guard()
        for name,data in records.items():
            bundle.recheck();archive.recheck();helper.recheck();output.recheck();large_output.recheck()
            inventory()
            destination = large_output if name == 'platform-sources.tar.gz' else output
            fd = writer.create(large_parent if destination is large_output else parent,name); destination.own(fd)
            offset = 0
            while offset < len(data):
                amount = min(65536,len(data)-offset); written = writer.write(fd,data[offset:offset+amount])
                require(type(written) is int and 0 < written <= amount); offset += written
            writer.sync(fd); path = destination.root/name; before = destination.protected(backend.fstat(fd))
            require(destination.identity(before) == destination.identity(backend.lstat(path)))
            destination.records[path] = fd,before,data; destination.recheck()
            written_names.add(name); inventory()
        writer.sync(parent);writer.sync(large_parent)
        bundle.recheck();archive.recheck();helper.recheck();output.recheck();large_output.recheck()
        require(written_names == {'release.json',*SIGNED_PLATFORM_FILES}); inventory()


def main():
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('public_key', type=Path, nargs='?'); parser.add_argument('fingerprint', nargs='?')
    parser.add_argument('--expected-architecture', choices=('x86_64',))
    parser.add_argument('--inspect-legacy-images', action='store_true')
    parser.add_argument('--complete-deployment', action='store_true')
    parser.add_argument('--complete-platform-source', action='store_true')
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--snapshot-for-signing', type=Path)
    args = parser.parse_args()
    if args.snapshot_for_signing is not None:
        require(not args.inspect_legacy_images and args.public_key is None and args.fingerprint is None
                and (args.source_root is None or args.complete_platform_source)
                and not (args.complete_deployment and args.complete_platform_source))
        if args.complete_platform_source:
            require(args.source_root is not None)
            with signing_station_platform_module(owner_uid=os.getuid(),owner_gid=os.getgid()) as module:
                platform_signing_snapshot(args.directory,args.snapshot_for_signing,source_root=args.source_root,platform_module=module,owner_uid=os.getuid(),owner_gid=os.getgid())
            print('Unsigned complete-platform snapshot prepared; no trust or activation granted.'); return
        operation = deployment_signing_snapshot if args.complete_deployment else signing_snapshot
        operation(args.directory, args.snapshot_for_signing, owner_uid=os.getuid(), owner_gid=os.getgid())
        print('Unsigned release snapshot prepared; no trust or activation granted.'); return
    require(args.public_key is not None and args.fingerprint is not None and args.expected_architecture is not None)
    require(sum((args.inspect_legacy_images,args.complete_deployment,args.complete_platform_source)) <= 1)
    if args.complete_platform_source:
        require(args.source_root is not None)
        with authenticated_platform_source(args.directory,args.public_key,args.fingerprint,expected_architecture=args.expected_architecture,source_root=args.source_root) as held:
            result = dict(held.metadata)
        print(result['status'] + '; installer activation remains unauthorized.'); return
    require(args.source_root is None or args.complete_deployment)
    operation = verify_deployment if args.complete_deployment else inspect_legacy_images if args.inspect_legacy_images else verify
    options = dict(source_root=args.source_root) if args.complete_deployment else {}
    result = operation(args.directory, args.public_key, args.fingerprint,
                       expected_architecture=args.expected_architecture, **options)
    print(result['status'] + '; installer activation remains unauthorized.')

if __name__ == '__main__':
    main()
