"""Materialize captured company bytes while their externally trusted context stays held.

No candidate import/execution, installer dispatch, package or service operation.
The caller must supply the active authenticated_deployment object from its trusted
verifier, an existing protected parent, and keep this context through caller work.
"""
from contextlib import contextmanager
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType, ModuleType

SOURCES = tuple(sorted((
    'scripts/autosoft.sh', 'scripts/backup_quiescence.py', 'scripts/backup_recovery.py',
    'scripts/bootstrap.py', 'scripts/build-company-release.sh', 'scripts/certificates.sh',
    'scripts/checkpoint_admission.py', 'scripts/company_source.py', 'scripts/host_kernel_security.py',
    'scripts/identity.py', 'scripts/host_package_inventory.py', 'scripts/install-lock.sh',
    'scripts/install-runtime-gate.sh', 'scripts/install.sh', 'scripts/installation_identity.py',
    'scripts/installer_parent.py', 'scripts/keycloak-provision.mjs', 'scripts/keycloak-start.sh',
    'scripts/lib.sh', 'scripts/maintenance-broker-security.mjs', 'scripts/maintenance.py',
    'scripts/maintenance_broker_security.py', 'scripts/maintenance_image_export.py',
    'scripts/maintenance_scanner.py', 'scripts/qualify-filesystem.py', 'scripts/qualify-samba.py',
    'scripts/quota-helper.py', 'scripts/quota_allocation.py', 'scripts/quota_runtime.py',
    'scripts/recovery_catalog.py', 'scripts/recovery_chain.py', 'scripts/recovery_services.py',
    'scripts/recovery_tools.py', 'scripts/refresh-sources.py', 'scripts/registry_manifest.py',
    'scripts/release-manifest.py', 'scripts/resolve-images.py', 'scripts/runtime_layout.py',
    'scripts/runtime_pair_init.py', 'scripts/security-check.sh', 'scripts/sign-company-release.sh',
    'scripts/startup_binding.py', 'scripts/storage-guard.sh', 'scripts/verify-release.py',
)))
TEMPLATES = ('deploy/compose.yaml', 'deploy/config/grafana-datasources.yml', 'deploy/config/loki.yml',
    'deploy/config/mysql.cnf', 'deploy/config/otel.yml', 'deploy/config/prometheus-web.yml',
    'deploy/config/prometheus.yml', 'deploy/config/rabbitmq.conf', 'deploy/config/redis.conf', 'deploy/config/squid.conf')
CONFIGS = ('approved-mirrors.json', 'images.lock.json', 'runtime-manifest.json', 'company-sources.json', 'company-deployment.json')
PROVENANCE = ('release.json', 'release.sig', 'company-signing-public-key.pem')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
FILE_LIMIT = 1024**2
TOTAL_LIMIT = 19*1024**2 + 32768 + 8192 + 16384 + 64 + 4096
FILE_COUNT = 62
TREE_DIRECTORIES = ('', 'scripts', 'deploy', 'deploy/config', 'company-release')
UNRELEASED_HANDLES = []

class MaterializationUnavailable(ValueError): pass
def require(value):
    if value is not True: raise MaterializationUnavailable('installer-materialization-unavailable')
def identity(info):
    require(all(type(getattr(info, key)) is int for key in FIELDS))
    return tuple(getattr(info, key) for key in FIELDS)
def protected(info, *, directory, mode=None):
    identity(info)
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    require(info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
    if mode is not None: require(stat.S_IMODE(info.st_mode) == mode)
    if not directory: require(info.st_nlink == 1)
    return info
def held_check(held):
    require(not UNRELEASED_HANDLES and held.active is True)
    held.recheck()
    require(held.active is True and not UNRELEASED_HANDLES)
def capture(held):
    held_check(held)
    groups=(held.sources, held.templates, held.configs, held.provenance)
    expected=(SOURCES,TEMPLATES,CONFIGS,PROVENANCE)
    require(all(type(group) is MappingProxyType and set(group) == set(names) for group,names in zip(groups,expected)))
    meta=held.metadata
    require(type(meta) is MappingProxyType and meta.get('status') == 'SCHEMA3_SOURCE_DEPLOYMENT_AND_IMAGE_BYTES_AUTHENTICATED'
        and type(meta.get('sourceFileCount')) is int and meta['sourceFileCount'] == 44
        and type(meta.get('deploymentFileCount')) is int and meta['deploymentFileCount'] == 10)
    require(all(meta.get(key) is True for key in ('signatureVerified','sourceAuthenticated','deploymentAuthenticated')))
    require(all(meta.get(key) is False for key in ('productionAuthorized','nativeAuthorized','installerActivated','trustContinuesAfterReturn')))
    rows={}; totals=[]
    for index,(group,names) in enumerate(zip(groups,expected)):
        total=0
        for name in names:
            raw=group[name]
            limit=32768 if name == 'company-sources.json' else 8192 if name == 'company-deployment.json' else \
                16384 if name == 'release.json' else 64 if name == 'release.sig' else 4096 if name == 'company-signing-public-key.pem' else FILE_LIMIT
            require(type(raw) is bytes and 0 < len(raw) <= limit)
            if name == 'release.sig': require(len(raw) == 64)
            relative=name if index < 2 else 'company-release/'+name
            require(relative not in rows and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,127}',relative) is not None
                and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',part) for part in relative.split('/')))
            rows[relative]=raw;total+=len(raw)
        totals.append(total)
    require(totals[0]+totals[1] <= 16*1024**2 and totals[1] <= 4*1024**2
        and sum(totals) <= TOTAL_LIMIT and len(rows) == FILE_COUNT)
    release_hash=meta.get('releaseSha256')
    require(type(release_hash) is str and re.fullmatch('[a-f0-9]{64}',release_hash) is not None
        and hashlib.sha256(rows['company-release/release.json']).hexdigest() == release_hash)
    held_check(held)
    return MappingProxyType(rows),release_hash

class NativeFiles:
    """Linux/POSIX root openat backend. No chmod/chown of an existing output."""
    def __init__(self):
        require(os.name == 'posix' and os.geteuid() == os.getegid() == 0
            and all(hasattr(os,name) for name in ('O_DIRECTORY','O_NOFOLLOW','O_CLOEXEC','O_NONBLOCK','pread')))
    def lstat(self,path): return os.stat(path,follow_symlinks=False)
    def open(self,parent,name,directory):
        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
        return os.open(name,flags|(os.O_DIRECTORY if directory else os.O_NONBLOCK),dir_fd=parent)
    def mkdir(self,parent,name): os.mkdir(name,0o700,dir_fd=parent)
    def create(self,parent,name): return os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    def fstat(self,fd): return os.fstat(fd)
    def cloexec(self,fd): return not os.get_inheritable(fd)
    def write(self,fd,raw): return os.write(fd,raw)
    def read(self,fd,size,offset): return os.pread(fd,size,offset)
    def chmod(self,fd,mode): os.fchmod(fd,mode)
    def sync(self,fd): os.fsync(fd)
    def names(self,fd,limit):
        result=[]
        with os.scandir(fd) as entries:
            for entry in entries:
                result.append(entry.name);require(len(result) <= limit)
        return sorted(result)
    def close(self,fd): os.close(fd)

class MaterializedDeployment:
    def __init__(self,held,parent,name,rows,release_hash,files,clock):
        require(type(name) is str and re.fullmatch('install-[a-f0-9]{32}',name) is not None)
        parent=Path(parent)
        require(parent.is_absolute() and parent != Path(parent.anchor) and parent == Path(os.path.normpath(str(parent)))
            and len(parent.parts) <= 32)
        self._held,self._parent,self._name,self._path=held,parent,name,parent/name
        self._rows,self._release_hash,self._files,self._clock=rows,release_hash,files,clock
        self._owned=[];self._unknown=set();self._anchors={};self._dirs={};self._records={};self._children={}
        self._active=True;self._ready=False;self._started=clock()
        require(type(self._started) in (int,float) and math.isfinite(self._started))
        self._deadline=self._started+60
    def _tick(self):
        now=self._clock()
        require(self._active and type(now) in (int,float) and math.isfinite(now) and self._started <= now < self._deadline)
    def _own(self,fd):
        require(type(fd) is int and fd >= 0 and fd not in self._owned)
        self._owned.append(fd);require(self._files.cloexec(fd));return fd
    def _close_one(self,fd):
        require(fd in self._owned and fd not in self._unknown)
        try: require(self._files.close(fd) is None)
        except BaseException:
            self._unknown.add(fd);UNRELEASED_HANDLES.append((self._files,fd));raise
        self._owned.remove(fd)
    def _directory(self,path,parent,name,*,anchor):
        self._tick();before=protected(self._files.lstat(path),directory=True,mode=0o700 if path == self._parent else None)
        fd=self._own(self._files.open(parent,name,True))
        require(identity(before) == identity(self._files.fstat(fd)) == identity(self._files.lstat(path)))
        (self._anchors if anchor else self._dirs)[path]=(fd,before)
        return fd
    def _guard(self):
        self._tick();require(not self._unknown and not UNRELEASED_HANDLES)
        for path,(fd,before) in (*self._anchors.items(),*self._dirs.items()):
            require(self._files.cloexec(fd))
            current=protected(self._files.lstat(path),directory=True)
            opened=protected(self._files.fstat(fd),directory=True)
            require(identity(current) == identity(before) == identity(opened))
        for path,(fd,before,_) in self._records.items():
            require(self._files.cloexec(fd) and identity(protected(self._files.lstat(path),directory=False,mode=0o400))
                == identity(before) == identity(self._files.fstat(fd)))
        for path,expected in self._children.items():
            fd=(self._anchors.get(path) or self._dirs[path])[0]
            require(self._names(fd,1024 if path == self._parent else FILE_COUNT) == sorted(expected))
    def _names(self,fd,limit):
        names=self._files.names(fd,limit)
        require(type(names) is list and len(names) <= limit and all(type(name) is str and 0 < len(name) <= 255
            and name not in ('.','..') and '/' not in name and '\\' not in name for name in names)
            and len(set(names)) == len(names) and names == sorted(names))
        return names
    def _before_effect(self):
        self._guard();held_check(self._held)
    def _parent_changed(self,path,*,new_directory):
        records=self._anchors if path in self._anchors else self._dirs
        fd,before=records[path]
        current=protected(self._files.fstat(fd),directory=True)
        require(identity(current) == identity(self._files.lstat(path))
            and identity(current)[:5] == identity(before)[:5]
            and current.st_nlink == before.st_nlink+(1 if new_directory else 0))
        records[path]=(fd,current)
    def _mkdir(self,path,parent_fd):
        self._before_effect();require(self._files.mkdir(parent_fd,path.name) is None)
        self._children[path.parent].add(path.name)
        self._parent_changed(path.parent,new_directory=True)
        fd=self._directory(path,parent_fd,path.name,anchor=False)
        require(stat.S_IMODE(self._dirs[path][1].st_mode) == 0o700)
        self._children[path]=set();require(self._files.sync(fd) is None);require(self._files.sync(parent_fd) is None);self._guard()
        return fd
    def _readback(self,fd,raw):
        offset=0;digest=hashlib.sha256()
        while offset <= len(raw):
            self._tick();amount=min(65536,len(raw)+1-offset);part=self._files.read(fd,amount,offset)
            require(type(part) is bytes and len(part) <= amount)
            if not part:break
            offset+=len(part);require(offset <= len(raw));digest.update(part)
        require(offset == len(raw) and digest.digest() == hashlib.sha256(raw).digest())
    def _file(self,relative,raw):
        path=self._path/relative;parent_fd=self._dirs[path.parent][0]
        self._before_effect();fd=self._own(self._files.create(parent_fd,path.name))
        created=protected(self._files.fstat(fd),directory=False,mode=0o600)
        require(identity(created) == identity(self._files.lstat(path)) and created.st_size == 0)
        self._children[path.parent].add(path.name)
        self._parent_changed(path.parent,new_directory=False)
        offset=0
        while offset < len(raw):
            self._tick();chunk=raw[offset:offset+65536];written=self._files.write(fd,chunk)
            require(type(written) is int and 0 < written <= len(chunk));offset+=written
        require(self._files.chmod(fd,0o400) is None);require(self._files.sync(fd) is None)
        before=protected(self._files.fstat(fd),directory=False,mode=0o400)
        require(before.st_size == len(raw) and identity(before) == identity(self._files.lstat(path)))
        self._readback(fd,raw);require(identity(self._files.fstat(fd)) == identity(before) == identity(self._files.lstat(path)))
        self._close_one(fd)
        fd=self._own(self._files.open(parent_fd,path.name,False))
        require(identity(self._files.fstat(fd)) == identity(before) == identity(self._files.lstat(path)))
        self._records[path]=(fd,before,raw);require(self._files.sync(parent_fd) is None);self._guard();held_check(self._held)
    def build(self):
        path=Path(self._parent.anchor);fd=self._directory(path,None,str(path),anchor=True)
        for part in self._parent.parts[1:]:
            path/=part;fd=self._directory(path,fd,part,anchor=True)
        self._children[self._parent]=set(self._names(fd,1024))
        require(self._name not in self._children[self._parent]);held_check(self._held)
        self._mkdir(self._path,fd)
        for relative in TREE_DIRECTORIES[1:]:
            path=self._path/relative;self._mkdir(path,self._dirs[path.parent][0])
        for relative,raw in sorted(self._rows.items()):self._file(relative,raw)
        for path,(fd,previous) in reversed(list(self._dirs.items())):
            self._before_effect();require(self._files.chmod(fd,0o500) is None);require(self._files.sync(fd) is None)
            before=protected(self._files.fstat(fd),directory=True,mode=0o500)
            require(identity(before) == identity(self._files.lstat(path))
                and all(getattr(before,key) == getattr(previous,key) for key in FIELDS if key not in ('st_mode','st_ctime_ns')))
            self._dirs[path]=(fd,before)
        self._guard();self._ready=True
    @property
    def root(self):self.recheck();return self._path
    @property
    def files(self):
        self.recheck()
        return MappingProxyType({name:MappingProxyType(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())) for name,raw in self._rows.items()})
    @property
    def release_sha256(self):self.recheck();return self._release_hash
    def recheck(self):
        try:
            require(self._active and self._ready)
            now=self._clock();require(type(now) in (int,float) and math.isfinite(now) and now >= self._started)
            self._deadline=now+60
            held_check(self._held);self._guard()
            for path,(fd,before,raw) in self._records.items():
                self._readback(fd,raw);require(identity(self._files.fstat(fd)) == identity(before) == identity(self._files.lstat(path)))
            self._guard();held_check(self._held)
        except BaseException:self._active=False;raise
    def close(self):
        self._active=False;failed=bool(self._unknown)
        for fd in reversed(list(self._owned)):
            if fd in self._unknown:failed=True;continue
            try:self._close_one(fd)
            except BaseException:failed=True
        require(not failed)

@contextmanager
def materialized_deployment(held,parent,name,*,files=None,clock=time.monotonic):
    """Fresh-only finite tree; preserves all partial output and never dispatches it."""
    rows,release_hash=capture(held)
    tree=MaterializedDeployment(held,parent,name,rows,release_hash,files if files is not None else NativeFiles(),clock)
    try:
        tree.build();tree.recheck();yield tree
    finally:
        try:
            if tree._ready:tree.recheck()
            else:held_check(held)
        finally:tree.close()


# A finite foundation projection, not a complete schema4 release bundle.
# Its archive stays with the original verifier/Store capability. The legacy
# schema3 entry above remains independent and unchanged.
PLATFORM_FOUNDATION_CONFIGS = (*CONFIGS, 'platform-sources.json')
PLATFORM_FOUNDATION_FILE_COUNT = 63
PLATFORM_FOUNDATION_TOTAL_LIMIT = TOTAL_LIMIT + FILE_LIMIT
_PLATFORM_FOUNDATION_SOURCES = set()


def _require_platform_foundation_source(held, verifier):
    """The company caller supplies its separately authenticated original V."""
    require(type(verifier) is ModuleType
            and tuple(verifier.COMPANY_SOURCES) == SOURCES
            and tuple(verifier.COMPANY_DEPLOYMENT) == TEMPLATES)
    require(verifier.require_platform_source(held) is held)
    require(not UNRELEASED_HANDLES)


def capture_platform_foundation(held, *, verifier):
    """Capture 44 host files, ten templates and nine config/provenance leaves.

    Genuine issuance in the caller's original verifier precedes source access.
    This does not authorize host effects, complete-bundle verification or full
    installation. The company caller must authenticate verifier identity first.
    """
    _require_platform_foundation_source(held, verifier)
    values, modes, configs, provenance, metadata = (
        held.files, held.git_modes, held.configs, held.provenance, held.metadata)
    require(all(type(group) is MappingProxyType for group in
                (values, modes, configs, provenance, metadata)))
    require(set(configs) == set(PLATFORM_FOUNDATION_CONFIGS)
            and set(provenance) == set(PROVENANCE))
    require(metadata.get('status') == 'SCHEMA4_COMPLETE_PLATFORM_SOURCE_BYTES_AUTHENTICATED'
            and type(metadata.get('sourceFileCount')) is int and metadata['sourceFileCount'] == 44
            and type(metadata.get('deploymentFileCount')) is int and metadata['deploymentFileCount'] == 10)
    require(all(metadata.get(key) is True for key in
                ('signatureVerified', 'sourceAuthenticated', 'deploymentAuthenticated', 'platformSourceAuthenticated')))
    require(all(metadata.get(key) is False for key in
                ('productionAuthorized', 'nativeAuthorized', 'installerActivated', 'trustContinuesAfterReturn')))
    manifest = verifier.decode(configs['platform-sources.json'], FILE_LIMIT, canonical_only=True)
    require(type(manifest) is dict and type(manifest.get('files')) is list
            and 0 < len(manifest['files']) <= 2048)
    signed = {}
    for row in manifest['files']:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'gitMode'}
                and type(row['path']) is str and row['path'] not in signed)
        signed[row['path']] = row
    rows, totals = {}, []
    for names in (SOURCES, TEMPLATES):
        total = 0
        for name in names:
            require(name in values and name in modes and name in signed)
            raw, row = values[name], signed[name]
            require(type(raw) is bytes and 0 < len(raw) <= FILE_LIMIT
                    and type(row['bytes']) is int and row['bytes'] == len(raw)
                    and type(row['sha256']) is str and row['sha256'] == hashlib.sha256(raw).hexdigest()
                    and type(row['gitMode']) is str and row['gitMode'] in ('100644', '100755')
                    and modes[name] == row['gitMode'])
            rows[name] = raw; total += len(raw)
        totals.append(total)
    for group, names in ((configs, PLATFORM_FOUNDATION_CONFIGS), (provenance, PROVENANCE)):
        total = 0
        for name in names:
            raw = group[name]
            limit = (32768 if name == 'company-sources.json' else 8192 if name == 'company-deployment.json'
                     else 16384 if name == 'release.json' else 64 if name == 'release.sig'
                     else 4096 if name == 'company-signing-public-key.pem' else FILE_LIMIT)
            require(type(raw) is bytes and 0 < len(raw) <= limit)
            if name == 'release.sig': require(len(raw) == 64)
            rows['company-release/' + name] = raw; total += len(raw)
        totals.append(total)
    require(totals[0] + totals[1] <= 16 * FILE_LIMIT and totals[1] <= 4 * FILE_LIMIT
            and sum(totals) <= PLATFORM_FOUNDATION_TOTAL_LIMIT
            and len(rows) == PLATFORM_FOUNDATION_FILE_COUNT)
    release_hash = metadata.get('releaseSha256')
    require(type(release_hash) is str and re.fullmatch('[a-f0-9]{64}', release_hash) is not None
            and hashlib.sha256(rows['company-release/release.json']).hexdigest() == release_hash)
    _require_platform_foundation_source(held, verifier)
    return MappingProxyType(rows), release_hash


class _PlatformFoundationSource:
    """Private temporary adapter; never fabricates a schema3 capability."""
    def __init__(self, held, verifier):
        self._held, self._verifier = held, verifier
        self._original_check = verifier.require_platform_source
        self._active = False

    @property
    def active(self):
        return self._active and self in _PLATFORM_FOUNDATION_SOURCES

    def recheck(self):
        try:
            require(self.active and self._verifier.require_platform_source is self._original_check)
            _require_platform_foundation_source(self._held, self._verifier)
        except BaseException:
            self.expire()
            raise

    def expire(self):
        self._active = False
        _PLATFORM_FOUNDATION_SOURCES.discard(self)


@contextmanager
def materialized_platform_foundation(held, parent, name, *, verifier, files, clock=time.monotonic):
    """Explicit authenticated schema4 projection with an explicit file backend.

    Keep the original verifier/source and quiet protected parent live throughout.
    No existing output is adopted, no archive is copied, and no child is run.
    The supplied backend's native effects and observable release are a separate
    trusted-company obligation; this API installs no default native backend.
    """
    rows, release_hash = capture_platform_foundation(held, verifier=verifier)
    require(files is not None)
    source = _PlatformFoundationSource(held, verifier)
    source._active = True; _PLATFORM_FOUNDATION_SOURCES.add(source)
    tree = None
    try:
        source.recheck()
        tree = MaterializedDeployment(source, parent, name, rows, release_hash, files, clock)
        tree.build(); tree.recheck(); yield tree
    finally:
        try:
            if tree is not None:
                try:
                    if tree._ready: tree.recheck()
                    else: source.recheck()
                finally: tree.close()
        finally: source.expire()
