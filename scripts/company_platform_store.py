"""Fresh company artifact retention API; no native adapter or installer activation.

Call from the original trusted worker with live independently trusted verifier,
parent and bootstrap modules. A captured module-row hash binds the action, not
the executing module's origin: the caller must load these exact trusted bytes.
The storage capability and this API do not authorize later execution from the
customer repository. Native caller/FS/descriptor-capacity admission is pending.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat
import time

FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
CONFIGS = ('approved-mirrors.json', 'images.lock.json', 'runtime-manifest.json',
           'company-sources.json', 'company-deployment.json', 'platform-sources.json')
PROVENANCE = ('release.json', 'release.sig', 'company-signing-public-key.pem')
ARCHIVE = 'platform-sources.tar.gz'
MODULE_PATH = 'scripts/company_platform_store.py'
ARCHIVE_MAX = 32 * 1024 ** 2
TOTAL_MAX = 39 * 1024 ** 2
RECORD_MAX = 65536
UNRELEASED = []


class StoreUnavailable(ValueError):
    pass


def require(value, code='company_store_unavailable'):
    if not value:
        raise StoreUnavailable(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'


def absolute(value):
    require(type(value) is str and len(value) <= 2048 and value.startswith('/') and value.isascii()
            and '\\' not in value and '\0' not in value and '//' not in value)
    parts=PurePosixPath(value).parts
    require(len(parts) <= 32 and str(PurePosixPath(value)) == value and all(p not in ('.', '..') for p in parts)
            and all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) for p in parts[1:]))
    return value


def identity(value, count=9):
    require(type(value) is dict and set(value) == set(FIELDS)
            and all(type(value[name]) is int and value[name] >= 0 for name in FIELDS))
    return tuple(value[name] for name in FIELDS[:count])


def live_source(V, held):
    validator=getattr(V, 'require_platform_source', None)
    require(callable(validator) and validator(held) is held, 'company_store_live_source')
    return held


def captured_inputs(V, held):
    """Only issued captured bytes; no path reads, recompression or extraction."""
    live_source(V, held); metadata=dict(held.metadata)
    configs=dict(held.configs); provenance=dict(held.provenance); archive=held.archive_bytes
    require(set(configs) == set(CONFIGS) and set(provenance) == set(PROVENANCE))
    records={**configs, **provenance, ARCHIVE:archive}
    require(all(type(value) is bytes and 0 < len(value) for value in records.values()))
    require(len(archive) <= ARCHIVE_MAX and type(metadata['archiveBytes']) is int
            and metadata['archiveBytes'] == len(archive) and digest(archive) == metadata['archiveSha256'])
    require(all(len(configs[name]) <= 1024 ** 2 for name in CONFIGS)
            and len(provenance['release.json']) <= 16384 and len(provenance['release.sig']) <= 16384
            and len(provenance['company-signing-public-key.pem']) <= 4096
            and sum(map(len, records.values())) <= TOTAL_MAX)
    for name in ('releaseSha256', 'platformManifestSha256', 'archiveSha256', 'signingKeyFingerprint'):
        require(type(metadata.get(name)) is str and re.fullmatch('[a-f0-9]{64}', metadata[name]))
    require(type(metadata.get('sourceTree')) is str and re.fullmatch('[a-f0-9]{40}',metadata['sourceTree']))
    require(digest(provenance['release.json']) == metadata['releaseSha256']
            and digest(configs['platform-sources.json']) == metadata['platformManifestSha256'])
    # Cryptographic key verification belongs to the issued capability; retain its
    # verified fingerprint alongside the exact original PEM rather than infer it
    # by hashing PEM encoding. Never import candidate signing or archive helpers.
    release=dict(metadata['release']); signed=dict(release['files'])
    require(set(signed) == {*CONFIGS, ARCHIVE})
    for name in (*CONFIGS, ARCHIVE):
        row=dict(signed[name]); raw=records[name]
        require(set(row) == {'bytes','sha256'} and type(row['bytes']) is int
                and row['bytes'] == len(raw) and row['sha256'] == digest(raw))
    live_source(V, held)
    return records, metadata


class StoreFiles:
    """Separate finite IO budget, extending the trusted SeedBackend with chmod.

    The backend must provide nofollow/openat/CLOEXEC/exclusive durable bounded
    operations; exclusive create returns an owned read/write FD even though the
    new pathname has mode0400. No native implementation is supplied. This owns only its own
    FDs, never the outer source, parent or SeedStorage handles. Kernel IO and
    actual descriptor capacity require a separately qualified native adapter.
    """
    def __init__(self, module, backend, *, clock=None):
        require(type(backend) is getattr(module,'SeedBackend',None) and not UNRELEASED)
        require(all(callable(getattr(backend,name,None)) for name in
            ('open','lstat','fstat','inheritable','read','names','mkdir','create','write','sync','chmod','close')))
        self.backend=backend; self.clock=clock or time.monotonic
        self.deadline=self.clock()+600; self.active=True; self.owned=[]; self.rows={}

    def tick(self):
        require(self.active and not UNRELEASED and self.clock() <= self.deadline,'company_store_deadline_or_unknown')

    def own(self, fd):
        require(type(fd) is int and fd >= 0 and fd not in self.owned)
        self.owned.append(fd)
        require(self.backend.inheritable(fd) is False)
        return fd

    def hold(self, path, *, mode=None, directory=True):
        self.tick(); path=absolute(path)
        if path in self.rows:
            self.check_one(path); return path
        require(len(self.rows) < 128,'company_store_descriptor_policy')
        before=self.backend.lstat(path); identity(before)
        fd=self.own(self.backend.open(path,'directory' if directory else 'file'))
        require(identity(self.backend.fstat(fd)) == identity(before)
                == identity(self.backend.lstat(path)))
        require(before['st_uid'] == before['st_gid'] == 0
            and stat.S_IFMT(before['st_mode']) == (stat.S_IFDIR if directory else stat.S_IFREG)
            and stat.S_IMODE(before['st_mode']) & 0o022 == 0
            and (mode is None or stat.S_IMODE(before['st_mode']) == mode)
            and (directory or before['st_nlink'] == 1))
        self.rows[path]=dict(fd=fd, before=dict(before), directory=directory, raw=None)
        self.check_one(path); return path

    def check_one(self, path, *, readback=False):
        self.tick(); row=self.rows[path]; a=self.backend.lstat(path); b=self.backend.fstat(row['fd'])
        require(identity(a) == identity(b) == identity(row['before']),'company_store_held_identity')
        if readback and row['raw'] is not None:
            require(self.backend.read(row['fd'],len(row['raw'])) == row['raw'],'company_store_held_bytes')
            require(identity(self.backend.lstat(path)) == identity(a)
                    and identity(self.backend.fstat(row['fd'])) == identity(b))

    def check(self, *, readback=False):
        try:
            for path in tuple(self.rows): self.check_one(path,readback=readback)
        except BaseException: self.active=False; raise

    def names(self, path, maximum):
        self.check_one(path); names=self.backend.names(self.rows[path]['fd'],maximum)
        require(type(names) is list and len(names) <= maximum and len(names) == len(set(names))
            and all(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+',name)
                    and name not in ('.','..') for name in names),'company_store_inventory')
        self.check_one(path); return sorted(names)

    def create(self, parent, name, raw=None):
        self.check(); require(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+',name)
            and name not in ('.','..'))
        require(raw is None or type(raw) is bytes and 0 < len(raw) <= ARCHIVE_MAX)
        row=self.rows[parent]; before=dict(row['before']); previous=self.names(parent,12)
        require(name not in previous and len(self.rows) < 128)
        fd=self.own(self.backend.mkdir(row['fd'],name,0,0,0o700) if raw is None
            else self.backend.create(row['fd'],name,0,0,0o400))
        path=parent+'/'+name
        if raw is not None:
            offset=0
            while offset < len(raw):
                self.tick(); part=raw[offset:offset+65536]; amount=self.backend.write(fd,part)
                require(type(amount) is int and 0 < amount <= len(part),'company_store_write_unknown')
                offset+=amount
        require(self.backend.sync(fd) is None and self.backend.sync(row['fd']) is None,'company_store_sync_unknown')
        current=self.backend.lstat(parent); opened=self.backend.fstat(row['fd'])
        require(identity(current) == identity(opened) and identity(current,5) == identity(before,5))
        names=self.backend.names(row['fd'],12)
        require(type(names) is list and len(names) == len(set(names))
            and sorted(names) == sorted(previous+[name]),'company_store_parent_transition')
        require(identity(self.backend.lstat(parent)) == identity(current)
            and identity(self.backend.fstat(row['fd'])) == identity(opened))
        # Exactly this owned create explains the one parent's contents change.
        # No other control/source/ancestor is refreshed.
        row['before']=dict(current)
        info=self.backend.lstat(path)
        require(identity(info) == identity(self.backend.fstat(fd)) and info['st_uid'] == info['st_gid'] == 0
            and stat.S_IFMT(info['st_mode']) == (stat.S_IFDIR if raw is None else stat.S_IFREG)
            and stat.S_IMODE(info['st_mode']) == (0o700 if raw is None else 0o400)
            and (raw is None or info['st_nlink'] == 1 and info['st_size'] == len(raw)))
        self.rows[path]=dict(fd=fd,before=dict(info),directory=raw is None,raw=raw)
        self.check(readback=True); return path

    def finalize_directory(self, path):
        self.check(readback=True); row=self.rows[path]; before=dict(row['before'])
        require(row['directory'] and stat.S_IMODE(before['st_mode']) == 0o700)
        require(self.backend.chmod(row['fd'],0o500) is None,'company_store_chmod_unknown')
        current=self.backend.lstat(path); opened=self.backend.fstat(row['fd'])
        require(identity(current) == identity(opened) and stat.S_IMODE(current['st_mode']) == 0o500
            and all(current[name] == before[name] for name in FIELDS if name not in ('st_mode','st_ctime_ns')),
            'company_store_mode_transition')
        row['before']=dict(current)
        require(self.backend.sync(row['fd']) is None,'company_store_sync_unknown')
        self.check(readback=True)

    def close(self):
        self.active=False; failures=[]
        for fd in reversed(self.owned):
            try: require(self.backend.close(fd) is None,'company_store_close_unknown')
            except BaseException: failures.append((self.backend,fd))
        self.owned=[]; UNRELEASED.extend(failures)
        require(not failures and not UNRELEASED,'company_store_close_unknown')


def authenticated_store_request(held, *, verifier_module, bootstrap_module, storage, operation_id,
                                installation_request_sha256=None):
    require(installation_request_sha256 is None or type(installation_request_sha256) is str
            and re.fullmatch('[a-f0-9]{64}',installation_request_sha256),'company_store_installation_request')
    live_source(verifier_module,held)
    require(type(storage) is getattr(bootstrap_module,'SeedStorage',None) and storage.active
            and storage.fresh is True and type(operation_id) is str
            and re.fullmatch('[a-f0-9]{32}',operation_id),'company_store_storage')
    storage.check(); records,metadata=captured_inputs(verifier_module,held)
    require(MODULE_PATH in held.files and type(held.files[MODULE_PATH]) is bytes
            and 0 < len(held.files[MODULE_PATH]) <= 1024 ** 2)
    parent=absolute(storage.data)+'/company/platform-releases'
    request=dict(schemaVersion=1,scope='FRESH_COMPANY_PLATFORM_ARTIFACT_STORE_ONLY',
        installationId=storage.installation_id,dataDir=storage.data,installRoot=storage.root,
        storeParent=parent,operationId=operation_id,releaseSha256=metadata['releaseSha256'],
        platformManifestSha256=metadata['platformManifestSha256'],sourceTree=metadata['sourceTree'],
        archiveSha256=metadata['archiveSha256'],archiveBytes=metadata['archiveBytes'],
        signingKeyFingerprint=metadata['signingKeyFingerprint'],storageBindingSha256=storage.binding_sha256)
    if installation_request_sha256 is not None:
        request['installationRequestSha256']=installation_request_sha256
    request_sha=digest(canonical(request))
    action=digest(b'company-platform-store-v1:'+request_sha.encode()+b':'+digest(held.files[MODULE_PATH]).encode())
    live_source(verifier_module,held); storage.check()
    return request,request_sha,action,records


def store_authenticated_platform(held, *, verifier_module, bootstrap_module, parent_module,
                                 parent, storage, backend_module, backend, operation_id, clock=None,
                                 installation_request_sha256=None):
    """Exclusive first artifact only; orphan/existing releases never adopted.

    Precreate the empty root-owned0700 company/platform-releases parent in a
    separately reviewed stage before holding source/storage contexts. Call in
    the original direct worker, never a nested subprocess with copied evidence.
    Return only after known owned IO closes; the original parent must still wait
    for known outer source/parent/storage closures before acknowledging its stage.
    The exclusive child mkdir precedes the intent; a durable intent precedes all
    artifact/terminal bytes. Even an orphan empty child prevents automatic retry.
    Native admission must reserve disk and FD capacity before that mkdir; raw
    created file bytes are at most39MiB plus two64KiB records, excluding filesystem
    allocation overhead. An existing volume's capacity is not that reservation.
    This source API has no native adapter, caller activation or execution grant.
    An explicit installation request binds the original shared parent session;
    the per-stage action still binds this complete request and captured module.
    None preserves the historical standalone request and parent binding.
    """
    require(type(storage) is getattr(bootstrap_module,'SeedStorage',None)
            and storage.files.backend is backend,'company_store_storage')
    files=StoreFiles(backend_module,backend,clock=clock)
    try:
        request,request_sha,action,records=authenticated_store_request(held,verifier_module=verifier_module,
            bootstrap_module=bootstrap_module,storage=storage,operation_id=operation_id,
            installation_request_sha256=installation_request_sha256)
        def bound():
            live_source(verifier_module,held)
            require(type(parent) is getattr(parent_module,'HeldParent',None)
                and parent.arguments.stage == 'company-platform-store'
                and parent.arguments.request == (installation_request_sha256 if installation_request_sha256 is not None else request_sha)
                and parent.arguments.action == action,
                'company_store_parent_binding')
            parent.check(); storage.check(); files.check(); live_source(verifier_module,held)
        base=request['storeParent']
        for ancestor in reversed((PurePosixPath(base),*PurePosixPath(base).parents)):
            files.hold(str(ancestor),mode=0o700 if str(ancestor) == base else None)
        require(files.rows[base]['before']['st_dev'] == storage.files.records[storage.data]['before']['st_dev'])
        bound(); require(files.names(base,0) == [],'company_store_not_fresh')
        root=files.create(base,request['releaseSha256']); bound()
        pins={name:dict(bytes=len(raw),sha256=digest(raw)) for name,raw in records.items()}
        intent=dict(schemaVersion=1,scope=request['scope'],request=request,requestSha256=request_sha,
            actionSha256=action,files=pins)
        intent_raw=canonical(intent); require(len(intent_raw) <= RECORD_MAX,'company_store_record_limit')
        files.create(root,'intent.json',intent_raw); bound()
        for name in sorted(records):
            bound(); files.create(root,name,records[name]); bound()
        require(files.names(root,11) == sorted(['intent.json',*records]))
        files.check(readback=True); bound()
        verified=dict(schemaVersion=1,scope=request['scope'],requestSha256=request_sha,
            actionSha256=action,installationId=storage.installation_id,
            releaseSha256=request['releaseSha256'],archiveSha256=request['archiveSha256'],
            platformManifestSha256=request['platformManifestSha256'],signingKeyFingerprint=request['signingKeyFingerprint'],
            exactCapturedBytesRetained=True,installationActivated=False,nativeQualified=False,
            fullInstallDenied=True)
        verified_raw=canonical(verified); require(len(verified_raw) <= RECORD_MAX,'company_store_record_limit')
        files.create(root,'verified.json',verified_raw); bound()
        expected=sorted(['intent.json','verified.json',*records])
        require(files.names(root,12) == expected)
        files.finalize_directory(root); bound()
        require(files.names(root,12) == expected and files.names(base,1) == [request['releaseSha256']])
        require(backend.sync(files.rows[base]['fd']) is None,'company_store_sync_unknown')
        files.check(readback=True); bound()
    finally:
        files.close()
    return dict(verified,root=root,ownedStoreHandlesReleased=True,
        outerSourceParentStorageContextsRequireClosure=True,executionAuthorized=False)
