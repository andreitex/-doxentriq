"""Fresh immutable company source bytes, with no native backend or activation.

The original trusted direct worker supplies exact independently trusted V/B/P/M
modules and a live issued source, parent and SeedStorage. Module-row hashes bind
actions, not the executing code's origin. The assembled captured loader, native
FD/disk/memory reservation, service absence and full installer remain separate
prerequisites. Never execute this tree or adopt partial state through this API.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat
import time

FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
          'st_size','st_mtime_ns','st_ctime_ns')
MODULE_PATH = 'scripts/company_source_tree.py'
STORE_MODULE_PATH = 'scripts/company_platform_store.py'
STAGE = 'company-source-materialize'
SCOPE = 'FRESH_IMMUTABLE_COMPANY_SOURCE_BYTES_ONLY'
MAX_FILES, MAX_DIRS = 2048, 512
MAX_FILE_BYTES, MAX_TOTAL_BYTES = 8*1024**2, 64*1024**2
RECORD_MAX, CHUNK, MAX_HELD = 65536, 65536, 2700
UNRELEASED = []


class SourceTreeUnavailable(ValueError):
    pass


def require(value, code='company_source_unavailable'):
    if not value:
        raise SourceTreeUnavailable(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'


def identity(value, count=9):
    require(type(value) is dict and set(value)==set(FIELDS)
            and all(type(value[name]) is int and value[name]>=0 for name in FIELDS))
    return tuple(value[name] for name in FIELDS[:count])


def relative(value):
    require(type(value) is str and 0<len(value)<=256 and value.isascii())
    parts=value.split('/')
    require(len(parts)<=16 and all(re.fullmatch('[A-Za-z0-9_.-]+',p)
            and p not in ('.','..') and not p.endswith('.') for p in parts))
    return value


def absolute(value):
    require(type(value) is str and len(value)<=2048 and value.startswith('/') and value.isascii()
            and str(PurePosixPath(value))==value and '\\' not in value and '//' not in value)
    require(len(PurePosixPath(value).parts)<=32
            and all(re.fullmatch('[A-Za-z0-9_.-]+',p) and p not in ('.','..')
                    for p in PurePosixPath(value).parts[1:]))
    return value


def live_source(V, held):
    validator=getattr(V,'require_platform_source',None)
    require(callable(validator) and validator(held) is held,'company_source_live_source')


def source_plan(files, modes, header):
    """Independent finite map/rows/Git-tree check; no IO, Git or extraction."""
    require(type(files) is dict and type(modes) is dict and 0<len(files)<=MAX_FILES
            and set(files)==set(modes),'company_source_file_policy')
    directories=set(); rows=[]; total=0; trie={}
    for name in sorted(files):
        relative(name); raw=files[name]; mode=modes[name]
        require(type(raw) is bytes and len(raw)<=MAX_FILE_BYTES
                and type(mode) is str and mode in ('100644','100755'),'company_source_file_policy')
        total+=len(raw); require(total<=MAX_TOTAL_BYTES,'company_source_total_policy')
        parts=name.split('/'); directories.update('/'.join(parts[:n]) for n in range(1,len(parts)))
        current=trie
        for part in parts[:-1]:
            current=current.setdefault(part,{})
            require(type(current) is dict,'company_source_path_conflict')
        require(parts[-1] not in current,'company_source_path_conflict')
        oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).digest()
        current[parts[-1]]=(mode,oid)
        rows.append(dict(path=name,bytes=len(raw),sha256=digest(raw),gitMode=mode))
    require(len(directories)<=MAX_DIRS and len({p.lower() for p in files})==len(files)
            and len({p.lower() for p in directories})==len(directories)
            and not {p.lower() for p in files}.intersection(p.lower() for p in directories),
            'company_source_directory_policy')
    def tree(current):
        entries=[]
        for name,value in current.items():
            directory=type(value) is dict
            mode,oid=('40000',tree(value)) if directory else value
            entries.append((name.encode()+ (b'/' if directory else b''),
                            mode.encode()+b' '+name.encode()+b'\0'+oid))
        raw=b''.join(row for _,row in sorted(entries))
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
    source_tree=tree(trie).hex()
    require(type(header) is dict and type(header.get('fileCount')) is int
            and type(header.get('totalBytes')) is int
            and header['fileCount']==len(files) and header['totalBytes']==total
            and header['files']==rows and header['sourceTree']==source_tree,'company_source_signed_rows_or_tree')
    return dict(files=files,modes=modes,directories=sorted(directories,key=lambda p:(p.count('/'),p)),
                rows=rows,sourceTree=source_tree,totalBytes=total,mapSha256=digest(canonical(rows)))


def expected_store(M, held, V, B, storage, store_operation_id, shared):
    """Version1 closed Store bytes/result, independently matched to P's outcome.

    Closure flags in a journal are not authority. The original parent must have
    independently confirmed this canonical public result after actual known
    owned and outer closures; P's held record binds that assertion.
    """
    request,sha,action,records=M.authenticated_store_request(held,verifier_module=V,
        bootstrap_module=B,storage=storage,operation_id=store_operation_id,
        installation_request_sha256=shared)
    require(type(request) is dict and set(request)=={'schemaVersion','scope','installationId','dataDir',
        'installRoot','storeParent','operationId','releaseSha256','platformManifestSha256','sourceTree',
        'archiveSha256','archiveBytes','signingKeyFingerprint','storageBindingSha256','installationRequestSha256'}
        and type(request['schemaVersion']) is int and request['schemaVersion']==1
        and request['scope']=='FRESH_COMPANY_PLATFORM_ARTIFACT_STORE_ONLY'
        and request['installationRequestSha256']==shared and digest(canonical(request))==sha)
    require(set(records)=={*M.CONFIGS,*M.PROVENANCE,M.ARCHIVE} and len(records)==10)
    require(action==digest(b'company-platform-store-v1:'+sha.encode()+b':'
            +digest(held.files[STORE_MODULE_PATH]).encode())
            and request['installationId']==storage.installation_id
            and request['dataDir']==storage.data and request['installRoot']==storage.root,
            'company_source_store_request')
    root=absolute(request['storeParent'])+'/'+request['releaseSha256']
    intent=dict(schemaVersion=1,scope=request['scope'],request=request,requestSha256=sha,
        actionSha256=action,files={name:dict(bytes=len(raw),sha256=digest(raw)) for name,raw in records.items()})
    verified=dict(schemaVersion=1,scope=request['scope'],requestSha256=sha,actionSha256=action,
        installationId=storage.installation_id,releaseSha256=request['releaseSha256'],
        archiveSha256=request['archiveSha256'],platformManifestSha256=request['platformManifestSha256'],
        signingKeyFingerprint=request['signingKeyFingerprint'],exactCapturedBytesRetained=True,
        installationActivated=False,nativeQualified=False,fullInstallDenied=True)
    outcome=dict(verified,root=root,ownedStoreHandlesReleased=True,
        outerSourceParentStorageContextsRequireClosure=True,executionAuthorized=False)
    originals={**records,'intent.json':canonical(intent),'verified.json':canonical(verified)}
    require(all(type(raw) is bytes for raw in originals.values())
            and all(len(originals[n])<=RECORD_MAX for n in ('intent.json','verified.json')))
    return dict(request=request,requestSha256=sha,actionSha256=action,root=root,
                originals=originals,outcome=outcome,outcomeSha256=digest(canonical(outcome)))


def authenticated_source_request(held, *, verifier_module, bootstrap_module, store_module,
                                 storage, operation_id, store_operation_id,
                                 installation_request_sha256):
    """Effect-free planner; it does not need a current P or create stage intent."""
    require(type(installation_request_sha256) is str
            and re.fullmatch('[a-f0-9]{64}',installation_request_sha256),'company_source_shared_request')
    require(all(type(value) is str and re.fullmatch('[a-f0-9]{32}',value)
                for value in (operation_id,store_operation_id)),'company_source_operation')
    V,B,M=verifier_module,bootstrap_module,store_module
    live_source(V,held)
    require(type(storage) is getattr(B,'SeedStorage',None) and storage.active and storage.fresh is True,
            'company_source_storage')
    storage.check(); files=dict(held.files); modes=dict(held.git_modes); metadata=dict(held.metadata)
    configs=dict(held.configs); header=V.platform_manifest_header(configs['platform-sources.json'])
    plan=source_plan(files,modes,header)
    require(header['sourceTree']==metadata['sourceTree'] and header['sourceRevision']==metadata['sourceRevision']
            and header['fileCount']==metadata['fileCount'] and header['totalBytes']==metadata['totalBytes']
            and digest(configs['platform-sources.json'])==metadata['platformManifestSha256'])
    # Independent fixed host/template catalogs, never caller-selected paths.
    for validator,name,catalog in ((V.source_manifest,'company-sources.json',V.COMPANY_SOURCES),
                                  (V.deployment_manifest,'company-deployment.json',V.COMPANY_DEPLOYMENT)):
        declared=validator(configs[name])
        require(tuple(row['path'] for row in declared['files'])==tuple(catalog))
        for row in declared['files']:
            raw=files[row['path']]
            require(row['bytes']==len(raw) and row['sha256']==digest(raw))
    require(MODULE_PATH in files and STORE_MODULE_PATH in files and len(files[MODULE_PATH])>0
            and len(files[STORE_MODULE_PATH])>0,'company_source_module_row')
    prior=expected_store(M,held,V,B,storage,store_operation_id,installation_request_sha256)
    source_parent=absolute(storage.data)+'/company/source-releases'
    request=dict(schemaVersion=1,scope=SCOPE,mode='fresh-never-activated',
        installationId=storage.installation_id,operationId=operation_id,dataDir=storage.data,
        installRoot=storage.root,sourceParent=source_parent,artifactRoot=prior['root'],
        installationRequestSha256=installation_request_sha256,storeOperationId=store_operation_id,
        storeRequestSha256=prior['requestSha256'],storeActionSha256=prior['actionSha256'],
        storeOutcomeSha256=prior['outcomeSha256'],storeModuleSha256=digest(files[STORE_MODULE_PATH]),
        releaseSha256=metadata['releaseSha256'],platformManifestSha256=metadata['platformManifestSha256'],
        sourceRevision=metadata['sourceRevision'],sourceTree=plan['sourceTree'],
        archiveSha256=metadata['archiveSha256'],archiveBytes=metadata['archiveBytes'],
        signingKeyFingerprint=metadata['signingKeyFingerprint'],sourceMapSha256=plan['mapSha256'],
        fileCount=len(files),directoryCount=len(plan['directories']),totalBytes=plan['totalBytes'],
        storageBindingSha256=storage.binding_sha256)
    sha=digest(canonical(request))
    action=digest(b'company-source-materialize-v1:'+sha.encode()+b':'+digest(files[MODULE_PATH]).encode())
    live_source(V,held); storage.check()
    return request,sha,action,plan,prior


class SourceFiles:
    """Finite owned full-nine IO; explicit trusted SeedBackend + pread/chmod.

    pread(fd,count,offset) returns at most count bytes without changing position.
    Existing SeedFiles/StoreFiles caps are untouched.2700 is a policy ceiling,
    NOT native FD reservation.600s is a logical check deadline, not a universal
    kernel IO bound; current storage checks may perform23 native queries each.
    """
    def __init__(self,module,backend,*,clock=None):
        require(type(backend) is getattr(module,'SeedBackend',None) and not UNRELEASED)
        require(all(callable(getattr(backend,name,None)) for name in
            ('open','lstat','fstat','inheritable','pread','names','mkdir','create','write','sync','chmod','close')),
            'company_source_backend')
        self.backend=backend; self.clock=clock or time.monotonic
        self.deadline=self.clock()+600; self.active=True; self.owned=[]; self.rows={}

    def tick(self):
        require(self.active and not UNRELEASED and self.clock()<=self.deadline,'company_source_deadline_or_unknown')

    def own(self,fd):
        require(type(fd) is int and fd>=0 and fd not in self.owned)
        self.owned.append(fd)
        require(self.backend.inheritable(fd) is False)
        return fd

    def hold(self,path,*,directory=True,mode=None,raw=None):
        self.tick(); path=absolute(path)
        if path in self.rows:
            self.check_one(path,readback=raw is not None)
            require(raw is None or self.rows[path]['raw']==raw)
            return path
        require(len(self.rows)<MAX_HELD,'company_source_descriptor_policy')
        before=self.backend.lstat(path); identity(before)
        fd=self.own(self.backend.open(path,'directory' if directory else 'file'))
        require(identity(before)==identity(self.backend.fstat(fd))==identity(self.backend.lstat(path)))
        require(before['st_uid']==before['st_gid']==0
            and stat.S_IFMT(before['st_mode'])==(stat.S_IFDIR if directory else stat.S_IFREG)
            and stat.S_IMODE(before['st_mode'])&0o022==0
            and (mode is None or stat.S_IMODE(before['st_mode'])==mode)
            and (directory or before['st_nlink']==1 and type(raw) is bytes and before['st_size']==len(raw)))
        self.rows[path]=dict(fd=fd,before=dict(before),directory=directory,raw=raw,names=None)
        self.check_one(path,readback=not directory); return path

    def check_one(self,path,*,readback=False):
        self.tick(); row=self.rows[path]
        before=self.backend.lstat(path); opened=self.backend.fstat(row['fd'])
        require(self.backend.inheritable(row['fd']) is False
            and identity(before)==identity(opened)==identity(row['before']),'company_source_held_identity')
        if readback and row['raw'] is not None:
            raw=row['raw']; offset=0
            while offset<len(raw):
                self.tick(); count=min(CHUNK,len(raw)-offset)
                chunk=self.backend.pread(row['fd'],count,offset)
                require(type(chunk) is bytes and len(chunk)==count and chunk==raw[offset:offset+count],
                        'company_source_held_bytes')
                offset+=count
            tail=self.backend.pread(row['fd'],1,len(raw))
            require(type(tail) is bytes and tail==b'','company_source_held_bytes')
        if row['names'] is not None:
            require(self._names(row['fd'],len(row['names']))==row['names'],'company_source_inventory')
        require(identity(self.backend.lstat(path))==identity(before)
                and identity(self.backend.fstat(row['fd']))==identity(opened),'company_source_held_identity')

    def check(self,*,readback=False):
        try:
            for path in tuple(self.rows): self.check_one(path,readback=readback)
        except BaseException: self.active=False; raise

    def _names(self,fd,maximum):
        names=self.backend.names(fd,maximum)
        require(type(names) is list and len(names)<=maximum and len(names)==len(set(names))
            and all(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+',name)
                    and name not in ('.','..') for name in names),'company_source_inventory')
        return sorted(names)

    def inventory(self,path,expected):
        self.check_one(path); row=self.rows[path]
        require(row['directory'] and type(expected) is list and expected==sorted(set(expected)))
        require(self._names(row['fd'],len(expected))==expected,'company_source_inventory')
        self.check_one(path); row['names']=list(expected)

    def create(self,parent,name,raw=None):
        try: return self._create(parent,name,raw)
        except BaseException: self.active=False; raise

    def _create(self,parent,name,raw=None):
        self.check(); relative(name); require('/' not in name and len(self.rows)<MAX_HELD)
        row=self.rows[parent]; require(row['directory'] and stat.S_IMODE(row['before']['st_mode'])==0o700)
        before=dict(row['before']); previous=self._names(row['fd'],MAX_FILES+MAX_DIRS+3)
        require(name not in previous)
        require(raw is None or type(raw) is bytes and len(raw)<=MAX_FILE_BYTES)
        fd=self.own(self.backend.mkdir(row['fd'],name,0,0,0o700) if raw is None
                    else self.backend.create(row['fd'],name,0,0,0o400))
        path=parent+'/'+name
        if raw is not None:
            offset=0
            while offset<len(raw):
                self.tick(); part=raw[offset:offset+CHUNK]; amount=self.backend.write(fd,part)
                require(type(amount) is int and 0<amount<=len(part),'company_source_write_unknown')
                offset+=amount
        require(self.backend.sync(fd) is None and self.backend.sync(row['fd']) is None,'company_source_sync_unknown')
        current=self.backend.lstat(parent); opened=self.backend.fstat(row['fd'])
        require(identity(current)==identity(opened) and identity(current,5)==identity(before,5)
                and current['st_nlink']==before['st_nlink']+(1 if raw is None else 0),
                'company_source_parent_transition')
        names=self._names(row['fd'],MAX_FILES+MAX_DIRS+3)
        require(names==sorted(previous+[name]),'company_source_parent_transition')
        require(identity(self.backend.lstat(parent))==identity(current)
                and identity(self.backend.fstat(row['fd']))==identity(opened))
        # Exactly the owned create changes one parent; no ancestor/control rebase.
        row['before']=dict(current); row['names']=names
        info=self.backend.lstat(path)
        require(identity(info)==identity(self.backend.fstat(fd)) and info['st_uid']==info['st_gid']==0
            and info['st_dev']==before['st_dev']
            and stat.S_IFMT(info['st_mode'])==(stat.S_IFDIR if raw is None else stat.S_IFREG)
            and stat.S_IMODE(info['st_mode'])==(0o700 if raw is None else 0o400)
            and (raw is None or info['st_nlink']==1 and info['st_size']==len(raw)))
        self.rows[path]=dict(fd=fd,before=dict(info),directory=raw is None,raw=raw,
                            names=[] if raw is None else None)
        self.check_one(path,readback=True); self.check(); return path

    def seal_directory(self,path):
        try: self._seal_directory(path)
        except BaseException: self.active=False; raise

    def _seal_directory(self,path):
        self.check(); row=self.rows[path]; before=dict(row['before'])
        require(row['directory'] and stat.S_IMODE(before['st_mode'])==0o700)
        require(self.backend.chmod(row['fd'],0o500) is None,'company_source_chmod_unknown')
        current=self.backend.lstat(path); opened=self.backend.fstat(row['fd'])
        require(identity(current)==identity(opened) and stat.S_IMODE(current['st_mode'])==0o500
            and all(current[name]==before[name] for name in FIELDS if name not in ('st_mode','st_ctime_ns')),
            'company_source_mode_transition')
        row['before']=dict(current)
        require(self.backend.sync(row['fd']) is None,'company_source_sync_unknown')
        self.check()

    def close(self):
        self.active=False; failures=[]
        for fd in reversed(self.owned):
            try: require(self.backend.close(fd) is None,'company_source_close_unknown')
            except BaseException: failures.append((self.backend,fd))
        self.owned=[]; UNRELEASED.extend(failures)
        require(not failures and not UNRELEASED,'company_source_close_unknown')


def prior_store(parent,P,prior,shared):
    parent.check()
    require(parent.arguments.request==shared,'company_source_parent_request')
    base=parent.session_path+'/company-platform-store'
    require(base+'.intent' in parent.files and base+'.confirmed' in parent.files,
            'company_source_prior_store')
    intent=P.record(parent.files[base+'.intent'][2],'install-stage-v1',('session','stage','action','closed'))
    confirmed=P.record(parent.files[base+'.confirmed'][2],'install-stage-confirmed-v1',
                       ('session','stage','action','outcome','independently_confirmed'))
    require(intent==dict(session=parent.arguments.session,stage='company-platform-store',
        action=prior['actionSha256'],closed='true')
        and confirmed==dict(session=parent.arguments.session,stage='company-platform-store',
            action=prior['actionSha256'],outcome=prior['outcomeSha256'],independently_confirmed='true'),
        'company_source_prior_store')
    parent.check()


def materialize_authenticated_company_source(held, *, verifier_module, bootstrap_module,
        store_module, parent_module, parent, storage, backend_module, backend,
        operation_id, store_operation_id, installation_request_sha256, clock=None):
    """Fresh output only; source parent must be independently precreated empty.

    Original parent confirms only after known own AND outer V/P/storage closure.
    Child mkdir precedes durable intent; intent precedes all source payload.
    Partials/orphans/unknown closes are preserved, never adopted, retried/deleted.
    Source write ceiling64MiB+two64KiB journals excludes directory/allocation
    overhead. Native disk/FD/cgroup/time reservation is mandatory but absent;
    this finite injected API makes no native fit or trusted-loader/reboot claim.
    """
    V,B,M,P=verifier_module,bootstrap_module,store_module,parent_module
    require(type(storage) is getattr(B,'SeedStorage',None) and storage.files.backend is backend,
            'company_source_storage')
    io=SourceFiles(backend_module,backend,clock=clock)
    try:
        request,sha,action,plan,prior=authenticated_source_request(held,verifier_module=V,
            bootstrap_module=B,store_module=M,storage=storage,operation_id=operation_id,
            store_operation_id=store_operation_id,installation_request_sha256=installation_request_sha256)
        require(type(parent) is getattr(P,'HeldParent',None),'company_source_parent_type')
        def bound():
            live_source(V,held)
            require(parent.arguments.stage==STAGE and parent.arguments.request==installation_request_sha256
                    and parent.arguments.action==action,'company_source_parent_binding')
            prior_store(parent,P,prior,installation_request_sha256)
            storage.check(); io.check(); live_source(V,held)
        bound()
        for base in (request['sourceParent'],prior['request']['storeParent'],prior['root']):
            for ancestor in reversed((PurePosixPath(base),*PurePosixPath(base).parents)):
                path=str(ancestor)
                mode=(0o500 if path==prior['root'] else 0o700 if path in
                    (request['sourceParent'],prior['request']['storeParent']) else None)
                io.hold(path,mode=mode)
        device=storage.files.records[storage.data]['before']['st_dev']
        require(all(row['before']['st_dev']==device for path,row in io.rows.items()
                    if path==storage.data or path.startswith(storage.data+'/')),'company_source_device')
        io.inventory(request['sourceParent'],[])
        io.inventory(prior['request']['storeParent'],[request['releaseSha256']])
        io.inventory(prior['root'],sorted(prior['originals']))
        for name,raw in sorted(prior['originals'].items()):
            io.hold(prior['root']+'/'+name,directory=False,mode=0o400,raw=raw)
            require(io.rows[prior['root']+'/'+name]['before']['st_dev']==device,'company_source_device')
        io.check(readback=True); bound()
        bound(); root=io.create(request['sourceParent'],request['releaseSha256']); bound()
        intent=dict(schemaVersion=1,scope=SCOPE,request=request,requestSha256=sha,actionSha256=action)
        intent_raw=canonical(intent); require(len(intent_raw)<=RECORD_MAX)
        bound(); io.create(root,'intent.json',intent_raw); bound()
        bound(); source=io.create(root,'source'); bound()
        for directory in plan['directories']:
            parent_path,_,name=directory.rpartition('/')
            bound(); io.create(source+('/'+parent_path if parent_path else ''),name); bound()
        for name,raw in sorted(plan['files'].items()):
            parent_path,_,leaf=name.rpartition('/')
            bound(); io.create(source+('/'+parent_path if parent_path else ''),leaf,raw); bound()
        expected={source:[]}
        for name in (*plan['directories'],*plan['files']):
            parent_path,_,leaf=name.rpartition('/')
            expected.setdefault(source+('/'+parent_path if parent_path else ''),[]).append(leaf)
            if name in plan['directories']: expected.setdefault(source+'/'+name,[])
        for directory,names in expected.items(): io.inventory(directory,sorted(names))
        io.check(readback=True); bound()
        verified=dict(schemaVersion=1,scope=SCOPE,requestSha256=sha,actionSha256=action,
            installationId=storage.installation_id,releaseSha256=request['releaseSha256'],
            platformManifestSha256=request['platformManifestSha256'],sourceTree=plan['sourceTree'],
            sourceMapSha256=plan['mapSha256'],fileCount=request['fileCount'],directoryCount=request['directoryCount'],
            totalBytes=plan['totalBytes'],exactCapturedSourceBytes=True,physicalFilesMode='0400',
            physicalDirectoriesMode='0500',nativeQualified=False,executionAuthorized=False,
            rebootAuthenticationImplemented=False,fullInstallDenied=True)
        raw=canonical(verified); require(len(raw)<=RECORD_MAX)
        bound(); io.create(root,'bytes-verified.json',raw); bound()
        io.inventory(root,['bytes-verified.json','intent.json','source'])
        for directory in sorted(expected,key=lambda p:(-p.count('/'),p)):
            bound(); io.seal_directory(directory); bound()
        bound(); io.seal_directory(root); bound()
        io.inventory(request['sourceParent'],[request['releaseSha256']])
        require(backend.sync(io.rows[request['sourceParent']]['fd']) is None,'company_source_sync_unknown')
        io.check(readback=True); bound()
    finally:
        io.close()
    return dict(verified,root=root,sourceRoot=source,ownedSourceHandlesReleased=True,
        outerSourceParentStorageContextsRequireClosure=True,companyArtifactStoreRechecked=True)
