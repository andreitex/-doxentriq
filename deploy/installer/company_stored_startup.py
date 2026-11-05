"""Readonly confirmed stored-startup inputs; no installer or native default.

The separately authenticated company entry supplies its ORIGINAL FullEntry
module/object, verifier-issued source, physical guard and held installer parent.
Matching pins/records does not authenticate this executing module's initial
origin. This API preserves trusted Python identities, not hostile interpreter
isolation. Outer parent/verifier/guard/backend closures remain caller duties.
"""
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat
import time
import uuid

STAGE = 'company-stored-startup'
SCOPE = 'CONFIRMED_STORED_STARTUP_INPUTS_ONLY'
STORE_SCOPE = 'FRESH_COMPANY_PLATFORM_ARTIFACT_STORE_ONLY'
SOURCE_SCOPE = 'FRESH_IMMUTABLE_COMPANY_SOURCE_BYTES_ONLY'
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
CONFIGS = ('approved-mirrors.json','images.lock.json','runtime-manifest.json',
           'company-sources.json','company-deployment.json','platform-sources.json')
PROVENANCE = ('release.json','release.sig','company-signing-public-key.pem')
ARCHIVE = 'platform-sources.tar.gz'
M_PATH, C_PATH = 'scripts/company_platform_store.py', 'scripts/company_source_tree.py'
MAX_RECORD, MAX_HELD = 65536, 72
UNRELEASED = []
_ISSUED = set()
_OWNERS = set()


class StoredStartupUnavailable(ValueError): pass


def require(value):
    if not value: raise StoredStartupUnavailable('company-stored-startup-unavailable')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                      allow_nan=False).encode('ascii') + b'\n'


def absolute(value):
    require(type(value) is str and 1 < len(value) <= 2048 and value.isascii()
            and value.startswith('/') and str(PurePosixPath(value)) == value
            and '\\' not in value and '//' not in value)
    parts=PurePosixPath(value).parts
    require(2 <= len(parts) <= 32 and all(re.fullmatch('[A-Za-z0-9_.-]+',p)
            and p not in ('.','..') and not p.endswith('.') for p in parts[1:]))
    return value


def request_value(value):
    keys={'schemaVersion','scope','operationId','installationId','installationRequestSha256',
          'dataDir','installRoot','releaseSha256','storeOperationId','sourceOperationId',
          'storageBindingSha256','expectedDevice'}
    require(type(value) is dict and set(value)==keys and type(value['schemaVersion']) is int
            and value['schemaVersion']==1 and type(value['scope']) is str and value['scope']==SCOPE)
    for name in ('operationId','storeOperationId','sourceOperationId'):
        require(type(value[name]) is str and re.fullmatch('[a-f0-9]{32}',value[name]))
    for name in ('installationRequestSha256','releaseSha256','storageBindingSha256'):
        require(type(value[name]) is str and re.fullmatch('[a-f0-9]{64}',value[name]))
    identifier=value['installationId']
    require(type(identifier) is str and str(uuid.UUID(identifier))==identifier)
    absolute(value['dataDir']); absolute(value['installRoot'])
    require(type(value['expectedDevice']) is int and 0 <= value['expectedDevice'] < 2**64
            and len(canonical(value))<=4096)
    return dict(value)


def _expected(V,G,held,request):
    """Reconstruct current version1 journals/results without operational exec."""
    require(V.require_platform_source(held) is held)
    metadata=dict(held.metadata); files=dict(held.files); modes=dict(held.git_modes)
    configs=dict(held.configs); provenance=dict(held.provenance); archive=held.archive_bytes
    require(set(configs)==set(CONFIGS) and set(provenance)==set(PROVENANCE))
    require(metadata['releaseSha256']==request['releaseSha256']
            and sha(provenance['release.json'])==request['releaseSha256'])
    plan=G.source_plan(files,modes,configs['platform-sources.json'])
    header=plan['header']; rows=plan['rows']; records={**configs,**provenance,ARCHIVE:archive}
    require(all(type(raw) is bytes for raw in records.values())
            and sha(archive)==metadata['archiveSha256'] and len(archive)==metadata['archiveBytes']
            and all(name in files for name in (M_PATH,C_PATH)))
    data,release=request['dataDir'],request['releaseSha256']
    store_root=data+'/company/platform-releases/'+release
    source_root=data+'/company/source-releases/'+release
    store=dict(schemaVersion=1,scope=STORE_SCOPE,installationId=request['installationId'],
        dataDir=data,installRoot=request['installRoot'],storeParent=data+'/company/platform-releases',
        operationId=request['storeOperationId'],releaseSha256=release,
        platformManifestSha256=metadata['platformManifestSha256'],sourceTree=header['sourceTree'],
        archiveSha256=metadata['archiveSha256'],archiveBytes=metadata['archiveBytes'],
        signingKeyFingerprint=metadata['signingKeyFingerprint'],storageBindingSha256=request['storageBindingSha256'],
        installationRequestSha256=request['installationRequestSha256'])
    store_sha=sha(canonical(store)); store_action=sha(b'company-platform-store-v1:'+store_sha.encode()+b':'+sha(files[M_PATH]).encode())
    store_verified=dict(schemaVersion=1,scope=STORE_SCOPE,requestSha256=store_sha,actionSha256=store_action,
        installationId=request['installationId'],releaseSha256=release,archiveSha256=metadata['archiveSha256'],
        platformManifestSha256=metadata['platformManifestSha256'],signingKeyFingerprint=metadata['signingKeyFingerprint'],
        exactCapturedBytesRetained=True,installationActivated=False,nativeQualified=False,fullInstallDenied=True)
    store_outcome=dict(store_verified,root=store_root,ownedStoreHandlesReleased=True,
        outerSourceParentStorageContextsRequireClosure=True,executionAuthorized=False)
    store_outcome_sha=sha(canonical(store_outcome))
    source=dict(schemaVersion=1,scope=SOURCE_SCOPE,mode='fresh-never-activated',installationId=request['installationId'],
        operationId=request['sourceOperationId'],dataDir=data,installRoot=request['installRoot'],
        sourceParent=data+'/company/source-releases',artifactRoot=store_root,
        installationRequestSha256=request['installationRequestSha256'],storeOperationId=request['storeOperationId'],
        storeRequestSha256=store_sha,storeActionSha256=store_action,storeOutcomeSha256=store_outcome_sha,
        storeModuleSha256=sha(files[M_PATH]),releaseSha256=release,platformManifestSha256=metadata['platformManifestSha256'],
        sourceRevision=header['sourceRevision'],sourceTree=header['sourceTree'],archiveSha256=metadata['archiveSha256'],
        archiveBytes=metadata['archiveBytes'],signingKeyFingerprint=metadata['signingKeyFingerprint'],
        sourceMapSha256=sha(canonical(rows)),fileCount=len(files),directoryCount=len(plan['directories']),
        totalBytes=plan['totalBytes'],storageBindingSha256=request['storageBindingSha256'])
    source_sha=sha(canonical(source)); source_action=sha(b'company-source-materialize-v1:'+source_sha.encode()+b':'+sha(files[C_PATH]).encode())
    source_verified=dict(schemaVersion=1,scope=SOURCE_SCOPE,requestSha256=source_sha,actionSha256=source_action,
        installationId=request['installationId'],releaseSha256=release,platformManifestSha256=metadata['platformManifestSha256'],
        sourceTree=header['sourceTree'],sourceMapSha256=source['sourceMapSha256'],fileCount=source['fileCount'],
        directoryCount=source['directoryCount'],totalBytes=source['totalBytes'],exactCapturedSourceBytes=True,
        physicalFilesMode='0400',physicalDirectoriesMode='0500',nativeQualified=False,executionAuthorized=False,
        rebootAuthenticationImplemented=False,fullInstallDenied=True)
    source_outcome=dict(source_verified,root=source_root,sourceRoot=source_root+'/source',ownedSourceHandlesReleased=True,
        outerSourceParentStorageContextsRequireClosure=True,companyArtifactStoreRechecked=True)
    journals={store_root+'/intent.json':canonical(dict(schemaVersion=1,scope=STORE_SCOPE,request=store,
        requestSha256=store_sha,actionSha256=store_action,files={name:dict(bytes=len(raw),sha256=sha(raw)) for name,raw in records.items()})),
        store_root+'/verified.json':canonical(store_verified),source_root+'/intent.json':canonical(dict(schemaVersion=1,
            scope=SOURCE_SCOPE,request=source,requestSha256=source_sha,actionSha256=source_action)),
        source_root+'/bytes-verified.json':canonical(source_verified)}
    require(all(0<len(raw)<=MAX_RECORD for raw in journals.values()))
    return journals, {'company-platform-store':(store_action,store_outcome_sha),
        'company-source-materialize':(source_action,sha(canonical(source_outcome)))}, source_root+'/source'


class StoredStartup:
    """Only hold_confirmed_stored_startup issues this live readonly capability."""
    def __init__(self): self._active=False; self._owned=[]; self._rows={}; self._retained=False
    def _expire(self): self._active=False; _ISSUED.discard(self)
    def _retain(self,reason):
        if not self._retained:
            self._retained=True; UNRELEASED.append((self,reason,self._backend,self._parent,self._held))
    def _tick(self):
        now=self._clock(); require(type(now) in (int,float) and not isinstance(now,bool)
            and math.isfinite(now) and 0<=now<self._deadline)
    def _identity(self,info):
        require(type(info) is dict and set(info)==set(FIELDS)
            and all(type(info[name]) is int and info[name]>=0 for name in FIELDS))
        return tuple(info[name] for name in FIELDS)
    def _protected(self,path,info,directory):
        self._identity(info); require(info['st_uid']==info['st_gid']==0 and not stat.S_IMODE(info['st_mode'])&0o022)
        require(stat.S_ISDIR(info['st_mode']) if directory else stat.S_ISREG(info['st_mode']))
        if path==self._request['dataDir'] or path.startswith(self._request['dataDir']+'/'):
            require(info['st_dev']==self._request['expectedDevice'])
        if not directory: require(stat.S_IMODE(info['st_mode'])==0o400 and info['st_nlink']==1)
        elif path in self._inventories: require(stat.S_IMODE(info['st_mode'])==0o500)
        return info
    def _open(self,path,directory,parent,name):
        self._tick(); require(len(self._owned)<MAX_HELD and path not in self._rows)
        before=self._protected(path,self._backend.lstat(path),directory)
        fd=self._backend.open(parent,name,directory)
        if not(type(fd) is int and fd>=0 and fd not in self._owned):
            self._retain(('open-result-unknown',fd)); require(False)
        self._owned.append(fd)
        require(self._backend.inheritable(fd) is False and self._identity(before)==
            self._identity(self._protected(path,self._backend.fstat(fd),directory))==
            self._identity(self._protected(path,self._backend.lstat(path),directory)))
        self._rows[path]=(fd,dict(before),directory); return fd
    def _read(self,path,raw):
        self._tick(); fd,info,_=self._rows[path]; require(info['st_size']==len(raw))
        require(self._backend.pread(fd,len(raw),0)==raw and self._backend.pread(fd,1,len(raw))==b'')
    def _capture(self):
        for leaf in sorted(self._journals):
            parent=None; path='/'
            if path not in self._rows: self._open(path,True,None,'/')
            parent=self._rows[path][0]
            parts=PurePosixPath(leaf).parts[1:]
            for i,name in enumerate(parts):
                path=str(PurePosixPath(path)/name); directory=i<len(parts)-1
                if path not in self._rows: self._open(path,directory,parent,name)
                parent=self._rows[path][0]
        self.recheck()
    def _parent_check(self):
        P=self._modules[self._F.PARENT]; parent=self._parent
        require(type(parent) is P.HeldParent and parent.live)
        args=parent.arguments
        require(args.stage==STAGE and args.request==self._request['installationRequestSha256']
                and args.action==self._action)
        parent.check()
        for stage,(action,outcome) in self._stages.items():
            base=parent.session_path+'/'+stage
            require(base+'.intent' in parent.files and base+'.confirmed' in parent.files)
            intent=P.record(parent.files[base+'.intent'][2],'install-stage-v1',('session','stage','action','closed'))
            confirmed=P.record(parent.files[base+'.confirmed'][2],'install-stage-confirmed-v1',
                ('session','stage','action','outcome','independently_confirmed'))
            require(intent==dict(session=args.session,stage=stage,action=action,closed='true')
                and confirmed==dict(session=args.session,stage=stage,action=action,outcome=outcome,independently_confirmed='true'))
        parent.check()
    def recheck(self):
        issued=type(self) is StoredStartup and self in _ISSUED
        try:
            require(issued and self._active and not UNRELEASED); self._tick()
            self._F.FullEntry.recheck(self._entry)
            V,G=self._modules[self._F.VERIFIER],self._modules[self._F.GUARD]
            require(V.require_platform_source(self._held) is self._held)
            require(G.require_company_source_guard(self._guard,verifier_module=V,held=self._held) is self._guard)
            require(not self._modules[self._F.BACKEND].UNRELEASED_RESOURCES)
            self._parent_check()
            for path,(fd,expected,directory) in self._rows.items():
                self._tick(); require(self._backend.inheritable(fd) is False
                    and self._identity(self._protected(path,self._backend.lstat(path),directory))==self._identity(expected)
                    ==self._identity(self._protected(path,self._backend.fstat(fd),directory)))
                if path in self._journals:self._read(path,self._journals[path])
                if path in self._inventories:
                    expected_names=self._inventories[path]
                    names=self._backend.names(fd,len(expected_names)+1)
                    require(type(names) is list and sorted(names)==expected_names)
                require(self._identity(self._backend.fstat(fd))==self._identity(expected)
                    ==self._identity(self._backend.lstat(path)))
            self._parent_check(); self._F.FullEntry.recheck(self._entry)
        except BaseException:
            if issued:self._expire()
            raise
        return self
    def inspection(self):
        StoredStartup.recheck(self)
        return dict(scope=SCOPE,status='held',releaseSha256=self._request['releaseSha256'],
            installationId=self._request['installationId'],sourceRoot=self._source_root,
            requestSha256=sha(canonical(self._request)),actionSha256=self._action,
            storedJournalsSha256=sha(canonical({path:sha(raw) for path,raw in self._journals.items()})),
            priorStageOutcomesSha256=sha(canonical(self._stages)),changed=False,fullInstallDenied=True,
            runtimePairInitialized=False,backupReady=False,nativeQualified=False,
            outerContextsRequireClosure=True)
    def inspect_initialized(self,*,inputs,fresh_assembly=None):
        """Call ORIGINAL captured startup verifier with explicit trusted adapters.

        This returned observation protects only this invocation. It neither
        starts services nor initializes missing journals. Adapters are trusted
        company IO seams, never administrator/app-provided confirmation code.
        """
        try:
            StoredStartup.recheck(self)
            require(type(inputs) is dict and set(inputs)=={'host_directory','files','command','mount',
                'layout','gate_factory','allocation_factory','read_state','clock','timeout'}
                and inputs['files'] is not None and all(callable(inputs[name]) for name in
                    ('command','mount','layout','gate_factory','allocation_factory','read_state','clock'))
                and type(inputs['timeout']) in (int,float) and not isinstance(inputs['timeout'],bool)
                and math.isfinite(inputs['timeout']) and 0<inputs['timeout']<=50)
            with self.assembly(fresh_assembly=fresh_assembly) as assembly:
                result=assembly.call('scripts/startup_binding.py','verify',self._request['dataDir'],
                    self._request['installRoot'],**dict(inputs))
                require(type(result) is dict and set(result)=={'scope','status','installationId',
                    'hostSha256','configurationSha256','admissionSha256','allocationSha256',
                    'encryptedMountSha256','layoutSha256','changed','backupReady'}
                    and result['scope']=='STARTUP_BINDING_ONLY' and result['status']=='verified'
                    and result['installationId']==self._request['installationId']
                    and result['changed'] is False and result['backupReady'] is False
                    and all(type(result[name]) is str and re.fullmatch('[a-f0-9]{64}',result[name])
                        for name in ('hostSha256','configurationSha256','admissionSha256','allocationSha256',
                                     'encryptedMountSha256','layoutSha256')))
            StoredStartup.recheck(self); return dict(result)
        except BaseException:
            if type(self) is StoredStartup and self in _ISSUED:self._expire()
            raise
    @contextmanager
    def assembly(self,*,fresh_assembly=None):
        """Borrow an original issued, physically bound fresh assembly if given.

        The default retained/reboot route composes its own captured modules.
        A fresh caller keeps its assembly and the SAME source guard live until
        after this context and the surrounding stored-startup context close.
        Borrowing neither recompiles nor closes the caller's assembly, and does
        not supply filesystem, stage, runtime-pair or service-start authority.
        """
        try:
            StoredStartup.recheck(self)
            if fresh_assembly is None:
                with self._entry.compose(self._held,source_guard=self._guard) as assembly:
                    StoredStartup.recheck(self); yield assembly; StoredStartup.recheck(self)
            else:
                self._fresh_assembly(fresh_assembly)
                yield fresh_assembly
                StoredStartup.recheck(self); self._fresh_assembly(fresh_assembly)
        except BaseException:
            if type(self) is StoredStartup and self in _ISSUED:self._expire()
            raise
    def _fresh_assembly(self,value):
        # Exact original module/class before any candidate callback. Original
        # recheck verifies private issuance and its one-way bound-guard registry.
        L=self._modules[self._F.LOADER]
        require(type(value) is L.FreshInstallationAssembly
            and getattr(value,'_entry',None) is self._entry.origin
            and getattr(value,'_source',None) is self._held
            and getattr(value,'_guard',None) is self._guard)
        L.FreshInstallationAssembly.recheck(value)
        StoredStartup.recheck(self)
        return value
    def close(self):
        require(type(self) is StoredStartup and self in _OWNERS)
        _OWNERS.remove(self)
        self._expire(); errors=[]
        owned,self._owned=self._owned,[]
        for fd in reversed(owned):
            try:require(self._backend.close(fd) is None)
            except BaseException:errors.append(fd)
        if errors:self._retain(('journal-close-unknown',tuple(errors)))
        require(not errors and not UNRELEASED)


@contextmanager
def hold_confirmed_stored_startup(entry,*,full_entry_module,held,source_guard,parent,
                                 request,worker_sha256,backend,clock=None):
    """Hold exact prior independently confirmed outputs before operational exec.

    expectedDevice is a placement constraint, not encryption evidence. Initial
    company worker/package trust and live mount/storage binding are supplied by
    the original trusted entry. Public construction, journal flags or callbacks
    cannot replace the original parent confirmations. No native constructor or
    runtime-pair initialization is invoked. After this and guard unwind, caller
    must call exact backend.require_released and close all outer contexts before
    independently acknowledging an installer stage. No zero exit confirms it.
    """
    require(not UNRELEASED)
    F=full_entry_module; require(type(entry) is F.FullEntry)
    F.FullEntry.recheck(entry); modules=entry.modules; request=request_value(request)
    require(type(worker_sha256) is str and re.fullmatch('[a-f0-9]{64}',worker_sha256))
    BK=modules[F.BACKEND]; require(type(backend) is BK.ReadOnlySourceBackend)
    V,G=modules[F.VERIFIER],modules[F.GUARD]
    require(type(parent) is modules[F.PARENT].HeldParent and parent.live
            and type(held) is V.HeldPlatformSource and type(source_guard) is G.HeldCompanySource)
    require(V.require_platform_source(held) is held
        and G.require_company_source_guard(source_guard,verifier_module=V,held=held) is source_guard)
    journals,stages,source_root=_expected(V,G,held,request)
    require(source_guard.root==source_root and source_guard._backend is backend)
    value=StoredStartup(); value._F,value._entry,value._modules=F,entry,modules
    value._held,value._guard,value._parent=held,source_guard,parent
    value._backend,value._request,value._journals,value._stages=backend,request,journals,stages
    value._source_root=source_root; value._clock=clock or time.monotonic
    now=value._clock(); require(type(now) in (int,float) and not isinstance(now,bool) and math.isfinite(now) and now>=0)
    value._deadline=now+600
    value._action=sha(b'company-stored-startup-v1:'+sha(canonical(request)).encode()+b':'+worker_sha256.encode())
    store_root=request['dataDir']+'/company/platform-releases/'+request['releaseSha256']
    value._inventories={store_root:sorted(['intent.json','verified.json',*CONFIGS,*PROVENANCE,ARCHIVE]),
        str(PurePosixPath(source_root).parent):['bytes-verified.json','intent.json','source']}
    value._active=True; _ISSUED.add(value); _OWNERS.add(value)
    try:
        value._parent_check(); value._capture(); yield value; value.recheck()
    finally:value.close()
