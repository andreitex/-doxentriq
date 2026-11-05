"""Read-only rereading of Store/Source effects before the parent's confirmation.

The company caller supplies original authenticated V/B/P/M/C modules, a genuine
held source, original held parent, original fresh SeedStorage and explicit IO.
This API owns its read descriptors only. The caller must release ALL outer
contexts before confirming; these returned observations grant no ACK authority.
No native defaults, writes, adoption, repair, signing or service activation.
"""
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat
from types import ModuleType

STAGES = ('company-platform-store', 'company-source-materialize')
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
          'st_size','st_mtime_ns','st_ctime_ns')
PLAN_FIELDS = frozenset(('schemaVersion','scope','stage','installationRequestSha256',
    'operationId','storeOperationId','stageRequest','stageRequestSha256','actionSha256'))
MAX_HANDLES, MAX_TOTAL, CHUNK = 2700, 104*1024**2, 65536
UNRELEASED = []


class RetentionEffectsUnavailable(ValueError): pass


def require(value):
    if value is not True: raise RetentionEffectsUnavailable('company-retention-effects-unavailable')


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def namespace(module): return {k:v for k,v in vars(module).items() if k!='__builtins__'}


def _hash(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None)


def _metadata(value):
    require(type(value) is dict and set(value)==set(FIELDS)
        and all(type(value[name]) is int and value[name]>=0 for name in FIELDS))
    return dict(value)


class _Reader:
    """Finite own reads; captured close is admitted before any unwind callback."""
    def __init__(self,module,backend,clock,bound):
        require(type(module) is ModuleType and type(backend) is module.SeedBackend and callable(clock))
        self.module,self.backend,self.clock,self.bound = module,backend,clock,bound
        self.globals,self.methods = namespace(module),dict(vars(type(backend)))
        self.callbacks = {k:v for k,v in vars(backend).items() if callable(v)}
        self.calls = {name:getattr(backend,name) for name in
                      ('open','lstat','fstat','inheritable','pread','names')}
        require(all(callable(v) for v in self.calls.values()))
        self.saved_close = self.methods.get('close'); require(callable(self.saved_close))
        self.owned,self.attempted,self.rows = [],set(),{}
        self.original_owned,self.original_attempted,self.original_state = self.owned,self.attempted,vars(self)
        self.total,self.closed = 0,False
        now = clock(); require(type(now) in (int,float) and math.isfinite(now) and now>=0)
        self.deadline = now+600
        owned,attempted,state = self.owned,self.attempted,vars(self)
        original_type,reader_methods = type(self),dict(vars(type(self)))
        original_globals,original_methods,callbacks = self.globals,self.methods,self.callbacks
        backend_type,saved_close,retained = type(backend),self.saved_close,UNRELEASED
        observe_namespace,admit = namespace,require
        def dispose():
            # These references were captured before any acquisition; no live
            # reader cleanup method or replacement ownership list is invoked.
            try:
                current_methods = dict(vars(original_type))
                admit(type(self) is original_type and set(current_methods)==set(reader_methods)
                    and all(current_methods[k] is reader_methods[k] for k in current_methods)
                    and vars(self) is state and dict.get(state,'owned') is owned
                    and dict.get(state,'attempted') is attempted and dict.get(state,'closed') is False
                    and type(owned) is list and len(owned)<=MAX_HANDLES
                    and all(type(fd) is int and fd>=0 for fd in owned)
                    and len(owned)==len(set(owned)) and type(attempted) is set
                    and len(attempted)<=MAX_HANDLES
                    and all(type(fd) is int and fd>=0 for fd in attempted)
                    and attempted<=set(owned))
                def backend_unchanged():
                    current = observe_namespace(module)
                    current_methods = dict(vars(backend_type))
                    admit(set(current)==set(original_globals) and all(current[k] is original_globals[k] for k in current)
                        and type(backend) is backend_type and set(current_methods)==set(original_methods)
                        and all(current_methods[k] is original_methods[k] for k in current_methods))
                    current_calls = {k:v for k,v in vars(backend).items() if callable(v)}
                    admit(set(current_calls)==set(callbacks) and all(current_calls[k] is callbacks[k] for k in current_calls))
                backend_unchanged()
            except BaseException as error:
                retained.append((self,'cleanup-boundary-unknown',backend,state,owned,attempted,
                    dict.get(state,'owned'),dict.get(state,'attempted'),saved_close,error)); raise
            dict.__setitem__(state,'closed',True)
            failures = []
            for fd in reversed(owned):
                if fd in attempted: failures.append((fd,'already-attempted')); continue
                attempted.add(fd)
                try:
                    backend_unchanged(); admit(saved_close(backend,fd) is None)
                except BaseException as error: failures.append((fd,error))
            if failures:
                retained.append((self,'close-unknown',backend,state,owned,attempted,saved_close,tuple(failures)))
                admit(False)
            owned.clear()
        self.dispose = dispose

    def trust(self):
        now = namespace(self.module)
        require(set(now)==set(self.globals) and all(now[k] is self.globals[k] for k in now)
            and type(self.backend) is self.module.SeedBackend)
        current_methods = dict(vars(type(self.backend)))
        require(set(current_methods)==set(self.methods)
            and all(current_methods[k] is self.methods[k] for k in current_methods))
        current = {k:v for k,v in vars(self.backend).items() if callable(v)}
        require(set(current)==set(self.callbacks) and all(current[k] is self.callbacks[k] for k in current))

    def tick(self):
        require(not self.closed and not UNRELEASED)
        now = self.clock(); require(type(now) in (int,float) and math.isfinite(now) and 0<=now<=self.deadline)
        self.trust(); self.bound()

    def check(self):
        self.tick()
        for path,row in self.rows.items():
            require(_metadata(self.calls['lstat'](path))==row['metadata']
                and _metadata(self.calls['fstat'](row['fd']))==row['metadata']
                and self.calls['inheritable'](row['fd']) is False)
        self.bound(); self.trust()

    def hold(self,path,directory,mode=None,raw=None):
        self.tick()
        require(type(path) is str and str(PurePosixPath(path))==path and path.startswith('/')
            and type(directory) is bool and path not in self.rows and len(self.owned)<MAX_HANDLES)
        before = _metadata(self.calls['lstat'](path))
        require(before['st_uid']==before['st_gid']==0 and not stat.S_IMODE(before['st_mode'])&0o022
            and (stat.S_ISDIR(before['st_mode']) if directory else stat.S_ISREG(before['st_mode']) and before['st_nlink']==1)
            and (mode is None or stat.S_IMODE(before['st_mode'])==mode))
        try:
            fd = self.calls['open'](path,'directory' if directory else 'file')
        except BaseException as error:
            # The protocol cannot prove whether a throwing acquisition left a
            # registered-but-unreturned resource; retain the exact outer refs.
            UNRELEASED.append((self,'acquisition-release-unknown',self.backend,self.saved_close,error))
            raise
        # A malformed acquisition remains uncertain; never guess a descriptor.
        if not (type(fd) is int and fd>=0 and fd not in self.owned):
            UNRELEASED.append((self,'acquisition-unknown',fd,self.backend,self.saved_close)); require(False)
        self.owned.append(fd)
        require(_metadata(self.calls['fstat'](fd))==before and self.calls['inheritable'](fd) is False
            and _metadata(self.calls['lstat'](path))==before)
        self.rows[path] = dict(fd=fd,metadata=before,directory=directory,raw=raw)
        if not directory:
            require(type(raw) is bytes and len(raw)<=32*1024**2 and before['st_size']==len(raw))
            self.total += len(raw); require(self.total<=MAX_TOTAL)
            offset = 0
            while offset<len(raw):
                self.tick(); count = min(CHUNK,len(raw)-offset)
                part = self.calls['pread'](fd,count,offset)
                require(type(part) is bytes and 0<len(part)<=count and part==raw[offset:offset+len(part)])
                offset += len(part)
            require(self.calls['pread'](fd,1,len(raw))==b'')
        self.check()

    def inventory(self,path,names):
        self.tick(); require(path in self.rows and self.rows[path]['directory'] is True
            and type(names) is list and len(names)<=2560 and names==sorted(set(names)))
        actual = self.calls['names'](self.rows[path]['fd'],len(names))
        require(type(actual) is list and len(actual)==len(names)
            and all(type(name) is str for name in actual) and sorted(actual)==names)
        self.check()

def verify_retained_effects(stage,*,expected_plan,expected_outcome_sha256,held,
        verifier_module,bootstrap_module,parent_module,parent,store_module,source_module,
        storage,backend_module,backend,operation_id,store_operation_id,
        installation_request_sha256,clock):
    """Compare actual sealed bytes against rederived original signed outcomes.

    The original parent record binds the pending stage/action/global request.
    Source verification also checks its actual independently confirmed Store
    predecessor. A success returns the ORIGINAL outcome hash; it never includes
    wrapper observations in that digest or creates confirmation records.
    """
    require(not UNRELEASED and type(stage) is str and stage in STAGES
        and type(expected_plan) is bytes and 0<len(expected_plan)<=16384)
    _hash(expected_outcome_sha256); _hash(installation_request_sha256)
    require(all(type(v) is str and re.fullmatch('[a-f0-9]{32}',v) is not None for v in (operation_id,store_operation_id))
        and (stage!=STAGES[0] or operation_id==store_operation_id))
    V,B,P,M,C = verifier_module,bootstrap_module,parent_module,store_module,source_module
    require(all(type(module) is ModuleType for module in (V,B,P,M,C,backend_module))
        and type(storage) is B.SeedStorage and type(parent) is P.HeldParent
        and storage.files.backend is backend and storage.fresh is True)
    modules = [(module,namespace(module)) for module in (V,B,P,M,C)]
    classes = [(kind,dict(vars(kind))) for kind in (B.SeedStorage,P.HeldParent)]
    def bound():
        for module,old in modules:
            current = namespace(module)
            require(set(current)==set(old) and all(current[k] is old[k] for k in current))
        for kind,old in classes:
            current = dict(vars(kind))
            require(set(current)==set(old) and all(current[k] is old[k] for k in current))
        require(V.require_platform_source(held) is held)
        storage.check(); parent.check()
        require(storage.active and storage.fresh is True and storage.files.backend is backend
            and parent.arguments.request==installation_request_sha256 and parent.arguments.stage==stage)
    bound()
    prior = C.expected_store(M,held,V,B,storage,store_operation_id,installation_request_sha256)
    if stage==STAGES[0]:
        request,request_sha,action = prior['request'],prior['requestSha256'],prior['actionSha256']
        root,outcome = prior['root'],prior['outcome']
        directories = {request['storeParent']: (0o700,[request['releaseSha256']]),
                       root: (0o500,sorted(prior['originals']))}
        files = {root+'/'+name:raw for name,raw in prior['originals'].items()}
    else:
        request,request_sha,action,plan,prior = C.authenticated_source_request(held,
            verifier_module=V,bootstrap_module=B,store_module=M,storage=storage,
            operation_id=operation_id,store_operation_id=store_operation_id,
            installation_request_sha256=installation_request_sha256)
        C.prior_store(parent,P,prior,installation_request_sha256)
        root = request['sourceParent']+'/'+request['releaseSha256']; source = root+'/source'
        verified = dict(schemaVersion=1,scope=C.SCOPE,requestSha256=request_sha,actionSha256=action,
            installationId=storage.installation_id,releaseSha256=request['releaseSha256'],
            platformManifestSha256=request['platformManifestSha256'],sourceTree=plan['sourceTree'],
            sourceMapSha256=plan['mapSha256'],fileCount=request['fileCount'],directoryCount=request['directoryCount'],
            totalBytes=plan['totalBytes'],exactCapturedSourceBytes=True,physicalFilesMode='0400',
            physicalDirectoriesMode='0500',nativeQualified=False,executionAuthorized=False,
            rebootAuthenticationImplemented=False,fullInstallDenied=True)
        outcome = dict(verified,root=root,sourceRoot=source,ownedSourceHandlesReleased=True,
            outerSourceParentStorageContextsRequireClosure=True,companyArtifactStoreRechecked=True)
        intent = dict(schemaVersion=1,scope=C.SCOPE,request=request,requestSha256=request_sha,actionSha256=action)
        files = {prior['root']+'/'+name:raw for name,raw in prior['originals'].items()}
        files.update({root+'/intent.json':canonical(intent),root+'/bytes-verified.json':canonical(verified)})
        files.update({source+'/'+name:raw for name,raw in plan['files'].items()})
        directories = {prior['request']['storeParent']:(0o700,[request['releaseSha256']]),
            prior['root']:(0o500,sorted(prior['originals'])),request['sourceParent']:(0o700,[request['releaseSha256']]),
            root:(0o500,['bytes-verified.json','intent.json','source']),source:(0o500,[])}
        for name in plan['directories']: directories[source+'/'+name] = (0o500,[])
        for name in (*plan['directories'],*plan['files']):
            parent_name,_,leaf = name.rpartition('/')
            directories[source+('/'+parent_name if parent_name else '')][1].append(leaf)
        directories = {path:(mode,sorted(names)) for path,(mode,names) in directories.items()}
    rederived = dict(schemaVersion=1,scope='RETENTION_STAGE_PLAN_ONLY',stage=stage,
        installationRequestSha256=installation_request_sha256,operationId=operation_id,
        storeOperationId=store_operation_id,stageRequest=request,stageRequestSha256=request_sha,actionSha256=action)
    require(canonical(rederived)==expected_plan and parent.arguments.action==action
        and sha(canonical(outcome))==expected_outcome_sha256)
    # Capture every ancestor before opening leaves; keep the inventory exact.
    ancestors = set()
    for path in directories:
        ancestors.update(str(p) for p in PurePosixPath(path).parents)
    require(len(ancestors|set(directories))+len(files)<=MAX_HANDLES
        and sum(len(raw) for raw in files.values())<=MAX_TOTAL)
    reader = _Reader(backend_module,backend,clock,bound)
    dispose = reader.dispose
    try:
        for path in sorted(ancestors|set(directories),key=lambda p:(p.count('/'),p)):
            reader.hold(path,True,directories[path][0] if path in directories else None)
        device = storage.files.records[storage.data]['before']['st_dev']
        require(all(row['metadata']['st_dev']==device for path,row in reader.rows.items()
            if path==storage.data or path.startswith(storage.data+'/')))
        for path,raw in sorted(files.items()):
            reader.hold(path,False,0o400,raw)
            require(reader.rows[path]['metadata']['st_dev']==device)
        for path,(_,names) in sorted(directories.items()): reader.inventory(path,names)
        reader.check(); bound()
    finally:
        dispose()
    bound()
    return dict(operationResult=outcome,operationOutcomeSha256=sha(canonical(outcome)),
        exactEffectsReread=True,ownedReadHandlesKnownReleased=True,outerContextsRequireClosure=True,
        stageAcknowledged=False,nativeQualified=False)
