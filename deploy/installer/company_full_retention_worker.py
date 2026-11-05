"""Direct-worker Store/Source bridge with explicit trusted IO contracts only.

The company entry independently authenticates this module, original F/S and the
adapter modules. No CLI, native default, parent ACK or service activation exists.
Planning and execution each own a new signed source/fresh assembly. Output and
outer release observations never replace the parent's independent effect check.
"""
import hashlib
import json
import math
import re
import time
from types import ModuleType

BOOTSTRAP='scripts/bootstrap.py'
STORE='scripts/company_platform_store.py'
SOURCE='scripts/company_source_tree.py'
STARTUP='scripts/startup_binding.py'
STAGES=('company-platform-store','company-source-materialize')
PLAN_FIELDS=frozenset(('schemaVersion','scope','stage','installationRequestSha256',
    'operationId','storeOperationId','stageRequest','stageRequestSha256','actionSha256'))
UNRELEASED=[]
MAX_PLAN=16384
MAX_SEED_HANDLES=8192
EFFECT_FIELDS=frozenset(('operationResult','operationOutcomeSha256','exactEffectsReread',
    'ownedReadHandlesKnownReleased','outerContextsRequireClosure','stageAcknowledged','nativeQualified'))


class RetentionWorkerUnavailable(ValueError):pass


def require(value,code='company-retention-worker-unavailable'):
    if value is not True:raise RetentionWorkerUnavailable(code)


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def sha(raw):return hashlib.sha256(raw).hexdigest()


def namespace(module):return {k:v for k,v in vars(module).items() if k!='__builtins__'}


class _Adapter:
    """Independently trusted concrete class, with a known-release observation.

    require_released must observe all resources, including failed acquisitions
    and transient command/enumeration resources, and return this exact instance.
    A caller-supplied boolean or separate callback is never a release adapter.
    """
    def __init__(self,module,value,name):
        require(type(module) is ModuleType and type(name) is str)
        cls=vars(module).get(name)
        require(type(cls) is type and type(value) is cls)
        self.module,self.value,self.cls=module,value,cls
        self.globals,self.methods=namespace(module),dict(vars(cls))
        self.instance_methods={k:v for k,v in vars(value).items() if callable(v)}
        self.release=self.methods.get('require_released')
        require(callable(self.release))
        self.require_released()

    def check(self):
        now=namespace(self.module)
        require(set(now)==set(self.globals) and all(now[k] is self.globals[k] for k in now)
            and type(self.value) is self.cls and dict(vars(self.cls))==self.methods)
        current={k:v for k,v in vars(self.value).items() if callable(v)}
        require(set(current)==set(self.instance_methods)
            and all(current[k] is self.instance_methods[k] for k in current))

    def require_released(self):
        try:
            self.check();require(self.release(self.value) is self.value);self.check()
        except BaseException as error:
            UNRELEASED.append((self,'adapter-release-unknown',self.value,self.release,error))
            raise


class _Effects:
    """Explicit original read-only verifier; unknown reads retain every borrower.

    Module provenance is an independently trusted entry prerequisite. An empty
    journal or a successful return alone never substitutes for its exact code
    boundaries and known owned read closure.
    """
    def __init__(self,module):
        require(type(module) is ModuleType)
        self.module=module;self.globals=namespace(module)
        self.function=self.globals.get('verify_retained_effects')
        self.ledger=self.globals.get('UNRELEASED')
        self.classes={value:dict(vars(value)) for value in self.globals.values()
            if type(value) is type and getattr(value,'__module__',None)==module.__name__}
        require(callable(self.function) and type(self.ledger) is list)
        self.check()

    def check(self):
        current=namespace(self.module)
        require(set(current)==set(self.globals) and all(current[k] is self.globals[k] for k in current)
            and all(set(vars(kind))==set(old) and all(vars(kind)[key] is old[key] for key in old)
                for kind,old in self.classes.items())
            and type(self.ledger) is list and current.get('UNRELEASED') is self.ledger
            and len(self.ledger)==0)

    def release_observation(self):
        try:self.check()
        except BaseException as error:
            # No changed cleanup helper, opaque journal operation or borrower
            # check is invoked here. The exact original/current refs survive.
            current=vars(self.module)
            UNRELEASED.append((self,'effect-read-release-unknown',self.module,self.function,
                self.ledger,dict.get(current,'UNRELEASED'),self.globals,current,self.classes,error))
            raise

    def result(self,value,expected_sha):
        self.check()
        require(type(value) is dict and set(value)==EFFECT_FIELDS
            and type(value['operationResult']) is dict
            and type(value['operationOutcomeSha256']) is str and value['operationOutcomeSha256']==expected_sha
            and all(value[name] is True for name in ('exactEffectsReread','ownedReadHandlesKnownReleased','outerContextsRequireClosure'))
            and value['stageAcknowledged'] is False and value['nativeQualified'] is False)
        raw=canonical(value['operationResult'])
        require(len(raw)<=MAX_PLAN and sha(raw)==expected_sha)
        return value


class _Resources:
    """Owned original-B resources. Unknown release keeps outer contexts live."""
    def __init__(self,assembly,scope,backend,runner,clock):
        self.assembly,self.scope,self.backend,self.runner=assembly,scope,backend,runner
        modules=assembly.modules
        self.B,self.M,self.C,self.Startup=(modules[p] for p in (BOOTSTRAP,STORE,SOURCE,STARTUP))
        self.modules={p:modules[p] for p in (BOOTSTRAP,STORE,SOURCE,STARTUP)}
        self.snapshots={p:namespace(module) for p,module in self.modules.items()}
        self.classes={name:dict(vars(getattr(self.B,name))) for name in ('SeedFiles','SeedCommands','SeedStorage')}
        self.files=self.commands=self.storage=None
        self.files_identity=self.files_state=self.files_state_original=None
        self.files_owned=self.files_owned_original=None
        self.files_constructor_closed=None
        self.seed_release_ledger=self.snapshots[BOOTSTRAP].get('SEED_UNRELEASED')
        self.commands_state=self.storage_state=None
        self.commands_state_original=self.storage_state_original=None
        self.commands_identity=self.storage_identity=None
        self.clock=clock;start=clock()
        require(type(start) in (int,float) and math.isfinite(start) and start>=0)
        self.deadline=start+600;self.closed=False

    def trust(self):
        for p,module in self.modules.items():
            now=namespace(module);old=self.snapshots[p]
            require(set(now)==set(old) and all(now[k] is old[k] for k in now))
        require(all(dict(vars(getattr(self.B,k)))==v for k,v in self.classes.items()))
        self.backend.check();self.runner.check()

    def build(self,request):
        self.trust()
        root=request['dataDir']+'/company/host-releases/install-'+request['operationId']
        self.files=self.B.SeedFiles(self.backend.module,self.backend.value,clock=self.clock)
        self.files_identity=self.files
        self.files_state=vars(self.files);self.files_state_original=self.files_state
        require(type(self.files_state) is dict)
        self.files_owned=dict.get(self.files_state,'owned');self.files_owned_original=self.files_owned
        self._files_check()
        self.commands=self.B.SeedCommands(self.runner.module,self.runner.value)
        self.trust();self.commands_state=vars(self.commands);require(type(self.commands_state) is dict)
        self.commands_state_original=self.commands_state
        self.commands_identity=self.commands
        try:
            self.storage=self.B.SeedStorage(request['dataDir'],root,startup_module=self.Startup,
                files=self.files,commands=self.commands,fresh=True,host_directory='/etc/autosoft')
        except BaseException:
            # The original constructor closes SeedFiles before propagating a
            # refusal. Recognize that exact, independently observed closure;
            # never retry the old descriptor list or adopt arbitrary drift.
            try:
                self.trust()
                closed=dict.get(self.files_state_original,'owned')
                if closed is not self.files_owned_original and type(closed) is list and not closed:
                    self.files_constructor_closed=closed
                    self._files_constructor_close_check()
            except BaseException:
                self.files_constructor_closed=None
            raise
        self.trust();self.storage_state=vars(self.storage);require(type(self.storage_state) is dict)
        self.storage_state_original=self.storage_state
        self.storage_identity=self.storage
        self.check(request)

    def _files_check(self):
        # Original close uses active/backend/owned. Check those exact plain
        # ownership boundaries before invoking it; never inspect an opaque
        # replacement through its attribute, iteration or indexing callbacks.
        value,state,owned=self.files,self.files_state,self.files_owned
        require(value is self.files_identity and type(value) is self.B.SeedFiles
            and type(state) is dict and state is self.files_state_original and vars(value) is state
            and dict.get(state,'backend') is self.backend.value
            and type(owned) is list and owned is self.files_owned_original and dict.get(state,'owned') is owned)
        require(len(owned)<=MAX_SEED_HANDLES and all(type(fd) is int and fd>=0 for fd in owned)
            and len(owned)==len(set(owned)))

    def _files_constructor_close_check(self):
        value,state,owned=self.files_identity,self.files_state_original,self.files_constructor_closed
        require(value is self.files and type(value) is self.B.SeedFiles
            and type(state) is dict and vars(value) is state
            and dict.get(state,'backend') is self.backend.value
            and dict.get(state,'active') is False
            and type(owned) is list and not owned and dict.get(state,'owned') is owned
            and owned is not self.files_owned_original
            and type(self.files_owned_original) is list
            and len(self.files_owned_original)<=MAX_SEED_HANDLES
            and all(type(fd) is int and fd>=0 for fd in self.files_owned_original)
            and len(self.files_owned_original)==len(set(self.files_owned_original))
            and type(self.seed_release_ledger) is list and not self.seed_release_ledger
            and self.B.SEED_UNRELEASED is self.seed_release_ledger)
        self.backend.require_released()

    def check(self,request,parent=None):
        now=self.clock();require(type(now) in (int,float) and math.isfinite(now) and 0<=now<=self.deadline)
        self.trust();self.scope.recheck();self.assembly.recheck();self._files_check()
        require(self.storage is self.storage_identity and self.commands is self.commands_identity
            and type(self.storage) is self.B.SeedStorage and type(self.commands) is self.B.SeedCommands
            and self.storage.files is self.files
            and self.files.backend is self.backend.value and self.storage.commands is self.commands
            and self.commands.runner is self.runner.value and self.storage.startup is self.Startup
            and self.storage.fresh is True and vars(self.storage) is self.storage_state
            and vars(self.commands) is self.commands_state
            and type(self.storage_state) is dict and self.storage_state is self.storage_state_original
            and type(self.commands_state) is dict and self.commands_state is self.commands_state_original)
        self.B.SeedStorage.check(self.storage)
        intent=self.B._seed_decode(self.files.records['/etc/autosoft/installation.intent.json']['raw'])
        proposal=intent['proposal']
        require(proposal['data_dir']==request['dataDir'] and proposal['storage_file']==request['backingFile']
            and type(proposal['capacity_gib']) is int and proposal['capacity_gib']==request['capacityGiB']
            and proposal['install_root']==request['dataDir']+'/company/host-releases/install-'+request['operationId']
            and self.storage.receipt['storage_file']==request['backingFile']
            and self.storage.root==proposal['install_root'])
        if parent is not None:parent.check()
        self.trust();self.scope.recheck();self.assembly.recheck()

    def close(self):
        require(not self.closed);self.closed=True;errors=[]
        try:
            now=namespace(self.B);old=self.snapshots[BOOTSTRAP]
            require(set(now)==set(old) and all(now[k] is old[k] for k in now)
                and all(dict(vars(getattr(self.B,k)))==v for k,v in self.classes.items()))
            for name,state,identity,original in (('storage',self.storage_state,self.storage_identity,self.storage_state_original),
                                                 ('commands',self.commands_state,self.commands_identity,self.commands_state_original)):
                if identity is not None:
                    value=getattr(self,name)
                    require(value is identity and type(value) is getattr(self.B,'Seed'+name.title())
                        and type(state) is dict and state is original and vars(value) is state)
        except BaseException as error:
            errors.append(('resource-expiration-unknown',self.storage_identity,self.commands_identity,error))
            UNRELEASED.append((self,'resource-expiration-unknown',self.storage_identity,self.commands_identity,
                self.storage,self.commands,self.storage_state,self.commands_state,error))
        # Expire the exact captured plain dictionaries without calling a live
        # resource attribute setter. Class/dictionary drift still denies known
        # release below; these references are never adopted or refreshed.
        for state,original in ((self.storage_state,self.storage_state_original),
                                (self.commands_state,self.commands_state_original)):
            if type(state) is dict and state is original:
                dict.__setitem__(state,'active',False)
        if self.files_identity is not None or self.files is not None:
            try:
                # Cleanup does not depend on unrelated planner namespaces.
                # Original SeedFiles.close resolves B's helpers and backend
                # methods, so both exact boundaries must still be intact.
                now=namespace(self.B);old=self.snapshots[BOOTSTRAP]
                require(set(now)==set(old) and all(now[k] is old[k] for k in now)
                    and all(dict(vars(getattr(self.B,k)))==v for k,v in self.classes.items()))
                self.backend.check()
                if self.files_constructor_closed is not None:
                    self._files_constructor_close_check()
                else:
                    self._files_check()
                    self.classes['SeedFiles']['close'](self.files_identity)
            except BaseException as error:
                errors.append(('seed-files-release-unknown',self.files,error))
                # Retain the original list even if original close emptied it.
                UNRELEASED.append((self,'seed-files-release-unknown',self.files,self.backend.value,error,
                    self.files_identity,self.files_state_original,self.files_owned_original,self.files_state,self.files_owned))
        for adapter in (self.backend,self.runner):
            try:adapter.require_released()
            except BaseException as error:
                errors.append(('adapter-release-unknown',adapter,error))
                UNRELEASED.append((self,'adapter-release-unknown',adapter,adapter.value,error))
        if errors:
            UNRELEASED.append((self,'owned-resource-release-unknown',self.scope,self.assembly,self.files,
                self.commands,self.storage,self.backend,self.runner,tuple(errors)))
            raise RetentionWorkerUnavailable('company-retention-owned-release-unknown')


def _operation(scope,resources,stage,operation_id,store_operation_id,shared):
    held=scope.source;V=scope._coordinator._V
    if stage==STAGES[0]:
        request,request_sha,action,unused=resources.M.authenticated_store_request(held,
            verifier_module=V,bootstrap_module=resources.B,storage=resources.storage,
            operation_id=operation_id,installation_request_sha256=shared)
    else:
        request,request_sha,action,unused,prior=resources.C.authenticated_source_request(held,
            verifier_module=V,bootstrap_module=resources.B,store_module=resources.M,
            storage=resources.storage,operation_id=operation_id,store_operation_id=store_operation_id,
            installation_request_sha256=shared)
    return dict(schemaVersion=1,scope='RETENTION_STAGE_PLAN_ONLY',stage=stage,
        installationRequestSha256=shared,operationId=operation_id,storeOperationId=store_operation_id,
        stageRequest=request,stageRequestSha256=request_sha,actionSha256=action)


def _inputs(stage,operation_id,store_operation_id,clock):
    require(not UNRELEASED and type(stage) is str and stage in STAGES and callable(clock))
    require(all(type(v) is str and re.fullmatch('[a-f0-9]{32}',v) is not None for v in (operation_id,store_operation_id)))
    require(stage!=STAGES[0] or operation_id==store_operation_id)


def _plan(raw):
    require(type(raw) is bytes and 0<len(raw)<=MAX_PLAN)
    try:value=json.loads(raw)
    except (ValueError,UnicodeError,RecursionError):raise RetentionWorkerUnavailable() from None
    require(type(value) is dict and set(value)==PLAN_FIELDS and canonical(value)==raw
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']=='RETENTION_STAGE_PLAN_ONLY' and type(value['stageRequest']) is dict)
    return value


def _run(stage,*,entry,full_entry_module,stage_module,request_raw,request_sha256,
        operational_catalog,key_fingerprint,expected_architecture,files,crypto,
        backend_module,backend,runner_module,runner,operation_id,store_operation_id,
        clock,expected_plan=None,parent_arguments=None,parent_system_module=None,parent_system=None,
        effect_verifier_module=None,expected_outcome_sha256=None):
    _inputs(stage,operation_id,store_operation_id,clock)
    F,S=full_entry_module,stage_module
    require(type(F) is ModuleType and type(S) is ModuleType and type(entry) is F.FullEntry)
    F.FullEntry.recheck(entry)
    require(files is not None and crypto is not None)
    effects=None
    if effect_verifier_module is not None:
        require(expected_plan is not None and type(expected_outcome_sha256) is str
            and re.fullmatch('[a-f0-9]{64}',expected_outcome_sha256) is not None)
        effects=_Effects(effect_verifier_module)
    else:require(expected_outcome_sha256 is None)
    # Explicit release-capable adapters are captured before source IO/effects.
    be=_Adapter(backend_module,backend,'SeedBackend');ru=_Adapter(runner_module,runner,'SeedRunner')
    system=None
    if expected_plan is not None:
        _plan(expected_plan)
        system=_Adapter(parent_system_module,parent_system,'ParentSystem')
    else:require(parent_arguments is None and parent_system_module is None and parent_system is None)
    globals_F,globals_S=namespace(F),namespace(S)
    def trust():
        for module,snapshot in ((F,globals_F),(S,globals_S)):
            now=namespace(module);require(set(now)==set(snapshot) and all(now[k] is snapshot[k] for k in now))
        be.check();ru.check()
        if system is not None:system.check()
        if effects is not None:effects.check()
        F.FullEntry.recheck(entry)
    coordinator_cm=source_cm=assembly_cm=parent_cm=None
    coordinator=scope=assembly=parent=resources=None
    parent_module=parent_globals=parent_methods=None
    entered=[False]*4;result=plan_raw=outcome_sha=effect_observation=None;body_error=None;release_error=None
    try:
        trust()
        coordinator_cm=S.stage_coordinator(entry,full_entry_module=F,request_raw=request_raw,
            request_sha256=request_sha256,operational_catalog=operational_catalog,
            key_fingerprint=key_fingerprint,expected_architecture=expected_architecture,
            files=files,crypto=crypto,stages=(stage,),clock=clock,timeout=900)
        coordinator=coordinator_cm.__enter__();entered[0]=True
        source_cm=coordinator.source_stage(stage);scope=source_cm.__enter__();entered[1]=True
        assembly_cm=scope.assembly();assembly=assembly_cm.__enter__();entered[2]=True
        resources=_Resources(assembly,scope,be,ru,clock)
        request=coordinator._request
        resources.build(request);trust()
        plan=_operation(scope,resources,stage,operation_id,store_operation_id,request_sha256)
        plan_raw=canonical(plan);require(len(plan_raw)<=MAX_PLAN)
        resources.check(request)
        if expected_plan is not None:
            require(plan_raw==expected_plan,'company-retention-plan-changed')
            P=coordinator._P
            parent_module,parent_globals,parent_methods=P,namespace(P),dict(vars(P.HeldParent))
            require(type(parent_arguments) is P.ParentInput
                and parent_arguments.request==request_sha256 and parent_arguments.stage==stage
                and parent_arguments.action==plan['actionSha256'])
            parent_cm=P.hold_parent(parent_arguments,system=system.value)
            parent=parent_cm.__enter__();entered[3]=True
            resources.check(request,parent);trust()
            common=dict(verifier_module=coordinator._V,bootstrap_module=resources.B,
                parent_module=P,parent=parent,storage=resources.storage,backend_module=be.module,
                backend=be.value,operation_id=operation_id,installation_request_sha256=request_sha256,clock=clock)
            if effects is not None:
                effects.check()
                effect_observation=effects.function(stage,expected_plan=expected_plan,
                    expected_outcome_sha256=expected_outcome_sha256,held=scope.source,
                    verifier_module=coordinator._V,bootstrap_module=resources.B,parent_module=P,parent=parent,
                    store_module=resources.M,source_module=resources.C,storage=resources.storage,
                    backend_module=be.module,backend=be.value,operation_id=operation_id,
                    store_operation_id=store_operation_id,installation_request_sha256=request_sha256,clock=clock)
                effects.result(effect_observation,expected_outcome_sha256)
                result=effect_observation['operationResult']
            elif stage==STAGES[0]:
                result=resources.M.store_authenticated_platform(scope.source,**common)
            else:
                result=resources.C.materialize_authenticated_company_source(scope.source,
                    store_module=resources.M,store_operation_id=store_operation_id,**common)
            require(type(result) is dict)
            outcome_sha=sha(canonical(result))
        resources.check(request,parent);trust()
    except BaseException as error:body_error=error
    finally:
        # Effects can hold reads underneath every borrowed outer context. Test
        # its exact boundary and ledger BEFORE any resource/parent check or
        # close (original parent check can itself close on rejection).
        if effects is not None:
            try:effects.release_observation()
            except BaseException as error:release_error=error
        # Always observe borrowed contexts on exceptional exits; invalid known
        # state prevents success but is distinct from uncertain owned release.
        if release_error is None and resources is not None and resources.storage is not None:
            try:resources.check(coordinator._request,parent)
            except BaseException as error:
                if body_error is None:body_error=error
        if release_error is None and resources is not None:
            try:resources.close()
            except BaseException as error:release_error=error
        elif release_error is None:
            for adapter in (be,ru):
                try:adapter.require_released()
                except BaseException as error:
                    release_error=error;UNRELEASED.append((adapter,'pre-resource-release-unknown',adapter.value,error))
        if release_error is None and parent_cm is not None:
            try:
                now=namespace(parent_module)
                require(set(now)==set(parent_globals) and all(now[k] is parent_globals[k] for k in now)
                    and dict(vars(parent_module.HeldParent))==parent_methods)
                system.check()
                if entered[3]:parent_cm.__exit__(None,None,None);entered[3]=False
            except BaseException as error:release_error=error
        if system is not None:
            try:system.require_released()
            except BaseException as error:
                release_error=error;UNRELEASED.append((system,'parent-system-release-unknown',system.value,parent_cm,parent,error))
        if release_error is None:
            for index,cm in ((2,assembly_cm),(1,source_cm),(0,coordinator_cm)):
                if entered[index]:
                    try:cm.__exit__(None,None,None);entered[index]=False
                    except BaseException as error:release_error=error;break
        if release_error is not None:
            UNRELEASED.append((entry,'retention-context-release-unknown',coordinator_cm,source_cm,assembly_cm,
                parent_cm,coordinator,scope,assembly,parent,resources,be,ru,system,tuple(entered),release_error))
            if effects is not None:
                UNRELEASED.append((entry,'effect-borrowers-retained',effects,effects.module,effects.ledger,
                    vars(effects.module).get('UNRELEASED'),resources,parent,scope,assembly,coordinator,
                    parent_cm,assembly_cm,source_cm,coordinator_cm))
    if release_error is not None:raise RetentionWorkerUnavailable('company-retention-release-unknown') from release_error
    if body_error is not None:raise body_error
    if expected_plan is None:return plan_raw
    response=dict(operationResult=result,operationOutcomeSha256=outcome_sha,
        stagePlanSha256=sha(plan_raw),ownedResourcesKnownReleased=True,
        sourceAssemblyClosedObservation=scope.closed_observation,
        effectsIndependentlyConfirmed=False,stageAcknowledged=False,nativeAuthorized=False)
    if effects is not None:
        require(outcome_sha==expected_outcome_sha256)
        response['retainedEffectsObservation']=effect_observation
    return response


def plan_stage(stage,*,entry,full_entry_module,stage_module,request_raw,request_sha256,
        operational_catalog,key_fingerprint,expected_architecture,files,crypto,
        backend_module,backend,runner_module,runner,operation_id,store_operation_id,clock=time.monotonic):
    """Effect-free detached plan before the original Bash parent's stage intent.

    Source/storage reads and supervised absence probes are performed through
    explicit trusted adapters. A separate execute_stage call reissues source;
    the plan itself is neither an execution capability nor a confirmation.
    """
    return _run(stage,entry=entry,full_entry_module=full_entry_module,stage_module=stage_module,
        request_raw=request_raw,request_sha256=request_sha256,operational_catalog=operational_catalog,
        key_fingerprint=key_fingerprint,expected_architecture=expected_architecture,files=files,crypto=crypto,
        backend_module=backend_module,backend=backend,runner_module=runner_module,runner=runner,
        operation_id=operation_id,store_operation_id=store_operation_id,clock=clock)


def execute_stage(stage,*,expected_plan,parent_arguments,parent_system_module,parent_system,
        entry,full_entry_module,stage_module,request_raw,request_sha256,operational_catalog,
        key_fingerprint,expected_architecture,files,crypto,backend_module,backend,
        runner_module,runner,operation_id,store_operation_id,clock=time.monotonic):
    """Reauthenticate/replan then run the original Store or Source in this worker.

    No nested bootstrap process, NativeSystem/runner/backend fallback or ACK.
    The original operation result is untouched; its canonical hash is the one
    expected by original Source's prior-Store predicate. Caller must separately
    verify actual effects after every original parent/source/storage close.
    """
    require(expected_plan is not None and parent_arguments is not None and parent_system is not None)
    return _run(stage,entry=entry,full_entry_module=full_entry_module,stage_module=stage_module,
        request_raw=request_raw,request_sha256=request_sha256,operational_catalog=operational_catalog,
        key_fingerprint=key_fingerprint,expected_architecture=expected_architecture,files=files,crypto=crypto,
        backend_module=backend_module,backend=backend,runner_module=runner_module,runner=runner,
        operation_id=operation_id,store_operation_id=store_operation_id,clock=clock,
        expected_plan=expected_plan,parent_arguments=parent_arguments,parent_system_module=parent_system_module,
        parent_system=parent_system)


def verify_stage(stage,*,effect_verifier_module,expected_plan,expected_outcome_sha256,
        parent_arguments,parent_system_module,parent_system,entry,full_entry_module,stage_module,
        request_raw,request_sha256,operational_catalog,key_fingerprint,expected_architecture,
        files,crypto,backend_module,backend,runner_module,runner,operation_id,store_operation_id,
        clock=time.monotonic):
    """Fresh original authority and read-only actual effect verification.

    The caller supplies the hash of a known original returned operation after
    prior closure. This call creates no confirmation/ACK, repairs no partial
    state, and cannot adopt an uncertain writer through its terminal records.
    Unknown Effects reads retain SeedFiles/storage/P/assembly/source/coordinator
    exactly; only an observation of ParentSystem release is still permitted.
    """
    require(effect_verifier_module is not None and expected_plan is not None
        and parent_arguments is not None and parent_system is not None)
    return _run(stage,entry=entry,full_entry_module=full_entry_module,stage_module=stage_module,
        request_raw=request_raw,request_sha256=request_sha256,operational_catalog=operational_catalog,
        key_fingerprint=key_fingerprint,expected_architecture=expected_architecture,files=files,crypto=crypto,
        backend_module=backend_module,backend=backend,runner_module=runner_module,runner=runner,
        operation_id=operation_id,store_operation_id=store_operation_id,clock=clock,
        expected_plan=expected_plan,parent_arguments=parent_arguments,parent_system_module=parent_system_module,
        parent_system=parent_system,effect_verifier_module=effect_verifier_module,
        expected_outcome_sha256=expected_outcome_sha256)
