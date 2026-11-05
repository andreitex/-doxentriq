"""One-use original-parent adapter; no native default, init or activation.

The company entry independently authenticates this executing module and its
original FullEntry module. Candidate pins or public constructors cannot replace
that bootstrap trust. This API borrows caller-owned entry/source/assembly/parent
contexts; it owns no descriptors and confirms no effects. Trusted Python object
identity is not isolation from hostile code within that same interpreter.
"""
from contextlib import contextmanager
import hashlib
from types import ModuleType
import uuid

PAIR = 'scripts/runtime_pair_init.py'
CONTROL = 'scripts/checkpoint_admission.py'
STARTUP = 'scripts/startup_binding.py'
_ISSUED = {}
_TYPES = set()
UNCONFIRMED = []


class RuntimePairParentUnavailable(ValueError): pass


def require(value):
    if not value: raise RuntimePairParentUnavailable('company-runtime-pair-parent-unavailable')


def _original(entry,F,assembly):
    # Initial F provenance is supplied independently by the company caller.
    require(type(F) is ModuleType and type(entry) is F.FullEntry
            and entry in F._ISSUED_ENTRIES)
    F.FullEntry.recheck(entry)
    L=entry.modules[F.LOADER]
    require(type(assembly) is L.FreshInstallationAssembly and assembly in L._FRESH_ASSEMBLIES
            and assembly._entry is entry.origin)
    L.FreshInstallationAssembly.recheck(assembly)
    modules=assembly.modules;V=entry.modules[F.VERIFIER]
    require(V.require_platform_source(assembly._source) is assembly._source)
    P,R,C=modules[F.PARENT],modules[PAIR],modules[CONTROL]
    require(P is entry.modules[F.PARENT] and modules[F.VERIFIER] is V
            and R.C is C and R.S is modules[STARTUP] and R.S.C is C)
    F.FullEntry.recheck(entry);L.FreshInstallationAssembly.recheck(assembly)
    return L,P,R,C


def _request(C,R,value):
    C.fields(value,{'stage','installationId','storageProofSha256','dataRootSha256'})
    require(type(value['stage']) is str and value['stage']==R.STAGE=='fresh-runtime-pair')
    identifier=value['installationId']
    require(type(identifier) is str and str(uuid.UUID(identifier))==identifier)
    C.hash_value(value['storageProofSha256']);C.hash_value(value['dataRootSha256'])
    return dict(value)


def _borrowed(state):
    try:
        require(not UNCONFIRMED)
        L,P,R,C=_original(state['entry'],state['F'],state['assembly'])
        require((L,P,R,C)==state['originals'])
        parent=state['parent']
        require(type(parent) is P.HeldParent and parent.live)
        args=parent.arguments
        require(type(args) is P.ParentInput and args==state['arguments']
                and args.request==state['installation'] and args.stage==R.STAGE)
        observed=P.HeldParent.check(parent)
        require(observed==state['parentObservation'] and parent.stage_hash==state['intent'])
    except BaseException:
        if not state['retained']:
            state['retained']=True
            UNCONFIRMED.append((state,'borrowed-context-check-failed',state['entry'],state['assembly'],state['parent']))
        raise


def _state(authority):
    require(type(authority) in _TYPES)
    state=_ISSUED.get(authority)
    require(state is not None and type(authority) is state['type'] and state['active'])
    return state


def _expire(authority,state):
    state['active']=False;_ISSUED.pop(authority,None)


def _check(authority,request,evidence):
    state=_state(authority)
    try:
        require(state['holding'])
        _borrowed(state)
        R,C=state['originals'][2:]
        current=_request(C,R,request)
        C.fields(evidence,{'scope','stage','installationId','requestSha256','parentSessionId',
            'parentIntentSha256','nativeAuthorized'})
        require(current==state['request'] and evidence==state['evidence']
                and type(evidence['nativeAuthorized']) is bool and evidence['nativeAuthorized'] is False)
        _borrowed(state)
    except BaseException:
        _expire(authority,state);raise


@contextmanager
def _hold(authority,request):
    state=_state(authority)
    try:
        require(not state['used']);state['used']=True
        _borrowed(state)
        R,C=state['originals'][2:];current=_request(C,R,request)
        request_hash=C.digest(current)
        action=hashlib.sha256(b'full-runtime-pair-v1:'+state['installation'].encode()+b':'+
            state['worker'].encode()+b':'+request_hash.encode()).hexdigest()
        require(state['parent'].arguments.action==action)
        supplied=dict(scope='INSTALLER_PARENT_STAGE_ONLY',stage=R.STAGE,
            installationId=current['installationId'],requestSha256=request_hash,
            parentSessionId=state['parent'].arguments.session,parentIntentSha256=state['intent'],
            nativeAuthorized=False)
        state['request'],state['evidence'],state['holding']=current,supplied,True
        _check(authority,current,supplied)
        try:
            yield dict(supplied)
        finally:
            # Check borrowed lifetimes even if a caught check expired authority.
            _borrowed(state)
            _check(authority,current,supplied)
    finally:
        state['holding']=False;_expire(authority,state)


@contextmanager
def hold_runtime_pair_parent(entry,*,full_entry_module,assembly,parent,
                             installation_request_sha256,full_worker_sha256):
    """Issue one original R subclass after live original F/L/P validation.

    The caller closes its original parent and stage/storage contexts before a
    separate Bash acknowledgement. This adapter closes none of them, invokes no
    R.initialize and never claims native authorization. A copied returned record
    is usable only within this exact authority's one active hold invocation.
    Unknown underlying lifetime checks retain exact borrowed references; there
    is no automatic retry, adoption or process-wide reset API.
    """
    require(not UNCONFIRMED)
    F=full_entry_module;L,P,R,C=_original(entry,F,assembly)
    C.hash_value(installation_request_sha256);C.hash_value(full_worker_sha256)
    require(type(parent) is P.HeldParent and parent.live)
    args=parent.arguments
    require(type(args) is P.ParentInput and args.request==installation_request_sha256 and args.stage==R.STAGE)
    observed=P.HeldParent.check(parent);intent=parent.stage_hash;C.hash_value(intent)
    state=dict(entry=entry,F=F,assembly=assembly,parent=parent,originals=(L,P,R,C),
        installation=installation_request_sha256,worker=full_worker_sha256,arguments=args,
        parentObservation=dict(observed),intent=intent,retained=False,active=True,used=False,holding=False)
    authority_type=type('_IssuedRuntimePairParent',(R.ParentStageAuthority,),
        dict(__module__=__name__,qualification=R.QUALIFICATION,hold=_hold,check=_check))
    authority=authority_type();state['type']=authority_type
    _TYPES.add(authority_type);_ISSUED[authority]=state
    try:
        _borrowed(state)
        try:
            yield authority
        finally:
            _borrowed(state)
    finally:
        _expire(authority,state);_TYPES.discard(authority_type)
