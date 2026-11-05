"""Actual original source/prepare/child/join APIs under labelled RAM fixtures.

No old unittest classes, native process/socket, signing, scope or issuer is used.
Only named frozen fixture definitions execute after a separately authorized run.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys
from types import CellType, CodeType, FunctionType, GetSetDescriptorType, MappingProxyType, MemberDescriptorType, ModuleType, TracebackType
import unittest

ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'deploy/installer'
OWNER_PIN='91b14445e6891998c88bef3f98d3baf12fe559f673165104bb4440c70b8b17fa'
FIXED_BASIS_PIN='0a496694d0634fffddb544ce5e0a11ebb66deeea639e413c37a45484e5e72d43'
JOIN_BASIS_PIN='056cf2d81122f1c678e8e59bc5a6d4607ad5ea046e4c82ac911e91ccd932841d'
RETAINED=[]  # Actual unknown RAM objects remain strong; no cleanup qualification.


def sha(raw):return hashlib.sha256(raw).hexdigest()


def load(name,path,pin=None):
    raw=path.read_bytes();assert len(raw)<=131072
    if pin is not None:assert sha(raw)==pin
    value=ModuleType(name);value.__file__=str(path);sys.modules[name]=value
    try:exec(compile(raw,str(path),'exec'),vars(value))
    except BaseException:sys.modules.pop(name,None);raise
    return value


def named_basis(name,path,pin,names):
    raw=path.read_bytes();assert len(raw)<=65536 and sha(raw)==pin
    nodes=[]
    for node in ast.parse(raw).body:
        if isinstance(node,(ast.Import,ast.ImportFrom,ast.Assign)):nodes.append(node)
        elif isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names:nodes.append(node)
    assert {n.name for n in nodes if isinstance(n,(ast.FunctionDef,ast.ClassDef))}==set(names)
    assert not any(isinstance(n,ast.ClassDef) and n.name=='Controls' for n in nodes)
    value=ModuleType(name);value.__file__=str(path);sys.modules[name]=value
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<explicit named frozen RAM definitions>','exec'),vars(value))
    return value


def keeper_record(module):
    keeper=module.UNRELEASED[0];kind=type(keeper)
    assert type(kind)is type
    descriptor=type.__getattribute__(kind,'__dict__')['_RetainedOwner__record']
    assert type(descriptor)is MemberDescriptorType
    record=descriptor.__get__(keeper,kind)
    assert type(record)is dict and record['value'] is not None
    return keeper,record


def live_reader_view(verifier):
    """Known original HPS/Snapshot native refs; negative-cap controls only."""
    assert len(verifier._ISSUED_PLATFORM_SOURCES)==1
    hps=next(iter(verifier._ISSUED_PLATFORM_SOURCES))
    assert type(hps)is verifier.HeldPlatformSource
    getter=type.__getattribute__(verifier.HeldPlatformSource,'__dict__')['_HeldPlatformSource__recheck']
    assert type(getter)is MemberDescriptorType
    recheck=getter.__get__(hps,verifier.HeldPlatformSource)
    assert type(recheck)is FunctionType and recheck.__globals__ is vars(verifier)
    cells=recheck.__closure__;assert type(cells)is tuple and len(cells)<=8
    for cell in cells:
        assert type(cell)is CellType
        snapshot=cell.cell_contents
        if type(snapshot)is verifier.PlatformInputSnapshot:
            descriptor=type.__getattribute__(verifier.Snapshot,'__dict__')['__dict__']
            assert type(descriptor)is GetSetDescriptorType
            state=descriptor.__get__(snapshot,type(snapshot));assert type(state)is dict
            return hps,state['files']
    raise AssertionError('original snapshot absent')


def failure_observation(fixture,primary):
    """Failure-only known refs/primitive metadata, never messages or payload."""
    assert type(fixture)is Fixture
    getter=type.__getattribute__(Fixture,'__dict__')['__dict__']
    assert type(getter)is GetSetDescriptorType
    state=getter.__get__(fixture,Fixture);assert type(state)is dict
    module=dict.get(state,'O');record=None;keeper=None
    if type(module)is ModuleType:
        public=dict.get(vars(module),'UNRELEASED')
        if type(public)is list and public:
            keeper,record=keeper_record(module)
        elif dict.get(state,'last_keeper') is not None:
            keeper=dict.get(state,'last_keeper');kind=type(keeper)
            assert type(kind)is type
            descriptor=type.__getattribute__(kind,'__dict__').get('_RetainedOwner__record')
            assert type(descriptor)is MemberDescriptorType
            record=descriptor.__get__(keeper,kind)
    if record is not None:assert type(record)is dict and len(record)<=128 and all(type(key)is str for key in record)
    # The same fixture, primary and actual private keeper remain strong. No effects.
    state['kept']=True;RETAINED.append((fixture,primary,keeper,record))
    known_types=((AssertionError,'AssertionError'),(ValueError,'ValueError'),(TypeError,'TypeError'),
                 (KeyError,'KeyError'),(AttributeError,'AttributeError'),(OSError,'OSError'))
    label=next((name for kind,name in known_types if type(primary)is kind),'OtherError')
    if type(module)is ModuleType and type(primary)is dict.get(vars(module),'SourceOwnerUnavailable'):label='SourceOwnerUnavailable'
    kind=type(primary);assert type(kind)is type
    lineage=type.__getattribute__(kind,'__mro__');assert len(lineage)<=8 and any(base is BaseException for base in lineage)
    tb=type.__getattribute__(BaseException,'__dict__')['__traceback__'].__get__(primary,kind)
    frames=[]
    while tb is not None and len(frames)<8:
        assert type(tb)is TracebackType
        code=tb.tb_frame.f_code;assert type(code)is CodeType
        name=code.co_name;filename=code.co_filename.rsplit('\\',1)[-1].rsplit('/',1)[-1]
        assert type(name)is str and type(filename)is str
        frames.append(dict(file=filename[:96],function=name[:64],line=tb.tb_lineno));tb=tb.tb_next
    phase=dict.get(record,'phase') if record is not None else None
    if type(phase)is not str or phase not in ('prepared','opening','ready','running','closed','aborted'):phase=None
    rows=dict.get(record,'reader_rows') if record is not None else None
    rows_count=len(rows) if type(rows)is list and len(rows)<=512 else None
    returns=dict.get(record,'returns') if record is not None else None
    returns_count=len(returns) if type(returns)is list and len(returns)<=24 else None
    summary=dict(scope='SOURCE_OWNER_TEST_FAILURE_METADATA_DATA_ONLY',errorClass=label,frames=frames,
        tracebackTruncated=tb is not None,knownPrivateRecord=record is not None,phase=phase,
        readerRows=rows_count,majorReturns=returns_count,primaryReferenceRetained=True,
        actualPrivateKeeperRetained=keeper is not None,cleanupQualified=False,executionEvidenceIssued=False,stageAcknowledged=False)
    raw=json.dumps(summary,sort_keys=True,separators=(',',':')).encode('ascii');assert len(raw)<=4096
    return raw


class Fixture:
    serial=0
    latest=None
    def __init__(self,*,crypto_bool=False):
        Fixture.latest=self
        Fixture.serial+=1;self.prefix='source_owner_ram_'+str(Fixture.serial)
        self.kept=False;self.owner=None;self.last_record=None;self.loaded=[]
        self.fixed_basis=named_basis(self.prefix+'_fixed_basis',ROOT/'tests/test_company_fixed_execute_child.py',FIXED_BASIS_PIN,
            {'canonical','seed_bytes','sha','named_fixture','failure_observation','Fixture'})
        self.fixed_basis.Fixture.serial=Fixture.serial*1000
        self.fixed_basis.SIGNED.T.Fixture.serial=Fixture.serial*1000
        self.fx=self.fixed_basis.Fixture()
        self.base=self.fx.base;self.V=self.base.V
        self.baseline_hps=self.base.source
        self.source_archive=self.baseline_hps.archive_bytes
        assert type(self.source_archive)is bytes and 0<len(self.source_archive)<=8*1024*1024
        # Original CM exits before a fresh owner acquisition. No HPS promotion.
        self.base.close_source()
        assert not self.baseline_hps.active and not self.V._ISSUED_PLATFORM_SOURCES and not self.base.files.held
        self.O=self.module('owner',HERE/'company_source_owned_execute.py',OWNER_PIN)
        self.I=self.module('inputs',ROOT/'deploy/installer/company_authenticated_cli_inputs.py')
        self.M=self.module('compose',ROOT/'deploy/installer/company_authenticated_cli_compose.py')
        self.S=self.module('signed',ROOT/'deploy/installer/company_signed_execute_preparation.py')
        self.E=self.module('child',ROOT/'deploy/installer/company_fixed_execute_child.py')
        self.join_basis=named_basis(self.prefix+'_join_basis',ROOT/'tests/test_company_startup_join.py',JOIN_BASIS_PIN,
            {'load','Meta','Uname','Endpoint','Poll','Actor','World','Fixture'})
        self.join_basis.Fixture.serial=Fixture.serial*1000
        self.join=self.join_basis.Fixture();self.J=self.join.modules['execute']
        self.X=self.module('source_crypto',ROOT/'deploy/installer/company_release_crypto.py')
        self.crypto_truthiness=[]
        if crypto_bool:
            # Separate initial dependency CLASS profile, never a signed append.
            trap_globals={'calls':self.crypto_truthiness,'ValueError':ValueError}
            exec('def trap(self):\n calls.append(self)\n raise ValueError("public truthiness trap")\n',trap_globals)
            self.X.ReleaseCrypto.__bool__=trap_globals['trap']
        original_methods={name:vars(self.X.ReleaseCrypto)[name].__code__ for name in ('__init__','verify','require_released')}
        self.source_crypto=self.X.ReleaseCrypto(**dict(self.fx.crypto_configuration,
            os_module=self.fx.h.os,sys_module=self.fx.h.sys,subprocess_module=self.fx.h.subprocess,
            select_module=self.fx.h.select,signal_module=self.fx.h.signal,fcntl_module=self.fx.h.fcntl,clock=self.fx.clock))
        assert all(vars(self.X.ReleaseCrypto)[name].__code__ is code for name,code in original_methods.items())
        self.F=ModuleType(self.prefix+'_source_files');sys.modules[self.F.__name__]=self.F;self.loaded.append(self.F)
        self.reader_state={'calls':[],'opens':[],'boolCalls':[],'aliasAt':None,'aliasFD':None,'openError':None,'opaque':None,'postOpen':None,'failClose':None,'closeError':None}
        self.F.__dict__.update(backend=self.base.files,state=self.reader_state,ValueError=ValueError)
        self.reader_profile=('class Files:\n'
            ' def __bool__(self):\n  state["boolCalls"].append(self)\n  raise ValueError("public reader truthiness trap")\n'
            ' def lstat(self,path):\n  state["calls"].append(("lstat",path))\n  return backend.lstat(path)\n'
            ' def open(self,parent,name,directory):\n'
            '  state["calls"].append(("open",parent,name,directory))\n'
            '  if state["openError"] is not None:raise state["openError"]\n'
            '  if state["opaque"] is not None:return state["opaque"]\n'
            '  if state["aliasFD"] is not None and (state["aliasAt"] is None or len(state["opens"])+1==state["aliasAt"]):fd=state["aliasFD"]\n'
            '  else:fd=backend.open(parent,name,directory)\n'
            '  state["opens"].append(fd)\n'
            '  if state["postOpen"] is not None:state["postOpen"](fd)\n'
            '  return fd\n'
            ' def fstat(self,fd):\n  state["calls"].append(("fstat",fd))\n  return backend.fstat(fd)\n'
            ' def cloexec(self,fd):\n  state["calls"].append(("cloexec",fd))\n  return backend.cloexec(fd)\n'
            ' def read(self,fd,amount,offset):\n  state["calls"].append(("read",fd,amount,offset))\n  return backend.read(fd,amount,offset)\n'
            ' def close(self,fd):\n  state["calls"].append(("close",fd))\n'
            '  if state["failClose"]==fd:raise state["closeError"]\n'
            '  return backend.close(fd)\n')
        exec(compile(self.reader_profile,'<pre-origin direct-sixmethod RAM reader>','exec'),vars(self.F))
        self.files=self.F.Files()
        self.source_parameters=dict(directory=str(self.base.bundle),public_key=str(self.base.public),
            fingerprint=self.base.fingerprint,source_root=str(self.base.sources))
        self.publication_observations=[]
        observations=self.fx.plan_cli._observations
        assert type(observations)is list and len(observations)==1
        plan_record_raw=observations[0].completed_record()
        assert type(plan_record_raw)is bytes and 0<len(plan_record_raw)<=32768
        plan_record=json.loads(plan_record_raw)
        assert type(plan_record)is dict and all(type(key)is str for key in plan_record)
        assert set(plan_record)=={'schemaVersion','scope','command','deliveryIdentitySha256','binding','planBase64','result','outcomeSha256','stageAcknowledged','fullInstallationCompleted','nativeQualified'}
        assert plan_record['schemaVersion']==1 and plan_record['scope']=='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY' and plan_record['command']=='plan-stage'
        delivery_identity=plan_record['deliveryIdentitySha256']
        assert type(delivery_identity)is str and len(delivery_identity)==64 and all(char in '0123456789abcdef' for char in delivery_identity)
        self.original_plan_record_raw=plan_record_raw
        request=json.loads(self.fx.request_raw);plan=json.loads(self.fx.plan);invocation=json.loads(self.fx.invocation_raw)
        assert all(type(value)is dict and len(value)<=32 and all(type(key)is str for key in value) for value in (request,plan,invocation))
        binding=plan_record['binding']
        assert type(binding)is dict and set(binding)=={'stage','requestSha256','releaseSha256','operationId','storeOperationId','planSha256'}
        assert binding['requestSha256']==sha(self.fx.request_raw)==plan['installationRequestSha256']==invocation['requestSha256']
        assert binding['releaseSha256']==request['releaseSha256']==sha(self.base.release_raw)==invocation['releaseSha256']
        assert binding['stage']==plan['stage']==invocation['stage'] and binding['planSha256'] is None
        assert invocation['planSha256']==sha(self.fx.plan)
        parent=invocation['parent'];assert type(parent)is list and len(parent)==7 and all(type(value)is str for value in parent)
        parent_input=self.fx.plan_cli._P.ParentInput.from_argv(parent)
        assert parent_input.request==binding['requestSha256'] and parent_input.stage==binding['stage'] and parent_input.action==plan['actionSha256']
        # This input preimage is an independent DATA expectation, not a plan field.
        self.input_preimage=self.fx.request_raw+self.fx.invocation_raw+self.fx.plan
        self.join.binding.update(requestSha256=binding['requestSha256'],releaseSha256=binding['releaseSha256'],
            deliveryIdentitySha256=delivery_identity,planSha256=sha(self.fx.plan),actionSha256=parent_input.action,
            inputSha256=sha(self.input_preimage),sourceSha256=sha(self.source_archive),
            stage=binding['stage'],session=parent_input.session)
        def at_write(fd,raw):
            cli=self.fx.execute_cli;assert cli is not None
            c_globals=vars(type(cli))['recheck'].__globals__
            assert id(cli) in c_globals['_CLOSED_OWNERS']
            assert raw==cli._observations[-1].completed_record()
            assert not self.fx.backend.handles and not self.fx.parent.descriptors and not self.fx.h.fds
            assert not any(row['path'] is not None for row in self.fx.r.handles.values())
            assert len(self.V._ISSUED_PLATFORM_SOURCES)==1
            hps=next(iter(self.V._ISSUED_PLATFORM_SOURCES));assert hps is not self.baseline_hps and hps.active
            assert hps.archive_bytes==self.source_archive
            self.publication_observations.append((raw,hps))
        self.fx.r.hooks['write']=at_write
    def module(self,label,path,pin=None):
        value=load(self.prefix+'_'+label,path,pin);self.loaded.append(value);return value
    def arguments(self):
        return dict(package_module=self.base.PB,delivery_module=self.base.D,cli_module=self.base.C,
            source_files_module=self.F,source_files=self.files,source_crypto_module=self.X,source_crypto=self.source_crypto,
            source_parameters=self.source_parameters,root=self.fx.signed.root,io_configuration=self.fx.io_configuration,
            crypto_configuration=self.fx.crypto_configuration,station=self.fx.station)
    def prepare(self,**changes):
        args=self.arguments();args.update(changes)
        self.owner=self.O.prepare_source_owned_execute(self.V,self.I,self.M,self.S,self.E,self.J,**args)
        return self.owner
    def permit(self,*,subject=None,role='execute',same_capture_subject=False):
        self.join.subjects['execute']=self.owner if subject is None else subject
        if same_capture_subject:self.join.subjects['capture']=self.owner
        execute,capture=self.join.exchange();return execute if role=='execute' else capture
    def counters(self):
        return (len(self.reader_state['calls']),len(self.reader_state['opens']),len(self.fx.h.starts),
            len(self.fx.r.writes),len(self.fx.native_calls),len(self.join.world.log),len(self.base.files.closed))
    def record(self):
        keeper,record=keeper_record(self.O);assert record['value'] is self.owner
        self.last_record=record;self.last_keeper=keeper;return keeper,record
    def keep_unknown(self):
        if self.O.UNRELEASED:keeper,record=self.record()
        else:
            keeper,record=self.last_keeper,self.last_record
            descriptor=type.__getattribute__(type(keeper),'__dict__')['_RetainedOwner__record']
            assert type(descriptor)is MemberDescriptorType and descriptor.__get__(keeper,type(keeper)) is record
        assert record['failed'] and record['primary'] is not None
        assert record['reader_unknown'] or record['child_attempted'] or record['enter_attempted'] and not record['entered'] or record['exit_attempted'] and not record['known_closed']
        self.kept=True;RETAINED.append((self,keeper,record))
    def dispose(self):
        if self.kept:return  # Exact asserted uncertainty only; no close/removal.
        if self.owner is not None:
            self.owner.abort();assert self.owner.require_released() is self.owner
        assert not self.base.files.held and not self.fx.h.fds
        self.fx.dispose()
        self.join.dispose()
        for value in self.loaded:
            if sys.modules.get(value.__name__) is value:del sys.modules[value.__name__]


class Controls(unittest.TestCase):
    def _callTestMethod(self,method):
        try:return unittest.TestCase._callTestMethod(self,method)
        except BaseException as primary:
            fixture=type.__getattribute__(Fixture,'__dict__').get('latest')
            try:raw=failure_observation(fixture,primary)
            except BaseException:
                # Keep only exact current test fixture refs; observer refusal is DATA.
                if type(fixture)is Fixture:
                    getter=type.__getattribute__(Fixture,'__dict__')['__dict__']
                    state=getter.__get__(fixture,Fixture);state['kept']=True
                    RETAINED.append((fixture,primary))
                raw=b'{"scope":"SOURCE_OWNER_TEST_FAILURE_METADATA_DATA_ONLY","diagnosticUnavailable":true,"cleanupQualified":false}'
            sys.stdout.write('SOURCE_OWNER_TEST_FAILURE_DATA='+raw.decode('ascii')+'\n')
            raise
    def fixture(self,**kwargs):
        value=Fixture(**kwargs);self.addCleanup(value.dispose);return value
    def denied(self,f,action):
        try:action()
        except f.O.SourceOwnerUnavailable as problem:return problem
        self.fail('original source owner did not refuse')
    def test_real_source_join_child_publication_then_original_source_exit(self):
        f=self.fixture();owner=f.prepare();self.assertIs(owner.open(),owner)
        hps=next(iter(f.V._ISSUED_PLATFORM_SOURCES));self.assertIsNot(hps,f.baseline_hps)
        result=owner.run(f.permit())
        self.assertEqual(len(f.fx.r.writes),1);raw=f.fx.r.writes[0][1]
        self.assertEqual(f.publication_observations,[(raw,hps)])
        self.assertEqual(result['publication']['publication']['recordSha256'],sha(raw))
        self.assertEqual(result['publication']['publication']['recordBytes'],len(raw))
        self.assertFalse(hps.active or f.V._ISSUED_PLATFORM_SOURCES or f.V.UNRELEASED_HANDLES or f.base.files.held)
        self.assertIs(owner.require_released(),owner)
        self.assertFalse(any(result[key] for key in ('initialOriginsQualified','completeCopyGraphQualified','bashWaitObserved','streamEofObserved','recordDurablyStored','executionEvidenceIssued','stageAcknowledged')))
    def test_successful_terminal_repeats_never_recheck_expired_source_or_run_child(self):
        f=self.fixture();owner=f.prepare();owner.open();permit=f.permit();result=owner.run(permit)
        counters=f.counters();self.denied(f,owner.open);self.denied(f,lambda:owner.run(permit))
        self.assertIs(owner.abort(),owner);self.assertIs(owner.require_released(),owner)
        self.assertEqual(f.counters(),counters)
        _,record=f.record();self.assertIs(record['result'],result);self.assertIs(record['publication'],result['publication'])
        self.assertIs(record['exit_return'],False);self.assertTrue(record['known_closed'])
    def test_valid_open_clean_abort_is_once_only_and_repeat_observation_has_no_effect(self):
        f=self.fixture();owner=f.prepare();owner.open();hps=next(iter(f.V._ISSUED_PLATFORM_SOURCES))
        self.assertIs(owner.abort(),owner);self.assertFalse(hps.active or f.base.files.held)
        counters=f.counters();self.assertIs(owner.abort(),owner);self.assertIs(owner.require_released(),owner)
        self.denied(f,owner.open);self.denied(f,lambda:owner.run(object()));f.O.UNRELEASED.clear()
        self.assertIs(owner.abort(),owner);self.assertEqual(f.counters(),counters)
    def test_wrong_subject_private_permit_refusal_can_only_abort_before_child(self):
        f=self.fixture();owner=f.prepare();owner.open();permit=f.permit(subject=object())
        self.denied(f,lambda:owner.run(permit));keeper,record=f.record()
        primary=record['primary'][1];self.assertFalse(record['child_attempted']);self.assertIs(record['hps'],next(iter(f.V._ISSUED_PLATFORM_SOURCES)))
        f.O.UNRELEASED.clear();counters=f.counters();self.denied(f,lambda:owner.run(permit));self.assertEqual(f.counters(),counters)
        self.assertIs(record['primary'][1],primary);self.assertIs(owner.abort(),owner);self.assertIs(owner.require_released(),owner)
        self.assertTrue(record['known_closed']);self.assertIs(record['exit_return'],False)
    def test_capture_role_permit_same_subject_still_cannot_execute(self):
        f=self.fixture();owner=f.prepare();owner.open();permit=f.permit(role='capture',same_capture_subject=True)
        self.denied(f,lambda:owner.run(permit));_,record=f.record()
        self.assertFalse(record['child_attempted'] or f.fx.r.writes);self.assertIs(owner.abort(),owner)
    def test_public_permit_clone_is_not_a_private_startup_issuer(self):
        f=self.fixture();owner=f.prepare();owner.open()
        clone=object.__new__(f.J.RolePermit);self.denied(f,lambda:owner.run(clone))
        _,record=f.record();self.assertFalse(record['child_attempted']);self.assertIs(owner.abort(),owner)
    def test_public_owner_clone_and_unconfigured_main_have_zero_reader_effects(self):
        f=self.fixture();clone=object.__new__(f.O.SourceOwnedExecute);counters=f.counters()
        self.denied(f,clone.open);self.denied(f,clone.abort);self.denied(f,lambda:f.O.main([]))
        self.assertEqual(f.counters(),counters);self.assertFalse(f.O.UNRELEASED)
    def test_borrowed_foreign_truthiness_never_runs_and_no_native_default_selected(self):
        f=self.fixture(crypto_bool=True);owner=f.prepare();owner.open();owner.abort()
        self.assertFalse(f.reader_state['boolCalls'] or f.crypto_truthiness)
        self.assertGreater(len(f.reader_state['opens']),0);self.assertIs(owner.require_released(),owner)
        self.assertFalse(f.base.files.held or f.fx.h.fds)
    def test_foreign_input_dictionary_key_refuses_before_callback_or_ownership(self):
        f=self.fixture();calls=[]
        class Key:
            def __hash__(self):calls.append('hash');return hash('directory')
            def __eq__(self,other):calls.append('eq');return other=='directory'
        params=dict(f.source_parameters);value=params.pop('directory');params[Key()]=value;calls.clear()
        counters=f.counters();self.denied(f,lambda:f.prepare(source_parameters=params))
        self.assertFalse(calls or f.O.UNRELEASED);self.assertEqual(f.counters(),counters)
    def test_saved_helper_attribute_drift_denies_before_source_open_then_known_abort(self):
        f=self.fixture();owner=f.prepare();original=f.I.prepare_authenticated_cli_inputs
        original.foreign_marker=object();counters=f.counters()
        try:self.denied(f,owner.open)
        finally:del original.foreign_marker
        self.assertEqual(f.counters(),counters);self.assertIs(owner.abort(),owner);self.assertIs(owner.require_released(),owner)
    def test_unreturned_reader_open_keeps_actual_error_and_never_guesses_exit(self):
        f=self.fixture();marker=OSError('public RAM unreturned acquisition');f.reader_state['openError']=marker
        owner=f.prepare();self.denied(f,owner.open);_,record=f.record()
        self.assertTrue(record['reader_unknown'] and record['enter_attempted']);self.assertFalse(record['entered'])
        self.assertIs(record['last_reader_error'][1],marker);self.assertIsNotNone(record['cm'])
        counters=f.counters();self.denied(f,owner.abort);self.assertEqual(f.counters(),counters);f.keep_unknown()
    def test_opaque_open_return_is_retained_without_foreign_getter_or_close(self):
        f=self.fixture();calls=[]
        class Opaque:
            @property
            def __class__(self):calls.append('getter');raise AssertionError('foreign getter')
        opaque=Opaque();f.reader_state['opaque']=opaque;owner=f.prepare();self.denied(f,owner.open)
        _,record=f.record();self.assertIs(record['unknown_reader_return'],opaque);self.assertTrue(record['reader_unknown'])
        self.assertFalse(calls);self.assertFalse(any(call[0]=='close' for call in f.reader_state['calls']))
        self.assertFalse(record['reader_rows']);f.keep_unknown()
    def test_post_open_drift_retains_undelivered_fd_even_with_empty_verifier_ledger(self):
        f=self.fixture();f.reader_state['postOpen']=lambda fd:setattr(f.O,'foreign_binding',object())
        owner=f.prepare()
        try:self.denied(f,owner.open)
        finally:del f.O.foreign_binding
        keeper,record=f.record();row=record['reader_rows'][0]
        self.assertIs(row['returned'],f.reader_state['opens'][0]);self.assertFalse(row['delivered_to_verifier'])
        self.assertIsNotNone(row['postguard_error']);self.assertTrue(record['reader_unknown'])
        self.assertIn(row['fd'],f.base.files.held);self.assertNotIn(row['fd'],f.base.files.closed)
        counters=f.counters();f.O.UNRELEASED.clear();self.denied(f,owner.abort);self.assertEqual(f.counters(),counters)
        self.assertIs(f.last_keeper,keeper);f.keep_unknown()
    def test_cap_full_live_alias_marks_old_row_ambiguous_before_refusal(self):
        f=self.fixture();owner=f.prepare();owner.open();hps,view=live_reader_view(f.V)
        while len(f.reader_state['opens'])<512:view.open(None,str(f.base.bundle),True)
        first=f.reader_state['opens'][0];f.reader_state['aliasFD']=first
        self.denied(f,lambda:view.open(None,str(f.base.bundle),True));self.denied(f,owner.abort)
        _,record=f.record();self.assertEqual(len(record['reader_rows']),512)
        matches=[row for row in record['reader_rows'] if row['fd']==first]
        self.assertTrue(matches and all(row['ambiguous'] for row in matches));self.assertTrue(record['reader_unknown'])
        self.assertNotIn(first,f.base.files.closed);self.assertIn(first,f.base.files.held);f.keep_unknown()
    def test_original_child_partial_write_retains_borrowers_and_forbids_source_exit(self):
        f=self.fixture();owner=f.prepare();owner.open();permit=f.permit();f.fx.r.write_results=[1]
        self.denied(f,lambda:owner.run(permit));_,record=f.record()
        self.assertTrue(record['child_attempted']);self.assertFalse(record['child_success'] or record['exit_attempted'])
        self.assertEqual(len(f.fx.r.writes),1);self.assertEqual(f.fx.r.writes[0][1],f.fx.execute_cli._observations[-1].completed_record())
        self.assertIsNotNone(record['child']);self.assertIsNotNone(record['preparation'])
        primary=record['primary'][1];counters=f.counters();self.denied(f,owner.abort)
        self.assertIs(record['primary'][1],primary);self.assertIsNotNone(record['cleanup_error']);self.assertEqual(f.counters(),counters);f.keep_unknown()
    def test_original_source_close_failure_retains_primary_and_never_retries(self):
        f=self.fixture();owner=f.prepare();owner.open();fd=next(iter(f.base.files.held))
        marker=OSError('public RAM source close uncertainty');f.reader_state.update(failClose=fd,closeError=marker)
        self.denied(f,owner.abort);_,record=f.record();self.assertTrue(record['reader_unknown'] and record['exit_attempted'])
        self.assertIsNotNone(record['exit_error']);primary=record['primary'][1]
        self.assertTrue(any(row['fd']==fd and row['attempted'] and row['close_error'] is marker for row in record['reader_rows']))
        attempts=sum(call[0]=='close' and call[1]==fd for call in f.reader_state['calls']);self.assertEqual(attempts,1)
        counters=f.counters();self.denied(f,owner.abort);self.assertEqual(f.counters(),counters)
        self.assertIs(record['primary'][1],primary);self.assertIsNotNone(record['cleanup_error']);f.keep_unknown()
    def test_actual_source_exit_return_survives_later_original_boundary_denial(self):
        f=self.fixture();owner=f.prepare();owner.open();result=owner.run(f.permit())
        f.O.foreign_binding=object()
        try:self.denied(f,owner.require_released)
        finally:del f.O.foreign_binding
        _,record=f.record();self.assertIs(record['result'],result);self.assertIs(record['exit_return'],False)
        self.assertIs(record['publication'],result['publication']);self.assertTrue(record['known_closed'])
        counters=f.counters();self.assertIs(owner.abort(),owner);self.assertIs(owner.require_released(),owner);self.assertEqual(f.counters(),counters)


if __name__=='__main__':unittest.main(verbosity=2)
