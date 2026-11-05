"""Genuine F/V/S/P with original B/M/C; injected protected IO only.

No accepted tests are run here. Existing fixture definitions supply the bounded
fake files/crypto and original-parent model. Logical /opt translation and the
encrypted-proof adapter are installed before trusted capture, never in shipped
code or by mutating an issued assembly. External ancestry is quiet before hold.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import stat
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    import importlib.util
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


W=load('retention_worker_under_test',ROOT/'deploy/installer/company_full_retention_worker.py')
E=load('worker_retention_effects_original',ROOT/'deploy/installer/company_retention_effects.py')
ST=load('retention_stage_fixtures',ROOT/'tests/test_company_stage_scope.py')
CT=load('retention_source_fixtures',ROOT/'tests/test_company_source_tree.py')
S,F,PT,T=ST.S,ST.F,ST.PT,CT.T
ADAPTERS=sys.modules[__name__]
MALICIOUS_CALLS=[]


def forbidden_parent_close(value):
    MALICIOUS_CALLS.append(value)
    raise AssertionError('changed parent close must never run')


class SeedBackend(T.SeedBackend):
    def close(self,fd):
        node=self.handles[fd]
        if getattr(self,'parent_drift',None) and node is self.nodes['/etc/autosoft/installation.intent.json']:
            cls=self.parent_drift.pop()
            self.parent_restore.append((cls,cls.close))
            cls.close=forbidden_parent_close
        return T.SeedBackend.close(self,fd)
    def require_released(self):
        if self.handles:raise ValueError('backend-handles-live')
        return self


class SeedRunner(T.SeedRunner):
    def require_released(self):
        if self.unknown:raise ValueError('runner-release-unknown')
        return self


class ParentSystem(PT.FakeSystem):
    def __init__(self):
        super().__init__();self.unknown=[]
    def close(self,fd):
        self.closed.append(fd)
        if self.close_error==fd:
            self.unknown.append(fd)
            raise OSError('parent-close-unknown')
        del self.descriptors[fd]
    def require_released(self):
        if self.descriptors or self.unknown:raise ValueError('parent-release-unknown')
        return self


class Fixture:
    configured_stage=ST.StageScopeControls.configured
    def __init__(self):
        self.f,self.clock=ST.T.Fixture(),ST.Clock()
        initial=T.Fixture();initial.files.close();initial.storage.active=False
        self.backend=SeedBackend();vars(self.backend).update(vars(initial.backend))
        self.backend.parent_drift=[];self.backend.parent_restore=[]
        self.runner=SeedRunner(self.backend)
        self.backend.chmod_calls=[];self.backend.fail_chmod=False;self.backend.after_chmod=None
        self.backend.pread_calls=[];self.backend.pread_hook=None
        self.data,self.global_op,self.store_op,self.source_op=initial.DATA,'b'*32,'1'*32,'2'*32
        self.install=self.data+'/company/host-releases/install-'+self.global_op
        for name in ('host-releases','platform-releases','source-releases'):
            self.backend.directory(self.data+'/company/'+name,mode=0o700)
        self.backend.directory(self.install,mode=0o700)
        for leaf in ('installation.intent.json','installation.json','installation.storage-receipt.json'):
            path='/etc/autosoft/'+leaf;value=json.loads(self.backend.nodes[path]['raw'])
            (value['proposal'] if leaf=='installation.intent.json' else value)['install_root']=self.install
            self.backend.file(path,W.canonical(value))
        self.mount=initial.mount
        self.entry=self.system=None
    @contextmanager
    def configured(self):
        original=F._register
        def register(path,*args,**kw):
            module=original(path,*args,**kw)
            if path==F.LOADER:
                original_L=module._register
                def register_L(member,*a,**options):
                    captured=original_L(member,*a,**options)
                    if member==W.STARTUP:
                        def encrypted(data,receipt,command):
                            assert str(data).replace('\\','/')==self.data
                            assert receipt['storage_file']=='/srv/backing.luks'
                            return json.loads(json.dumps(self.mount))
                        captured.encrypted_proof=encrypted
                    return captured
                module._register=register_L
            return module
        with patch.object(F,'_register',side_effect=register), self.configured_stage() as (entry,args):
            self.request.update(dataDir=self.data,backingFile='/srv/backing.luks',capacityGiB=32)
            raw=W.canonical(self.request)
            self.args=dict(entry=entry,full_entry_module=F,stage_module=S,request_raw=raw,
                request_sha256=W.sha(raw),operational_catalog=self.f.catalog,
                key_fingerprint=self.f.q.fingerprint,expected_architecture='amd64',
                files=self.f.q.files,crypto=self.f.q.crypto,backend_module=ADAPTERS,backend=self.backend,
                runner_module=ADAPTERS,runner=self.runner,clock=self.clock)
            P=entry.modules[F.PARENT]
            template=P.ParentInput(42,11,12,'s-Abc123Def456',self.args['request_sha256'],W.STAGES[0],'c'*64)
            with patch.object(PT,'P',P),patch.object(PT,'ARGS',template):
                self.system=ParentSystem();self.P=P;self.session=P.BASE+'/sessions/'+template.session
                old=self.session+'/'+template.stage+'.intent'
                self.system.bodies.pop(self.system.metas.pop(old).st_ino)
                yield self
    def plan(self,stage=W.STAGES[0],**changes):
        args=dict(self.args,operation_id=self.store_op if stage==W.STAGES[0] else self.source_op,
                  store_operation_id=self.store_op);args.update(changes)
        return W.plan_stage(stage,**args)
    def prepare(self,stage,plan):
        assert not self.system.descriptors
        action=json.loads(plan)['actionSha256']
        self.system.add(self.session+'/'+stage+'.intent',self.system.stage(stage,action))
        return self.P.ParentInput(42,11,12,'s-Abc123Def456',self.args['request_sha256'],stage,action)
    def execute(self,stage,plan,**changes):
        parent=self.prepare(stage,plan)
        args=dict(self.args,operation_id=self.store_op if stage==W.STAGES[0] else self.source_op,
            store_operation_id=self.store_op,expected_plan=plan,parent_arguments=parent,
            parent_system_module=ADAPTERS,parent_system=self.system)
        args.update(changes);return W.execute_stage(stage,**args)
    def verify(self,stage,plan,outcome_sha,**changes):
        # Reacquire the actual existing pending intent; no duplicate intent,
        # confirmation, writer replay or synthetic parent instance is made.
        parent=self.P.ParentInput(42,11,12,'s-Abc123Def456',self.args['request_sha256'],
            stage,json.loads(plan)['actionSha256'])
        args=dict(self.args,operation_id=self.store_op if stage==W.STAGES[0] else self.source_op,
            store_operation_id=self.store_op,expected_plan=plan,expected_outcome_sha256=outcome_sha,
            effect_verifier_module=E,parent_arguments=parent,parent_system_module=ADAPTERS,parent_system=self.system)
        args.update(changes);return W.verify_stage(stage,**args)
    def released(self):
        assert not self.backend.handles and not self.system.descriptors
        V=self.entry.modules[F.VERIFIER]
        assert not V._ISSUED_PLATFORM_SOURCES and not self.f.q.files.records and not self.f.q.files.dirs
        assert not S._COORDINATORS and not S._SCOPES
    def confirm_store(self,result):
        self.released();root=result['root'];nodes=self.backend.nodes
        verified=json.loads(nodes[root+'/verified.json']['raw']);intent=json.loads(nodes[root+'/intent.json']['raw'])
        originals={name:(self.f.q.bundle/name).read_bytes() for name in CT.M.CONFIGS}
        originals.update({name:(self.f.q.bundle/name).read_bytes() for name in (CT.M.ARCHIVE,'release.json','release.sig')})
        originals['company-signing-public-key.pem']=self.f.q.public.read_bytes()
        assert set(n[len(root)+1:] for n in nodes if n.startswith(root+'/'))=={'intent.json','verified.json',*originals}
        assert stat.S_IMODE(nodes[root]['info']['st_mode'])==0o500
        for name,raw in originals.items():
            assert nodes[root+'/'+name]['raw']==raw and stat.S_IMODE(nodes[root+'/'+name]['info']['st_mode'])==0o400
        assert result==dict(verified,root=root,ownedStoreHandlesReleased=True,
            outerSourceParentStorageContextsRequireClosure=True,executionAuthorized=False)
        assert intent['request']['installationRequestSha256']==self.args['request_sha256']
        self.system.add(self.session+'/'+W.STAGES[0]+'.confirmed',PT.encoded('install-stage-confirmed-v1',
            session='s-Abc123Def456',stage=W.STAGES[0],action=intent['actionSha256'],
            outcome=W.sha(W.canonical(result)),independently_confirmed='true'))
    def clean(self):
        # Synthetic failure disposal is test-only. Product offers no retry/reset.
        for cls,original in self.backend.parent_restore:cls.close=original
        self.backend.parent_restore.clear()
        self.backend.fail_close=None
        for fd in list(self.backend.handles):self.backend.close(fd)
        if self.system is not None:
            self.system.close_error=None
            for fd in list(self.system.descriptors):self.system.close(fd)
            self.system.unknown.clear()
        for row in W.UNRELEASED:
            if len(row)>1 and row[1]=='retention-context-release-unknown':
                cms=row[2:6]
                for cm in reversed(cms):
                    if cm is not None:
                        try:cm.__exit__(None,None,None)
                        except BaseException:pass
        if self.f.q is not None:
            self.f.q.files.fail_close=None
            for fd in list(self.f.q.files.records)+list(self.f.q.files.dirs):self.f.q.files.close(fd)
        self.f.clean();W.UNRELEASED.clear();S.UNRELEASED.clear();F.UNRELEASED.clear()


class EarlyControls(unittest.TestCase):
    def setUp(self):W.UNRELEASED.clear()
    def tearDown(self):W.UNRELEASED.clear()
    def test_closed_plan_schema_canonical_types_and_cap(self):
        value=dict(schemaVersion=1,scope='RETENTION_STAGE_PLAN_ONLY',stage=W.STAGES[0],
            installationRequestSha256='a'*64,operationId='b'*32,storeOperationId='b'*32,
            stageRequest={},stageRequestSha256='c'*64,actionSha256='d'*64)
        self.assertEqual(W._plan(W.canonical(value)),value)
        for raw in (W.canonical(dict(value,schemaVersion=True)),W.canonical(dict(value,extra=True)),
                    W.canonical(value)+b' ',b'['*2000,b'x'*(W.MAX_PLAN+1)):
            with self.assertRaises(ValueError):W._plan(raw)
    def test_invalid_stage_operations_and_sticky_unknown_deny(self):
        for args in (('other','a'*32,'a'*32), (W.STAGES[0],'a'*32,'b'*32), (W.STAGES[1],'A'*32,'a'*32)):
            with self.assertRaises(ValueError):W._inputs(*args,lambda:1)
        marker=object();W.UNRELEASED.append(marker)
        with self.assertRaises(ValueError):W._inputs(W.STAGES[0],'a'*32,'a'*32,lambda:1)
        self.assertIs(W.UNRELEASED[0],marker)
    def test_release_adapter_requires_exact_concrete_class_and_return(self):
        module=ModuleType('fixed_release_test')
        class Backend:
            def require_released(self):return True
        module.SeedBackend=Backend
        backend=Backend()
        with self.assertRaises(ValueError):W._Adapter(module,backend,'SeedBackend')
        self.assertIs(W.UNRELEASED[-1][2],backend)
        self.assertIs(W.UNRELEASED[-1][3],Backend.require_released)
    def test_changed_release_helper_is_not_invoked_and_reference_retained(self):
        module=ModuleType('fixed_release_test')
        class Backend:
            def require_released(self):return self
        module.SeedBackend=Backend;backend=Backend();adapter=W._Adapter(module,backend,'SeedBackend');calls=[]
        def malicious(value):calls.append(value);return value
        Backend.require_released=malicious
        with self.assertRaises(ValueError):adapter.require_released()
        self.assertEqual(calls,[]);self.assertIs(W.UNRELEASED[-1][2],backend)
    def test_instance_callback_drift_denies_before_release(self):
        module=ModuleType('fixed_release_test')
        class Backend:
            def require_released(self):return self
        module.SeedBackend=Backend;backend=Backend();adapter=W._Adapter(module,backend,'SeedBackend');calls=[]
        backend.close=lambda fd:calls.append(fd)
        with self.assertRaises(ValueError):adapter.require_released()
        self.assertEqual(calls,[])


class CompositionControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(W.UNRELEASED);self.fixtures=[]
    def tearDown(self):
        for f in self.fixtures:f.clean()
    def fixture(self):
        f=Fixture();self.fixtures.append(f);return f
    def test_real_store_then_confirmed_source_untouched_outcome_and_all_closures(self):
        f=self.fixture()
        with f.configured():
            plan=f.plan();self.assertEqual(f.backend.effects,[]);f.released()
            stored=f.execute(W.STAGES[0],plan);result=stored['operationResult'];f.released()
            self.assertEqual(stored['operationOutcomeSha256'],W.sha(W.canonical(result)))
            self.assertEqual(json.loads(plan)['stageRequestSha256'],result['requestSha256'])
            self.assertFalse(stored['effectsIndependentlyConfirmed']);self.assertFalse(stored['stageAcknowledged'])
            self.assertFalse(stored['nativeAuthorized']);self.assertTrue(stored['ownedResourcesKnownReleased'])
            self.assertNotIn(f.session+'/'+W.STAGES[0]+'.confirmed',f.system.metas)
            # The writer returns no confirmation. This independent parent
            # fixture rereads all actual twelve sealed leaves after release.
            f.confirm_store(result)
            source_plan=f.plan(W.STAGES[1]);f.released()
            source=f.execute(W.STAGES[1],source_plan);f.released()
            output=source['operationResult'];self.assertEqual(source['operationOutcomeSha256'],W.sha(W.canonical(output)))
            self.assertTrue(output['companyArtifactStoreRechecked']);self.assertTrue(output['ownedSourceHandlesReleased'])
            self.assertFalse(source['stageAcknowledged']);self.assertFalse(source['nativeAuthorized'])
            self.assertEqual(f.source_calls,[tuple(f.source_calls[0])]*4)
            self.assertEqual(f.native_calls,[])
            self.assertNotIn('/etc/autosoft/storage.key',f.backend.reads)
            self.assertNotIn('/srv/backing.luks',f.backend.reads)
    def test_wrong_replanned_action_and_geometry_deny_before_output(self):
        f=self.fixture()
        with f.configured():
            plan=f.plan();changed=json.loads(plan);changed['actionSha256']='f'*64
            with self.assertRaises(ValueError):f.execute(W.STAGES[0],W.canonical(changed))
            self.assertEqual(f.backend.effects,[]);f.released()
            request=dict(f.request,capacityGiB=64);raw=W.canonical(request)
            with self.assertRaises(ValueError):f.plan(request_raw=raw,request_sha256=W.sha(raw))
            self.assertEqual(f.backend.effects,[]);f.released()
    def test_failed_parent_acquisition_rechecks_system_and_preserves_no_output(self):
        f=self.fixture()
        with f.configured():
            plan=f.plan();f.system.missing_pidfd=True
            with self.assertRaises(ValueError):f.execute(W.STAGES[0],plan)
            self.assertEqual(f.backend.effects,[]);f.released();self.assertFalse(W.UNRELEASED)
    def test_failed_parent_acquisition_unknown_close_retains_exact_system_and_contexts(self):
        f=self.fixture()
        with f.configured():
            plan=f.plan();f.system.missing_pidfd=True
            # First owned P directory handle; failure preserves the adapter FD
            # registry even though original HeldParent clears its own handles.
            f.system.close_error=f.system.next_fd+1
            with self.assertRaisesRegex(ValueError,'release-unknown'):f.execute(W.STAGES[0],plan)
            self.assertTrue(f.system.descriptors);self.assertTrue(f.system.unknown)
            self.assertTrue(any(row[1]=='parent-system-release-unknown' and row[2] is f.system for row in W.UNRELEASED))
            self.assertEqual(f.backend.effects,[])
            self.assertTrue(f.f.q.files.records or f.f.q.files.dirs)
            f.clean() # Dispose synthetic retained uncertainty while F is live.
    def test_active_writer_denies_and_all_known_contexts_close(self):
        f=self.fixture()
        with f.configured():
            f.runner.active_unit=True
            with self.assertRaises(ValueError):f.plan()
            self.assertEqual(f.backend.effects,[]);f.released()
    def test_active_writer_constructor_unknown_close_is_retained_without_retry(self):
        f=self.fixture()
        # Uncertain closure also denies the outer entry's successful return.
        with self.assertRaisesRegex(ValueError,'company-full-entry-unavailable'):
            with f.configured():
                f.runner.active_unit=True
                failed=f.backend.next_fd+1
                f.backend.fail_close=failed
                with self.assertRaisesRegex(ValueError,'release-unknown'):f.plan()
                self.assertEqual(f.backend.close_attempts.count(failed),1)
                self.assertIn(failed,f.backend.handles)
                self.assertTrue(W.UNRELEASED)
                self.assertTrue(f.f.q.files.records or f.f.q.files.dirs)
                self.assertEqual(f.backend.effects,[])
                f.clean() # Synthetic disposal only; the product has no retry/reset.
    def test_source_without_original_store_confirmation_denies_before_effect(self):
        f=self.fixture()
        with f.configured():
            plan=f.plan(W.STAGES[1])
            # Planning derives the exact expected Store result without a parent
            # record. Effectful original Source still requires the held prior.
            with self.assertRaises(ValueError):f.execute(W.STAGES[1],plan)
            self.assertEqual(f.backend.effects,[]);f.released()


class CleanupBoundaryControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(W.UNRELEASED);MALICIOUS_CALLS.clear();self.fixtures=[]
    def tearDown(self):
        for f in self.fixtures:f.clean()
    def fixture(self):
        f=Fixture();self.fixtures.append(f);return f
    @contextmanager
    def resources(self,f):
        args=f.args
        with S.stage_coordinator(f.entry,**{k:args[k] for k in ('full_entry_module','request_raw',
            'request_sha256','operational_catalog','key_fingerprint','expected_architecture','files','crypto','clock')},
            stages=(W.STAGES[0],)) as coordinator:
            with coordinator.source_stage(W.STAGES[0]) as scope,scope.assembly() as assembly:
                resources=W._Resources(assembly,scope,W._Adapter(ADAPTERS,f.backend,'SeedBackend'),
                    W._Adapter(ADAPTERS,f.runner,'SeedRunner'),f.clock)
                resources.build(coordinator._request)
                yield resources
    def test_bootstrap_close_drift_retains_owned_files_without_changed_callback(self):
        f=self.fixture()
        with f.configured(),self.resources(f) as resources:
            original=resources.B.SeedFiles.close;owned=tuple(resources.files.owned);calls=[]
            def malicious(value):calls.append(value)
            resources.B.SeedFiles.close=malicious
            try:
                with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
                self.assertEqual(calls,[]);self.assertEqual(tuple(resources.files.owned),owned)
                self.assertTrue(f.backend.handles)
                self.assertTrue(any(row[1]=='seed-files-release-unknown' and row[2] is resources.files for row in W.UNRELEASED))
            finally:
                resources.B.SeedFiles.close=original;original(resources.files)
                W.UNRELEASED.clear() # Explicit synthetic uncertainty disposal.
            self.assertEqual(len(f.backend.close_attempts),len(set(f.backend.close_attempts)))
    def test_backend_close_drift_retains_exact_adapter_without_changed_callback(self):
        f=self.fixture()
        with f.configured(),self.resources(f) as resources:
            original=SeedBackend.close;owned=tuple(resources.files.owned);calls=[]
            def malicious(value,fd):calls.append(fd)
            SeedBackend.close=malicious
            try:
                with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
                self.assertEqual(calls,[]);self.assertEqual(tuple(resources.files.owned),owned)
                self.assertTrue(any(row[1]=='adapter-release-unknown' and row[2] is f.backend for row in W.UNRELEASED))
            finally:
                SeedBackend.close=original;resources.classes['SeedFiles']['close'](resources.files)
                W.UNRELEASED.clear()
            self.assertFalse(f.backend.handles)
    def test_parent_close_drift_after_operation_preserves_output_no_callback_or_ack(self):
        f=self.fixture()
        with f.configured():
            plan=f.plan();f.backend.parent_drift.append(f.P.HeldParent)
            with self.assertRaisesRegex(ValueError,'release-unknown'):f.execute(W.STAGES[0],plan)
            self.assertEqual(MALICIOUS_CALLS,[]);self.assertFalse(f.backend.handles)
            self.assertTrue(f.system.descriptors)
            root=f.data+'/company/platform-releases/'+f.request['releaseSha256']
            self.assertIn(root+'/verified.json',f.backend.nodes)
            self.assertNotIn(f.session+'/'+W.STAGES[0]+'.confirmed',f.system.metas)
            retained=[row for row in W.UNRELEASED if row[1]=='retention-context-release-unknown']
            self.assertTrue(retained);self.assertIs(retained[-1][9].system,f.system)
            self.assertTrue(f.f.q.files.records or f.f.q.files.dirs)
            f.clean()
    def test_resource_setattr_drift_cannot_run_during_expiration(self):
        f=self.fixture()
        with f.configured(),self.resources(f) as resources:
            classes=(resources.B.SeedStorage,resources.B.SeedCommands);calls=[]
            def malicious(value,name,item):calls.append((value,name,item))
            for cls in classes:cls.__setattr__=malicious
            try:
                with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
                self.assertEqual(calls,[])
                self.assertIs(resources.storage_state['active'],False)
                self.assertIs(resources.commands_state['active'],False)
                self.assertTrue(f.backend.handles)
                self.assertTrue(any(row[1]=='owned-resource-release-unknown' and row[0] is resources for row in W.UNRELEASED))
            finally:
                for cls in classes:del cls.__setattr__
                resources.classes['SeedFiles']['close'](resources.files)
                W.UNRELEASED.clear()
    def test_foreign_resource_preserves_original_reference_and_closes_known_files(self):
        f=self.fixture()
        with f.configured(),self.resources(f) as resources:
            original=resources.storage;calls=[]
            class Foreign:
                def __setattr__(self,name,value):calls.append((name,value))
            foreign=Foreign();resources.storage=foreign
            with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
            self.assertEqual(calls,[]);self.assertFalse(f.backend.handles)
            retained=[row for row in W.UNRELEASED if row[1]=='resource-expiration-unknown']
            self.assertTrue(retained);self.assertIs(retained[-1][2],original);self.assertIs(retained[-1][4],foreign)
            self.assertIs(resources.storage_state['active'],False)
            W.UNRELEASED.clear()
    def test_opaque_state_replacement_retained_without_setitem_and_known_files_closed(self):
        f=self.fixture()
        with f.configured(),self.resources(f) as resources:
            calls=[];original=resources.storage_state
            class Opaque:
                def __setitem__(self,name,value):calls.append((name,value))
            opaque=Opaque();resources.storage_state=opaque
            with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
            self.assertEqual(calls,[]);self.assertFalse(f.backend.handles)
            retained=[row for row in W.UNRELEASED if row[1]=='resource-expiration-unknown']
            self.assertTrue(retained);self.assertIs(retained[-1][6],opaque)
            self.assertIs(resources.storage_state_original,original)
            self.assertIs(resources.commands_state['active'],False)
            W.UNRELEASED.clear() # Dispose synthetic uncertainty only.

    def test_replaced_seed_files_retains_original_without_foreign_callbacks(self):
        f=self.fixture()
        with f.configured(),self.resources(f) as resources:
            original,state,owned=resources.files,resources.files_state,resources.files_owned;calls=[]
            class Foreign:
                def __getattribute__(self,name):calls.append(('get',name));raise AssertionError('foreign attribute')
                def __setattr__(self,name,value):calls.append(('set',name));raise AssertionError('foreign setter')
            foreign=Foreign();resources.files=foreign;before=list(f.backend.close_attempts)
            try:
                with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
                self.assertEqual(calls,[]);self.assertEqual(f.backend.close_attempts,before)
                self.assertTrue(f.backend.handles);self.assertIs(resources.commands_state['active'],False)
                retained=[r for r in W.UNRELEASED if r[1]=='seed-files-release-unknown']
                self.assertTrue(retained);self.assertIs(retained[-1][2],foreign)
                self.assertIs(retained[-1][5],original);self.assertIs(retained[-1][6],state);self.assertIs(retained[-1][7],owned)
            finally:
                resources.classes['SeedFiles']['close'](original);W.UNRELEASED.clear()
    def test_opaque_seed_owned_list_never_iterated_or_closed(self):
        f=self.fixture()
        with f.configured(),self.resources(f) as resources:
            original=resources.files_owned;calls=[]
            class Opaque:
                def __iter__(self):calls.append('iter');raise AssertionError('opaque iteration')
                def __len__(self):calls.append('len');raise AssertionError('opaque length')
            opaque=Opaque();resources.files_state['owned']=opaque;before=list(f.backend.close_attempts)
            try:
                with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
                self.assertEqual(calls,[]);self.assertEqual(f.backend.close_attempts,before)
                retained=[r for r in W.UNRELEASED if r[1]=='seed-files-release-unknown']
                self.assertTrue(retained);self.assertIs(retained[-1][7],original)
                self.assertIs(retained[-1][6]['owned'],opaque);self.assertTrue(f.backend.handles)
            finally:
                resources.files_state['owned']=original
                resources.classes['SeedFiles']['close'](resources.files);W.UNRELEASED.clear()
    def test_malformed_seed_owned_integers_duplicates_and_cap_deny_close(self):
        for invalid in ([True],[None],[-1],[7,7],list(range(W.MAX_SEED_HANDLES+1))):
            with self.subTest(sample=type(invalid[0]).__name__,size=len(invalid)):
                f=self.fixture()
                with f.configured(),self.resources(f) as resources:
                    original=resources.files_owned;before=list(f.backend.close_attempts)
                    original_handles=list(original);original[:]=invalid
                    try:
                        with self.assertRaisesRegex(ValueError,'owned-release-unknown'):resources.close()
                        self.assertEqual(f.backend.close_attempts,before);self.assertTrue(f.backend.handles)
                        self.assertTrue(any(r[1]=='seed-files-release-unknown' and r[7] is original for r in W.UNRELEASED))
                    finally:
                        original[:]=original_handles
                        resources.classes['SeedFiles']['close'](resources.files);W.UNRELEASED.clear()


class EffectBoundaryControls(unittest.TestCase):
    def setUp(self):self.assertFalse(W.UNRELEASED);self.assertFalse(E.UNRELEASED)
    def tearDown(self):W.UNRELEASED.clear();E.UNRELEASED.clear()
    def test_exact_effect_observer_schema_hash_and_boolean_types(self):
        binding=W._Effects(E);original=dict(outcome='original');digest=W.sha(W.canonical(original))
        value=dict(operationResult=original,operationOutcomeSha256=digest,exactEffectsReread=True,
            ownedReadHandlesKnownReleased=True,outerContextsRequireClosure=True,stageAcknowledged=False,nativeQualified=False)
        self.assertIs(binding.result(value,digest),value)
        for changed in (dict(value,extra=True),dict(value,exactEffectsReread=1),dict(value,stageAcknowledged=0),
                        dict(value,operationOutcomeSha256='a'*64),dict(value,operationResult=dict(outcome='changed'))):
            with self.assertRaises(ValueError):binding.result(changed,digest)
        self.assertFalse(W.UNRELEASED);self.assertFalse(E.UNRELEASED)
    def test_effect_function_and_reader_class_drift_never_invoke_foreign_callback(self):
        for target,name in ((E,'verify_retained_effects'),(E._Reader,'check')):
            binding=W._Effects(E);original=getattr(target,name);calls=[]
            def malicious(*args,**kw):calls.append((args,kw))
            setattr(target,name,malicious)
            try:
                with self.assertRaises(ValueError):binding.release_observation()
                self.assertEqual(calls,[]);self.assertIs(W.UNRELEASED[-1][3],binding.function)
            finally:setattr(target,name,original);W.UNRELEASED.clear()
    def test_opaque_or_nonempty_effect_ledger_retains_exact_original_and_current(self):
        original=E.UNRELEASED;calls=[]
        class Opaque:
            def __len__(self):calls.append('len');raise AssertionError('opaque ledger')
            def __iter__(self):calls.append('iter');raise AssertionError('opaque ledger')
        binding=W._Effects(E);opaque=Opaque();E.UNRELEASED=opaque
        try:
            with self.assertRaises(ValueError):binding.release_observation()
            self.assertEqual(calls,[]);self.assertIs(W.UNRELEASED[-1][4],original);self.assertIs(W.UNRELEASED[-1][5],opaque)
        finally:E.UNRELEASED=original;W.UNRELEASED.clear()
        marker=object();binding=W._Effects(E);original.append(marker)
        with self.assertRaises(ValueError):binding.release_observation()
        self.assertIs(W.UNRELEASED[-1][4][0],marker)
    def test_missing_effect_module_or_unknown_preflight_denies_without_callback(self):
        for module in (None,object(),ModuleType('empty_effect_module')):
            with self.assertRaises(ValueError):W._Effects(module)
        marker=object();E.UNRELEASED.append(marker)
        with self.assertRaises(ValueError):W._Effects(E)
        self.assertIs(E.UNRELEASED[0],marker)


class EffectIntegrationControls(unittest.TestCase):
    def setUp(self):self.assertFalse(W.UNRELEASED);self.assertFalse(E.UNRELEASED);self.fixtures=[]
    def tearDown(self):
        for f in self.fixtures:f.clean()
        E.UNRELEASED.clear()
    def fixture(self):f=Fixture();self.fixtures.append(f);return f
    def store(self,f):
        plan=f.plan();f.released();output=f.execute(W.STAGES[0],plan);f.released()
        return plan,output
    def test_original_store_execute_release_then_fresh_verify_retains_outcome_no_writes_or_ack(self):
        f=self.fixture()
        with f.configured():
            plan,output=self.store(f);effects=list(f.backend.effects)
            result=f.verify(W.STAGES[0],plan,output['operationOutcomeSha256']);f.released()
            self.assertEqual(result['operationResult'],output['operationResult'])
            self.assertEqual(result['operationOutcomeSha256'],output['operationOutcomeSha256'])
            observation=result['retainedEffectsObservation'];self.assertEqual(set(observation),W.EFFECT_FIELDS)
            self.assertIs(observation['exactEffectsReread'],True);self.assertIs(observation['ownedReadHandlesKnownReleased'],True)
            self.assertIs(result['ownedResourcesKnownReleased'],True);self.assertFalse(result['stageAcknowledged'])
            self.assertFalse(result['effectsIndependentlyConfirmed']);self.assertFalse(result['nativeAuthorized'])
            self.assertEqual(f.backend.effects,effects);self.assertFalse(E.UNRELEASED)
            self.assertNotIn(f.session+'/'+W.STAGES[0]+'.confirmed',f.system.metas)
            self.assertNotIn('/etc/autosoft/storage.key',f.backend.reads);self.assertNotIn('/srv/backing.luks',f.backend.reads)
    def test_original_source_verify_requires_actual_prior_confirmed_store(self):
        f=self.fixture()
        with f.configured():
            store_plan,stored=self.store(f);f.confirm_store(stored['operationResult'])
            plan=f.plan(W.STAGES[1]);f.released();output=f.execute(W.STAGES[1],plan);f.released()
            effects=list(f.backend.effects);result=f.verify(W.STAGES[1],plan,output['operationOutcomeSha256']);f.released()
            self.assertEqual(result['operationResult'],output['operationResult']);self.assertEqual(f.backend.effects,effects)
            self.assertEqual(result['operationOutcomeSha256'],output['operationOutcomeSha256'])
            self.assertFalse(result['stageAcknowledged']);self.assertFalse(E.UNRELEASED)
            self.assertNotIn(f.session+'/'+W.STAGES[1]+'.confirmed',f.system.metas)
    def test_stale_plan_wrong_hash_and_stable_metadata_byte_tamper_close_known_contexts(self):
        f=self.fixture()
        with f.configured():
            plan,output=self.store(f);effects=list(f.backend.effects)
            changed=json.loads(plan);changed['actionSha256']='f'*64
            for proposed,digest in ((W.canonical(changed),output['operationOutcomeSha256']),(plan,'a'*64)):
                with self.assertRaises(ValueError):f.verify(W.STAGES[0],proposed,digest)
                f.released();self.assertFalse(E.UNRELEASED);self.assertFalse(W.UNRELEASED)
            path=output['operationResult']['root']+'/images.lock.json';node=f.backend.nodes[path]
            metadata=dict(node['info']);node['raw']=b'!'+node['raw'][1:]
            with self.assertRaises(ValueError):f.verify(W.STAGES[0],plan,output['operationOutcomeSha256'])
            self.assertEqual(node['info'],metadata);f.released();self.assertFalse(E.UNRELEASED);self.assertFalse(W.UNRELEASED)
            self.assertEqual(f.backend.effects,effects)
    def test_effect_failed_read_close_retains_all_borrowers_without_resource_expiration_or_ack(self):
        f=self.fixture()
        with f.configured():
            plan,output=self.store(f);target=f.backend.nodes[output['operationResult']['root']+'/images.lock.json'];failed=[]
            def mark(fd,count,offset):
                if f.backend.handles[fd] is target and not failed:f.backend.fail_close=fd;failed.append(fd)
                return f.backend.handles[fd]['raw'][offset:offset+count]
            f.backend.pread_hook=mark;effects=list(f.backend.effects)
            with self.assertRaisesRegex(ValueError,'release-unknown'):f.verify(W.STAGES[0],plan,output['operationOutcomeSha256'])
            self.assertEqual(len(failed),1);self.assertEqual(f.backend.close_attempts.count(failed[0]),1)
            self.assertTrue(E.UNRELEASED);self.assertTrue(f.backend.handles);self.assertTrue(f.system.descriptors)
            row=next(r for r in W.UNRELEASED if r[1]=='effect-borrowers-retained');resources=row[6]
            self.assertFalse(resources.closed);self.assertIs(resources.storage_state['active'],True)
            self.assertIs(resources.commands_state['active'],True);self.assertIs(row[7].live,True)
            self.assertTrue(f.f.q.files.records or f.f.q.files.dirs);self.assertEqual(f.backend.effects,effects)
            self.assertNotIn(f.session+'/'+W.STAGES[0]+'.confirmed',f.system.metas)
            with self.assertRaises(ValueError):f.verify(W.STAGES[0],plan,output['operationOutcomeSha256'])
            self.assertEqual(f.backend.close_attempts.count(failed[0]),1)
            f.clean();E.UNRELEASED.clear() # Synthetic disposal only, never shipped recovery.
    def test_effect_boundary_drift_after_reads_retains_contexts_without_changed_callback(self):
        f=self.fixture()
        with f.configured():
            plan,output=self.store(f);target=f.backend.nodes[output['operationResult']['root']+'/images.lock.json']
            original=E.verify_retained_effects;called=[];drifted=[]
            def malicious(*args,**kw):called.append((args,kw))
            def drift(fd,count,offset):
                if f.backend.handles[fd] is target and not drifted:E.verify_retained_effects=malicious;drifted.append(True)
                return f.backend.handles[fd]['raw'][offset:offset+count]
            f.backend.pread_hook=drift
            try:
                with self.assertRaisesRegex(ValueError,'release-unknown'):f.verify(W.STAGES[0],plan,output['operationOutcomeSha256'])
                self.assertTrue(drifted);self.assertEqual(called,[]);self.assertFalse(E.UNRELEASED)
                row=next(r for r in W.UNRELEASED if r[1]=='effect-borrowers-retained');self.assertFalse(row[6].closed)
                self.assertIs(row[6].storage_state['active'],True);self.assertTrue(f.system.descriptors)
                self.assertTrue(f.f.q.files.records or f.f.q.files.dirs)
            finally:E.verify_retained_effects=original;f.clean()
    def test_equal_comparing_reader_attribute_never_runs_equality_and_retains_borrowers(self):
        f=self.fixture()
        with f.configured():
            plan,output=self.store(f);target=f.backend.nodes[output['operationResult']['root']+'/images.lock.json']
            original=E._Reader.__doc__;called=[];drifted=[]
            class Equal:
                def __eq__(self,other):called.append(other);raise AssertionError('foreign equality')
            replaced=Equal()
            def drift(fd,count,offset):
                if f.backend.handles[fd] is target and not drifted:E._Reader.__doc__=replaced;drifted.append(True)
                return f.backend.handles[fd]['raw'][offset:offset+count]
            f.backend.pread_hook=drift
            try:
                with self.assertRaisesRegex(ValueError,'release-unknown'):f.verify(W.STAGES[0],plan,output['operationOutcomeSha256'])
                self.assertTrue(drifted);self.assertEqual(called,[]);self.assertTrue(E.UNRELEASED)
                row=next(r for r in W.UNRELEASED if r[1]=='effect-borrowers-retained');resources=row[6]
                self.assertFalse(resources.closed);self.assertIs(resources.storage_state['active'],True)
                self.assertIs(resources.commands_state['active'],True);self.assertIs(row[7].live,True)
                self.assertTrue(f.system.descriptors);self.assertTrue(f.f.q.files.records or f.f.q.files.dirs)
                self.assertNotIn(f.session+'/'+W.STAGES[0]+'.confirmed',f.system.metas)
            finally:E._Reader.__doc__=original;f.clean();E.UNRELEASED.clear()


if __name__=='__main__':unittest.main(verbosity=2)
