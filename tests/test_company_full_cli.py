"""Actual admitted Q/F/V/P composition; synthetic protected IO, no native CLI.

Existing fixture definitions are reused without running their tests. The only
path translation and encrypted-proof substitution are installed in this test
before trusted origin capture. Shipped inputs retain the strict /opt policy.
"""
import base64
from contextlib import contextmanager
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import MappingProxyType, ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


C = load('full_cli_controls', ROOT/'deploy/installer/company_full_cli.py')
D = load('full_cli_delivery_fixture', ROOT/'deploy/installer/build-full-cli-package.py')
PB = load('full_cli_package_fixture', ROOT/'deploy/installer/build-full-package.py')
WT = load('full_cli_worker_fixtures', ROOT/'tests/test_company_full_retention_worker.py')
FINGERPRINT = WT.ST.T.T.T.FINGERPRINT


def pin(raw): return dict(bytes=len(raw), sha256=C.sha(raw))


class Fixture:
    def __init__(self):
        self.w = WT.Fixture()
        self.w.store_op = self.w.global_op
        self.mapping, self.contexts, self.calls, self.operational_exec = {}, [], [], []
        self.package_captures = {path: (ROOT/path).read_bytes() for path in PB.PACKAGE_PATHS}
        self.package_pins = {path: pin(raw) for path, raw in self.package_captures.items()}
        self.launch = {path: (ROOT/path).read_bytes() for path in D.LAUNCH_PATHS}
        self.launch_pins = {path: pin(raw) for path, raw in self.launch.items()}
        values = dict(self.w.f.raw, **self.package_captures, **self.launch)
        reader = lambda path, maximum: values[path.relative_to(ROOT).as_posix()]
        self.package = PB.assemble(ROOT, FINGERPRINT, package_pins=self.package_pins,
            operational_catalog=self.w.f.catalog, reader=reader)
        self.delivery = D.assemble(ROOT, launch_pins=self.launch_pins, package_pins=self.package_pins,
            operational_catalog=self.w.f.catalog, fingerprint=FINGERPRINT,
            full_package_raw=self.package, full_package_pin=pin(self.package), reader=reader)
        self.args = dict(delivery_module=D, delivery_pin=pin(self.delivery), launch_pins=self.launch_pins,
            package_pins=self.package_pins, operational_catalog=self.w.f.catalog,
            fingerprint=FINGERPRINT, full_package_pin=pin(self.package),
            bootstrap_records={path:self.package_captures[path] for path in C.BOOTSTRAP_PATHS},
            bootstrap_pins={path:self.package_pins[path] for path in C.BOOTSTRAP_PATHS},
            running_cli_raw=self.launch[C.CLI])
        self.request = dict(schemaVersion=1, mode='full-installation', operationId=self.w.global_op,
            releaseSha256='a'*64, bundleRoot='/opt/autosoft-company/incoming/release',
            sourceRoot='/opt/autosoft-company/incoming/source', keyPath='/opt/autosoft-company/bootstrap/company.pem',
            dataDir=self.w.data, backingFile='/srv/backing.luks', capacityGiB=32,
            runscVersion='20261005.0', runscSha512='c'*128)
        self.system = None

    @contextmanager
    def context(self, genuine=False, **changes):
        # Test-only adapters are captured before original F/L snapshots. There
        # is no mutable-path translator or encrypted-proof callback in the CLI.
        original = C._register
        def register(path, *a, **kw):
            module = original(path, *a, **kw)
            if path == C.COMPOSITION and genuine:
                register_Q = module._register
                def q_register(member, *args, **options):
                    result = register_Q(member, *args, **options)
                    if member == module.FULL_ENTRY:
                        register_F = result._register
                        def f_register(name, *fa, **fk):
                            captured = register_F(name, *fa, **fk)
                            if name == result.LOADER:
                                register_L = captured._register
                                def l_register(leaf, *la, **lk):
                                    if leaf in D.OPERATIONAL_PATHS and leaf not in C.BOOTSTRAP_PATHS:
                                        self.operational_exec.append(leaf)
                                    value = register_L(leaf, *la, **lk)
                                    if leaf == result.VERIFIER:
                                        source = value.authenticated_platform_source
                                        def translated(directory, key, fingerprint, **inputs):
                                            logical = (directory,key,inputs['source_root'])
                                            assert logical == tuple(self.mapping)
                                            self.calls.append(logical)
                                            return source(self.mapping[directory],self.mapping[key],fingerprint,
                                                **dict(inputs,source_root=self.mapping[inputs['source_root']]))
                                        def native(*args,**kw): raise AssertionError('native fallback')
                                        value.authenticated_platform_source = translated
                                        value.NativeFiles = value.NativeCrypto = native
                                    if leaf == WT.W.STARTUP:
                                        def encrypted(data, receipt, command):
                                            assert str(data).replace('\\','/') == self.w.data
                                            assert receipt['storage_file'] == '/srv/backing.luks'
                                            return copy.deepcopy(self.w.mount)
                                        value.encrypted_proof = encrypted
                                    return value
                                captured._register = l_register
                            return captured
                        result._register = f_register
                    return result
                module._register = q_register
            return module
        with patch.object(C,'_register',side_effect=register):
            with C.authenticated_cli(self.delivery, **dict(self.args, **changes)) as controller:
                self.contexts.append(controller)
                if genuine:
                    q = self.w.f.q = WT.ST.U.Q.Fixture(controller._V, WT.ST.U.P)
                    q.values.update(self.w.f.raw)
                    q.modes.update({path:'100644' for path in self.w.f.raw})
                    q.refresh_platform()
                    for path in q.root.parents:
                        q.files.changes.setdefault(path,{}).update(st_mtime_ns=101,st_ctime_ns=202,st_size=0)
                    self.request['releaseSha256'] = C.sha((q.bundle/'release.json').read_bytes())
                    self.mapping.clear()
                    self.mapping.update({self.request['bundleRoot']:q.bundle,self.request['keyPath']:q.public,
                        self.request['sourceRoot']:q.sources})
                    self.request_raw = C.canonical(self.request)
                    if self.system is None:
                        P = controller._P
                        template = P.ParentInput(42,11,12,'s-Abc123Def456',C.sha(self.request_raw),WT.W.STAGES[0],'c'*64)
                        with patch.object(WT.PT,'P',P),patch.object(WT.PT,'ARGS',template):
                            self.system = WT.ParentSystem()
                        self.w.system = self.system
                        self.session = P.BASE+'/sessions/'+template.session
                        old = self.session+'/'+template.stage+'.intent'
                        self.system.bodies.pop(self.system.metas.pop(old).st_ino)
                if genuine:
                    P=controller._P
                    template=P.ParentInput(42,11,12,'s-Abc123Def456',C.sha(self.request_raw),WT.W.STAGES[0],'c'*64)
                    # A fresh worker's original P has fresh Metadata classes;
                    # real station observations would be parsed into that P.
                    # RAM inode/bytes never change when doing this conversion.
                    self.system.metas={path:P.Metadata(*(getattr(meta,name) for name in P.FIELDS))
                        for path,meta in self.system.metas.items()}
                    self.system.parent_dir=self.system.metas[P.BASE]
                    self.system.parent_lock=self.system.metas[P.BASE+'/install.lock']
                    with patch.object(WT.PT,'P',P),patch.object(WT.PT,'ARGS',template):yield controller
                else:yield controller

    def invocation(self, command, plan=None, outcome=None):
        stage = WT.W.STAGES[0]
        parent = None
        if plan is not None:
            action = json.loads(plan)['actionSha256']
            parent = ['42','11','12','s-Abc123Def456',C.sha(self.request_raw),stage,action]
        value = dict(schemaVersion=1,scope='FULL_RETENTION_CLI_INVOCATION_ONLY',command=command,
            stage=stage,requestSha256=C.sha(self.request_raw),releaseSha256=self.request['releaseSha256'],
            operationId=self.w.store_op,storeOperationId=self.w.store_op,
            planSha256=C.sha(plan) if plan else None,outcomeSha256=outcome,parent=parent)
        return C.canonical(value)

    def dispatch(self, cli, command, plan=None, evidence=None, outcome=None, **changes):
        q = self.w.f.q
        raw = self.invocation(command, plan, outcome)
        args = dict(request_raw=self.request_raw,request_sha256=C.sha(self.request_raw),
            invocation_raw=raw,invocation_sha256=C.sha(raw),plan_raw=plan,
            files=q.files,crypto=q.crypto,backend_module=WT.ADAPTERS,backend=self.w.backend,
            runner_module=WT.ADAPTERS,runner=self.w.runner,clock=self.w.clock)
        if command != 'plan-stage':
            args.update(parent_system_module=WT.ADAPTERS,parent_system=self.system,execution_evidence=evidence)
        args.update(changes)
        return cli.dispatch(command,**args)

    def clean(self):
        # Only RAM/fixture resources and synthetic retained modules are disposed.
        # Shipped code has no reset/reconciliation and no unknown-close retry.
        self.w.clean()
        for controller in self.contexts:
            record=C._CLI_OWNERS[id(controller)];state=record[1]
            for module,namespace,classes in C._NESTED_OWNERS.get(id(controller),()):
                for key,value in namespace:
                    if vars(module).get(key) is not value:setattr(module,key,value)
                for kind,methods in classes:
                    for key,value in methods:
                        if key not in ('__dict__','__weakref__') and vars(kind).get(key) is not value:
                            setattr(kind,key,value)
            if record[5] is not None:
                for path,module,namespace,classes in record[5][0]:
                    for kind,methods in classes:
                        for key,value in methods:
                            if key not in ('__dict__','__weakref__') and vars(kind).get(key) is not value:
                                setattr(kind,key,value)
                registrations=record[5][1]
            else:registrations=tuple(state['_owned'])
            cm=state.get('_composition_cm')
            if cm is not None:
                cm_record=C._CM_OWNERS.get(id(controller))
                if cm_record is not None:
                    expected=dict(cm_record[4]);plain=vars(cm)
                    plain.clear();plain.update(expected)
                try:
                    if cm_record is not None:cm_record[7](cm,None,None,None)
                    else:cm.__exit__(None,None,None)
                except BaseException:pass
            for name,module in reversed(registrations):
                if sys.modules.get(name) is module: del sys.modules[name]
        self.contexts.clear()
        C.UNRELEASED.clear(); C._CLIS.clear(); C._CLI_OWNERS.clear()
        C._OBSERVATIONS.clear(); C._OBSERVATION_RECORDS.clear(); C._CLOSED_OWNERS.clear()
        C._EXPIRED_OWNERS.clear(); C._ATTEMPTS.clear(); C._REQUESTS.clear()
        C._EFFECT_RETURNS.clear()
        C._CM_OWNERS.clear()
        C._NESTED_OWNERS.clear()


class RefusalControls(unittest.TestCase):
    def setUp(self): self.f = Fixture()
    def tearDown(self): self.f.clean()
    def reject(self, fn):
        with self.assertRaises((ValueError,TypeError,KeyError)): fn()

    def describe(self, cli):
        raw = C.canonical(self.f.request)
        return cli.dispatch('describe',request_raw=raw,request_sha256=C.sha(raw))

    def test_fixed_argv_rejects_arbitrary_modes_roots_flags_and_aliases(self):
        path='/opt/autosoft-company/requests/'+'b'*32+'.json'
        self.assertEqual(C.parse_argv(['--describe','--request',path])['command'],'describe')
        for argv in (['--install','--request',path],['--describe','--request','/tmp/request.json'],
                     ['--describe','--request',path,'--tool','/usr/bin/bash'],
                     ['--describe','--request',path.replace('/requests/','/requests//')]):
            self.reject(lambda:C.parse_argv(argv))

    def test_immutable_result_capture_is_bounded_and_foreign_values_have_no_callbacks(self):
        original={'known':MappingProxyType({'closed':True,'effects':False})}
        captured=C._wire(original)
        self.assertEqual(captured,{'known':{'closed':True,'effects':False}})
        self.assertIsNot(captured,original)
        class Foreign(dict):
            def items(self):self.fail('foreign callback')
        for value in (Foreign(a=1),{'a':object()},list(range(129)),{str(i):i for i in range(129)}):
            self.reject(lambda:C._wire(value))
        for value in (2**64,{'a':'x'*20000,'b':'y'*20000}):self.reject(lambda:C._wire(value))
        nested={};cursor=nested
        for i in range(18):cursor['next']={};cursor=cursor['next']
        self.reject(lambda:C._wire(nested))

    def test_independent_bootstrap_pins_deny_before_first_compile(self):
        for path in C.BOOTSTRAP_PATHS:
            records=dict(self.f.args['bootstrap_records']);records[path]+=b'\n'
            with patch.object(C,'_register',side_effect=AssertionError('compile')):
                with self.assertRaises(ValueError):
                    with self.f.context(bootstrap_records=records): self.fail('yield')

    def test_bad_last_launch_and_initial_cli_bytes_deny_before_compile(self):
        original=self.f.delivery
        value=json.loads(original);value['launchRecords'][C.SEED_RUNNER]['base64']='!'
        self.f.delivery=C.canonical(value)
        with patch.object(C,'_register',side_effect=AssertionError('compile')):
            with self.assertRaises(ValueError):
                with self.f.context(delivery_pin=pin(self.f.delivery)):self.fail('yield')
        self.f.delivery=original
        with patch.object(C,'_register',side_effect=AssertionError('compile')):
            with self.assertRaises(ValueError):
                with self.f.context(running_cli_raw=b'foreign'):self.fail('yield')

    def test_describe_is_non_ack_and_requires_actual_outer_close(self):
        with self.f.context() as cli:
            observation=self.describe(cli)
            self.reject(observation.completed_record)
            cli._closed=True
            self.reject(observation.completed_record)
            cli._closed=False
        record=json.loads(observation.completed_record())
        self.assertFalse(record['stageAcknowledged']);self.assertFalse(record['fullInstallationCompleted'])
        self.assertFalse(record['nativeQualified']);self.reject(cli.recheck)

    def test_observation_record_owner_command_and_dict_mutations_deny(self):
        with self.f.context() as cli:observation=self.describe(cli)
        state=vars(observation);original=dict(state)
        for field,value in (('_record',C.canonical(dict(command='execute-stage'))),
                            ('_owner',C.FullCli()),('_command','execute-stage')):
            state[field]=value
            self.reject(lambda:C._observation_record(observation))
            state.clear();state.update(original)
        observation.__dict__=dict(state)
        self.reject(observation.completed_record)
        observation.__dict__=state

    def test_observation_class_mutation_denies_before_owner_callback(self):
        with self.f.context() as cli:observation=self.describe(cli)
        with patch.object(C.CliObservation,'completed_record',lambda self:self.fail('changed method')):
            self.reject(lambda:C._observation_record(observation))
        with patch.object(C.FullCli,'recheck',lambda self:self.fail('changed owner')):
            self.reject(lambda:C._observation_record(observation))

    def test_unissued_observation_and_owner_public_flags_do_not_establish_execution(self):
        self.reject(C.CliObservation().completed_record)
        with self.f.context() as cli:
            observation=self.describe(cli)
            clone=C.CliObservation();clone.__dict__=dict(vars(observation))
            cli._closed=True;cli._active=False
            self.reject(clone.completed_record);self.reject(observation.completed_record)
            cli._closed=False;cli._active=True

    def test_caught_bad_request_expires_context_and_observation(self):
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                observation=self.describe(cli)
                self.reject(lambda:cli.dispatch('describe',request_raw=b'{}\n',request_sha256=C.sha(b'{}\n')))
                self.reject(cli.recheck)
        self.reject(observation.completed_record)

    def test_stale_plan_and_serialized_completion_flags_deny_before_worker(self):
        raw=C.canonical(self.f.request);request_sha=C.sha(raw);stage=WT.W.STAGES[0]
        value=dict(schemaVersion=1,scope='FULL_RETENTION_CLI_INVOCATION_ONLY',command='execute-stage',
            stage=stage,requestSha256=request_sha,releaseSha256=self.f.request['releaseSha256'],
            operationId=self.f.w.global_op,storeOperationId=self.f.w.global_op,
            planSha256='c'*64,outcomeSha256=None,
            parent=['42','11','12','s-Abc123Def456',request_sha,stage,'d'*64])
        invocation=C.canonical(value)
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                self.reject(lambda:cli.dispatch('execute-stage',request_raw=raw,request_sha256=request_sha,
                    invocation_raw=invocation,invocation_sha256=C.sha(invocation),plan_raw=b'{}\n',clock=lambda:1))
                self.assertFalse(C._EFFECT_RETURNS[id(cli)])
                self.assertFalse(cli._modules[C.STAGES]._COORDINATORS)
                self.assertIsNone(self.f.w.f.q)
        C.UNRELEASED.clear()
        with self.f.context() as cli:
            self.reject(lambda:cli._evidence(dict(command='execute-stage',knownReleased=True),{}))

    def test_describe_replay_is_denied_without_worker_calls(self):
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                self.describe(cli)
                with patch.object(cli._modules[C.WORKER],'plan_stage',side_effect=AssertionError('worker')):
                    self.reject(lambda:self.describe(cli))

    def test_foreign_evidence_metaclass_is_denied_before_dictionary_observation(self):
        calls=[]
        class Meta(type):
            def __getattribute__(cls,name):
                if name=='__dict__':calls.append(name);raise AssertionError('foreign class observation')
                return type.__getattribute__(cls,name)
        class Foreign(metaclass=Meta):pass
        module=ModuleType('foreign_held_execution');module.HeldExecutionEvidence=Foreign
        module.require_known_execution=lambda value:self.fail('foreign validator')
        with self.f.context() as cli:self.reject(lambda:cli._evidence(Foreign(),{},module))
        self.assertEqual(calls,[])

    def test_external_evidence_class_drift_retains_exact_issuer_without_changed_getter(self):
        calls=[];module=ModuleType('trusted_injected_execution_io')
        class Held:
            @property
            def record_bytes(self):calls.append('original');return b'{}\n'
        evidence=Held();module.HeldExecutionEvidence=Held
        def validator(value):
            Held.record_bytes=property(lambda self:calls.append('changed'))
            return value
        module.require_known_execution=validator
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                self.reject(lambda:cli._evidence(evidence,{},module))
        self.assertEqual(calls,[])
        self.assertTrue(C.UNRELEASED);self.assertIn(evidence,C.UNRELEASED[0])

    def test_unknown_launch_ledger_preserves_original_composition_references(self):
        marker=object()
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                original=cli._composition
                cli._modules[C.WORKER].UNRELEASED.append(marker)
                self.reject(cli.recheck)
        self.assertTrue(C.UNRELEASED)
        self.assertIs(C._CLI_OWNERS[id(cli)][1]['_composition'],original)
        self.assertFalse(C._CLI_OWNERS[id(cli)][1]['_closed'])

    def test_module_map_deletion_and_snapshot_laundering_do_not_call_changed_methods(self):
        for mode in ('delete','launder'):
            with self.assertRaises(ValueError):
                with self.f.context() as cli:
                    if mode=='delete': cli._modules.clear()
                    else:
                        Q=cli._modules[C.COMPOSITION]
                        def foreign(value): self.fail('changed Q callback')
                        Q.FullComposition.recheck=foreign
                        cli._class_snapshots[C.COMPOSITION][Q.FullComposition]['recheck']=foreign
                    self.reject(cli.recheck)
            self.assertTrue(C.UNRELEASED)
            # Explicit test-only retained pure-module disposal; no real handles.
            self.f.clean()

    def test_cleared_attempts_and_restored_public_active_flags_cannot_replay(self):
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                self.describe(cli);cli._used.clear()
                self.reject(cli.recheck)
                cli._active=True;cli._failed=False
                self.reject(cli.recheck)

    def test_context_exit_callback_drift_is_not_invoked_or_accepted_as_closure(self):
        calls=[]
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                observation=self.describe(cli)
                cli._composition_cm.__exit__=lambda *args:calls.append(args)
        self.assertEqual(calls,[]);self.assertTrue(C.UNRELEASED)
        self.assertFalse(cli._closed)
        self.reject(observation.completed_record)

    def test_nested_full_entry_and_loader_class_drift_deny_before_callbacks(self):
        calls=[]
        for path,name in ((None,'FullEntry'),('loader','TrustedEntry')):
            with self.assertRaises(ValueError):
                with self.f.context() as cli:
                    kind=cli._F.FullEntry if path is None else cli._L.TrustedEntry
                    kind.recheck=lambda *a:calls.append(a)
                    self.reject(cli.recheck)
            self.assertEqual(calls,[]);self.assertTrue(C.UNRELEASED)
            self.f.clean()

    def test_nested_verifier_parent_and_backend_class_drift_is_retained_before_exit(self):
        calls=[]
        for member,name,method in (('_V','HeldPlatformSource','recheck'),('_P','HeldParent','close'),
                                   ('_BK','ReadOnlySourceBackend','close')):
            with self.assertRaises(ValueError):
                with self.f.context() as cli:
                    kind=getattr(getattr(cli,member),name)
                    setattr(kind,method,lambda *a:calls.append(a))
            self.assertEqual(calls,[]);self.assertTrue(C.UNRELEASED)
            self.assertFalse(cli._closed);self.f.clean()

    def test_nested_namespace_drift_cannot_be_laundered_into_launch_snapshots(self):
        calls=[]
        with self.assertRaises(ValueError):
            with self.f.context() as cli:
                cli._F.require=lambda *a:calls.append(a)
                self.reject(cli.recheck)
        self.assertEqual(calls,[]);self.assertTrue(C.UNRELEASED)

    def test_original_bootstrap_registries_are_shared_and_main_has_no_native_default(self):
        with self.f.context() as cli:
            modules=cli.original_modules
            self.assertIs(modules['verifier'],cli._entry.origin.modules[cli._F.VERIFIER])
            self.assertIs(modules['parent'],cli._entry.origin.modules[cli._F.PARENT])
            self.assertIs(cli._composition.entry,cli._entry)
            self.assertFalse(cli._V._ISSUED_PLATFORM_SOURCES)
        with patch('subprocess.Popen',side_effect=AssertionError('native')):
            self.reject(lambda:C.main(['--describe','--request','anything']))


class GenuineFlowControls(unittest.TestCase):
    def setUp(self):self.f=Fixture()
    def tearDown(self):self.f.clean()

    def test_real_plan_execute_close_fresh_verify_close_with_original_registries_and_current_effects(self):
        f=self.f
        with patch('subprocess.Popen',side_effect=AssertionError('native child')):
            with f.context(genuine=True) as cli:
                plan_observation=f.dispatch(cli,'plan-stage')
                self.assertFalse(cli._V._ISSUED_PLATFORM_SOURCES)
                self.assertFalse(cli._modules[C.STAGES]._SCOPES)
                with self.assertRaises(ValueError):plan_observation.completed_record()
            plan=base64.b64decode(json.loads(plan_observation.completed_record())['planBase64'],validate=True)
            with f.context(genuine=True) as cli:
                action=json.loads(plan)['actionSha256']
                f.system.add(f.session+'/'+WT.W.STAGES[0]+'.intent',f.system.stage(WT.W.STAGES[0],action))
                execution=f.dispatch(cli,'execute-stage',plan)
                self.assertFalse(f.w.backend.handles);self.assertFalse(f.system.descriptors)
                self.assertFalse(f.w.f.q.files.records);self.assertFalse(f.w.f.q.files.dirs)
                self.assertFalse(cli._V._ISSUED_PLATFORM_SOURCES)
                self.assertEqual(C.sha(cli._raw[C.EFFECTS]),C.sha((ROOT/C.EFFECTS).read_bytes()))
            known=json.loads(execution.completed_record());outcome=known['outcomeSha256']
            self.assertEqual(outcome,C.sha(C.canonical(known['result']['operationResult'])))
            before=copy.deepcopy(f.w.backend.nodes)
            with f.context(genuine=True) as cli:
                verification=f.dispatch(cli,'verify-stage',plan,execution,outcome)
                self.assertFalse(f.w.backend.handles);self.assertFalse(f.system.descriptors)
                self.assertFalse(cli._V._ISSUED_PLATFORM_SOURCES)
                self.assertFalse(cli._modules[C.STAGES]._COORDINATORS)
            checked=json.loads(verification.completed_record())
            self.assertEqual(checked['outcomeSha256'],outcome)
            self.assertEqual(checked['result']['operationResult'],known['result']['operationResult'])
            self.assertEqual(f.w.backend.nodes,before)
            self.assertFalse(checked['stageAcknowledged']);self.assertFalse(checked['nativeQualified'])
            self.assertEqual(len(f.calls),3)

    def test_signed_operational_source_drift_refuses_before_operational_compile(self):
        f=self.f
        with self.assertRaises(ValueError):
            with f.context(genuine=True) as cli:
                f.w.f.q.values['scripts/company_source_tree.py']+=b'\n# signed but not independently approved\n'
                f.w.f.q.refresh_platform()
                f.request['releaseSha256']=C.sha((f.w.f.q.bundle/'release.json').read_bytes())
                f.request_raw=C.canonical(f.request)
                # Allow authenticated parser compilation, count only actual
                # operational assembly registrations captured before origin.
                with self.assertRaises(ValueError):f.dispatch(cli,'plan-stage')
                self.assertTrue(f.w.f.q.crypto.calls)
                self.assertEqual(f.operational_exec,[])

    def test_post_writer_serialization_failure_retains_original_return_hash_and_context(self):
        f=self.f
        with f.context(genuine=True) as cli:planned=f.dispatch(cli,'plan-stage')
        plan=base64.b64decode(json.loads(planned.completed_record())['planBase64'],validate=True)
        with self.assertRaises(ValueError):
            with f.context(genuine=True) as cli:
                action=json.loads(plan)['actionSha256']
                f.system.add(f.session+'/'+WT.W.STAGES[0]+'.intent',f.system.stage(WT.W.STAGES[0],action))
                with patch.object(C,'_wire',side_effect=ValueError('injected post-effect conversion')):
                    with self.assertRaises(ValueError):f.dispatch(cli,'execute-stage',plan)
                returns=C._EFFECT_RETURNS[id(cli)]
                self.assertEqual(len(returns),1)
                row=returns[0]
                self.assertEqual(row[0],'execute-stage');self.assertIs(row[3],cli._modules[C.WORKER])
                self.assertEqual(C.sha(row[5]),row[6]);self.assertEqual(row[6],row[4]['operationOutcomeSha256'])
                self.assertFalse(f.w.backend.handles);self.assertFalse(f.system.descriptors)
                self.assertFalse(cli._V._ISSUED_PLATFORM_SOURCES)
        self.assertTrue(C.UNRELEASED);self.assertFalse(cli._closed)
        self.assertIs(C._CLI_OWNERS[id(cli)][1]['_composition'],cli._composition)
        with self.assertRaises(ValueError):cli.recheck()


if __name__=='__main__':unittest.main(verbosity=2)
