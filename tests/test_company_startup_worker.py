"""Original issued stored-startup authority through the new worker boundary.

These use injected fixture IO, not native installation or service activation.
"""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


N=load('native_startup_controls','deploy/installer/company_startup_worker.py')
T=load('native_startup_original_fixture','tests/test_company_stored_startup.py')


class StartupWorkerControls(unittest.TestCase):
    def setUp(self):self.fixture=T.Fixture()
    def tearDown(self):
        self.fixture.clean();T.W.UNRELEASED.clear();self.assertFalse(T.W._ISSUED)

    def hold(self,s,fresh,**changes):
        values=dict(full_entry_module=T.FT.F,held=s.held,source_guard=s.guard,parent=s.parent,
            request=s.request,worker_sha256=T.WORKER,backend=s.backend,assembly=fresh,clock=self.fixture.clock)
        values.update(changes)
        return N.held_startup(T.W,s.entry,**values)

    def test_exact_original_bound_assembly_and_same_session_prior_confirmations(self):
        with self.fixture.scope() as s,s.entry.fresh_installation_modules(s.held) as fresh:
            fresh.bind_source_guard(s.guard)
            with self.hold(s,fresh) as capability:
                observed=capability.inspection()
                self.assertEqual(observed['priorStageOutcomesSha256'],T.W.sha(T.W.canonical(s.stages)))
                self.assertEqual(observed['actionSha256'],N.stage_action(T.W,s.request,T.WORKER))
                self.assertIs(capability._parent,s.parent)
                self.assertFalse(observed['nativeQualified']);self.assertTrue(observed['fullInstallDenied'])
            self.assertIs(fresh.recheck(),fresh)

    def test_different_worker_cannot_use_original_parent_action(self):
        with self.assertRaises(ValueError),self.fixture.scope() as s,s.entry.fresh_installation_modules(s.held) as fresh:
            fresh.bind_source_guard(s.guard)
            with self.hold(s,fresh,worker_sha256='0'*64):self.fail('wrong worker admitted')

    def test_missing_prior_confirmation_cannot_be_replaced_by_journal_bytes(self):
        def alter(s):
            path=s.IP.BASE+'/sessions/'+s.args.session+'/company-platform-store.confirmed'
            s.system.metas.pop(path)
        with self.assertRaises(ValueError),self.fixture.scope(alter=alter):self.fail('missing prior admitted')

    def test_changed_prior_outcome_refuses_exact_original_capability(self):
        def alter(s):
            path=s.IP.BASE+'/sessions/'+s.args.session+'/company-source-materialize.confirmed'
            info=s.system.metas[path];raw=s.system.bodies[info.st_ino]
            s.system.bodies[info.st_ino]=raw.replace(s.stages['company-source-materialize'][1].encode(),b'0'*64)
        with self.assertRaises(ValueError),self.fixture.scope(alter=alter) as s,s.entry.fresh_installation_modules(s.held) as fresh:
            fresh.bind_source_guard(s.guard)
            with self.hold(s,fresh):self.fail('changed prior outcome admitted')

    def test_unbound_fresh_assembly_refuses_before_operational_call(self):
        with self.assertRaises(ValueError),self.fixture.scope() as s,s.entry.fresh_installation_modules(s.held) as fresh:
            with self.hold(s,fresh):self.fail('unbound assembly admitted')

    def test_original_verifier_missing_runtime_state_never_initializes(self):
        calls=[]
        class Missing:
            def require_root(self):calls.append('root')
            def protected(self,*args,**kwargs):raise ValueError('missing runtime state')
        def denied(*args,**kwargs):raise AssertionError('unexpected native effect')
        inputs=dict(host_directory='/etc/autosoft',files=Missing(),command=denied,mount=denied,
            layout=denied,gate_factory=denied,allocation_factory=denied,read_state=denied,clock=lambda:0,timeout=1)
        with self.assertRaises(ValueError),self.fixture.scope() as s,s.entry.fresh_installation_modules(s.held) as fresh:
            fresh.bind_source_guard(s.guard)
            with self.hold(s,fresh) as capability:
                capability.inspect_initialized(inputs=inputs,fresh_assembly=fresh)
        self.assertTrue(calls);self.assertEqual(set(calls),{'root'})

    def test_request_derives_exact_store_source_operation_and_storage_binding(self):
        request=dict(operationId='a'*32,dataDir='/srv/data',releaseSha256='b'*64)
        storage=SimpleNamespace(root='/srv/data/company/host-releases/install-'+'a'*32,
            installation_id=T.INSTALLATION,binding_sha256='c'*64)
        proposed=N.stage_request(T.W,request,b'full request',storage,7)
        self.assertEqual(proposed['storeOperationId'],'a'*32)
        self.assertEqual(proposed['sourceOperationId'],T.W.sha(('source:'+'a'*32).encode())[:32])
        self.assertEqual(proposed['storageBindingSha256'],'c'*64)
        first=N.stage_action(T.W,proposed,T.WORKER)
        for changed in (dict(proposed,expectedDevice=8),dict(proposed,storageBindingSha256='d'*64),
                        dict(proposed,installationRequestSha256='e'*64)):
            self.assertNotEqual(N.stage_action(T.W,changed,T.WORKER),first)


if __name__=='__main__':unittest.main(verbosity=2)
