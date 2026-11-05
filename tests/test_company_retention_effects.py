"""Original V/B/P/M/C effects with protected RAM IO; no native execution."""
import importlib.util
import json
from pathlib import Path
import stat
import sys
from types import ModuleType
import unittest

ROOT = Path(__file__).resolve().parents[1]
def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module

E = load('retention_effects_under_test',ROOT/'deploy/installer/company_retention_effects.py')
CT = load('retention_effects_fixtures',ROOT/'tests/test_company_source_tree.py')
M,B,P,T = CT.M,CT.B,CT.P,CT.T


def plan(stage,request,request_sha,action,operation,store_operation):
    return E.canonical(dict(schemaVersion=1,scope='RETENTION_STAGE_PLAN_ONLY',stage=stage,
        installationRequestSha256=CT.F.GLOBAL,operationId=operation,storeOperationId=store_operation,
        stageRequest=request,stageRequestSha256=request_sha,actionSha256=action))


class EffectsControls(unittest.TestCase):
    def setUp(self):
        E.UNRELEASED.clear(); self.fixtures=[]; self.restores=[]
        CT.C.UNRELEASED.clear(); M.UNRELEASED.clear(); B.SEED_UNRELEASED.clear()
    def tearDown(self):
        for cls,name,old in reversed(self.restores): setattr(cls,name,old)
        for fixture in self.fixtures:
            fixture.t.backend.fail_close=None; fixture.t.backend.pread_hook=None
            fixture.close()
            for fd in list(fixture.t.backend.handles): fixture.t.backend.close(fd)
        E.UNRELEASED.clear(); CT.C.UNRELEASED.clear(); M.UNRELEASED.clear(); B.SEED_UNRELEASED.clear()
    def fixture(self):
        f=CT.Fixture(); self.fixtures.append(f); return f
    def store(self,f):
        with f.q.held() as held:
            request,request_sha,action,f.records=f.store_request(held)
            arguments=f.session.prepare(E.STAGES[0],action)
            with f.session.hold(arguments) as parent: result=f.store(held,parent)
            f.close_storage()
        self.assertFalse(f.t.backend.handles); self.assertFalse(f.session.system.descriptors)
        self.assertFalse(f.V._ISSUED_PLATFORM_SOURCES)
        f.reopen()
        return arguments,plan(E.STAGES[0],request,request_sha,action,f.t.OP,f.t.OP),result
    def verify(self,f,held,parent,stage,proposed,result,**changes):
        args=dict(expected_plan=proposed,expected_outcome_sha256=E.sha(E.canonical(result)),held=held,
            verifier_module=f.V,bootstrap_module=B,parent_module=P,parent=parent,
            store_module=M,source_module=CT.C,storage=f.t.storage,backend_module=T,backend=f.t.backend,
            operation_id=f.t.OP if stage==E.STAGES[0] else f.OP,store_operation_id=f.t.OP,
            installation_request_sha256=CT.F.GLOBAL,clock=lambda:0)
        args.update(changes); return E.verify_retained_effects(stage,**args)

    def test_original_store_reread_after_outer_release_preserves_exact_outcome(self):
        f=self.fixture(); arguments,proposed,result=self.store(f)
        effects=list(f.t.backend.effects)
        with f.q.held() as held,f.session.hold(arguments) as parent:
            borrowed=set(f.t.backend.handles)
            observation=self.verify(f,held,parent,E.STAGES[0],proposed,result)
            self.assertEqual(observation['operationResult'],result)
            self.assertEqual(observation['operationOutcomeSha256'],E.sha(E.canonical(result)))
            self.assertEqual(set(f.t.backend.handles),borrowed)
            self.assertTrue(observation['exactEffectsReread']); self.assertFalse(observation['stageAcknowledged'])
            self.assertFalse(observation['nativeQualified']); self.assertTrue(observation['outerContextsRequireClosure'])
            self.assertNotIn(f.session.path+'/'+E.STAGES[0]+'.confirmed',f.session.system.metas)
        self.assertEqual(f.t.backend.effects,effects)
        self.assertNotIn('/etc/autosoft/storage.key',f.t.backend.reads)
        self.assertNotIn('/srv/backing.luks',f.t.backend.reads)

    def test_original_source_and_confirmed_store_reread_after_release(self):
        f=self.fixture(); f.store_first()
        with f.current() as (held,parent,request,request_sha,source_plan,prior):
            result=f.materialize(held,parent); action=parent.arguments.action
            arguments=parent.arguments
            proposed=plan(E.STAGES[1],request,request_sha,action,f.OP,f.t.OP)
            f.close_storage()
        self.assertFalse(f.t.backend.handles); self.assertFalse(f.V._ISSUED_PLATFORM_SOURCES)
        f.reopen(); effects=list(f.t.backend.effects)
        with f.q.held() as held,f.session.hold(arguments) as parent:
            borrowed=set(f.t.backend.handles)
            observation=self.verify(f,held,parent,E.STAGES[1],proposed,result)
            self.assertEqual(observation['operationResult'],result)
            self.assertEqual(set(f.t.backend.handles),borrowed)
            self.assertNotIn(f.session.path+'/'+E.STAGES[1]+'.confirmed',f.session.system.metas)
        self.assertEqual(f.t.backend.effects,effects)

    def test_tampered_bytes_with_same_metadata_cannot_pass_terminal_journal(self):
        f=self.fixture(); arguments,proposed,result=self.store(f)
        path=result['root']+'/images.lock.json'; node=f.t.backend.nodes[path]
        node['raw']=b'!'+node['raw'][1:]
        with f.q.held() as held,f.session.hold(arguments) as parent:
            borrowed=set(f.t.backend.handles)
            with self.assertRaises(E.RetentionEffectsUnavailable): self.verify(f,held,parent,E.STAGES[0],proposed,result)
            self.assertEqual(set(f.t.backend.handles),borrowed)
        self.assertFalse(E.UNRELEASED)

    def test_extra_leaf_and_wrong_permission_are_denied(self):
        for change in ('extra','mode','device'):
            f=self.fixture(); arguments,proposed,result=self.store(f)
            if change=='extra': f.t.backend.file(result['root']+'/foreign',b'x',mode=0o400)
            else:
                row=f.t.backend.nodes[result['root']+'/verified.json']['info']
                row['st_mode']=stat.S_IFREG|0o600 if change=='mode' else row['st_mode']
                if change=='device': row['st_dev']=2
            with f.q.held() as held,f.session.hold(arguments) as parent:
                borrowed=set(f.t.backend.handles)
                with self.assertRaises(E.RetentionEffectsUnavailable): self.verify(f,held,parent,E.STAGES[0],proposed,result)
                self.assertEqual(set(f.t.backend.handles),borrowed)

    def test_stale_plan_and_wrong_outcome_hash_deny_before_new_read_handles(self):
        f=self.fixture(); arguments,proposed,result=self.store(f)
        with f.q.held() as held,f.session.hold(arguments) as parent:
            next_fd=f.t.backend.next_fd
            for changes in (dict(expected_plan=proposed+b' '),dict(expected_outcome_sha256='a'*64),
                            dict(installation_request_sha256='b'*64),dict(operation_id='c'*32)):
                with self.assertRaises(ValueError): self.verify(f,held,parent,E.STAGES[0],proposed,result,**changes)
                self.assertEqual(f.t.backend.next_fd,next_fd)

    def test_metadata_drift_during_read_denies_and_closes_own_handles(self):
        f=self.fixture(); arguments,proposed,result=self.store(f); changed=[]
        target=f.t.backend.nodes[result['root']+'/images.lock.json']
        def drift(fd,count,offset):
            row=f.t.backend.handles[fd]
            if row is target and not changed:
                changed.append(True); row['info']['st_ctime_ns']+=1
            return row['raw'][offset:offset+count]
        f.t.backend.pread_hook=drift
        with f.q.held() as held,f.session.hold(arguments) as parent:
            borrowed=set(f.t.backend.handles)
            with self.assertRaises(E.RetentionEffectsUnavailable): self.verify(f,held,parent,E.STAGES[0],proposed,result)
            self.assertEqual(set(f.t.backend.handles),borrowed)
        self.assertTrue(changed); self.assertFalse(E.UNRELEASED)

    def test_failed_close_retains_original_handle_and_blocks_replay(self):
        f=self.fixture(); arguments,proposed,result=self.store(f)
        # First new descriptor belongs to this independent reader, not storage.
        fail=f.t.backend.next_fd+1; f.t.backend.fail_close=fail
        with f.q.held() as held,f.session.hold(arguments) as parent:
            with self.assertRaises(E.RetentionEffectsUnavailable): self.verify(f,held,parent,E.STAGES[0],proposed,result)
            self.assertIn(fail,f.t.backend.handles)
            self.assertEqual(f.t.backend.close_attempts.count(fail),1)
            self.assertTrue(E.UNRELEASED)
            with self.assertRaises(E.RetentionEffectsUnavailable): self.verify(f,held,parent,E.STAGES[0],proposed,result)
            self.assertEqual(f.t.backend.close_attempts.count(fail),1)


class ReaderControls(unittest.TestCase):
    def setUp(self):
        E.UNRELEASED.clear(); self.backend=T.SeedBackend(); self.calls=[]
        self.backend.pread_calls=[]; self.backend.pread_hook=None
    def tearDown(self):
        self.backend.fail_close=None
        for fd in list(self.backend.handles): T.SeedBackend.close(self.backend,fd)
        E.UNRELEASED.clear()
    def reader(self): return E._Reader(T,self.backend,lambda:0,lambda:None)
    def test_captured_cleanup_ignores_replaced_disposer(self):
        reader=self.reader(); dispose=reader.dispose; reader.hold('/',True)
        reader.dispose=lambda:self.calls.append('foreign')
        dispose(); self.assertEqual(self.calls,[]); self.assertFalse(self.backend.handles)
    def test_backend_method_drift_never_invokes_foreign_close(self):
        reader=self.reader(); dispose=reader.dispose; reader.hold('/',True)
        original=T.SeedBackend.close
        T.SeedBackend.close=lambda value,fd:self.calls.append(fd)
        try:
            with self.assertRaises(E.RetentionEffectsUnavailable): dispose()
            self.assertEqual(self.calls,[]); self.assertTrue(self.backend.handles)
        finally: T.SeedBackend.close=original
    def test_opaque_ownership_replacement_is_retained_without_iteration(self):
        reader=self.reader(); dispose=reader.dispose; reader.hold('/',True); original=reader.owned
        calls=self.calls
        class Opaque:
            def __iter__(self): calls.append('iteration'); raise AssertionError()
        foreign=Opaque(); reader.owned=foreign
        with self.assertRaises(E.RetentionEffectsUnavailable): dispose()
        self.assertEqual(self.calls,[]); self.assertTrue(self.backend.handles)
        self.assertIs(E.UNRELEASED[-1][4],original); self.assertIs(E.UNRELEASED[-1][6],foreign)
    def test_empty_files_and_short_reads_have_bounded_exact_readback(self):
        self.backend.file('/empty',b'',mode=0o400)
        self.backend.file('/content',b'abcdefgh',mode=0o400)
        reader=self.reader(); dispose=reader.dispose
        reader.hold('/',True); reader.hold('/empty',False,0o400,b'')
        dispose()
        self.backend.pread_hook=lambda fd,count,offset:self.backend.handles[fd]['raw'][offset:offset+min(count,2)]
        # Install trusted fixture callback before constructing its reader.
        reader=self.reader(); dispose=reader.dispose
        reader.hold('/content',False,0o400,b'abcdefgh'); dispose()
        self.assertFalse(self.backend.handles)

    def test_malformed_attempt_ledger_denies_without_a_close(self):
        reader=self.reader(); dispose=reader.dispose; reader.hold('/',True)
        reader.attempted.add(True)
        with self.assertRaises(E.RetentionEffectsUnavailable): dispose()
        self.assertTrue(self.backend.handles); self.assertEqual(self.backend.close_attempts,[])
        self.assertTrue(E.UNRELEASED)

    def test_throwing_acquisition_retains_registered_unreturned_resource(self):
        original=T.SeedBackend.open
        def uncertain(value,path,kind):
            original(value,path,kind); raise OSError('registered-but-unreturned')
        T.SeedBackend.open=uncertain
        try:
            reader=self.reader(); dispose=reader.dispose
            with self.assertRaises(OSError): reader.hold('/',True)
            self.assertTrue(E.UNRELEASED); self.assertTrue(self.backend.handles)
            self.assertIs(E.UNRELEASED[-1][2],self.backend)
            dispose(); self.assertEqual(self.backend.close_attempts,[])
        finally: T.SeedBackend.open=original

    def test_equal_comparing_backend_method_never_invokes_equality_or_close(self):
        reader=self.reader(); dispose=reader.dispose; reader.hold('/',True)
        original=T.SeedBackend.close; calls=self.calls
        class EqualComparing:
            def __eq__(self,other): calls.append('equality'); return True
            def __call__(self,*args): calls.append('foreign')
        T.SeedBackend.close=EqualComparing()
        try:
            with self.assertRaises(E.RetentionEffectsUnavailable): dispose()
            self.assertEqual(calls,[]); self.assertTrue(self.backend.handles)
            self.assertTrue(E.UNRELEASED)
        finally: T.SeedBackend.close=original

    def test_equal_comparing_reader_method_never_invokes_equality_or_close(self):
        reader=self.reader(); dispose=reader.dispose; reader.hold('/',True)
        original=E._Reader.trust; calls=self.calls
        class EqualComparing:
            def __eq__(self,other): calls.append('equality'); return True
            def __call__(self,*args): calls.append('foreign')
        E._Reader.trust=EqualComparing()
        try:
            with self.assertRaises(E.RetentionEffectsUnavailable): dispose()
            self.assertEqual(calls,[]); self.assertTrue(self.backend.handles)
            self.assertTrue(E.UNRELEASED)
        finally: E._Reader.trust=original

    def test_foreign_backend_type_is_denied_before_class_dictionary_observation(self):
        reader=self.reader(); dispose=reader.dispose; reader.hold('/',True)
        original=reader.backend; calls=self.calls
        class ForeignMeta(type):
            def __getattribute__(kind,name):
                if name=='__dict__': calls.append('foreign-class-observation')
                return super().__getattribute__(name)
        class Foreign(metaclass=ForeignMeta): pass
        reader.backend=Foreign()
        try:
            with self.assertRaises(E.RetentionEffectsUnavailable): reader.trust()
            self.assertEqual(calls,[]); self.assertTrue(self.backend.handles)
            self.assertFalse(E.UNRELEASED)
        finally:
            reader.backend=original; dispose()


if __name__=='__main__': unittest.main()
