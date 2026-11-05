"""Injected immutable source controls; no native FS/Git/installer activation.

Composition uses actual V issuance and P.acquire/check with their protected
injected fixtures. Quiet external ancestry is declared before capture, never
refreshed while held; owned fixture roots and source bytes use actual readback.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


C=load('company_source_tree_under_test',ROOT/'scripts/company_source_tree.py')
F=load('source_shared_session_fixtures',ROOT/'tests/test_install_session_stage_binding.py')
M,B,P,T=F.M,F.B,F.P,F.T


def pread(self,fd,count,offset):
    self.pread_calls.append((fd,count,offset))
    if self.pread_hook:return self.pread_hook(fd,count,offset)
    return self.handles[fd]['raw'][offset:offset+count]


# Explicit trusted injected extension only. Existing SeedFiles/StoreFiles and
# their finite caps remain unchanged; no native backend is inferred.
T.SeedBackend.pread=pread


class Fixture(F.Fixture):
    OP='2'*32
    def __init__(self):
        super().__init__()
        self.close_storage()
        self.base=self.t.DATA+'/company/source-releases'
        self.t.backend.directory(self.base,mode=0o700)
        self.t.backend.pread_calls=[];self.t.backend.pread_hook=None
        self.q.values[C.MODULE_PATH]=(ROOT/C.MODULE_PATH).read_bytes()
        self.q.modes[C.MODULE_PATH]='100644'
        self.q.refresh_platform()
        self.reopen()
        self.session=F.Session();self.store_result=None
    def request(self,held,*,shared=F.GLOBAL,store_op=None):
        return C.authenticated_source_request(held,verifier_module=self.V,bootstrap_module=B,
            store_module=M,storage=self.t.storage,operation_id=self.OP,
            store_operation_id=store_op or self.t.OP,installation_request_sha256=shared)
    def store_first(self,*,shared=F.GLOBAL):
        with self.q.held() as held:
            _,_,action,self.records=self.store_request(held,shared)
            with self.session.hold(self.session.prepare('company-platform-store',action)) as parent:
                self.store_result=self.store(held,parent,shared)
            self.close_storage()
        self.session.confirm_store(self,self.store_result)
        self.reopen()
    def materialize(self,held,parent,*,shared=F.GLOBAL,store_op=None,clock=None):
        return C.materialize_authenticated_company_source(held,verifier_module=self.V,bootstrap_module=B,
            store_module=M,parent_module=P,parent=parent,storage=self.t.storage,
            backend_module=SimpleNamespace(SeedBackend=T.SeedBackend),backend=self.t.backend,
            operation_id=self.OP,store_operation_id=store_op or self.t.OP,
            installation_request_sha256=shared,clock=clock)
    @contextmanager
    def current(self,*,action=None,shared=F.GLOBAL):
        with self.q.held() as held:
            request,sha,expected,plan,prior=self.request(held,shared=shared)
            with self.session.hold(self.session.prepare(C.STAGE,action or expected)) as parent:
                yield held,parent,request,sha,plan,prior


class CompositionControls(unittest.TestCase):
    def setUp(self):
        C.UNRELEASED.clear();M.UNRELEASED.clear();B.SEED_UNRELEASED.clear();self.fixtures=[]
    def tearDown(self):
        for f in self.fixtures:
            f.t.backend.fail_close=None;f.close()
        for backend,fd in C.UNRELEASED:
            if fd in backend.handles:backend.close(fd)
        C.UNRELEASED.clear();M.UNRELEASED.clear();B.SEED_UNRELEASED.clear()
    def fixture(self):
        f=Fixture();self.fixtures.append(f);return f
    def test_genuine_issued_source_actual_prior_stage_and_exact_immutable_tree(self):
        f=self.fixture();f.store_first()
        originals={p:n['raw'] for p,n in f.t.backend.nodes.items() if p.startswith(f.store_result['root']+'/')}
        with f.current() as (held,parent,request,sha,plan,prior):
            root=f.base+'/'+request['releaseSha256'];synced=[];sync=f.t.backend.sync
            def measured_sync(fd):
                synced.append(next(p for p,n in f.t.backend.nodes.items() if n is f.t.backend.handles[fd]))
                return sync(fd)
            f.t.backend.sync=measured_sync
            def before_payload(path):
                if path.startswith(root+'/source'):
                    self.assertIn(root+'/intent.json',synced);self.assertIn(root,synced)
            f.t.backend.after_create=before_payload
            result=f.materialize(held,parent)
            self.assertEqual(prior['outcome'],f.store_result)
            self.assertEqual(request['installationRequestSha256'],F.GLOBAL)
            self.assertEqual(request['storeOutcomeSha256'],C.digest(C.canonical(f.store_result)))
            self.assertNotEqual(sha,F.GLOBAL)
            source=result['sourceRoot'];root=result['root']
            self.assertEqual({p[len(source)+1:] for p,n in f.t.backend.nodes.items()
                if p.startswith(source+'/') and n['raw'] is not None},set(plan['files']))
            for name,raw in plan['files'].items():
                row=f.t.backend.nodes[source+'/'+name]
                self.assertEqual(row['raw'],raw);self.assertEqual(stat.S_IMODE(row['info']['st_mode']),0o400)
            dirs=[source]+[source+'/'+n for n in plan['directories']]+[root]
            self.assertTrue(all(stat.S_IMODE(f.t.backend.nodes[p]['info']['st_mode'])==0o500 for p in dirs))
            self.assertEqual(json.loads(f.t.backend.nodes[root+'/intent.json']['raw'])['request'],request)
            self.assertIs(result['ownedSourceHandlesReleased'],True)
            self.assertIs(result['executionAuthorized'],False);self.assertIs(result['fullInstallDenied'],True)
            self.assertIs(result['rebootAuthenticationImplemented'],False)
            self.assertTrue(parent.handles);self.assertTrue(f.t.files.owned)
        self.assertEqual({p:n['raw'] for p,n in f.t.backend.nodes.items() if p in originals},originals)
        self.assertTrue(all(0<count<=65536 for _,count,_ in f.t.backend.pread_calls))
        self.assertEqual(len([p for p in f.t.backend.nodes if p.startswith(root+'/') and '/' not in p[len(root)+1:]]),3)
    def test_planner_effect_free_before_source_stage_intent(self):
        f=self.fixture()
        with f.q.held() as held:
            request,_,action,_,_=f.request(held)
            self.assertEqual(f.t.backend.effects,[])
            self.assertNotIn(f.session.path+'/'+C.STAGE+'.intent',f.session.system.metas)
            self.assertEqual(len(action),64);self.assertEqual(request['storeOperationId'],f.t.OP)
    def test_malformed_or_missing_explicit_shared_hash_precedes_queries_and_output(self):
        f=self.fixture()
        with f.q.held() as held:
            calls=len(f.t.runner.calls)
            for bad in (None,True,0,b'a'*64,'','a'*63,'A'*64,'g'*64):
                with self.subTest(value=repr(bad)),self.assertRaises(ValueError):f.request(held,shared=bad)
            self.assertEqual(len(f.t.runner.calls),calls);self.assertEqual(f.t.backend.effects,[])
    def test_missing_prior_confirmation_actual_parent_refuses_before_source(self):
        f=self.fixture()
        with f.q.held() as held:
            _,_,sa,_=f.store_request(held)
            f.session.prepare('company-platform-store',sa)
            _,_,action,_,_=f.request(held)
            with self.assertRaises(P.ParentUnavailable):
                with f.session.hold(f.session.prepare(C.STAGE,action)):self.fail('unconfirmed prior stage')
            self.assertEqual(f.t.backend.effects,[])
    def test_wrong_held_prior_outcome_denies_even_when_parent_accepts_record(self):
        f=self.fixture();f.store_first()
        path=f.session.path+'/company-platform-store.confirmed'
        intent=f.session.system.stage('company-platform-store',f.store_result['actionSha256'])
        self.assertTrue(intent)
        f.session.system.add(path,F.PT.encoded('install-stage-confirmed-v1',session=F.PT.ARGS.session,
            stage='company-platform-store',action=f.store_result['actionSha256'],outcome='e'*64,independently_confirmed='true'))
        before=len(f.t.backend.effects)
        with f.current() as (held,parent,*_):
            with self.assertRaises(ValueError):f.materialize(held,parent)
        self.assertEqual(len(f.t.backend.effects),before)
    def test_prior_raw_artifact_changed_bytes_denies_before_mkdir(self):
        f=self.fixture();f.store_first();path=f.store_result['root']+'/release.sig'
        f.t.backend.nodes[path]['raw']=b'X'*len(f.t.backend.nodes[path]['raw'])
        before=len(f.t.backend.effects)
        with f.current() as (held,parent,*_):
            with self.assertRaises(ValueError):f.materialize(held,parent)
        self.assertEqual(len(f.t.backend.effects),before)
    def test_wrong_current_action_denies_before_mkdir(self):
        f=self.fixture();f.store_first();before=len(f.t.backend.effects)
        with f.current(action='f'*64) as (held,parent,*_):
            with self.assertRaises(ValueError):f.materialize(held,parent)
        self.assertEqual(len(f.t.backend.effects),before)
    def test_wrong_store_operation_binding_denies_before_mkdir(self):
        f=self.fixture();f.store_first();before=len(f.t.backend.effects)
        with f.q.held() as held:
            _,_,action,_,_=f.request(held,store_op='3'*32)
            with f.session.hold(f.session.prepare(C.STAGE,action)) as parent:
                with self.assertRaises(ValueError):f.materialize(held,parent,store_op='3'*32)
        self.assertEqual(len(f.t.backend.effects),before)
    def test_legacy_omitted_shared_store_intent_denies_before_source(self):
        f=self.fixture();f.store_first();path=f.store_result['root']+'/intent.json'
        row=json.loads(f.t.backend.nodes[path]['raw']);row['request'].pop('installationRequestSha256')
        raw=C.canonical(row);f.t.backend.nodes[path]['raw']=raw
        f.t.backend.nodes[path]['info']['st_size']=len(raw)
        before=len(f.t.backend.effects)
        with f.current() as (held,parent,*_):
            with self.assertRaises(ValueError):f.materialize(held,parent)
        self.assertEqual(len(f.t.backend.effects),before)
    def test_nonempty_source_parent_preserves_orphan_and_denies(self):
        f=self.fixture();f.store_first();orphan=f.base+'/'+'f'*64
        f.t.backend.directory(orphan);before=len(f.t.backend.effects)
        with f.current() as (held,parent,*_):
            with self.assertRaises(ValueError):f.materialize(held,parent)
        self.assertIn(orphan,f.t.backend.nodes);self.assertEqual(len(f.t.backend.effects),before)
    def test_unissued_same_class_never_reads_callback_or_output(self):
        f=self.fixture();calls=[]
        forged=f.V.HeldPlatformSource({}, {}, {}, {}, {},lambda:calls.append('forged'))
        with self.assertRaises(ValueError):f.request(forged)
        self.assertEqual(calls,[]);self.assertEqual(f.t.backend.effects,[])
    def test_quiet_injected_ancestor_drift_expires_genuine_source(self):
        f=self.fixture();ancestor=f.q.root.parent
        with self.assertRaises(ValueError):
            with f.q.held() as held:
                saved=f.q.files.frozen[ancestor]
                f.q.files.frozen[ancestor]=SimpleNamespace(**vars(saved))
                f.q.files.frozen[ancestor].st_nlink+=1
                f.request(held)
        self.assertFalse(f.q.files.records);self.assertFalse(f.q.files.dirs)
        self.assertEqual(f.t.backend.effects,[])


class PlanControls(unittest.TestCase):
    def header(self,files,modes=None):
        modes=modes or {name:'100644' for name in files}
        rows=[dict(path=p,bytes=len(raw),sha256=C.digest(raw),gitMode=modes[p]) for p,raw in sorted(files.items())]
        return modes,dict(fileCount=len(files),totalBytes=sum(map(len,files.values())),files=rows,
            sourceTree=T.independent_source_tree(files,modes))
    def test_independent_tree_order_empty_and_executable_logical_modes(self):
        files={'a/z':b'hello','a.c':b'','z':b'#!'};modes={'a/z':'100644','a.c':'100644','z':'100755'}
        _,header=self.header(files,modes);plan=C.source_plan(files,modes,header)
        self.assertEqual(plan['sourceTree'],T.independent_source_tree(files,modes))
        self.assertEqual(plan['directories'],['a']);self.assertEqual(plan['modes']['z'],'100755')
    def test_wrong_signed_tree_or_rows_denied(self):
        files={'src/x':b'x'};modes,header=self.header(files)
        for change in ('tree','row'):
            wrong=json.loads(json.dumps(header))
            if change=='tree':wrong['sourceTree']='f'*40
            else:wrong['files'][0]['sha256']='f'*64
            with self.subTest(change=change),self.assertRaises(ValueError):C.source_plan(files,modes,wrong)
    def test_path_traversal_case_alias_and_file_directory_conflict_deny(self):
        for files in ({'../escape':b'x'},{'src/a':b'x','src/A':b'y'},
                      {'Src/a':b'x','src/b':b'y'},{'src':b'x','src/a':b'y'}):
            modes={p:'100644' for p in files}
            with self.subTest(paths=list(files)),self.assertRaises(ValueError):C.source_plan(files,modes,{})
    def test_exact2048_file_boundary_and2049_denial(self):
        files={f'src/f{n:04d}':b'' for n in range(2048)};modes,header=self.header(files)
        self.assertEqual(len(C.source_plan(files,modes,header)['files']),2048)
        files['src/overflow']=b'';modes['src/overflow']='100644'
        with self.assertRaises(ValueError):C.source_plan(files,modes,header)
    def test_exact512_directory_boundary_and513_denial(self):
        files={f'd{n:03d}/x':b'' for n in range(512)};modes,header=self.header(files)
        self.assertEqual(len(C.source_plan(files,modes,header)['directories']),512)
        files['overflow/x']=b'';modes['overflow/x']='100644'
        with self.assertRaises(ValueError):C.source_plan(files,modes,header)
    def test_file8MiB_and_total64MiB_strict_policy(self):
        raw=b'x'*(8*1024**2);files={f'src/f{n}':raw for n in range(8)};modes,header=self.header(files)
        self.assertEqual(C.source_plan(files,modes,header)['totalBytes'],64*1024**2)
        files['src/overflow']=b'x';modes['src/overflow']='100644'
        with self.assertRaises(ValueError):C.source_plan(files,modes,header)
        with self.assertRaises(ValueError):C.source_plan({'src/big':raw+b'x'},{'src/big':'100644'}, {})
    def test_signed_count_boolean_and_unknown_mode_refused(self):
        files={'src/x':b''};modes,header=self.header(files);header['fileCount']=True
        with self.assertRaises(ValueError):C.source_plan(files,modes,header)
        with self.assertRaises(ValueError):C.source_plan(files,{'src/x':'120000'},header)


class IOControls(unittest.TestCase):
    def setUp(self):
        C.UNRELEASED.clear();self.backend=T.SeedBackend()
        self.backend.pread_calls=[];self.backend.pread_hook=None
        self.backend.chmod_calls=[];self.backend.fail_chmod=False;self.backend.after_chmod=None
        self.backend.directory('/source-parent')
        self.io=C.SourceFiles(SimpleNamespace(SeedBackend=T.SeedBackend),self.backend)
        self.io.hold('/');self.io.hold('/source-parent',mode=0o700);self.io.inventory('/source-parent',[])
    def tearDown(self):
        self.backend.fail_close=None
        try:self.io.close()
        except ValueError:pass
        for backend,fd in C.UNRELEASED:
            if fd in backend.handles:backend.close(fd)
        C.UNRELEASED.clear()
    def root(self):return self.io.create('/source-parent','release')
    def test_empty_and_multichunk_bytes_exact_readback(self):
        root=self.root();self.io.create(root,'empty',b'');raw=b'x'*(65536*2+7)
        self.io.create(root,'large',raw);self.io.check(readback=True)
        self.assertTrue(all(n<=65536 for _,n,_ in self.backend.pread_calls))
        self.assertEqual(self.backend.nodes[root+'/large']['raw'],raw)
    def test_full_nine_directory_and_file_drift_refused(self):
        root=self.root();leaf=self.io.create(root,'file',b'x')
        for path,field in ((root,'st_nlink'),(root,'st_size'),(root,'st_mtime_ns'),(leaf,'st_ctime_ns')):
            old=self.backend.nodes[path]['info'][field];self.backend.nodes[path]['info'][field]+=1
            with self.subTest(path=path,field=field),self.assertRaises(ValueError):self.io.check_one(path)
            self.backend.nodes[path]['info'][field]=old
    def test_replaced_path_not_held_descriptor_refused(self):
        root=self.root();leaf=self.io.create(root,'file',b'x');old=self.backend.nodes[leaf]
        self.backend.file(leaf,b'x',mode=0o400)
        with self.assertRaises(ValueError):self.io.check_one(leaf)
        self.backend.nodes[leaf]=old
    def test_unknown_extra_inventory_refused(self):
        root=self.root();self.io.create(root,'file',b'x');self.backend.file(root+'/extra',b'x',mode=0o400)
        with self.assertRaises(ValueError):self.io.check()
        self.assertFalse(self.io.active)
    def test_sync_failure_preserves_orphan_no_adoption(self):
        self.backend.fail_sync='release'
        with self.assertRaises(OSError):self.root()
        self.assertIn('/source-parent/release',self.backend.nodes)
        self.assertTrue(self.io.owned)
    def test_zero_write_unknown_preserves_partial(self):
        root=self.root();self.backend.write=lambda fd,raw:0
        with self.assertRaises(ValueError):self.io.create(root,'file',b'payload')
        self.assertEqual(self.backend.nodes[root+'/file']['raw'],b'')
    def test_explicit_chmod_only_mode_and_ctime_transition(self):
        root=self.root();self.io.create(root,'file',b'x');self.io.seal_directory(root)
        self.assertEqual(stat.S_IMODE(self.backend.nodes[root]['info']['st_mode']),0o500)
        self.io.check(readback=True)
    def test_chmod_replacement_or_unexplained_metadata_drift_refused(self):
        root=self.root()
        self.backend.after_chmod=lambda fd:self.backend.handles[fd]['info'].__setitem__('st_mtime_ns',99999)
        with self.assertRaises(ValueError):self.io.seal_directory(root)
    def test_every_close_attempt_and_exact_unknown_reference_retained(self):
        root=self.root();self.io.create(root,'file',b'x');owned=list(self.io.owned)
        bad=owned[-1];self.backend.fail_close=bad
        with self.assertRaises(ValueError):self.io.close()
        self.assertEqual(self.backend.close_attempts,list(reversed(owned)))
        self.assertEqual(C.UNRELEASED,[(self.backend,bad)])
        with self.assertRaises(ValueError):C.SourceFiles(SimpleNamespace(SeedBackend=T.SeedBackend),self.backend)
    def test_readback_short_overflow_nonbytes_and_changed_payload_refused(self):
        root=self.root();leaf=self.io.create(root,'file',b'abc')
        for answer in (b'',b'abcd',bytearray(b'abc'),b'xyz'):
            self.backend.pread_hook=lambda fd,n,o,value=answer:value
            with self.subTest(answer=repr(answer)),self.assertRaises(ValueError):self.io.check_one(leaf,readback=True)
        self.backend.pread_hook=None
    def test_deadline_denies_before_owned_create(self):
        self.io.clock=lambda:self.io.deadline+1
        before=list(self.backend.effects)
        with self.assertRaises(ValueError):self.root()
        self.assertEqual(self.backend.effects,before)
    def test_backend_without_explicit_pread_or_wrong_type_denied(self):
        with self.assertRaises(ValueError):C.SourceFiles(SimpleNamespace(SeedBackend=object),self.backend)
        self.backend.pread=None
        with self.assertRaises(ValueError):C.SourceFiles(SimpleNamespace(SeedBackend=T.SeedBackend),self.backend)
    def test_wrong_created_device_denied_and_retained(self):
        self.backend.after_create=lambda path:self.backend.nodes[path]['info'].__setitem__('st_dev',2)
        with self.assertRaises(ValueError):self.root()
        self.assertIn('/source-parent/release',self.backend.nodes)
    def test_unexplained_parent_link_transition_not_rebased(self):
        self.backend.after_create=lambda path:self.backend.nodes['/source-parent']['info'].__setitem__('st_nlink',99)
        before=dict(self.io.rows['/source-parent']['before'])
        with self.assertRaises(ValueError):self.root()
        self.assertEqual(self.io.rows['/source-parent']['before'],before)
        self.assertFalse(self.io.active)


if __name__=='__main__':
    unittest.main(verbosity=2)
