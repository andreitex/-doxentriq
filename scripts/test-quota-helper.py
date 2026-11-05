"""Synthetic journal/protocol controls. These are not native XFS qualification."""
import ast,copy,importlib.util,json,os,stat,sys,tempfile,time,types,unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('quota_test_runtime',HERE/'quota_runtime.py');Q=importlib.util.module_from_spec(spec);spec.loader.exec_module(Q)
APP='d9224505-f564-44e5-a697-16e1451fc44a'
REQUEST={'appId':APP,'name':'documents','sizeMb':16}
KEY=APP+'/documents'
def state(status='active'):return {'nextProjectId':10001,'projects':{KEY:{'projectId':10000,'sizeMb':16,'status':status}}}

class InjectedAdmission:
    # Legacy controls keep their original journal/native assertions. The new
    # focused suite uses actual Gate/Allocation code with injected OS policy.
    def admit(self,_):return self
    def mark_possible_effect(self):pass
    def complete(self,_):pass
    def abort_before_effect(self):pass
    def release(self):pass

class InjectedAllocation:
    def __init__(self,data):self.path=data/'quota/projects.json'
    @contextmanager
    def acquire(self):yield self
    def read_state(self,read):return read(self.path)
    def commit(self,value,*,read_state,write_state):write_state(self.path,value)

class Tests(unittest.TestCase):
    def setUp(self):
        for target,replacement in (('checkpoint_gate',lambda _:InjectedAdmission()),('allocation_store',InjectedAllocation),('storage_owner',lambda _:None)):
            item=patch.object(Q,target,replacement);item.start();self.addCleanup(item.stop)

    def test_isolated_importlib_caller_resolves_only_sibling_without_path_mutation(self):
        before=list(sys.path)
        spec=importlib.util.spec_from_file_location('quota_helper_import_fixture',HERE/'quota-helper.py')
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        self.assertEqual(sys.path,before)
        self.assertEqual(Path(helper._runtime.__file__),HERE/'quota_runtime.py')
        helper.DATA=Path('/synthetic-data')
        with patch.object(helper,'create_storage',return_value={'synthetic':True}) as create:
            self.assertEqual(helper.provision(REQUEST),{'synthetic':True})
            create.assert_called_once_with(helper.DATA,REQUEST)
            create.reset_mock()
            with self.assertRaises(ValueError):helper.provision({**REQUEST,'name':'../escape'})
            create.assert_not_called()

    def test_request_rejects_traversal_boolean_noncanonical_extra_and_wrong_types(self):
        self.assertEqual(Q.validate_request(REQUEST),REQUEST)
        for value in ([],{**REQUEST,'name':'../../escape'},{**REQUEST,'sizeMb':True},{**REQUEST,'sizeMb':0},{**REQUEST,'appId':APP.upper()},{**REQUEST,'extra':1},{**REQUEST,'name':[]},{**REQUEST,'appId':False}):
            with self.assertRaises((ValueError,TypeError,AttributeError)):Q.validate_request(value)

    def test_json_duplicates_nonfinite_and_raw_bounds_rejected(self):
        for raw in (b'{"appId":1,"appId":2}',b'{"x":NaN}',b'\xff',b''):
            with self.assertRaises((ValueError,UnicodeError)):Q.decode(raw)
        with self.assertRaises(ValueError):Q.decode(b'{}',1)

    def test_state_project_collisions_invalid_identity_and_unknown_records_rejected(self):
        self.assertEqual(Q.validate_state(state()),state())
        variants=[]
        for field,value in (('projectId',True),('projectId',10001),('sizeMb',True),('status','uncertain'),('other',1)):
            item=state();item['projects'][KEY][field]=value;variants.append(item)
        other=state();other['projects'][APP+'/other']=dict(other['projects'][KEY]);variants.append(other)
        variants.extend(({'nextProjectId':True,'projects':{}},{'nextProjectId':10000,'projects':{'../x':{}}}))
        for value in variants:
            with self.assertRaises(ValueError):Q.validate_state(value)

    def test_pending_cannot_be_replayed_or_silently_resized(self):
        events=[]
        for value in (REQUEST,{**REQUEST,'sizeMb':32}):
            with patch.object(Q,'protected_directory'):
                with self.assertRaises(ValueError):Q.provision(Path('/safe'),value,mount=lambda *_:'/dev/mapper/autosoft-data',read_state=lambda _:state('pending'),write_state=lambda *_:events.append('write'),command=lambda *_:events.append('command'),limits=lambda *_:events.append('limits'))
        self.assertEqual(events,[])

    def fixture(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        root=Path(directory.name);(root/'runtime/storage').mkdir(parents=True)
        value={'nextProjectId':10000,'projects':{}};events=[]
        def read(_):return copy.deepcopy(value)
        def write(_,item):events.append('commit_'+item['projects'][KEY]['status']);value.clear();value.update(copy.deepcopy(item))
        def command(args):events.append('limit' if 'limit ' in ' '.join(args) else 'project');return ''
        return root,value,events,read,write,command

    def test_first_dispatch_commits_pending_before_any_native_write_and_checks_twice(self):
        root,value,events,read,write,command=self.fixture()
        with patch.object(Q,'protected_directory'),patch.object(Q.os,'chown',side_effect=lambda *_:events.append('chown'),create=True),patch.object(Q.stat,'S_IMODE',return_value=0o755):
            result=Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=write,command=command,limits=lambda *_:events.append('proof'),sync=lambda *_:events.append('sync'))
        self.assertEqual(events,['commit_pending','project','limit','proof','chown','proof','sync','sync','sync','commit_active','proof'])
        self.assertTrue(result['quotaEnforced']);self.assertEqual(value['projects'][KEY]['status'],'active')

    def test_lost_write_result_retains_pending_and_next_request_cannot_dispatch(self):
        root,value,events,read,write,command=self.fixture()
        def failure(*_):raise RuntimeError('private diagnostic')
        with patch.object(Q,'protected_directory'),patch.object(Q.os,'chown',create=True),patch.object(Q.stat,'S_IMODE',return_value=0o755):
            with self.assertRaises(RuntimeError):Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=write,command=command,limits=failure)
            self.assertEqual(value['projects'][KEY]['status'],'pending');before=list(events)
            with self.assertRaises(ValueError):Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=write,command=command,limits=failure)
        self.assertEqual(events,before)

    def test_failed_directory_sync_never_commits_active_or_replays(self):
        root,value,events,read,write,command=self.fixture()
        with patch.object(Q,'protected_directory'),patch.object(Q.os,'chown',create=True),patch.object(Q.stat,'S_IMODE',return_value=0o755):
            with self.assertRaises(RuntimeError):Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=write,command=command,limits=lambda *_:None,sync=lambda *_:(_ for _ in ()).throw(RuntimeError('sync unavailable')))
            self.assertEqual(value['projects'][KEY]['status'],'pending');before=list(events)
            with self.assertRaises(ValueError):Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=write,command=command,limits=lambda *_:None)
        self.assertEqual(events,before)

    def test_failed_pending_commit_creates_no_directory_or_native_dispatch(self):
        root,value,events,read,write,command=self.fixture()
        with patch.object(Q,'protected_directory'):
            with self.assertRaises(RuntimeError):Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=lambda *_:(_ for _ in ()).throw(RuntimeError('commit unavailable')),command=command,limits=lambda *_:None)
        self.assertFalse((root/'runtime/storage'/APP).exists());self.assertEqual(events,[])

    def test_existing_leaf_not_adopted_or_overwritten(self):
        root,value,events,read,write,command=self.fixture()
        path=root/'runtime/storage'/APP/'documents';path.mkdir(parents=True);(path/'sentinel').write_text('retain')
        with patch.object(Q,'protected_directory'):
            with self.assertRaises(ValueError):Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=write,command=command,limits=lambda *_:None)
        self.assertEqual(events,[]);self.assertEqual((path/'sentinel').read_text(),'retain')

    def test_active_retry_is_read_only_and_still_requires_native_proof(self):
        root,value,events,read,write,command=self.fixture();value.update(state())
        path=root/'runtime/storage'/APP/'documents'
        class Info:st_uid=10001;st_gid=10001
        def lstat(p):
            if p==path:return Info()
            return original(p)
        original=Path.lstat
        with patch.object(Q,'protected_directory'),patch.object(Path,'lstat',lstat),patch.object(Q.os,'chown',side_effect=AssertionError('must not chown'),create=True):
            result=Q.provision(root,REQUEST,mount=lambda *_:'encrypted',read_state=read,write_state=write,command=command,limits=lambda *_:events.append('read_proof'))
        self.assertEqual(events,['read_proof','read_proof']);self.assertTrue(result['quotaEnforced'])

    def test_identity_authentication_rejects_other_bearer_unicode_and_surrogates(self):
        token='a'*40
        self.assertTrue(Q.authenticated('Bearer '+token,token))
        for value in ('Bearer '+token+'x','Bearer µ','Bearer \ud800',None):self.assertFalse(Q.authenticated(value,token))

    def test_bounded_command_small_success_and_nonzero_private_failure(self):
        self.assertEqual(Q.output([sys.executable,'-c','print("ok")']),'ok'+os.linesep)
        with self.assertRaisesRegex(Q.QuotaUnavailable,'^Quota command is unavailable$'):Q.output([sys.executable,'-c','import sys;print("private-value");sys.exit(1)'])

    def test_bounded_command_overflow_and_timeout_reap_without_exposing_text(self):
        start=time.monotonic()
        with self.assertRaisesRegex(Q.QuotaUnavailable,'^Quota command is unavailable$'):Q.output([sys.executable,'-c','print("private-value"*10000)'],maximum=100)
        self.assertLess(time.monotonic()-start,6)
        start=time.monotonic()
        with self.assertRaisesRegex(Q.QuotaUnavailable,'^Quota command is unavailable$'):Q.output([sys.executable,'-c','import time;time.sleep(30)'],seconds=0.1)
        self.assertLess(time.monotonic()-start,6)

    def test_readback_requires_both_exact_hard_limits_and_zero_soft_limits(self):
        record=state()['projects'][KEY];source='/dev/mapper/autosoft-data'
        Q.parse_quota_dump('fs = '+source+'\n10000 0 32768 0 100000\n',record,source)
        for row in ('10000 0 32768 0 0','10000 0 32767 0 100000','10000 1 32768 0 100000','10000 0 32768 1 100000','10001 0 32768 0 100000','10000 0 32768 0 100000 1'):
            with self.assertRaises(ValueError):Q.parse_quota_dump('fs = '+source+'\n'+row,record,source)

    def test_readback_rejects_wrong_source_and_duplicate_project_rows(self):
        record=state()['projects'][KEY]
        for text in ('fs = /dev/foreign\n10000 0 32768 0 100000','fs = /dev/mapper/autosoft-data\n10000 0 32768 0 100000\n10000 0 32768 0 100000'):
            with self.assertRaises(ValueError):Q.parse_quota_dump(text,record,'/dev/mapper/autosoft-data')

    def test_inode_tool_must_agree_with_kernel_project_and_inheritance_flags(self):
        text='fsxattr.projid = 10000\nfsxattr.xflags = 0x200 [proj-inherit]\n'
        Q.parse_inode_stat(text,10000,0x200)
        for changed in (text.replace('10000','10001'),text.replace('0x200','0x0'),text+text,text+'fsxattr.projid = foreign\n'):
            with self.assertRaises(ValueError):Q.parse_inode_stat(changed,10000,0x200)

    def socket_directory(self,uid=0,gid=0,mode=0o750,exists=True):
        # Execute the actual startup function with injected filesystem identity;
        # no claim about native systemd, ownership or Unix sockets is made.
        tree=ast.parse((HERE/'quota-helper.py').read_bytes())
        fn=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prepare_socket_directory')
        events=[];info=types.SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFDIR|mode)
        directory=types.SimpleNamespace(parent='run',lstat=lambda:info,mkdir=lambda **kw:events.append(('mkdir',kw)))
        def chown(p,user,group):events.append(('chown',user,group));info.st_uid=user;info.st_gid=group
        def chmod(p,bits):events.append(('chmod',bits));info.st_mode=stat.S_IFDIR|bits
        namespace={'require':Q.require,'stat':stat,'os':types.SimpleNamespace(path=types.SimpleNamespace(lexists=lambda _:exists),chown=chown,chmod=chmod),'protected_directory':lambda _:None}
        exec(compile(ast.Module(body=[fn],type_ignores=[]),'quota-directory-test','exec'),namespace)
        return lambda:namespace['prepare_socket_directory'](directory),events,info

    def test_startup_accepts_systemd_root_group_and_sets_only_exact_runtime_directory(self):
        run,events,info=self.socket_directory()
        run();self.assertEqual(events,[('chown',0,10001)]);self.assertEqual(info.st_gid,10001)

    def test_startup_preserves_correct_group_and_refuses_foreign_identity(self):
        run,events,info=self.socket_directory(gid=10001);run();self.assertEqual(events,[])
        for uid,gid,mode in ((10001,0,0o750),(0,77,0o750),(0,0,0o770),(0,0,0o700)):
            run,events,_=self.socket_directory(uid,gid,mode)
            with self.assertRaises(ValueError):run()
            self.assertEqual(events,[])

    def test_startup_new_directory_gets_explicit_mode_despite_private_umask(self):
        run,events,info=self.socket_directory(mode=0o700,exists=False)
        run();self.assertEqual(events,[('mkdir',{'mode':0o700}),('chmod',0o750),('chown',0,10001)])

if __name__=='__main__':unittest.main(verbosity=2)
