"""Genuine original issuance + injected readonly stage/FD controls; no native."""
from contextlib import contextmanager
from dataclasses import replace
import copy
import importlib.util
from pathlib import Path, PurePosixPath
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module; spec.loader.exec_module(module); return module
W=load('stored_startup_controls',ROOT/'deploy/installer/company_stored_startup.py')
FT=load('stored_startup_entry_fixture',ROOT/'tests/test_company_full_entry.py')
PT=load('stored_startup_parent_fixture',ROOT/'scripts/test-installer-parent.py')
BT=load('stored_startup_os_fixture',ROOT/'tests/test_company_source_guard_backend.py')
INSTALLATION='64a2a5f8-04b9-43b5-9807-122d866db1f1'
WORKER='9'*64


class OS:
    name='posix'; O_RDONLY,O_NOFOLLOW,O_CLOEXEC,O_DIRECTORY,O_NONBLOCK=0,1,2,4,8
    def __init__(self,ram):
        self.ram=ram; self.supports_dir_fd={self.open}; self.close_error=None
    def open(self,name,flags,**options):
        return self.ram.open(options.get('dir_fd'),name,bool(flags&self.O_DIRECTORY))
    def get_inheritable(self,fd):return self.ram.inheritable(fd)
    def lstat(self,path):return N(**self.ram.lstat(path))
    def fstat(self,fd):return N(**self.ram.fstat(fd))
    def pread(self,fd,count,offset):return self.ram.pread(fd,count,offset)
    def close(self,fd):
        if fd==self.close_error:raise OSError('synthetic close')
        return self.ram.close(fd)


class Libc(BT.Libc):
    def __init__(self,ram):super().__init__();self.ram=ram
    def syscall(self,num,fd,buf,size):
        assert num==217 and size==4096
        self.calls.append((num,fd,size)); index=self.cursor.get(fd,0); self.cursor[fd]=index+1
        parent=PurePosixPath(self.ram.handles[fd]['path'])
        names=['.','..']+sorted(PurePosixPath(path).name for path in self.ram.nodes
            if PurePosixPath(path)!=parent and PurePosixPath(path).parent==parent)
        raw=b''.join(BT.record(name) for name in names) if index==0 else b''
        assert len(raw)<=size
        buf.raw=raw+b'\0'*(size-len(raw));return len(raw)


class Fixture(FT.Fixture):
    def __init__(self):super().__init__();self.clock=FT.T.T.Clock();self.ram=None;self.parent_system=None
    @contextmanager
    def scope(self,*,alter=None):
        with self.entry() as entry:
            V,IP,G,BK=(entry.modules[path] for path in (FT.F.VERIFIER,FT.F.PARENT,FT.F.GUARD,FT.F.BACKEND))
            self.q=FT.T.T.Q.Fixture(V,FT.T.T.P)
            self.q.values.update(self.raw);self.q.modes.update({path:'100644' for path in self.raw});self.q.refresh_platform()
            for path in self.q.root.parents:
                self.q.files.changes.setdefault(path,{}).update(st_mtime_ns=101,st_ctime_ns=202,st_size=0)
            with self.q.held() as held:
                request=dict(schemaVersion=1,scope=W.SCOPE,operationId='1'*32,installationId=INSTALLATION,
                    installationRequestSha256='a'*64,dataDir='/data',installRoot='/installation',
                    releaseSha256=held.metadata['releaseSha256'],storeOperationId='2'*32,
                    sourceOperationId='3'*32,storageBindingSha256='d'*64,expectedDevice=7)
                journals,stages,root=W._expected(V,G,held,request)
                self.ram=FT.T.T.ReadOnlySourceBackend();self.ram.build(root,dict(held.files))
                store='/data/company/platform-releases/'+request['releaseSha256']
                self.ram.add('/data/company/platform-releases',True,mode=0o700)
                self.ram.add(store,True,mode=0o500)
                for name,raw in {**dict(held.configs),**dict(held.provenance),W.ARCHIVE:held.archive_bytes}.items():
                    self.ram.add(store+'/'+name,raw=raw)
                for path,raw in journals.items():self.ram.add(path,raw=raw)
                os=OS(self.ram);libc=Libc(self.ram);ctypes=BT.Ctypes(libc)
                dents=BK.LinuxAMD64Getdents64(ctypes_module=ctypes,libc=libc,
                    sys_module=N(platform='linux',byteorder='little'),machine_module=N(machine=lambda:'x86_64'))
                backend=BK.ReadOnlySourceBackend(os_module=os,sys_module=N(platform='linux'),getdents64=dents)
                system=PT.FakeSystem(); self.parent_system=system
                # Convert injected metadata to THIS original parent module's class.
                system.metas={path:IP.Metadata(*(getattr(info,f) for f in IP.FIELDS)) for path,info in system.metas.items()}
                system.parent_dir=system.metas[IP.BASE];system.parent_lock=system.metas[IP.BASE+'/install.lock']
                original_fstat=system.fstat
                system.fstat=lambda fd:IP.Metadata(*(getattr(original_fstat(fd),field) for field in IP.FIELDS))
                system.add=lambda *args,**kwargs:self._add_parent(IP,system,*args,**kwargs)
                old=IP.BASE+'/sessions/'+PT.ARGS.session+'/'+PT.ARGS.stage+'.intent';system.metas.pop(old)
                action=W.sha(b'company-stored-startup-v1:'+W.sha(W.canonical(request)).encode()+b':'+WORKER.encode())
                args=IP.ParentInput(42,11,12,PT.ARGS.session,request['installationRequestSha256'],W.STAGE,action)
                base=IP.BASE+'/sessions/'+args.session
                system.add(base+'/'+W.STAGE+'.intent',PT.encoded('install-stage-v1',session=args.session,stage=W.STAGE,action=action,closed='true'))
                for stage,(stage_action,outcome) in stages.items():
                    system.add(base+'/'+stage+'.intent',PT.encoded('install-stage-v1',session=args.session,stage=stage,action=stage_action,closed='true'))
                    system.add(base+'/'+stage+'.confirmed',PT.encoded('install-stage-confirmed-v1',session=args.session,stage=stage,action=stage_action,outcome=outcome,independently_confirmed='true'))
                state=N(entry=entry,V=V,G=G,IP=IP,BK=BK,held=held,request=request,journals=journals,
                    stages=stages,root=root,backend=backend,os=os,system=system,args=args)
                if alter:alter(state)
                try:
                    with IP.hold_parent(args,system=system) as parent:
                        with G.hold_authenticated_company_source(held,verifier_module=V,source_root=root,
                            expected_device=7,backend_module=BK,backend=backend,clock=self.clock) as guard:
                            state.parent,state.guard=parent,guard;yield state
                    backend.require_released()
                finally:
                    # Fixture-only disposal for deliberately uncertain synthetic FDs.
                    for fd in list(backend._owned):
                        if fd not in backend._close_attempted:
                            try:backend.close(fd)
                            except BaseException:pass
                    BK.UNRELEASED_RESOURCES.clear();G.UNRELEASED_HANDLES.clear()
                    if self.ram:self.ram.handles.clear()
    def _add_parent(self,IP,system,path,body=b'',directory=False,mode=None):
        system.next_inode+=1
        import stat
        info=IP.Metadata(2049,system.next_inode,(stat.S_IFDIR if directory else stat.S_IFREG)|
            (mode if mode is not None else 0o600),0,0,2 if directory else 1,
            0 if directory else len(body),1000000001,2000000002)
        system.metas[path]=info
        if not directory:system.bodies[info.st_ino]=body
        return info
    def hold(self,state,**changes):
        args=dict(full_entry_module=FT.F,held=state.held,source_guard=state.guard,parent=state.parent,
            request=state.request,worker_sha256=WORKER,backend=state.backend,clock=self.clock)
        args.update(changes);return W.hold_confirmed_stored_startup(state.entry,**args)


class StoredStartupControls(unittest.TestCase):
    def setUp(self):self.assertFalse(W.UNRELEASED);self.f=Fixture()
    def tearDown(self):
        self.f.clean();W.UNRELEASED.clear();self.assertFalse(W._ISSUED)
    def deny_hold(self,s,**changes):
        with self.assertRaises((ValueError,TypeError,KeyError)):
            with self.f.hold(s,**changes):self.fail('admitted')
    def test_exact_original_parent_journals_hold_before_compose(self):
        with self.f.scope() as s,self.f.hold(s) as cap:
            self.assertEqual(len(cap._journals),4);self.assertIs(cap._parent,s.parent)
            self.assertEqual(cap.inspection()['status'],'held')
            with cap.assembly() as assembly:
                self.assertIs(assembly.modules[FT.F.VERIFIER],s.V)
                self.assertIs(assembly.modules[FT.F.PARENT],s.IP)
                S=assembly.modules['scripts/startup_binding.py'];R=assembly.modules['scripts/runtime_pair_init.py']
                self.assertIs(R.S,S);self.assertIs(S.verify.__kwdefaults__['layout'],S.L.verify)
                with self.assertRaises(ValueError):
                    with R.ParentStageAuthority().hold({}):self.fail('native pair')
            result=cap.inspection()
            for key in ('changed','runtimePairInitialized','backupReady','nativeQualified'):self.assertIs(result[key],False)
            self.assertIs(result['fullInstallDenied'],True)
    def test_expected_journals_match_actual_store_and_source_request_protocols(self):
        with self.f.scope() as s:
            B=load('stored_protocol_bootstrap',ROOT/'scripts/bootstrap.py')
            M=load('stored_protocol_store',ROOT/W.M_PATH);C=load('stored_protocol_source',ROOT/W.C_PATH)
            storage=object.__new__(B.SeedStorage);storage.active=True;storage.fresh=True
            storage.data='/data';storage.root='/installation';storage.installation_id=INSTALLATION
            storage.binding_sha256='d'*64;storage.check=lambda:None
            prior=C.expected_store(M,s.held,s.V,B,storage,'2'*32,'a'*64)
            for path,raw in s.journals.items():
                if path.startswith(prior['root']+'/'):self.assertEqual(raw,prior['originals'][path.rsplit('/',1)[1]])
            source,request_sha,action,_,_=C.authenticated_source_request(s.held,verifier_module=s.V,
                bootstrap_module=B,store_module=M,storage=storage,operation_id='3'*32,
                store_operation_id='2'*32,installation_request_sha256='a'*64)
            import json
            journal=json.loads(s.journals[str(PurePosixPath(s.root).parent)+'/intent.json'])
            self.assertEqual(journal['request'],source);self.assertEqual(journal['requestSha256'],request_sha)
            self.assertEqual(journal['actionSha256'],action);self.assertEqual(s.stages['company-platform-store'][1],prior['outcomeSha256'])
    def test_late_source_journal_malformed_denies_zero_operational_exec(self):
        with self.f.scope() as s:
            path=str(PurePosixPath(s.root).parent)+'/bytes-verified.json'
            self.f.ram.nodes[path]['raw']=b'{}\n';self.f.ram.nodes[path]['info']['st_size']=3
            with patch('builtins.exec',side_effect=AssertionError('op compile')):
                self.deny_hold(s)
    def test_partial_missing_store_journal_preserved(self):
        with self.f.scope() as s:
            path=next(p for p in s.journals if p.endswith('/verified.json'))
            self.f.ram.nodes.pop(path)
            before=set(self.f.ram.nodes);self.deny_hold(s);self.assertEqual(set(self.f.ram.nodes),before)
    def test_false_or_float_terminal_types_refused_by_exact_raw_bytes(self):
        with self.f.scope() as s:
            path=next(p for p in s.journals if p.endswith('/verified.json'))
            original=self.f.ram.nodes[path]['raw']
            for old,new in ((b'"schemaVersion":1',b'"schemaVersion":true'),
                            (b'"schemaVersion":1',b'"schemaVersion":1.0'),
                            (b'"exactCapturedBytesRetained":true',b'"exactCapturedBytesRetained":false')):
                raw=original.replace(old,new);self.assertNotEqual(raw,original)
                self.f.ram.nodes[path]['raw']=raw;self.f.ram.nodes[path]['info']['st_size']=len(raw);self.deny_hold(s)
            self.f.ram.nodes[path]['raw']=original;self.f.ram.nodes[path]['info']['st_size']=len(original)
    def test_cross_session_confirmation_refuses_original_parent_acquisition(self):
        def mutate(s):
            path=s.IP.BASE+'/sessions/'+s.args.session+'/company-source-materialize.confirmed'
            info=s.system.metas[path];raw=s.system.bodies[info.st_ino]
            s.system.bodies[info.st_ino]=raw.replace(s.args.session.encode(),b's-Other0000000')
        with self.assertRaises(ValueError):
            with self.f.scope(alter=mutate):self.fail('cross session')
    def test_stale_prior_outcome_is_not_journal_flag_authority(self):
        with self.f.scope() as s:
            path=s.parent.session_path+'/company-source-materialize.confirmed'
            fd,info,raw=s.parent.files[path];old=s.stages['company-source-materialize'][1]
            changed=raw.replace(old.encode(),b'0'*64);s.system.bodies[info.st_ino]=changed
            s.parent.files[path]=(fd,info,changed);self.deny_hold(s)
    def test_current_parent_action_and_request_exact(self):
        with self.f.scope() as s:
            for args in (replace(s.args,action='0'*64),replace(s.args,request='0'*64)):
                old=s.parent.arguments;s.parent.arguments=args;self.deny_hold(s);s.parent.arguments=old
    def test_request_closed_types_paths_release_and_operation_binding(self):
        with self.f.scope() as s:
            for field,bad in (('schemaVersion',True),('expectedDevice',7.0),('dataDir','/data/../x'),
                              ('installationId','64A2A5F8-04B9-43B5-9807-122D866DB1F1'),
                              ('releaseSha256','0'*64),('sourceOperationId','4'*32),
                              ('storageBindingSha256','0'*64)):
                request=dict(s.request);request[field]=bad;self.deny_hold(s,request=request)
            self.deny_hold(s,request=dict(s.request,unexpected=True))
    def test_forged_entry_parent_guard_backend_deny_before_journal_io(self):
        with self.f.scope() as s:
            before=len(self.f.ram.events)
            for changes in (dict(parent=True),dict(source_guard=True),dict(backend=N()),dict(held=True)):
                self.deny_hold(s,**changes)
            self.assertEqual(len(self.f.ram.events),before)
    def test_unknown_native_default_never_constructed_or_sibling_imported(self):
        with self.f.scope() as s:
            with (patch('subprocess.Popen',side_effect=AssertionError('native')),patch('ctypes.CDLL',side_effect=AssertionError('native')),
                  patch('importlib.util.spec_from_file_location',side_effect=AssertionError('sibling'))):
                with self.f.hold(s) as cap,cap.assembly():pass
    def test_expiry_caught_boundary_expires_cap_and_prevents_compile(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.hold(s) as cap:
            self.f.clock.value=601
            with self.assertRaises(ValueError):cap.recheck()
            self.assertNotIn(cap,W._ISSUED)
            with patch('builtins.exec',side_effect=AssertionError('compile')):
                with self.assertRaises(ValueError):
                    with cap.assembly():self.fail('expired')
    def test_parent_death_after_admission_expires_before_compose(self):
        with self.assertRaises(ValueError):
            with self.f.scope() as s,self.f.hold(s) as cap:
                s.system.dead=True
                with self.assertRaises(ValueError):
                    with cap.assembly():self.fail('dead parent')
                self.assertNotIn(cap,W._ISSUED)
    def test_same_metadata_content_drift_refuses_held_recheck(self):
        with self.assertRaises(ValueError):
            with self.f.scope() as s,self.f.hold(s) as cap:
                path=next(p for p in s.journals if p.endswith('/verified.json'))
                self.f.ram.nodes[path]['raw']=b'x'+s.journals[path][1:]
                with self.assertRaises(ValueError):cap.recheck()
                self.assertNotIn(cap,W._ISSUED)
    def test_path_or_fd_replacement_refuses_and_preserves_partial_records(self):
        with self.assertRaises(ValueError):
            with self.f.scope() as s,self.f.hold(s) as cap:
                path=next(iter(s.journals));old=self.f.ram.nodes[path]
                self.f.ram.add(path,raw=old['raw']);self.assertNotEqual(old['info']['st_ino'],self.f.ram.nodes[path]['info']['st_ino'])
                with self.assertRaises(ValueError):cap.recheck()
                self.assertIn(path,self.f.ram.nodes)
    def test_unexpected_store_child_denies_before_operational_compile(self):
        with self.f.scope() as s:
            path=next(p for p in s.journals if p.endswith('/verified.json'));root=str(PurePosixPath(path).parent)
            self.f.ram.add(root+'/unknown',raw=b'preserve')
            self.deny_hold(s);self.assertIn(root+'/unknown',self.f.ram.nodes)
    def test_known_journal_close_before_backend_release_and_outer_guard_close(self):
        with self.f.scope() as s:
            with self.f.hold(s) as cap:own=list(cap._owned)
            self.assertTrue(all(fd not in s.backend._owned for fd in own))
            with self.assertRaises(ValueError):s.backend.require_released() # guard still holds source FDs
        self.assertFalse(self.f.ram.handles)
    def test_unknown_journal_close_retains_exact_refs_and_blocks_new_admission(self):
        with self.assertRaises(ValueError):
            with self.f.scope() as s:
                with self.f.hold(s) as cap:s.os.close_error=cap._owned[-1]
        self.assertTrue(W.UNRELEASED);self.assertIs(W.UNRELEASED[0][0],cap)
        self.assertIs(W.UNRELEASED[0][2],s.backend);self.assertIs(W.UNRELEASED[0][3],s.parent)
        with self.assertRaises(ValueError):
            with W.hold_confirmed_stored_startup(None,full_entry_module=True,held=True,source_guard=True,
                parent=True,request={},worker_sha256=WORKER,backend=True):self.fail('unknown reentry')
    def test_public_constructor_cannot_invoke_saved_contexts(self):
        fake=W.StoredStartup()
        with self.assertRaises(ValueError):fake.recheck()
        with self.assertRaises(ValueError):fake.inspection()
        with self.assertRaises(ValueError):
            with fake.assembly():self.fail('fake')
    def test_initialized_inspection_denies_missing_adapters_before_compile(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.hold(s) as cap:
            with patch('builtins.exec',side_effect=AssertionError('compile')):
                with self.assertRaises(ValueError):cap.inspect_initialized(inputs={})
            self.assertNotIn(cap,W._ISSUED)
    def test_original_startup_verifier_missing_state_cannot_initialize(self):
        class MissingFiles:
            def require_root(self):pass
            def protected(self,*_,**__):raise ValueError('missing independently initialized host state')
        def denied(*_,**__):raise AssertionError('no command/gate/init/native')
        inputs=dict(host_directory='/etc/autosoft',files=MissingFiles(),command=denied,mount=denied,
            layout=denied,gate_factory=denied,allocation_factory=denied,read_state=denied,clock=lambda:0,timeout=1)
        with self.assertRaises(ValueError),self.f.scope() as s,self.f.hold(s) as cap:
            with self.assertRaises(ValueError):cap.inspect_initialized(inputs=inputs)
            self.assertNotIn(cap,W._ISSUED)
    def test_public_subclass_callbacks_and_fake_close_denied_before_io(self):
        calls=[]
        class Fake(W.StoredStartup):
            def recheck(self):calls.append('forged callback');return self
        fake=Fake();fake._backend=N(close=lambda fd:calls.append(('close',fd)));fake._owned=[77]
        for call in (lambda:W.StoredStartup.inspection(fake),lambda:W.StoredStartup.close(fake)):
            with self.assertRaises(ValueError):call()
        with self.assertRaises(ValueError):
            with W.StoredStartup.assembly(fake):self.fail('forged')
        self.assertEqual(calls,[])
    def test_closed_capability_cannot_reuse_old_descriptor_scope(self):
        with self.f.scope() as s:
            with self.f.hold(s) as cap:own=list(cap._owned)
            before=len(self.f.ram.events)
            with self.assertRaises(ValueError):cap.close()
            with self.assertRaises(ValueError):cap.inspection()
            self.assertEqual(before,len(self.f.ram.events));self.assertFalse(set(own)&s.backend._owned)


class BorrowedFreshStartupControls(unittest.TestCase):
    def setUp(self):self.assertFalse(W.UNRELEASED);self.f=Fixture()
    def tearDown(self):
        self.f.clean();W.UNRELEASED.clear();self.assertFalse(W._ISSUED)
    def fresh(self,s):return s.entry.fresh_installation_modules(s.held)
    def deny_borrow(self,s,value):
        with self.assertRaises(ValueError),self.f.hold(s) as cap:
            with self.assertRaises(ValueError):
                with cap.assembly(fresh_assembly=value):self.fail('borrow admitted')
            self.assertNotIn(cap,W._ISSUED)
    def test_bound_borrow_keeps_exact_bootstrap_store_source_and_no_compile(self):
        with self.f.scope() as s,self.fresh(s) as fresh:
            fresh.bind_source_guard(s.guard);before=dict(fresh.modules)
            with self.f.hold(s) as cap:
                with patch('builtins.compile',side_effect=AssertionError('recompile')):
                    with cap.assembly(fresh_assembly=fresh) as assembly:
                        self.assertIs(assembly,fresh)
                        for path in ('scripts/bootstrap.py',W.M_PATH,W.C_PATH):
                            self.assertIs(assembly.modules[path],before[path])
                        self.assertIs(assembly.modules[FT.F.VERIFIER],s.V)
                        self.assertIs(assembly.modules[FT.F.PARENT],s.IP)
                        R=assembly.modules['scripts/runtime_pair_init.py']
                        self.assertIs(R.S,assembly.modules['scripts/startup_binding.py'])
                        with self.assertRaises(ValueError):
                            with R.ParentStageAuthority().hold({}):self.fail('native authority')
            self.assertIs(fresh.recheck(),fresh)
            self.assertEqual(fresh.call('scripts/installation_identity.py','installation_id',INSTALLATION),INSTALLATION)
            self.assertFalse(set(cap._owned)&s.backend._owned)
    def test_default_retained_route_still_composes_distinct_operational_modules(self):
        with self.f.scope() as s,self.fresh(s) as fresh:
            fresh.bind_source_guard(s.guard)
            with self.f.hold(s) as cap,cap.assembly() as retained:
                self.assertIsNot(retained,fresh)
                for path in ('scripts/bootstrap.py',W.M_PATH,W.C_PATH):
                    self.assertIsNot(retained.modules[path],fresh.modules[path])
                self.assertIs(retained.modules[FT.F.VERIFIER],fresh.modules[FT.F.VERIFIER])
            self.assertIs(fresh.recheck(),fresh)
    def test_unbound_issued_fresh_assembly_cannot_enter_stored_startup(self):
        with self.f.scope() as s,self.fresh(s) as fresh:
            self.deny_borrow(s,fresh)
            self.assertIs(fresh.recheck(),fresh)
    def test_public_constructor_and_subclass_callbacks_never_run(self):
        with self.f.scope() as s:
            L=s.entry.modules[FT.F.LOADER];calls=[]
            class Forged(L.FreshInstallationAssembly):
                def recheck(self):calls.append('fake');return self
            for value in (L.FreshInstallationAssembly(),Forged()):
                value._entry=s.entry.origin;value._source=s.held;value._guard=s.guard
                value.recheck=lambda:calls.append('instance callback')
                self.deny_borrow(s,value)
            self.assertEqual(calls,[])
    def test_foreign_original_loader_type_cannot_borrow(self):
        with self.f.scope() as s:
            other=load('stored_fresh_foreign_loader',ROOT/'scripts/company_captured_loader.py')
            fake=other.FreshInstallationAssembly()
            fake._entry=s.entry.origin;fake._source=s.held;fake._guard=s.guard
            self.deny_borrow(s,fake)
    def test_same_issued_assembly_requires_exact_origin_source_and_guard(self):
        with self.f.scope() as s,self.fresh(s) as fresh:
            fresh.bind_source_guard(s.guard)
            for name in ('_entry','_source','_guard'):
                original=getattr(fresh,name);setattr(fresh,name,object())
                try:self.deny_borrow(s,fresh)
                finally:setattr(fresh,name,original)
            self.assertIs(fresh.recheck(),fresh)
    def test_closed_issued_assembly_cannot_reenter_even_with_saved_bindings(self):
        with self.f.scope() as s:
            with self.fresh(s) as fresh:fresh.bind_source_guard(s.guard)
            self.deny_borrow(s,fresh)
    def test_late_borrowed_failure_expires_startup_and_keeps_outer_ownership(self):
        with self.f.scope() as s,self.fresh(s) as fresh:
            fresh.bind_source_guard(s.guard)
            with self.assertRaises(RuntimeError),self.f.hold(s) as cap:
                with cap.assembly(fresh_assembly=fresh):raise RuntimeError('injected business failure')
            self.assertNotIn(cap,W._ISSUED);self.assertIs(fresh.recheck(),fresh)
    def test_caught_source_drift_denies_later_borrow_before_business_callback(self):
        with self.assertRaises(ValueError),self.f.scope() as s,self.fresh(s) as fresh,self.f.hold(s) as cap:
            fresh.bind_source_guard(s.guard)
            path=str(next(path for path,row in s.guard._rows.items() if not row['directory']))
            self.f.ram.nodes[path]['raw']=b'changed'
            with patch('builtins.compile',side_effect=AssertionError('compile')):
                with self.assertRaises(ValueError):
                    with cap.assembly(fresh_assembly=fresh):self.fail('stale guard')
            self.assertNotIn(cap,W._ISSUED)
    def test_initialized_inspection_reuses_original_verifier_without_compile(self):
        calls=[]
        class MissingFiles:
            def require_root(self):calls.append('require root')
            def protected(self,*args,**kwargs):
                calls.append(('missing state',args,kwargs));raise ValueError('independently initialized state absent')
        def denied(*_,**__):raise AssertionError('no native/init/command')
        inputs=dict(host_directory='/etc/autosoft',files=MissingFiles(),command=denied,mount=denied,
            layout=denied,gate_factory=denied,allocation_factory=denied,read_state=denied,clock=lambda:0,timeout=1)
        with self.assertRaises(ValueError),self.f.scope() as s,self.fresh(s) as fresh,self.f.hold(s) as cap:
            fresh.bind_source_guard(s.guard)
            with patch('builtins.compile',side_effect=AssertionError('compile')):
                with self.assertRaises(ValueError):cap.inspect_initialized(inputs=inputs,fresh_assembly=fresh)
            self.assertTrue(calls);self.assertNotIn(cap,W._ISSUED)


if __name__=='__main__':unittest.main(verbosity=2)
