"""Injected Linux filesystem controls; no native output, crypto or activation."""
import copy
import hashlib
import importlib.util
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


E=load('full_package_emit_controls','deploy/installer/company_full_package_emit.py')
B=load('full_package_emit_builder','deploy/installer/build-full-package.py')
G=load('full_package_emit_readonly','scripts/company_source_guard_backend.py')
C=load('full_package_emit_consumer','deploy/installer/company_full_package_loader.py')


class Buffer:
    def __init__(self,size):self.data=bytearray(size)
    @property
    def raw(self):return bytes(self.data)


class Space:
    """Finite kernel fixture with explicit separate directory cursors and FDs."""
    def __init__(self):
        self.nodes={};self.fds={};self.cursor={};self.closed=[];self.events=[];self.serial=0;self.nextfd=10
        self.hook=None;self.close_failure=None;self.write_failure=False;self.sync_failure=None
        self.partial_write=0;self.bad_create=None;self.first_fstat_failure=None
        self.root='/station/source';self.destination='/station/output/new-package'
        for name in ('/','/station','/station/source','/station/output'):
            self.add(name,True,0o755)
        paths=set(B.PACKAGE_PATHS)|set(B.OPERATIONAL_PATHS)
        self.raw={path:('# captured inert '+path+'\n').encode() for path in paths}
        for name,raw in self.raw.items():
            parts=name.split('/')
            for i in range(1,len(parts)):
                parent=self.root+'/'+ '/'.join(parts[:i])
                if parent not in self.nodes:self.add(parent,True,0o755)
            self.add(self.root+'/'+name,False,0o644,raw)
        self.pins={name:self.row(self.raw[name]) for name in B.PACKAGE_PATHS}
        self.catalog={name:dict(**self.row(self.raw[name]),gitMode='100644') for name in B.OPERATIONAL_PATHS}
        self.os=SimpleNamespace(name='posix',O_RDONLY=0,O_RDWR=2,O_CREAT=64,O_EXCL=128,
            O_NOFOLLOW=256,O_CLOEXEC=512,O_NONBLOCK=1024,O_DIRECTORY=2048,
            open=self.open,lstat=self.lstat,fstat=self.fstat,get_inheritable=self.inheritable,
            pread=self.pread,write=self.write,fsync=self.sync,fchmod=self.chmod,mkdir=self.mkdir,
            close=self.close,geteuid=lambda:0,getegid=lambda:0)
        self.os.supports_dir_fd={self.os.open,self.os.mkdir}
        self.system=SimpleNamespace(platform='linux',byteorder='little')
        self.ctypes=SimpleNamespace(c_long='long',c_void_p='ptr',c_uint='uint',
            sizeof=lambda name:4 if name=='uint' else 8,CFUNCTYPE=lambda *a,**k:lambda target:self.getdents,
            create_string_buffer=Buffer,byref=lambda x:x,get_errno=lambda:0,set_errno=lambda x:None)
        self.getter=G.LinuxAMD64Getdents64(ctypes_module=self.ctypes,libc=object(),
            sys_module=self.system,machine_module=SimpleNamespace(machine=lambda:'x86_64'))
        self.readonly=G.ReadOnlySourceBackend(os_module=self.os,sys_module=self.system,getdents64=self.getter)
        self.backend=E.FullPackageBackend(os_module=self.os,sys_module=self.system,
            read_backend_module=G,read_backend=self.readonly)

    @staticmethod
    def row(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

    def add(self,path,directory,mode,raw=b''):
        self.serial+=1
        self.nodes[path]=dict(directory=directory,raw=raw,info=dict(st_dev=9,st_ino=self.serial,
            st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|mode,st_uid=0,st_gid=0,
            st_nlink=2 if directory else 1,st_size=4096 if directory else len(raw),st_mtime_ns=100,st_ctime_ns=200))

    def tick(self,path):
        self.nodes[path]['info']['st_mtime_ns']+=1;self.nodes[path]['info']['st_ctime_ns']+=1

    def names(self,path):
        return sorted(n.rsplit('/',1)[-1] for n in self.nodes if n!='/' and str(PurePosixPath(n).parent)==path)

    def at(self,path,dir_fd):
        if dir_fd is None:return path
        parent=self.fds[dir_fd][0]
        return parent if path=='.' else str(PurePosixPath(parent)/path)

    def open(self,path,flags,mode=0,*,dir_fd=None):
        name=self.at(path,dir_fd);self.events.append(('open',name,flags,dir_fd))
        if flags & self.os.O_CREAT:
            if name in self.nodes:raise FileExistsError(name)
            self.add(name,False,mode);self.tick(str(PurePosixPath(name).parent))
        if name not in self.nodes:raise FileNotFoundError(name)
        fd=self.nextfd;self.nextfd+=1;self.fds[fd]=(name,self.nodes[name]);self.cursor[fd]=0
        if flags & self.os.O_CREAT and self.bad_create is not None:return self.bad_create
        return fd

    def lstat(self,path):return SimpleNamespace(**copy.copy(self.nodes[path]['info']))
    def fstat(self,fd):
        if self.first_fstat_failure==self.fds[fd][0]:
            self.first_fstat_failure=None;raise OSError('injected first fstat')
        return SimpleNamespace(**copy.copy(self.fds[fd][1]['info']))
    def inheritable(self,fd):return False
    def pread(self,fd,size,offset):
        self.events.append(('pread',self.fds[fd][0],size,offset))
        return self.fds[fd][1]['raw'][offset:offset+size]
    def write(self,fd,raw):
        path,node=self.fds[fd];self.events.append(('write',path,len(raw)))
        if self.write_failure:raise OSError('injected write loss')
        count=min(len(raw),self.partial_write) if self.partial_write else len(raw)
        node['raw']+=raw[:count];node['info']['st_size']=len(node['raw']);self.tick(path)
        if self.hook:
            hook,self.hook=self.hook,None;hook(path)
        return count
    def sync(self,fd):
        path=self.fds[fd][0];self.events.append(('sync',path))
        if path==self.sync_failure:raise OSError('injected fsync loss')
    def chmod(self,fd,mode):
        path,node=self.fds[fd];self.events.append(('chmod',path,mode))
        node['info']['st_mode']=stat.S_IFMT(node['info']['st_mode'])|mode;self.tick(path)
    def mkdir(self,name,mode,*,dir_fd):
        path=self.at(name,dir_fd);self.events.append(('mkdir',path))
        if path in self.nodes:raise FileExistsError(path)
        self.add(path,True,mode);parent=self.fds[dir_fd][0];self.nodes[parent]['info']['st_nlink']+=1;self.tick(parent)
    def close(self,fd):
        self.closed.append(fd);self.events.append(('close',self.fds[fd][0]))
        if self.fds[fd][0]==self.close_failure:raise OSError('injected uncertain close')
        del self.fds[fd];self.cursor.pop(fd,None)
    def getdents(self,number,fd,buffer,size):
        assert number==217;path=self.fds[fd][0];names=['.','..',*self.names(path)];out=b''
        index=self.cursor[fd]
        while index<len(names):
            name=names[index];target=path if name=='.' else str(PurePosixPath(path).parent) if name=='..' else str(PurePosixPath(path)/name)
            node=self.nodes[target];length=(19+len(name)+1+7)//8*8
            row=node['info']['st_ino'].to_bytes(8,'little')+(index+1).to_bytes(8,'little')+length.to_bytes(2,'little')+bytes([4 if node['directory'] else 8])+name.encode()+b'\0'
            row=row.ljust(length,b'\0')
            if len(out)+len(row)>size:break
            out+=row;index+=1
        self.cursor[fd]=index;buffer.data[:len(out)]=out;return len(out)
    def emit(self,**kwargs):
        args=dict(builder_module=B,package_pins=self.pins,operational_catalog=self.catalog,key_fingerprint='5'*64,
            backend_module=E,backend=self.backend,clock=lambda:1)
        args.update(kwargs)
        # The real builder's Path abstraction is injected to simulate Linux on
        # Windows; it is selected before the emitter snapshots its namespace.
        with patch.object(B,'Path',PurePosixPath):
            return E.emit_full_package(self.root,self.destination,**args)


class EmitterControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(E.UNRELEASED);self.assertFalse(G.UNRELEASED_RESOURCES);self.s=Space()
    def tearDown(self):
        # Synthetic fixture references only; product exposes no reset/retry API.
        E.UNRELEASED.clear();G.UNRELEASED_RESOURCES.clear();B.UNRELEASED.clear()
    def reject(self,**kwargs):
        with self.assertRaises((ValueError,OSError,KeyError)):self.s.emit(**kwargs)
    def no_output(self):self.assertFalse(any(e[0]=='mkdir' for e in self.s.events))

    def test_exact_canonical_three_leaf_output_sealed_and_all_fds_closed(self):
        result=self.s.emit();root=self.s.destination
        self.assertEqual(self.s.names(root),sorted(E.LEAVES));self.assertEqual(stat.S_IMODE(self.s.nodes[root]['info']['st_mode']),0o500)
        for name in E.LEAVES:self.assertEqual(stat.S_IMODE(self.s.nodes[root+'/'+name]['info']['st_mode']),0o400)
        raw=self.s.nodes[root+'/full-package.json']['raw']
        self.assertEqual(B.validate_package(raw,package_pins=self.s.pins,operational_catalog=self.s.catalog,fingerprint='5'*64)['scope'],B.SCOPE)
        self.assertTrue(result['ownedResourcesReleased']);self.assertFalse(result['signatureCreated']);self.assertFalse(result['installationAuthorized'])
        self.assertFalse(self.s.fds);self.assertFalse(self.s.readonly._owned);self.assertFalse(self.s.backend._owned)

    def test_existing_consumer_accepts_exact_emitted_wire_before_first_compile(self):
        self.s.emit();raw=self.s.nodes[self.s.destination+'/full-package.json']['raw']
        class StopBeforeCompile(Exception):pass
        with patch.object(C,'_register',side_effect=StopBeforeCompile) as register:
            with self.assertRaises(StopBeforeCompile):
                with C.authenticated_full_package(raw,package_module=B,package_pins=self.s.pins,
                    operational_catalog=self.s.catalog,key_fingerprint='5'*64):self.fail('must stop')
        self.assertEqual(register.call_count,1);self.assertEqual(register.call_args.args[0],C.FULL_ENTRY)
        self.assertFalse(C.UNRELEASED)

    def test_intent_durable_before_payload_and_terminal_before_directory_lock(self):
        self.s.emit();events=self.s.events;r=self.s.destination
        intent_sync=events.index(('sync',r+'/intent.json'))
        payload_open=next(i for i,e in enumerate(events) if e[0]=='open' and e[1]==r+'/full-package.json')
        final_sync=events.index(('sync',r+'/verified.json'));lock=events.index(('chmod',r,0o500))
        self.assertLess(intent_sync,payload_open);self.assertLess(final_sync,lock)
        self.assertEqual(sum(e[0]=='mkdir' for e in events),1)

    def test_bad_package_pin_refuses_before_any_output_effect(self):
        pins=copy.deepcopy(self.s.pins);pins[next(iter(pins))]['sha256']='0'*64
        self.reject(package_pins=pins);self.no_output();self.assertFalse(self.s.fds)

    def test_missing_or_extra_catalog_and_boolean_byte_count_refuse(self):
        for change in ('extra','missing','boolean'):
            s=Space();catalog=copy.deepcopy(s.catalog)
            if change=='extra':catalog['extra.py']=next(iter(catalog.values()))
            elif change=='missing':catalog.pop(next(iter(catalog)))
            else:catalog[next(iter(catalog))]['bytes']=True
            with self.assertRaises(ValueError):s.emit(operational_catalog=catalog)
            self.assertFalse(any(e[0]=='mkdir' for e in s.events))

    def test_invalid_fingerprint_and_missing_explicit_backend_refuse(self):
        self.reject(key_fingerprint='untrusted');self.no_output()
        self.reject(backend=SimpleNamespace());self.no_output()

    def test_source_symlink_mode_owner_or_hardlink_refuse_before_output(self):
        name=self.s.root+'/scripts/bootstrap.py';original=copy.copy(self.s.nodes[name]['info'])
        for key,value in [('st_mode',stat.S_IFLNK|0o644),('st_mode',stat.S_IFREG|0o666),('st_uid',10001),('st_nlink',2)]:
            s=Space();s.nodes[name]['info'][key]=value
            with self.assertRaises(ValueError):s.emit()
            self.assertFalse(any(e[0]=='mkdir' for e in s.events));self.assertFalse(s.fds)
        self.assertEqual(self.s.nodes[name]['info'],original)

    def test_source_first_fstat_failure_closes_registered_fd(self):
        self.s.first_fstat_failure=self.s.root+'/scripts/bootstrap.py';self.reject()
        self.no_output();self.assertFalse(self.s.fds);self.assertFalse(E.UNRELEASED)

    def test_directory_ancestor_drift_during_write_denies_without_refresh(self):
        self.s.hook=lambda path:self.s.tick('/station/source')
        self.reject();self.assertIn(self.s.destination,self.s.nodes)
        self.assertNotIn(self.s.destination+'/full-package.json',self.s.nodes);self.assertFalse(self.s.fds)

    def test_stable_metadata_source_byte_corruption_is_detected(self):
        name=self.s.root+'/scripts/bootstrap.py'
        self.s.hook=lambda path:self.s.nodes[name].update(raw=b'X'*len(self.s.nodes[name]['raw']))
        self.reject();self.assertFalse(self.s.fds)

    def test_replaced_source_inode_while_original_fd_held_denies(self):
        name=self.s.root+'/scripts/bootstrap.py'
        def replace(path):
            old=self.s.nodes[name];self.s.add(name,False,0o644,old['raw'])
        self.s.hook=replace;self.reject();self.assertFalse(self.s.fds)

    def test_builder_namespace_drift_denies_after_opened_output_retained(self):
        original=B.sha
        self.s.hook=lambda path:setattr(B,'sha',lambda raw:'0'*64)
        try:self.reject();self.assertIn(self.s.destination+'/intent.json',self.s.nodes)
        finally:B.sha=original
        self.assertFalse(self.s.fds)

    def test_existing_destination_or_orphan_is_preserved_not_adopted(self):
        self.s.add(self.s.destination,True,0o700);self.s.add(self.s.destination+'/intent.json',False,0o400,b'old')
        self.reject();self.assertEqual(self.s.nodes[self.s.destination+'/intent.json']['raw'],b'old');self.no_output()

    def test_extra_output_entry_denies_exact_inventory(self):
        self.s.hook=lambda path:self.s.add(self.s.destination+'/surprise',False,0o400,b'x')
        self.reject();self.assertIn(self.s.destination+'/surprise',self.s.nodes);self.assertFalse(self.s.fds)

    def test_write_and_fsync_errors_preserve_fresh_partial_root(self):
        for fail in ('write','sync'):
            s=Space();s.write_failure=fail=='write';s.sync_failure=s.destination+'/intent.json' if fail=='sync' else None
            with self.assertRaises(OSError):s.emit()
            self.assertIn(s.destination,s.nodes);self.assertNotIn(s.destination+'/full-package.json',s.nodes);self.assertFalse(s.fds)

    def test_short_writes_complete_bounded_chunks_and_exact_readback(self):
        self.s.partial_write=17;self.s.emit()
        writes=[e[2] for e in self.s.events if e[0]=='write'];self.assertTrue(writes);self.assertLessEqual(max(writes),E.CHUNK)
        self.assertFalse(self.s.fds)

    def test_output_readback_corruption_denies_and_retains_bytes(self):
        def corrupt(path):self.s.nodes[path]['raw']=b'Z'*len(self.s.nodes[path]['raw'])
        self.s.hook=corrupt;self.reject();self.assertIn(self.s.destination+'/intent.json',self.s.nodes);self.assertFalse(self.s.fds)

    def test_unknown_terminal_close_denies_success_attempts_every_other_close_once(self):
        self.s.close_failure=self.s.destination+'/verified.json';self.reject()
        self.assertTrue(E.UNRELEASED);self.assertEqual(len(self.s.fds),1)
        self.assertEqual(len(self.s.closed),len(set(self.s.closed)))
        before=list(self.s.events);self.reject();self.assertEqual(self.s.events,before)
        self.assertTrue(any(row[0] is self.s.backend for row in E.UNRELEASED if len(row)>1))

    def test_malformed_create_handle_retained_without_blind_close(self):
        marker=object();self.s.bad_create=marker;self.reject()
        self.assertTrue(any(row[2] is marker for row in E.UNRELEASED if len(row)>2));self.assertNotIn(marker,self.s.closed)

    def test_logical_deadline_and_nonfinite_clock_deny_before_output(self):
        count=[0]
        def clock():count[0]+=1;return count[0]*100
        self.reject(clock=clock);self.no_output()
        for value in (float('inf'),float('nan')):
            with self.assertRaises(ValueError):self.s.emit(clock=lambda:value)

    def test_output_source_overlap_and_noncanonical_paths_deny(self):
        with patch.object(B,'Path',PurePosixPath):
            for destination in ('/station/source/output','/station/output/../bad','//station/output','/new'):
                with self.assertRaises(ValueError):E.emit_full_package(self.s.root,destination,builder_module=B,
                    package_pins=self.s.pins,operational_catalog=self.s.catalog,key_fingerprint='5'*64,
                    backend_module=E,backend=self.s.backend)
        self.no_output()

    def test_concrete_backend_uses_exact_exclusive_openat_flags(self):
        self.s.emit();created=[e for e in self.s.events if e[0]=='open' and e[2]&self.s.os.O_CREAT]
        self.assertEqual(len(created),3)
        for _,name,flags,parent in created:
            self.assertIsInstance(parent,int)
            for bit in (self.s.os.O_RDWR,self.s.os.O_CREAT,self.s.os.O_EXCL,self.s.os.O_NOFOLLOW,self.s.os.O_CLOEXEC,self.s.os.O_NONBLOCK):self.assertTrue(flags&bit)

    def test_backend_rejects_unsupported_platform_before_filesystem_operations(self):
        before=list(self.s.events)
        with self.assertRaises(ValueError):E.FullPackageBackend(os_module=self.s.os,sys_module=SimpleNamespace(platform='win32'),read_backend_module=G,read_backend=self.s.readonly)
        self.assertEqual(self.s.events,before)

    def test_bounded_directory_overflow_stops_and_closes_enumeration(self):
        for i in range(66):self.s.add('/station/output/extra'+str(i),False,0o400,b'x')
        self.reject();self.no_output();self.assertFalse(self.s.fds);self.assertFalse(G.UNRELEASED_RESOURCES)

    def test_enumeration_close_unknown_visible_to_outer_completion(self):
        self.s.close_failure='/station/output';self.reject();self.no_output()
        self.assertTrue(G.UNRELEASED_RESOURCES);self.assertTrue(E.UNRELEASED)
        self.assertEqual(len(self.s.closed),len(set(self.s.closed)))


class CleanupDriftControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(E.UNRELEASED);self.assertFalse(G.UNRELEASED_RESOURCES);self.s=Space()
    def tearDown(self):
        E.UNRELEASED.clear();G.UNRELEASED_RESOURCES.clear();B.UNRELEASED.clear()
    def reject(self):
        with self.assertRaises((ValueError,OSError,KeyError)):self.s.emit()
    def once(self):self.assertEqual(len(self.s.closed),len(set(self.s.closed)))
    def output_fd(self):
        return next(fd for fd,(path,node) in self.s.fds.items() if path==self.s.destination+'/intent.json')

    def test_changed_writer_fd_helper_never_runs_and_known_closes_finish(self):
        called=[]
        def malicious(*args):called.append(args);raise AssertionError('changed helper called')
        original=E.FullPackageBackend._fd
        self.s.hook=lambda path:setattr(E.FullPackageBackend,'_fd',malicious)
        try:self.reject()
        finally:E.FullPackageBackend._fd=original
        self.assertEqual(called,[]);self.assertFalse(self.s.fds);self.assertFalse(E.UNRELEASED);self.once()

    def test_changed_readonly_fd_helper_never_runs_during_unwind(self):
        called=[];original=G.ReadOnlySourceBackend._fd
        self.s.hook=lambda path:setattr(G.ReadOnlySourceBackend,'_fd',lambda *args:called.append(args))
        try:self.reject()
        finally:G.ReadOnlySourceBackend._fd=original
        self.assertEqual(called,[]);self.assertFalse(self.s.fds);self.assertFalse(E.UNRELEASED);self.once()

    def test_changed_readonly_close_never_runs_and_original_syscall_releases(self):
        called=[];original=G.ReadOnlySourceBackend.close
        self.s.hook=lambda path:setattr(G.ReadOnlySourceBackend,'close',lambda *args:called.append(args))
        try:self.reject()
        finally:G.ReadOnlySourceBackend.close=original
        self.assertEqual(called,[]);self.assertFalse(self.s.fds);self.assertFalse(G.UNRELEASED_RESOURCES);self.once()

    def test_changed_release_helpers_never_run_after_drift(self):
        for cls in (E.FullPackageBackend,G.ReadOnlySourceBackend):
            self.s=Space();called=[];original=cls.require_released
            self.s.hook=lambda path:setattr(cls,'require_released',lambda *args:called.append(args))
            try:self.reject()
            finally:cls.require_released=original
            self.assertEqual(called,[]);self.assertFalse(self.s.fds);self.assertFalse(E.UNRELEASED);self.once()

    def test_changed_os_close_never_runs_and_frozen_close_is_used(self):
        called=[];original=self.s.os.close
        self.s.hook=lambda path:setattr(self.s.os,'close',lambda *args:called.append(args))
        self.reject()
        self.assertIsNot(self.s.os.close,original);self.assertEqual(called,[])
        self.assertFalse(self.s.fds);self.assertFalse(E.UNRELEASED);self.once()

    def test_replaced_writer_registry_retains_exact_refs_and_closes_known_readonly(self):
        original=self.s.backend._owned;replacement=set();held=[]
        def change(path):held.append(self.output_fd());self.s.backend._owned=replacement
        self.s.hook=change;self.reject();fd=held[0]
        self.assertEqual(set(self.s.fds),{fd});self.assertNotIn(fd,self.s.closed);self.once()
        self.assertTrue(any(row[1]=='ownership-registry-unknown' and row[2][1] is original
            and row[2][2] is replacement for row in E.UNRELEASED))
        before=list(self.s.closed);self.reject();self.assertEqual(self.s.closed,before)

    def test_overlap_fd_is_retained_other_owned_closes_are_attempted_once(self):
        held=[]
        def change(path):
            fd=self.output_fd();held.append(fd);self.s.readonly._owned.add(fd)
        self.s.hook=change;self.reject();fd=held[0]
        self.assertEqual(set(self.s.fds),{fd});self.assertNotIn(fd,self.s.closed);self.once()
        self.assertIn(fd,self.s.backend._owned);self.assertIn(fd,self.s.readonly._owned)
        self.assertTrue(any(row[1]=='fd-ownership-overlap-or-attempted' and row[2]==fd for row in E.UNRELEASED))

    def test_already_attempted_writer_fd_is_not_closed_again(self):
        held=[]
        def change(path):
            fd=self.output_fd();held.append(fd);self.s.backend._attempted.add(fd)
        self.s.hook=change;self.reject();fd=held[0]
        self.assertEqual(set(self.s.fds),{fd});self.assertNotIn(fd,self.s.closed);self.once()
        self.assertIn(fd,self.s.backend._attempted);self.assertTrue(E.UNRELEASED)

    def test_opaque_or_overcap_registry_is_retained_without_iteration_or_close(self):
        class Opaque:
            def __contains__(self,value):return False
            def __iter__(self):raise AssertionError('opaque registry iterated')
        for replacement in (Opaque(),set(range(1000,1000+E.MAX_HELD+1))):
            self.s=Space();before=[]
            def change(path):before.extend(self.s.closed);self.s.backend._owned=replacement
            self.s.hook=change
            self.reject();self.assertTrue(self.s.fds);self.assertTrue(E.UNRELEASED)
            self.assertTrue(any(row[1]=='ownership-registry-unknown' and row[2][2] is replacement for row in E.UNRELEASED))
            self.assertEqual(self.s.closed,before);E.UNRELEASED.clear()

    def test_unknown_transient_readonly_enumeration_is_retained_without_retry(self):
        held=[];release=self.s.readonly._calls['close']
        def change(path):
            fd=next(fd for fd,(name,node) in self.s.fds.items() if name=='/station/output')
            held.append(fd);self.s.readonly._enumeration=fd;self.s.readonly._close_attempted.add(fd)
            self.s.readonly._unknown=True;G.UNRELEASED_RESOURCES.append((self.s.readonly,'fd',fd,release))
        self.s.hook=change;self.reject();fd=held[0]
        self.assertEqual(set(self.s.fds),{fd});self.assertNotIn(fd,self.s.closed);self.once()
        self.assertTrue(any(row[0] is self.s.readonly and row[2]==fd and row[3] is release for row in G.UNRELEASED_RESOURCES))
        self.assertEqual(self.s.readonly._enumeration,fd);self.assertTrue(E.UNRELEASED)


if __name__=='__main__':unittest.main(verbosity=2)
