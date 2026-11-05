"""Injected explicit Linux/amd64 getdents64; no real ctypes or native calls."""
import importlib.util
from pathlib import Path
import stat,struct
from types import SimpleNamespace as N
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('explicit_source_backend',ROOT/'scripts/company_source_guard_backend.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

def record(name,ino=90,kind=8,pad=0,offset=123):
    raw=name if type(name) is bytes else name.encode('ascii');length=(19+len(raw)+1+7)//8*8
    return struct.pack('<QqHB',ino,offset,length,kind)+raw+b'\0'+bytes([pad])*(length-20-len(raw))

class Libc:
    def __init__(self):
        self.calls=[];self.chunks=[record('a')+record('b'),b''];self.cursor={};self.result=None;self.errno=5;self.hook=None;self.buffer=None
    def syscall(self,num,fd,buf,size):
        self.calls.append((num,fd,size))
        if self.hook:self.hook(num,fd,buf,size)
        i=self.cursor.get(fd,0);raw=self.chunks[i] if i<len(self.chunks) else b'';self.cursor[fd]=i+1
        buf.raw=self.buffer if self.buffer is not None else raw+b'\0'*(size-len(raw))
        return len(raw) if self.result is None else self.result

class Ctypes:
    c_long,c_uint,c_void_p=object(),object(),object()
    def __init__(self,libc):self.libc=libc;self.bindings=[];self.widths={self.c_long:8,self.c_uint:4,self.c_void_p:8};self.errno=None
    def sizeof(self,type):return self.widths[type]
    def CFUNCTYPE(self,*types,**kw):
        self.bindings.append((types,kw))
        def bind(symbol):self.bindings.append(symbol);assert symbol==('syscall',self.libc);return self.libc.syscall
        return bind
    def create_string_buffer(self,size):return N(raw=b'\0'*size)
    def byref(self,value):return value
    def get_errno(self):return self.libc.errno
    def set_errno(self,value):self.errno=value

class OS:
    name='posix';O_RDONLY,O_NOFOLLOW,O_CLOEXEC,O_DIRECTORY,O_NONBLOCK=0,1,2,4,8
    def __init__(self):
        self.supports_dir_fd={self.open};self.calls=[];self.next=20;self.held=set();self.fd_result=None
        self.inherit=False;self.inherit_error=False;self.close_result=None;self.close_error=None;self.read_result=None;self.raw=b'hello';self.fstat_hook=None
        self.info=N(**dict(zip(B.FIELDS,(7,90,stat.S_IFDIR|0o500,0,0,2,0,101,202))))
    def open(self,path,flags,**kw):
        self.calls.append(('open',path,flags,kw))
        if self.fd_result is not None:return self.fd_result
        self.next+=1;self.held.add(self.next);return self.next
    def get_inheritable(self,fd):
        self.calls.append(('inherit',fd))
        if self.inherit_error:raise OSError('injected')
        return self.inherit
    def lstat(self,path):self.calls.append(('lstat',path));return self.info
    def fstat(self,fd):self.calls.append(('fstat',fd));return self.fstat_hook(fd) if self.fstat_hook else self.info
    def pread(self,fd,count,offset):self.calls.append(('pread',fd,count,offset));return self.read_result if self.read_result is not None else self.raw[offset:offset+count]
    def close(self,fd):
        self.calls.append(('close',fd))
        if fd==self.close_error:raise OSError('injected close')
        if self.close_result is None:self.held.discard(fd)
        return self.close_result

class Controls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(B.UNRELEASED_HANDLES);self.o=OS();self.l=Libc();self.c=Ctypes(self.l)
        self.sys=N(platform='linux',byteorder='little');self.machine=N(machine=lambda:'x86_64')
        self.d=self.dents();self.b=self.backend();self.fd=self.b.open(None,'/',True)
    def tearDown(self):B.UNRELEASED_HANDLES.clear() # synthetic fixture cleanup only
    def dents(self,**kw):
        args=dict(ctypes_module=self.c,libc=self.l,sys_module=self.sys,machine_module=self.machine);args.update(kw);return B.LinuxAMD64Getdents64(**args)
    def backend(self,**kw):
        args=dict(os_module=self.o,sys_module=self.sys,getdents64=self.d);args.update(kw);return B.ReadOnlySourceBackend(**args)
    def finish(self):
        for fd in list(self.b._owned):
            if fd not in self.b._close_attempted:self.b.close(fd)
        self.assertIs(self.b.require_released(),self.b)
    def closed(self):return [v[1] for v in self.o.calls if v[0]=='close']
    def denied(self,raw):
        self.l.chunks=[raw]
        with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,3)
        self.assertEqual(self.b._owned,{self.fd});self.assertIsNone(self.b._enumeration)
    def test_explicit_amd64_binding_syscall217_widths_errno(self):
        self.assertEqual(self.c.bindings[0],((self.c.c_long,self.c.c_long,self.c.c_uint,self.c.c_void_p,self.c.c_uint),dict(use_errno=True)))
        self.assertEqual(self.d.read(self.fd,4096),record('a')+record('b'));self.assertEqual(self.l.calls,[(217,self.fd,4096)]);self.assertEqual(self.c.errno,0);self.finish()
    def test_unsupported_architecture_endian_width_and_platform(self):
        for kw in (dict(sys_module=N(platform='win32',byteorder='little')),dict(sys_module=N(platform='linux',byteorder='big')),dict(machine_module=N(machine=lambda:'aarch64'))):
            with self.assertRaises(B.SourceBackendUnavailable):self.dents(**kw)
        self.c.widths[self.c.c_void_p]=4
        with self.assertRaises(B.SourceBackendUnavailable):self.dents()
        self.o.name='nt'
        with self.assertRaises(B.SourceBackendUnavailable):self.backend()
        self.o.name='posix';self.o.supports_dir_fd=set()
        with self.assertRaises(B.SourceBackendUnavailable):self.backend()
        self.finish()
    def test_concrete_syscall_adapter_no_callback_fallback(self):
        for value in (None,N(read=lambda *_:b'')):
            with self.assertRaises(B.SourceBackendUnavailable):self.backend(getdents64=value)
        self.finish()
    def test_directory_file_flags_and_openat_parent(self):
        self.assertEqual(self.o.calls[0],('open','/',15,{}));self.b.open(self.fd,'x',False)
        self.assertIn(('open','x',11,dict(dir_fd=self.fd)),self.o.calls);self.finish()
    def test_flags_names_and_paths_deny_before_syscalls(self):
        for key,value in (('O_RDONLY',2),('O_NOFOLLOW',True),('O_NONBLOCK',1),('O_CLOEXEC',0)):
            original=getattr(self.o,key);setattr(self.o,key,value)
            with self.assertRaises(B.SourceBackendUnavailable):self.backend()
            setattr(self.o,key,original)
        before=len(self.o.calls)
        for name in ('../x','a/b','x\\y','x.','é',True,'','.'):
            with self.assertRaises(B.SourceBackendUnavailable):self.b.open(self.fd,name,False)
        for path in ('relative','/a/../b','/a//b','/x/',True):
            with self.assertRaises(B.SourceBackendUnavailable):self.b.lstat(path)
        self.assertEqual(before,len(self.o.calls));self.finish()
    def test_captured_os_reference_independent_of_later_attribute(self):
        self.o.lstat=lambda *_:self.fail('replaced');self.assertEqual(self.b.lstat('/safe')['st_ino'],90);self.finish()
    def test_invalid_borrowed_and_boolean_fd_no_syscall(self):
        before=len(self.o.calls)
        for fd in (True,-1,2**31,self.fd+99,'21'):
            for action in (lambda:self.b.fstat(fd),lambda:self.b.inheritable(fd),lambda:self.b.pread(fd,1,0),lambda:self.b.names(fd,1),lambda:self.b.close(fd)):
                with self.assertRaises(B.SourceBackendUnavailable):action()
        self.assertEqual(before,len(self.o.calls));self.finish()
    def test_closed_nine_metadata_strict_types_and_no_alias(self):
        row=self.b.fstat(self.fd);self.assertEqual(set(row),set(B.FIELDS));row['st_ino']=999;self.assertEqual(self.b.lstat('/safe')['st_ino'],90)
        for value in (True,-1,1.5,None):
            self.o.info.st_size=value
            with self.assertRaises(B.SourceBackendUnavailable):self.b.fstat(self.fd)
        self.o.info.st_size=0;self.finish()
    def test_pread_bounds_and_result_type(self):
        self.o.raw=b'x'*65536;self.assertEqual(len(self.b.pread(self.fd,65536,0)),65536);self.assertEqual(self.b.pread(self.fd,1,B.MAX_OFFSET),b'')
        for raw in (b'ab',bytearray()):
            self.o.read_result=raw
            with self.assertRaises(B.SourceBackendUnavailable):self.b.pread(self.fd,1,0)
        before=len(self.o.calls)
        for count,offset in ((True,0),(0,0),(65537,0),(1,True),(1,-1),(2,B.MAX_OFFSET)):
            with self.assertRaises(B.SourceBackendUnavailable):self.b.pread(self.fd,count,offset)
        self.assertEqual(before,len(self.o.calls));self.finish()
    def test_inherited_new_fd_registered_before_close_and_error(self):
        for value in (True,0,None):
            self.o.inherit=value
            with self.assertRaises(B.SourceBackendUnavailable):self.b.open(self.fd,'x',False)
            self.assertIn(self.o.next,self.closed());self.assertNotIn(self.o.next,self.b._owned)
        self.finish()
    def test_first_inheritable_failure_releases_new_fd(self):
        self.o.inherit_error=True
        with self.assertRaises(OSError):self.b.open(self.fd,'x',False)
        self.assertIn(self.o.next,self.closed());self.finish()
    def test_malformed_open_result_unknown_and_never_blind_closed(self):
        opaque=object();self.o.fd_result=opaque
        with self.assertRaises(B.SourceBackendUnavailable):self.b.open(self.fd,'x',False)
        self.assertIs(B.UNRELEASED_HANDLES[-1][2],opaque);self.assertNotIn(opaque,self.closed());self.b.close(self.fd)
        with self.assertRaises(B.SourceBackendUnavailable):self.b.require_released()
        with self.assertRaises(B.SourceBackendUnavailable):self.backend()
    def test_duplicate_native_fd_retained_no_second_close(self):
        self.o.fd_result=self.fd
        with self.assertRaises(B.SourceBackendUnavailable):self.b.open(self.fd,'x',False)
        self.assertEqual(self.closed(),[]);self.assertEqual(B.UNRELEASED_HANDLES[-1][2],self.fd);self.b.close(self.fd)
        with self.assertRaises(B.SourceBackendUnavailable):self.b.close(self.fd)
        self.assertEqual(self.closed(),[self.fd])
    def test_successful_fd_number_reuse_and_capacity_before_open(self):
        self.b.close(self.fd);self.o.fd_result=self.fd;self.assertEqual(self.b.open(None,'/',True),self.fd)
        self.b._owned.update(range(100,2800));before=len(self.o.calls)
        with self.assertRaises(B.SourceBackendUnavailable):self.b.open(self.fd,'x',False)
        self.assertEqual(before,len(self.o.calls));self.b._owned={self.fd};self.finish()
    def test_separate_dot_fd_and_each_inventory_has_fresh_cursor(self):
        self.assertEqual(self.b.names(self.fd,3),['a','b']);self.assertEqual(self.b.names(self.fd,3),['a','b'])
        opens=[v for v in self.o.calls if v[0]=='open' and v[1]=='.'];self.assertEqual(len(opens),2)
        self.assertTrue(all(v[2]==15 and v[3]==dict(dir_fd=self.fd) for v in opens))
        fds={v[1] for v in self.l.calls};self.assertEqual(len(fds),2);self.assertTrue(fds.isdisjoint({self.fd}));self.assertTrue(fds.issubset(self.closed()));self.finish()
    def test_limit_overflow_sentinel_stops_without_next_call(self):
        self.l.chunks=[record('a',pad=0x99)+record('b')+record('c'),b'do-not-read']
        self.assertEqual(self.b.names(self.fd,2),['a','b']);self.assertEqual(len(self.l.calls),1);self.finish()
    def test_empty_and_dot_inventory_and_invalid_limit(self):
        self.l.chunks=[record('.',kind=4)+record('..',kind=4),b''];self.assertEqual(self.b.names(self.fd,1),[])
        before=len(self.o.calls)
        for limit in (True,0,-1,2562):
            with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,limit)
        self.assertEqual(before,len(self.o.calls));self.finish()
    def test_truncated_bad_reclen_alignment_and_missing_nul(self):
        raw=record('a')
        for bad in (raw[:23],raw[:16]+b'\0\0'+raw[18:],raw[:16]+b'\x19\0'+raw[18:],raw[:19]+b'x'*5):self.denied(bad)
        self.finish()
    def test_duplicate_unsafe_nonascii_zero_inode_and_wrong_type(self):
        for raw in (record('a')+record('a'),record('..')+record('..'),record('../x'),record(b'\xff'),record('a',ino=0),record('a',kind=10)):self.denied(raw)
        self.finish()
    def test_max_name_and_opaque_signed_offset(self):
        name='a'*255;self.l.chunks=[record(name,offset=-1,kind=0),b''];self.assertEqual(self.b.names(self.fd,2),[name]);self.finish()
    def test_initial_dot_fd_identity_mismatch_stops_before_getdents(self):
        self.o.fstat_hook=lambda fd:N(**dict(vars(self.o.info),st_ino=90 if fd==self.fd else 91))
        with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,3)
        self.assertEqual(self.l.calls,[]);self.assertEqual(self.b._owned,{self.fd});self.finish()
    def test_timestamp_drift_after_getdents_denies_without_refresh(self):
        self.l.hook=lambda *_:setattr(self.o.info,'st_mtime_ns',102)
        with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,3)
        self.assertEqual(self.b._owned,{self.fd});self.finish()
    def test_first_dot_fstat_error_still_closes_owned_fd(self):
        def check(fd):
            if fd!=self.fd:raise OSError('injected stat')
            return self.o.info
        self.o.fstat_hook=check
        with self.assertRaises(OSError):self.b.names(self.fd,3)
        self.assertEqual(self.b._owned,{self.fd});self.assertIn(self.o.next,self.closed());self.finish()
    def test_syscall_errno_error_no_retry_and_known_fd_close(self):
        self.l.result=-1
        with self.assertRaises(OSError):self.b.names(self.fd,3)
        self.assertEqual(len(self.l.calls),1);self.assertEqual(self.b._owned,{self.fd});self.finish()
    def test_syscall_bad_result_buffer_errno_and_arguments(self):
        for value in (True,-2,4097):
            self.l.result=value
            with self.assertRaises(B.SourceBackendUnavailable):self.d.read(self.fd,4096)
        self.l.result=0;self.l.buffer=bytearray(4096)
        with self.assertRaises(B.SourceBackendUnavailable):self.d.read(self.fd,4096)
        self.l.buffer=None;self.l.result=-1;self.l.errno=0
        with self.assertRaises(B.SourceBackendUnavailable):self.d.read(self.fd,4096)
        before=len(self.l.calls)
        for fd,size in ((True,1),(-1,1),(2**31,1),(self.fd,True),(self.fd,0),(self.fd,4097)):
            with self.assertRaises(B.SourceBackendUnavailable):self.d.read(fd,size)
        self.assertEqual(before,len(self.l.calls));self.finish()
    def test_repeated_record_attack_is_bounded(self):
        self.l.chunks=[record('.')]*20
        with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,3)
        self.assertLessEqual(len(self.l.calls),2);self.assertFalse(B.UNRELEASED_HANDLES);self.finish()
    def test_false_enumeration_close_unknown_even_after_outer_fd_close(self):
        self.o.close_result=False
        with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,3)
        failed=self.o.next;item=B.UNRELEASED_HANDLES[-1];self.assertEqual(item[2],failed);self.assertEqual(item[3],self.o.close)
        self.o.close_result=None;self.b.close(self.fd)
        with self.assertRaises(B.SourceBackendUnavailable):self.b.require_released()
        before=self.closed()
        with self.assertRaises(B.SourceBackendUnavailable):self.b.close(failed)
        self.assertEqual(before,self.closed())
    def test_throwing_enumeration_close_exact_reference_no_retry(self):
        self.o.close_error=self.o.next+1
        with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,3)
        failed=self.o.next;self.assertEqual(B.UNRELEASED_HANDLES[-1][2],failed);self.b.close(self.fd)
        with self.assertRaises(B.SourceBackendUnavailable):self.b.close(failed)
        self.assertEqual(self.closed().count(failed),1)
    def test_pre_return_inherit_error_and_failed_close_retained(self):
        self.o.inherit_error=True;self.o.close_error=self.o.next+1
        with self.assertRaises(B.SourceBackendUnavailable):self.b.names(self.fd,3)
        self.assertEqual(B.UNRELEASED_HANDLES[-1][2],self.o.next);self.b.close(self.fd)
        with self.assertRaises(B.SourceBackendUnavailable):self.b.require_released()
    def test_outer_release_requires_all_known_descriptors_closed(self):
        with self.assertRaises(B.SourceBackendUnavailable):self.b.require_released()
        self.finish()

if __name__=='__main__':unittest.main(verbosity=2)
