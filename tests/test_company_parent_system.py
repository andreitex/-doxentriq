"""Original P with injected OS/ctypes/getdents/poll; no native construction."""
import importlib.util
from pathlib import Path
import stat
import struct
import sys
from types import SimpleNamespace as N
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
PT=load('tracked_parent_data','scripts/test-installer-parent.py')
P=PT.P
BK=load('tracked_parent_getdents','scripts/company_source_guard_backend.py')
A=load('tracked_parent_system','deploy/installer/company_parent_system.py')
ARGS=PT.ARGS

def dent(name,ino=5,kind=8):
    raw=name.encode();length=(19+len(raw)+1+7)//8*8
    return struct.pack('<QqHB',ino,0,length,kind)+raw+b'\0'*(length-19-len(raw))

class Clock:
    def __init__(self):self.now=0
    def __call__(self):return self.now

class OS:
    name='posix';O_RDONLY,O_NOFOLLOW,O_CLOEXEC,O_DIRECTORY,O_NONBLOCK=0,1,2,4,8
    def __init__(self):
        data=PT.FakeSystem();self.metas=dict(data.metas);self.bodies=dict(data.bodies)
        self.held={};self.calls=[];self.next=100;self.inherit=False;self.fd_result=None;self.close_error=None
        self.close_result=None;self.read_hook=None;self.fstat_hook=None;self.dead=False;self.parent=42;self.uid=(0,0,0)
        self.supports_dir_fd={self.open,self.stat,self.readlink};self.parent_fds={11:P.BASE,12:P.BASE+'/install.lock'}
        self.proc_dirs={'/proc/73','/proc/42','/proc/73/fd','/proc/73/fdinfo','/proc/42/fdinfo',
            '/proc/sys','/proc/sys/kernel','/proc/sys/kernel/random'}
        for i,path in enumerate(sorted(self.proc_dirs)):
            self.metas[path]=P.Metadata(4,2000+i,stat.S_IFDIR|0o555,0,0,2,0,1,2)
        self.binary=P.Metadata(2049,3000,stat.S_IFREG|0o755,0,0,1,77,1,2)
        self.metas['/usr/bin/bash']=self.binary
    def path(self,path,kw):
        if 'dir_fd' not in kw:return path
        root=self.held[kw['dir_fd']][0]
        return root if path=='.' else root.rstrip('/')+'/'+path
    def proc_raw(self,path):
        if path.endswith('/status'):
            pid=int(path.split('/')[2]);ppid=self.parent if pid==73 else 1
            return f'Name:\t{"bash" if pid==42 else "python"}\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nTracerPid:\t0\nUid:\t0 0 0 0\nGid:\t0 0 0 0\n'.encode()
        if path=='/proc/42/stat':
            values=['S']+['1']*49;values[19]='123456';return ('42 (bash) '+' '.join(values)+'\n').encode()
        if path.endswith('/boot_id'):return b'00000000-0000-4000-8000-000000000001\n'
        if '/fdinfo/' in path:
            pid,fd=int(path.split('/')[2]),int(path.rsplit('/',1)[1])
            if pid==73:
                target,meta=self.held[fd]
                if target=='pidfd':return f'pos:\t0\nflags:\t02000002\nmnt_id:\t9\nino:\t{meta.st_ino}\nPid:\t42\nNSpid:\t42\n'.encode()
                flags='02100000';locked=False
            else:meta=self.metas[self.parent_fds[fd]];flags='0100000';locked=fd==12
            raw=f'pos:\t0\nflags:\t{flags}\nmnt_id:\t77\nino:\t{meta.st_ino}\n'
            if locked:raw+=f'lock:\t1: FLOCK ADVISORY WRITE 37 08:01:{meta.st_ino} 0 EOF\n'
            return raw.encode()
        raise AssertionError(path)
    def metadata(self,path,follow=True):
        if path in self.metas:return self.metas[path]
        if path in ('/proc/42/exe',):return self.binary
        if '/ns/' in path:return P.Metadata(4,55 if path.endswith('/pid') else 66,stat.S_IFREG|0o444,0,0,1,0,1,2)
        if '/fd/' in path:
            pid,fd=int(path.split('/')[2]),int(path.rsplit('/',1)[1])
            return self.metas[self.parent_fds[fd]] if pid==42 else self.held[fd][1]
        if path.startswith('/proc/'):
            self.proc_raw(path);return P.Metadata(4,4000+sum(path.encode()),stat.S_IFREG|0o444,0,0,1,0,1,2)
        raise AssertionError(path)
    def stat(self,path,**kw):
        full=self.path(path,kw);self.calls.append(('stat',full,kw));return self.metadata(full,kw.get('follow_symlinks',True))
    def open(self,path,flags,**kw):
        full=self.path(path,kw);self.calls.append(('open',full,flags,kw))
        if self.fd_result is not None:return self.fd_result
        self.next+=1;self.held[self.next]=(full,self.metadata(full));return self.next
    def fstat(self,fd):
        self.calls.append(('fstat',fd));return self.fstat_hook(fd) if self.fstat_hook else self.held[fd][1]
    def get_inheritable(self,fd):
        if self.inherit=='error':raise OSError('fixture')
        return self.inherit
    def pread(self,fd,count,offset):return self.bodies[self.held[fd][1].st_ino][offset:offset+count]
    def read(self,fd,count):
        if self.read_hook:return self.read_hook(fd,count)
        return self.proc_raw(self.held[fd][0])[:count]
    def close(self,fd):
        self.calls.append(('close',fd))
        if fd==self.close_error:raise OSError('fixture-close')
        if self.close_result is None:del self.held[fd]
        return self.close_result
    def readlink(self,path,**kw):
        full=self.path(path,kw);self.calls.append(('readlink',full))
        if '/ns/' in full:
            kind=full.rsplit('/',1)[1];return kind+':['+str(self.metadata(full).st_ino)+']'
        if full=='/proc/42/exe':return '/usr/bin/bash'
        pid,fd=int(full.split('/')[2]),int(full.rsplit('/',1)[1])
        return self.parent_fds[fd] if pid==42 else self.held[fd][0]
    def getpid(self):return 73
    def getppid(self):return self.parent
    def getresuid(self):return self.uid
    def getresgid(self):return (0,0,0)
    def pidfd_open(self,pid,flags):
        self.calls.append(('pidfd',pid,flags));self.next+=1
        self.held[self.next]=('pidfd',P.Metadata(99,9000,0o700,0,0,1,0,1,2));return self.next
    def major(self,dev):return dev>>8
    def minor(self,dev):return dev&255
    def names(self,path):
        if path=='/proc/73/fd':return [(str(fd),meta.st_ino,10) for fd,(name,meta) in self.held.items()]
        prefix=path.rstrip('/')+'/'
        return [(p[len(prefix):],m.st_ino,4 if stat.S_ISDIR(m.st_mode) else 8)
            for p,m in self.metas.items() if p.startswith(prefix) and '/' not in p[len(prefix):]]

class Libc:
    def __init__(self,o):self.o=o;self.cursor={};self.raw=None;self.fail=False;self.bindings=[]
    def fstatfs(self,fd,buffer):
        kind=0x9fa0 if self.o.held[fd][0]=='/proc' else 0x58465342
        buffer.raw=kind.to_bytes(8,'little')+b'\0'*504;return 0
    def syscall(self,num,fd,buffer,size):
        assert num==217
        raw=self.raw if self.raw is not None else b''.join(dent(n,i,k) for n,i,k in self.o.names(self.o.held[fd][0]))
        pos=self.cursor.get(fd,0);part=raw[pos:pos+size];self.cursor[fd]=pos+len(part)
        buffer.raw=part+b'\0'*(size-len(part));return len(part)

class Ctypes:
    c_int,c_long,c_void_p,c_uint=object(),object(),object(),object()
    def __init__(self,libc):self.libc=libc;self.widths={self.c_int:4,self.c_long:8,self.c_void_p:8,self.c_uint:4}
    def sizeof(self,kind):return self.widths[kind]
    def CFUNCTYPE(self,*types,**kw):
        def bind(pair):
            name,libc=pair;assert libc is self.libc;self.libc.bindings.append((name,types,kw));return getattr(libc,name)
        return bind
    def create_string_buffer(self,size):return N(raw=b'\0'*size)
    def byref(self,buffer):return buffer
    def set_errno(self,value):pass
    def get_errno(self):return 5

class Poll:
    def __init__(self,o):self.o=o
    def register(self,fd,events):self.o.calls.append(('poll-register',fd,events))
    def poll(self,timeout):return [(1,1)] if self.o.dead else []

class Controls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(A.UNRELEASED_RESOURCES);self.o=OS();self.libc=Libc(self.o);self.c=Ctypes(self.libc)
        self.clock=Clock();self.system=N(platform='linux',byteorder='little');self.platform=N(machine=lambda:'x86_64')
        self.select=N(poll=lambda:Poll(self.o),POLLIN=1,POLLHUP=2,POLLERR=4)
        self.d=BK.LinuxAMD64Getdents64(ctypes_module=self.c,libc=self.libc,sys_module=self.system,machine_module=self.platform)
        self.a=self.adapter()
    def tearDown(self):
        # Synthetic disposal only; no product uncertainty reset API exists.
        A.UNRELEASED_RESOURCES.clear();A._SYSTEM_STATE.clear()
    def adapter(self,**changes):
        args=dict(os_module=self.o,sys_module=self.system,platform_module=self.platform,select_module=self.select,
            ctypes_module=self.c,libc=self.libc,backend_module=BK,getdents64=self.d,clock=self.clock)
        args.update(changes);return A.ParentSystem(P,**args)
    def proc(self):
        root=self.a.open(None,'/',True);self.a.proc_fd=self.a.open(root,'proc',True)
        self.a._arguments,self.a._own_pid=ARGS,73 # Fixed private protocol test fixture only.
        return root,self.a.proc_fd
    def finish(self):
        for fd in reversed(tuple(self.a._owned)):
            if fd not in self.a._attempted:self.a.close(fd)
        self.a.proc_fd=None;self.assertIs(self.a.require_released(),self.a);self.assertFalse(self.o.held)
    def closed(self):return [row[1] for row in self.o.calls if row[0]=='close']
    def test_original_parent_full_hold_checks_and_known_release(self):
        with P.hold_parent(ARGS,system=self.a) as parent:
            report=parent.check();self.assertEqual(report['session'],ARGS.session)
            self.assertIs(report['nativeAuthorized'],False);self.assertEqual(report['qualification'],'INJECTED_PARENT_EVIDENCE_UNQUALIFIED')
        self.assertIs(self.a.require_released(),self.a);self.assertFalse(self.o.held)
        self.assertEqual(len(self.closed()),len(set(self.closed())))
        self.assertFalse(any('/fd/' in row[1] for row in self.o.calls if row[0]=='open'))
        self.assertTrue(any(row[0]=='pidfd' for row in self.o.calls))
    def test_explicit_dependencies_and_architecture_no_default_constructor(self):
        with self.assertRaises(TypeError):A.ParentSystem(P)
        for changes in (dict(sys_module=N(platform='win32',byteorder='little')),
                        dict(platform_module=N(machine=lambda:'aarch64')),dict(getdents64=N(read=lambda *a:b'')),dict(seconds=True),dict(seconds=601)):
            with self.assertRaises((A.ParentSystemUnavailable,AttributeError)):self.adapter(**changes)
        self.assertEqual(self.o.calls,[])
    def test_fstatfs_exact_explicit_binding_and_abi(self):
        self.proc();self.assertEqual(self.a.filesystem(self.a.proc_fd),0x9fa0)
        self.assertEqual(self.libc.bindings[-1],('fstatfs',(self.c.c_int,self.c.c_int,self.c.c_void_p),dict(use_errno=True)))
        self.finish()
        self.c.widths[self.c.c_void_p]=4
        with self.assertRaises(A.ParentSystemUnavailable):self.adapter()
    def test_fixed_paths_and_borrowed_fds_deny_before_open(self):
        root=self.a.open(None,'/',True);before=len(self.o.calls)
        for args in ((None,'/etc',True),(root,'../etc',True),(root,'x/y',False),(root,'tmp',True),(999,'proc',True)):
            with self.assertRaises(A.ParentSystemUnavailable):self.a.open(*args)
        self.assertEqual(len(self.o.calls),before);self.finish()
    def test_open_flags_and_first_cloexec_error_closes_new_fd(self):
        self.o.inherit='error'
        with self.assertRaises(OSError):self.a.open(None,'/',True)
        self.assertEqual(self.closed(),[101]);self.assertFalse(self.o.held)
        self.o.inherit=False;self.assertIs(self.a.require_released(),self.a)
        flags=next(row[2] for row in self.o.calls if row[0]=='open');self.assertEqual(flags,15)
    def test_first_fstat_failure_closes_registered_fd(self):
        self.o.fstat_hook=lambda fd:(_ for _ in ()).throw(OSError('fixture'))
        with self.assertRaises(OSError):self.a.open(None,'/',True)
        self.assertEqual(self.closed(),[101]);self.assertFalse(self.a._owned)
    def test_malformed_open_result_retained_never_blind_closed(self):
        opaque=object();self.o.fd_result=opaque
        with self.assertRaises(A.ParentSystemUnavailable):self.a.open(None,'/',True)
        self.assertIs(A.UNRELEASED_RESOURCES[-1][2][1],opaque);self.assertEqual(self.closed(),[])
        with self.assertRaises(A.ParentSystemUnavailable):self.a.require_released()
    def test_duplicate_open_result_retained_no_second_close(self):
        root=self.a.open(None,'/',True);self.o.fd_result=root
        with self.assertRaises(A.ParentSystemUnavailable):self.a.open(root,'proc',True)
        self.assertEqual(self.closed(),[]);self.a.close(root);self.assertEqual(self.closed(),[root])
        with self.assertRaises(A.ParentSystemUnavailable):self.a.close(root)
    def test_close_error_is_sticky_and_not_retried(self):
        root=self.a.open(None,'/',True);self.o.close_error=root
        with self.assertRaises(A.ParentSystemUnavailable):self.a.close(root)
        self.o.close_error=None
        with self.assertRaises(A.ParentSystemUnavailable):self.a.close(root)
        self.assertEqual(self.closed(),[root]);self.assertIn(root,self.a._owned)
        with self.assertRaises(A.ParentSystemUnavailable):self.a.require_released()
    def test_close_non_none_denies_and_retains_exact_rawclose(self):
        root=self.a.open(None,'/',True);self.o.close_result=False
        with self.assertRaises(A.ParentSystemUnavailable):self.a.close(root)
        self.assertIs(A.UNRELEASED_RESOURCES[-1][3].__self__,self.o)
    def test_dependency_drift_denies_before_callback_and_saved_close_safe(self):
        root=self.a.open(None,'/',True);calls=[];self.o.fstat=lambda fd:calls.append(fd)
        with self.assertRaises(A.ParentSystemUnavailable):self.a.fstat(root)
        self.assertEqual(calls,[]);self.o.close=lambda fd:calls.append(fd)
        self.a.close(root);self.assertEqual(calls,[]);self.assertEqual(self.closed(),[root])
        with self.assertRaises(A.ParentSystemUnavailable):self.a.require_released()
    def test_deadline_and_fd_capacity_are_admitted_before_effect(self):
        self.clock.now=600
        with self.assertRaises(A.ParentSystemUnavailable):self.a.open(None,'/',True)
        self.assertEqual(self.o.calls,[])
    def test_capacity_does_not_call_os_open(self):
        self.a._owned.update(range(A.MAX_OWNED));before=len(self.o.calls)
        with self.assertRaises(A.ParentSystemUnavailable):self.a.open(None,'/',True)
        self.assertEqual(before,len(self.o.calls))
    def test_proc_read_nofollow_chain_and_transient_release(self):
        self.proc();before=set(self.a._owned);raw=self.a._proc_read(('sys','kernel','random','boot_id'),64)
        self.assertTrue(raw.endswith(b'\n'));self.assertEqual(self.a._owned,before)
        self.assertFalse(any('/fd/' in row[1] for row in self.o.calls if row[0]=='open'));self.finish()
    def test_proc_read_error_closes_all_transient_fds(self):
        self.proc();before=set(self.a._owned);self.o.read_hook=lambda *a:(_ for _ in ()).throw(OSError('fixture'))
        with self.assertRaises(OSError):self.a._proc_read(('42','status'),16384)
        self.assertEqual(self.a._owned,before);self.finish()
    def test_proc_close_failure_retains_exact_fd_and_other_closes_continue(self):
        self.proc();self.o.close_error=self.o.next+2
        with self.assertRaises(A.ParentSystemUnavailable):self.a._proc_read(('42','status'),16384)
        bad=self.o.close_error;self.assertIn(bad,self.a._owned);self.assertIn(bad-1,self.closed())
        self.assertIs(A.UNRELEASED_RESOURCES[-1][0],self.a)
    def test_proc_size_and_metadata_drift_deny(self):
        self.proc();self.o.read_hook=lambda fd,count:b'x'*count
        with self.assertRaises(A.ParentSystemUnavailable):self.a._proc_read(('42','status'),8)
        self.o.read_hook=None;self.finish()
    def test_proc_path_limit_rejects_environ_and_fd_before_open(self):
        self.proc();before=len(self.o.calls)
        # Only public fixed protocol entrypoints can choose proc names.
        for pid,fd in ((42,99),(99,11),(True,11)):
            with self.assertRaises(A.ParentSystemUnavailable):self.a.parent_descriptor(pid,fd)
        for parts in (('42','environ'),('42','fd','11'),('42','cmdline'),('1','status')):
            with self.assertRaises(A.ParentSystemUnavailable):self.a._proc_read(parts,64)
        self.assertEqual(before,len(self.o.calls));self.finish()
    def test_enumeration_owns_separate_dot_fd_and_closes(self):
        root=self.a.open(None,'/',True);self.libc.raw=dent('etc',kind=4)+dent('proc',kind=4)
        self.assertEqual(self.a.names(root,2),('etc','proc'));self.assertEqual(self.a._owned,{root})
        self.assertTrue(any(row[0]=='open' and row[1]=='/' and 'dir_fd' in row[3] for row in self.o.calls));self.finish()
    def test_enumeration_duplicates_special_types_and_overflow_deny(self):
        root=self.a.open(None,'/',True)
        for raw in (dent('x')+dent('x'),dent('x',kind=10),dent('a')+dent('b'),b'broken'):
            self.libc.raw=raw
            with self.assertRaises((A.ParentSystemUnavailable,UnicodeError)):self.a.names(root,1)
            self.assertEqual(self.a._owned,{root})
        self.finish()
    def test_original_parent_dead_reparent_and_non_root_refuse(self):
        for name,value in (('dead',True),('parent',99),('uid',(False,0,0))):
            setattr(self.o,name,value)
            with self.assertRaises(P.ParentUnavailable):
                with P.hold_parent(ARGS,system=self.a):self.fail('invalid parent entered')
            self.assertFalse(self.o.held);setattr(self.o,name,False if name=='dead' else 42 if name=='parent' else (0,0,0))
            self.assertIs(self.a.require_released(),self.a)
    def test_original_parent_failed_acquisition_close_unknown_remains_unreleased(self):
        self.o.close_error=101;self.o.parent=99
        with self.assertRaises(P.ParentUnavailable):
            with P.hold_parent(ARGS,system=self.a):self.fail('invalid parent entered')
        self.assertIn(101,self.o.held);self.assertEqual(self.closed().count(101),1)
        with self.assertRaises(A.ParentSystemUnavailable):self.a.require_released()
    def test_proc_metadata_drift_after_read_denies_and_closes_transients(self):
        self.proc();before=set(self.a._owned)
        def changed(fd,count):
            path,meta=self.o.held[fd];raw=self.o.proc_raw(path)
            self.o.held[fd]=(path,P.Metadata(*(getattr(meta,k)+1 if k=='st_mtime_ns' else getattr(meta,k) for k in P.FIELDS)))
            return raw
        self.o.read_hook=changed
        with self.assertRaises(A.ParentSystemUnavailable):self.a._proc_read(('42','status'),16384)
        self.assertEqual(self.a._owned,before);self.o.read_hook=None;self.finish()
    def test_original_parent_inherited_lock_descriptor_is_observed_not_opened_or_closed(self):
        self.o.held[500]=(P.BASE+'/install.lock',self.o.metas[P.BASE+'/install.lock'])
        with self.assertRaises(P.ParentUnavailable):
            with P.hold_parent(ARGS,system=self.a):self.fail('inherited lock entered')
        self.assertEqual(set(self.o.held),{500});self.assertNotIn(500,self.closed())
        self.assertFalse(any('/fd/' in row[1] for row in self.o.calls if row[0]=='open'))
        self.assertIs(self.a.require_released(),self.a)
    def test_pidfd_first_cloexec_failure_is_owned_closed_and_root_anchors_preserved(self):
        self.proc();before=set(self.a._owned);self.o.inherit=True
        with self.assertRaises(A.ParentSystemUnavailable):self.a.pidfd(42)
        self.assertEqual(self.a._owned,before);self.assertIn(self.o.next,self.closed())
        self.o.inherit=False;self.finish()
    def test_original_close_avoids_drifted_adapter_fd_helper(self):
        root=self.a.open(None,'/',True);original=A.ParentSystem._fd;close=A.ParentSystem.close;calls=[]
        A.ParentSystem._fd=lambda *args:calls.append(args)
        try:
            with self.assertRaises(A.ParentSystemUnavailable):self.a.fstat(root)
            close(self.a,root);self.assertEqual(calls,[]);self.assertFalse(self.o.held)
        finally:A.ParentSystem._fd=original
        with self.assertRaises(A.ParentSystemUnavailable):self.a.require_released()

if __name__=='__main__':unittest.main(verbosity=2)
