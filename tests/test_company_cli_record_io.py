"""Explicit RAM syscall/ownership controls, never native IO or processes."""
import importlib.util
from pathlib import Path, PurePosixPath
import stat
import sys
from types import ModuleType, SimpleNamespace
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
PATH = '/opt/autosoft-company/evidence/'+'a'*32+'/company-platform-store'
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def load():
    name='record_io_'+uuid.uuid4().hex
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy/installer/company_cli_record_io.py')
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


class RAM:
    def __init__(self, product):
        self.P=product;self.handles={};self.close_calls=[];self.opens=[];self.reads=[];self.writes=[]
        self.offset=3;self.now=0.0;self.hooks={};self.fail_close=set();self.poll_events=[];self.write_results=[]
        self.bodies={'request.json':b'{"request":1}\n','invocation.json':b'{"invocation":1}\n','plan.json':b'{"plan":1}\n'}
        self.metas={};inode=1
        for path in ['/', '/opt','/opt/autosoft-company','/opt/autosoft-company/evidence',PATH.rsplit('/',1)[0],PATH]:
            self.metas[path]=self.meta(inode,stat.S_IFDIR|0o700,nlink=2);inode+=1
        for name,body in self.bodies.items():
            self.metas[PATH+'/'+name]=self.meta(inode,stat.S_IFREG|0o400,size=len(body));inode+=1
        for fd,inode in ((40,100),(41,101)):
            self.handles[fd]=dict(path=None,identity=self.meta(inode,stat.S_IFIFO|0o600),flags=2049,fdflags=1)
        self.o=ModuleType('ram_os');self.s=ModuleType('ram_sys');self.f=ModuleType('ram_fcntl');self.select=ModuleType('ram_select')
        self.s.platform='linux';self.o.stat_result=self.o.uname_result=SimpleNamespace
        for key,value in dict(O_RDONLY=0,O_NOFOLLOW=131072,O_CLOEXEC=524288,O_NONBLOCK=2048,O_DIRECTORY=65536,O_LARGEFILE=0).items():setattr(self.o,key,value)
        for key in ('open','stat','fstat','pread','close','write','uname'):setattr(self.o,key,getattr(self,key))
        self.o.supports_dir_fd={self.o.open,self.o.stat};self.o.supports_follow_symlinks={self.o.stat}
        self.f.F_GETFL=3;self.f.F_GETFD=1;self.f.fcntl=self.fcntl
        self.select.poll=self.poll_factory

    @staticmethod
    def meta(inode,mode,nlink=1,size=0):
        return dict(zip(FIELDS,(7,inode,mode,0,0,nlink,size,101,202)))

    def hook(self,key,*args):
        if key in self.hooks:return self.hooks[key](*args)

    def uname(self):
        self.hook('uname');return SimpleNamespace(machine='x86_64')

    def clock(self):
        self.now+=0.001;self.hook('clock');return self.now

    def path(self,name,parent):
        if name=='/':return '/'
        return str(PurePosixPath(self.handles[parent]['path'])/name)

    def open(self,name,flags,*,dir_fd=None):
        path=self.path(name,dir_fd);self.opens.append((name,flags,dir_fd))
        self.hook('open',path)
        fd=self.offset;self.offset+=1
        self.handles[fd]=dict(path=path,identity=self.metas[path],flags=(flags & ~524288)|32768,fdflags=1)
        return fd

    def stat(self,name,*,dir_fd=None,follow_symlinks=True):
        assert follow_symlinks is False
        return SimpleNamespace(**dict(self.metas[self.path(name,dir_fd)]))

    def fstat(self,fd):
        self.hook('fstat',fd)
        return SimpleNamespace(**dict(self.handles[fd]['identity']))

    def pread(self,fd,count,offset):
        name=PurePosixPath(self.handles[fd]['path']).name;self.reads.append((fd,count,offset))
        value=self.hook('pread',fd,count,offset)
        if value is not None:return value
        return self.bodies[name][offset:offset+count]

    def close(self,fd):
        self.close_calls.append(fd)
        if fd in self.fail_close:raise OSError(5,'synthetic close')
        del self.handles[fd];self.hook('close',fd)

    def fcntl(self,fd,command):
        return self.handles[fd]['flags' if command==3 else 'fdflags']

    def write(self,fd,raw):
        self.writes.append((fd,raw));self.hook('write',fd,raw)
        value=self.write_results.pop(0) if self.write_results else len(raw)
        if isinstance(value,BaseException):raise value
        return value

    def poll_factory(self):
        fixture=self
        class Poll:
            def register(self,fd,mask):
                self.fd=fd;fixture.hook('register',fd,mask)
            def poll(self,millis):
                value=fixture.poll_events.pop(0) if fixture.poll_events else [(self.fd,4)]
                if isinstance(value,BaseException):raise value
                return value
        result=Poll();self.last_poll=result;return result

    def outputs(self):
        return {role:dict(fd=fd,identity=dict(self.handles[fd]['identity']),flags=2049,fdFlags=1)
                for role,fd in (('stdout',40),('stderr',41))}

    def arguments(self):
        return dict(directory_identity=dict(self.metas[PATH]),
            input_pins={name:dict(bytes=len(raw),sha256=self.P.hashlib.sha256(raw).hexdigest()) for name,raw in self.bodies.items()},
            outputs=self.outputs(),os_module=self.o,sys_module=self.s,fcntl_module=self.f,
            select_module=self.select,clock=self.clock,seconds=30,protected_fds=(90,91))


class RecordIOControls(unittest.TestCase):
    def setUp(self):self.P=load();self.r=RAM(self.P)
    def context(self,**changes):return self.P.hold_publisher_io(PATH,**dict(self.r.arguments(),**changes))
    def reject(self,action,*args,**kwargs):
        with self.assertRaises(self.P.RecordIOUnavailable):action(*args,**kwargs)
    def finish(self,io):
        self.assertIs(io.release_inputs(),io);self.assertIs(self.P.require_inputs_released(io),io)
        self.assertEqual(io.write_stdout(b'A\0B\n'),4)
        self.assertIs(io.close_outputs(),io);self.assertIs(self.P.require_released(io),io)

    def test_actual_captured_bytes_nonblocking_exact_output_and_known_scope_release(self):
        with self.context() as io:
            captured=io.captured_inputs
            self.assertEqual(dict(captured),dict(request_raw=self.r.bodies['request.json'],invocation_raw=self.r.bodies['invocation.json'],plan_raw=self.r.bodies['plan.json']))
            with self.assertRaises(TypeError):captured['request_raw']=b'caller'
            self.assertEqual(len(self.r.handles),11)
            self.finish(io)
            self.assertFalse(self.r.handles)
        self.assertEqual(self.r.writes,[(40,b'A\0B\n')]);self.assertEqual(len(self.r.close_calls),11)
        self.assertEqual(len(set(self.r.close_calls)),11)
        self.assertIs(self.P.require_released(io),io)

    def test_traversal_wrong_mode_or_foreign_keys_refuse_before_transfer(self):
        for path in (PATH+'/../other',PATH.replace('/evidence/','/incoming/'),PATH.replace('a'*32,'0'*32)):
            self.reject(self.P.hold_publisher_io(path,**self.r.arguments()).__enter__)
        self.assertEqual(self.r.opens,[]);self.assertEqual(self.r.close_calls,[])

    def test_wrong_input_hash_or_writable_hardlinked_leaf_refuses_and_closes_knowns(self):
        self.r.metas[PATH+'/request.json']['st_nlink']=2
        self.reject(self.context().__enter__)
        self.assertFalse(self.r.handles);self.assertEqual(len(self.r.close_calls),len(set(self.r.close_calls)))

    def test_same_pipe_distinct_numeric_outputs_denied_without_adoption(self):
        outputs=self.r.outputs();outputs['stderr']['identity']=dict(outputs['stdout']['identity'])
        self.reject(self.context(outputs=outputs).__enter__)
        self.assertEqual(self.r.opens,[]);self.assertEqual(self.r.close_calls,[])

    def test_stat_supported_in_both_sets_no_lstat_membership_or_libc_largefile_required(self):
        self.assertFalse(hasattr(self.r.o,'lstat'));self.assertEqual(self.r.o.O_LARGEFILE,0)
        with self.context() as io:self.finish(io)
        self.assertFalse(self.r.handles)

    def test_uname_callback_drift_denied_before_transferred_endpoint_io(self):
        calls=[]
        self.r.hooks['uname']=lambda:setattr(self.r.o,'close',lambda fd:calls.append(fd))
        self.reject(self.context().__enter__)
        self.assertEqual(self.r.opens,[]);self.assertEqual(self.r.close_calls,[]);self.assertEqual(calls,[])

    def test_clock_callback_drift_denied_before_transfer_and_original_open_not_selected_late(self):
        calls=[]
        self.r.hooks['clock']=lambda:setattr(self.r.o,'open',lambda *args,**kwargs:calls.append(args))
        self.reject(self.context().__enter__)
        self.assertEqual(calls,[]);self.assertEqual(self.r.opens,[]);self.assertEqual(self.r.close_calls,[])

    def test_read_eof_drift_uses_saved_raw_closes_no_changed_callback(self):
        calls=[]
        def change(fd,count,offset):
            if offset==len(self.r.bodies['request.json']):self.r.o.close=lambda value:calls.append(value)
        self.r.hooks['pread']=change
        self.reject(self.context().__enter__)
        self.assertFalse(self.r.handles);self.assertEqual(calls,[])

    def test_source_metadata_drift_after_capture_refuses_and_retains_originals(self):
        with self.assertRaises(self.P.RecordIOUnavailable):
            with self.context() as io:
                self.r.metas[PATH+'/plan.json']['st_ctime_ns']+=1
                self.reject(lambda:io.captured_inputs)
        self.assertFalse(self.r.handles);self.assertTrue(self.P.UNRELEASED)

    def test_eagain_and_eintr_are_bounded_zero_byte_transients_not_eof(self):
        self.r.poll_events=[InterruptedError(4,'synthetic'),[(40,4)],[(40,4)]]
        self.r.write_results=[BlockingIOError(11,'synthetic'),4]
        with self.context() as io:self.finish(io)
        self.assertEqual(len(self.r.writes),2);self.assertFalse(self.r.handles)

    def test_partial_write_records_actual_count_no_retry_and_known_close_observable(self):
        original_arguments=self.r.arguments()
        self.r.write_results=[2]
        with self.context() as io:
            io.release_inputs();self.reject(io.write_stdout,b'A\0B\n')
            record=self.P.UNRELEASED[-1][0]
            self.assertEqual(record['accepted'],2);self.assertEqual(record['output_raw'],b'A\0B\n')
            self.reject(io.write_stdout,b'again')
            io.close_outputs();self.assertIs(self.P.require_released(io),io)
        self.assertEqual(len(self.r.writes),1)
        self.reject(self.P.hold_publisher_io(PATH,**original_arguments).__enter__)

    def test_zero_write_or_broken_pipe_is_denial_never_eof(self):
        self.r.write_results=[0]
        with self.context() as io:
            io.release_inputs();self.reject(io.write_stdout,b'zero')
            self.assertEqual(self.P.UNRELEASED[-1][0]['accepted'],0)
            io.close_outputs();self.assertIs(self.P.require_released(io),io)
        self.assertEqual(len(self.r.writes),1)

    def test_unexpected_transient_errno_refuses_without_extra_write(self):
        self.r.write_results=[BlockingIOError(5,'wrong transient')]
        with self.context() as io:
            io.release_inputs();self.reject(io.write_stdout,b'fixed')
            io.close_outputs();self.assertIs(self.P.require_released(io),io)
        self.assertEqual(len(self.r.writes),1)

    def test_write_drift_retains_successful_return_before_guard_and_knownclose(self):
        foreign=[];self.r.hooks['write']=lambda fd,raw:setattr(self.r.o,'close',lambda value:foreign.append(value))
        with self.assertRaises(self.P.RecordIOUnavailable):
            with self.context() as io:
                io.release_inputs();self.reject(io.write_stdout,b'actual')
                self.assertEqual(self.P.UNRELEASED[-1][0]['accepted'],6)
                self.reject(io.close_outputs)
                self.assertIs(self.P.require_released(io),io)
        self.assertEqual(foreign,[]);self.assertFalse(self.r.handles)

    def test_close_drift_keeps_known_closed_rows_and_no_replacement_calls(self):
        foreign=[];self.r.hooks['close']=lambda fd:setattr(self.r.o,'close',lambda value:foreign.append(value))
        with self.assertRaises(self.P.RecordIOUnavailable):
            with self.context() as io:self.reject(io.release_inputs)
        record=self.P.UNRELEASED[-1][0]
        self.assertTrue(all(row['closed'] for row in record['rows']))
        self.assertIs(self.P.require_released(io),io)
        self.assertFalse(self.r.handles);self.assertEqual(foreign,[])
        self.assertEqual(len(self.r.close_calls),len(set(self.r.close_calls)))

    def test_unknown_output_close_once_private_failure_survives_public_clear(self):
        original_arguments=self.r.arguments()
        self.r.fail_close.add(40)
        with self.assertRaises(self.P.RecordIOUnavailable):
            with self.context() as io:
                io.release_inputs();io.write_stdout(b'public');self.reject(io.close_outputs)
                self.P.UNRELEASED.clear();self.reject(io.close_outputs);self.reject(self.P.require_released,io)
        self.assertEqual(self.r.close_calls.count(40),1);self.assertIn(40,self.r.handles)
        self.reject(self.P.hold_publisher_io(PATH,**original_arguments).__enter__)

    def test_acquisition_error_retains_actual_attempt_no_guessed_close(self):
        def problem(path):raise OSError(5,'unreturned acquisition')
        self.r.hooks['open']=problem
        self.reject(self.context().__enter__)
        record=self.P.UNRELEASED[-1][0]
        self.assertTrue(record['acquisition_unknown']);self.assertTrue(record['attempts'])
        self.assertFalse(self.r.handles);self.assertEqual(sorted(self.r.close_calls),[40,41])

    def test_unissued_clone_public_flags_and_parent_protected_fd_alias_denied(self):
        clone=self.P.PublisherIO();clone.inputs_released=clone.outputs_released=True
        self.reject(self.P.require_released,clone);self.reject(self.P.require_publisher_io,clone)
        self.reject(self.context(protected_fds=(40,90)).__enter__)
        self.assertEqual(self.r.close_calls,[])

    def test_poll_count_and_deadline_are_admissions_no_unbounded_retry(self):
        self.r.poll_events=[[]]*1025
        with self.context() as io:
            io.release_inputs();self.reject(io.write_stdout,b'fixed')
            self.assertEqual(self.P.UNRELEASED[-1][0]['polls'],1025)
            io.close_outputs();self.assertIs(self.P.require_released(io),io)
        self.assertEqual(self.r.writes,[])

    def test_main_unconfigured_and_no_effects(self):
        self.reject(self.P.main,[]);self.assertEqual(self.r.opens,[]);self.assertEqual(self.r.close_calls,[])

    def test_successful_close_then_second_valid_acquisition_denied_before_callbacks(self):
        original_arguments=self.r.arguments()
        with self.context() as io:self.finish(io)
        callbacks=[]
        self.r.hooks['uname']=lambda:callbacks.append('uname')
        self.r.hooks['clock']=lambda:callbacks.append('clock')
        self.reject(self.P.hold_publisher_io(PATH,**original_arguments).__enter__)
        self.assertEqual(callbacks,[]);self.assertEqual(len(self.r.opens),9)
        self.assertIs(self.P.require_released(io),io)

    def test_owned_drift_caught_restored_never_revives_capture_or_write(self):
        original_close=self.r.o.close
        with self.assertRaises(self.P.RecordIOUnavailable):
            with self.context() as io:
                reads=len(self.r.reads);foreign=[]
                self.r.o.close=lambda fd:foreign.append(fd)
                self.reject(lambda:io.captured_inputs)
                self.r.o.close=original_close
                self.P.UNRELEASED.clear()
                self.reject(lambda:io.captured_inputs)
                self.reject(io.write_stdout,b'forbidden')
                self.assertEqual(len(self.r.reads),reads);self.assertEqual(self.r.writes,[])
                self.assertEqual(foreign,[])
        self.assertFalse(self.r.handles)
        self.assertIs(self.P.require_released(io),io)

    def test_register_replaces_poll_never_invokes_shadow_and_failure_sticks(self):
        called=[];original_arguments=self.r.arguments()
        self.r.hooks['register']=lambda fd,mask:setattr(self.r.last_poll,'poll',lambda millis:called.append(millis))
        self.reject(self.context().__enter__)
        self.assertEqual(called,[]);self.assertEqual(self.r.writes,[]);self.assertFalse(self.r.handles)
        record=self.P.UNRELEASED[-1][0]
        self.assertIs(record['poll'],self.r.last_poll)
        self.P.UNRELEASED.clear()
        self.reject(self.P.hold_publisher_io(PATH,**original_arguments).__enter__)


if __name__=='__main__':unittest.main(verbosity=2)
