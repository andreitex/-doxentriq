"""Injected POSIX ownership controls plus local thread serialization; not native qualification."""
import importlib.util
import os
from pathlib import Path
import signal
import sys
import threading
import time
import types
import unittest
from contextlib import contextmanager
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('quota_command_runtime',HERE/'quota_runtime.py')
Q=importlib.util.module_from_spec(spec);spec.loader.exec_module(Q)

class Clock:
    def __init__(self):self.now=0
    def monotonic(self):return self.now
    def sleep(self,seconds):self.now+=seconds

class Pipe:
    def __init__(self,kernel,blocks):self.kernel=kernel;self.blocks=list(blocks);self.closed=False
    def read(self,_):
        self.kernel.events.append('read')
        value=self.blocks.pop(0) if self.blocks else b''
        if isinstance(value,BaseException):raise value
        return value
    def close(self):
        self.kernel.events.append('pipe-close');self.closed=True
        if self.kernel.close_pipe_failure:raise OSError('private pipe failure')

class Process:
    def __init__(self,kernel,blocks):self.kernel=kernel;self.pid=6123;self.returncode=None;self.stdout=Pipe(kernel,blocks)
    def poll(self):raise AssertionError('POSIX numeric poll would reap')
    def wait(self,**_):raise AssertionError('POSIX numeric wait would reap')
    def kill(self):raise AssertionError('POSIX numeric kill forbidden')

class Kernel:
    WEXITED=1;WNOHANG=2;WNOWAIT=4;P_PIDFD=5;P_PID=6;CLD_EXITED=7;CLD_KILLED=8;CLD_DUMPED=9
    def __init__(self,*,state='exit',blocks=(b'ok\n',),hang=False):
        self.state=state;self.status=0;self.code=self.CLD_EXITED;self.events=[];self.process=Process(self,blocks);self.clock=Clock();self.hang=hang
        self.open_failure=False;self.fd_drift=False;self.wrong_pid=False;self.no_child=False;self.bad_status=False;self.bad_group=False
        self.reap_failure=False;self.reap_mismatch=False;self.close_fd_failure=False;self.close_pipe_failure=False;self.stuck_pipe=False;self.signal_failure=False;self.start_failure=False;self.join_failure=False;self.group_present_after_reap=False;self.group_observation_failure=False;self.sigchld=signal.SIG_DFL
        self.fd_open=False;self.fd_closed=False;self.launches=[];self.thread=None;self.reaped=False
    def popen(self,args,**kwargs):self.launches.append((args,kwargs));self.events.append('spawn');return self.process
    def pidfd_open(self,pid,flags):
        self.events.append('pidfd-open');assert(pid,flags)==(6123,0)
        if self.open_failure:raise OSError('private unavailable pidfd')
        self.fd_open=True;return 17
    def fstat(self,fd):
        assert fd==17 and self.fd_open and not self.fd_closed
        return types.SimpleNamespace(st_dev=4,st_ino=10 if self.fd_drift else 9,st_mode=0o600)
    def waitid(self,kind,identifier,flags):
        self.events.append(('waitid',kind,identifier,flags))
        assert (kind,identifier) in ((self.P_PIDFD,17),(self.P_PID,6123))
        if self.no_child:raise ChildProcessError('private already reaped')
        if self.reaped:raise AssertionError('already reaped')
        if not flags&self.WNOWAIT and self.reap_failure:raise OSError('private reap unavailable')
        if self.state=='running':return None
        info=types.SimpleNamespace(si_pid=9 if self.wrong_pid else 6123,si_code=self.code,si_status=True if self.bad_status else self.status)
        if not flags&self.WNOWAIT:
            self.reaped=True;self.events.append('reap')
            if self.reap_mismatch:info.si_status=1
        return info
    def getpgid(self,pid):self.events.append('group-proof');return 1 if self.bad_group else pid
    def killpg(self,pid,sig):
        assert pid==6123
        if sig==0:
            assert self.reaped;self.events.append('group-observe')
            if self.group_observation_failure:raise PermissionError('private observation error')
            if self.group_present_after_reap:return
            raise ProcessLookupError('group absent')
        assert not self.reaped;assert sig==signal.SIGKILL;self.events.append('group-kill')
        if self.signal_failure:raise OSError('private signal failure')
        if self.state=='running':self.state='exit';self.code=self.CLD_KILLED;self.status=int(signal.SIGKILL)
        if self.thread and not self.stuck_pipe:self.thread.alive=False
    def close(self,fd):
        assert fd==17 and not self.fd_closed;self.events.append('pidfd-close');self.fd_closed=True
        if self.close_fd_failure:raise OSError('private close failure')
    def make_thread(self,target,daemon):
        kernel=self
        class Thread:
            def __init__(self):self.alive=False
            def start(self):
                if kernel.start_failure:raise RuntimeError('private thread-start error')
                self.alive=kernel.hang
                if not kernel.hang:target()
            def join(self,seconds):
                kernel.events.append(('join',seconds))
                if kernel.join_failure or kernel.start_failure:raise RuntimeError('private join error')
                if self.alive:kernel.clock.now+=seconds
            def is_alive(self):return self.alive
        self.thread=Thread();return self.thread
    @contextmanager
    def installed(self):
        values={name:getattr(self,name) for name in ('WEXITED','WNOHANG','WNOWAIT','P_PIDFD','P_PID','CLD_EXITED','CLD_KILLED','CLD_DUMPED')}
        values.update(name='posix',pidfd_open=self.pidfd_open,fstat=self.fstat,waitid=self.waitid,getpgid=self.getpgid,killpg=self.killpg,close=self.close,get_inheritable=lambda _:False)
        with patch.multiple(Q.os,create=True,**values),patch.object(Q.signal,'SIGCHLD',17,create=True),patch.object(Q.signal,'SIGKILL',9,create=True),patch.object(Q.signal,'NSIG',65),patch.object(Q.signal,'getsignal',lambda _:self.sigchld),patch.object(Q.subprocess,'Popen',self.popen),patch.object(Q.threading,'Thread',self.make_thread),patch.object(Q.time,'monotonic',self.clock.monotonic),patch.object(Q.time,'sleep',self.clock.sleep):yield self

class Tests(unittest.TestCase):
    def setUp(self):Q._COMMAND_UNCERTAIN=None;Q._COMMAND_LOCK=threading.Lock()
    def tearDown(self):Q._COMMAND_UNCERTAIN=None
    def unavailable(self,kernel,*,uncertain=False,**kwargs):
        with kernel.installed(),self.assertRaisesRegex(Q.QuotaUnavailable,'^Quota command '+('exit is uncertain' if uncertain else 'is unavailable')+'$'):Q.output(['/fixed/tool'],**kwargs)
    def test_success_uses_pidfd_wnowait_then_reaps_and_closes_exact_descriptors(self):
        k=Kernel()
        with k.installed():self.assertEqual(Q.output(['/fixed/tool']),'ok\n')
        self.assertEqual(k.process.returncode,0);self.assertTrue(k.reaped and k.fd_closed and k.process.stdout.closed)
        self.assertLess(k.events.index('group-kill'),k.events.index('reap'));self.assertLess(k.events.index('reap'),k.events.index('group-observe'))
        waits=[e for e in k.events if isinstance(e,tuple) and e[0]=='waitid']
        self.assertTrue(all(e[1:3]==(k.P_PIDFD,17) for e in waits));self.assertTrue(waits[0][3]&k.WNOWAIT);self.assertFalse(waits[-1][3]&k.WNOWAIT)
        self.assertEqual(k.launches[0],(['/fixed/tool'],dict(stdin=Q.subprocess.DEVNULL,stdout=Q.subprocess.PIPE,stderr=Q.subprocess.DEVNULL,env={'PATH':'/usr/bin:/usr/sbin:/bin:/sbin','LANG':'C','LC_ALL':'C'},start_new_session=True,close_fds=True)))
    def test_exited_leader_pipe_failure_kills_group_before_reap(self):
        k=Kernel(blocks=(OSError('private pipe payload'),));self.unavailable(k)
        self.assertLess(k.events.index('group-kill'),k.events.index('reap'));self.assertTrue(k.fd_closed and k.process.stdout.closed)
    def test_timeout_live_leader_is_killed_reaped_and_drained_within_cleanup_budget(self):
        k=Kernel(state='running',hang=True);self.unavailable(k,seconds=0.1)
        self.assertLess(k.events.index('group-kill'),k.events.index('reap'));self.assertLessEqual(k.clock.now,5.2);self.assertFalse(k.thread.alive)
    def test_overflow_never_returns_truncated_output_and_cleans_owned_leader(self):
        k=Kernel(state='running',blocks=(b'x'*101,));self.unavailable(k,maximum=100)
        self.assertIn('group-kill',k.events);self.assertTrue(k.reaped and k.fd_closed)
    def test_ascii_failure_occurs_before_reaping_and_retains_group_cleanup_authority(self):
        k=Kernel(blocks=(b'\xff',));self.unavailable(k)
        self.assertLess(k.events.index('group-kill'),k.events.index('reap'))
    def test_nonzero_and_signaled_statuses_are_not_success(self):
        for code,status in ((Kernel.CLD_EXITED,3),(Kernel.CLD_KILLED,signal.SIGTERM),(Kernel.CLD_DUMPED,signal.SIGABRT)):
            with self.subTest(code=code):
                k=Kernel();k.code=code;k.status=int(status);self.unavailable(k);self.assertTrue(k.reaped)
    def test_missing_pidfd_capability_refuses_before_dispatch(self):
        k=Kernel()
        with k.installed(),patch.object(Q.os,'pidfd_open',None):
            # An unavailable API is represented by a missing attribute, as on old Python.
            del Q.os.pidfd_open
            with self.assertRaisesRegex(Q.QuotaUnavailable,'^Quota command is unavailable$'):Q.output(['/fixed/tool'])
        self.assertEqual(k.launches,[])
    def test_nondefault_sigchld_refuses_before_dispatch(self):
        k=Kernel();k.sigchld=signal.SIG_IGN;self.unavailable(k);self.assertEqual(k.launches,[])
    def test_failed_pidfd_creation_only_cleans_and_never_allows_success(self):
        k=Kernel(state='running');k.open_failure=True;self.unavailable(k)
        self.assertTrue(k.reaped and k.process.stdout.closed);self.assertNotIn('pidfd-close',k.events)
        self.assertTrue(all(e[1:3]==(k.P_PID,6123) for e in k.events if isinstance(e,tuple) and e[0]=='waitid'))
    def test_wrong_child_identity_cannot_signal_or_reap_a_borrowed_process(self):
        k=Kernel();k.wrong_pid=True;self.unavailable(k,uncertain=True)
        self.assertNotIn('group-kill',k.events);self.assertNotIn('reap',k.events);self.assertIsNotNone(Q._COMMAND_UNCERTAIN);self.assertTrue(k.fd_closed)
    def test_external_reap_evidence_refuses_numeric_group_signal_and_latches(self):
        k=Kernel();k.no_child=True;self.unavailable(k,uncertain=True)
        self.assertNotIn('group-kill',k.events);self.assertNotIn('reap',k.events);self.assertIsNotNone(Q._COMMAND_UNCERTAIN)
    def test_pidfd_drift_during_execution_cannot_signal_numeric_group(self):
        k=Kernel();original=k.fstat;reads=0
        def fstat(fd):
            nonlocal reads
            reads+=1
            if reads>2:k.fd_drift=True
            return original(fd)
        k.fstat=fstat;self.unavailable(k,uncertain=True)
        self.assertNotIn('group-kill',k.events);self.assertNotIn('reap',k.events)
    def test_malformed_status_and_wrong_group_fail_closed_without_borrowed_signal(self):
        for field in ('bad_status','bad_group'):
            with self.subTest(field=field):
                k=Kernel(blocks=(OSError('private'),));setattr(k,field,True);self.unavailable(k,uncertain=True);self.assertNotIn('group-kill',k.events)
                Q._COMMAND_UNCERTAIN=None
    def test_reap_failure_closes_numeric_signal_admission_and_latches_unknown(self):
        k=Kernel();k.reap_failure=True;self.unavailable(k,uncertain=True)
        self.assertEqual(k.events.count('group-kill'),1);self.assertTrue(k.fd_closed);self.assertIsNotNone(Q._COMMAND_UNCERTAIN)
    def test_post_reap_status_mismatch_never_signals_group(self):
        k=Kernel();k.reap_mismatch=True;self.unavailable(k,uncertain=True)
        self.assertLess(k.events.index('group-kill'),k.events.index('reap'));self.assertEqual(k.events.count('group-kill'),1);self.assertTrue(k.fd_closed)
    def test_post_reap_descriptor_failure_never_signals_and_blocks_later_launch(self):
        k=Kernel();k.close_fd_failure=True;self.unavailable(k,uncertain=True)
        self.assertTrue(k.reaped and k.process.stdout.closed);self.assertLess(k.events.index('group-kill'),k.events.index('reap'));self.assertEqual(k.events.count('group-kill'),1)
        second=Kernel();self.unavailable(second);self.assertEqual(second.launches,[])
    def test_uncertain_pipe_or_signal_cleanup_retains_owner_and_fails_closed(self):
        for field in ('stuck_pipe','signal_failure','close_pipe_failure'):
            with self.subTest(field=field):
                k=Kernel(state='running',hang=True);setattr(k,field,True);self.unavailable(k,uncertain=True,seconds=0.1)
                self.assertLessEqual(k.clock.now,5.2);self.assertIsNotNone(Q._COMMAND_UNCERTAIN);Q._COMMAND_UNCERTAIN=None
    def test_thread_start_and_join_errors_have_private_uncertain_outcomes(self):
        for field in ('start_failure','join_failure'):
            with self.subTest(field=field):
                k=Kernel();setattr(k,field,True);self.unavailable(k,uncertain=True)
                self.assertTrue(k.reaped and k.fd_closed);self.assertIsNotNone(Q._COMMAND_UNCERTAIN);Q._COMMAND_UNCERTAIN=None
    def test_drifted_pidfd_is_never_closed_as_an_owned_descriptor(self):
        k=Kernel();original=k.fstat;reads=0
        def fstat(fd):
            nonlocal reads
            reads+=1
            if reads>2:k.fd_drift=True
            return original(fd)
        k.fstat=fstat;self.unavailable(k,uncertain=True)
        self.assertNotIn('pidfd-close',k.events);self.assertNotIn('group-kill',k.events)
    def test_lock_release_failure_cannot_return_success_or_expose_private_error(self):
        class BrokenLock:
            def acquire(self,timeout):return True
            def release(self):raise RuntimeError('private release error')
        Q._COMMAND_LOCK=BrokenLock();k=Kernel();self.unavailable(k,uncertain=True)
        self.assertTrue(k.reaped and k.fd_closed);self.assertLess(k.events.index('group-kill'),k.events.index('reap'))
    def test_remaining_or_unobservable_group_prevents_success_without_post_reap_signal(self):
        for field in ('group_present_after_reap','group_observation_failure'):
            with self.subTest(field=field):
                k=Kernel();setattr(k,field,True);self.unavailable(k,uncertain=True,seconds=0.1)
                self.assertTrue(k.reaped);self.assertEqual(k.events.count('group-kill'),1)
                self.assertLess(k.events.index('group-kill'),k.events.index('reap'));self.assertGreater(k.events.count('group-observe'),0)
                self.assertLessEqual(k.clock.now,5.2);self.assertIsNotNone(Q._COMMAND_UNCERTAIN);Q._COMMAND_UNCERTAIN=None
    def test_invalid_command_limits_do_not_dispatch(self):
        k=Kernel()
        with k.installed():
            for args,kwargs in (([],{}),(['/tool'],{'seconds':True}),(['/tool'],{'seconds':11}),(['/tool'],{'maximum':True}),(['/tool'],{'maximum':32769}),([1],{})):
                with self.assertRaises(ValueError):Q.output(args,**kwargs)
        self.assertEqual(k.launches,[])
    def test_lock_wait_is_bounded_and_does_not_dispatch(self):
        Q._COMMAND_LOCK.acquire();k=Kernel()
        try:
            start=time.monotonic();self.unavailable(k,seconds=0.05);self.assertLess(time.monotonic()-start,0.5)
        finally:Q._COMMAND_LOCK.release()
        self.assertEqual(k.launches,[])
    def test_parallel_trusted_callers_serialize_launches_and_both_finish(self):
        entered=threading.Event();release=threading.Event();launches=[];results=[];errors=[]
        class LocalProcess:
            def __init__(self):self.pid=1;self.returncode=None;self.stdout=types.SimpleNamespace(read=lambda _:b'',close=lambda:None)
            def poll(self):self.returncode=0;return 0
            def wait(self,timeout):return 0
        def spawn(args,**kwargs):
            launches.append(args);entered.set()
            if len(launches)==1:self.assertTrue(release.wait(2))
            return LocalProcess()
        def call(name):
            try:results.append(Q.output([name],seconds=2))
            except BaseException as error:errors.append(error)
        with patch.object(Q.os,'name','nt'),patch.object(Q.subprocess,'Popen',spawn):
            first=threading.Thread(target=call,args=('/first',));second=threading.Thread(target=call,args=('/second',))
            first.start();self.assertTrue(entered.wait(1));second.start();time.sleep(0.05)
            self.assertEqual(launches,[['/first']]);release.set();first.join(2);second.join(2)
        self.assertFalse(first.is_alive() or second.is_alive());self.assertEqual(errors,[]);self.assertEqual(results,['','']);self.assertEqual(launches,[['/first'],['/second']])

if __name__=='__main__':unittest.main(verbosity=2)
