"""Injected fixed-command/process controls; no native Git or Linux execution."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('company_git_runner_controls', ROOT / 'scripts/platform_git_runner.py')
G = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(G)
ARTIFACT_ROOT = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', ROOT / '.local'))
ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
FIXTURE = ARTIFACT_ROOT / ('platform-git-runner-' + uuid.uuid4().hex)
FIXTURE.mkdir()
REVISION = '1' * 40
ELF = b'\x7fELF\x02\x01\x01' + b'\0' * 11 + b'\x3e\x00' + b'\0' * 44 + b'fixture-git-bytes'
SHA = hashlib.sha256(ELF).hexdigest()


class Clock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def tick(self, amount): self.now += amount


class Files:
    def __init__(self, root):
        self.root, self.rows, self.data, self.fds = root, {}, {}, {}
        self.next_inode, self.next_fd = 10, 100
        self.opened, self.closed, self.fail_close, self.inheritable = [], [], set(), set()
        self.on_read = None
        for target in (root, Path(G.BINARY).parent):
            for p in reversed([target, *target.parents]):
                if p not in self.rows: self.add(p, stat.S_IFDIR | 0o755, 0)
        self.add(Path(G.BINARY), stat.S_IFREG | 0o755, len(ELF)); self.data[Path(G.BINARY)] = ELF
    def add(self, path, mode, size):
        self.next_inode += 1
        self.rows[path] = SimpleNamespace(st_dev=1, st_ino=self.next_inode, st_mode=mode,
            st_uid=0, st_gid=0, st_nlink=2 if stat.S_ISDIR(mode) else 1,
            st_size=size, st_mtime_ns=1, st_ctime_ns=1)
    def lstat(self, path): return SimpleNamespace(**vars(self.rows[Path(path)]))
    def fstat(self, fd): return SimpleNamespace(**vars(self.fds[fd][1]))
    def cloexec(self, fd): return fd not in self.inheritable
    def open(self, parent, name, directory):
        path = Path(name) if parent is None else self.fds[parent][0] / name
        self.next_fd += 1; fd = self.next_fd
        self.fds[fd] = path, self.lstat(path); self.opened.append((fd, path, directory))
        return fd
    def read(self, fd, size, offset):
        if self.on_read is not None:
            callback, self.on_read = self.on_read, None; callback()
        return self.data[self.fds[fd][0]][offset:offset + size]
    def close(self, fd):
        self.closed.append(fd)
        if fd in self.fail_close: raise OSError('injected close failure')
        self.fds.pop(fd)


class Job:
    def __init__(self, system):
        self.system, self.started, self.disposed = system, False, False
    def start(self, argv, env, executable, end):
        self.system.events.append(('start', argv, env, executable, end)); self.started = True
        if self.system.on_start: self.system.on_start()
        if self.system.start_error: raise OSError('injected start failure')
    def capture(self, end):
        self.system.events.append(('capture', end))
        if self.system.on_capture: self.system.on_capture()
        if self.system.capture_error: raise OSError('injected capture failure')
        G.require(self.system.clock() < end)
        return self.system.output
    def dispose(self, end):
        self.system.events.append(('dispose', end)); self.disposed = True
        if self.system.dispose_error: raise OSError('injected unknown disposal')
        G.require(self.system.clock() < end)


class System:
    def __init__(self, clock):
        self.clock, self.events, self.memory, self.jobs = clock, [], {}, []
        self.next_fd = 9000; self.output = b'exact\x00binary\xff'
        self.start_error = self.capture_error = self.dispose_error = self.close_error = False
        self.on_start = self.on_capture = None
    def executable(self):
        self.next_fd += 1; self.memory[self.next_fd] = None
        self.events.append(('executable', self.next_fd)); return self.next_fd
    def populate(self, fd, raw): self.memory[fd] = raw; self.events.append(('populate', fd))
    def check(self, fd, expected, size):
        self.events.append(('check', fd)); raw = self.memory[fd]
        G.require(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == expected)
    def close(self, fd):
        self.events.append(('close', fd))
        if self.close_error: raise OSError('injected executable close failure')
        self.memory.pop(fd)
    def job(self, clock):
        assert clock is self.clock
        job = Job(self); self.jobs.append(job); self.events.append(('job', job)); return job


def prefix(root):
    return (G.BINARY, '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch',
        '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c',
        'core.untrackedCache=false', '-c', 'core.attributesFile=/dev/null', '-C', str(root))


class RunnerControls(unittest.TestCase):
    def setUp(self):
        self.assertEqual(G.UNRELEASED_RESOURCES, [])
        self.clock = Clock(); self.root = FIXTURE / 'source'
        self.files = Files(self.root); self.system = System(self.clock)
    def tearDown(self):
        # All resources in this suite are explicitly injected tokens, never OS FDs.
        G.UNRELEASED_RESOURCES.clear()
    def runner(self, **kwargs):
        return G.NativeGitRunner(SHA, self.root, REVISION, files=self.files, system=self.system,
                                 clock=self.clock, **kwargs)
    def call(self, runner, tail=('rev-parse', '--show-toplevel'), **kwargs):
        return runner(prefix(self.root) + tail, env=dict(G.ENV), limit=G.STDOUT_LIMIT,
                      timeout=G.CALL_SECONDS, **kwargs)
    def test_exact_seven_tails_use_original_callable_protocol_and_binary_output(self):
        tails = (('rev-parse', '--show-toplevel'), ('rev-parse', '--verify', 'HEAD^{commit}'),
            ('rev-parse', '--verify', REVISION + '^{tree}'), ('ls-files', '--others', '--exclude-standard', '-z'),
            ('ls-files', '--others', '--ignored', '--exclude-standard', '-z'),
            ('ls-tree', '-rz', '--full-tree', REVISION), ('ls-files', '--stage', '--full-name', '-z'))
        with self.runner() as r:
            for tail in tails: self.assertEqual(self.call(r, tail), self.system.output)
            self.assertEqual(r.calls, 7); self.assertEqual(r.jobs, [])
            self.assertTrue(all(j.disposed for j in self.system.jobs))
        self.assertEqual(self.files.fds, {}); self.assertEqual(self.system.memory, {})
    def test_constructor_has_no_filesystem_or_process_effect_and_lifetime_is_explicit(self):
        r = self.runner(); self.assertEqual(self.files.opened, []); self.assertEqual(self.system.events, [])
        with self.assertRaises(G.GitUnavailable): self.call(r)
        self.assertEqual(self.system.jobs, [])
        with self.assertRaises(G.GitUnavailable): r.__enter__()
        self.assertEqual(self.files.opened, [])
        r = self.runner()
        with r: self.assertTrue(r.active)
        with self.assertRaises(G.GitUnavailable): r.__enter__()
    def test_bad_tails_and_binary_flags_root_revision_are_denied_before_job(self):
        for tail in (('fetch',), ('status',), ('diff',), ('checkout', REVISION), ('update-index',),
                     ('ls-tree', '-rz', '--full-tree', '2' * 40), ('ls-files', '--stage', '-z')):
            with self.subTest(tail=tail):
                with self.runner() as r:
                    with self.assertRaises(G.GitUnavailable): self.call(r, tail)
                self.assertEqual(self.system.jobs, [])
        for index, text in ((0, '/usr/bin/other'), (1, '--optional-locks'), (3, '--lazy-fetch'), (13, str(self.root.parent))):
            with self.subTest(index=index):
                with self.runner() as r:
                    argv = list(prefix(self.root) + ('rev-parse', '--show-toplevel')); argv[index] = text
                    with self.assertRaises(G.GitUnavailable): r(tuple(argv), env=dict(G.ENV), limit=G.STDOUT_LIMIT, timeout=30)
                self.assertEqual(self.system.jobs, [])
    def test_environment_injection_and_noncanonical_parameter_types_refused(self):
        cases = [(dict(G.ENV, GIT_SSH_COMMAND='secret'), G.STDOUT_LIMIT, 30),
                 (dict(G.ENV, GIT_CONFIG_COUNT='1'), G.STDOUT_LIMIT, 30),
                 (dict(G.ENV, HOME='/caller'), G.STDOUT_LIMIT, 30),
                 (dict(G.ENV, TZ=True), G.STDOUT_LIMIT, 30), (dict(G.ENV), True, 30),
                 (dict(G.ENV), G.STDOUT_LIMIT, 30.0), (dict(G.ENV), G.STDOUT_LIMIT + 1, 30)]
        for env, limit, timeout in cases:
            with self.subTest(env=env, limit=limit, timeout=timeout):
                with self.runner() as r:
                    with self.assertRaises(G.GitUnavailable): r(prefix(self.root) + ('rev-parse','--show-toplevel'), env=env, limit=limit, timeout=timeout)
                self.assertEqual(self.system.jobs, [])
    def test_argv_shape_nul_and_oversized_values_never_dispatch(self):
        for argv in (list(prefix(self.root)), prefix(self.root) + ('\0',),
                     prefix(self.root) + ('x' * 513,), prefix(self.root) + (None,)):
            with self.runner() as r:
                with self.assertRaises(G.GitUnavailable): r(argv, env=dict(G.ENV), limit=G.STDOUT_LIMIT, timeout=30)
            self.assertEqual(self.system.jobs, [])
    def test_hash_and_elf_architecture_checked_before_executable_or_job(self):
        for raw in (ELF + b'tamper', b'#!/bin/sh\n' + b'\0' * 80, ELF[:18] + b'\x28\x00' + ELF[20:]):
            with self.subTest(raw=raw[:20]):
                self.files = Files(self.root); self.system = System(self.clock)
                self.files.data[Path(G.BINARY)] = raw; self.files.rows[Path(G.BINARY)].st_size = len(raw)
                sha = hashlib.sha256(raw).hexdigest() if raw != ELF + b'tamper' else SHA
                r = G.NativeGitRunner(sha,self.root,REVISION,files=self.files,system=self.system,clock=self.clock)
                with self.assertRaises(G.GitUnavailable): r.__enter__()
                self.assertEqual(self.system.events, []); self.assertEqual(self.files.fds, {})
    def test_bad_tool_or_root_protection_and_all_nine_identity_changes_refused(self):
        for field, value in (('st_uid',1),('st_gid',1),('st_mode',stat.S_IFLNK|0o755),('st_nlink',2),('st_mode',stat.S_IFREG|0o777)):
            self.files = Files(self.root); self.system = System(self.clock)
            setattr(self.files.rows[Path(G.BINARY)],field,value)
            with self.assertRaises(G.GitUnavailable): self.runner().__enter__()
            self.assertEqual(self.system.jobs,[]); self.assertEqual(self.files.fds,{})
        for field in G.FIELDS:
            self.files = Files(self.root); self.system = System(self.clock)
            with self.runner() as r:
                row = self.files.rows[self.root]; setattr(row,field,getattr(row,field)+1)
                with self.assertRaises(G.GitUnavailable): self.call(r)
            self.assertEqual(self.system.jobs,[])
    def test_inheritable_input_handle_fails_and_close_is_attempted(self):
        original = self.files.open
        def inherit(*args):
            fd=original(*args);self.files.inheritable.add(fd);return fd
        self.files.open=inherit
        with self.assertRaises(G.GitUnavailable): self.runner().__enter__()
        self.assertEqual(self.files.fds,{});self.assertTrue(self.files.closed);self.assertEqual(self.system.jobs,[])
    def test_tool_content_drift_with_unchanged_metadata_denied_before_launch(self):
        with self.runner() as r:
            self.files.data[Path(G.BINARY)]=ELF[:-1]+b'X'
            with self.assertRaises(G.GitUnavailable):self.call(r)
            self.assertEqual(self.system.jobs,[])
    def test_post_capture_tool_and_root_drift_never_returns_success(self):
        for target in ('tool','root','sealed'):
            self.files=Files(self.root);self.system=System(self.clock)
            with self.runner() as r:
                def change():
                    if target=='tool':self.files.data[Path(G.BINARY)]=ELF[:-1]+b'X'
                    elif target=='root':self.files.rows[self.root].st_ino+=1
                    else:self.system.memory[r.fd]=b'changed sealed bytes'
                self.system.on_capture=change
                with self.assertRaises(G.GitUnavailable):self.call(r)
                self.assertTrue(self.system.jobs[-1].disposed)
    def test_context_exit_rechecks_before_closing_and_detects_late_change(self):
        with self.assertRaises(G.GitUnavailable):
            with self.runner():self.files.rows[self.root].st_ctime_ns+=1
        self.assertEqual(self.files.fds,{});self.assertEqual(self.system.memory,{})
    def test_global_budget_covers_105_calls_and_refuses_call_129(self):
        with self.runner() as r:
            for _ in range(128):self.call(r)
            self.assertEqual(r.calls,128);self.assertEqual(len(self.system.jobs),128)
            with self.assertRaises(G.GitUnavailable):self.call(r)
            self.assertEqual(len(self.system.jobs),128)
    def test_call_and_context_disposal_reserves_share_original_deadline(self):
        with self.runner(seconds=60) as r:
            self.clock.tick(40)
            self.call(r)
            start=next(e for e in self.system.events if e[0]=='start')
            dispose=next(e for e in self.system.events if e[0]=='dispose')
            self.assertEqual(start[-1],50);self.assertEqual(dispose[-1],55)
            self.clock.tick(10)
            with self.assertRaises(G.GitUnavailable):self.call(r)
            self.assertEqual(len(self.system.jobs),1)
    def test_deadline_expiry_before_launch_or_after_capture_cannot_pass(self):
        with self.runner(seconds=20) as r:
            self.clock.tick(10)
            with self.assertRaises(G.GitUnavailable):self.call(r)
            self.assertEqual(self.system.jobs,[])
        self.clock=Clock();self.files=Files(self.root);self.system=System(self.clock)
        with self.assertRaises(G.GitUnavailable):
            with self.runner() as r:
                self.system.on_capture=lambda:self.clock.tick(31)
                with self.assertRaises(G.GitUnavailable):self.call(r)
                self.assertIn(self.system.jobs[-1],G.UNRELEASED_RESOURCES)
    def test_known_capture_failure_releases_job_but_expires_producer(self):
        with self.runner() as r:
            self.system.capture_error=True
            with self.assertRaises(G.GitUnavailable):self.call(r)
            self.assertEqual(r.jobs,[]);self.assertTrue(self.system.jobs[-1].disposed)
            self.assertEqual(G.UNRELEASED_RESOURCES,[])
            self.system.capture_error=False
            with self.assertRaises(G.GitUnavailable):self.call(r)
            self.assertEqual(len(self.system.jobs),1)
    def test_disposal_uncertainty_keeps_exact_job_and_blocks_next_producer(self):
        with self.assertRaises(G.GitUnavailable):
            with self.runner() as r:
                self.system.dispose_error=True
                with self.assertRaises(G.GitUnavailable):self.call(r)
                self.assertIs(G.UNRELEASED_RESOURCES[-1],self.system.jobs[-1])
                with self.assertRaises(G.GitUnavailable):self.runner()
        self.assertEqual(self.files.fds,{});self.assertEqual(self.system.memory,{})
    def test_executable_and_input_close_failures_attempt_all_and_keep_exact_refs(self):
        r=self.runner();r.__enter__();fd=r.fd;input_fd=r.paths.handles[0]
        self.system.close_error=True;self.files.fail_close.add(input_fd)
        with self.assertRaises(G.GitUnavailable):r.close()
        self.assertIn((self.system,fd),G.UNRELEASED_RESOURCES)
        self.assertIn((self.files,input_fd),G.UNRELEASED_RESOURCES)
        self.assertEqual(set(self.files.closed),{fd for fd,path,isdir in self.files.opened})
        with self.assertRaises(G.GitUnavailable):self.runner()
    def test_malformed_constructor_and_clock_values_are_effect_free(self):
        for kwargs in ({'seconds':True},{'seconds':10},{'calls':129},{'owner_uid':True}):
            with self.assertRaises(G.GitUnavailable):self.runner(**kwargs)
        for value in (float('nan'),float('inf'),True):
            with self.assertRaises(G.GitUnavailable):G.NativeGitRunner(SHA,self.root,REVISION,files=self.files,system=self.system,clock=lambda:value)
        self.assertEqual(self.files.opened,[]);self.assertEqual(self.system.events,[])
    def test_default_backends_fail_closed_without_linux_capabilities(self):
        with patch.object(G.sys,'platform','win32'):
            with self.assertRaises(G.GitUnavailable):G.NativeFiles()
            with self.assertRaises(G.GitUnavailable):G.NativeSystem()
    def test_existing_nativegit_inventory_api_accepts_injected_runner_protocol(self):
        spec=importlib.util.spec_from_file_location('company_git_existing_protocol',ROOT/'scripts/platform_source.py')
        platform=importlib.util.module_from_spec(spec);spec.loader.exec_module(platform)
        paths=set(platform.REQUIRED_ANCHORS)|{root+'/fixture.txt' for root in platform.SOURCE_ROOTS}
        entries=tuple((name,'100644',platform._blob(b'fixture')) for name in sorted(paths))
        tree=platform._tree(entries)
        responses={('rev-parse','--show-toplevel'):str(self.root).encode()+b'\n',
            ('rev-parse','--verify','HEAD^{commit}'):REVISION.encode()+b'\n',
            ('rev-parse','--verify',REVISION+'^{tree}'):tree.encode()+b'\n',
            ('ls-files','--others','--exclude-standard','-z'):b'',
            ('ls-files','--others','--ignored','--exclude-standard','-z'):b'',
            ('ls-tree','-rz','--full-tree',REVISION):b''.join((mode+' blob '+blob+'\t'+name).encode()+b'\0' for name,mode,blob in entries),
            ('ls-files','--stage','--full-name','-z'):b''.join((mode+' '+blob+' 0\t'+name).encode()+b'\0' for name,mode,blob in entries)}
        def output():
            argv=next(e[1] for e in reversed(self.system.events) if e[0]=='start')
            self.system.output=responses[argv[len(prefix(self.root)):]]
        self.system.on_capture=output;guards=[]
        # The binary path is POSIX in this deliberately injected Linux protocol.
        from pathlib import PurePosixPath
        with self.runner() as r,patch.object(platform,'Path',PurePosixPath):
            git=platform.NativeGit(G.BINARY,r)
            self.assertEqual(git.inspect(self.root,REVISION,lambda:guards.append('guard')),(tree,entries))
            self.assertEqual(r.calls,7);self.assertEqual(len(guards),14)
        self.assertEqual(self.files.fds,{});self.assertEqual(self.system.memory,{})


class Pipe:
    def __init__(self,label,fd,h):self.label,self.fd,self.h=label,fd,h
    def fileno(self):return self.fd
    def close(self):
        self.h.events.append(('pipe-close',self.label))
        if self.h.fail_pipe==self.label:raise OSError('pipe close')


class Selector:
    def __init__(self,h):self.h,self.map=h,{}
    def register(self,stream,mask,label):self.map[stream.fd]=SimpleNamespace(fileobj=stream,data=label)
    def unregister(self,stream):self.map.pop(stream.fd)
    def select(self,wait):self.h.clock.tick(min(wait,0.01));return [(v,1) for v in list(self.map.values())]
    def get_map(self):return self.map
    def close(self):self.h.events.append(('selector-close',));self.map.clear()


class Process:
    def __init__(self,h):
        self.h,self.pid,self.returncode=h,731,None
        self.stdout,self.stderr=Pipe('stdout',101,h),Pipe('stderr',102,h)
    def wait(self,timeout):
        self.h.events.append(('wait',timeout))
        if self.h.fail_wait:raise TimeoutError('wait')
        self.returncode=self.h.wait_code;return self.returncode


class Harness:
    def __init__(self,clock):
        self.clock,self.events=clock,[];self.payload={101:b'git\x00raw',102:b''}
        self.fail_wait=self.fail_kill=self.fail_start=self.fail_pidfd=False;self.fail_pipe=None
        self.exit_code=self.wait_code=0;self.process=Process(self);self.selector=Selector(self)
    def popen(self,argv,**kwargs):
        self.events.append(('popen',argv,kwargs))
        if self.fail_start:raise OSError('ambiguous Popen')
        return self.process
    def pidfd(self,pid):
        if self.fail_pidfd:raise OSError('pidfd')
        assert pid==self.process.pid;return 777
    def read(self,fd,size):
        data=self.payload[fd];out=data[:size];self.payload[fd]=data[size:];return out
    def waitid(self,kind,pidfd,flags):
        assert kind==3 and pidfd==777 and flags==7
        self.events.append(('ownership-probe',pidfd,flags))
        return SimpleNamespace(si_pid=self.process.pid,si_code=1,si_status=self.exit_code)
    def kill(self,pid,sig):
        self.events.append(('kill',pid,self.process.returncode))
        if self.fail_kill:raise PermissionError('kill')
    def close(self,fd):self.events.append(('fd-close',fd))
    def patches(self):
        return (patch.object(G.subprocess,'Popen',self.popen),patch.object(G.os,'pidfd_open',self.pidfd,create=True),
            patch.object(G.os,'P_PIDFD',3,create=True),patch.object(G.os,'WEXITED',1,create=True),
            patch.object(G.os,'WNOHANG',2,create=True),patch.object(G.os,'WNOWAIT',4,create=True),
            patch.object(G.os,'CLD_EXITED',1,create=True),patch.object(G.os,'CLD_KILLED',2,create=True),
            patch.object(G.os,'CLD_DUMPED',3,create=True),patch.object(G.os,'waitid',self.waitid,create=True),
            patch.object(G.os,'set_blocking',lambda *a:None),patch.object(G.os,'read',self.read),
            patch.object(G.os,'killpg',self.kill,create=True),patch.object(G.os,'close',self.close),
            patch.object(G.signal,'SIGKILL',9,create=True),
            patch.object(G.signal,'pidfd_send_signal',lambda *a:self.events.append(('pidfd-kill',)),create=True),
            patch.object(G.selectors,'DefaultSelector',lambda:self.selector))


class NativeProtocolControls(unittest.TestCase):
    def setUp(self):
        self.assertEqual(G.UNRELEASED_RESOURCES,[]);self.clock=Clock();self.h=Harness(self.clock)
        self.patches=self.h.patches()
        native_job=G._NativeJob
        self.station_checks=0;self.station_error=False
        def station_guard():
            self.station_checks+=1
            if self.station_error:raise G.GitUnavailable('company-git-unavailable')
        self.patches+=(patch.object(G,'_NativeJob',lambda clock:native_job(clock,station_guard=station_guard)),)
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        G.UNRELEASED_RESOURCES.clear()
    def job(self):
        j=G._NativeJob(self.clock);j.start((G.BINARY,),dict(G.ENV),999,25);return j
    def test_sealed_fd_execution_empty_stdin_exact_environment_and_no_extra_fds(self):
        j=self.job();self.assertEqual(j.capture(25),b'git\x00raw');j.dispose(30)
        kwargs=self.h.events[0][2]
        self.assertEqual(kwargs['executable'],'/proc/self/fd/999');self.assertEqual(kwargs['pass_fds'],(999,))
        self.assertEqual(kwargs['env'],G.ENV);self.assertIs(kwargs['stdin'],G.subprocess.DEVNULL)
        self.assertIs(kwargs['close_fds'],True);self.assertIs(kwargs['start_new_session'],True)
        kill=next(i for i,e in enumerate(self.h.events) if e[0]=='kill');wait=next(i for i,e in enumerate(self.h.events) if e[0]=='wait')
        self.assertLess(kill,wait);self.assertIsNone(self.h.events[kill][2])
        self.assertEqual(sum(e[0]=='kill' for e in self.h.events),1);self.assertIn(('fd-close',777),self.h.events)
    def test_stdout_and_stderr_overflow_are_capped_and_never_success(self):
        for fd,size in ((101,G.STDOUT_LIMIT+1),(102,G.STDERR_LIMIT+1)):
            self.h.payload={101:b'',102:b''};self.h.payload[fd]=b'x'*size
            j=self.job()
            with self.assertRaises(G.GitUnavailable):j.capture(25)
            with self.assertRaises(G.GitUnavailable):j.dispose(30)
            self.assertIn(j,G.UNRELEASED_RESOURCES);G.UNRELEASED_RESOURCES.clear()
            self.h.process=Process(self.h);self.h.selector=Selector(self.h)
    def test_nonzero_status_cannot_pass_but_known_reap_closes_every_resource(self):
        self.h.exit_code=self.h.wait_code=7;j=self.job()
        with self.assertRaises(G.GitUnavailable):j.capture(25)
        j.dispose(30);self.assertEqual(G.UNRELEASED_RESOURCES,[])
        self.assertEqual(sum(e[0]=='pipe-close' for e in self.h.events),2)
    def test_wait_result_conflicting_with_peeked_status_denies(self):
        j=self.job();j.capture(25);self.h.wait_code=7
        with self.assertRaises(G.GitUnavailable):j.dispose(30)
        self.assertIn(j,G.UNRELEASED_RESOURCES)
    def test_failed_popen_retains_ambiguous_job_without_inventing_child(self):
        self.h.fail_start=True;j=G._NativeJob(self.clock)
        with self.assertRaises(OSError):j.start((G.BINARY,),dict(G.ENV),999,25)
        with self.assertRaises(G.GitUnavailable):j.dispose(30)
        self.assertIn(j,G.UNRELEASED_RESOURCES);self.assertIsNone(j.process)
    def test_pidfd_setup_failure_retains_unknown_without_signaling_or_wait(self):
        self.h.fail_pidfd=True;j=G._NativeJob(self.clock)
        with self.assertRaises(OSError):j.start((G.BINARY,),dict(G.ENV),999,25)
        with self.assertRaises(G.GitUnavailable):j.dispose(30)
        self.assertIn(j,G.UNRELEASED_RESOURCES)
        self.assertEqual(sum(e[0]=='pipe-close' for e in self.h.events),2)
        self.assertFalse(any(e[0] in ('kill','pidfd-kill','wait') for e in self.h.events))
        self.assertIs(j.process,self.h.process);self.assertIsNone(j.pidfd)
    def test_kill_or_wait_fault_retains_exact_job_and_denies_completion(self):
        for fault in ('fail_kill','fail_wait'):
            self.h.process=Process(self.h);self.h.selector=Selector(self.h);self.h.payload={101:b'',102:b''}
            self.h.fail_kill=self.h.fail_wait=False;setattr(self.h,fault,True)
            j=self.job();j.capture(25)
            with self.assertRaises(G.GitUnavailable):j.dispose(30)
            self.assertIn(j,G.UNRELEASED_RESOURCES)
            if fault=='fail_wait':self.assertEqual(j.pidfd,777)
            G.UNRELEASED_RESOURCES.clear()
    def test_pipe_close_failure_attempts_other_pipe_selector_and_pidfd(self):
        j=self.job();j.capture(25);self.h.fail_pipe='stdout'
        with self.assertRaises(G.GitUnavailable):j.dispose(30)
        self.assertIn(('pipe-close','stderr'),self.h.events);self.assertIn(('selector-close',),self.h.events)
        self.assertIn(('fd-close',777),self.h.events);self.assertIn(j,G.UNRELEASED_RESOURCES)
    def test_timeout_respects_separate_cleanup_reserve_and_no_replay(self):
        j=self.job();self.clock.tick(25)
        with self.assertRaises(G.GitUnavailable):j.capture(25)
        j.dispose(30);self.assertEqual(G.UNRELEASED_RESOURCES,[])
        with self.assertRaises(G.GitUnavailable):j.dispose(30)
    def test_expired_disposal_never_reports_known_release(self):
        j=self.job();j.capture(25);self.clock.tick(30)
        with self.assertRaises(G.GitUnavailable):j.dispose(30)
        self.assertIn(j,G.UNRELEASED_RESOURCES);self.assertEqual(j.pidfd,777)
    def test_expired_start_has_no_possible_launch_or_process(self):
        j=G._NativeJob(self.clock);self.clock.tick(25)
        with self.assertRaises(G.GitUnavailable):j.start((G.BINARY,),dict(G.ENV),999,25)
        self.assertIsNone(j.process);self.assertFalse(j.possible_launch);j.dispose(30)
        self.assertFalse(any(e[0]=='popen' for e in self.h.events))
    def test_externally_reaped_child_with_unchanged_popen_bookkeeping_never_signals(self):
        j=self.job();self.assertIsNone(j.process.returncode)
        with patch.object(G.os,'waitid',side_effect=ChildProcessError('another consumer reaped child')):
            with self.assertRaises(G.GitUnavailable):j.dispose(30)
        self.assertFalse(any(e[0] in ('kill','pidfd-kill','wait') for e in self.h.events))
        self.assertIn(j,G.UNRELEASED_RESOURCES);self.assertIs(j.process,self.h.process)
        self.assertEqual(j.pidfd,777);self.assertNotIn(('fd-close',777),self.h.events)
        self.assertEqual(sum(e[0]=='pipe-close' for e in self.h.events),2)
    def test_failed_or_inconsistent_wait_ownership_probe_retains_exact_handles(self):
        for fault in ('error','wrong_pid','unknown_code','bool_status','lost_known_status'):
            with self.subTest(fault=fault):
                self.h.events=[];self.h.process=Process(self.h);self.h.selector=Selector(self.h)
                j=self.job();self.h.payload={101:b'',102:b''}
                if fault=='lost_known_status':j.capture(25)
                value=SimpleNamespace(si_pid=self.h.process.pid,si_code=1,si_status=0)
                if fault=='wrong_pid':value.si_pid+=1
                elif fault=='unknown_code':value.si_code=99
                elif fault=='bool_status':value.si_status=False
                elif fault=='lost_known_status':value=None
                probe=patch.object(G.os,'waitid',side_effect=OSError('ownership unknown')) if fault=='error' else patch.object(G.os,'waitid',return_value=value)
                with probe:
                    with self.assertRaises(G.GitUnavailable):j.dispose(30)
                self.assertFalse(any(e[0] in ('kill','pidfd-kill','wait') for e in self.h.events))
                self.assertIn(j,G.UNRELEASED_RESOURCES);self.assertEqual(j.pidfd,777)
                G.UNRELEASED_RESOURCES.clear()
    def test_living_child_ownership_probe_occurs_immediately_before_group_signal(self):
        j=self.job()
        with patch.object(G.os,'waitid',side_effect=lambda *args:self.h.events.append(('live-ownership',args))):
            j.dispose(30)
        kill=next(i for i,e in enumerate(self.h.events) if e[0]=='kill')
        self.assertEqual(self.h.events[kill-1][0],'live-ownership')
        self.assertEqual(self.h.events[kill-1][1],(3,777,7))
        self.assertEqual(self.station_checks,2);self.assertEqual(G.UNRELEASED_RESOURCES,[])
    def test_station_contract_loss_after_launch_denies_signaling_and_reaping(self):
        j=self.job();self.station_error=True
        with self.assertRaises(G.GitUnavailable):j.dispose(30)
        self.assertFalse(any(e[0] in ('kill','pidfd-kill','wait') for e in self.h.events))
        self.assertIn(j,G.UNRELEASED_RESOURCES);self.assertEqual(j.pidfd,777)


class SealedExecutableControls(unittest.TestCase):
    def setUp(self):
        self.assertEqual(G.UNRELEASED_RESOURCES,[])
        self.raw=bytearray();self.sealed=0;self.events=[]
        self.fc=SimpleNamespace(F_ADD_SEALS=1,F_GET_SEALS=2,F_SEAL_SEAL=16,F_SEAL_WRITE=32,F_SEAL_GROW=64,F_SEAL_SHRINK=128)
        def fcntl(fd,op,value=None):
            self.assertEqual(fd,1200)
            if op==1:self.sealed=value;self.events.append(('seal',value));return 0
            self.assertEqual(op,2);return self.sealed
        self.fc.fcntl=fcntl
        def write(fd,raw):
            self.assertEqual(fd,1200);self.raw.extend(raw);return len(raw)
        self.os=SimpleNamespace(MFD_CLOEXEC=1,MFD_ALLOW_SEALING=2,MFD_EXEC=4,
            memfd_create=lambda name,flags:self.events.append(('memfd',name,flags)) or 1200,
            write=write,fchmod=lambda fd,mode:self.events.append(('chmod',fd,mode)),
            fstat=lambda fd:SimpleNamespace(st_size=len(self.raw)),get_inheritable=lambda fd:False,
            pread=lambda fd,size,offset:bytes(self.raw[offset:offset+size]),
            close=lambda fd:self.events.append(('close',fd)))
        self.mock=patch.object(G,'os',self.os);self.mock.start()
        self.system=object.__new__(G.NativeSystem);self.system.fcntl=self.fc;self.system.seals=240
    def tearDown(self):self.mock.stop();G.UNRELEASED_RESOURCES.clear()
    def test_immutable_memfd_flags_exact_bytes_mode_all_seals_and_hash(self):
        fd=self.system.executable();self.system.populate(fd,ELF);self.system.check(fd,SHA,len(ELF))
        self.assertEqual(self.raw,ELF);self.assertEqual(self.events[0],('memfd','company-git-executable',7))
        self.assertIn(('chmod',1200,0o555),self.events);self.assertIn(('seal',240),self.events)
        self.system.close(fd);self.assertIn(('close',1200),self.events)
    def test_missing_seal_inheritance_length_or_digest_denied(self):
        self.system.populate(1200,ELF)
        for fault in ('seal','inherit','length','digest'):
            with self.subTest(fault=fault):
                self.sealed=240;self.os.get_inheritable=lambda fd:False
                sha,size=SHA,len(ELF)
                if fault=='seal':self.sealed=16
                elif fault=='inherit':self.os.get_inheritable=lambda fd:True
                elif fault=='length':size+=1
                else:sha='0'*64
                with self.assertRaises(G.GitUnavailable):self.system.check(1200,sha,size)
    def test_missing_pidfd_or_selector_preflight_has_no_process_or_memfd_effect(self):
        base=dict(name='posix',memfd_create=lambda *a:None,MFD_CLOEXEC=1,MFD_ALLOW_SEALING=2,
            pidfd_open=lambda *a:None,P_PIDFD=3,waitid=lambda *a:None,WEXITED=1,WNOHANG=2,WNOWAIT=4)
        signal=SimpleNamespace(pidfd_send_signal=lambda *a:None,SIGCHLD=1,SIG_DFL=0,getsignal=lambda *a:0)
        for missing in ('pidfd_open','selector'):
            data=dict(base)
            if missing=='pidfd_open':data.pop(missing)
            with patch.object(G,'os',SimpleNamespace(**data)),patch.object(G,'sys',SimpleNamespace(platform='linux')),patch.object(G,'signal',signal),patch.object(G,'selectors',SimpleNamespace(DefaultSelector=None if missing=='selector' else lambda:None)):
                with self.assertRaises(G.GitUnavailable):G.NativeSystem()
        self.assertEqual(self.events,[])


class StationContractControls(unittest.TestCase):
    def setUp(self):
        self.assertEqual(G.UNRELEASED_RESOURCES,[]);self.events=[];self.task_names=['731']
        self.close_error=False;self.signal_default=True;self.directory=True
        owner=self
        class Tasks:
            def __init__(self):self.items=iter(owner.task_names)
            def __iter__(self):return self
            def __next__(self):
                name=next(self.items);owner.events.append(('task',name))
                return SimpleNamespace(name=name,is_dir=lambda **kw:owner.directory)
            def close(self):
                owner.events.append(('task-close',))
                if owner.close_error:raise OSError('task iterator close unknown')
        self.Tasks=Tasks
        def scandir(path):
            self.assertEqual(path,'/proc/self/task');self.events.append(('scandir',path));return Tasks()
        self.os=SimpleNamespace(name='posix',memfd_create=lambda *a:self.events.append(('memfd',)),
            MFD_CLOEXEC=1,MFD_ALLOW_SEALING=2,pidfd_open=lambda *a:None,P_PIDFD=3,
            waitid=lambda *a:None,WEXITED=1,WNOHANG=2,WNOWAIT=4,CLD_EXITED=1,CLD_KILLED=2,CLD_DUMPED=3,
            getpid=lambda:731,scandir=scandir)
        self.signal=SimpleNamespace(pidfd_send_signal=lambda *a:None,SIGCHLD=17,SIG_DFL=0,
            getsignal=lambda *a:0 if self.signal_default else 1)
        self.fc=SimpleNamespace(F_ADD_SEALS=1,F_GET_SEALS=2,F_SEAL_SEAL=16,F_SEAL_WRITE=32,F_SEAL_GROW=64,F_SEAL_SHRINK=128)
        self.patches=(patch.object(G,'os',self.os),patch.object(G,'sys',SimpleNamespace(platform='linux')),
            patch.object(G,'signal',self.signal),patch.object(G,'selectors',SimpleNamespace(DefaultSelector=lambda:None)),
            patch.dict(sys.modules,{'fcntl':self.fc}))
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        G.UNRELEASED_RESOURCES.clear()
    def test_exact_named_contract_is_required_before_any_proc_or_tool_effect(self):
        for contract in (None,True,False,1,{},[],G.STATION_CONTRACT+' ', 'single-threaded'):
            with self.subTest(contract=contract):
                with self.assertRaises(G.GitUnavailable):G.NativeSystem(station_contract=contract)
                self.assertEqual(self.events,[])
        system=G.NativeSystem(station_contract=G.STATION_CONTRACT)
        self.assertEqual(system.station_contract,G.STATION_CONTRACT)
        self.assertEqual(self.events,[('scandir','/proc/self/task'),('task','731'),('task-close',)])
    def test_actual_linux_task_inventory_denies_multiple_missing_foreign_or_nondirectory_tasks(self):
        for names,directory in (([],True),(['731','732','733'],True),(['732'],True),(['731'],False)):
            with self.subTest(names=names,directory=directory):
                self.events=[];self.task_names=names;self.directory=directory
                with self.assertRaises(G.GitUnavailable):G.NativeSystem(station_contract=G.STATION_CONTRACT)
                self.assertNotIn(('memfd',),self.events);self.assertIn(('task-close',),self.events)
                self.assertLessEqual(sum(e[0]=='task' for e in self.events),2)
    def test_default_sigchld_and_required_native_capabilities_remain_live_requirements(self):
        self.signal_default=False
        with self.assertRaises(G.GitUnavailable):G.NativeSystem(station_contract=G.STATION_CONTRACT)
        self.assertEqual(self.events,[]);self.signal_default=True
        system=G.NativeSystem(station_contract=G.STATION_CONTRACT);self.events=[]
        self.task_names=['731','732']
        with self.assertRaises(G.GitUnavailable):system.check_station()
        self.assertIn(('task-close',),self.events)
        self.task_names=['731'];self.events=[]
        for capability in ('pidfd_open','scandir','CLD_DUMPED'):
            value=getattr(self.os,capability);delattr(self.os,capability)
            try:
                with self.assertRaises(G.GitUnavailable):G.NativeSystem(station_contract=G.STATION_CONTRACT)
                self.assertEqual(self.events,[])
            finally:setattr(self.os,capability,value)
    def test_proc_inventory_close_uncertainty_is_retained_and_no_launch_occurs(self):
        self.close_error=True
        with self.assertRaises(G.GitUnavailable):G.NativeSystem(station_contract=G.STATION_CONTRACT)
        self.assertEqual(len(G.UNRELEASED_RESOURCES),1)
        system,tasks=G.UNRELEASED_RESOURCES[0]
        self.assertIsInstance(system,G.NativeSystem);self.assertIsInstance(tasks,self.Tasks)
        self.assertNotIn(('memfd',),self.events)
        count=len(self.events)
        with self.assertRaises(G.GitUnavailable):G.NativeSystem(station_contract=G.STATION_CONTRACT)
        self.assertEqual(len(self.events),count)


if __name__=='__main__':unittest.main(verbosity=2)
