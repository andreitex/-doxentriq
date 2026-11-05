"""Injected syscall/process controls only; no native runner or old suite run."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import stat
from types import ModuleType, SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('seed_runner_under_test',ROOT/'deploy/installer/company_seed_runner.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
DATA='/srv/autosoft/data';BACKING='/var/lib/autosoft.img'

class Clock:
 def __init__(self):self.now=0.0
 def __call__(self):return self.now

class Harness:
 """Explicit trusted primitive modules with real owned descriptor accounting."""
 def __init__(self):
  self.clock=Clock();self.fd=10;self.nodes={};self.fds={};self.log=[];self.starts=[];self.seals={};self.pid=800
  self.killed=False;self.reaped=False;self.descendant=False;self.mode='success';self.exit_code=0
  self.stdout=b'ok\n';self.stderr=b'';self.fail_close=None;self.close_false=False;self.constructor_error=False
  self.pidfd_error=False;self.bad_fd=None;self.ownership_error=False;self.kill_error=False;self.reap_error=False
  self.pipe_error=False;self.bad_events=False;self.seal_error=False;self.seal_return=None;self.stage=0;self.tasks=['77'];self.sigchld=0;self.probe_raw=None
  for path in ('/','/usr','/usr/bin','/usr/sbin'):self.node(path,b'',True)
  tool=bytearray(128);tool[:7]=b'\x7fELF\x02\x01\x01';tool[18:20]=b'\x3e\x00';self.tool=bytes(tool)
  for path in R.TOOLS:self.node(path,self.tool)
  self.os=ModuleType('explicit_fake_os');self.sys=ModuleType('explicit_fake_sys');self.subprocess=ModuleType('explicit_fake_subprocess')
  self.select=ModuleType('explicit_fake_select');self.signal=ModuleType('explicit_fake_signal');self.io=ModuleType('explicit_fake_io');self.fcntl=ModuleType('explicit_fake_fcntl')
  for name in ('open','lstat','fstat','get_inheritable','pread','write','fchmod','close','memfd_create','pidfd_open',
               'waitid','getpgid','killpg','set_blocking','read','getpid','getuid','getgid','uname','listdir'):setattr(self.os,name,getattr(self,name))
  for name,value in dict(O_RDONLY=0,O_NOFOLLOW=1,O_CLOEXEC=2,O_DIRECTORY=4,O_NONBLOCK=8,MFD_CLOEXEC=1,MFD_ALLOW_SEALING=2,
                         P_PIDFD=3,P_PID=1,WEXITED=4,WNOHANG=1,WNOWAIT=0x100,CLD_EXITED=1,CLD_KILLED=2,CLD_DUMPED=3).items():setattr(self.os,name,value)
  self.os.name='posix';self.sys.platform='linux';self.sys.byteorder='little'
  self.signal.getsignal=lambda kind:self.sigchld;self.signal.pidfd_send_signal=self.pidfd_send_signal
  self.signal.SIGCHLD=17;self.signal.SIG_DFL=0;self.signal.SIGKILL=9;self.signal.NSIG=65
  self.select.POLLIN=1;self.select.POLLHUP=16;self.select.POLLERR=8;self.select.POLLNVAL=32
  for name,value in dict(F_ADD_SEALS=1033,F_GET_SEALS=1034,F_SEAL_WRITE=8,F_SEAL_GROW=4,F_SEAL_SHRINK=2,F_SEAL_SEAL=1).items():setattr(self.fcntl,name,value)
  self.fcntl.fcntl=self.fcntl_call
  h=self
  class FileIO:
   def __init__(self,label):self.fd=h.new_fd(dict(role='pipe',label=label,raw=h.stdout if label=='stdout' else h.stderr,offset=0));self._closed=False
   def fileno(self):return self.fd
   @property
   def closed(self):return self._closed
   def close(self):
    if not self._closed:
     answer=h.close(self.fd)
     if answer is not None:return answer
     self._closed=True
  class Popen:
   def __init__(self,argv,**kw):
    if h.starts:h.pid+=1
    h.killed=False;h.reaped=False
    h.starts.append((argv,kw));h.log.append(('launch',tuple(argv)))
    self.pid=h.pid;self.returncode=None;self.stdout=FileIO('stdout');self.stderr=FileIO('stderr');self.stdin=None
    h.last_process=self
    if h.constructor_error:raise OSError('constructor outcome uncertain')
  class Poll:
   def __init__(self):self.registered={}
   def register(self,fd,mask):self.registered[fd]=mask
   def unregister(self,fd):del self.registered[fd]
   def poll(self,ms):
    h.clock.now+=ms/1000
    if h.bad_events:return [(123456,1)]
    return [(fd,1) for fd in self.registered]
  self.io.FileIO=FileIO;self.subprocess.Popen=Popen;self.subprocess.PIPE=-1;self.subprocess.DEVNULL=-3;self.select.poll=Poll
 def node(self,path,raw,directory=False):
  ino=100+len(self.nodes);self.nodes[path]=dict(raw=raw,info=dict(zip(R.FIELDS,(1,ino,(stat.S_IFDIR|0o755) if directory else stat.S_IFREG|0o755,0,0,2 if directory else 1,len(raw),11,12))))
 def new_fd(self,row):self.fd+=1;self.fds[self.fd]=row;return self.fd
 def open(self,name,flags,dir_fd=None):
  path=name if dir_fd is None else self.fds[dir_fd]['path'].rstrip('/')+'/'+name
  self.log.append(('open',path,flags,dir_fd))
  if path=='/proc/77/status':return self.new_fd(dict(role='probe',raw=self.probe_raw if self.probe_raw is not None else b'Name:\tpython\nThreads:\t'+str(len(self.tasks)).encode()+b'\n'))
  if self.bad_fd is not None:answer=self.bad_fd;self.bad_fd=None;return answer
  return self.new_fd(dict(role='file',path=path))
 def lstat(self,path):
  if path=='/proc/77/status':return SimpleNamespace(**dict(zip(R.FIELDS,(3,77,stat.S_IFREG|0o444,0,0,1,0,0,0))))
  return SimpleNamespace(**self.nodes[path]['info'])
 def fstat(self,fd):
  row=self.fds[fd]
  if row['role']=='probe':return self.lstat('/proc/77/status')
  if row['role']=='file':return self.lstat(row['path'])
  mode=(stat.S_IFIFO|0o600) if row['role']=='pipe' else (stat.S_IFREG|row.get('mode',0o500))
  return SimpleNamespace(**dict(zip(R.FIELDS,(2,fd,mode,0,0,1,len(row.get('raw',b'')),0,0))))
 def get_inheritable(self,fd):return False
 def pread(self,fd,maximum,offset):
  row=self.fds[fd];raw=self.nodes[row['path']]['raw'] if row['role']=='file' else row.get('raw',b'')
  return raw[offset:offset+maximum]
 def write(self,fd,raw):self.fds[fd]['raw']+=raw;return len(raw)
 def fchmod(self,fd,mode):self.fds[fd]['mode']=mode
 def close(self,fd):
  self.log.append(('close',fd))
  if self.fail_close==fd or self.fail_close==self.fds[fd]['role']:raise OSError('close unknown')
  if self.close_false:return False
  del self.fds[fd]
 def memfd_create(self,name,flags):return self.new_fd(dict(role='executable',raw=b'',mode=0o777))
 def pidfd_open(self,pid,flags):
  if self.pidfd_error:raise OSError('no pidfd created')
  return self.new_fd(dict(role='pidfd'))
 def fcntl_call(self,fd,command,*args):
  if command==1033:
   if self.seal_error:return -1
   if self.seal_return is not None:return self.seal_return
   self.seals[fd]=args[0];return 0
  return self.seals[fd]
 def getpid(self):return 77
 def getuid(self):return 0
 def getgid(self):return 0
 def uname(self):return SimpleNamespace(machine='x86_64')
 def listdir(self,path):assert path=='/proc/self/task';return self.tasks
 def getpgid(self,pid):return pid
 def killpg(self,pid,signal):
  self.log.append(('killpg',pid,signal,self.reaped))
  if signal:
   assert not self.reaped
   if self.kill_error:raise OSError('kill unknown')
   self.killed=True;self.descendant=False
  elif not self.descendant:raise ProcessLookupError('absent')
 def pidfd_send_signal(self,fd,signal):self.log.append(('pidfd-signal',fd,signal));self.killed=True
 def waitid(self,kind,identifier,flags):
  consume=not bool(flags&0x100);self.log.append(('waitid',consume,kind,identifier))
  if self.ownership_error and not consume:raise ChildProcessError('ownership lost')
  if self.reap_error and consume:raise OSError('reap unknown')
  if self.reaped:raise ChildProcessError('already consumed')
  if self.mode=='timeout' and not self.killed:return None
  if consume:self.reaped=True
  return SimpleNamespace(si_pid=self.pid,si_code=2 if self.mode=='timeout' else 1,si_status=9 if self.mode=='timeout' else self.exit_code)
 def set_blocking(self,fd,blocking):assert blocking is False
 def read(self,fd,maximum):
  if self.pipe_error:raise OSError('pipe unknown')
  row=self.fds[fd];raw=row['raw'][row['offset']:row['offset']+maximum];row['offset']+=len(raw)
  if not raw and self.mode=='timeout' and not self.killed:raise BlockingIOError()
  return raw
 def make(self,**changes):
  pins={p:dict(sha256=hashlib.sha256(self.nodes[p]['raw']).hexdigest(),bytes=len(self.nodes[p]['raw']),identity=dict(self.nodes[p]['info'])) for p in R.TOOLS}
  args=dict(tool_catalog=pins,data_directory=DATA,storage_file=BACKING,
   budget=dict(calls=64,seconds=600,toolReadBytes=1024**2,outputBytes=1024**2),os_module=self.os,sys_module=self.sys,
   subprocess_module=self.subprocess,select_module=self.select,signal_module=self.signal,io_module=self.io,fcntl_module=self.fcntl,
   clock=self.clock,station_contract=R.STATION_CONTRACT)
  args.update(changes);return R.SeedRunner(**args)
 def call(self,runner,args=None,**changes):
  kw=dict(stdin=None,maximum=65536,timeout=60,tool=None,environment=dict(R.ENV));kw.update(changes)
  return runner.run(args or ['/usr/bin/docker','ps','-aq','--no-trunc'],**kw)

def original_commands():
 raw=(ROOT/'scripts/bootstrap.py').read_bytes();tree=ast.parse(raw)
 names={'SeedUnavailable','_seed_require','SeedCommands'}
 nodes=[n for n in tree.body if getattr(n,'name',None) in names]
 assert len(nodes)==3
 module=ModuleType('original_seed_commands');module.SEED_UNRELEASED=[]
 exec(compile(ast.Module(body=nodes,type_ignores=[]),str(ROOT/'scripts/bootstrap.py'),'exec'),vars(module))
 return module

class RunnerControls(unittest.TestCase):
 def setUp(self):self.assertFalse(R.UNRELEASED);self.harnesses=[]
 def tearDown(self):
  # Explicit disposal of synthetic registries only, never a product retry.
  for h in self.harnesses:h.fds.clear()
  R.UNRELEASED.clear()
 def harness(self):h=Harness();self.harnesses.append(h);return h
 def test_original_seed_commands_protocol_and_close_fds_only_executable_inherited(self):
  h=self.harness();h.stdout=b'';runner=h.make();B=original_commands();original=B.SeedCommands(R,runner)
  self.assertIs(runner.require_released(),runner);self.assertEqual(original.text(['/usr/bin/docker','ps','-aq','--no-trunc']),'')
  self.assertFalse(h.fds);self.assertIs(runner.require_released(),runner)
  argv,kw=h.starts[0];self.assertIs(kw['close_fds'],True);self.assertEqual(len(kw['pass_fds']),1)
  self.assertTrue(kw['executable'].startswith('/proc/self/fd/'));self.assertIs(kw['shell'],False)
  self.assertEqual(kw['env'],R.ENV);self.assertEqual(kw['cwd'],'/');self.assertEqual(kw['bufsize'],0)
 def test_exact_twenty_three_query_vectors_admitted_and_mutation_refused(self):
  h=self.harness();runner=h.make();prefix=['/usr/bin/systemctl','show',*('--property='+x for x in R.PROPERTIES),'--']
  queries=[prefix+[u] for u in R.UNITS]+[['/usr/bin/docker','ps','-aq','--no-trunc'],
   ['/usr/sbin/cryptsetup','luksUUID',BACKING],['/usr/sbin/cryptsetup','status','autosoft-data'],
   ['/usr/sbin/losetup','--noheadings','--output','BACK-FILE','--','/dev/loop123'],
   ['/usr/bin/findmnt','-n','-o','TARGET,SOURCE,FSTYPE,OPTIONS','--target',DATA],
   ['/usr/bin/findmnt','-n','-o','SOURCE,FSTYPE,OPTIONS','--target',DATA],['/usr/sbin/xfs_quota','-x','-c','state -p',DATA]]
  self.assertEqual(len(queries),23)
  for query in queries:self.assertEqual(runner.request(query,None,65536,60,None,dict(R.ENV)),tuple(query))
  for query in (['/bin/bash','-c','true'],['/usr/bin/docker','run'],['/usr/bin/systemctl','start','autosoft.service'],
                ['/usr/sbin/xfs_quota','-x','-c','limit -p bhard=1m 1',DATA],['/usr/bin/git','--version']):
   with self.assertRaises(ValueError):runner.request(query,None,65536,60,None,dict(R.ENV))
  self.assertEqual(h.starts,[]);self.assertEqual(h.fds,{})
 def test_wrong_paths_units_properties_loop_and_environment_before_open(self):
  for args,changes in ((['/usr/sbin/cryptsetup','luksUUID','/other'],{}),
   (['/usr/sbin/losetup','--noheadings','--output','BACK-FILE','--','/dev/loop-1'],{}),
   (['/usr/bin/findmnt','-n','-o','SOURCE,FSTYPE,OPTIONS','--target','/other'],{}),
   (None,{'stdin':b'command'}),(None,{'tool':object()}),(None,{'maximum':True}),(None,{'timeout':59}),
   (None,{'environment':dict(R.ENV,LD_PRELOAD='evil')})):
   h=self.harness();runner=h.make()
   with self.assertRaises(ValueError):h.call(runner,args,**changes)
   self.assertFalse(h.starts);self.assertFalse(h.fds);self.assertIs(runner.require_released(),runner)
 def test_tool_digest_identity_type_owner_link_and_caps_deny_before_launch(self):
  for field,value in (('st_uid',10001),('st_mode',stat.S_IFLNK|0o777),('st_nlink',2)):
   h=self.harness();h.nodes['/usr/bin/docker']['info'][field]=value;runner=h.make()
   with self.assertRaises(ValueError):h.call(runner)
   self.assertFalse(h.starts);self.assertFalse(h.fds)
  h=self.harness();runner=h.make();h.nodes['/usr/bin/docker']['raw']=b'X'*128
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.starts);self.assertFalse(h.fds)
  with self.assertRaises(ValueError):R.catalog({})
  with self.assertRaises(ValueError):R.budgets(dict(calls=True,seconds=60,toolReadBytes=1024,outputBytes=1024))
 def test_source_ancestor_or_tool_metadata_drift_and_read_budget_refused(self):
  h=self.harness();runner=h.make();h.nodes['/usr/bin/docker']['info']['st_ctime_ns']+=1
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.starts);self.assertFalse(h.fds)
  h=self.harness();runner=h.make(budget=dict(calls=1,seconds=60,toolReadBytes=1,outputBytes=1))
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.starts);self.assertFalse(h.fds)
 def test_memfd_is_sealed_and_executable_hash_rechecked(self):
  h=self.harness();runner=h.make();result=h.call(runner)
  self.assertEqual(result,dict(exitCode=0,stdout=b'ok\n',stderr=b'',ownedReleased=True))
  self.assertEqual(set(h.seals.values()),{15});self.assertFalse(h.fds)
  self.assertEqual(runner.observations[0]['stdout'],b'ok\n')
  with self.assertRaises(TypeError):runner.observations[0]['ownedReleased']=False
 def test_seal_failure_closes_known_fds_and_never_launches(self):
  h=self.harness();h.seal_error=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.starts);self.assertFalse(h.fds);self.assertIs(runner.require_released(),runner)
 def test_success_with_descendant_always_kills_group_before_consuming_status(self):
  h=self.harness();h.descendant=True;runner=h.make();h.call(runner)
  signals=[r for r in h.log if r[0]=='killpg'];self.assertEqual(signals[0],('killpg',h.pid,9,False));self.assertEqual(signals[-1][2:],(0,True))
  consume=next(i for i,r in enumerate(h.log) if r[:2]==('waitid',True));kill=next(i for i,r in enumerate(h.log) if r[:3]==('killpg',h.pid,9))
  self.assertLess(kill,consume);self.assertFalse(h.fds);self.assertFalse(h.descendant)
 def test_nonzero_exit_preserved_in_closed_result(self):
  h=self.harness();h.exit_code=7;runner=h.make();result=h.call(runner)
  self.assertEqual(result['exitCode'],7);self.assertIs(result['ownedReleased'],True);self.assertFalse(h.fds)
 def test_timeout_disposes_within_same_sixty_second_bound_and_no_retry(self):
  h=self.harness();h.mode='timeout';h.descendant=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertTrue(h.killed);self.assertTrue(h.reaped);self.assertFalse(h.fds);self.assertLess(h.clock.now,60)
  self.assertIs(runner.require_released(),runner)
  with self.assertRaises(ValueError):h.call(runner)
  self.assertEqual(len(h.starts),1)
 def test_outer_deadline_and_call_budget_before_new_launch(self):
  h=self.harness();runner=h.make();h.clock.now=596
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.starts);self.assertFalse(h.fds)
  h=self.harness();runner=h.make(budget=dict(calls=1,seconds=600,toolReadBytes=1024**2,outputBytes=1024))
  h.call(runner)
  with self.assertRaises(ValueError):h.call(runner)
  self.assertEqual(len(h.starts),1)
 def test_stdout_and_stderr_overflow_retained_bounded_and_cleanup_attempted(self):
  for label in ('stdout','stderr'):
   h=self.harness();setattr(h,label,b'A'*65537);runner=h.make()
   with self.assertRaises(ValueError):h.call(runner)
   self.assertTrue(h.killed);self.assertTrue(h.reaped);self.assertFalse(h.fds)
   self.assertLessEqual(len(runner.observations[0][label]),65536);self.assertIs(runner.observations[0]['captureComplete'],False)
 def test_process_constructor_ambiguity_retains_original_refs_no_relaunch(self):
  h=self.harness();h.constructor_error=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertTrue(R.UNRELEASED);self.assertEqual(len(runner.jobs),1);self.assertTrue(h.fds)
  self.assertIs(runner.jobs[0].p.modules['subprocess'],h.subprocess)
  with self.assertRaises(ValueError):runner.require_released()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertEqual(len(h.starts),1)
 def test_pidfd_creation_failure_is_cleanup_only_and_pipes_are_registered(self):
  h=self.harness();h.pidfd_error=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertTrue(h.killed);self.assertTrue(h.reaped);self.assertFalse(h.fds);self.assertIs(runner.require_released(),runner)
  self.assertTrue(any(r[0]=='waitid' and r[2]==1 for r in h.log))
 def test_lost_ownership_never_signals_or_reaps_and_retains_process_pidfd(self):
  h=self.harness();h.ownership_error=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(any(r[0]=='killpg' for r in h.log));self.assertFalse(h.reaped)
  self.assertTrue(any(v['role']=='pidfd' for v in h.fds.values()));self.assertTrue(R.UNRELEASED)
 def test_failed_kill_attempts_pidfd_signal_and_retains_unknown(self):
  h=self.harness();h.kill_error=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertTrue(any(r[0]=='pidfd-signal' for r in h.log));self.assertTrue(R.UNRELEASED)
  with self.assertRaises(ValueError):runner.require_released()
 def test_failed_reap_retains_unreaped_pidfd_and_never_postreap_signal(self):
  h=self.harness();h.reap_error=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.reaped);self.assertTrue(h.fds);self.assertTrue(R.UNRELEASED)
  self.assertFalse(any(r[0]=='killpg' and r[2]==0 for r in h.log))
 def test_unknown_pipe_error_and_poll_event_fail_closed(self):
  for field in ('pipe_error','bad_events'):
   h=self.harness();setattr(h,field,True);runner=h.make()
   with self.assertRaises(ValueError):h.call(runner)
   self.assertTrue(h.killed);self.assertIs(runner.observations[0]['captureComplete'],False)
   self.assertTrue(R.UNRELEASED);R.UNRELEASED.clear()
 def test_every_raw_and_pipe_close_failure_retained_once_other_closes_attempted(self):
  for role in ('file','executable','pidfd','pipe'):
   h=self.harness();h.fail_close=role;runner=h.make()
   with self.assertRaises(ValueError):h.call(runner)
   self.assertTrue(R.UNRELEASED);self.assertTrue(h.fds)
   closed=[r[1] for r in h.log if r[0]=='close'];self.assertEqual(len(closed),len(set(closed)))
   self.assertTrue(any(r['closed'] for r in runner.jobs[0].raw))
   with self.assertRaises(ValueError):runner.require_released()
   R.UNRELEASED.clear()
 def test_false_raw_close_result_denies_known_release(self):
  h=self.harness();h.close_false=True;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertTrue(h.fds);self.assertTrue(R.UNRELEASED)
 def test_malformed_open_return_retained_without_closing_invalid_reference(self):
  h=self.harness();opaque=object();h.bad_fd=opaque;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertTrue(any(r[1]=='invalid-returned-fd' and r[3] is opaque for r in R.UNRELEASED))
  self.assertTrue(all(r['role']=='probe' for r in h.fds.values()));self.assertFalse(h.starts)
 def test_multiple_tasks_or_custom_sigchld_denied_before_open(self):
  for field,value in (('tasks',['77','78']),('sigchld',1)):
   h=self.harness();setattr(h,field,value);runner=h.make()
   with self.assertRaises(ValueError):h.call(runner)
   self.assertFalse(h.starts);self.assertFalse(h.fds)
 def test_primitive_drift_never_invokes_changed_callback(self):
  h=self.harness();runner=h.make();called=[];h.os.open=lambda *a,**k:called.append((a,k))
  with self.assertRaises(ValueError):h.call(runner)
  self.assertEqual(called,[]);self.assertFalse(h.starts);self.assertFalse(h.fds)
 def test_unsupported_os_missing_capability_and_contract_deny_construction(self):
  h=self.harness();h.sys.platform='win32'
  with self.assertRaises(ValueError):h.make()
  h=self.harness();del h.os.pidfd_open
  with self.assertRaises(ValueError):h.make()
  h=self.harness()
  with self.assertRaises(ValueError):h.make(station_contract='yes')
  self.assertFalse(h.starts);self.assertFalse(h.fds)
 def test_station_probe_close_failure_retains_exact_fd_and_never_launches(self):
  h=self.harness();h.fail_close='probe';runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.starts);self.assertEqual(len(runner._p.probes),1)
  row=runner._p.probes[0];self.assertTrue(row['attempted']);self.assertFalse(row['closed']);self.assertIn(row['fd'],h.fds)
  self.assertTrue(any(r[1]=='station-probe-close-unknown' and r[2] is row for r in R.UNRELEASED))
  before=[r for r in h.log if r[0]=='close']
  with self.assertRaises(ValueError):runner.require_released()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertEqual([r for r in h.log if r[0]=='close'],before)
 def test_station_probe_overflow_duplicate_or_malformed_threads_deny_known_closes(self):
  for raw in (b'A'*16385,b'Threads:\t1\nThreads:\t1\n',b'Threads:\t01\n',b'Threads:\t2\n'):
   h=self.harness();h.probe_raw=raw;runner=h.make()
   with self.assertRaises(ValueError):h.call(runner)
   self.assertFalse(h.starts);self.assertFalse(h.fds);self.assertFalse(R.UNRELEASED)
   self.assertIs(runner.require_released(),runner)
 def test_station_probe_flags_noninheritance_and_no_hidden_enumerator(self):
  h=self.harness();runner=h.make();h.call(runner)
  probes=[r for r in h.log if r[0]=='open' and r[1]=='/proc/77/status']
  self.assertTrue(probes);self.assertTrue(all(r[2]==11 for r in probes));self.assertEqual(runner._p.probes,[])
  self.assertNotIn('listdir',runner._p.os);self.assertFalse(h.fds)
 def test_boolean_seal_return_is_not_integer_zero(self):
  h=self.harness();h.seal_return=False;runner=h.make()
  with self.assertRaises(ValueError):h.call(runner)
  self.assertFalse(h.starts);self.assertFalse(h.fds);self.assertIs(runner.require_released(),runner)
 def test_every_tool_family_executes_only_its_fixed_query_and_releases(self):
  h=self.harness();runner=h.make()
  queries=[['/usr/bin/systemctl','show',*('--property='+v for v in R.PROPERTIES),'--',R.UNITS[0]],
   ['/usr/bin/docker','ps','-aq','--no-trunc'],['/usr/sbin/cryptsetup','luksUUID',BACKING],
   ['/usr/sbin/cryptsetup','status','autosoft-data'],['/usr/sbin/losetup','--noheadings','--output','BACK-FILE','--','/dev/loop0'],
   ['/usr/bin/findmnt','-n','-o','TARGET,SOURCE,FSTYPE,OPTIONS','--target',DATA],
   ['/usr/bin/findmnt','-n','-o','SOURCE,FSTYPE,OPTIONS','--target',DATA],['/usr/sbin/xfs_quota','-x','-c','state -p',DATA]]
  for query in queries:
   result=h.call(runner,query);self.assertEqual(result['stdout'],b'ok\n');self.assertIs(result['ownedReleased'],True)
   self.assertFalse(h.fds);self.assertIs(runner.require_released(),runner)
  self.assertEqual({args[0] for args,kw in h.starts},set(R.TOOLS));self.assertEqual(len(runner.observations),8)

if __name__=='__main__':unittest.main(verbosity=2)
