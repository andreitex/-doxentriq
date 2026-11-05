"""Injected syscall/process controls; no OpenSSL, keys, VM or old suites run."""
import base64
from collections import namedtuple
from enum import IntEnum
import hashlib
import importlib.util
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
 sys.modules[name]=module;spec.loader.exec_module(module);return module
C=load('company_crypto_controls',ROOT/'deploy/installer/company_release_crypto.py')
T=load('company_crypto_explicit_syscall_fixture',ROOT/'tests/test_company_seed_runner.py')
MESSAGE=b'{"schemaVersion":4}\n';SIGNATURE=b's'*64
KEY=b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(bytes.fromhex('302a300506032b6570032100')+b'a'*32)+b'\n-----END PUBLIC KEY-----\n'

class Harness(T.Harness):
 def __init__(self):
  super().__init__();self.reuse=True;self.callback=None;self.close_callback=None;self.wait_callback=None
  self.station_count=0;self.opens=[];self.close_attempts=[];self.mutations=[];self.mem_calls=[]
  self.node(C.TOOL,self.tool);self.node('/dev/null',b'')
  self.nodes['/dev/null']['info']['st_mode']=stat.S_IFCHR|0o666
  self.os.O_RDWR=16;self.os.stat=self.stat;self.os.major=lambda n:n>>8;self.os.minor=lambda n:n&255
  self.os.open=self.open;self.os.fstat=self.fstat;self.os.close=self.close;self.os.memfd_create=self.memfd_create
  self.os.pread=self.pread;self.os.waitid=self.waitid
  self.os.waitid_result=namedtuple('waitid_result','si_pid si_uid si_signo si_status si_code')
  self.subprocess._active=[];h=self
  class Popen:
   def __init__(self,argv,**kw):
    h.starts.append((argv,kw));h.log.append(('launch',tuple(argv)))
    self.pid=h.pid;self.returncode=None;self.stdin=self.stdout=self.stderr=None
    h.last_process=self
    if h.constructor_error:raise OSError('ambiguous constructor')
  self.subprocess.Popen=Popen
 def new_fd(self,row):
  if self.reuse:
   fd=next(n for n in range(3,100) if n not in self.fds)
  else:self.fd+=1;fd=self.fd
  self.fds[fd]=row;return fd
 def open(self,*a,**kw):
  fd=super().open(*a,**kw);self.opens.append(fd)
  if self.fds.get(fd,{}).get('role')=='probe':self.station_count+=1
  return fd
 def fstat(self,fd):
  value=super().fstat(fd)
  if 'inode_override' in self.fds[fd]:value.st_ino=self.fds[fd]['inode_override']
  if self.fds[fd]['role']=='executable':value.st_nlink=0
  if self.fds[fd].get('path')=='/dev/null':value.st_rdev=259
  return value
 def stat(self,path):
  assert path.startswith('/proc/self/fd/');return self.fstat(int(path.rsplit('/',1)[1]))
 def pread(self,fd,size,offset):
  if self.callback:self.callback(self,fd,size,offset)
  return super().pread(fd,size,offset)
 def memfd_create(self,name,flags):
  fd=super().memfd_create(name,flags);self.mem_calls.append((name,fd));return fd
 def close(self,fd):
  self.close_attempts.append((fd,self.fds.get(fd,{}).get('role')))
  if self.close_callback:self.close_callback(self,fd)
  return super().close(fd)
 def waitid(self,kind,identifier,flags):
  if self.wait_callback:self.wait_callback(self,kind,identifier,flags)
  result=super().waitid(kind,identifier,flags)
  if result is None:return None
  return self.os.waitid_result(result.si_pid,0,17,result.si_status,result.si_code)
 def pin(self):return dict(bytes=len(self.tool),sha256=hashlib.sha256(self.tool).hexdigest(),identity=dict(self.nodes[C.TOOL]['info']))
 def crypto(self,**changes):
  args=dict(openssl_pin=self.pin(),budget=dict(calls=2,seconds=30),os_module=self.os,sys_module=self.sys,
   subprocess_module=self.subprocess,select_module=self.select,signal_module=self.signal,fcntl_module=self.fcntl,
   clock=self.clock,station_contract=C.STATION_CONTRACT,protected_fds=(0,1,2))
  args.update(changes);return C.ReleaseCrypto(**args)

class CryptoControls(unittest.TestCase):
 def setUp(self):self.h=Harness();self.assertFalse(C.UNRELEASED)
 def tearDown(self):
  # Exact synthetic process/FD state only. No product reconciliation/reset API.
  self.h.fds.clear();C.UNRELEASED.clear();C._OWNERS.clear()
 def reject(self,call):
  with self.assertRaises((ValueError,TypeError,OSError)):call()
 def test_exact_fixed_verification_uses_three_sealed_inputs_and_known_closes(self):
  h=self.h;crypto=h.crypto();self.assertIs(crypto.require_released(),crypto)
  self.assertIs(crypto.verify(MESSAGE,SIGNATURE,KEY),True);self.assertIs(crypto.require_released(),crypto)
  argv,options=h.starts[0]
  self.assertEqual(argv[:5],[C.TOOL,'pkeyutl','-verify','-rawin','-pubin'])
  self.assertEqual(argv[5::2],['-inkey','-in','-sigfile']);self.assertEqual(options['env'],dict(C.ENV))
  self.assertEqual(options['stdin'],options['stdout']);self.assertEqual(options['stdout'],options['stderr'])
  self.assertFalse(options['shell']);self.assertTrue(options['close_fds']);self.assertTrue(options['start_new_session'])
  self.assertEqual(len(options['pass_fds']),4);self.assertTrue(options['executable'].startswith('/proc/self/fd/'))
  self.assertEqual(len(h.mem_calls),4);self.assertFalse(h.fds);self.assertTrue(h.reaped)
  self.assertTrue(any(row[0]=='killpg' and row[2]==9 and row[3] is False for row in h.log))
 def test_known_closed_lowest_fd_reuse_succeeds_across_all_station_checks(self):
  h=self.h;crypto=h.crypto();self.assertIs(crypto.verify(MESSAGE,SIGNATURE,KEY),True)
  self.assertGreater(len(h.opens),len(set(h.opens)));self.assertEqual(h.station_count,3)
  self.assertFalse(h.fds);self.assertFalse(C.UNRELEASED)
 def test_exact_message_signature_key_bytes_reach_the_fixed_fd_vector(self):
  h=self.h;seen=[];original=h.subprocess.Popen
  class Capture(original):pass
  # Use a concrete independently supplied Popen class with captured constructor.
  def initial(instance,argv,**options):
   ids=[int(argv[index].rsplit('/',1)[1]) for index in (8,10,6)]
   seen.append(tuple(h.fds[fd]['raw'] for fd in ids));original.__init__(instance,argv,**options)
  Capture.__init__=initial;h.subprocess.Popen=Capture
  crypto=h.crypto();self.assertTrue(crypto.verify(MESSAGE,SIGNATURE,KEY));self.assertEqual(seen,[(MESSAGE,SIGNATURE,KEY)])
 def test_boolean_pin_budget_and_missing_station_contract_deny_before_open(self):
  bad=hpin=self.h.pin();bad=dict(bad,bytes=True)
  for changes in (dict(openssl_pin=bad),dict(budget=dict(calls=True,seconds=30)),dict(station_contract=''),dict(protected_fds=(True,))):
   self.reject(lambda:self.h.crypto(**changes))
  self.assertFalse(self.h.opens);self.assertFalse(self.h.starts)
 def test_wrong_platform_and_missing_pidfd_capability_deny_before_open(self):
  for name,value in (('platform','win32'),('byteorder','big')):
   old=getattr(self.h.sys,name);setattr(self.h.sys,name,value);self.reject(self.h.crypto);setattr(self.h.sys,name,old)
  old=self.h.os.pidfd_open;self.h.os.pidfd_open=None;self.reject(self.h.crypto);self.h.os.pidfd_open=old
  self.assertFalse(self.h.opens)
 def test_native_int_backed_signal_constants_work_without_custom_integer_callback(self):
  h=self.h
  class Signals(IntEnum):SIGCHLD=17;SIGKILL=9
  class Handlers(IntEnum):SIG_DFL=0
  h.signal.SIGCHLD=Signals.SIGCHLD;h.signal.SIGKILL=Signals.SIGKILL;h.signal.SIG_DFL=Handlers.SIG_DFL
  h.sigchld=Handlers.SIG_DFL;crypto=h.crypto()
  self.assertTrue(crypto.verify(MESSAGE,SIGNATURE,KEY));self.assertFalse(h.fds)
  class Number(int):
   def __int__(self):self.fail('custom integer callback')
  self.assertEqual(C._signal_number(Number(9)),9)
 def test_boolean_signal_handler_and_uid_cannot_establish_station_admission(self):
  h=self.h;h.signal.SIGKILL=True;self.reject(h.crypto);self.assertFalse(h.opens)
  h.signal.SIGKILL=9;h.os.getuid=lambda:False;self.reject(h.crypto);self.assertFalse(h.opens)
 def test_unissued_subclass_and_foreign_process_metaclass_deny_without_callbacks(self):
  class Fake(C.ReleaseCrypto):pass
  self.reject(lambda:Fake(**{}))
  calls=[]
  class Meta(type):
   def __getattribute__(cls,name):
    if name=='__dict__':calls.append(name)
    return type.__getattribute__(cls,name)
  class Foreign(metaclass=Meta):pass
  self.h.subprocess.Popen=Foreign;self.reject(self.h.crypto);self.assertFalse(calls)
 def test_bad_input_types_sizes_and_non_ed25519_keys_fail_before_open(self):
  for values in ((True,SIGNATURE,KEY),(b'',SIGNATURE,KEY),(b'x'*16385,SIGNATURE,KEY),
                 (MESSAGE,b's'*63,KEY),(MESSAGE,SIGNATURE,b'private key'),(MESSAGE,SIGNATURE,b'k'*4097)):
   crypto=self.h.crypto();self.reject(lambda:crypto.verify(*values));self.assertFalse(self.h.opens)
 def test_multitask_and_changed_sigchld_station_deny_before_child(self):
  for kind in ('tasks','signal'):
   h=Harness();self.h=h
   if kind=='tasks':h.tasks=['77','78']
   else:h.sigchld=1
   crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
   self.assertFalse(h.starts);self.assertFalse(h.fds);C._OWNERS.clear()
 def test_tool_sha_identity_mode_and_link_mismatches_deny_before_child(self):
  for field,value in (('sha256','a'*64),('mode',stat.S_IFREG|0o777),('link',2)):
   h=Harness();self.h=h;pin=h.pin()
   if field=='sha256':pin['sha256']=value
   else:h.nodes[C.TOOL]['info']['st_mode' if field=='mode' else 'st_nlink']=value
   crypto=h.crypto(openssl_pin=pin);self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
   self.assertFalse(h.starts);self.assertFalse(h.fds);C._OWNERS.clear()
 def test_seal_failure_and_input_byte_drift_never_launch(self):
  h=self.h;h.seal_error=True;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertFalse(h.starts);self.assertFalse(h.fds)
 def test_same_length_input_drift_after_sealing_denies_before_child(self):
  h=self.h;changed=[]
  def callback(h,fd,size,offset):
   if not changed and offset==0 and any(name=='company-release-0' and item==fd for name,item in h.mem_calls):
    raw=h.fds[fd]['raw'];h.fds[fd]['raw']=bytes([raw[0]^1])+raw[1:];changed.append(fd)
  h.callback=callback;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertTrue(changed);self.assertFalse(h.starts);self.assertFalse(h.fds)
 def test_nonzero_verifier_exit_is_authentication_denial_with_known_release(self):
  h=self.h;h.exit_code=1;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertFalse(h.fds);self.assertTrue(h.reaped);self.assertIs(crypto.require_released(),crypto)
  count=len(h.starts);self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY));self.assertEqual(len(h.starts),count)
 def test_timeout_owns_signal_before_consuming_wait_and_releases_once(self):
  h=self.h;h.mode='timeout';crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertTrue(h.killed);self.assertTrue(h.reaped);self.assertFalse(h.fds);self.assertLess(h.clock.now,15)
  kill=next(i for i,row in enumerate(h.log) if row[0]=='killpg' and row[2]==9)
  reap=next(i for i,row in enumerate(h.log) if row[0]=='waitid' and row[1] is True)
  self.assertLess(kill,reap)
 def test_external_reaper_or_ownership_failure_sends_no_numeric_group_signal(self):
  h=self.h;h.ownership_error=True;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertFalse(any(row[0]=='killpg' for row in h.log));self.assertFalse(h.reaped)
  self.assertTrue(C.UNRELEASED);self.reject(crypto.require_released)
  self.assertIs(C.UNRELEASED[-1][1]['process'],h.last_process)
 def test_pidfd_acquisition_failure_retains_exact_child_and_never_falls_back_to_pid(self):
  h=self.h;h.pidfd_error=True;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertFalse(any(row[0]=='killpg' for row in h.log));self.assertFalse(h.reaped);self.assertTrue(C.UNRELEASED)
  self.assertIs(C.UNRELEASED[-1][1]['process'],h.last_process)
 def test_pidfd_identity_drift_never_signals_or_consumes_wait(self):
  h=self.h
  def callback(h,kind,identifier,flags):
   if flags&h.os.WNOWAIT:h.fds[identifier]['inode_override']=999999
  h.wait_callback=callback;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertFalse(any(row[0]=='killpg' for row in h.log));self.assertFalse(h.reaped);self.assertTrue(C.UNRELEASED)
 def test_foreign_process_replacement_retains_original_child_without_dict_callback(self):
  h=self.h;calls=[]
  class Foreign:
   @property
   def __dict__(self):calls.append('dict');raise AssertionError('foreign process')
  def callback(h,kind,identifier,flags):
   if flags&h.os.WNOWAIT:C._OWNERS[id(crypto)]['job']['process']=Foreign()
  h.wait_callback=callback;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertFalse(calls);self.assertFalse(any(row[0]=='killpg' for row in h.log));self.assertTrue(C.UNRELEASED)
  self.assertIs(C.UNRELEASED[-1][0]['child'][0],h.last_process)
 def test_ambiguous_constructor_retains_possible_launch_without_blind_reap(self):
  h=self.h;h.constructor_error=True;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertTrue(C.UNRELEASED);self.assertFalse(h.reaped);self.assertFalse(any(row[0]=='killpg' for row in h.log))
 def test_unknown_close_is_attempted_once_and_blocks_reuse_and_new_calls(self):
  h=self.h;h.fail_close='probe';crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertEqual(len(h.close_attempts),1);self.assertTrue(C.UNRELEASED);self.assertFalse(h.starts)
  opened=len(h.opens);self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY));self.assertEqual(len(h.opens),opened)
 def test_changed_cleanup_helper_is_never_invoked_after_guard_detects_drift(self):
  h=self.h;calls=[];original=C._station
  def changed(*args):calls.append(args);raise AssertionError('changed cleanup')
  def callback(h,kind,identifier,flags):
   if flags&h.os.WNOWAIT:C._station=changed
  h.wait_callback=callback;crypto=h.crypto()
  try:self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  finally:C._station=original
  self.assertFalse(calls);self.assertTrue(C.UNRELEASED);self.assertFalse(h.reaped)
 def test_helper_changed_during_cleanup_station_cannot_run_after_first_check(self):
  h=self.h;calls=[];original=C._ownership
  def changed(*a):calls.append(a);raise AssertionError('changed helper')
  def callback(h,fd):
   if h.station_count==3 and h.fds[fd]['role']=='probe':C._ownership=changed
  h.close_callback=callback;crypto=h.crypto()
  try:self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  finally:C._ownership=original
  self.assertFalse(calls);self.assertFalse(any(row[0]=='killpg' for row in h.log));self.assertTrue(C.UNRELEASED)
 def test_changed_raw_close_module_callback_is_not_used_for_original_owned_fds(self):
  h=self.h;calls=[];original=h.os.close
  def callback(h,kind,identifier,flags):h.os.close=lambda fd:calls.append(fd)
  h.wait_callback=callback;crypto=h.crypto()
  self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY));self.assertFalse(calls)
  self.assertGreater(len(h.close_attempts),2);self.assertTrue(C.UNRELEASED);h.os.close=original
 def test_opaque_registration_is_retained_without_iteration_callback(self):
  h=self.h;calls=[]
  class Opaque:
   def __iter__(self):calls.append('iter');raise AssertionError('foreign ownership')
  def callback(h,kind,identifier,flags):
   job=C._OWNERS[id(crypto)]['job'];job['registrations'][-1]=Opaque()
  h.wait_callback=callback;crypto=h.crypto();self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertFalse(calls);self.assertTrue(C.UNRELEASED)
 def test_caller_owned_duplicate_descriptor_is_never_closed(self):
  h=self.h;h.bad_fd=42;crypto=h.crypto(protected_fds=(0,1,2,42))
  self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY));self.assertFalse(any(fd==42 for fd,role in h.close_attempts))
  self.assertTrue(C.UNRELEASED)
 def test_plain_instance_drift_and_call_budget_do_not_restart_adapter(self):
  h=self.h;crypto=h.crypto(budget=dict(calls=1,seconds=30))
  self.assertTrue(crypto.verify(MESSAGE,SIGNATURE,KEY));self.reject(lambda:crypto.verify(MESSAGE,SIGNATURE,KEY))
  self.assertEqual(len(h.starts),1)
  crypto.extra=True;self.reject(crypto.require_released)

 def test_exception_replaced_during_cleanup_cannot_run_foreign_constructor(self):
  h=self.h;calls=[];original=C.ReleaseCryptoUnavailable
  def changed(*args):calls.append(args);return ValueError('foreign constructor')
  def callback(h,fd):
   if h.station_count==3 and h.fds[fd]['role']=='probe':C.ReleaseCryptoUnavailable=changed
  h.close_callback=callback;crypto=h.crypto()
  try:
   with self.assertRaises(original):crypto.verify(MESSAGE,SIGNATURE,KEY)
  finally:C.ReleaseCryptoUnavailable=original
  self.assertFalse(calls);self.assertFalse(any(row[0]=='killpg' for row in h.log))
  self.assertFalse(h.reaped);self.assertTrue(C.UNRELEASED)
  retained=C.UNRELEASED[-1];self.assertIs(retained[0]['child'][0],h.last_process)
  self.assertIs(retained[1]['process'],h.last_process)
  self.assertIn(retained[1]['pidfd'],h.fds);self.assertGreater(len(h.close_attempts),3)
  self.reject(crypto.require_released)

if __name__=='__main__':unittest.main(verbosity=2)
