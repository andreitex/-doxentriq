"""Injected binary syscall/ownership controls; no OS pipes/tools/native stages."""
import errno,importlib.util,stat,sys,unittest
from pathlib import Path
from types import ModuleType,SimpleNamespace
D=Path(__file__).resolve().parents[1]/'deploy/installer'
def fresh_capture():
 spec=importlib.util.spec_from_file_location('owned_binary_capture_controls',D/'company_binary_capture.py');module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module
C=fresh_capture()
class Fixture:
 def __init__(self,*,fresh=True):
  global C
  if fresh:C=fresh_capture()
  self.now=1.;self.advance=.01;self.parts={3:[b'a\0b',b''],4:[b'e\0r',b'']};self.closed=[];self.reads=[];self.polls=0
  self.events=None;self.callback=None;self.fail_close=None;self.timestamp=False;self.empty=False;h=self
  self.meta={fd:dict(st_dev=7,st_ino=100+fd,st_mode=stat.S_IFIFO|0o600,st_uid=0,st_gid=0,st_nlink=1,st_size=0,st_mtime_ns=1,st_ctime_ns=1) for fd in (3,4)}
  self.os=ModuleType('explicit_os');self.os.read=self.read;self.os.fstat=self.fstat;self.os.close=self.close
  self.os.O_RDONLY=0;self.os.O_ACCMODE=3;self.os.O_NONBLOCK=2048;self.os.O_LARGEFILE=0
  self.f=ModuleType('explicit_fcntl');self.f.F_GETFL=3;self.f.F_GETFD=1;self.f.FD_CLOEXEC=1;self.f.fcntl=lambda fd,cmd:2048 if cmd==3 else 1
  self.s=ModuleType('explicit_select');self.s.POLLIN=1;self.s.POLLHUP=16;self.s.POLLERR=8;self.s.POLLNVAL=32
  class Poll:
   def __init__(self):self.active=set()
   def register(self,fd,mask):self.active.add(fd)
   def unregister(self,fd):self.active.remove(fd)
   def poll(self,timeout):
    h.polls+=1;h.now+=h.advance
    if h.events is not None:return h.events
    if h.empty:return []
    return [(fd,17) for fd in sorted(self.active)]
  self.s.poll=Poll
  self.binding=dict(requestSha256='a'*64,releaseSha256='b'*64,deliverySha256='c'*64,planSha256='d'*64,actionSha256='e'*64,inputSha256='f'*64,
   stage='company-platform-store',session='s-ABCDEF123456',parentPid=100,childPid=101,parentStart=1000,childStart=1001,bootId='11111111-1111-1111-1111-111111111111')
  self.handoff=dict(binding=self.binding,channels={role:dict(fd=fd,identity=dict(self.meta[fd]),flags=2048,fdFlags=1) for role,fd in (('stdout',3),('stderr',4))})
 def clock(self):return self.now
 def fstat(self,fd):
  if self.timestamp:self.meta[fd]['st_mtime_ns']+=1
  return SimpleNamespace(**self.meta[fd])
 def close(self,fd):
  self.closed.append(fd)
  if fd==self.fail_close:raise OSError('unknown close')
 def read(self,fd,count):
  self.reads.append((fd,count))
  if self.callback:self.callback(self,fd)
  row=self.parts[fd].pop(0) if self.parts[fd] else b''
  if isinstance(row,BaseException):raise row
  if type(row) is bytes and len(row)>count:self.parts[fd].insert(0,row[count:]);return row[:count]
  return row
 def capture(self,deadline=3):return C.capture_binary(self.handoff,os_module=self.os,select_module=self.s,fcntl_module=self.f,clock=self.clock,deadline=deadline)
class CaptureControls(unittest.TestCase):
 def setUp(self):
  global C
  C=fresh_capture();self.h=Fixture()
 def tearDown(self):C.UNRELEASED.clear()
 def deny(self):
  with self.assertRaises(ValueError):self.h.capture()
 def test_concurrent_exact_binary_nul_eof_and_known_reader_closes(self):
  answer=self.h.capture();self.assertEqual((answer['stdout'],answer['stderr']),(b'a\0b',b'e\0r'))
  self.assertEqual(answer['eofRoles'],('stdout','stderr'));self.assertEqual(sorted(self.h.closed),[3,4])
  self.assertFalse(answer['executionEvidenceIssued']);self.assertFalse(answer['stageTerminalQualified']);self.assertFalse(answer['stageAcknowledged'])
  with self.assertRaises(TypeError):answer['stdout']=b'changed'
 def test_short_positive_bytes_and_hup_are_not_eof(self):
  self.h.parts={3:[b'x',b'y\0',b''],4:[b'']};answer=self.h.capture();self.assertEqual(answer['stdout'],b'xy\0');self.assertEqual(answer['readCalls'],4)
 def test_eagain_eintr_retry_within_same_deadline_not_eof(self):
  self.h.parts[3]=[BlockingIOError(errno.EAGAIN,'again'),InterruptedError(errno.EINTR,'interrupt'),b'\0',b'']
  answer=self.h.capture();self.assertEqual(answer['stdout'],b'\0');self.assertEqual(answer['pollCalls'],4)
 def test_other_read_error_refuses_and_known_closes_sticky_no_retry(self):
  self.h.parts[3]=[OSError(errno.EIO,'io error')];self.deny();self.assertEqual(sorted(self.h.closed),[3,4]);self.assertTrue(C.UNRELEASED)
  before=len(self.h.reads);self.deny();self.assertEqual(len(self.h.reads),before)
 def test_stdout_overflow_sentinel_refusal(self):
  self.h.parts[3]=[b'x'*32769,b''];self.deny();self.assertTrue(C.UNRELEASED);self.assertTrue(all(n<=4096 for fd,n in self.h.reads));self.assertEqual(sorted(self.h.closed),[3,4])
 def test_stderr_overflow_sentinel_refusal(self):
  self.h.parts[4]=[b'x'*8193,b''];self.deny();self.assertTrue(C.UNRELEASED);self.assertEqual(sorted(self.h.closed),[3,4])
 def test_idle_deadline_refuses_then_closes_with_reserved_time(self):
  self.h.empty=True;self.h.advance=.1;self.deny();self.assertEqual(sorted(self.h.closed),[3,4]);self.assertLess(self.h.now,3);self.assertTrue(C.UNRELEASED)
 def test_poll_counter_no_progress_is_finite(self):
  self.h.empty=True;self.h.advance=0;self.deny();self.assertEqual(self.h.polls,8192);self.assertEqual(sorted(self.h.closed),[3,4])
 def test_read_counter_no_progress_is_finite(self):
  self.h.parts[3]=[b'x']*5000;self.h.parts[4]=[b''];self.h.advance=0;self.deny();self.assertEqual(len(self.h.reads),4096);self.assertEqual(sorted(self.h.closed),[3,4])
 def test_bool_duplicate_and_bad_last_fd_refuse_before_callbacks(self):
  for bad in (True,3,-1):
   self.h=Fixture();self.h.handoff['channels']['stderr']['fd']=bad;self.deny();self.assertEqual(self.h.reads,[]);self.assertEqual(self.h.closed,[]);self.assertEqual(self.h.polls,0)
 def test_wrong_access_flags_refuse_before_fd_ownership(self):
  self.h.handoff['channels']['stderr']['flags']=2049;self.deny();self.assertEqual(self.h.closed,[]);self.assertEqual(self.h.reads,[])
 def test_initial_identity_mismatch_retains_without_guessed_close(self):
  self.h.meta[3]['st_ino']+=1;self.deny();self.assertEqual(self.h.closed,[]);self.assertTrue(C.UNRELEASED);self.assertIs(C.UNRELEASED[-1][0],self.h.handoff)
 def test_authorized_pipe_timestamp_changes_recorded_not_identity_denied(self):
  self.h.timestamp=True;answer=self.h.capture();self.assertNotEqual(answer['descriptorViews'][0][1][0]['st_mtime_ns'],answer['descriptorViews'][0][1][-1]['st_mtime_ns'])
  self.assertEqual(answer['stdout'],b'a\0b');self.assertEqual(sorted(self.h.closed),[3,4])
 def test_mid_read_identity_drift_retains_exact_uncertain_fd(self):
  self.h.callback=lambda h,fd:h.meta[3].update(st_ino=999)
  self.deny();self.assertNotIn(3,self.h.closed);self.assertIn(4,self.h.closed);self.assertTrue(C.UNRELEASED)
 def test_bad_read_type_refuses_never_marks_eof(self):
  self.h.parts[3]=[bytearray(b'x')];self.deny();self.assertTrue(C.UNRELEASED);self.assertEqual(sorted(self.h.closed),[3,4])
 def test_unknown_duplicate_poll_fd_refuses_before_read(self):
  for events in ([(99,1)],[(3,1),(3,1)],[(3,32)]):
   self.h=Fixture();self.h.events=events;self.deny();self.assertTrue(C.UNRELEASED);C.UNRELEASED.clear()
 def test_opaque_poll_entry_never_invokes_iteration(self):
  calls=[]
  class Opaque:
   def __iter__(self):calls.append('iter');raise AssertionError('opaque event')
  self.h.events=[Opaque()];self.deny();self.assertFalse(calls);self.assertEqual(sorted(self.h.closed),[3,4])
 def test_uncertain_close_attempted_once_retains_all_original_refs(self):
  self.h.fail_close=3;self.deny();self.assertEqual(self.h.closed.count(3),1);self.assertEqual(self.h.closed.count(4),1)
  retained=C.UNRELEASED[-1];self.assertIs(retained[0],self.h.handoff);self.assertIs(retained[7],self.h.os)
  before=list(self.h.closed);self.deny();self.assertEqual(self.h.closed,before)
 def test_os_callbacks_replaced_during_read_do_not_replace_saved_operations(self):
  calls=[]
  def callback(h,fd):h.os.close=lambda fd:calls.append('close');h.os.read=lambda *a:calls.append('read')
  self.h.callback=callback;answer=self.h.capture();self.assertFalse(calls);self.assertEqual(answer['stdout'],b'a\0b');self.assertEqual(sorted(self.h.closed),[3,4])
 def test_handoff_binding_mutation_cannot_relabel_detached_capture(self):
  self.h.callback=lambda h,fd:h.binding.update(requestSha256='0'*64)
  answer=self.h.capture();self.assertEqual(answer['binding']['requestSha256'],'a'*64)
 def test_changed_exception_global_cannot_invoke_foreign_constructor(self):
  calls=[];original=C.CaptureUnavailable
  def bad(*a):calls.append(a);return ValueError('foreign')
  def callback(h,fd):C.CaptureUnavailable=bad
  self.h.callback=callback;self.h.parts[3]=[None]
  try:
   with self.assertRaises(original):self.h.capture()
  finally:C.CaptureUnavailable=original
  self.assertFalse(calls);self.assertEqual(sorted(self.h.closed),[3,4])
 def test_poll_acquisition_failure_closes_admitted_but_unreturned_readers(self):
  def broken():raise OSError('injected poll constructor')
  self.h.s.poll=broken;self.deny();self.assertEqual(sorted(self.h.closed),[3,4]);self.assertTrue(C.UNRELEASED);self.assertIs(C.UNRELEASED[-1][-1][0][1],broken)
 def test_same_pipe_identity_with_different_fd_roles_denied_before_effects(self):
  self.h.handoff['channels']['stderr']['identity']['st_dev']=self.h.handoff['channels']['stdout']['identity']['st_dev']
  self.h.handoff['channels']['stderr']['identity']['st_ino']=self.h.handoff['channels']['stdout']['identity']['st_ino']
  self.deny();self.assertEqual(self.h.closed,[]);self.assertEqual(self.h.reads,[]);self.assertEqual(self.h.polls,0)
 def test_same_transient_class_wrong_errno_refuses_without_retry(self):
  for kind in ('read-blocked','read-interrupted','poll-interrupted'):
   self.h=Fixture()
   if kind=='read-blocked':self.h.parts[3]=[BlockingIOError(errno.EIO,'unexpected error')]
   elif kind=='read-interrupted':self.h.parts[3]=[InterruptedError(errno.EAGAIN,'unexpected error')]
   else:
    def broken(poller,timeout):raise InterruptedError(errno.EIO,'unexpected poll error')
    self.h.s.poll.poll=broken
   self.deny();self.assertEqual(self.h.polls,0 if kind=='poll-interrupted' else 1)
   self.assertEqual(sorted(self.h.closed),[3,4]);self.assertTrue(C.UNRELEASED);C.UNRELEASED.clear()
 def test_actual_fcntl_boolean_or_float_return_never_establishes_pipe_admission(self):
  for kind in ('bool','float'):
   self.h=Fixture()
   self.h.f.fcntl=lambda fd,cmd:2048 if cmd==3 else True
   if kind=='float':self.h.f.fcntl=lambda fd,cmd:2048.0 if cmd==3 else 1
   self.deny();self.assertEqual(self.h.reads,[]);self.assertEqual(self.h.closed,[]);self.assertTrue(C.UNRELEASED);C.UNRELEASED.clear()
 def test_public_failure_ledger_replacement_cannot_restart_original_scope(self):
  original=C.UNRELEASED
  def callback(h,fd):C.UNRELEASED=[]
  self.h.callback=callback;self.h.parts[3]=[None]
  try:
   self.deny();self.assertTrue(original);self.assertEqual(C.UNRELEASED,[])
   before=len(self.h.reads);self.deny();self.assertEqual(len(self.h.reads),before)
  finally:C.UNRELEASED=original
 def test_owned_bad_poll_public_clear_cannot_reset_private_failure_or_refs(self):
  self.h.events=[(99,1)];self.deny();record=C.UNRELEASED[-1]
  self.assertEqual(sorted(self.h.closed),[3,4]);self.assertIs(record[0],self.h.handoff);self.assertIs(record[7],self.h.os)
  C.UNRELEASED.clear();self.assertEqual(C.UNRELEASED,[])
  cells=dict(zip(C.capture_binary.__code__.co_freevars,(cell.cell_contents for cell in C.capture_binary.__closure__)))
  self.assertIs(cells['retained_records'][0],record);self.assertIs(cells['failed'],True)
  next_fixture=Fixture(fresh=False);calls=[]
  def forbidden():calls.append('clock');raise AssertionError('failure latch must precede collaborators')
  next_fixture.clock=forbidden
  with self.assertRaises(C.CaptureUnavailable):next_fixture.capture()
  self.assertEqual((calls,next_fixture.reads,next_fixture.closed,next_fixture.polls),([],[],[],0))
  self.assertIs(cells['retained_records'][0][0],self.h.handoff);self.assertIs(cells['retained_records'][0][7],self.h.os)
 def test_uncertain_close_public_clear_cannot_retry_or_drop_private_originals(self):
  self.h.fail_close=3;self.deny();record=C.UNRELEASED[-1]
  self.assertEqual(self.h.closed.count(3),1);self.assertEqual(self.h.closed.count(4),1);self.assertIs(record[7],self.h.os)
  C.UNRELEASED.clear();self.assertEqual(C.UNRELEASED,[])
  cells=dict(zip(C.capture_binary.__code__.co_freevars,(cell.cell_contents for cell in C.capture_binary.__closure__)))
  self.assertIs(cells['retained_records'][0],record);self.assertIs(cells['failed'],True)
  next_fixture=Fixture(fresh=False);calls=[]
  def forbidden():calls.append('clock');raise AssertionError('uncertain close must prohibit another capture')
  next_fixture.clock=forbidden
  with self.assertRaises(C.CaptureUnavailable):next_fixture.capture()
  self.assertEqual((calls,next_fixture.reads,next_fixture.closed,next_fixture.polls),([],[],[],0))
  self.assertEqual(self.h.closed.count(3),1);self.assertEqual(self.h.closed.count(4),1);self.assertIs(cells['retained_records'][0][6],self.h.os.close)
 def test_foreign_hash_keys_at_five_sites_deny_without_callbacks_or_ownership(self):
  for site in ('handoff','binding','channels','row','identity'):
   self.h=Fixture();calls=[];clock_calls=[]
   class Foreign:
    def __hash__(self):calls.append('hash');return 42
    def __eq__(self,other):calls.append('eq');return False
   targets={'handoff':self.h.handoff,'binding':self.h.binding,'channels':self.h.handoff['channels'],
    'row':self.h.handoff['channels']['stdout'],'identity':self.h.handoff['channels']['stdout']['identity']}
   targets[site][Foreign()]='synthetic';calls.clear()
   self.h.clock=lambda:(clock_calls.append('clock') or self.h.now)
   self.h.os.fstat=lambda fd:(calls.append('fstat') or None);self.h.f.fcntl=lambda *a:(calls.append('fcntl') or 0);self.h.s.poll=lambda:calls.append('poll-factory')
   self.deny();self.assertEqual(calls,[]);self.assertEqual(clock_calls,['clock'])
   self.assertEqual((self.h.reads,self.h.closed,self.h.polls),([],[],0));self.assertEqual(C.UNRELEASED,[])
 def test_foreign_colliding_eq_keys_at_five_sites_deny_before_set_or_lookup(self):
  for site,existing in (('handoff','binding'),('binding','stage'),('channels','stdout'),('row','identity'),('identity','st_ino')):
   self.h=Fixture();calls=[];clock_calls=[]
   class Foreign:
    def __hash__(self):calls.append('hash');return hash(existing)
    def __eq__(self,other):calls.append('eq');return False
   targets={'handoff':self.h.handoff,'binding':self.h.binding,'channels':self.h.handoff['channels'],
    'row':self.h.handoff['channels']['stdout'],'identity':self.h.handoff['channels']['stdout']['identity']}
   targets[site][Foreign()]='synthetic';calls.clear()
   self.h.clock=lambda:(clock_calls.append('clock') or self.h.now)
   self.h.os.fstat=lambda fd:(calls.append('fstat') or None);self.h.f.fcntl=lambda *a:(calls.append('fcntl') or 0);self.h.s.poll=lambda:calls.append('poll-factory')
   self.deny();self.assertEqual(calls,[]);self.assertEqual(clock_calls,['clock'])
   self.assertEqual((self.h.reads,self.h.closed,self.h.polls),([],[],0));self.assertEqual(C.UNRELEASED,[])
if __name__=='__main__':unittest.main(verbosity=2)
