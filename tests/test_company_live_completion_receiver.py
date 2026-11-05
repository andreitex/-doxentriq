"""Injected socket/kernel-shaped controls; no native endpoint/process action."""
import collections,errno,hashlib,socket as original_socket,_socket as original_raw_socket,struct,types,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]/'deploy/installer'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
Meta=collections.namedtuple('Meta',FIELDS)
def load():
    module=types.ModuleType('controlled_completion_receiver');module.__file__=str(HERE/'company_live_completion_receiver.py')
    exec(compile((HERE/'company_live_completion_receiver.py').read_bytes(),module.__file__,'exec'),vars(module));return module


class Fixture:
    def __init__(self):
        self.M=load();self.calls=[];self.time=0.;self.hook=None;self.close_error=False;self.right_close_error=False;self.deferred=False
        self.records={20:Meta(9,200,0o140777,0,0,1,0,0,0)};self.closed=[];self.cred=(500,0,0)
        self.messages=[(b'ASET1|public\n',[(1,2,struct.pack('=iii',*self.cred))],0,None),(b'',[],0,None)]
        self.os=types.ModuleType('controlled_os');self.os.name='posix';self.os.stat_result=Meta;self.os.fstat=self.fstat;self.os.close=self.raw_close
        self.sy=types.ModuleType('controlled_sys');self.sy.platform='linux'
        self.fc=types.ModuleType('controlled_fcntl');self.fc.fcntl=self.fcntl
        self.se=types.ModuleType('controlled_select');self.se.POLLIN=1;self.se.POLLHUP=16;self.se.POLLERR=8;self.se.POLLNVAL=32;self.se.poll=self.poll_factory
        self.sock=types.ModuleType('controlled_socket')
        vars(self.sock).update(AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PASSCRED=16,SCM_CREDENTIALS=2,SCM_RIGHTS=1,MSG_CTRUNC=8,MSG_TRUNC=32,MSG_CMSG_CLOEXEC=1073741824)
        self.raw_constants=types.ModuleType('controlled_raw_socket_constants')
        vars(self.raw_constants).update({key:vars(self.sock)[key] for key in ('AF_UNIX','SOCK_STREAM','SOL_SOCKET','SO_PASSCRED','SCM_CREDENTIALS','SCM_RIGHTS','MSG_CTRUNC','MSG_TRUNC','MSG_CMSG_CLOEXEC')})
        fixture=self
        class Socket:
            __slots__=('_fd','_io_refs','_closed')
            def __init__(self):self._fd=20;self._io_refs=0;self._closed=False
            @property
            def family(self):return 1
            @property
            def type(self):return 1
            @property
            def proto(self):return 0
            def fileno(self):fixture.event('fileno');return self._fd
            def getsockopt(self,level,option):fixture.event('getsockopt',level,option);return 1
            def recvmsg(self,size,ancsize,flags):
                fixture.event('recvmsg',size,ancsize,flags)
                result=fixture.messages.pop(0)
                if isinstance(result,BaseException):raise result
                return result
            def close(self):
                fixture.event('socket-close',self._fd)
                if fixture.close_error:raise OSError(errno.EIO,'injected-close-unknown')
                if fixture.deferred:return None
                fixture.closed.append(self._fd);del fixture.records[self._fd];self._fd=-1;self._closed=True
        Socket.__module__=self.sock.__name__;self.sock.socket=Socket;self.endpoint=Socket()
        self.binding={key:'a'*64 for key in self.M.BINDING[:6]}
        self.binding.update(stage='company-platform-store',session='s-ABCDEFGHIJKL',parentPid=500,childPid=501,parentStart=10,childStart=11,bootId='12345678-1234-1234-1234-123456789abc')
        self.handoff=dict(endpoint=dict(fd=20,identity=dict(zip(FIELDS,self.records[20]))),sender=dict(role='original-bash',pid=500,uid=0,gid=0,start=10,bootId=self.binding['bootId']),binding=self.binding,protectedFds=(30,31))
    def event(self,name,*args):
        self.calls.append((name,*args))
        if self.hook:self.hook(name,*args)
    def fstat(self,fd):self.event('fstat',fd);return self.records[fd]
    def raw_close(self,fd):
        self.event('raw-close',fd)
        if self.right_close_error:raise OSError(errno.EIO,'injected-right-close-unknown')
        self.closed.append(fd);del self.records[fd]
    def fcntl(self,fd,command):self.event('fcntl',fd,command);return 1 if command==1 else 2050
    def clock(self):self.time+=.001;return self.time
    def poll_factory(self):
        fixture=self
        class Poll:
            def __init__(self):self.fds=[]
            def register(self,fd,mask):self.fds.append(fd);fixture.event('poll-register',fd)
            def poll(self,timeout):fixture.event('poll');return [(20,17)]
        return Poll()
    def positive(self,raw,cred=None,flags=0):return (raw,[(1,2,struct.pack('=iii',*(self.cred if cred is None else cred)))],flags,None)
    def right(self,fd):
        self.records[fd]=Meta(9,fd+200,0o100600,0,0,1,0,0,0);return (1,1,struct.pack('=i',fd))
    def run(self):return self.M.receive_completion(self.handoff,endpoint=self.endpoint,os_module=self.os,sys_module=self.sy,socket_module=self.sock,raw_constants_module=self.raw_constants,
        fcntl_module=self.fc,select_module=self.se,clock=self.clock)


class Controls(unittest.TestCase):
    def test_fragmented_same_sender_actual_eof_known_owner_close_data_only(self):
        f=Fixture();f.messages=[f.positive(b'ASE'),f.positive(b'T1|public'),f.positive(b'\n'),(b'',[],0,None)];r=f.run()
        self.assertEqual(r['raw'],b'ASET1|public\n');self.assertEqual(r['fragments'],3);self.assertTrue(r['actualStreamEof'] and r['ownScopeKnownReleased'])
        self.assertIs(f.M.require_released(r),r);self.assertFalse(r['executionEvidenceIssued'] or r['parentAuthenticated'] or r['senderBirthAuthenticated'])
        self.assertEqual(f.closed,[20]);self.assertFalse(f.records)
        with self.assertRaises(TypeError):r['raw']=b'changed'
    def test_mixed_sender_second_fragment_denies_then_closes_original_owner(self):
        f=Fixture();f.messages=[f.positive(b'a'),f.positive(b'b',(501,0,0))]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20]);self.assertTrue(f.M.UNRELEASED)
    def test_missing_credentials_never_accepts_a_positive_fragment(self):
        f=Fixture();f.messages=[(b'a',[],0,None)]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20])
    def test_duplicate_credentials_denied(self):
        f=Fixture();item=f.positive(b'a');f.messages=[(item[0],item[1]*2,0,None)]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20])
    def test_rights_on_eof_are_registered_closed_before_denial(self):
        f=Fixture();right=f.right(21);f.messages=[(b'',[right],0,None)]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[21,20]);self.assertFalse(f.records)
    def test_ctrunc_stays_unknown_after_disclosed_right_once_close(self):
        f=Fixture();right=f.right(21);f.messages=[(b'a',[right],8,None)]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[21,20]);before=len(f.calls);f.M.UNRELEASED.clear()
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(len(f.calls),before)
    def test_rights_actual_return_registered_before_os_drift_postguard(self):
        f=Fixture();right=f.right(21);f.messages=[(b'a',[right],0,None)]
        def mutate(name,*args):
            if name=='recvmsg':f.os.added_during_recv=True
        f.hook=mutate
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[21,20]);self.assertTrue(f.M.UNRELEASED)
    def test_unreturned_recv_exception_retains_unknown_no_retry(self):
        f=Fixture();f.messages=[MemoryError('unreturned-acquisition')]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20]);self.assertEqual(sum(row[0]=='recvmsg' for row in f.calls),1);self.assertTrue(f.M.UNRELEASED)
    def test_eagain_and_eintr_retry_same_scope_before_eof(self):
        f=Fixture();f.messages=[BlockingIOError(errno.EAGAIN,'busy'),InterruptedError(errno.EINTR,'signal'),f.positive(b'a'),(b'',[],0,None)]
        r=f.run();self.assertEqual(r['raw'],b'a');self.assertEqual(sum(row[0]=='recvmsg' for row in f.calls),4)
    def test_unexpected_errno_is_not_retried_or_eof(self):
        f=Fixture();f.messages=[BlockingIOError(errno.EIO,'unexpected')]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(sum(row[0]=='recvmsg' for row in f.calls),1);self.assertEqual(f.closed,[20])
    def test_oversize_without_eof_denies_and_retains_actual_return(self):
        f=Fixture();f.messages=[f.positive(b'x'*512) for _ in range(4)]+[f.positive(b'x')]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20]);self.assertTrue(f.M.UNRELEASED)
    def test_empty_stream_is_not_a_completed_status(self):
        f=Fixture();f.messages=[(b'',[],0,None)]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20])
    def test_non_eof_progress_deadline_denies_without_second_acquisition(self):
        f=Fixture();f.messages=[f.positive(b'x')]*200;clock=f.clock
        def advance():f.time+=1.;return f.time
        f.clock=advance
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20]);before=len(f.calls)
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(len(f.calls),before)
    def test_close_unknown_is_never_retried(self):
        f=Fixture();f.close_error=True
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(sum(row[0]=='socket-close' for row in f.calls),1);self.assertIn(20,f.records)
    def test_deferred_close_none_cannot_claim_known_descriptor_release(self):
        f=Fixture();f.deferred=True
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertIn(20,f.records);self.assertTrue(f.M.UNRELEASED)
    def test_changed_socket_close_code_never_runs_on_unwind(self):
        f=Fixture();method=f.sock.socket.close;original=method.__code__
        def replacement(self):f.calls.append(('changed-socket-close',));self._closed=True;self._fd=-1
        def mutate(name,*args):
            if name=='recvmsg':method.__code__=replacement.__code__
        f.hook=mutate
        try:
            with self.assertRaises(f.M.CompletionUnavailable):f.run()
        finally:method.__code__=original
        self.assertFalse(f.closed);self.assertIn(20,f.records)
    def test_right_fstat_mutated_close_body_never_runs(self):
        f=Fixture();right=f.right(21);f.messages=[(b'a',[right],0,None)];method=Fixture.raw_close;original=method.__code__
        def replacement(self,fd):self.calls.append(('changed-close',fd))
        def mutate(name,*args):
            if name=='fstat' and args[0]==21:method.__code__=replacement.__code__
        f.hook=mutate
        try:
            with self.assertRaises(f.M.CompletionUnavailable):f.run()
        finally:method.__code__=original
        self.assertFalse(any(row[0]=='changed-close' for row in f.calls));self.assertIn(21,f.records)
    def test_success_then_second_valid_call_is_denied_before_callbacks(self):
        f=Fixture();f.run();before=len(f.calls)
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(len(f.calls),before)
    def test_wrong_expected_fd_is_not_adopted_or_blind_closed(self):
        f=Fixture();f.handoff['endpoint']['fd']=22
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertFalse(f.closed);self.assertIn(20,f.records)
    def test_foreign_binding_key_denies_without_hash_eq_or_socket_callbacks(self):
        f=Fixture();calls=[]
        class Key:
            def __hash__(self):calls.append('hash');return 1
            def __eq__(self,other):calls.append('eq');return False
        f.binding[Key()]='a';calls.clear()
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertFalse(calls or f.calls)

    def test_errno_symbol_mutation_cannot_turn_eio_into_transient(self):
        f=Fixture();f.messages=[BlockingIOError(errno.EIO,'unexpected')];original=errno.EAGAIN
        def mutate(name,*args):
            if name=='recvmsg':errno.EAGAIN=errno.EIO
        f.hook=mutate
        try:
            with self.assertRaises(f.M.CompletionUnavailable):f.run()
        finally:errno.EAGAIN=original
        self.assertEqual(sum(row[0]=='recvmsg' for row in f.calls),1);self.assertEqual(f.closed,[20])
    def test_successful_close_boundary_drift_retains_return_without_data(self):
        f=Fixture()
        def mutate(name,*args):
            if name=='socket-close':f.M.changed_during_close=True
        f.hook=mutate
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20]);self.assertFalse(f.records)
        self.assertTrue(any(row[0]=='socket-close-return' and row[1] is None for row in f.M.UNRELEASED[0][8]))

    def test_truncated_return_remains_explicit_unknown_after_known_closes(self):
        for mask in (8,32):
            with self.subTest(mask=mask):
                f=Fixture();right=f.right(21);f.messages=[(b'a',[right],mask,None)]
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                self.assertEqual(f.closed,[21,20]);self.assertIs(f.M.UNRELEASED[0][-1],True)
                before=len(f.calls);f.M.UNRELEASED.clear()
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                self.assertEqual(len(f.calls),before)

    def test_real_public_stdlib_enums_do_not_replace_explicit_raw_integer_policy(self):
        f=Fixture();f.sock.SOCK_STREAM=original_socket.SOCK_STREAM;f.sock.MSG_CTRUNC=original_socket.MSG_CTRUNC
        f.raw_constants.SOCK_STREAM=original_raw_socket.SOCK_STREAM
        self.assertIs(type(f.sock.SOCK_STREAM),original_socket.SocketKind);self.assertIs(type(f.raw_constants.SOCK_STREAM),int)
        self.assertIs(type(f.sock.MSG_CTRUNC),original_socket.MsgFlag)
        r=f.run();self.assertEqual(r['raw'],b'ASET1|public\n');self.assertEqual(f.closed,[20])
    def test_actual_platform_raw_constants_are_inspected_without_socket_construction(self):
        f=Fixture();f.raw_constants=original_raw_socket
        expected=dict(AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PASSCRED=16,SCM_CREDENTIALS=2,SCM_RIGHTS=1,MSG_CTRUNC=8,MSG_TRUNC=32,MSG_CMSG_CLOEXEC=1073741824)
        if all(type(vars(original_raw_socket).get(key)) is int and vars(original_raw_socket)[key]==value for key,value in expected.items()):
            r=f.run();self.assertFalse(r['nativeQualified'])
        else:
            with self.assertRaises(f.M.CompletionUnavailable):f.run()
            self.assertFalse(f.calls or f.closed)
    def test_foreign_bool_and_opaque_raw_constants_deny_before_callbacks(self):
        calls=[]
        class Opaque:
            def __int__(self):calls.append('int');return 1
            def __eq__(self,other):calls.append('eq');return True
        for value in (True,Opaque(),original_socket.SOCK_STREAM):
            with self.subTest(value_kind=type(value).__name__):
                f=Fixture();f.raw_constants.SOCK_STREAM=value
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                self.assertFalse(f.calls or f.closed or calls)
    def test_raw_constants_module_drift_denies_after_actual_return_known_close(self):
        f=Fixture()
        def mutate(name,*args):
            if name=='recvmsg':f.raw_constants.SOCK_STREAM=True
        f.hook=mutate
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(f.closed,[20]);self.assertTrue(f.M.UNRELEASED)
        self.assertTrue(any(row[0]=='recvmsg-return' for row in f.M.UNRELEASED[0][8]))

class EOFDiagnosticsControls(unittest.TestCase):
    AUTHORITY = ('parentAuthenticated','senderBirthAuthenticated','inputOriginQualified',
                 'sourceClosureObserved','actualBashWaitObserved','completeCopygraphQualified',
                 'nativeQualified','executionEvidenceIssued','stageAcknowledged')
    KEYS = ('scope','firstPhase','firstReason','recvAttempts','acceptedBytes','positiveFragments',
            'disclosedRights','truncationUnknown','lastReturn','socketCloseAttempted',
            'socketKnownClosed','unknownOwnership','cleanupErrorPresent') + AUTHORITY

    def diagnostic(self, fixture):
        value = fixture.M.observe_failure()
        self.assertIs(type(value), types.MappingProxyType)
        self.assertEqual(set(value), set(self.KEYS))
        self.assertEqual(value['scope'], 'LIVE_COMPLETION_FAILURE_OBSERVATION_DATA_ONLY')
        self.assertIs(type(value['firstPhase']), str)
        self.assertIn(value['firstReason'], ('predicate-refused','callback-exception'))
        for key in self.AUTHORITY:self.assertIs(value[key], False)
        with self.assertRaises(TypeError):value['firstReason']='changed'
        with self.assertRaises(fixture.M.CompletionUnavailable):fixture.M.require_released(value)
        return value

    def plain(self, value):
        if type(value) in (dict, types.MappingProxyType):
            return {key:self.plain(item) for key,item in value.items()}
        if type(value) in (tuple,list):return [self.plain(item) for item in value]
        self.assertIn(type(value),(str,int,bool,type(None)))
        return value

    def test_authenticated_fragments_then_zero_credentials_eof_preserves_eof_data(self):
        f=Fixture();self.assertIsNone(f.M.observe_failure())
        zero=(b'',[(1,2,struct.pack('=iii',0,0,0))],1073741824,None)
        f.messages=[f.positive(b'ASE'),f.positive(b'T1|public\n'),zero]
        value=f.run()
        self.assertEqual(value['raw'],b'ASET1|public\n')
        self.assertEqual(value['eofCredentials'],(0,0,0))
        self.assertEqual(value['observedCredentials'],(f.cred,f.cred))
        self.assertTrue(value['actualStreamEof'] and value['ownScopeKnownReleased'])
        self.assertEqual(f.closed,[20]);self.assertFalse(f.records)
        self.assertIs(f.M.require_released(value),value)
        self.assertIsNone(f.M.observe_failure())

    def test_empty_ancillary_eof_retains_none_without_synthetic_credentials(self):
        f=Fixture();value=f.run()
        self.assertIsNone(value['eofCredentials'])
        self.assertEqual(value['observedCredentials'],(f.cred,))
        self.assertEqual(f.closed,[20])

    def test_zero_credentials_cannot_authenticate_positive_bytes_or_an_empty_stream(self):
        zero=(1,2,struct.pack('=iii',0,0,0))
        for messages in ([(b'x',[zero],0,None)],[(b'',[zero],0,None)]):
            with self.subTest(positive=bool(messages[0][0])):
                f=Fixture();f.messages=messages
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                data=self.diagnostic(f)
                self.assertEqual(data['acceptedBytes'],0)
                self.assertFalse(f.records)
                self.assertIs(data['socketKnownClosed'],True)

    def test_eof_malformed_duplicate_or_other_credentials_never_complete(self):
        zero=(1,2,struct.pack('=iii',0,0,0))
        cases=([zero,zero],[(1,2,b'\0'*8)],[(1,2,b'\0'*16)],
               [(1,2,struct.pack('=iii',500,0,0))],[(1,2,struct.pack('=iii',0,1,0))],
               [(1,2,struct.pack('=iii',0,0,1))],[(1,999,b'')])
        for ancillary in cases:
            with self.subTest(ancillary=ancillary):
                f=Fixture();f.messages=[f.positive(b'accepted'),(b'',ancillary,0,None)]
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                data=self.diagnostic(f)
                self.assertEqual(data['firstPhase'],'eof-controls')
                self.assertEqual(data['lastReturn']['payloadBytes'],0)
                self.assertIs(data['socketKnownClosed'],True)
                self.assertEqual(f.closed,[20]);self.assertFalse(f.records)

    def test_eof_rights_are_disclosed_once_and_truncation_remains_unknown(self):
        for mask in (0,8,32):
            with self.subTest(mask=mask):
                f=Fixture();right=f.right(21)
                f.messages=[f.positive(b'accepted'),(b'',[right],mask,None)]
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                data=self.diagnostic(f)
                self.assertEqual(data['disclosedRights'],1)
                self.assertIs(data['truncationUnknown'],mask!=0)
                self.assertEqual(f.closed,[21,20]);self.assertFalse(f.records)
                before=len(f.calls);f.M.UNRELEASED.clear()
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                self.assertEqual(len(f.calls),before)
                self.assertEqual(self.plain(f.M.observe_failure()),self.plain(data))

    def test_first_failure_survives_cleanup_error_and_public_ledger_clear(self):
        first=Fixture();first.messages=[first.positive(b'PRIVATE-STATUS-TAIL',(501,0,0))]
        with self.assertRaises(first.M.CompletionUnavailable):first.run()
        first_data=self.diagnostic(first)
        f=Fixture();f.close_error=True;f.messages=[f.positive(b'PRIVATE-STATUS-TAIL',(501,0,0))]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        data=self.diagnostic(f)
        self.assertEqual((data['firstPhase'],data['firstReason']),
                         (first_data['firstPhase'],first_data['firstReason']))
        self.assertEqual(data['firstPhase'],'positive-credentials')
        self.assertIs(data['cleanupErrorPresent'],True)
        self.assertIs(data['socketKnownClosed'],False)
        self.assertEqual(sum(row[0]=='socket-close' for row in f.calls),1)
        import json
        self.assertNotIn('PRIVATE-STATUS-TAIL',json.dumps(self.plain(data)))
        f.M.UNRELEASED.clear();before=len(f.calls)
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(len(f.calls),before)
        self.assertEqual(self.plain(f.M.observe_failure()),self.plain(data))

    def test_return_summary_is_retained_before_post_callback_origin_refusal(self):
        f=Fixture();f.messages=[f.positive(b'PRIVATE-RETURN')]
        def mutate(name,*args):
            if name=='recvmsg':f.os.changed_after_return=True
        f.hook=mutate
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        data=self.diagnostic(f);last=data['lastReturn']
        self.assertIs(last['shapeKnown'],True)
        self.assertEqual(last['payloadBytes'],14)
        self.assertEqual(last['credentials'],(f.cred,))
        self.assertEqual(last['ancillaryShape'],((1,2,12),))
        self.assertEqual(data['acceptedBytes'],0)
        import json
        self.assertNotIn('PRIVATE-RETURN',json.dumps(self.plain(data)))

    def test_opaque_receive_return_never_runs_diagnostic_attributes(self):
        f=Fixture();calls=[]
        class Opaque:
            def __iter__(self):calls.append('iter');raise AssertionError('foreign iteration')
            def __len__(self):calls.append('len');raise AssertionError('foreign length')
            def __str__(self):calls.append('str');raise AssertionError('foreign formatting')
            @property
            def errno(self):calls.append('errno');raise AssertionError('foreign errno')
        opaque=Opaque();f.messages=[opaque]
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        data=self.diagnostic(f)
        self.assertEqual(data['firstPhase'],'returned-shape')
        self.assertIs(data['lastReturn']['shapeKnown'],False)
        self.assertIsNone(data['lastReturn']['payloadBytes'])
        self.assertFalse(calls)

    def test_foreign_exception_attributes_and_text_are_never_diagnostic_input(self):
        f=Fixture();calls=[]
        class ForeignError(OSError):
            def __str__(self):calls.append('str');raise AssertionError('foreign formatting')
            @property
            def errno(self):calls.append('errno');raise AssertionError('foreign errno')
        problem=ForeignError(5,'PRIVATE-EXCEPTION-TAIL');f.messages=[problem];calls.clear()
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        data=self.diagnostic(f)
        self.assertEqual(data['firstReason'],'callback-exception')
        self.assertIsNone(data['lastReturn'])
        import json
        self.assertNotIn('PRIVATE-EXCEPTION-TAIL',json.dumps(self.plain(data)))
        self.assertFalse(calls)

    def test_saved_failure_accessor_uses_no_changed_formatter_or_public_accessor(self):
        f=Fixture();calls=[];original=f.M.observe_failure
        def foreign_accessor():calls.append('accessor');raise AssertionError('foreign accessor')
        def foreign_formatter(*args):calls.append('formatter');raise AssertionError('foreign formatter')
        def mutate(name,*args):
            if name=='recvmsg':
                f.M.observe_failure=foreign_accessor;f.M.str=foreign_formatter;f.M.type=foreign_formatter
        f.hook=mutate
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        data=original()
        self.assertIs(type(data),types.MappingProxyType)
        self.assertEqual(data['lastReturn']['payloadBytes'],len(b'ASET1|public\n'))
        self.assertFalse(calls)
        before=len(f.calls);f.M.UNRELEASED.clear()
        with self.assertRaises(f.M.CompletionUnavailable):f.run()
        self.assertEqual(len(f.calls),before)
        self.assertFalse(calls)

    def test_invalid_large_diagnostic_scalars_are_not_exported(self):
        giant=1<<20000
        cases=(([(1,2,struct.pack('=iii',500,0,0))],giant),
               ([(1,2,struct.pack('=iii',500,0,0))],-1),
               ([(giant,2,b'opaque')],0),([(1,giant,b'opaque')],0))
        for index,(ancillary,flags) in enumerate(cases):
            with self.subTest(index=index):
                f=Fixture();f.messages=[(b'x',ancillary,flags,None)]
                with self.assertRaises(f.M.CompletionUnavailable):f.run()
                data=self.diagnostic(f);summary=data['lastReturn']
                self.assertIs(summary['shapeKnown'],False)
                if index<2:self.assertIsNone(summary['flags'])
                else:self.assertFalse(summary['ancillaryShape'])
                import json
                encoded=json.dumps(self.plain(data)).encode()
                self.assertLess(len(encoded),2048)


if __name__=='__main__':unittest.main(verbosity=2)
