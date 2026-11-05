"""Linked RAM endpoints + original P parsers; no sockets/processes/native IO."""
import hashlib
import importlib.util
from pathlib import Path
import stat
import struct
import sys
from types import ModuleType
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
SOURCE_PIN='8aa949381e170c2f58a498406644df91504c13ced6a2afcb3df229949e1bdb75'
PARENT_PIN='e8d0c9de63eec5f68f20cc559030c728f97d4c21090dc343370209472491c547'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BOOT='12345678-1234-4123-8123-123456789abc'


def load(name,path,pin):
    raw=path.read_bytes()
    assert len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==pin
    module=ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    try:exec(compile(raw,str(path),'exec'),vars(module))
    except BaseException:
        sys.modules.pop(name,None);raise
    return module


class Meta:
    __slots__=FIELDS
    def __init__(self,values):
        for key,value in zip(FIELDS,values):setattr(self,key,value)


class Uname:
    __slots__=('machine',)
    def __init__(self):self.machine='x86_64'


class Endpoint:
    __slots__=('family','type','proto','_io_refs','_closed','_fd','_world','_role')
    def __init__(self,world,role,fd):
        self.family,self.type,self.proto,self._io_refs,self._closed=1,5,0,0,False
        self._fd,self._world,self._role=fd,world,role
    def fileno(self):return -1 if self._closed else self._fd
    def getsockopt(self,level,kind):
        assert (level,kind)==(1,16);return 1
    def sendmsg(self,parts):
        assert type(parts)is list and len(parts)==1 and type(parts[0])is bytes
        world=self._world;raw=parts[0];peer='capture' if self._role=='execute' else 'execute'
        result=(raw,[(1,2,struct.pack('=iii',world.actors[self._role].pid,0,0))],1073741824,None)
        world.queues[peer].append(result);world.sent.append((self._role,raw));world.log.append(('send',self._role,len(raw)))
        world.hook('send',self._role,result)
        return world.send_count if world.send_count is not None else len(raw)
    def recvmsg(self,size,ancsize,flags):
        assert (size,ancsize,flags)==(512,96,1073741824)
        result=self._world.queues[self._role].pop(0)
        if self._world.receive_transform:result=self._world.receive_transform(self._role,result)
        self._world.recv_returns.append((self._role,result));self._world.log.append(('recv',self._role))
        self._world.hook('recv',self._role,result)
        return result
    def close(self):
        self._world.close_attempts.append(self._fd)
        if self._world.fail_close==self._fd:raise OSError('public RAM close uncertainty')
        del self._world.fds[self._fd];self._closed=True


class Poll:
    __slots__=('_world','_role','fd','mask')
    def __init__(self,world,role):self._world,self._role=world,role
    def register(self,fd,mask):self.fd,self.mask=fd,mask
    def poll(self,milliseconds):
        self._world.log.append(('poll',self._role,milliseconds));self._world.now+=0.001
        self._world.hook('poll',self._role,self.mask)
        if self.mask&4:return [(self.fd,4)]
        if not self._world.queues[self._role] and self._role=='execute' and not self._world.driven:
            self._world.driven=True
            self._world.capture_permit=self._world.capture_join.join()
        return [(self.fd,1)] if self._world.queues[self._role] else []


class Actor:
    def __init__(self,world,role,pid):
        self.world,self.role,self.pid=world,role,pid
        self.os=ModuleType('ram_'+role+'_os');self.os.name='posix';self.os.stat_result=Meta;self.os.uname_result=Uname
        for name in ('getpid','getppid','getresuid','getresgid','uname','open','stat','fstat','pread','close'):
            setattr(self.os,name,getattr(self,name))
        self.sys=ModuleType('ram_'+role+'_sys');self.sys.platform='linux'
        self.socket=ModuleType('ram_'+role+'_socket');self.raw=ModuleType('ram_'+role+'_raw_socket')
        self.socket.socket=Endpoint;self.socket._socket=self.raw
        for key,value in dict(AF_UNIX=1,SOCK_SEQPACKET=5,SOL_SOCKET=1,SO_PASSCRED=16,SCM_CREDENTIALS=2,
                             SCM_RIGHTS=1,MSG_CTRUNC=8,MSG_TRUNC=32,MSG_CMSG_CLOEXEC=1073741824).items():setattr(self.raw,key,value)
        self.fc=ModuleType('ram_'+role+'_fcntl');self.fc.fcntl=self.fcntl
        self.select=ModuleType('ram_'+role+'_select');self.select.poll=self.poll
    def getpid(self):return self.pid
    def getppid(self):return 42
    def getresuid(self):return (0,0,0)
    def getresgid(self):return (0,0,0)
    def uname(self):return self.world.uname
    def clock(self):
        self.world.now+=self.world.clock_step;self.world.hook('clock',self.role,None);return self.world.now
    def poll(self):return Poll(self.world,self.role)
    def open(self,path,flags,*,dir_fd=None):
        if dir_fd is not None:path=self.world.fds[dir_fd]['path'].rstrip('/')+'/'+path
        self.world.log.append(('open',self.role,path,flags));self.world.hook('open',self.role,path)
        if self.world.open_alias is not None:
            result=self.world.open_alias;self.world.open_alias=None;return result
        assert path in self.world.nodes
        self.world.next_fd+=1;fd=self.world.next_fd
        self.world.fds[fd]=dict(path=path,meta=self.world.nodes[path][0],flags=(flags&~524288)|32768)
        return fd
    def stat(self,path,*,follow_symlinks=False):
        assert follow_symlinks is False;return self.world.nodes[path][0]
    def fstat(self,fd):
        result=self.world.fds[fd]['meta'];self.world.hook('fstat',self.role,fd);return result
    def pread(self,fd,amount,offset):
        path=self.world.fds[fd]['path'];self.world.log.append(('pread',self.role,path,amount,offset))
        self.world.hook('pread',self.role,(path,amount,offset))
        if self.world.no_eof:return b'x'*amount
        raw=self.world.nodes[path][1];limit=min(amount,self.world.chunk) if self.world.chunk else amount
        return raw[offset:offset+limit]
    def close(self,fd):
        self.world.close_attempts.append(fd)
        if self.world.fail_close==fd:raise OSError('public RAM close uncertainty')
        del self.world.fds[fd]
    def fcntl(self,fd,command):
        assert command in (1,3);return 1 if command==1 else self.world.fds[fd]['flags']


class World:
    def __init__(self):
        self.nodes={};self.fds={};self.next_fd=200;self.queues={'execute':[],'capture':[]}
        self.sent=[];self.recv_returns=[];self.log=[];self.close_attempts=[];self.hooks={}
        self.now=0.0;self.clock_step=0.001;self.chunk=None;self.no_eof=False
        self.fail_close=None;self.open_alias=None;self.send_count=None;self.receive_transform=None
        self.driven=False;self.capture_join=None;self.capture_permit=None;self.uname=Uname()
        self.actors={role:Actor(self,role,pid) for role,pid in (('execute',101),('capture',102))}
        for path in ('/','/proc','/proc/sys','/proc/sys/kernel','/proc/sys/kernel/random'):
            self.node(path,b'',True)
        self.node('/proc/sys/kernel/random/boot_id',(BOOT+'\n').encode())
        for pid,name,ppid,start in ((42,'bash',7,100),(101,'python3.12',42,1001),(102,'python3.12',42,1002)):
            self.node('/proc/'+str(pid),b'',True);self.birth(pid,name,ppid,start)
        self.endpoints={}
        for role,fd in (('execute',1001),('capture',1002)):
            meta=Meta((3,fd,stat.S_IFSOCK|0o600,0,0,1,0,1,1))
            self.fds[fd]=dict(path=None,meta=meta,flags=2050);self.endpoints[role]=Endpoint(self,role,fd)
    def hook(self,name,role,value):
        action=self.hooks.get(name)
        if action:action(role,value)
    def node(self,path,raw,directory=False):
        if path in self.nodes:meta=self.nodes[path][0]
        else:meta=Meta((1,10+len(self.nodes),(stat.S_IFDIR|0o555) if directory else (stat.S_IFREG|0o444),0,0,2 if directory else 1,0,1,1))
        self.nodes[path]=(meta,raw)
    def birth(self,pid,name,ppid,start):
        values=['S']+['0']*49;values[1]=str(ppid);values[19]=str(start)
        self.node('/proc/'+str(pid)+'/stat',(str(pid)+' ('+name+') '+' '.join(values)+'\n').encode())
        self.node('/proc/'+str(pid)+'/status',('Name:\t'+name+'\nPid:\t'+str(pid)+'\nTgid:\t'+str(pid)+
            '\nPPid:\t'+str(ppid)+'\nTracerPid:\t0\nUid:\t0 0 0 0\nGid:\t0 0 0 0\nState:\tS (sleeping)\n').encode())
    def rights(self,count):
        fds=list(range(5000,5000+count))
        for fd in fds:self.fds[fd]=dict(path=None,meta=Meta((5,fd,stat.S_IFREG|0o400,0,0,1,0,1,1)),flags=133120)
        return fds


class Fixture:
    serial=0
    def __init__(self):
        Fixture.serial+=1;self.prefix='startup_join_controls_'+str(Fixture.serial);self.loaded=[]
        self.P=self.module('parent',ROOT/'scripts/installer_parent.py',PARENT_PIN)
        self.modules={role:self.module(role,ROOT/'deploy/installer/company_startup_join.py',SOURCE_PIN) for role in ('execute','capture')}
        self.world=World();self.subjects={role:object() for role in self.modules}
        self.binding=dict(zip(('requestSha256','releaseSha256','deliveryIdentitySha256','planSha256','actionSha256','inputSha256','sourceSha256'),
                              (str(n)*64 for n in range(1,8))))
        self.binding.update(stage='company-platform-store',session='s-Abc123Def456')
        self.parent=dict(pid=42,start=100,bootId=BOOT);self.joins={}
    def module(self,label,path,pin):
        result=load(self.prefix+'_'+label,path,pin);self.loaded.append(result);return result
    def args(self,role):
        actor=self.world.actors[role];endpoint=self.world.endpoints[role]
        return dict(endpoint=endpoint,endpoint_identity=dict(fd=endpoint.fileno(),identity={key:getattr(self.world.fds[endpoint.fileno()]['meta'],key) for key in FIELDS}),
            expected_parent=dict(self.parent),expected_binding=dict(self.binding),expected_peer_pid=102 if role=='execute' else None,
            parent_module=self.P,os_module=actor.os,sys_module=actor.sys,socket_module=actor.socket,
            raw_constants_module=actor.raw,fcntl_module=actor.fc,select_module=actor.select,clock=actor.clock,seconds=15)
    def prepare(self,role='execute',**changes):
        args=self.args(role);args.update(changes)
        result=self.modules[role].prepare_startup_join(role,self.subjects[role],**args);self.joins[role]=result
        if role=='capture':self.world.capture_join=result
        return result
    def exchange(self):
        self.prepare('capture');execute=self.prepare('execute');return execute.join(),self.world.capture_permit
    def record(self,role='execute'):return self.modules[role].UNRELEASED[0][0]
    def dispose(self):
        # Only dedicated Python registrations are fixture-owned. Failed native-
        # shaped references are never closed or treated as known by this cleanup.
        for module in self.loaded:
            if sys.modules.get(module.__name__) is module:del sys.modules[module.__name__]


class Controls(unittest.TestCase):
    def fixture(self):
        value=Fixture();self.addCleanup(value.dispose);return value
    def refused(self,f,action):
        with self.assertRaises(f.modules['execute'].StartupUnavailable):action()
    def test_execute_role_uses_actual_capture_reply_and_closes_its_16_handles(self):
        f=self.fixture();execute,capture=f.exchange();data=execute.data
        self.assertEqual(data['role'],'execute');self.assertEqual((data['ownPid'],data['peerPid']),(101,102))
        self.assertEqual([role for role,raw in f.world.sent],['execute','capture'])
        self.assertTrue(f.world.sent[0][1].startswith(b'CSJ1|'));self.assertTrue(f.world.sent[1][1].startswith(b'CSJP1|'))
        self.assertFalse(f.world.fds);self.assertEqual(len(f.world.close_attempts),32)
        self.assertFalse(data['initialOriginsQualified'] or data['executionEvidenceIssued'] or data['stageAcknowledged'])
    def test_capture_role_private_permit_matches_actual_sender_birth_and_subject(self):
        f=self.fixture();execute,capture=f.exchange();module=f.modules['capture'];data=capture.data
        self.assertEqual((data['role'],data['ownPid'],data['peerPid'],data['peerStart']),('capture',102,101,1001))
        self.assertIs(module.require_startup_permit(capture,f.subjects['capture'],role='capture'),capture)
        self.assertFalse(hasattr(module,'HeldExecutionEvidence') or hasattr(module,'require_known_execution') or hasattr(capture,'record_bytes'))
    def test_wrong_subject_denial_is_private_sticky_after_public_clear(self):
        f=self.fixture();permit,_=f.exchange();module=f.modules['execute']
        self.refused(f,lambda:module.require_startup_permit(permit,object(),role='execute'))
        before=(len(f.world.log),len(module.UNRELEASED));module.UNRELEASED.clear()
        self.refused(f,lambda:module.require_startup_permit(permit,f.subjects['execute'],role='execute'))
        self.assertEqual(len(f.world.log),before[0]);self.assertFalse(module.UNRELEASED)
    def test_wrong_role_and_public_permit_clone_cannot_issue_or_reopen(self):
        f=self.fixture();permit,_=f.exchange();module=f.modules['execute']
        self.refused(f,lambda:module.require_startup_permit(module.RolePermit(),f.subjects['execute'],role='execute'))
        self.refused(f,lambda:module.require_startup_permit(permit,f.subjects['execute'],role='capture'))
    def test_missing_credentials_refuses_actual_reply(self):
        f=self.fixture();f.world.receive_transform=lambda role,row:(row[0],[],row[2],row[3]) if role=='execute' else row
        self.refused(f,f.exchange);self.assertTrue(f.record()['failed']);self.assertFalse(f.world.fds)
    def test_foreign_uid_credentials_refuse_actual_reply(self):
        f=self.fixture();f.world.receive_transform=lambda role,row:(row[0],[(1,2,struct.pack('=iii',102,1,0))],row[2],row[3]) if role=='execute' else row
        self.refused(f,f.exchange);self.assertEqual(len(f.world.recv_returns),2)
    def test_duplicate_credentials_refuse_instead_of_selecting_one(self):
        f=self.fixture();f.world.receive_transform=lambda role,row:(row[0],row[1]*2,row[2],row[3]) if role=='execute' else row
        self.refused(f,f.exchange);self.assertTrue(f.record()['failed'])
    def test_parent_birth_drift_after_reply_prevents_permit(self):
        f=self.fixture()
        def change(role,row):
            if role=='execute':f.world.birth(42,'bash',7,101)
        f.world.hooks['recv']=change;self.refused(f,f.exchange)
    def test_peer_birth_drift_after_reply_mismatches_actual_frame(self):
        f=self.fixture()
        def change(role,row):
            if role=='execute':f.world.birth(102,'python3.12',42,1003)
        f.world.hooks['recv']=change;self.refused(f,f.exchange)
    def test_peer_parent_change_is_refused_by_original_status_parser(self):
        f=self.fixture()
        def change(role,row):
            if role=='execute':f.world.birth(102,'python3.12',99,1002)
        f.world.hooks['recv']=change;self.refused(f,f.exchange)
    def test_disclosed_right_is_registered_and_once_closed_before_refusal(self):
        f=self.fixture();rights=f.world.rights(1)
        f.world.receive_transform=lambda role,row:(row[0],[(1,1,struct.pack('=i',rights[0]))],row[2],row[3]) if role=='execute' else row
        self.refused(f,f.exchange);record=f.record()
        self.assertTrue(any(row['role']=='received-right' and row['fd']==rights[0] for row in record['rows']))
        self.assertEqual(f.world.close_attempts.count(rights[0]),1)
    def test_excess_128_rights_keep_rows_bounded_and_excess_unknown(self):
        f=self.fixture();rights=f.world.rights(128)
        ancillary=[(1,1,struct.pack('=16i',*rights[offset:offset+16])) for offset in range(0,128,16)]
        f.world.receive_transform=lambda role,row:(row[0],ancillary,row[2],row[3]) if role=='execute' else row
        self.refused(f,f.exchange);record=f.record()
        self.assertEqual(len(record['rows']),32);self.assertTrue(record['unknown'] and record['excess_acquisitions'])
        excess=[row[0] for row in record['excess_acquisitions']]
        self.assertTrue(all(fd in f.world.fds and fd not in f.world.close_attempts for fd in excess))
        self.assertIs(record['raw_recv'],f.world.recv_returns[-1][1])
    def test_right_alias_marks_original_endpoint_ambiguous_without_close(self):
        f=self.fixture();fd=f.world.endpoints['execute'].fileno()
        f.world.receive_transform=lambda role,row:(row[0],[(1,1,struct.pack('=i',fd))],row[2],row[3]) if role=='execute' else row
        self.refused(f,f.exchange);record=f.record();aliases=[row for row in record['rows'] if row['fd']==fd]
        self.assertEqual(len(aliases),2);self.assertTrue(all(row['ambiguous'] for row in aliases))
        self.assertNotIn(fd,f.world.close_attempts)
    def test_truncated_right_return_stays_unknown_even_if_disclosed_fd_closes(self):
        f=self.fixture();fd=f.world.rights(1)[0]
        f.world.receive_transform=lambda role,row:(row[0],[(1,1,struct.pack('=i',fd))],8,row[3]) if role=='execute' else row
        self.refused(f,f.exchange);self.assertTrue(f.record()['unknown']);self.assertEqual(f.world.close_attempts.count(fd),1)
    def test_postreturn_module_drift_keeps_raw_and_registered_right_before_guard(self):
        f=self.fixture();fd=f.world.rights(1)[0]
        f.world.receive_transform=lambda role,row:(row[0],[(1,1,struct.pack('=i',fd))],row[2],row[3]) if role=='execute' else row
        def drift(role,row):
            if role=='execute':f.world.actors[role].os.extra=object()
        f.world.hooks['recv']=drift;self.refused(f,f.exchange);record=f.record()
        self.assertIs(record['raw_recv'],f.world.recv_returns[-1][1])
        self.assertTrue(any(row['role']=='received-right' and row['fd']==fd for row in record['rows']))
        self.assertTrue(record['failed'] and record['unknown'])
    def test_partial_send_retains_count_and_never_retries(self):
        f=self.fixture();f.prepare('capture');join=f.prepare('execute');f.world.send_count=1
        self.refused(f,join.join);record=f.record();self.assertEqual(record['send_return'],1)
        before=len(f.world.sent);f.modules['execute'].UNRELEASED.clear();self.refused(f,join.join)
        self.assertEqual(len(f.world.sent),before)
    def test_unknown_socket_close_is_once_only_and_no_permit_after_public_clear(self):
        f=self.fixture();f.world.fail_close=1001;self.refused(f,f.exchange);record=f.record()
        self.assertTrue(record['unknown']);self.assertEqual(f.world.close_attempts.count(1001),1)
        f.modules['execute'].UNRELEASED.clear();self.refused(f,f.joins['execute'].join)
        self.assertEqual(f.world.close_attempts.count(1001),1)
    def test_fragmented_proc_progress_uses_actual_eof_and_original_parsers(self):
        f=self.fixture();f.world.chunk=32;execute,capture=f.exchange()
        self.assertEqual(execute.data['ownStart'],1001);self.assertFalse(f.world.fds)
        self.assertTrue(any(item[0]=='pread' and item[4]>0 for item in f.world.log))
    def test_operation_budget_exhaustion_still_uses_bounded_disposal(self):
        f=self.fixture();f.world.chunk=1;join=f.prepare('execute');self.refused(f,join.join);record=f.record()
        self.assertEqual(record['calls'],432);self.assertLessEqual(record['cleanup_calls'],80)
        self.assertTrue(all(row['closed'] for row in record['rows']));self.assertFalse(record['unknown'])
    def test_clock_expiry_consumes_attempt_and_blocks_retry(self):
        f=self.fixture();f.world.clock_step=20;join=f.prepare('execute');self.refused(f,join.join)
        before=len(f.world.log);self.refused(f,join.join);self.assertEqual(len(f.world.log),before)
    def test_default_main_and_unknown_join_clone_have_no_station_callbacks(self):
        f=self.fixture();before=list(f.world.log);module=f.modules['execute']
        self.refused(f,module.main);self.refused(f,module.StartupJoin().join);self.assertEqual(f.world.log,before)
    def test_invalid_baseline_protected_fd_refuses_before_ownership_or_callbacks(self):
        f=self.fixture();before=list(f.world.log)
        self.refused(f,lambda:f.prepare('execute',protected_fds=(0,)))
        self.assertEqual(f.world.log,before);self.assertFalse(f.modules['execute'].UNRELEASED)


if __name__=='__main__':unittest.main(verbosity=2)
