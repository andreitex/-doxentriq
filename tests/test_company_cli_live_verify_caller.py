"""Original CLI/R/P/receiver/status/builder; explicit RAM kernel and PS only.

The synthetic ParentSystem launch source is captured before delivery admission.
No imported prior fixture tree, operational stage, socket or process is run.
"""
import ast
import collections
import contextlib
import errno
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys
from types import MappingProxyType, ModuleType
import unittest

ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'deploy/installer'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
class Meta:
    __slots__=FIELDS
    def __init__(self,*values):
        assert len(values)==len(FIELDS)
        for field,value in zip(FIELDS,values):object.__setattr__(self,field,value)
    def __iter__(self):return iter(tuple(object.__getattribute__(self,field) for field in FIELDS))
    def _replace(self,**changes):return Meta(*(changes.get(field,object.__getattribute__(self,field)) for field in FIELDS))

class Uname:
    __slots__=('sysname','nodename','release','version','machine')
    def __init__(self,*values):
        assert len(values)==len(self.__slots__)
        for field,value in zip(self.__slots__,values):object.__setattr__(self,field,value)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()+b'\n'

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def load(name,path):
    module=ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(path.read_bytes(),str(path),'exec'),vars(module));return module

def contains(value,target,seen=None):
    if value is target:return True
    if seen is None:seen=set()
    if id(value) in seen:return False
    seen.add(id(value))
    if type(value) in (dict,MappingProxyType):return any(contains(item,target,seen) for item in value.values())
    if type(value) in (list,tuple):return any(contains(item,target,seen) for item in value)
    return False

def data_bytes(value):
    if type(value) is bytes:return [value]
    if type(value) in (dict,MappingProxyType):return [raw for item in value.values() for raw in data_bytes(item)]
    if type(value) in (tuple,list):return [raw for item in value for raw in data_bytes(item)]
    assert type(value) in (str,int,bool,type(None))
    return []

def synthetic_parent_source():
    """Derive only the explicit RAM PS model, never import its old tests."""
    tree=ast.parse((ROOT/'scripts/test-installer-parent.py').read_bytes())
    helpers=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('shell','encoded')]
    model=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='FakeSystem')
    model.name='ParentSystem'
    class References(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in ('P','ARGS'):
                return ast.copy_location(ast.Attribute(ast.Name('self',ast.Load()),'_p' if node.id=='P' else 'arguments',node.ctx),node)
            return node
    model=References().visit(model)
    init=next(node for node in model.body if isinstance(node,ast.FunctionDef) and node.name=='__init__')
    init.args=ast.parse('def init(self,parent_module,arguments,backend_module):pass').body[0].args
    init.body=ast.parse('self._p=parent_module\nself._bk=backend_module\nself.arguments=arguments\nself.unknown=[]\nself.release_count=0\nself.fail_open=False\nself._dependencies=[(self,"_p",parent_module,None),(self,"_bk",backend_module,None)]\nself._modules=[]\nself._classes=[]\nself._calls={}\nself._flags={}').body+init.body
    opening=next(node for node in model.body if isinstance(node,ast.FunctionDef) and node.name=='open')
    opening.body[-1:-1]=ast.parse("if self.fail_open:\n self.unknown.append(self.next_fd)\n raise MemoryError('injected unreturned parent FD')").body
    model.body=[node for node in model.body if not (isinstance(node,ast.FunctionDef) and node.name=='close')]
    model.body+=ast.parse("""def close(self,fd):
 self.closed.append(fd)
 if self.close_error==fd:
  self.unknown.append(fd)
  raise OSError('injected parent close unknown')
 self.descriptors.pop(fd)
def require_released(self):
 self.release_count+=1
 for value,key,expected,stamp in self._dependencies:getattr(value,key)
 getattr(self._bk,'LinuxAMD64Getdents64')
 if self.descriptors or self.unknown:raise ValueError('injected parent ownership remains')
 return self
""").body
    module=ast.Module(body=ast.parse('import stat').body+helpers+[model],type_ignores=[])
    return (ast.unparse(ast.fix_missing_locations(module))+'\n').encode()


class Fixture:
    counter=0
    def __init__(self,stage='company-platform-store'):
        Fixture.counter+=1;self.prefix='live_candidate_fixture_'+str(Fixture.counter)
        self.events=[];self.closed=[];self.hook=None;self.time=0.;self.restores=[]
        self.records={};self.paths={};self.file_bodies={};self.socket_close_error=False
        self.open_unreturned=False;self.read_error=False;self.close_error_path=None
        self.open_alias=None
        self.reuse_endpoint_fd=False;self.alias_existing=False
        self.C=load(self.prefix+'_cli',ROOT/'deploy/installer/company_full_cli.py')
        self.D=load(self.prefix+'_delivery',ROOT/'deploy/installer/build-full-cli-package.py')
        self.PB=load(self.prefix+'_package',ROOT/'deploy/installer/build-full-package.py')
        self.M=load(self.prefix+'_caller',HERE/'company_cli_live_verify_caller.py')
        self.E=load(self.prefix+'_receiver',ROOT/'deploy/installer/company_live_completion_receiver.py')
        self.S=load(self.prefix+'_status',ROOT/'deploy/installer/company_bash_execution_status.py')
        self.B=load(self.prefix+'_builder',ROOT/'deploy/installer/company_cli_verify_invocation.py')
        package={path:(ROOT/path).read_bytes() for path in self.PB.PACKAGE_PATHS}
        operational={path:(ROOT/path).read_bytes() for path in self.D.OPERATIONAL_PATHS}
        launch={path:(ROOT/path).read_bytes() for path in self.D.LAUNCH_PATHS}
        launch[self.C.PARENT_SYSTEM]=synthetic_parent_source()
        package_pins={path:pin(raw) for path,raw in package.items()}
        launch_pins={path:pin(raw) for path,raw in launch.items()}
        catalog={path:dict(**pin(raw),gitMode='100644') for path,raw in operational.items()}
        values=dict(operational,**package,**launch)
        def reader(path,maximum):return values[path.relative_to(ROOT).as_posix()]
        fingerprint='a'*64
        full=self.PB.assemble(ROOT,fingerprint,package_pins=package_pins,operational_catalog=catalog,reader=reader)
        delivery=self.D.assemble(ROOT,launch_pins=launch_pins,package_pins=package_pins,
            operational_catalog=catalog,fingerprint=fingerprint,full_package_raw=full,full_package_pin=pin(full),reader=reader)
        self.cli_cm=self.C.authenticated_cli(delivery,delivery_module=self.D,delivery_pin=pin(delivery),
            launch_pins=launch_pins,package_pins=package_pins,operational_catalog=catalog,
            fingerprint=fingerprint,full_package_pin=pin(full),bootstrap_records={path:package[path] for path in self.C.BOOTSTRAP_PATHS},
            bootstrap_pins={path:package_pins[path] for path in self.C.BOOTSTRAP_PATHS},running_cli_raw=launch[self.C.CLI])
        self.cli=self.cli_cm.__enter__();self.delivery=delivery
        self.R=self.cli._modules[self.C.REQUEST];origins=self.cli.original_modules
        self.P=origins['parent'];self.BK=origins['backend']
        self.PS=self.cli._modules[self.C.PARENT_SYSTEM]
        self.request=dict(schemaVersion=1,mode='full-installation',operationId='1'*32,releaseSha256='a'*64,
            bundleRoot='/opt/autosoft-company/incoming/bundle',sourceRoot='/opt/autosoft-company/incoming/source',
            keyPath='/opt/autosoft-company/bootstrap/company.pem',dataDir='/srv/autosoft',backingFile='/srv/backing.luks',
            capacityGiB=128,runscVersion='20261005.0',runscSha512='c'*128)
        self.request_raw=canonical(self.request);request_hash=pin(self.request_raw)['sha256']
        operation='1'*32 if stage=='company-platform-store' else '2'*32
        action='e'*64
        self.plan=dict(schemaVersion=1,scope='RETENTION_STAGE_PLAN_ONLY',stage=stage,
            installationRequestSha256=request_hash,operationId=operation,storeOperationId='1'*32,
            stageRequest={'fixture':'DATA_ONLY'},stageRequestSha256=pin(canonical({'fixture':'DATA_ONLY'}))['sha256'],actionSha256=action)
        self.plan_raw=canonical(self.plan)
        self.invocation=dict(schemaVersion=1,scope='FULL_RETENTION_CLI_INVOCATION_ONLY',command='execute-stage',stage=stage,
            requestSha256=request_hash,releaseSha256='a'*64,operationId=operation,storeOperationId='1'*32,
            planSha256=pin(self.plan_raw)['sha256'],outcomeSha256=None,
            parent=['42','11','12','s-Abc123Def456',request_hash,stage,action])
        self.invocation_raw=canonical(self.invocation)
        parent_arguments=self.P.ParentInput.from_argv(self.invocation['parent'])
        self.system=self.PS.ParentSystem(self.P,parent_arguments,self.BK)
        self.system_state=vars(self.system)
        self.binding=dict(requestSha256=request_hash,releaseSha256='a'*64,deliverySha256=pin(delivery)['sha256'],
            planSha256=pin(self.plan_raw)['sha256'],actionSha256=action,
            inputSha256=pin(self.request_raw+self.invocation_raw+self.plan_raw)['sha256'],stage=stage,
            session=parent_arguments.session,parentPid=42,childPid=74,parentStart=self.system.start,childStart=123457,
            bootId=self.system.boot)
        operation_result={'scope':'PUBLIC_SYNTHETIC_RECORD_DATA_ONLY','artifact':'fixture'}
        self.outcome=pin(canonical(operation_result))['sha256']
        record_binding={key:self.invocation[key] for key in ('stage','requestSha256','releaseSha256','operationId','storeOperationId','planSha256')}
        record_binding.update(session=parent_arguments.session,actionSha256=action)
        self.record_raw=canonical(dict(schemaVersion=1,scope='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY',command='execute-stage',
            deliveryIdentitySha256=self.cli._identity,binding=record_binding,planBase64=None,
            result=dict(operationResult=operation_result,operationOutcomeSha256=self.outcome,
                stagePlanSha256=self.invocation['planSha256'],ownedResourcesKnownReleased=True,stageAcknowledged=False,nativeAuthorized=False),
            outcomeSha256=self.outcome,stageAcknowledged=False,fullInstallationCompleted=False,nativeQualified=False))
        self.stderr=b'public diagnostic\0\xff\n';self.stdout=self.record_raw
        self.frame=self.S.encode_execution_status(self.binding,execute_invocation_raw=self.invocation_raw,
            completed_record_raw=self.record_raw,expected_delivery_identity_sha256=self.cli._identity,
            stdout=self.stdout,stderr=self.stderr,exit_code=0)
        self.stage_path='/opt/autosoft-company/evidence/'+operation+'/'+stage
        self.record_path=self.stage_path+'/executed.json'
        for index,path in enumerate(('/', '/opt','/opt/autosoft-company','/opt/autosoft-company/evidence',
                                     '/opt/autosoft-company/evidence/'+operation,self.stage_path,'/srv','/srv/autosoft')):
            self.paths[path]=Meta(2049,10000+index,0o40700 if path==self.stage_path else 0o40755,0,0,2,0,1,2)
        self.paths[self.record_path]=Meta(2049,11000,0o100400,0,0,1,len(self.record_raw),1,2)
        self.file_bodies[self.record_path]=self.record_raw
        self.records[20]=('socket',Meta(9,20000,0o140777,0,0,1,0,0,0),2050)
        self.messages=[self.positive(self.frame[offset:offset+256]) for offset in range(0,len(self.frame),256)]
        self.messages.append((b'',[(1,2,struct.pack('=iii',0,0,0))],0,None))
        self.os=ModuleType(self.prefix+'_os');self.os.name='posix';self.os.stat_result=Meta;self.os.uname_result=Uname
        for name in ('open','stat','fstat','pread','close','uname'):setattr(self.os,name,getattr(self,name))
        for name in ('getuid','getgid','geteuid','getegid'):setattr(self.os,name,lambda:0)
        self.os.supports_dir_fd={self.os.open,self.os.stat};self.os.supports_follow_symlinks={self.os.stat}
        for name,value in dict(O_RDONLY=0,O_DIRECTORY=65536,O_NOFOLLOW=131072,O_CLOEXEC=524288,O_NONBLOCK=2048).items():setattr(self.os,name,value)
        self.sy=ModuleType(self.prefix+'_sys');self.sy.platform='linux'
        self.fc=ModuleType(self.prefix+'_fcntl');self.fc.fcntl=self.fcntl;self.fc.F_GETFD=1;self.fc.F_GETFL=3
        self.se=ModuleType(self.prefix+'_select');self.se.poll=self.poll
        for name,value in dict(POLLIN=1,POLLHUP=16,POLLERR=8,POLLNVAL=32).items():setattr(self.se,name,value)
        self.sock=ModuleType(self.prefix+'_socket');self.raw=ModuleType(self.prefix+'_raw_socket')
        constants=dict(AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PASSCRED=16,SCM_CREDENTIALS=2,SCM_RIGHTS=1,MSG_CTRUNC=8,MSG_TRUNC=32,MSG_CMSG_CLOEXEC=1073741824)
        vars(self.sock).update(constants);vars(self.raw).update(constants)
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
            def getsockopt(self,level,option):fixture.event('passcred');return 1
            def recvmsg(self,size,ancillary,flags):
                fixture.event('recvmsg',size)
                value=fixture.messages.pop(0)
                if isinstance(value,BaseException):raise value
                return value
            def close(self):
                fixture.event('socket-close',self._fd)
                if fixture.socket_close_error:raise OSError(errno.EIO,'injected socket close unknown')
                fixture.records.pop(self._fd);fixture.closed.append(self._fd);self._fd=-1;self._closed=True
        Socket.__module__=self.sock.__name__;self.sock.socket=Socket;self.endpoint=Socket()
        self.endpoint_identity=dict(fd=20,identity=dict(zip(FIELDS,self.records[20][1])))
        self.force_record_flags=None

    def positive(self,raw,pid=42):return (raw,[(1,2,struct.pack('=iii',pid,0,0))],0,None)
    def event(self,name,*args):
        self.events.append((name,*args,bool(self.system_state['descriptors'])))
        if self.hook:self.hook(name,*args)
    def clock(self):self.time+=.001;return self.time
    def uname(self):self.event('uname');return Uname('Linux','fixture','6.12','public','x86_64')
    def resolved(self,name,parent=None):
        return name if parent is None else self.records[parent][0].rstrip('/')+'/'+name
    def stat(self,name,*,dir_fd=None,follow_symlinks=False):
        self.event('stat',name,dir_fd,follow_symlinks);return self.paths[self.resolved(name,dir_fd)]
    def fstat(self,fd):self.event('fstat',fd);return self.records[fd][1]
    def open(self,name,flags,*,dir_fd=None):
        path=self.resolved(name,dir_fd)
        existing=[fd for fd in self.records if fd!=20]
        if self.alias_existing and existing:
            alias=existing[0];self.event('open-alias',path,alias);return alias
        if self.open_alias is not None:
            alias=next(iter(self.system_state['descriptors'])) if self.open_alias=='parent' else self.open_alias
            self.event('open-alias',path,alias);return alias
        available=([20] if self.reuse_endpoint_fd else [])+list(range(30,90))
        fd=next(number for number in available if number not in self.records)
        self.records[fd]=(path,self.paths[path],flags&~524288|32768)
        self.event('open',path,fd)
        if self.open_unreturned and path==self.record_path:raise MemoryError('injected unreturned record FD')
        return fd
    def pread(self,fd,size,offset):
        self.event('pread',fd,size,offset)
        if self.read_error:raise OSError(errno.EIO,'injected read unavailable')
        return self.file_bodies[self.records[fd][0]][offset:offset+size]
    def close(self,fd):
        self.event('file-close',fd)
        if self.records[fd][0]==self.close_error_path:raise OSError(errno.EIO,'injected file close unknown')
        self.records.pop(fd);self.closed.append(fd)
    def fcntl(self,fd,command):
        self.event('fcntl',fd,command)
        if command==1:return 1
        if fd!=20 and self.force_record_flags is not None:return self.force_record_flags
        return self.records[fd][2]
    def poll(self):
        fixture=self
        class Poll:
            def __init__(self):self.fds=[]
            def register(self,fd,mask):self.fds.append(fd);fixture.event('poll-register',fd)
            def poll(self,timeout):fixture.event('poll');return [(20,17)]
        return Poll()
    def collect(self,**changes):
        def supplied_pin(raw):value=pin(raw);return value['sha256'],value['bytes']
        args=dict(request_raw=self.request_raw,request_pin=supplied_pin(self.request_raw),execute_invocation_raw=self.invocation_raw,
            invocation_pin=supplied_pin(self.invocation_raw),plan_raw=self.plan_raw,plan_pin=supplied_pin(self.plan_raw),
            expected_binding=self.binding,parent_system_module=self.PS,parent_system=self.system,
            endpoint=self.endpoint,endpoint_identity=self.endpoint_identity,os_module=self.os,sys_module=self.sy,
            socket_module=self.sock,raw_constants_module=self.raw,fcntl_module=self.fc,select_module=self.se,
            clock=self.clock,seconds=20,stdout=self.stdout,stderr=self.stderr)
        args.update(changes)
        return self.M.collect_completion_candidate(self.C,self.cli,self.E,self.S,self.B,**args)
    def dispose(self):
        for callback in reversed(self.restores):callback()
        # Explicit RAM-only fixture disposal, never a candidate retry/reset.
        self.records.clear();self.system.descriptors.clear();self.system.unknown.clear()
        try:self.cli_cm.__exit__(None,None,None)
        except BaseException:pass
        for name in tuple(sys.modules):
            if name.startswith(self.prefix):sys.modules.pop(name,None)


class Controls(unittest.TestCase):
    def fixture(self,stage='company-platform-store'):
        value=Fixture(stage);self.addCleanup(value.dispose);return value
    def refused(self,fixture,**changes):
        with self.assertRaises(fixture.M.CompletionCandidateUnavailable):fixture.collect(**changes)

    def test_original_cli_parent_receiver_record_and_builder_close_before_data(self):
        f=self.fixture();result=f.collect()
        self.assertIs(type(result),MappingProxyType)
        self.assertEqual(result['scope'],'LIVE_VERIFY_COMPLETION_CANDIDATE_DATA_ONLY')
        self.assertEqual(result['completedRecordRaw'],f.record_raw)
        self.assertEqual(result['completedRecordSha256'],pin(f.record_raw)['sha256'])
        self.assertEqual(result['recordPath'],f.record_path)
        self.assertEqual(result['expectedDevice'],2049)
        expected=canonical(dict(f.invocation,command='verify-stage',outcomeSha256=f.outcome))
        self.assertEqual(result['verificationData']['invocation'],expected)
        self.assertEqual(result['verificationData']['outcomeSha256'],f.outcome)
        self.assertEqual(result['receiverData']['raw'],f.frame)
        self.assertEqual(result['receiverData']['eofCredentials'],(0,0,0))
        self.assertEqual(result['parentCheck']['scope'],f.P.SCOPE)
        self.assertTrue(result['parentOwnScopeKnownReleased'] and result['readonlyRecordOwnScopeKnownReleased'])
        self.assertTrue(result['futureWorkerMustReacquire'] and result['originalCliBorrowed'])
        for key in ('uninterruptedParentHoldForFutureVerification','parentNativeQualified','completeCopygraphQualified',
                    'sourceClosureQualified','executionEvidenceIssued','verificationDispatched','stageAcknowledged'):
            self.assertIs(result[key],False)
        self.assertFalse(f.records or f.system.descriptors or f.system.unknown)
        self.assertGreaterEqual(f.system.release_count,2)
        self.assertTrue(f.cli._active)
        self.assertFalse(f.C._ATTEMPTS[id(f.cli)] or f.C._EFFECT_RETURNS[id(f.cli)])
        self.assertTrue(all(event[-1] for event in f.events if event[0] in ('recvmsg','open','pread','file-close')))
        with self.assertRaises(TypeError):result['stageAcknowledged']=True
        self.assertIn(expected,data_bytes(result))

    def test_source_record_preserves_source_operation_and_store_operation(self):
        f=self.fixture('company-source-materialize');result=f.collect()
        invocation=json.loads(result['verificationData']['invocation'])
        self.assertEqual(invocation['operationId'],'2'*32)
        self.assertEqual(invocation['storeOperationId'],'1'*32)
        self.assertEqual(invocation['parent'],f.invocation['parent'])
        self.assertEqual(result['recordPath'],f.record_path)
        self.assertFalse(result['verificationDispatched'] or result['stageAcknowledged'])

    def test_known_receiver_release_allows_new_endpoint_number_lifetime(self):
        f=self.fixture();f.reuse_endpoint_fd=True;result=f.collect()
        self.assertTrue(result['parentOwnScopeKnownReleased'] and result['readonlyRecordOwnScopeKnownReleased'])
        self.assertEqual(sum(event[:2]==('socket-close',20) for event in f.events),1)
        self.assertEqual(sum(event[:2]==('file-close',20) for event in f.events),1)
        self.assertTrue(any(event[0]=='open' and event[2]==20 for event in f.events))
        self.assertFalse(f.records or f.system.descriptors)
        f=self.fixture();f.reuse_endpoint_fd=True;f.socket_close_error=True;self.refused(f)
        self.assertIn(20,f.records)
        self.assertFalse(any(event[0]=='open' for event in f.events))

    def test_tampered_capture_and_nonzero_or_boolean_exit_deny_before_parent_io(self):
        for changes in ({'plan_raw':b'tampered'}, {'expected_exit_code':True},{'expected_exit_code':1}):
            with self.subTest(change=next(iter(changes))):
                f=self.fixture();self.refused(f,**changes)
                self.assertFalse(f.events or f.system.log or f.system.descriptors)

    def test_wrong_parent_birth_or_session_denies_before_receiver(self):
        for field,value in (('parentStart',123457),('session','s-Other1234567')):
            with self.subTest(field=field):
                f=self.fixture();binding=dict(f.binding);binding[field]=value
                self.refused(f,expected_binding=binding)
                self.assertFalse(any(event[0]=='recvmsg' for event in f.events))
                self.assertTrue(f.M.UNRELEASED)

    def test_wrong_live_writer_credentials_retain_original_parent_and_cli(self):
        f=self.fixture();f.messages=[f.positive(f.frame[:256],43)]
        self.refused(f)
        self.assertTrue(f.system.descriptors)
        self.assertTrue(contains(f.M.UNRELEASED,f.system) and contains(f.M.UNRELEASED,f.cli))
        self.assertFalse(f.C._ATTEMPTS[id(f.cli)] or f.C._EFFECT_RETURNS[id(f.cli)])

    def test_fresh_record_tamper_denies_and_closes_known_inputs(self):
        f=self.fixture();body=f.record_raw.replace(b'fixture',b'changed')
        f.file_bodies[f.record_path]=body;f.paths[f.record_path]=f.paths[f.record_path]._replace(st_size=len(body))
        self.refused(f)
        self.assertFalse(f.records or f.system.descriptors)
        self.assertFalse(f.C._ATTEMPTS[id(f.cli)])

    def test_record_mode_link_count_and_accepted_device_are_required(self):
        for change in ({'st_mode':0o100600},{'st_nlink':2},{'st_dev':2050}):
            with self.subTest(change=next(iter(change))):
                f=self.fixture();f.paths[f.record_path]=f.paths[f.record_path]._replace(**change)
                self.refused(f)
                self.assertFalse(f.records or f.system.descriptors)
                self.assertFalse(f.C._ATTEMPTS[id(f.cli)])

    def test_reread_cannot_replace_independently_supplied_stdout_or_stderr(self):
        for change in ({'stdout':b'unrelated captured stdout'},{'stderr':b'changed diagnostic'}):
            with self.subTest(change=next(iter(change))):
                f=self.fixture();self.refused(f,**change)
                self.assertFalse(f.records or f.system.descriptors)
                self.assertFalse(f.C._ATTEMPTS[id(f.cli)])

    def test_unreturned_record_open_retains_the_acquired_fd_and_parent(self):
        f=self.fixture();f.open_unreturned=True;self.refused(f)
        acquired=[fd for fd,(path,meta,flags) in f.records.items() if path==f.record_path]
        self.assertEqual(len(acquired),1)
        self.assertNotIn(acquired[0],f.closed)
        self.assertTrue(f.system.descriptors)
        self.assertTrue(contains(f.M.UNRELEASED,f.system))
        before=len(f.events);f.M.UNRELEASED.clear();self.refused(f)
        self.assertEqual(len(f.events),before)

    def test_record_close_uncertainty_keeps_outer_parent_without_second_close(self):
        f=self.fixture();f.close_error_path=f.record_path;self.refused(f)
        owned=[fd for fd,(path,meta,flags) in f.records.items() if path==f.record_path]
        self.assertEqual(len(owned),1)
        self.assertEqual(sum(event[:2]==('file-close',owned[0]) for event in f.events),1)
        self.assertTrue(f.system.descriptors and f.M.UNRELEASED)
        before=len(f.events);f.M.UNRELEASED.clear();self.refused(f)
        self.assertEqual(len(f.events),before)

    def test_returned_live_parent_alias_is_never_adopted_or_closed_as_record_io(self):
        f=self.fixture();f.open_alias='parent';self.refused(f)
        aliased=next(event[2] for event in f.events if event[0]=='open-alias')
        self.assertIn(aliased,f.system_state['descriptors'])
        self.assertNotIn(aliased,f.system.closed)
        self.assertFalse(any(event[:2]==('file-close',aliased) for event in f.events))
        self.assertTrue(contains(f.M.UNRELEASED,f.system))

    def test_duplicate_live_record_fd_marks_both_references_uncertain(self):
        f=self.fixture();f.alias_existing=True;self.refused(f)
        duplicate=next(event[2] for event in f.events if event[0]=='open-alias')
        self.assertIn(duplicate,f.records)
        self.assertFalse(any(event[:2]==('file-close',duplicate) for event in f.events))
        self.assertTrue(f.system.descriptors and f.M.UNRELEASED)

    def test_data_directory_ancestor_and_held_path_changes_are_refused(self):
        for change in ('symlink','ancestor-replaced','held-data-replaced'):
            with self.subTest(change=change):
                f=self.fixture()
                if change=='symlink':f.paths['/srv']=f.paths['/srv']._replace(st_mode=0o120777)
                def mutate(name,*args):
                    path='/srv' if change=='ancestor-replaced' else '/srv/autosoft'
                    if (change=='ancestor-replaced' and name=='open' and args[0]==path) or (change=='held-data-replaced' and name=='pread'):
                        f.paths[path]=f.paths[path]._replace(st_ino=f.paths[path].st_ino+1)
                if change!='symlink':f.hook=mutate
                self.refused(f)
                self.assertFalse(f.C._ATTEMPTS[id(f.cli)] or f.C._EFFECT_RETURNS[id(f.cli)])

    def test_original_read_error_never_produces_verification_or_ack(self):
        f=self.fixture();f.read_error=True;self.refused(f)
        self.assertTrue(f.M.UNRELEASED)
        self.assertFalse(f.C._ATTEMPTS[id(f.cli)] or f.C._EFFECT_RETURNS[id(f.cli)])
        before=len(f.events);f.M.UNRELEASED.clear();self.refused(f)
        self.assertEqual(len(f.events),before)

    def test_foreign_cli_instance_getter_denies_without_dispatch(self):
        f=self.fixture();calls=[];original=type(f.cli)
        class Foreign:
            @property
            def original_modules(self):calls.append('getter');return {}
        f.cli.__class__=Foreign;f.restores.append(lambda:setattr(f.cli,'__class__',original))
        self.refused(f)
        self.assertFalse(calls or f.events or f.system.log)

    def test_endpoint_instance_drift_never_runs_foreign_close_or_getters(self):
        f=self.fixture();calls=[];original=f.sock.socket
        class Foreign:
            __slots__=('_fd','_io_refs','_closed')
            def fileno(self):calls.append('fileno');return self._fd
            def close(self):calls.append('close')
        def mutate(name,*args):
            if name=='fstat' and args[0]==20:f.endpoint.__class__=Foreign
        f.hook=mutate;f.restores.append(lambda:setattr(f.endpoint,'__class__',original))
        self.refused(f)
        self.assertFalse(calls)
        self.assertTrue(f.system.descriptors)
        self.assertTrue(contains(f.M.UNRELEASED,f.endpoint))

    def test_changed_original_parent_close_is_not_called_on_unwind(self):
        f=self.fixture();calls=[];kind=f.P.HeldParent;original=kind.close
        def foreign(value):calls.append('close');raise AssertionError('foreign parent close')
        def mutate(name,*args):
            if name=='pread':kind.close=foreign
        f.hook=mutate;f.restores.append(lambda:setattr(kind,'close',original))
        self.refused(f)
        self.assertFalse(calls)
        self.assertTrue(f.system.descriptors)
        self.assertTrue(contains(f.M.UNRELEASED,f.system))

    def test_changed_parent_system_instance_never_runs_foreign_attribute_dispatch(self):
        f=self.fixture();calls=[];original=type(f.system)
        class Foreign:
            def __getattribute__(self,name):calls.append(name);raise AssertionError('foreign system getter')
        def mutate(name,*args):
            if name=='pread':f.system.__class__=Foreign
        f.hook=mutate;f.restores.append(lambda:setattr(f.system,'__class__',original))
        self.refused(f)
        self.assertFalse(calls)
        self.assertTrue(contains(f.M.UNRELEASED,f.system))

    def test_missing_record_flags_refuse_after_known_original_receiver_release(self):
        f=self.fixture();f.force_record_flags=0;self.refused(f)
        self.assertTrue(f.endpoint._closed)
        self.assertFalse(f.records or f.system.descriptors)
        self.assertFalse(f.C._ATTEMPTS[id(f.cli)])

    def test_in_place_parent_dependencies_cannot_introduce_foreign_getters(self):
        for mutation in ('append','replace'):
            with self.subTest(mutation=mutation):
                f=self.fixture();calls=[]
                class Foreign:
                    def __getattribute__(self,name):calls.append(name);return True
                row=(Foreign(),'probe',True,None)
                def mutate(name,*args):
                    if name=='pread':
                        values=f.system_state['_dependencies']
                        if mutation=='append':values.append(row)
                        else:values[0]=row
                f.hook=mutate;self.refused(f)
                self.assertFalse(calls)
                self.assertTrue(contains(f.M.UNRELEASED,f.system))

    def test_changed_context_metaclass_is_refused_before_parent_construction(self):
        f=self.fixture();calls=[];kind=type(contextlib._GeneratorContextManager)
        owned='__call__' in vars(kind);original=vars(kind).get('__call__')
        def foreign(*args,**kwargs):calls.append('metaclass-call');raise AssertionError('foreign context construction')
        def restore():
            if owned:setattr(kind,'__call__',original)
            elif '__call__' in vars(kind):delattr(kind,'__call__')
        def mutate(name,*args):
            if name=='uname':kind.__call__=foreign
        f.hook=mutate;f.restores.append(restore)
        refused=False
        try:f.collect()
        except f.M.CompletionCandidateUnavailable:refused=True
        finally:restore()  # unittest itself constructs context managers on exit.
        self.assertTrue(refused)
        self.assertFalse(calls or f.system_state['descriptors'])
        self.assertFalse(any(event[0]=='recvmsg' for event in f.events))

    def test_parent_system_origins_match_original_cli_before_release_callback(self):
        for name in ('_p','_bk'):
            with self.subTest(origin=name):
                f=self.fixture();calls=[]
                class Foreign:
                    def __getattribute__(self,key):calls.append(key);raise AssertionError('foreign PS origin')
                f.system_state[name]=Foreign();self.refused(f)
                self.assertFalse(calls or f.system.log or f.system_state['descriptors'])
                self.assertEqual(f.system_state['release_count'],0)
                self.assertFalse(any(event[0]=='recvmsg' for event in f.events))

    def test_successful_candidate_is_one_use_without_native_reacquisition(self):
        f=self.fixture();f.collect();before=len(f.events);before_parent=len(f.system.log)
        f.M.UNRELEASED.clear();self.refused(f)
        self.assertEqual(len(f.events),before)
        self.assertEqual(len(f.system.log),before_parent)


if __name__=='__main__':unittest.main(verbosity=2)
