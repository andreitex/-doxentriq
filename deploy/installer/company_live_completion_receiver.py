"""One transferred credentialed stream capture; DATA only, main unconfigured.

Company source/syscall/socket/context origin, sender birth, source/parent/input
expectations, privilege policy and complete endpoint-copy/send chronology are
independently authenticated caller obligations. Bytes/credentials never issue
HeldExecutionEvidence or installer acknowledgement here. No socket is created.
"""
import errno,hashlib,math,stat,struct
from types import BuiltinFunctionType,FunctionType,GetSetDescriptorType,MappingProxyType,MemberDescriptorType,MethodDescriptorType,MethodType,ModuleType

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BINDING=('requestSha256','releaseSha256','deliverySha256','planSha256','actionSha256','inputSha256','stage','session','parentPid','childPid','parentStart','childStart','bootId')
UNRELEASED=[]
class CompletionUnavailable(ValueError):pass


def _factory(public,error_kind,namespace,primitives):
 (type,dict,tuple,list,set,str,int,float,bool,bytes,len,all,any,callable,vars,object,range,min,max,
  enumerate,zip,reversed,id,next,property,BaseException,OSError,BlockingIOError,InterruptedError,ValueError)=primitives
 gettype=type.__getattribute__;new_error,init_error=BaseException.__new__,BaseException.__init__
 fnkind,mkind,bkind=FunctionType,MethodType,BuiltinFunctionType;modulekind=ModuleType;proxy=MappingProxyType
 descriptor_kinds=(MethodDescriptorType,);field_kinds=(GetSetDescriptorType,MemberDescriptorType)
 raw_hash,isfinite,is_socket=hashlib.sha256,math.isfinite,stat.S_ISSOCK
 transient_errnos=(errno.EAGAIN,errno.EWOULDBLOCK,errno.EINTR)
 unpack=struct.Struct('=iii').unpack;unpack_fd=struct.Struct('=i').unpack
 fields,binding_keys=FIELDS,BINDING;used=failed=False;retained=[];issued=[];failure_observation=None
 def denial():
  result=new_error(error_kind);init_error(result,'live-completion-receiver-unavailable');raise result
 def need(value):
  if value is not True:denial()
 def closed(value,keys):
  need(type(value) is dict and len(value)==len(keys) and all(type(key) is str for key in value) and set(value)==set(keys));return value
 def same(current,expected):
  need(type(current) in (dict,proxy) and len(current)==len(expected) and all(type(key) is str for key in current)
   and all(key in current and current[key] is value for key,value in expected))
 def function(value):
  if type(value) is mkind:value=value.__func__
  if type(value) is bkind:return None
  need(type(value) is fnkind);return (value,value.__code__,value.__closure__,value.__defaults__,value.__kwdefaults__,tuple(vars(value).items()))
 def function_same(row):
  if row is None:return
  value,code,closure,defaults,kwdefaults,state=row
  need(value.__code__ is code and value.__closure__ is closure and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults);same(vars(value),state)
 def tables(kind):
  need(type(kind) is type);lineage=gettype(kind,'__mro__');need(len(lineage)<=8 and all(type(owner) is type for owner in lineage))
  rows=tuple((owner,gettype(owner,'__bases__'),gettype(owner,'__mro__'),tuple(gettype(owner,'__dict__').items())) for owner in lineage)
  need(all(len(table)<=128 and all(type(key) is str for key,value in table) for owner,bases,mro,table in rows));return rows
 def check_tables(rows):
  for owner,bases,mro,table in rows:
   need(gettype(owner,'__bases__') is bases and gettype(owner,'__mro__') is mro);same(gettype(owner,'__dict__'),table)
   for key,value in table:
    if type(value) is fnkind:function_same(functions_by_id[id(value)])
 def functions_in(rows):return tuple(function(value) for owner,bases,mro,table in rows for key,value in table if type(value) is fnkind)
 # The immutable expected function rows are private, never supplied by callers.
 functions_by_id={}
 def save_functions(rows):
  for row in rows:
   if row is not None:functions_by_id[id(row[0])]=row
 def capture(module):
  need(type(module) is modulekind);items=tuple(vars(module).items());need(len(items)<=512 and all(type(key) is str for key,value in items))
  rows=tuple(function(value) for key,value in items if type(value) in (fnkind,mkind));save_functions(rows);return module,items,rows
 def check_module(record):
  module,items,rows=record;same(vars(module),items)
  for row in rows:function_same(row)
 def hash_value(value):
  need(type(value) is str and len(value)==64 and all(char in '0123456789abcdef' for char in value));return value
 def expected_binding(value):
  closed(value,binding_keys);copy=dict(value)
  for key in binding_keys[:6]:hash_value(copy[key])
  need(type(copy['stage']) is str and copy['stage'] in ('company-platform-store','company-source-materialize'))
  need(type(copy['session']) is str and len(copy['session'])==14 and copy['session'].startswith('s-') and copy['session'][2:].isascii() and copy['session'][2:].isalnum())
  for key in ('parentPid','childPid'):need(type(copy[key]) is int and 2<=copy[key]<2**31)
  need(copy['parentPid']!=copy['childPid'])
  for key in ('parentStart','childStart'):need(type(copy[key]) is int and 2<=copy[key]<2**64)
  boot=copy['bootId'];need(type(boot) is str and len(boot)==36 and boot[8]==boot[13]==boot[18]==boot[23]=='-' and len(boot.replace('-',''))==32 and all(char in '0123456789abcdef' for char in boot.replace('-','')))
  return proxy(copy)
 def receive_completion(handoff,*,endpoint,os_module,sys_module,socket_module,raw_constants_module,fcntl_module,select_module,clock,seconds=15):
  nonlocal used,failed,failure_observation
  need(not used and not failed and not retained and type(public) is list and not public)
  closed(handoff,('endpoint','sender','binding','protectedFds'))
  end_spec=closed(handoff['endpoint'],('fd','identity'));expected_fd=end_spec['fd'];need(type(expected_fd) is int and 3<=expected_fd<1048576)
  identity=closed(end_spec['identity'],fields);need(all(type(identity[key]) is int and identity[key]>=0 for key in fields));expected_identity=tuple(identity[key] for key in fields)
  need(is_socket(expected_identity[2]) and expected_identity[3:5]==(0,0))
  binding=expected_binding(handoff['binding']);sender=closed(handoff['sender'],('role','pid','uid','gid','start','bootId'));sender=dict(sender)
  need(type(sender['role']) is str and sender['role'] in ('original-bash','capture') and type(sender['pid']) is int and 2<=sender['pid']<2**31
   and type(sender['uid']) is type(sender['gid']) is int and sender['uid']==sender['gid']==0 and type(sender['start']) is int and 2<=sender['start']<2**64
   and type(sender['bootId']) is str and sender['bootId']==binding['bootId'])
  if sender['role']=='original-bash':need(sender['pid']==binding['parentPid'] and sender['start']==binding['parentStart'])
  else:need(sender['pid'] not in (binding['parentPid'],binding['childPid']))
  protected=handoff['protectedFds'];need(type(protected) is tuple and len(protected)<=32 and all(type(fd) is int and fd>=3 for fd in protected))
  need(expected_fd not in protected and len(set(protected))==len(protected))
  need(type(seconds) in (int,float) and isfinite(seconds) and 0<seconds<=15 and callable(clock))
  modules=tuple(capture(value) for value in (os_module,sys_module,socket_module,fcntl_module,select_module,raw_constants_module))
  own_items=tuple(namespace.items());own_functions=tuple(function(value) for value in namespace.values() if type(value) is fnkind);save_functions(own_functions)
  error_tables=tables(error_kind);save_functions(functions_in(error_tables))
  s,o,f,se=socket_module,os_module,fcntl_module,select_module
  need(type(vars(sys_module).get('platform')) is str and sys_module.platform=='linux' and o.name=='posix')
  constants={name:vars(raw_constants_module).get(name) for name in ('AF_UNIX','SOCK_STREAM','SOL_SOCKET','SO_PASSCRED','SCM_CREDENTIALS','SCM_RIGHTS','MSG_CTRUNC','MSG_TRUNC','MSG_CMSG_CLOEXEC')}
  need(all(type(value) is int for value in constants.values()) and constants==dict(AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PASSCRED=16,SCM_CREDENTIALS=2,SCM_RIGHTS=1,MSG_CTRUNC=8,MSG_TRUNC=32,MSG_CMSG_CLOEXEC=1073741824))
  kind=vars(s).get('socket');need(type(kind) is type and type(endpoint) is kind);socket_tables=tables(kind);save_functions(functions_in(socket_tables))
  def definition(name):
   for owner,bases,mro,table in socket_tables:
    for key,value in table:
     if key==name:return value
   denial()
  bound={}
  for name in ('fileno','recvmsg','close','getsockopt'):
   descriptor=definition(name);need(type(descriptor) in (fnkind,*descriptor_kinds));bound[name]=descriptor.__get__(endpoint,kind)
  # Native getsets bypass socket.py's enum conversion. The property fallback is
  # solely an explicit injected test seam with saved original fget/code.
  getters={};getter_functions=[]
  for name in ('family','type','proto','_io_refs','_closed'):
   choices=[value for owner,bases,mro,table in socket_tables for key,value in table if key==name]
   native=next((value for value in choices if type(value) in field_kinds),None)
   if native is not None:getters[name]=lambda name=name,native=native:native.__get__(endpoint,kind)
   else:
    need(choices and type(choices[0]) is property and type(choices[0].fget) is fnkind);getter=choices[0].fget;row=function(getter);getter_functions.append(row);save_functions((row,));getters[name]=lambda getter=getter:getter(endpoint)
  raw_close,raw_fstat,raw_fcntl=vars(o).get('close'),vars(o).get('fstat'),vars(f).get('fcntl')
  poll_factory=vars(se).get('poll');need(all(callable(value) for value in (raw_close,raw_fstat,raw_fcntl,poll_factory)))
  callback_rows=tuple(function(value) for value in (raw_close,raw_fstat,raw_fcntl,poll_factory,clock));save_functions(callback_rows)
  stat_kind=vars(o).get('stat_result');need(type(stat_kind) is type)
  pollin,pollhup,pollerr,pollnval=(vars(se).get(key) for key in ('POLLIN','POLLHUP','POLLERR','POLLNVAL'));need(all(type(value) is int for value in (pollin,pollhup,pollerr,pollnval)))
  returns=[];attempts=[];rights=[];errors=[];raw=b'';fragments=0;credentials=[];actual_fd=None;admitted=False;socket_attempted=socket_closed=False;unknown=False;eof=False;eof_credentials=None;data=None;poll_record=None;calls=0
  phase='clock-start';first_phase=first_reason=None;last_return=None;truncation_unknown=False;cleanup_error=False
  def first_failure(problem):
   nonlocal first_phase,first_reason
   if first_phase is None:first_phase=phase;first_reason='predicate-refused' if type(problem) is error_kind else 'callback-exception'
  def return_summary(result):
   # Inspect only bounded exact built-in shapes; no payload is exported.
   answer=dict(shapeKnown=False,payloadBytes=None,flags=None,ancillaryCount=None,ancillaryShape=(),credentials=())
   if type(result) is not tuple or len(result)!=4:return proxy(answer)
   part,anc,msgflags,address=result
   if type(part) is bytes and len(part)<=2049:answer['payloadBytes']=len(part)
   if type(msgflags) is int and 0<=msgflags<2**31:answer['flags']=msgflags
   if type(anc) is not list or len(anc)>32:return proxy(answer)
   answer['ancillaryCount']=len(anc);shapes=[];recognized=[];valid=(type(part) is bytes and len(part)<=attempts[-1][1] and type(msgflags) is int and 0<=msgflags<2**31);total=0
   for item in anc:
    if type(item) is not tuple or len(item)!=3:valid=False;continue
    level,kind_value,body=item
    if type(level) is not int or type(kind_value) is not int or not (-2**31<=level<2**31 and -2**31<=kind_value<2**31) or type(body) is not bytes:valid=False;continue
    total+=len(body)
    if total>256:valid=False;break
    if len(shapes)<4:shapes.append((level,kind_value,len(body)))
    if level==1 and kind_value==2 and len(body)==12 and len(recognized)<4:recognized.append(unpack(body))
   answer.update(shapeKnown=valid,ancillaryShape=tuple(shapes),credentials=tuple(recognized));return proxy(answer)
  used=True  # Valid structural/initial class admission consumed before callbacks.
  def guard():
   same(namespace,own_items)
   for row in own_functions:function_same(row)
   check_tables(error_tables);check_tables(socket_tables)
   for record in modules:check_module(record)
   for row in callback_rows:function_same(row)
  def socket_guard():
   check_module(modules[2]);check_tables(socket_tables)
   for row in getter_functions:function_same(row)
   need(type(endpoint) is kind)
   for name in ('family','type','proto'):
    value=getters[name]();need(type(value) is int and value==({'family':1,'type':1,'proto':0}[name]))
   count=getters['_io_refs']();closed_value=getters['_closed']();need(type(count) is int and count==0 and type(closed_value) is bool)
   need(closed_value is socket_closed)
   check_module(modules[2]);check_tables(socket_tables)
   for row in getter_functions:function_same(row)
  def tick():
   nonlocal calls,phase
   phase='clock-check';guard();value=clock();returns.append(('clock',value));guard();need(type(value) in (int,float) and isfinite(value) and value<deadline-1)
   calls+=1;need(calls<=8192)
  def observed(value):
   need(type(value) is stat_kind);answer=tuple(object.__getattribute__(value,key) for key in fields);need(all(type(item) is int and item>=0 for item in answer));return answer
  def acquire_right(fd):
   nonlocal unknown
   row=dict(fd=fd,attempted=False,closed=False,identity=None,ambiguous=False);rights.append(row)
   if type(fd) is not int or fd<3 or fd==actual_fd or fd in protected:unknown=True;row['ambiguous']=True;return
   for old in rights[:-1]:
    if old['fd']==fd:old['ambiguous']=row['ambiguous']=True;unknown=True
  def disclose(result):
   nonlocal unknown,truncation_unknown
   # Pure bounded disclosure precedes any post-recv callback/namespace check.
   if type(result) is not tuple or len(result)!=4:unknown=True;return
   if type(result[2]) is not int:unknown=True
   elif result[2]&(8|32):unknown=True;truncation_unknown=True
   anc=result[1]
   if type(anc) is not list or len(anc)>32:unknown=True;return
   total=0
   for item in anc:
    if type(item) is not tuple or len(item)!=3:unknown=True;continue
    level,kind_value,body=item
    if type(level) is not int or type(kind_value) is not int or type(body) is not bytes:unknown=True;continue
    total+=len(body)
    if total>256:unknown=True;return
    if level==1 and kind_value==1:
     for offset in range(0,len(body)//4*4,4):acquire_right(unpack_fd(body[offset:offset+4])[0])
     if len(body)%4:unknown=True
  def close_right(row):
   need(not row['attempted'] and not row['ambiguous']);row['attempted']=True
   function_same(callback_rows[0]);function_same(callback_rows[1])
   actual=raw_fstat(row['fd']);returns.append(('right-fstat',row,actual));identity=observed(actual)
   if row['identity'] is not None:need(identity[:5]==row['identity'][:5])
   row['identity']=identity;function_same(callback_rows[1]);function_same(callback_rows[0])
   answer=raw_close(row['fd']);returns.append(('right-close',row,answer));need(answer is None);row['closed']=True
  try:
   guard();start=clock();returns.append(('clock-start',start));guard();need(type(start) in (int,float) and isfinite(start));deadline=start+seconds
   phase='endpoint-fileno';actual_fd=bound['fileno']();returns.append(('socket-fileno',actual_fd));guard();need(type(actual_fd) is int and actual_fd==expected_fd)
   phase='endpoint-metadata';socket_guard();meta=raw_fstat(actual_fd);returns.append(('socket-fstat',meta));guard();need(observed(meta)==expected_identity)
   phase='endpoint-flags';flags=raw_fcntl(actual_fd,3);returns.append(('socket-flags',flags));guard();fdflags=raw_fcntl(actual_fd,1);returns.append(('socket-fdflags',fdflags));guard()
   need(type(flags) is type(fdflags) is int and flags==2|2048 and fdflags==1)
   phase='endpoint-passcred';passcred=bound['getsockopt'](1,16);returns.append(('SO_PASSCRED',passcred));guard();need(type(passcred) is int and passcred==1);admitted=True
   phase='poll-create';poller=poll_factory();returns.append(('poller',poller));guard();poll_tables=tables(type(poller));save_functions(functions_in(poll_tables))
   descriptions={}
   for name in ('register','poll'):
    description=next((value for owner,bases,mro,table in poll_tables for key,value in table if key==name),None);need(type(description) in (fnkind,*descriptor_kinds));descriptions[name]=description.__get__(poller,type(poller))
   poll_record=(poller,poll_tables,descriptions)
   dict_getter=next((value for owner,bases,mro,table in poll_tables for key,value in table if key=='__dict__'),None)
   need(dict_getter is None or type(dict_getter) is GetSetDescriptorType)
   poll_state=None if dict_getter is None else dict_getter.__get__(poller,type(poller))
   need(poll_state is None or (type(poll_state) is dict and len(poll_state)<=16 and all(type(key) is str and key not in ('register','poll') for key in poll_state)))
   poll_items=() if poll_state is None else tuple(poll_state.items())
   def poll_guard():
    check_tables(poll_tables)
    if dict_getter is not None:need(dict_getter.__get__(poller,type(poller)) is poll_state);same(poll_state,poll_items)
   phase='poll-register';poll_guard();answer=descriptions['register'](actual_fd,pollin|pollhup|pollerr|pollnval);returns.append(('poll-register',answer));poll_guard();guard()
   for index in range(4096):
    tick();phase='poll-wait';socket_guard();poll_guard();events=descriptions['poll'](20);returns.append(('poll-events',events));poll_guard();guard()
    need(type(events) is list and len(events)<=1)
    if not events:continue
    event=events[0];need(type(event) is tuple and len(event)==2 and type(event[0]) is type(event[1]) is int and event[0]==actual_fd
      and event[1]&(pollerr|pollnval)==0 and event[1]&~(pollin|pollhup)==0 and event[1]!=0)
    phase='receive';attempts.append(('recvmsg',min(512,2049-len(raw)),256,1073741824))
    try:
     result=bound['recvmsg'](min(512,2049-len(raw)),256,1073741824);returns.append(('recvmsg-return',result));disclose(result);last_return=return_summary(result)
    except (BlockingIOError,InterruptedError) as problem:
     errors.append(('transient',problem));guard();need(type(problem) in (BlockingIOError,InterruptedError) and type(problem.errno) is int and problem.errno in transient_errnos);continue
    except BaseException as problem:unknown=True;errors.append(('recvmsg-unreturned',problem));raise
    phase='message-controls' if truncation_unknown else 'returned-shape';guard();need(type(result) is tuple and len(result)==4 and not unknown)
    part,anc,msgflags,address=result;need(type(part) is bytes and len(part)<=min(512,2049-len(raw)) and type(anc) is list and type(msgflags) is int)
    phase='message-controls';need(msgflags&~1073741824==0 and ((address is None) or (type(address) is str and address=='') or (type(address) is bytes and address==b'')))
    if part==b'':
     phase='eof-controls';need(fragments>0)
     if anc:
      need(len(anc)==1);item=anc[0];need(type(item) is tuple and len(item)==3 and type(item[0]) is type(item[1]) is int and item[:2]==(1,2) and type(item[2]) is bytes and len(item[2])==12)
      eof_credentials=unpack(item[2]);need(eof_credentials==(0,0,0))
     eof=True;break
    phase='positive-credentials';need(len(anc)==1);item=anc[0];need(type(item) is tuple and len(item)==3 and type(item[0]) is type(item[1]) is int and item[:2]==(1,2) and type(item[2]) is bytes and len(item[2])==12)
    cred=unpack(item[2]);credentials.append(cred);need(cred==(sender['pid'],sender['uid'],sender['gid']))
    raw+=part;fragments+=1;phase='body-cap';need(len(raw)<=2048)
   phase='capture-final';need(eof and 0<len(raw)<=2048 and not rights);guard();socket_guard()
  except BaseException as problem:first_failure(problem);errors.append(('capture',problem));failed=True
  finally:
   for row in reversed(rights):
    if row['attempted'] or row['closed'] or row['ambiguous']:continue
    try:phase='right-close';close_right(row)
    except BaseException as problem:first_failure(problem);cleanup_error=True;errors.append(('right-close-unknown',row,problem));unknown=True;failed=True
   if admitted:
    try:
     phase='socket-close';socket_guard();function_same(callback_rows[1]);meta=raw_fstat(actual_fd);returns.append(('socket-close-fstat',meta));need(observed(meta)[:5]==expected_identity[:5]);function_same(callback_rows[1]);socket_guard();socket_attempted=True
     answer=bound['close']();returns.append(('socket-close-return',answer));need(answer is None);socket_closed=True
     socket_guard();observed_fd=bound['fileno']();returns.append(('closed-socket-fileno',observed_fd));need(type(observed_fd) is int and observed_fd==-1)
    except BaseException as problem:first_failure(problem);cleanup_error=True;errors.append(('socket-close-unknown',problem));unknown=True;failed=True;socket_closed=False
   else:unknown=True
   if socket_closed and not unknown:
    try:phase='final-boundary';guard()
    except BaseException as problem:first_failure(problem);cleanup_error=True;errors.append(('final-boundary',problem));unknown=True;failed=True
   known=socket_closed and not unknown and all(row['closed'] for row in rights)
   if failed or not known:
    failed=True;record=(handoff,endpoint,modules,socket_tables,bound,getters,actual_fd,rights,returns,attempts,errors,raw,credentials,poll_record,admitted,socket_attempted,socket_closed,unknown)
    retained.append(record);public.append(record)
    failure_observation=proxy(dict(scope='LIVE_COMPLETION_FAILURE_OBSERVATION_DATA_ONLY',firstPhase=first_phase,firstReason=first_reason,
     recvAttempts=len(attempts),acceptedBytes=len(raw),positiveFragments=fragments,disclosedRights=len(rights),truncationUnknown=truncation_unknown,lastReturn=last_return,
     socketCloseAttempted=socket_attempted,socketKnownClosed=socket_closed and not unknown,unknownOwnership=unknown,cleanupErrorPresent=cleanup_error,
     parentAuthenticated=False,senderBirthAuthenticated=False,inputOriginQualified=False,sourceClosureObserved=False,actualBashWaitObserved=False,
     completeCopygraphQualified=False,nativeQualified=False,executionEvidenceIssued=False,stageAcknowledged=False))
  need(not failed and known)
  data=proxy(dict(scope='LIVE_CREDENTIALLED_COMPLETION_CAPTURE_DATA_ONLY',raw=raw,bytes=len(raw),sha256=raw_hash(raw).hexdigest(),fragments=fragments,
   observedCredentials=tuple(credentials),eofCredentials=eof_credentials,suppliedSender=proxy(sender),suppliedBinding=binding,actualStreamEof=True,ownScopeKnownReleased=True,
   parentAuthenticated=False,senderBirthAuthenticated=False,inputOriginQualified=False,sourceClosureObserved=False,actualBashWaitObserved=False,
   completeCopygraphQualified=False,nativeQualified=False,executionEvidenceIssued=False,stageAcknowledged=False))
  issued.append(data);return data
 def require_released(value):
  need(not failed and not retained and len(issued)==1 and value is issued[0]);return value
 def observe_failure():
  return failure_observation
 def main(argv=None):denial()
 return receive_completion,require_released,observe_failure,main


receive_completion,require_released,observe_failure,main=_factory(UNRELEASED,CompletionUnavailable,globals(),(type,dict,tuple,list,set,str,int,float,bool,bytes,len,all,any,callable,vars,object,range,min,max,
 enumerate,zip,reversed,id,next,property,BaseException,OSError,BlockingIOError,InterruptedError,ValueError))
del _factory
