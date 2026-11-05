"""Original-parent, credentialed status and protected record DATA composition.

Owns one original P context and its own readonly record handles; borrows the
original authenticated CLI and ParentSystem. No verification dispatch or issuer
is selected. Parent release precedes any future Worker reacquisition, leaving
an explicit continuity gap. Source/endpoint/capture/mount origin and complete
send/copy chronology are independently authenticated caller obligations.
"""
import contextlib,hashlib,json,math,stat
from types import BuiltinFunctionType,CellType,FunctionType,GeneratorType,GenericAlias,GetSetDescriptorType,MappingProxyType,MemberDescriptorType,MethodType,ModuleType

UNRELEASED=[]
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BINDING=('requestSha256','releaseSha256','deliverySha256','planSha256','actionSha256','inputSha256','stage','session','parentPid','childPid','parentStart','childStart','bootId')
class CompletionCandidateUnavailable(ValueError):pass


def _factory(public,error_kind,namespace,primitives):
 (type,dict,tuple,list,set,str,int,float,bool,bytes,len,all,any,vars,object,range,min,id,next,zip,reversed,BaseException,classmethod,staticmethod,property)=primitives
 fn,method,builtin,modulekind,proxy=FunctionType,MethodType,BuiltinFunctionType,ModuleType,MappingProxyType
 generator_kind,cell_kind,dict_descriptor_kind=GeneratorType,CellType,GetSetDescriptorType
 field_descriptor_kind=MemberDescriptorType
 generic_alias_kind=GenericAlias
 gettype=type.__getattribute__;new_error,init_error=BaseException.__new__,BaseException.__init__
 digest,loads,dumps,finite=hashlib.sha256,json.loads,json.dumps,math.isfinite
 fields,binding_fields=FIELDS,BINDING;used=failed=False;retained=[]
 cm_kind=contextlib._GeneratorContextManager;cm_meta=type(cm_kind)
 def deny():
  error=new_error(error_kind);init_error(error,'company-live-completion-candidate-unavailable');raise error
 def need(value):
  if value is not True:deny()
 def exact(value,keys):
  need(type(value) is dict and len(value)==len(keys) and all(type(key) is str for key in value) and set(value)==set(keys));return value
 def same(value,items):
  need(type(value) in (dict,proxy) and len(value)==len(items) and all(type(key) is str for key in value) and all(key in value and value[key] is saved for key,saved in items))
 def function(value):
  if type(value) is method:value=value.__func__
  if type(value) is builtin:return None
  need(type(value) is fn);return value,value.__code__,value.__closure__,value.__defaults__,value.__kwdefaults__,tuple(vars(value).items())
 def function_same(row):
  if row is None:return
  value,code,closure,defaults,kwdefaults,items=row
  need(value.__code__ is code and value.__closure__ is closure and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults);same(vars(value),items)
 def tables(kind,allow_cm=False):
  need(type(kind) is type or (allow_cm and type(kind) is cm_meta));mro=gettype(kind,'__mro__')
  need(len(mro)<=8 and all(type(owner) is type or (allow_cm and type(owner) is cm_meta) for owner in mro))
  rows=tuple((owner,gettype(owner,'__bases__'),gettype(owner,'__mro__'),tuple(gettype(owner,'__dict__').items())) for owner in mro)
  need(all(len(items)<=128 and all(type(key) is str for key,value in items) for owner,bases,lineage,items in rows))
  functions=[]
  for owner,bases,lineage,items in rows:
   for key,value in items:
    if type(value) is fn:functions.append(function(value))
    elif type(value) in (classmethod,staticmethod):
     target=value.__func__
     if type(target) in (fn,method,builtin):functions.append(function(target))
     else:need(type(value) is classmethod and key=='__class_getitem__' and target is generic_alias_kind)
    elif type(value) is property:
     for getter in (value.fget,value.fset,value.fdel):
      if getter is not None:functions.append(function(getter))
  return rows,tuple(functions)
 def table_same(record):
  rows,functions=record
  for owner,bases,mro,items in rows:need(gettype(owner,'__bases__') is bases and gettype(owner,'__mro__') is mro);same(gettype(owner,'__dict__'),items)
  for row in functions:function_same(row)
 def definition(record,name):return next((value for owner,bases,mro,items in record[0] for key,value in items if key==name),None)
 def capture(module):
  need(type(module) is modulekind);items=tuple(vars(module).items());need(len(items)<=512 and all(type(key) is str for key,value in items));name=dict(items).get('__name__');need(type(name) is str)
  classes=[];functions=[]
  for key,value in items:
   if type(value) in (fn,method):functions.append(function(value))
   elif type(value) is type:
    owner=gettype(value,'__module__');need(type(owner) is str)
    if owner==name:classes.append(tables(value))
  return module,items,tuple(classes),tuple(functions)
 def capture_same(record):
  module,items,classes,functions=record;same(vars(module),items)
  for item in classes:table_same(item)
  for item in functions:function_same(item)
 def original(module,name):
  value=vars(module).get(name);need(type(value) is fn and value.__globals__ is vars(module));return value
 def hash_value(value):need(type(value) is str and len(value)==64 and all(char in '0123456789abcdef' for char in value));return value
 def raw_pin(raw,pin,cap):
  need(type(raw) is bytes and 0<len(raw)<=cap and type(pin) is tuple and len(pin)==2 and type(pin[1]) is int and pin[1]==len(raw));hash_value(pin[0]);need(digest(raw).hexdigest()==pin[0])
 def freeze(value,counter,depth=0):
  counter[0]+=1;need(counter[0]<=2048 and depth<=16)
  if value is None or type(value) in (bool,int):
   if type(value) is int:need(-2**63<=value<2**64)
   return value
  if type(value) is str:need(len(value)<=32768);counter[1]+=len(value);need(counter[1]<=32768);return value
  if type(value) in (dict,proxy):
   need(len(value)<=128 and all(type(key) is str and 0<len(key)<=128 for key in value));return proxy({key:freeze(item,counter,depth+1) for key,item in value.items()})
  need(type(value) in (tuple,list) and len(value)<=128);return tuple(freeze(item,counter,depth+1) for item in value)
 def collect_completion_candidate(cli_module,cli,receiver_module,status_module,verification_builder_module,*,
  request_raw,request_pin,execute_invocation_raw,invocation_pin,plan_raw,plan_pin,expected_binding,
  parent_system_module,parent_system,endpoint,endpoint_identity,os_module,sys_module,socket_module,
  raw_constants_module,fcntl_module,select_module,clock,stdout,stderr,expected_exit_code=0,seconds=20):
  """DATA only; live PS station dependency bindings remain externally quiet.

  Stored dependency rows are guarded. Their original OS/libc/ctypes/platform/
  getdents object fields and getter/equality behavior are trusted station
  continuity obligations, not authenticated by this row snapshot.
  """
  nonlocal used,failed
  need(not used and not failed and not retained and type(public) is list and not public)
  raw_pin(request_raw,request_pin,4096);raw_pin(execute_invocation_raw,invocation_pin,4096);raw_pin(plan_raw,plan_pin,16384)
  need(type(stdout) is bytes and 0<len(stdout)<=32768 and type(stderr) is bytes and len(stderr)<=8192 and len(stdout)+len(stderr)<=40960 and type(expected_exit_code) is int and expected_exit_code==0)
  binding=dict(exact(expected_binding,binding_fields))
  for key in binding_fields[:6]:hash_value(binding[key])
  need(type(binding['stage']) is type(binding['session']) is type(binding['bootId']) is str)
  for key in ('parentPid','childPid'):need(type(binding[key]) is int and 2<=binding[key]<2**31)
  for key in ('parentStart','childStart'):need(type(binding[key]) is int and 2<=binding[key]<2**64)
  identity=dict(exact(endpoint_identity,('fd','identity')));identity['identity']=dict(exact(identity['identity'],fields))
  need(type(identity['fd']) is int and 3<=identity['fd']<1048576 and all(type(identity['identity'][key]) is int and identity['identity'][key]>=0 for key in fields))
  need(type(seconds) in (int,float) and finite(seconds) and 0<seconds<=20)
  modules=[capture(value) for value in (cli_module,receiver_module,status_module,verification_builder_module,parent_system_module,os_module,sys_module,socket_module,raw_constants_module,fcntl_module,select_module)]
  own_items=tuple(namespace.items());own_functions=tuple(function(value) for value in namespace.values() if type(value) is fn);error_tables=tables(error_kind)
  cm_tables=tables(cm_kind,True);cm_meta_tables=tables(cm_meta);cm_namespace=tuple(vars(contextlib).items());enter=definition(cm_tables,'__enter__');exit=definition(cm_tables,'__exit__');cm_dict=definition(cm_tables,'__dict__')
  need(type(enter) is type(exit) is fn and type(cm_dict) is dict_descriptor_kind)
  cm_callbacks=tuple(function(value) for owner,bases,mro,items in cm_tables[0] for key,value in items if key in ('__init__','__enter__','__exit__') and type(value) is fn)
  cli_kind=vars(cli_module).get('FullCli');ps_kind=vars(parent_system_module).get('ParentSystem');need(type(cli_kind) is type and type(cli) is cli_kind and type(ps_kind) is type and type(parent_system) is ps_kind)
  cli_instance_tables=tables(cli_kind);ps_instance_tables=tables(ps_kind)
  cli_dict=definition(cli_instance_tables,'__dict__');ps_dict=definition(ps_instance_tables,'__dict__');need(type(cli_dict) is type(ps_dict) is dict_descriptor_kind)
  cli_state=cli_dict.__get__(cli,cli_kind);ps_state=ps_dict.__get__(parent_system,ps_kind)
  need(type(cli_state) is type(ps_state) is dict and len(cli_state)<=128 and len(ps_state)<=128 and all(type(key) is str for key in cli_state) and all(type(key) is str for key in ps_state))
  cli_items=tuple(cli_state.items());ps_items=tuple(ps_state.items())
  forbidden_ps=tuple(key for owner,bases,mro,items in ps_instance_tables[0] for key,value in items if type(value) in (fn,classmethod,staticmethod,property))
  need(not any(key in ps_state for key in forbidden_ps))
  static_functions=[];static_budget=[0]
  def static_capture(value,depth=0):
   static_budget[0]+=1;need(static_budget[0]<=4096 and depth<=8)
   if type(value) in (dict,proxy):
    need(len(value)<=512 and all(type(key) is str for key in value));return ('mapping',value,tuple((key,static_capture(item,depth+1)) for key,item in value.items()))
   if type(value) in (list,tuple):
    need(len(value)<=512);return ('sequence',value,tuple(static_capture(item,depth+1) for item in value))
   if type(value) in (fn,method):static_functions.append(function(value))
   return ('reference',value)
  def static_same(current,saved):
   need(type(current) is type(saved[1]) and current is saved[1])
   if saved[0]=='mapping':
    need(len(current)==len(saved[2]) and all(type(key) is str for key in current))
    for key,item in saved[2]:need(key in current);static_same(current[key],item)
   elif saved[0]=='sequence':
    need(len(current)==len(saved[2]))
    for value,item in zip(current,saved[2]):static_same(value,item)
  ps_static=tuple((name,static_capture(ps_state[name])) for name in ('_dependencies','_modules','_classes','_calls','_flags') if name in ps_state)
  recheck=vars(cli_kind).get('recheck');origins=vars(cli_kind).get('original_modules');owned_state=original(cli_module,'_owned_state')
  need(type(recheck) is fn and type(origins) is property and type(origins.fget) is fn)
  ps_release=vars(ps_kind).get('require_released');need(type(ps_release) is fn)
  receive=original(receiver_module,'receive_completion');release_receiver=original(receiver_module,'require_released');bind_status=original(status_module,'bind_execution_status');prepare_builder=original(verification_builder_module,'prepare_verification_builder')
  callbacks=[function(value) for value in (recheck,origins.fget,owned_state,ps_release,receive,release_receiver,bind_status,prepare_builder,clock)]
  o,f=os_module,fcntl_module;need(type(vars(o).get('name')) is str and vars(o)['name']=='posix' and type(vars(sys_module).get('platform')) is str and vars(sys_module)['platform']=='linux')
  ops={name:vars(o).get(name) for name in ('uname','open','stat','fstat','pread','close')};ops['fcntl']=vars(f).get('fcntl');ops['clock']=clock
  op_rows={name:function(value) for name,value in ops.items()}
  for key,value in {'O_RDONLY':0,'O_DIRECTORY':65536,'O_NOFOLLOW':131072,'O_CLOEXEC':524288,'O_NONBLOCK':2048}.items():need(type(vars(o).get(key)) is int and vars(o)[key]==value)
  stat_kind=vars(o).get('stat_result');uname_kind=vars(o).get('uname_result');need(type(stat_kind) is type and type(uname_kind) is type);stat_tables=tables(stat_kind);uname_tables=tables(uname_kind)
  def field_readers(kind,kind_tables,names):
   readers={};plain=definition(kind_tables,'__dict__')
   for name in names:
    descriptor=definition(kind_tables,name)
    if type(descriptor) in (dict_descriptor_kind,field_descriptor_kind):readers[name]=(descriptor,None)
    else:need(descriptor is None and type(plain) is dict_descriptor_kind);readers[name]=(None,plain)
   return readers
  stat_readers=field_readers(stat_kind,stat_tables,fields);uname_readers=field_readers(uname_kind,uname_tables,('sysname','machine'))
  def read_field(value,kind,readers,name):
   descriptor,plain=readers[name]
   if descriptor is not None:return descriptor.__get__(value,kind)
   data=plain.__get__(value,kind);need(type(data) is dict and all(type(key) is str for key in data));return dict.get(data,name)
  rows=[];returns=[];attempts=[];errors=[];calls=0;unknown=False;receiver_transferred=False;receiver_known=False;cm=None;held=None;cm_state=None;cm_items=();generator=None;entered=False;exit_attempted=False;parent_closed=False;P=R=None;parent_args=None;parent_identity=None;parent_check=None;record_raw=None;receiver_data=None;status_data=None;verify_data=None;record_meta=None;device_meta=None;deadline=None;phase='admission';wrap=None;wrapped=None;wrap_cell=None;build=None
  record=dict(cli=cli,parent_system=parent_system,endpoint=endpoint,modules=modules,rows=rows,returns=returns,attempts=attempts,errors=errors)
  used=True  # Valid structural admission consumed before first collaborator.
  def guard():
   need(type(cli) is cli_kind and type(parent_system) is ps_kind)
   same(namespace,own_items)
   for row in own_functions:function_same(row)
   table_same(error_tables);table_same(cm_tables);table_same(cm_meta_tables);same(vars(contextlib),cm_namespace);table_same(stat_tables);table_same(uname_tables)
   for row in cm_callbacks:function_same(row)
   for item in modules:capture_same(item)
   for item in callbacks:function_same(item)
   for item in op_rows.values():function_same(item)
   need(cli_dict.__get__(cli,cli_kind) is cli_state);same(cli_state,cli_items)
   need(ps_dict.__get__(parent_system,ps_kind) is ps_state and len(ps_state)==len(ps_items) and all(type(key) is str for key in ps_state))
   for key,value in ps_items:
    need(key in ps_state)
    current=ps_state[key]
    if key=='_arguments' and value is None:need(current is None or current is parent_args)
    elif value is None or type(value) in (bool,int,float,str):need(current is None or type(current) in (bool,int,float,str))
    else:need(current is value)
   for name,item in ps_static:static_same(ps_state[name],item)
   for item in static_functions:function_same(item)
   if wrap_cell is not None:need(wrap_cell.cell_contents is wrapped)
  def boundary(label,action,*args,**kwargs):
   guard();attempts.append((label,action,args,kwargs));value=action(*args,**kwargs);returns.append((label,value));guard();return value
  def call(name,*args,**kwargs):
   nonlocal calls
   calls+=1;need(calls<=512);return boundary(name,ops[name],*args,**kwargs)
  def tick():
   value=call('clock');need(type(value) in (int,float) and finite(value) and value<deadline-2)
  def meta(value):
   table_same(stat_tables);need(type(value) is stat_kind);result=tuple(read_field(value,stat_kind,stat_readers,key) for key in fields);need(all(type(item) is int and item>=0 for item in result));return result
  def acquire(path,flags,role,dir_fd=None):
   nonlocal calls,unknown
   guard();calls+=1;need(calls<=512);attempts.append(('open',path,flags,dir_fd))
   try:fd=ops['open'](path,flags,**({} if dir_fd is None else {'dir_fd':dir_fd}))
   except BaseException as problem:unknown=True;errors.append(('open-unreturned',problem));raise
   returns.append(('open-return',fd));row=dict(fd=fd,role=role,identity=None,attempted=False,closed=False,ambiguous=False);rows.append(row)
   endpoint_protected=() if receiver_known else (identity['fd'],)
   protected=endpoint_protected if held is None else (*endpoint_protected,*parent_handles,parent_args.directory_fd,parent_args.lock_fd)
   aliases=[] if type(fd) is not int else [old for old in rows[:-1] if type(old['fd']) is int and old['fd']==fd and not old['closed']]
   if type(fd) is not int or fd<3 or len(rows)>16 or fd in protected or aliases:
    unknown=True;row['ambiguous']=True
    for old in aliases:old['ambiguous']=True
    deny()
   guard();return row
  def close_row(row):
   nonlocal unknown
   try:
    need(not row['closed'] and not row['attempted'] and not row['ambiguous']);row['attempted']=True
    function_same(op_rows['fstat']);function_same(op_rows['close']);table_same(stat_tables)
    actual=ops['fstat'](row['fd']);returns.append(('close-fstat',row,actual));now=meta(actual)
    if row['identity'] is not None:need(now==row['identity'])
    function_same(op_rows['fstat']);function_same(op_rows['close']);answer=ops['close'](row['fd']);returns.append(('close-return',row,answer));need(answer is None);row['closed']=True;function_same(op_rows['close'])
   except BaseException as problem:
    unknown=True;errors.append(('readonly-close-unknown',row,problem));raise
  def fd_check(row):
   value=meta(call('fstat',row['fd']))
   if row['identity'] is None:row['identity']=value
   else:need(value==row['identity'])
   flags=call('fcntl',row['fd'],3);fdflags=call('fcntl',row['fd'],1)
   required=131072|2048|(65536 if row['role']=='directory' else 0)
   need(type(flags) is type(fdflags) is int and flags&~32768==required and fdflags==1);return value
  def cm_check():
   guard();need(type(cm) is cm_kind and cm_dict.__get__(cm,cm_kind) is cm_state);same(cm_state,cm_items)
   need(type(generator) is generator_kind and cm_state.get('gen') is generator and generator.gi_code is wrapped.__code__)
   if generator.gi_frame is not None:
    frame=generator.gi_frame;need(frame.f_globals is vars(P) and frame.f_locals.get('arguments') is parent_args and frame.f_locals.get('system') is parent_system)
  def parent_check_live():
   guard();need(type(held) is held_kind);state=held_dict.__get__(held,held_kind)
   need(state is held_state and state.get('arguments') is parent_args and state.get('system') is parent_system and state.get('identity') is parent_identity and state.get('live') is True)
   current=state.get('handles');need(type(current) is list and len(current)==len(parent_handles) and all(type(value) is int and value==old for value,old in zip(current,parent_handles)))
   value=boundary('original-parent-check',check_parent,held);record['lastParentCheck']=value;cm_check();return value
  def close_parent():
   nonlocal exit_attempted,parent_closed
   need(entered and not exit_attempted);parent_check_live();cm_check();exit_attempted=True
   answer=exit(cm,None,None,None);returns.append(('original-parent-exit',answer));guard();cm_check();need(generator.gi_frame is None)
   state=held_dict.__get__(held,held_kind);need(state is held_state and state.get('live') is False and type(state.get('handles')) is list and len(state['handles'])==0)
   actual=boundary('original-parent-system-release',ps_release,parent_system);need(actual is parent_system);parent_closed=True
  try:
   guard();start=call('clock');need(type(start) in (int,float) and finite(start));deadline=start+seconds
   uname=call('uname');need(type(uname) is uname_kind);sysname=read_field(uname,uname_kind,uname_readers,'sysname');machine=read_field(uname,uname_kind,uname_readers,'machine');returns.append(('uname-fields',sysname,machine));guard();need(type(sysname) is type(machine) is str and sysname=='Linux' and machine=='x86_64')
   need(boundary('cli-recheck',recheck,cli) is cli);state=boundary('cli-owned-state',owned_state,cli);need(type(state) is dict)
   previous_request=state.get('_request_raw');need(previous_request is None or (type(previous_request) is bytes and previous_request==request_raw))
   module_map=state.get('_modules');need(type(module_map) is dict and all(type(key) is str for key in module_map));R=module_map.get(vars(cli_module)['REQUEST']);need(type(R) is modulekind and module_map.get(vars(cli_module)['PARENT_SYSTEM']) is parent_system_module)
   origins_value=boundary('original-cli-modules',origins.fget,cli);need(type(origins_value) is proxy and type(origins_value.get('parent')) is modulekind);P=origins_value['parent']
   need(type(origins_value.get('backend')) is modulekind and dict.get(ps_state,'_p') is P and dict.get(ps_state,'_bk') is origins_value['backend'])
   nested=tuple(value for value in origins_value.values() if type(value) is modulekind);modules.extend(capture(value) for value in (R,*nested));modules.extend(capture(value) for value in module_map.values())
   validate_request=vars(R).get('validate_request');validate_invocation=vars(R).get('validate_invocation');need(type(validate_request) is type(validate_invocation) is fn)
   callbacks.extend(function(value) for value in (validate_request,validate_invocation))
   request=boundary('original-request',validate_request,request_raw,request_sha256=request_pin[0]);invocation=boundary('original-invocation',validate_invocation,execute_invocation_raw,invocation_sha256=invocation_pin[0],request_raw=request_raw,request_sha256=request_pin[0])
   need(type(request) is type(invocation) is dict and invocation['command']=='execute-stage' and invocation['planSha256']==plan_pin[0])
   data_parts=tuple(request['dataDir'].split('/')[1:]);need(0<len(data_parts)<=9)
   plan=loads(plan_raw);need(type(plan) is dict and (dumps(plan,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')==plan_raw and plan['stage']==invocation['stage'] and plan['installationRequestSha256']==request_pin[0] and type(plan['actionSha256']) is str)
   parent_kind=vars(P).get('ParentInput');held_kind=vars(P).get('HeldParent');parent_parser=vars(parent_kind).get('from_argv');need(type(parent_parser) is classmethod and type(parent_parser.__func__) is fn)
   parent_args=boundary('original-parent-input',parent_parser.__get__(None,parent_kind),invocation['parent']);need(type(parent_args) is parent_kind and parent_args.action==plan['actionSha256'])
   need(all(binding[key]==value for key,value in {'requestSha256':request_pin[0],'releaseSha256':request['releaseSha256'],'planSha256':plan_pin[0],'stage':invocation['stage'],'session':parent_args.session,'actionSha256':parent_args.action,'parentPid':parent_args.parent_pid}.items()))
   composite=state.get('_identity');hash_value(composite)
   wrap=vars(P).get('hold_parent');need(type(wrap) is fn and wrap.__globals__ is vars(contextlib));wrapped=vars(wrap).get('__wrapped__');need(type(wrapped) is fn and wrapped.__globals__ is vars(P))
   need(type(wrap.__closure__) is tuple and len(wrap.__closure__)==1 and type(wrap.__closure__[0]) is cell_kind and wrap.__closure__[0].cell_contents is wrapped);wrap_cell=wrap.__closure__[0]
   callbacks.extend(function(value) for value in (wrap,wrapped));held_tables=tables(held_kind);held_dict=definition(held_tables,'__dict__');check_parent=vars(held_kind).get('check');need(type(held_dict) is dict_descriptor_kind and type(check_parent) is fn)
   callbacks.append(function(check_parent));need(boundary('initial-parent-system-release',ps_release,parent_system) is parent_system)
   build=boundary('original-verification-builder',prepare_builder,R,status_module);need(type(build) is fn);callbacks.append(function(build))
   phase='original-parent-acquisition';guard();cm=wrap(parent_args,system=parent_system);returns.append(('original-parent-context',cm));record['cm']=cm;guard();need(type(cm) is cm_kind)
   cm_state=cm_dict.__get__(cm,cm_kind);need(type(cm_state) is dict and type(cm_state.get('gen')) is generator_kind);cm_items=tuple(cm_state.items());generator=cm_state['gen'];cm_check()
   held=enter(cm);returns.append(('original-parent-enter',held));record['held']=held;entered=True;cm_items=tuple(cm_state.items());guard();cm_check();table_same(held_tables);need(type(held) is held_kind)
   held_state=held_dict.__get__(held,held_kind);need(type(held_state) is dict and type(held_state.get('handles')) is list);parent_handles=tuple(held_state['handles']);need(len(parent_handles)<=256 and all(type(fd) is int and fd>=3 for fd in parent_handles) and len(set(parent_handles))==len(parent_handles))
   parent_identity=held_state.get('identity');need(type(parent_identity) is tuple and len(parent_identity)==6 and type(parent_identity[0]) is type(parent_identity[1]) is type(parent_identity[3]) is int and type(parent_identity[2]) is str)
   need(parent_identity[1]==binding['parentPid'] and parent_identity[3]==binding['parentStart'] and parent_identity[2]==binding['bootId']);parent_check=parent_check_live()
   phase='credentialed-parent-status';now=call('clock');need(type(now) in (int,float) and finite(now));remaining=deadline-2-now;need(0<remaining<=20)
   protected_parent=tuple(dict.fromkeys((*parent_handles,parent_args.directory_fd,parent_args.lock_fd)));need(len(protected_parent)<=32 and identity['fd'] not in protected_parent)
   handoff=dict(endpoint=identity,sender=dict(role='original-bash',pid=parent_identity[1],uid=0,gid=0,start=parent_identity[3],bootId=parent_identity[2]),binding=binding,protectedFds=protected_parent)
   guard();receiver_transferred=True
   receiver_data=receive(handoff,endpoint=endpoint,os_module=o,sys_module=sys_module,socket_module=socket_module,raw_constants_module=raw_constants_module,fcntl_module=f,select_module=select_module,clock=clock,seconds=min(15,remaining));returns.append(('actual-receiver-data',receiver_data));record['receiver']=receiver_data;guard()
   released=boundary('original-receiver-release',release_receiver,receiver_data);need(released is receiver_data and type(receiver_data) is proxy and receiver_data.get('ownScopeKnownReleased') is True and type(receiver_data.get('raw')) is bytes);receiver_known=True;parent_check_live()
   phase='protected-record-read';tick();operation=invocation['operationId'];stage=invocation['stage'];need(operation!='0'*32)
   path='/opt/autosoft-company/evidence/'+operation+'/'+stage;parts=('opt','autosoft-company','evidence',operation,stage);parent=None;current='';path_rows=[]
   rootrow=acquire('/',65536|131072|524288|2048,'directory');fd_check(rootrow);need(rootrow['identity'][2]&0o170000==0o040000 and rootrow['identity'][2]&0o022==0 and rootrow['identity'][3:5]==(0,0));parent=rootrow;path_rows.append(('/',rootrow,None,'/'))
   data_rows=[];data_current=''
   for part in data_parts:
    tick();data_current+='/'+part;before=meta(call('stat',part,dir_fd=parent['fd'],follow_symlinks=False));need(before[2]&0o170000==0o040000 and before[2]&0o022==0 and before[3:5]==(0,0))
    row=acquire(part,65536|131072|524288|2048,'directory',parent['fd']);need(fd_check(row)==before and meta(call('stat',part,dir_fd=parent['fd'],follow_symlinks=False))==before);data_rows.append((data_current,row,parent,part));parent=row
   device_meta=parent['identity'];parent=rootrow
   for part in parts:
    tick();current+='/'+part;before=meta(call('stat',part,dir_fd=parent['fd'],follow_symlinks=False));need(before[2]&0o170000==0o040000 and before[2]&0o022==0 and before[3:5]==(0,0))
    if current.startswith('/opt/autosoft-company/evidence'):need(before[0]==device_meta[0])
    if part==stage:need(before[2]&0o7777==0o700)
    row=acquire(part,65536|131072|524288|2048,'directory',parent['fd']);need(fd_check(row)==before and meta(call('stat',part,dir_fd=parent['fd'],follow_symlinks=False))==before);path_rows.append((current,row,parent,part));parent=row
   before=meta(call('stat','executed.json',dir_fd=parent['fd'],follow_symlinks=False));need(before[2]==0o100400 and before[3:6]==(0,0,1) and before[0]==device_meta[0] and 0<before[6]<=32768)
   file=acquire('executed.json',131072|524288|2048,'record',parent['fd']);need(fd_check(file)==before);record_meta=before;body=b''
   for index in range(32770):
    tick();part=call('pread',file['fd'],min(4096,32769-len(body)),len(body));need(type(part) is bytes and len(part)<=min(4096,32769-len(body)))
    if part==b'':break
    body+=part;need(len(body)<=32768)
   else:deny()
   record_raw=body;record['recordRaw']=body;need(len(body)==before[6] and body==stdout and fd_check(file)==before and meta(call('stat','executed.json',dir_fd=parent['fd'],follow_symlinks=False))==before)
   for current,row,up,leaf in (*path_rows,*data_rows):need(fd_check(row)==row['identity'] and meta(call('stat',leaf,**({'follow_symlinks':False} if up is None else {'dir_fd':up['fd'],'follow_symlinks':False})))==row['identity'])
   need(fd_check(data_rows[-1][1])==device_meta);parent_check_live()
   phase='bind-execution-data';status_data=boundary('original-status-bind',bind_status,receiver_data['raw'],expected_binding=binding,execute_invocation_raw=execute_invocation_raw,completed_record_raw=body,expected_delivery_identity_sha256=composite,stdout=stdout,stderr=stderr,expected_exit_code=0);record['status']=status_data
   verify_data=boundary('original-verify-invocation',build,request_raw=request_raw,execute_invocation_raw=execute_invocation_raw,completed_record_raw=body,execution_status_raw=receiver_data['raw'],expected_binding=binding,expected_delivery_identity_sha256=composite,stdout=stdout,stderr=stderr,expected_exit_code=0);record['verify']=verify_data
   need(type(status_data) is type(verify_data) is proxy);parent_check=parent_check_live()
   phase='close-owned-record-readers'
   for row in reversed(rows):close_row(row);guard()
   phase='release-original-parent';close_parent();need(boundary('final-cli-recheck',recheck,cli) is cli);guard()
   return proxy(dict(scope='LIVE_VERIFY_COMPLETION_CANDIDATE_DATA_ONLY',requestRaw=request_raw,executeInvocationRaw=execute_invocation_raw,planRaw=plan_raw,completedRecordRaw=record_raw,completedRecordSha256=digest(record_raw).hexdigest(),recordPath=path+'/executed.json',recordMetadata=proxy(dict(zip(fields,record_meta))),expectedDevice=device_meta[0],receiverData=receiver_data,statusData=status_data,verificationData=verify_data,parentCheck=freeze(parent_check,[0,0]),parentOwnScopeKnownReleased=parent_closed,readonlyRecordOwnScopeKnownReleased=all(row['closed'] for row in rows),futureWorkerMustReacquire=True,uninterruptedParentHoldForFutureVerification=False,originalCliBorrowed=True,parentNativeQualified=False,completeCopygraphQualified=False,sourceClosureQualified=False,executionEvidenceIssued=False,verificationDispatched=False,stageAcknowledged=False))
  except BaseException as problem:
   errors.append((phase,problem))
   for row in reversed(rows):
    if row['closed'] or row['attempted'] or row['ambiguous']:continue
    try:close_row(row)
    except BaseException as caught:unknown=True;errors.append(('readonly-close-unknown',row,caught))
   if entered and not exit_attempted and not unknown and (not receiver_transferred or receiver_known):
    try:close_parent()
    except BaseException as caught:unknown=True;errors.append(('original-parent-close-unknown',caught))
   failed=True;record.update(phase=phase,problem=problem,cm=cm,held=held,parentArgs=parent_args,receiver=receiver_data,status=status_data,verify=verify_data,unknown=unknown or (receiver_transferred and not receiver_known) or (cm is not None and not parent_closed),receiverTransferred=receiver_transferred,receiverKnown=receiver_known,parentClosed=parent_closed)
   retained.append(record);public.append(record);deny()
 def main(argv=None):deny()
 return collect_completion_candidate,main


collect_completion_candidate,main=_factory(UNRELEASED,CompletionCandidateUnavailable,globals(),(type,dict,tuple,list,set,str,int,float,bool,bytes,len,all,any,vars,object,range,min,id,next,zip,reversed,BaseException,classmethod,staticmethod,property))
del _factory
