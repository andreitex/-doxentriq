"""Signed public helper admission -> original composition/bootstrap preparation.

Initial executing source/inputs/compose/helper/interpreter origins are externally
authenticated. All fixed public helper bytes are admitted before compilation.
This unit prepares source APIs only; it selects no IO, stage, issuer or ACK.
"""
import hashlib
from types import BuiltinFunctionType,FunctionType,MappingProxyType,ModuleType

HELPERS=(
 ('record','deploy/installer/company_cli_record.py','c48f61c44a0694ff0ae308970ca656c5f418f641f8e2f28329ac110e93d9f10d',4410),
 ('io','deploy/installer/company_cli_record_io.py','306b81f7cea78fa5eb25622e84115da7154ce82fad936644b1dccc6e8609ca47',27601),
 ('publisher','deploy/installer/company_cli_record_publish.py','dff4e2c0a57ebf35bfcddcb922f19f8df6e84f7ab1e90e0eef9e9adb8c0ce698',15822),
 ('captured','deploy/installer/company_cli_captured_publish.py','a56ddb3264ac748ea6ea935de72549caba8b09eebe6119fbbdffef8c96a406b5',6083),
 ('stage','deploy/installer/company_cli_stage_child.py','8e1097816963e48ce2157da4d69ab45cc158da787861209a0c38118f3cd09b69',17727),
 ('crypto','deploy/installer/company_release_crypto.py','ac1ee990cce7ceedef03b76e1d23d7ca5d4203dcf88c1783adc8e5954f5fdc1b',25854),
 ('receiver','deploy/installer/company_live_completion_receiver.py','772ab815a523ed08eb5d1b73f6cd05db95a5a5bddc1e9bf709ecc4a2369d67e9',23261),
 ('caller','deploy/installer/company_cli_live_verify_caller.py','ca2de8ec2fab602ba3fa4be18d887850545b3bdd00e1612d471ebb51be61a924',32248),
 ('record-store','deploy/installer/company_cli_executed_record_store.py','c4ac7faef7e0bbb25034552774ea1ef524f9a81aae4b02bca15337fd7b0bb107',17393),
 ('execution-status','deploy/installer/company_bash_execution_status.py','1ca5846d66a066f503af0a45786f1362847c6ccfaf919481527e760d14fdcd80',12797),
 ('verify-invocation','deploy/installer/company_cli_verify_invocation.py','5a4d9a475a4a77f4b0e2fce46bf48ad31825b279581840cde2fe5a9ec4e9d47d',7206),
 ('execute-bootstrap','deploy/installer/company_cli_execute_bootstrap.py','19c396d40bd74bc3672effaa9ddb6be5dd35534be1e3dd3edd652137f4880277',14062),
 ('source-inputs','deploy/installer/company_authenticated_cli_inputs.py','99156be4b544dbe16fecd47b977ff790de49863588703fe1317a253dc6840928',14204),
 ('composition','deploy/installer/company_authenticated_cli_compose.py','365e8c48ad86d90063e8e7a5305bc383d80bbfc62171040c67e52efd21819aea',17289),
 ('delivery','deploy/installer/build-full-cli-package.py','05e04b4e86c35d1bcc70ae0c251088e8b9789968ef070c2ae983393e2cc70a12',10266),
)
PROGRAMS=(('cli','deploy/installer/company_full_cli.py'),('delivery','deploy/installer/build-full-cli-package.py'),('record','deploy/installer/company_cli_record.py'),('io','deploy/installer/company_cli_record_io.py'),('publisher','deploy/installer/company_cli_record_publish.py'),('captured','deploy/installer/company_cli_captured_publish.py'),('crypto','deploy/installer/company_release_crypto.py'),('stage','deploy/installer/company_cli_stage_child.py'))
BOOTSTRAP=(('verifier','scripts/verify-release.py'),('parent','scripts/installer_parent.py'))
UNRELEASED=[]
class SignedExecuteUnavailable(ValueError):pass


def _factory(public,error_kind,namespace,primitives):
 (type,dict,tuple,list,set,str,int,bool,bytes,len,all,any,vars,object,id,format,compile,exec,sum,BaseException,property)=primitives
 fn,builtin,modulekind,proxy=FunctionType,BuiltinFunctionType,ModuleType,MappingProxyType
 gettype=type.__getattribute__;new_error,init_error=BaseException.__new__,BaseException.__init__
 digest=hashlib.sha256;helpers,programs,pair=HELPERS,PROGRAMS,BOOTSTRAP
 paths=tuple(path for role,path,sha,size in helpers);byrole={role:path for role,path,sha,size in helpers}
 registry={};retained=[];used=failed=False
 def deny():
  error=new_error(error_kind);init_error(error,'company-signed-execute-preparation-unavailable');raise error
 def need(value):
  if value is not True:deny()
 def same(current,items):
  need((type(current) is dict or type(current) is proxy) and len(current)==len(items) and all(type(key) is str for key in current) and all(key in current and current[key] is value for key,value in items))
 def function(value):
  if type(value) is builtin:return None
  need(type(value) is fn);return value,value.__code__,value.__closure__,value.__defaults__,value.__kwdefaults__,tuple(vars(value).items())
 def function_same(row):
  if row is None:return
  value,code,closure,defaults,kwdefaults,items=row
  need(value.__code__ is code and value.__closure__ is closure and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults);same(vars(value),items)
 def tables(kind):
  need(type(kind) is type);mro=gettype(kind,'__mro__');need(len(mro)<=8 and all(type(owner) is type for owner in mro));rows=tuple((owner,gettype(owner,'__bases__'),gettype(owner,'__mro__'),tuple(gettype(owner,'__dict__').items())) for owner in mro);functions=[]
  need(all(len(items)<=128 and all(type(key) is str for key,value in items) for owner,bases,lineage,items in rows))
  for owner,bases,lineage,items in rows:
   for key,value in items:
    if type(value) is fn:functions.append(function(value))
    elif type(value) is property:
     for getter in (value.fget,value.fset,value.fdel):
      if getter is not None:functions.append(function(getter))
  return rows,tuple(functions)
 def table_same(row):
  for owner,bases,mro,items in row[0]:need(gettype(owner,'__bases__') is bases and gettype(owner,'__mro__') is mro);same(gettype(owner,'__dict__'),items)
  for item in row[1]:function_same(item)
 def capture(module):
  need(type(module) is modulekind);items=tuple(vars(module).items());need(len(items)<=512 and all(type(key) is str for key,value in items));name=dict(items).get('__name__');need(type(name) is str);classes=[];functions=[]
  for key,value in items:
   if type(value) is fn:functions.append(function(value))
   elif type(value) is type:
    owner=gettype(value,'__module__');need(type(owner) is str)
    if owner==name:classes.append(tables(value))
  return module,items,tuple(classes),tuple(functions)
 def capture_same(row):
  module,items,classes,functions=row;same(vars(module),items)
  for value in classes:table_same(value)
  for value in functions:function_same(value)
 def method(kind,name,module):
  need(type(kind) is type);value=gettype(kind,'__dict__').get(name);need(type(value) is fn and value.__globals__ is vars(module));return value
 def retain(record,phase,error):
  nonlocal failed
  failed=True;record['failed']=True;row=(record,phase,error,record['inputs'],record.get('composition'),record.get('helper_module'),record.get('bootstrap'),record.get('summary'));retained.append(row);public.append(row)
 def plain_snapshot(value):
  need(type(value) is dict and len(value)<=64 and all(type(key) is str for key in value));return value,tuple((key,item,plain_snapshot(item) if type(item) is dict else None) for key,item in value.items())
 def plain_same(snapshot):
  value,items=snapshot;same(value,tuple((key,item) for key,item,child in items))
  for key,item,child in items:
   if child is not None:plain_same(child)
 def guard(record):
  need(type(record['inputs']) is record['input_kind']);same(namespace,record['own_items']);table_same(kind_tables);table_same(record['error_tables'])
  for row in record['own_functions']:function_same(row)
  for row in record['modules']:capture_same(row)
  for row in record['tables']:table_same(row)
  for row in record['functions']:function_same(row)
  for row in record['plain_arguments']:plain_same(row)
  if record.get('helper_snapshot') is not None:capture_same(record['helper_snapshot'])
  if record.get('bootstrap') is not None:need(type(record['bootstrap']) is record['bootstrap_kind'])
 def boundary(record,phase,callback,*args,_save=None,**kwargs):
  guard(record);record['attempts'].append((phase,callback,args,kwargs));value=callback(*args,**kwargs);record['returns'].append((phase,value))
  if _save is not None:record[_save]=value
  guard(record);return value
 def live(record):
  need(not failed and not retained and not record['failed']);need(boundary(record,'original-inputs-recheck',record['input_recheck'],record['inputs']) is record['inputs'])
 def issued(value):
  record=registry.get(id(value));need(type(record) is dict and record['value'] is value)
  try:need(type(value) is kind and not record['failed']);guard(record)
  except BaseException as error:retain(record,'issued-boundary',error);deny()
  return record
 def rows(value):
  need(type(value) is proxy and 0<len(value)<=33 and all(type(key) is str for key in value));result={}
  for path,row in value.items():
   need(type(row) is proxy and len(row)<=3 and all(type(key) is str for key in row));result[path]=dict(row)
  return result
 def frozen(value):
  if type(value) is dict:return proxy({key:frozen(item) for key,item in value.items()})
  return value
 class SignedExecutePreparation:
  __slots__=()
  def capture_preparation(self):
   record=issued(self)
   try:live(record);return record['summary']
   except BaseException as error:retain(record,'preparation-observation',error);deny()
  @property
  def bootstrap(self):
   record=issued(self)
   try:
    live(record);boundary(record,'original-bootstrap-construction-check',record['construction_getter'],record['bootstrap']);return record['bootstrap']
   except BaseException as error:retain(record,'bootstrap-observation',error);deny()
  @property
  def construction_modules(self):
   record=issued(self)
   try:
    live(record);value=boundary(record,'original-bootstrap-construction-modules',record['construction_getter'],record['bootstrap']);need(type(value) is proxy and len(value)==2 and all(type(key) is str for key in value) and set(value)=={'io','crypto'} and all(type(item) is modulekind for item in value.values()));return value
   except BaseException as error:retain(record,'construction-module-observation',error);deny()
 kind=SignedExecutePreparation;kind_tables=tables(kind)
 def prepare_signed_execute(inputs_module,source_inputs,compose_module,*,root,package_module,delivery_module,cli_module,sys_module):
  nonlocal used
  need(not used and not failed and not retained and type(public) is list and not public)
  modules=tuple(capture(value) for value in (inputs_module,compose_module,package_module,delivery_module,cli_module,sys_module))
  input_kind=vars(inputs_module).get('SourceInputs');need(type(input_kind) is type and type(source_inputs) is input_kind)
  input_recheck=method(input_kind,'recheck',inputs_module);input_capture=method(input_kind,'capture_inputs',inputs_module);require_helpers=method(input_kind,'require_helpers',inputs_module)
  compose_kind=vars(compose_module).get('PreparedCliComposition');compose_prepare=vars(compose_module).get('prepare_cli_composition');need(type(compose_kind) is type and type(compose_prepare) is fn and compose_prepare.__globals__ is vars(compose_module));compose_capture=method(compose_kind,'capture_delivery',compose_module)
  record=dict(value=None,inputs=source_inputs,input_kind=input_kind,input_recheck=input_recheck,input_capture=input_capture,require_helpers=require_helpers,modules=modules,tables=(tables(input_kind),tables(compose_kind)),functions=tuple(function(value) for value in (input_recheck,input_capture,require_helpers,compose_prepare,compose_capture)),error_tables=tables(error_kind),own_items=tuple(namespace.items()),own_functions=tuple(function(value) for value in namespace.values() if type(value) is fn),attempts=[],returns=[],failed=False,composition=None,helper_module=None,helper_snapshot=None,bootstrap=None,summary=None,plain_arguments=())
  used=True
  try:
   live(record);admitted=boundary(record,'original-signed-public-helpers',require_helpers,source_inputs,paths,_save='admitted');need(type(admitted) is proxy and all(type(key) is str for key in admitted))
   captures=admitted['captures'];pins=admitted['pins'];need(type(captures) is type(pins) is proxy and len(captures)==len(pins)==15 and all(type(key) is str for key in captures) and all(type(key) is str for key in pins) and set(captures)==set(pins)==set(paths))
   for role,path,sha,size in helpers:
    raw=captures[path];pin=pins[path];need(type(raw) is bytes and len(raw)==size and digest(raw).hexdigest()==sha and type(pin) is proxy and len(pin)==2 and all(type(key) is str for key in pin) and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int and pin['bytes']==size and type(pin['sha256']) is str and pin['sha256']==sha)
   record['helper_bytes']=dict(captures);record['helper_pins']=rows(pins);live(record)
   data=boundary(record,'original-source-inputs-capture',input_capture,source_inputs,_save='data');need(type(data) is proxy and all(type(key) is str for key in data))
   composition=boundary(record,'original-composition-prepare',compose_prepare,inputs_module,source_inputs,root=root,package_module=package_module,delivery_module=delivery_module,cli_module=cli_module,_save='composition');need(type(composition) is compose_kind)
   delivery=boundary(record,'original-composition-delivery',compose_capture,composition,_save='delivery');need(type(delivery) is proxy and all(type(key) is str for key in delivery) and type(delivery['deliveryRaw']) is bytes)
   files=data['sourceFiles'];need(type(files) is proxy and all(type(key) is str for key in files));actual={};actual_pins={}
   for label,path in (*programs,*pair):
    raw=captures[path] if path in captures else files[path];need(type(raw) is bytes and 0<len(raw)<=131072);actual[label]=raw;actual_pins[label]=dict(bytes=len(raw),sha256=digest(raw).hexdigest())
   need(sum(pin['bytes'] for pin in actual_pins.values())<=262144);record['capture_args']=(actual,actual_pins);record['plain_arguments']=(plain_snapshot(actual),plain_snapshot(actual_pins))
   auth=dict(delivery_pin=dict(delivery['deliveryPin']),launch_pins=rows(data['launchPins']),package_pins=rows(data['packagePins']),operational_catalog=rows(data['operationalCatalog']),fingerprint=data['fingerprint'],full_package_pin=dict(delivery['fullPackagePin']));record['authentication']=auth;record['plain_arguments']+=(plain_snapshot(auth),)
   live(record);name='_company_signed_execute_preparation_'+format(id(record),'x');helper=modulekind(name);helper.__file__='<admitted signed deploy/installer/company_cli_execute_bootstrap.py>';record['helper_module']=helper
   code=compile(captures[byrole['execute-bootstrap']],helper.__file__,'exec');record['returns'].append(('compiled-bootstrap-helper',code));guard(record);returned=exec(code,vars(helper));record['returns'].append(('executed-bootstrap-helper',returned));guard(record)
   record['helper_snapshot']=capture(helper);bootstrap_kind=vars(helper).get('ExecuteBootstrap');capture_bootstrap=vars(helper).get('capture_execute_bootstrap');need(type(bootstrap_kind) is type and type(capture_bootstrap) is fn and capture_bootstrap.__globals__ is vars(helper));record['bootstrap_kind']=bootstrap_kind
   for key,expected in (('PROGRAM_PATHS',programs),('BOOTSTRAP_PATHS',pair)):
    found=vars(helper).get(key);need(type(found) is tuple and len(found)==len(expected) and all(type(row) is tuple and len(row)==2 and all(type(item) is str for item in row) for row in found));need(found==expected)
   getter=gettype(bootstrap_kind,'__dict__').get('construction_modules');need(type(getter) is property and type(getter.fget) is fn and getter.fget.__globals__ is vars(helper));record['construction_getter']=getter.fget;record['functions']+=tuple(function(value) for value in (capture_bootstrap,getter.fget));record['tables']+=(tables(bootstrap_kind),)
   bootstrap=boundary(record,'original-execute-bootstrap-capture',capture_bootstrap,actual,actual_pins,sys_module=sys_module,_save='bootstrap');need(type(bootstrap) is bootstrap_kind);live(record)
   record['summary']=proxy(dict(scope='SIGNED_EXECUTE_PREPARATION_DATA_ONLY',deliveryRaw=delivery['deliveryRaw'],authentication=frozen(auth),programCaptures=proxy(actual),programPins=frozen(actual_pins),helperPins=frozen(record['helper_pins']),signedHelperCount=15,signedHelperBytes=246223,sourceObjectTransferred=False,downstreamOriginalSourceReauthenticationRequired=True,initialOriginSelfAuthenticated=False,operationalCodeCompiled=False,childPrepared=False,stageDispatched=False,nativeExecuted=False,executionEvidenceIssued=False,stageAcknowledged=False))
   value=object.__new__(kind);record['value']=value;registry[id(value)]=record;guard(record);return value
  except BaseException as error:retain(record,'signed-execute-prepare',error);deny()
 def main(argv=None):deny()
 return SignedExecutePreparation,prepare_signed_execute,main


SignedExecutePreparation,prepare_signed_execute,main=_factory(UNRELEASED,SignedExecuteUnavailable,globals(),(type,dict,tuple,list,set,str,int,bool,bytes,len,all,any,vars,object,id,format,compile,exec,sum,BaseException,property))
del _factory
