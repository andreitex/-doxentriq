"""Borrow original live platform source to derive bounded CLI byte/pin DATA.

Executing adapter/verifier/publisher/CLI origins are independently authenticated.
No source object is serialized or adopted by another verifier registry. A fresh
CLI/stage verifier must authenticate its own original platform source before
operational compilation. This adapter owns no source context, IO or process.
"""
import hashlib,json
from types import BuiltinFunctionType,FunctionType,MappingProxyType,MethodType,ModuleType

LAUNCH_PATHS=('deploy/installer/company_full_cli.py','deploy/installer/company_full_cli_request.py','scripts/install-lock.sh','deploy/installer/build-full-package.py','deploy/installer/company_full_package_loader.py','deploy/installer/company_stage_scope.py','deploy/installer/company_full_retention_worker.py','deploy/installer/company_retention_effects.py','deploy/installer/company_parent_system.py','deploy/installer/company_seed_backend.py','deploy/installer/company_seed_runner.py')
PACKAGE_PATHS=('scripts/company_captured_loader.py','scripts/verify-release.py','scripts/installer_parent.py','scripts/company_source_guard.py','scripts/company_source_guard_backend.py','scripts/installer_materialize.py','deploy/installer/company_full_entry.py','deploy/installer/company_stored_startup.py','deploy/installer/company_full_plan.py')
OPERATIONAL_PATHS=('scripts/bootstrap.py','scripts/checkpoint_admission.py','scripts/company_platform_store.py','scripts/company_source_tree.py','scripts/identity.py','scripts/installation_identity.py','scripts/installer_parent.py','scripts/platform_source.py','scripts/quota_allocation.py','scripts/quota_runtime.py','scripts/registry_manifest.py','scripts/resolve-images.py','scripts/runtime_layout.py','scripts/runtime_pair_init.py','scripts/startup_binding.py','scripts/verify-release.py')
BOOTSTRAP_PATHS=('scripts/verify-release.py','scripts/installer_parent.py')
UNRELEASED=[]
class AuthenticatedInputsUnavailable(ValueError):pass


def _factory(public,error_kind,namespace,primitives):
 (type,dict,tuple,list,set,str,int,bool,bytes,len,all,any,vars,object,id,zip,BaseException,property,classmethod,staticmethod)=primitives
 fn,method,builtin,modulekind,proxy=FunctionType,MethodType,BuiltinFunctionType,ModuleType,MappingProxyType
 gettype=type.__getattribute__;new_error,init_error=BaseException.__new__,BaseException.__init__
 raw_hash,dumps=hashlib.sha256,json.dumps;launch,package,operational,pair=LAUNCH_PATHS,PACKAGE_PATHS,OPERATIONAL_PATHS,BOOTSTRAP_PATHS
 required=tuple(dict.fromkeys((*launch,*package,*operational)));used=failed=False;registry={};retained=[]
 def deny():
  error=new_error(error_kind);init_error(error,'company-authenticated-cli-inputs-unavailable');raise error
 def need(value):
  if value is not True:deny()
 def same(current,items):
  need(type(current) in (dict,proxy) and len(current)==len(items) and all(type(key) is str for key in current) and all(key in current and current[key] is value for key,value in items))
 def function(value):
  if type(value) is method:value=value.__func__
  if type(value) is builtin:return None
  need(type(value) is fn);return value,value.__code__,value.__closure__,value.__defaults__,value.__kwdefaults__,tuple(vars(value).items())
 def function_same(row):
  if row is None:return
  value,code,closure,defaults,kwdefaults,items=row
  need(value.__code__ is code and value.__closure__ is closure and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults);same(vars(value),items)
 def tables(kind):
  need(type(kind) is type);mro=gettype(kind,'__mro__');need(len(mro)<=8 and all(type(owner) is type for owner in mro));rows=tuple((owner,gettype(owner,'__bases__'),gettype(owner,'__mro__'),tuple(gettype(owner,'__dict__').items())) for owner in mro)
  need(all(len(items)<=128 and all(type(key) is str for key,value in items) for owner,bases,lineage,items in rows));functions=[]
  for owner,bases,lineage,items in rows:
   for key,value in items:
    if type(value) is fn:functions.append(function(value))
    elif type(value) is property:
     for getter in (value.fget,value.fset,value.fdel):
      if getter is not None:functions.append(function(getter))
    elif type(value) in (classmethod,staticmethod):
     target=value.__func__
     if type(target) in (fn,method,builtin):functions.append(function(target))
  return rows,tuple(functions)
 def table_same(record):
  for owner,bases,mro,items in record[0]:need(gettype(owner,'__bases__') is bases and gettype(owner,'__mro__') is mro);same(gettype(owner,'__dict__'),items)
  for row in record[1]:function_same(row)
 def capture(module):
  need(type(module) is modulekind);items=tuple(vars(module).items());need(len(items)<=512 and all(type(key) is str for key,value in items));name=dict(items).get('__name__');need(type(name) is str);classes=[];functions=[]
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
 def hash_value(value):need(type(value) is str and len(value)==64 and all(char in '0123456789abcdef' for char in value));return value
 def canonical(value):return dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'
 def retain(record,phase,error):
  nonlocal failed
  failed=True;record['failed']=True;row=(record,phase,error,record['source'],record.get('maps'),record.get('data'));retained.append(row);public.append(row)
 def guard(record):
  need(type(record['source']) is record['source_kind']);same(namespace,record['own_items']);table_same(kind_tables);table_same(record['error_tables'])
  for row in record['own_functions']:function_same(row)
  for item in record['modules']:capture_same(item)
  for row in record['functions']:function_same(row)
 def boundary(record,label,callback,*args):
  guard(record);record['attempts'].append((label,callback,args));value=callback(*args);record['returns'].append((label,value));guard(record);return value
 def live(record):
  need(not record['failed'] and not failed and not retained)
  need(boundary(record,'original-live-source',record['validator'],record['source']) is record['source'])
 def maps(record):
  need(not record['failed'] and not failed and not retained)
  result=boundary(record,'original-platform-source-map-capture',record['capture_maps'],record['source'])
  need(type(result) is tuple and len(result)==3);files,modes,metadata=result
  record['actual_files'],record['actual_modes'],record['actual_metadata']=files,modes,metadata
  need(type(files) is type(modes) is type(metadata) is proxy and 0<len(files)<=2048 and len(files)==len(modes) and all(type(key) is str for key in files) and all(type(key) is str for key in modes) and set(files)==set(modes))
  need(all(type(key) is str for key in metadata) and len(metadata)<=128);hash_value(metadata.get('signingKeyFingerprint'));hash_value(metadata.get('releaseSha256'))
  if record['maps'] is not None:
   old_files,old_modes,old_metadata=record['maps'];need(files is old_files and modes is old_modes and metadata is old_metadata)
  return files,modes,metadata
 def selected(files,modes,paths,cap,total,*,shell=False):
  captures={};pins={};count=0
  for path in paths:
   need(path in files and path in modes);raw=files[path];mode=modes[path];expected='100755' if shell and path=='scripts/install-lock.sh' else '100644'
   need(type(raw) is bytes and 0<len(raw)<=cap and type(mode) is str and (mode in ('100644','100755') if shell and path=='scripts/install-lock.sh' else mode==expected));count+=len(raw);need(count<=total);captures[path]=raw;pins[path]=dict(bytes=len(raw),sha256=raw_hash(raw).hexdigest())
  return captures,pins
 def issued(value):
  record=registry.get(id(value));need(type(record) is dict and record['value'] is value)
  try:need(type(value) is kind and not record['failed']);guard(record)
  except BaseException as error:retain(record,'issued-boundary',error);deny()
  return record
 class SourceInputs:
  __slots__=()
  def recheck(self):
   record=issued(self)
   try:
    files,modes,metadata=maps(record)
    if record['maps'] is not None:
     old_files,old_modes,old_metadata=record['maps'];need(files is old_files and modes is old_modes and metadata is old_metadata)
    return self
   except BaseException as error:retain(record,'live-source-recheck',error);deny()
  def capture_inputs(self):
   record=issued(self)
   try:
    files,modes,metadata=maps(record)
    if record['data'] is not None:
     old_files,old_modes,old_metadata=record['maps'];need(files is old_files and modes is old_modes and metadata is old_metadata);return record['data']
    launch_bytes,launch_pins=selected(files,modes,launch,131072,262144,shell=True)
    package_bytes,package_pins=selected(files,modes,package,131072,262144)
    operational_bytes,op_pins=selected(files,modes,operational,8388608,16777216)
    catalog={path:dict(**op_pins[path],gitMode='100644') for path in operational};need(len(canonical(catalog))<=16384)
    for path in set(package)&set(operational):need(package_bytes[path] is operational_bytes[path] and package_pins[path]==op_pins[path])
    all_bytes={path:files[path] for path in required};all_modes={path:modes[path] for path in required}
    data=proxy(dict(scope='AUTHENTICATED_CLI_SOURCE_INPUT_DATA_ONLY',sourceFiles=proxy(all_bytes),sourceModes=proxy(all_modes),launchPins=proxy({path:proxy(pin) for path,pin in launch_pins.items()}),packagePins=proxy({path:proxy(pin) for path,pin in package_pins.items()}),operationalCatalog=proxy({path:proxy(row) for path,row in catalog.items()}),bootstrapRecords=proxy({path:package_bytes[path] for path in pair}),bootstrapPins=proxy({path:proxy(package_pins[path]) for path in pair}),fingerprint=metadata['signingKeyFingerprint'],releaseSha256=metadata['releaseSha256'],sourceObjectTransferred=False,initialOriginSelfAuthenticated=False,downstreamRegistryAuthenticated=False,downstreamOriginalSourceReauthenticationRequired=True,extraPrototypeHelpersAutomaticallyEnrolled=False,operationalCodeCompiled=False,executionEvidenceIssued=False,stageAcknowledged=False))
    record['data']=data;record['maps']=(files,modes,metadata);live(record);return data
   except BaseException as error:retain(record,'source-input-capture',error);deny()
  def require_helpers(self,paths):
   record=issued(self)
   try:
    need(type(paths) is tuple and 0<len(paths)<=16 and all(type(path) is str for path in paths) and len(set(paths))==len(paths))
    for path in paths:
     need(0<len(path)<=256 and path.isascii() and not path.startswith('/') and all(part not in ('','.', '..') and all(char.isascii() and (char.isalnum() or char in '_.-') for char in part) for part in path.split('/')))
    files,modes,metadata=maps(record);captures,pins=selected(files,modes,paths,131072,262144)
    answer=proxy(dict(scope='AUTHENTICATED_ADDITIONAL_HELPER_BYTES_DATA_ONLY',captures=proxy(captures),pins=proxy({path:proxy(pin) for path,pin in pins.items()}),sourceObjectTransferred=False,helperCodeCompiled=False,executionEvidenceIssued=False,stageAcknowledged=False));record['returns'].append(('helper-data',answer));live(record);return answer
   except BaseException as error:retain(record,'helper-input-capture',error);deny()
 kind=SourceInputs;kind_tables=tables(kind)
 def prepare_authenticated_cli_inputs(verifier_module,source,*,package_module,delivery_module,cli_module):
  nonlocal used
  need(not used and not failed and not retained and type(public) is list and not public)
  modules=tuple(capture(value) for value in (verifier_module,package_module,delivery_module,cli_module))
  for owner,name,expected in ((package_module,'PACKAGE_PATHS',package),(package_module,'OPERATIONAL_PATHS',operational),(delivery_module,'PACKAGE_PATHS',package),(delivery_module,'OPERATIONAL_PATHS',operational),(delivery_module,'LAUNCH_PATHS',launch),(cli_module,'LAUNCH_PATHS',launch)):
   actual=vars(owner).get(name);need(type(actual) is tuple and len(actual)==len(expected) and all(type(path) is str for path in actual));need(actual==expected)
  source_kind=vars(verifier_module).get('HeldPlatformSource');validator=vars(verifier_module).get('require_platform_source');need(type(source_kind) is type and type(source) is source_kind and type(validator) is fn and validator.__globals__ is vars(verifier_module))
  capture_maps=vars(verifier_module).get('capture_platform_source_maps');need(type(capture_maps) is fn and capture_maps.__globals__ is vars(verifier_module))
  getters={}
  for name in ('files','git_modes','metadata'):
   value=gettype(source_kind,'__dict__').get(name);need(type(value) is property and type(value.fget) is fn and value.fget.__globals__ is vars(verifier_module));getters[name]=value.fget
  error_tables=tables(error_kind);own_items=tuple(namespace.items());own_functions=tuple(function(value) for value in namespace.values() if type(value) is fn)
  record=dict(value=None,source=source,source_kind=source_kind,validator=validator,capture_maps=capture_maps,files_getter=getters['files'],modes_getter=getters['git_modes'],metadata_getter=getters['metadata'],modules=modules,error_tables=error_tables,own_items=own_items,own_functions=own_functions,functions=tuple(function(value) for value in (validator,capture_maps,*getters.values())),attempts=[],returns=[],maps=None,data=None,failed=False)
  used=True
  try:
   live(record);value=object.__new__(kind);record['value']=value;registry[id(value)]=record;value.capture_inputs();guard(record);return value
  except BaseException as error:retain(record,'source-input-prepare',error);deny()
 def main(argv=None):deny()
 return SourceInputs,prepare_authenticated_cli_inputs,main


SourceInputs,prepare_authenticated_cli_inputs,main=_factory(UNRELEASED,AuthenticatedInputsUnavailable,globals(),(type,dict,tuple,list,set,str,int,bool,bytes,len,all,any,vars,object,id,zip,BaseException,property,classmethod,staticmethod))
del _factory
