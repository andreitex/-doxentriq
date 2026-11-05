"""Original CLI record DATA reader, with no IO, issuer, native defaults or ACK.

The caller must independently authenticate the original CLI module before
preparing this reader, and prepare it before performing the stage. A supplied
ModuleType or a matching serialized flag is not that initial authentication.
Only the original completed_record method establishes its in-process closure.
The result cannot establish original Bash disposition or cross-process trust.
"""
import hashlib,json,re
from types import FunctionType,MappingProxyType,ModuleType

MAX_RECORD=32768
MAX_READERS=64
COMMANDS=('describe','plan-stage','execute-stage','verify-stage')
UNRELEASED=[]
class RecordUnavailable(ValueError):pass

def _factory(unknown,issued,error_type):
 maximum=MAX_RECORD;limit=MAX_READERS;commands=COMMANDS
 proxy=MappingProxyType;module_kind=ModuleType;function_kind=FunctionType
 raw_hash=hashlib.sha256;raw_loads=json.loads;raw_dumps=json.dumps;match=re.fullmatch
 def prepare_record_reader(cli_module,*,expected_command):
  """Capture the trusted original method before effects; consume once only."""
  exception=error_type;ledger=unknown;registry=issued
  def need(value):
   if value is not True:raise exception('company-cli-record-unavailable')
  need(type(ledger) is list and not ledger and type(registry) is list and len(registry)<limit)
  need(type(cli_module) is module_kind and type(expected_command) is str and expected_command in commands)
  namespace=dict(vars(cli_module));kind=namespace.get('CliObservation')
  need(type(kind) is type)
  methods=dict(vars(kind));method=methods.get('completed_record')
  need(type(method) is function_kind and method.__globals__ is vars(cli_module))
  namespace_items=tuple(namespace.items());method_items=tuple(methods.items())
  used=False
  def check():
   current=dict(vars(cli_module))
   need(set(current)==set(namespace) and all(current[k] is v for k,v in namespace_items))
   current_methods=dict(vars(kind))
   need(set(current_methods)==set(methods) and all(current_methods[k] is v for k,v in method_items))
  def read_completed(observation):
   nonlocal used
   need(not ledger and not used);used=True
   raw=None;second=None;state=None
   try:
    check();need(type(observation) is kind)
    state=object.__getattribute__(observation,'__dict__');need(type(state) is dict)
    raw=method(observation);check()
    need(type(raw) is bytes and 0<len(raw)<=maximum)
    second=method(observation);check();need(type(second) is bytes and second==raw)
    def pairs(items):
     result={}
     for k,v in items:need(type(k) is str and k not in result);result[k]=v
     return result
    value=raw_loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=lambda _:need(False))
    need(type(value) is dict and set(value)=={'schemaVersion','scope','command','deliveryIdentitySha256','binding','planBase64','result','outcomeSha256','stageAcknowledged','fullInstallationCompleted','nativeQualified'})
    need(type(value['schemaVersion']) is int and value['schemaVersion']==1 and value['scope']=='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY'
     and type(value['command']) is str and value['command']==expected_command and type(value['binding']) is dict
     and type(value['deliveryIdentitySha256']) is str and match('[a-f0-9]{64}',value['deliveryIdentitySha256']) is not None
     and value['stageAcknowledged'] is False and value['fullInstallationCompleted'] is False and value['nativeQualified'] is False)
    encoded=raw_dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'
    need(encoded==raw);check()
    return proxy(dict(scope='ORIGINAL_CLI_COMPLETION_RECORD_DATA_ONLY',record=raw,sha256=raw_hash(raw).hexdigest(),bytes=len(raw),command=expected_command,
     crossProcessEvidenceIssued=False,parentTerminalQualified=False,stageAcknowledged=False,installerActivated=False))
   except BaseException as error:
    # Preserve the actual original observation/owner and failed references.
    # This reader owns no descriptors and never guesses cleanup or retries.
    ledger.append((cli_module,kind,method,namespace_items,method_items,observation,state,raw,second,error))
    raise exception('company-cli-record-unavailable') from None
  registry.append(read_completed)
  return read_completed
 return prepare_record_reader

prepare_record_reader=_factory(UNRELEASED,[],RecordUnavailable)
del _factory
