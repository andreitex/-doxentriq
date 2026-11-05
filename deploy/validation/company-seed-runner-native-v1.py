"""Disabled one fixed readonly SeedRunner observation; no native defaults.

Root independently authenticates the actual six-tool catalog, scope, initial
company station and loader. A catalog digest only binds bytes; it never proves
their company origin. No filesystem namespace, key/backing data or service
mutation is selected. Injected catalogs are never native provenance.
"""
import hashlib,json,math,re,stat,sys
from types import ModuleType

INPUT_PINS={
 'deploy/installer/company_seed_runner.py':{'sha256':'42af406862e9e2f6a81f436851453f525f1f35bf044fc0dc24708ee61fa21e17','bytes':25874},
 'scripts/company_source_guard_backend.py':{'sha256':'08819a69449f28c4b568d58930ead4bade0475726138fa039945f2365322126d','bytes':10600}}
TOOLS=('/usr/bin/systemctl','/usr/bin/docker','/usr/sbin/cryptsetup','/usr/sbin/losetup','/usr/bin/findmnt','/usr/sbin/xfs_quota')
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
PROPERTIES=('ActiveState','SubState','MainPID','ControlPID','ControlGroup','LoadState')
VECTOR=('/usr/bin/systemctl','show',*('--property='+p for p in PROPERTIES),'--','autosoft.service')
MAX_INPUT=131072;MAX_OUTPUT=16384;MAX_CATALOG=16384;MAX_SELECTED_TOOL=16*1024**2
UNKNOWN=[]
class Unavailable(ValueError):pass
def need(value):
 if value is not True:raise Unavailable('seed-runner-native-unavailable')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()+b'\n'
def decode(raw,maximum):
 need(type(raw) is bytes and 0<len(raw)<=maximum)
 def pairs(items):
  answer={}
  for k,v in items:need(k not in answer);answer[k]=v
  return answer
 answer=json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=lambda _:need(False));need(canonical(answer)==raw);return answer
def scope(raw,wall,*,allow_disabled=False):
 v=decode(raw,8192)
 need(type(v) is dict and set(v)=={'schemaVersion','status','nativeOneAttempt','operationId','notBefore','expiresAt','maxAttempts','maxSeconds','maxInputBytes','maxOutputBytes','maxFds','toolCatalogSha256','sourcePinsSha256','commandSha256'})
 need(type(v['operationId']) is str and re.fullmatch('[a-f0-9]{32}',v['operationId']) is not None)
 for k,x in dict(schemaVersion=1,maxAttempts=1,maxSeconds=70,maxInputBytes=MAX_INPUT,maxOutputBytes=MAX_OUTPUT,maxFds=96).items():need(type(v[k]) is int and v[k]==x)
 need(type(v['notBefore']) is int and type(v['expiresAt']) is int and type(wall) in (int,float) and math.isfinite(wall))
 disabled=v['status']=='DISABLED_SOURCE_PROPOSAL' and v['nativeOneAttempt'] is False and v['operationId']=='0'*32 and v['notBefore']==v['expiresAt']==0
 need((allow_disabled and disabled) or (v['status']=='ROOT_AUTHORIZED_ONE_READONLY_SEED_RUNNER_PROBE' and v['nativeOneAttempt'] is True and v['operationId']!='0'*32 and v['notBefore']<=wall and 100<v['expiresAt']-wall<=1800))
 need(type(v['toolCatalogSha256']) is str and re.fullmatch('[a-f0-9]{64}',v['toolCatalogSha256']) is not None
  and v['sourcePinsSha256']==sha(canonical(INPUT_PINS)) and v['commandSha256']==sha(canonical(list(VECTOR))))
 return v
def catalog(raw,independent_digest):
 need(type(independent_digest) is str and re.fullmatch('[a-f0-9]{64}',independent_digest) is not None and type(raw) is bytes and sha(raw)==independent_digest)
 v=decode(raw,MAX_CATALOG)
 # Scope schema1 fixes the independently selected six-path catalog; the input
 # cannot choose its coverage, version, executable or command family.
 need(type(v) is dict and set(v)==set(TOOLS))
 for path,row in v.items():
  need(type(row) is dict and set(row)=={'sha256','bytes','identity'} and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256']) is not None
   and type(row['bytes']) is int and 64<=row['bytes']<=128*1024**2 and type(row['identity']) is dict and set(row['identity'])==set(FIELDS)
   and all(type(x) is int and x>=0 for x in row['identity'].values()))
  m=row['identity'];need(stat.S_ISREG(m['st_mode']) and stat.S_IMODE(m['st_mode']) in (0o500,0o555,0o755) and m['st_uid']==m['st_gid']==0 and m['st_nlink']==1 and m['st_size']==row['bytes'])
 need(v[VECTOR[0]]['bytes']<=MAX_SELECTED_TOOL);return v
def sources_admission(value):
 need(type(value) is dict and set(value)==set(INPUT_PINS) and all(type(v) is bytes for v in value.values()) and sum(len(v) for v in value.values())<=MAX_INPUT)
 for path,row in INPUT_PINS.items():need((sha(value[path]),len(value[path]))==(row['sha256'],row['bytes']))
def projected(raw):
 need(type(raw) is bytes and 0<len(raw)<=4096)
 pairs=[]
 for line in raw.decode('ascii').splitlines():
  name,sep,value=line.partition('=');need(bool(sep) and name in PROPERTIES and len(value)<=512 and all(32<=ord(c)<=126 for c in value));pairs.append((name,value))
 need(len(pairs)==6 and len({p for p,v in pairs})==6);v=dict(pairs)
 for name in ('MainPID','ControlPID'):need(re.fullmatch('0|[1-9][0-9]{0,9}',v[name]) is not None and int(v[name])<2**31)
 return v

class NativeStation:
 """Explicit independently trusted primitive modules; one owned memfd lift.

 The original runner owns all proc/tool/pidfd/pipe resources. This small wrapper
 additionally owns exact memfd population references and FSIZE restoration.
 Soft FSIZE is zero outside bounded population; no ordinary write is admitted.
 Initial kernel/loader/library semantics and actual capacity remain external.
 """
 def __init__(self,*,os_module,sys_module,subprocess_module,select_module,signal_module,io_module,fcntl_module,resource_module,clock,wall,started=None):
  need(all(type(m) is ModuleType for m in (os_module,sys_module,subprocess_module,select_module,signal_module,io_module,fcntl_module,resource_module)) and callable(clock) and callable(wall))
  self.modules=(os_module,sys_module,subprocess_module,select_module,signal_module,io_module,fcntl_module,resource_module)
  self.clock,self.wall=clock,wall;self.runner=None;self.memfds={};self.attempted=set();self.finished=False;self.catalog_bound=False;self.pid_scope=None
  value=clock() if started is None else started;need(type(value) in (int,float) and math.isfinite(value));self.end=value+70
  self.saved={k:getattr(os_module,k) for k in ('memfd_create','write','close','fstat')};self.limits={k:getattr(resource_module,k) for k in ('getrlimit','setrlimit','RLIMIT_FSIZE')}
  need(all(callable(self.saved[k]) for k in self.saved) and callable(self.limits['getrlimit']) and callable(self.limits['setrlimit']) and type(self.limits['RLIMIT_FSIZE']) is int)
  self.os=ModuleType('explicit_seed_runner_probe_os');self.os.__dict__.update(vars(os_module))
  records,attempted,raw=self.memfds,self.attempted,self.saved;limits=self.limits;owner=self;unknowns=UNKNOWN
  def own_memfd(name,flags):
   need(self.catalog_bound and not records and not attempted and not unknowns)
   fd=raw['memfd_create'](name,flags)
   if not(type(fd) is int and 0<=fd<2**31 and fd not in records):unknowns.append((owner,'memfd-result',fd,raw['close']));raise Unavailable()
   records[fd]=dict(identity=None,written=0,attempted=False)
   info=raw['fstat'](fd);need(stat.S_ISREG(info.st_mode) and info.st_nlink==0 and info.st_uid==info.st_gid==0 and info.st_size==0)
   records[fd]['identity']=(info.st_dev,info.st_ino,info.st_uid,info.st_gid);return fd
  def bounded_write(fd,data):
   need(type(fd) is int and fd in records and fd not in attempted and type(data) is bytes and 0<len(data)<=65536 and records[fd]['written']+len(data)<=self.selected_bytes and not unknowns)
   row=records[fd];info=raw['fstat'](fd);need(row['identity']==(info.st_dev,info.st_ino,info.st_uid,info.st_gid) and stat.S_ISREG(info.st_mode) and info.st_nlink==0 and info.st_size==row['written'])
   before=limits['getrlimit'](limits['RLIMIT_FSIZE']);need(before==(0,self.selected_bytes))
   error=None;amount=None
   try:
    limits['setrlimit'](limits['RLIMIT_FSIZE'],(self.selected_bytes,self.selected_bytes));amount=raw['write'](fd,data)
    need(type(amount) is int and 0<amount<=len(data));row['written']+=amount
   except BaseException as e:error=e
   finally:
    try:limits['setrlimit'](limits['RLIMIT_FSIZE'],before);need(limits['getrlimit'](limits['RLIMIT_FSIZE'])==before)
    except BaseException as e:unknowns.append((owner,'memfd-fsize-restoration',fd,before,limits,e));error=e
   if error is not None:raise error
   return amount
  def known_close(fd):
   need(type(fd) is int and fd>=0)
   if fd in records:
    need(fd not in attempted);attempted.add(fd);records[fd]['attempted']=True
   try:need(raw['close'](fd) is None)
   except BaseException as e:unknowns.append((owner,'raw-close',fd,records,attempted,raw['close'],e));raise
   if fd in records:del records[fd];attempted.remove(fd)
  self.memfd_close_original=known_close
  self.os.memfd_create,self.os.write,self.os.close=own_memfd,bounded_write,known_close
 def prepare(self,SR,BK,tools):
  need(not UNKNOWN and tuple(SR.TOOLS)==TOOLS and all(BK.absolute(p)==p for p in TOOLS))
  self.selected_bytes=tools[VECTOR[0]]['bytes'];self.catalog_bound=True
  resource=self.modules[-1];signal=self.modules[4]
  for which,value in ((resource.RLIMIT_AS,(268435456,268435456)),(resource.RLIMIT_CPU,(60,61)),(resource.RLIMIT_NOFILE,(96,96)),(resource.RLIMIT_FSIZE,(0,self.selected_bytes)),(resource.RLIMIT_CORE,(0,0))):resource.setrlimit(which,value)
  def expired(*_):raise Unavailable('seed-runner-native-deadline')
  signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,max(.001,self.end-self.clock()))
  self.signal=signal;self.alarm=True
  self.runner=SR.SeedRunner(tool_catalog=tools,data_directory='/srv/autosoft/validation/unused-seed-runner-data',storage_file='/var/lib/unused-seed-runner-backing',
   budget=dict(calls=1,seconds=min(60,int(self.end-self.clock())-1),toolReadBytes=8*self.selected_bytes+8,outputBytes=131072),os_module=self.os,sys_module=self.modules[1],subprocess_module=self.modules[2],select_module=self.modules[3],signal_module=signal,io_module=self.modules[5],fcntl_module=self.modules[6],clock=self.clock,station_contract=SR.STATION_CONTRACT)
  need(self.runner.require_released() is self.runner)
 def observe(self,SR):
  need(self.runner is not None and self.limits['getrlimit'](self.limits['RLIMIT_FSIZE'])==(0,self.selected_bytes) and not UNKNOWN)
  result=self.runner.run(list(VECTOR),stdin=None,maximum=65536,timeout=60,tool=None,environment=dict(SR.ENV))
  need(type(result) is dict and set(result)=={'exitCode','stdout','stderr','ownedReleased'} and type(result['exitCode']) is int and result['exitCode']==0 and result['ownedReleased'] is True and result['stderr']==b'')
  return result
 def finish(self):
  if self.finished:need(not UNKNOWN);return
  self.finished=True
  if self.runner is not None:
   try:need(self.runner.require_released() is self.runner)
   except BaseException as e:UNKNOWN.append((self,'runner-release',self.runner,e))
  for fd in reversed(tuple(self.memfds)):
   if fd in self.attempted:continue
   try:self.memfd_close_original(fd)
   except BaseException as e:UNKNOWN.append((self,'unreturned-memfd-release',fd,self.memfds,self.attempted,self.saved,e))
  if self.memfds or self.attempted:UNKNOWN.append((self,'memfd-release',self.memfds,self.attempted,self.saved))
  if self.catalog_bound:
   try:need(self.limits['getrlimit'](self.limits['RLIMIT_FSIZE'])==(0,self.selected_bytes))
   except BaseException as e:UNKNOWN.append((self,'fsize-final',self.limits,e))
  if getattr(self,'alarm',False):
   try:self.signal.setitimer(self.signal.ITIMER_REAL,0);self.alarm=False
   except BaseException as e:UNKNOWN.append((self,'alarm-release',e))
  need(self.clock()<self.end)
  need(not UNKNOWN)

def run(scope_raw,catalog_raw,sources,*,station):
 owned=[];error=None;phase='source-catalog-admission';result=None
 try:
  need(not UNKNOWN);sources_admission(sources);v=scope(scope_raw,station.wall());tools=catalog(catalog_raw,v['toolCatalogSha256']);phase='compile'
  for i,name in enumerate(INPUT_PINS):
   m=ModuleType('seed_runner_probe_'+v['operationId']+'_'+str(i));m.__file__='<pinned '+name+'>';need(m.__name__ not in sys.modules);sys.modules[m.__name__]=m;owned.append(m)
   exec(compile(sources[name],m.__file__,'exec'),vars(m))
  SR,BK=owned;phase='prepare';station.prepare(SR,BK,tools);phase='readonly-vector';observed=station.observe(SR);fields=projected(observed['stdout']);phase='release';station.finish()
  need(not SR.UNRELEASED and not BK.UNRELEASED_RESOURCES)
  result=dict(schemaVersion=1,status='NATIVE_READONLY_SEED_RUNNER_OBSERVED_ONLY',operationId=v['operationId'],toolCatalogSha256=v['toolCatalogSha256'],command=list(VECTOR),commandCalls=1,
   fields=fields,stdoutSha256=sha(observed['stdout']),stdoutBytes=len(observed['stdout']),stderrBytes=0,exitCode=0,allOwnedResourcesKnownReleased=True,
   dynamicLoaderQualified=False,toolOriginSelfAuthenticated=False,serviceAbsenceQualified=False,parentAuthorityQualified=False,storageAuthorityQualified=False,nativeCapacityQualified=False,installerActivated=False,automaticRetry=False)
 except BaseException as e:
  error=e
  try:station.finish()
  except BaseException:pass
 finally:
  for m in reversed(owned):
   if sys.modules.get(m.__name__) is m and not UNKNOWN:del sys.modules[m.__name__]
   else:UNKNOWN.append(('module-release',m));result=None
 if error is not None or UNKNOWN:result=dict(schemaVersion=1,status='NATIVE_READONLY_SEED_RUNNER_UNAVAILABLE',phase=phase,errorClass=type(error).__name__ if error else 'UnknownRelease',allOwnedResourcesKnownReleased=not UNKNOWN,unknownCount=len(UNKNOWN),automaticRetry=False)
 need(len(canonical(result))<=MAX_OUTPUT);return result
