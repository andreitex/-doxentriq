"""Disabled synthetic SeedBackend probe; only a separately admitted fresh root.

The initial company interpreter, OS/libc and root grant are external trust.
No original Store/Source operation, parent, storage authority, key or service
is selected. Numeric FD/disk/time admission is not a reservation guarantee.
"""
import hashlib,json,math,re,stat,sys,time
from pathlib import PurePosixPath
from types import ModuleType

INPUT_PINS={
 'deploy/installer/company_seed_backend.py':{'sha256':'ae7be5f73b5e279cde64f12bf031d0cb84576ac045f90e423775a093891fe768','bytes':28806},
 'scripts/company_source_guard_backend.py':{'sha256':'08819a69449f28c4b568d58930ead4bade0475726138fa039945f2365322126d','bytes':10600}}
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
VALIDATION='/srv/autosoft/validation'
PREFIX=VALIDATION+'/company-seed-backend-native-v3-'
DM_UUID=b'CRYPT-LUKS2-c23ab55044ff410ab15fa1a9640080f0-autosoft-data\n'
RELEASE='b'*64
MAX_INPUT=131072;MAX_OUTPUT=16384;MAX_WRITES=262144;MAX_PREPARER_FDS=32
# Three is an admission ceiling: exactly two Source subdirectories are created;
# one refused existing-directory attempt must reach mkdir before the count gate.
BUDGET=dict(sourceFiles=4,sourceDirectories=3,ownedFds=128,externalFdReserve=64,seconds=60,readBytes=1048576,writeBytes=65536)
STORE_NAMES=('approved-mirrors.json','images.lock.json','runtime-manifest.json','company-sources.json','company-deployment.json','platform-sources.json','release.json','release.sig','company-signing-public-key.pem','platform-sources.tar.gz','intent.json','verified.json')
SOURCE_FILES={'scripts/alpha.py':b'# inert synthetic alpha\n','scripts/beta.py':b'# inert synthetic beta\n','assets/data.json':b'{"synthetic":true}\n'}
UNKNOWN=[]
class Unavailable(ValueError):pass
def need(value):
 if value is not True:raise Unavailable('seed-backend-native-unavailable')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()+b'\n'
def decode(raw,maximum):
 need(type(raw) is bytes and 0<len(raw)<=maximum)
 def pairs(items):
  answer={}
  for name,value in items:need(name not in answer);answer[name]=value
  return answer
 value=json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=lambda _:need(False))
 need(canonical(value)==raw);return value
def validate_scope(raw,wall,*,allow_disabled=False):
 v=decode(raw,8192)
 need(type(v) is dict and set(v)=={'schemaVersion','status','nativeOneAttempt','operationId','root','notBefore','expiresAt','maxAttempts','maxSeconds','maxInputBytes','maxOutputBytes','maxWriteBytes','maxFds','deviceMajorMinor','dmUuid','inputPinsSha256','releaseSha256'})
 need(type(v['operationId']) is str and re.fullmatch('[a-f0-9]{32}',v['operationId']) is not None and v['root']==PREFIX+v['operationId'])
 for key,expected in dict(schemaVersion=1,maxAttempts=1,maxSeconds=60,maxInputBytes=MAX_INPUT,maxOutputBytes=MAX_OUTPUT,maxWriteBytes=MAX_WRITES,maxFds=192).items():need(type(v[key]) is int and v[key]==expected)
 need(type(v['notBefore']) is int and type(v['expiresAt']) is int and type(wall) in (int,float) and math.isfinite(wall))
 disabled=v['status']=='DISABLED_SOURCE_PROPOSAL' and v['nativeOneAttempt'] is False and v['operationId']=='0'*32 and v['notBefore']==v['expiresAt']==0
 need((allow_disabled and disabled) or (v['status']=='ROOT_AUTHORIZED_ONE_SYNTHETIC_SEED_BACKEND_PROBE' and v['nativeOneAttempt'] is True and v['operationId']!='0'*32 and v['notBefore']<=wall and 90<v['expiresAt']-wall<=1800))
 need(type(v['deviceMajorMinor']) is list and all(type(x) is int for x in v['deviceMajorMinor']) and v['deviceMajorMinor']==[253,3]
  and v['dmUuid']==DM_UUID.decode() and v['inputPinsSha256']==sha(canonical(INPUT_PINS)) and v['releaseSha256']==RELEASE)
 return v
def source_admission(sources):
 need(type(sources) is dict and set(sources)==set(INPUT_PINS) and all(type(v) is bytes for v in sources.values()) and sum(len(v) for v in sources.values())<=MAX_INPUT)
 for name,row in INPUT_PINS.items():need(type(sources[name]) is bytes and (sha(sources[name]),len(sources[name]))==(row['sha256'],row['bytes']))
def request_for(scope):
 return dict(schemaVersion=1,mode='full-installation',operationId=scope['operationId'],releaseSha256=RELEASE,
  bundleRoot='/opt/autosoft-company/incoming/unused-seed-backend-bundle',sourceRoot='/opt/autosoft-company/incoming/unused-seed-backend-source',
  keyPath='/opt/autosoft-company/bootstrap/unused-company.pem',dataDir=scope['root']+'/data',backingFile=scope['root']+'/unused-backing-metadata',capacityGiB=32,runscVersion='20260101.1',runscSha512='c'*128)
def expected_leaves():
 store={name:canonical(dict(scope='SYNTHETIC_SEED_BACKEND_SHAPE_ONLY',leaf=name)) for name in STORE_NAMES}
 source={'intent.json':b'{"syntheticIntent":true}\n','verified.json':b'{"syntheticVerified":true}\n',**{'source/'+p:raw for p,raw in SOURCE_FILES.items()}}
 return store,source

def mapper_device(info,device):
 # Fixed root:disk (GID6) block identity observed by the separate Root reader.
 # This accepts no other group, UID, file type or device number.
 need(type(device) is int and device>=0 and all(type(getattr(info,k,None)) is int for k in ('st_mode','st_uid','st_gid','st_rdev'))
  and stat.S_ISBLK(info.st_mode) and info.st_uid==0 and info.st_gid==6 and info.st_rdev==device)

class NativeStation:
 """Explicit root-only IO; every preparer open is registered before checks."""
 def __init__(self,*,os_module,sys_module,ctypes_module,libc,machine_module,resource_module,signal_module,clock,wall,started=None):
  self.os,self.sys,self.ctypes,self.libc,self.machine=os_module,sys_module,ctypes_module,libc,machine_module
  self.resource,self.signal,self.clock,self.wall=resource_module,signal_module,clock,wall
  self.end=(clock() if started is None else started)+60
  self.calls={k:getattr(os_module,k) for k in ('open','close','lstat','fstat','get_inheritable','pread','write','fsync','fchmod','mkdir','fstatvfs','readlink','getpid')}
  self.raw_close=self.calls['close'];self.owned={};self.attempted=set();self.records={};self.written=0;self.peak=0;self.alarm=False;self.fixtureCreated=False;self.effectAttempted=False;self.adapters=[]
  self.new_dirs=[];self.mutable_parents=set();self.input_raws={};self.finished=False
 def tick(self):need(self.clock()<self.end-5)
 def meta(self,value):
  row={k:getattr(value,k,None) for k in FIELDS};need(all(type(v) is int and v>=0 for v in row.values()));return row
 def open(self,*args,**kwargs):
  self.tick();need(len(self.owned)<MAX_PREPARER_FDS);fd=self.calls['open'](*args,**kwargs)
  if not(type(fd) is int and 0<=fd<2**31 and fd not in self.owned and fd not in self.attempted):UNKNOWN.append((self,'open-result',fd,self.raw_close));raise Unavailable()
  self.owned[fd]=args;self.peak=max(self.peak,len(self.owned));need(self.calls['get_inheritable'](fd) is False);return fd
 def close(self,fd):
  need(type(fd) is int and fd in self.owned and fd not in self.attempted);self.attempted.add(fd)
  try:need(self.raw_close(fd) is None)
  except BaseException:UNKNOWN.append((self,'preparer-close',fd,self.raw_close));raise
  del self.owned[fd];self.attempted.remove(fd)
 def hold(self,path,directory,mode=None):
  if path in self.records:return self.records[path][0]
  self.tick();parent=None if path=='/' else self.hold(str(PurePosixPath(path).parent),True)
  before=self.meta(self.calls['lstat'](path));need(before['st_uid']==before['st_gid']==0 and not stat.S_IMODE(before['st_mode'])&0o022
   and stat.S_IFMT(before['st_mode'])==(stat.S_IFDIR if directory else stat.S_IFREG) and (directory or before['st_nlink']==1)
   and (mode is None or stat.S_IMODE(before['st_mode'])==mode))
  flags=self.os.O_RDONLY|self.os.O_NOFOLLOW|self.os.O_CLOEXEC|(self.os.O_DIRECTORY if directory else self.os.O_NONBLOCK)
  fd=self.open('/' if parent is None else PurePosixPath(path).name,flags,**({} if parent is None else {'dir_fd':parent}))
  need(before==self.meta(self.calls['fstat'](fd))==self.meta(self.calls['lstat'](path)));self.records[path]=(fd,before);return fd
 def check(self):
  for path,(fd,before) in self.records.items():
   current=self.meta(self.calls['fstat'](fd));need(current==self.meta(self.calls['lstat'](path)))
   if path in self.mutable_parents:
    need(all(current[k]==before[k] for k in FIELDS[:5]) and current['st_nlink'] in (before['st_nlink'],before['st_nlink']+1))
   else:need(before==current)
  for path,raw in self.input_raws.items():need(self.calls['pread'](self.records[path][0],len(raw)+1,0)==raw)
 def refresh(self,path,before,*,nlink=0):
  fd=self.records[path][0];current=self.meta(self.calls['fstat'](fd));need(current==self.meta(self.calls['lstat'](path))
   and all(current[k]==before[k] for k in FIELDS[:5]) and current['st_nlink']==before['st_nlink']+nlink)
  self.records[path]=(fd,current);self.check()
 def mkdir(self,parent,name):
  self.check();before=dict(self.records[parent][1]);self.effectAttempted=True
  need(self.calls['mkdir'](name,0o700,dir_fd=self.records[parent][0]) is None)
  self.refresh(parent,before,nlink=1);path=parent+'/'+name;fd=self.hold(path,True,0o700);self.new_dirs.append(path);need(self.calls['fsync'](self.records[parent][0]) is None);return path,fd
 def put(self,parent,name,raw):
  self.check();need(type(raw) is bytes and 0<len(raw)<=65536 and self.written+len(raw)<=MAX_INPUT+8192)
  before=dict(self.records[parent][1]);self.effectAttempted=True
  fd=self.open(name,self.os.O_RDWR|self.os.O_CREAT|self.os.O_EXCL|self.os.O_NOFOLLOW|self.os.O_CLOEXEC|self.os.O_NONBLOCK,0o400,dir_fd=self.records[parent][0])
  need(self.calls['fchmod'](fd,0o400) is None);offset=0
  while offset<len(raw):
   self.tick();n=self.calls['write'](fd,raw[offset:offset+65536]);need(type(n) is int and 0<n<=len(raw)-offset);offset+=n;self.written+=n
  need(self.calls['fsync'](fd) is None and self.calls['fsync'](self.records[parent][0]) is None)
  self.close(fd);self.refresh(parent,before);self.hold(parent+'/'+name,False,0o400);self.input_raws[parent+'/'+name]=raw
 def small(self,path,maximum):
  fd=self.hold(path,False);before=self.records[path][1];raw=self.calls['pread'](fd,maximum+1,0)
  need(type(raw) is bytes and 0<len(raw)<=maximum);self.check();return raw
 def prepare(self,scope,sources,scope_raw):
  o,r,s=self.os,self.resource,self.signal
  need(o.name=='posix' and self.sys.platform=='linux' and self.sys.byteorder=='little' and self.machine.machine()=='x86_64' and o.getresuid()==o.getresgid()==(0,0,0))
  for which,bounds in ((r.RLIMIT_AS,(268435456,268435456)),(r.RLIMIT_CPU,(60,61)),(r.RLIMIT_NOFILE,(192,192)),(r.RLIMIT_FSIZE,(262144,262144)),(r.RLIMIT_CORE,(0,0))):r.setrlimit(which,bounds)
  def expired(*_):raise Unavailable('seed-backend-native-deadline')
  s.signal(s.SIGALRM,expired);s.setitimer(s.ITIMER_REAL,max(.001,self.end-self.clock()));self.alarm=True
  validation=self.hold(VALIDATION,True);info=self.calls['fstat'](validation);need([o.major(info.st_dev),o.minor(info.st_dev)]==[253,3])
  rows=[]
  for line in self.small('/proc/'+str(self.calls['getpid']())+'/mountinfo',65536).decode('ascii').splitlines():
   left,sep,right=line.partition(' - ');a,b=left.split(),right.split();need(bool(sep) and len(a)>=6 and len(b)>=3)
   if a[4]=='/srv/autosoft':rows.append((a,b))
  need(len(rows)==1);a,b=rows[0];need(a[2]=='253:3' and a[3]=='/' and {'rw','nosuid','nodev'}<=set(a[5].split(',')) and b[0]=='xfs' and b[1]=='/dev/mapper/autosoft-data')
  need(self.calls['readlink']('/dev/mapper/autosoft-data')=='../dm-3')
  target=self.calls['lstat']('/dev/dm-3');mapper_device(target,info.st_dev)
  dev=self.open('/dev/dm-3',o.O_PATH|o.O_NOFOLLOW|o.O_CLOEXEC)
  need(self.meta(target)==self.meta(self.calls['fstat'](dev))==self.meta(self.calls['lstat']('/dev/dm-3')) and self.calls['fstat'](dev).st_rdev==target.st_rdev);self.close(dev)
  need(self.small('/sys/devices/virtual/block/dm-3/dm/uuid',128)==DM_UUID)
  space=self.calls['fstatvfs'](validation);need(type(space.f_bavail) is int and type(space.f_frsize) is int and space.f_bavail*space.f_frsize>=MAX_WRITES*2)
  # Close unrelated readonly proc/sys ancestry before the first fresh write.
  for path,(fd,_) in reversed(tuple(self.records.items())):
   if not (path==VALIDATION or path in ('/','/srv','/srv/autosoft')):self.close(fd);del self.records[path]
  root,_=self.mkdir(VALIDATION,PurePosixPath(scope['root']).name);self.fixtureCreated=True
  self.put(root,'scope.json',scope_raw);inputs,_=self.mkdir(root,'inputs')
  for index,(name,raw) in enumerate(sorted(sources.items())):self.put(inputs,str(index)+'.source',raw)
  self.data,_=self.mkdir(root,'data');company,_=self.mkdir(self.data,'company')
  self.mkdir(company,'platform-releases');self.mkdir(company,'source-releases')
  self.check();self.mutable_parents={company+'/platform-releases',company+'/source-releases'}
 def release_preparer(self):
  failures=[]
  for fd in reversed(tuple(self.owned)):
   if fd in self.attempted:continue
   try:self.close(fd)
   except BaseException as e:failures.append((fd,e))
  self.records={}
  if failures or self.owned or self.attempted:UNKNOWN.append((self,'preparer-release',tuple(failures),self.owned,self.attempted,self.raw_close))
  need(not UNKNOWN)
 def adapter(self,SB,BK,scope):
  self.check()
  dents=BK.LinuxAMD64Getdents64(ctypes_module=self.ctypes,libc=self.libc,sys_module=self.sys,machine_module=self.machine)
  adapter=SB.SeedBackend(request_value=request_for(scope),budget=dict(BUDGET),os_module=self.os,sys_module=self.sys,read_backend_module=BK,getdents64=dents,clock=self.clock)
  self.adapters.append(adapter);need(adapter.require_released() is adapter);return adapter
 def seal(self):
  self.check()
  for path in reversed(self.new_dirs):
   fd,before=self.records[path];current=self.meta(self.calls['fstat'](fd));need(current==self.meta(self.calls['lstat'](path)))
   if path in self.mutable_parents:need(current['st_nlink']==before['st_nlink']+1)
   need(self.calls['fchmod'](fd,0o500) is None and self.calls['fsync'](fd) is None)
   after=self.meta(self.calls['fstat'](fd));need(after==self.meta(self.calls['lstat'](path)) and stat.S_IMODE(after['st_mode'])==0o500
    and all(after[k]==current[k] for k in FIELDS if k not in ('st_mode','st_ctime_ns')))
   self.records[path]=(fd,after);self.mutable_parents.discard(path)
  self.check()
 def finish(self):
  if self.finished:need(not UNKNOWN);return
  self.finished=True
  self.release_preparer()
  for adapter in self.adapters:
   try:need(adapter.require_released() is adapter)
   except BaseException as e:UNKNOWN.append((self,'adapter-release',adapter,e))
  if self.alarm:
   try:self.signal.setitimer(self.signal.ITIMER_REAL,0);self.alarm=False
   except BaseException as e:UNKNOWN.append((self,'alarm-release',e))
  need(not UNKNOWN)

def exercise(adapter,store,source):
 owned=[]
 def keep(fd):owned.append(fd);need(adapter.inheritable(fd) is False);return fd
 def put(parent,name,raw):
  fd=keep(adapter.create(parent,name,0,0,0o400));offset=0
  while offset<len(raw):n=adapter.write(fd,raw[offset:]);need(type(n) is int and 0<n<=len(raw)-offset);offset+=n
  need(adapter.sync(fd) is None and adapter.sync(parent) is None)
 try:
  base=keep(adapter.open(adapter.store_parent,'directory'));need(adapter.names(base,0)==[])
  root=keep(adapter.mkdir(base,RELEASE,0,0,0o700))
  for name,raw in store.items():put(root,name,raw)
  need(adapter.names(root,12)==sorted(store));need(adapter.chmod(root,0o500) is None and adapter.sync(root) is None)
  parent=keep(adapter.open(adapter.source_parent,'directory'));need(adapter.names(parent,0)==[])
  source_root=keep(adapter.mkdir(parent,RELEASE,0,0,0o700))
  for name in ('intent.json','verified.json'):put(source_root,name,source[name])
  tree=keep(adapter.mkdir(source_root,'source',0,0,0o700));dirs={}
  for name in ('scripts','assets'):dirs[name]=keep(adapter.mkdir(tree,name,0,0,0o700))
  for name,raw in SOURCE_FILES.items():parent,name=name.split('/');put(dirs[parent],name,raw)
  for fd in (*dirs.values(),tree,source_root):need(adapter.chmod(fd,0o500) is None and adapter.sync(fd) is None)
 finally:
  failures=[]
  for fd in reversed(owned):
   try:need(adapter.close(fd) is None)
   except BaseException as e:failures.append((adapter,fd,e))
  if failures:UNKNOWN.extend(failures)
 need(not UNKNOWN and adapter.require_released() is adapter)
 # One deliberately refused conflicting mkdir; preserve this same-run fixture.
 parent=adapter.open(adapter.store_parent,'directory');refused=False
 try:
  try:adapter.mkdir(parent,RELEASE,0,0,0o700)
  except FileExistsError:refused=True
 finally:
  try:need(adapter.close(parent) is None)
  except BaseException as e:UNKNOWN.append((adapter,'conflict-parent',parent,e))
 need(refused and not UNKNOWN and adapter.require_released() is adapter)

def readback(adapter,store,source):
 owned=[];rows={};dirs={adapter.store_parent:[RELEASE],adapter.store_root:sorted(store),adapter.source_parent:[RELEASE],adapter.source_root:['intent.json','source','verified.json'],adapter.source_root+'/source':['assets','scripts'],adapter.source_root+'/source/assets':['data.json'],adapter.source_root+'/source/scripts':['alpha.py','beta.py']}
 try:
  for path,names in dirs.items():
   fd=adapter.open(path,'directory');owned.append(fd);before=adapter.lstat(path);need(before==adapter.fstat(fd))
   need(stat.S_IMODE(before['st_mode'])==(0o700 if path in (adapter.store_parent,adapter.source_parent) else 0o500) and adapter.names(fd,len(names))==names)
   need(before==adapter.lstat(path)==adapter.fstat(fd))
  for root,files in ((adapter.store_root,store),(adapter.source_root,source)):
   for name,raw in files.items():
    path=root+'/'+name;fd=adapter.open(path,'file');owned.append(fd);before=adapter.lstat(path)
    need(before==adapter.fstat(fd) and stat.S_IMODE(before['st_mode'])==0o400 and adapter.read(fd,len(raw))==raw and before==adapter.lstat(path)==adapter.fstat(fd))
    rows[path]=dict(bytes=len(raw),sha256=sha(raw),metadata=before)
  for path in dirs:need(adapter.names(owned[list(dirs).index(path)],len(dirs[path]))==dirs[path])
 finally:
  failures=[]
  for fd in reversed(owned):
   try:need(adapter.close(fd) is None)
   except BaseException as e:failures.append((adapter,fd,e))
  if failures:UNKNOWN.extend(failures)
 need(not UNKNOWN and adapter.require_released() is adapter);return rows

def run(scope_raw,sources,*,station):
 modules=[];phase='source-admission';error=None;result=None
 try:
  need(not UNKNOWN);source_admission(sources);scope=validate_scope(scope_raw,station.wall());phase='compile'
  for index,name in enumerate(INPUT_PINS):
   m=ModuleType('company_seed_backend_probe_'+scope['operationId']+'_'+str(index));m.__file__='<pinned '+name+'>'
   need(m.__name__ not in sys.modules);sys.modules[m.__name__]=m;modules.append(m);exec(compile(sources[name],m.__file__,'exec'),vars(m))
  SB,BK=modules;phase='prepare';station.prepare(scope,sources,scope_raw)
  store,source=expected_leaves();phase='adapter-exercise';first=station.adapter(SB,BK,scope);exercise(first,store,source)
  phase='independent-readback';second=station.adapter(SB,BK,scope);rows=readback(second,store,source);station.check();phase='seal';station.seal()
  prepared={path:identity for path,(_,identity) in station.records.items() if path in station.new_dirs}
  phase='release';station.finish()
  need(not SB.UNRELEASED and not BK.UNRELEASED_RESOURCES)
  result=dict(schemaVersion=1,status='SYNTHETIC_SEED_BACKEND_OBSERVED_ONLY',operationId=scope['operationId'],root=scope['root'],outputs=rows,outputFiles=17,storeFiles=12,sourceFiles=3,sourceJournals=2,adapters=2,
   preparedDirectories=prepared,
   conflictRefused=True,allOwnedResourcesKnownReleased=True,peakAdapterFds=max(a.peak_owned for a in station.adapters),preparerPeakFds=station.peak,
   descriptorReservationGuaranteed=False,diskReservationGuaranteed=False,signatureCreated=False,parentAuthorityQualified=False,storageAuthorityQualified=False,installerActivated=False,nativeCapacityQualified=False,automaticRetry=False)
 except BaseException as e:
  error=e
  try:station.finish()
  except BaseException:pass
 finally:
  for m in reversed(modules):
   if sys.modules.get(m.__name__) is m and not UNKNOWN:del sys.modules[m.__name__]
   else:UNKNOWN.append(('source-module-release',m));result=None
 if error is not None or UNKNOWN:
  result=dict(schemaVersion=1,status='SYNTHETIC_SEED_BACKEND_UNAVAILABLE',phase=phase,errorClass=type(error).__name__ if error else 'UnknownRelease',fixtureCreated=station.fixtureCreated,possibleFixtureEffect=station.effectAttempted,allOwnedResourcesKnownReleased=not UNKNOWN,unknownCount=len(UNKNOWN),automaticRetry=False)
 need(len(canonical(result))<=MAX_OUTPUT);return result
