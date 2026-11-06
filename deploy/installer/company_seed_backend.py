"""Explicit finite Store/Source IO; no installer, process or native default.

The company entry authenticates this module, supplied OS/sys and original BK
before construction. Numeric budgets/current soft FD limit are admissions,
not proof of reserved descriptors/disk or native capacity. The caller retains
the original source/parent/storage guards and performs full stage readbacks.
Repository writes, adoption, unlink, existing chown and replay are absent.
"""
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType, ModuleType, SimpleNamespace

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BROKER_DIRECTORIES=('access-operations','access-pending','access-policies','access-used-approvals','active',
 'app-accounts','artifacts','builds','connector-secrets','connectors','fences','identity-policies','jwks-rotations',
 'jwks-stops','migration-imports','migration-snapshots','observations','operations','receipts','recovery-grants',
 'reports','repository','resources','secrets','security','sources','tls-rotations','used-approvals')
STORE_LEAVES={'approved-mirrors.json','images.lock.json','runtime-manifest.json','company-sources.json',
 'company-deployment.json','platform-sources.json','release.json','release.sig','company-signing-public-key.pem',
 'platform-sources.tar.gz','intent.json','verified.json'}
CHUNK=65536
MAX_FILES,MAX_DIRS,MAX_OWNED=2048,512,2700
MAX_READ_BYTES,MAX_WRITE_BYTES=512*1024**2,104*1024**2
UNRELEASED=[]
_CLOSE_SCOPES={}

class SeedBackendUnavailable(ValueError):pass

def require(value):
 if value is not True:raise SeedBackendUnavailable('company_seed_backend_unavailable')

def component(value):
 require(type(value) is str and 0<len(value)<=255 and value.isascii()
  and re.fullmatch('[A-Za-z0-9_.-]+',value) is not None and value not in ('.','..')
  and not value.endswith('.') and value.lower()!='.git')
 return value

def absolute(value):
 require(type(value) is str and value.isascii() and 0<len(value)<=4096 and value.startswith('/')
  and str(PurePosixPath(value))==value and not value.startswith('//') and '\\' not in value
  and len(PurePosixPath(value).parts)<=32)
 for part in PurePosixPath(value).parts[1:]:component(part)
 return value

def request(value):
 keys={'schemaVersion','mode','operationId','releaseSha256','bundleRoot','sourceRoot','keyPath','dataDir',
  'backingFile','capacityGiB','runscVersion','runscSha512'}
 require(type(value) is dict and set(value)==keys and type(value['schemaVersion']) is int and value['schemaVersion']==1
  and value['mode']=='full-installation' and type(value['mode']) is str)
 for name,pattern in (('operationId','[a-f0-9]{32}'),('releaseSha256','[a-f0-9]{64}'),('runscVersion','[0-9]{8}\\.[0-9]{1,8}'),('runscSha512','[a-f0-9]{128}')):
  require(type(value[name]) is str and re.fullmatch(pattern,value[name]) is not None)
 for name in ('bundleRoot','sourceRoot','keyPath','dataDir','backingFile'):
  absolute(value[name]);require(value[name]!='/' and len(value[name])<=1024)
 require(type(value['capacityGiB']) is int and 32<=value['capacityGiB']<=4096)
 data,backing=value['dataDir'],value['backingFile'];base='/opt/autosoft-company'
 require(data.startswith('/srv/') and data!='/srv/autosoft-company' and not data.startswith('/srv/autosoft-company/')
  and backing!=data and not backing.startswith(data+'/') and not data.startswith(backing+'/')
  and backing!=base and not backing.startswith(base+'/') and not base.startswith(backing+'/'))
 require(all(value[k].startswith(base+'/incoming/') and not value[k].startswith(data+'/') for k in ('bundleRoot','sourceRoot'))
  and value['keyPath'].startswith(base+'/bootstrap/') and value['keyPath'].endswith('.pem'))
 return MappingProxyType(dict(value))

def budgets(value):
 keys={'sourceFiles','sourceDirectories','ownedFds','externalFdReserve','seconds','readBytes','writeBytes'}
 require(type(value) is dict and set(value)==keys and all(type(x) is int for x in value.values())
  and 1<=value['sourceFiles']<=MAX_FILES and 0<=value['sourceDirectories']<=MAX_DIRS
  and value['sourceFiles']+value['sourceDirectories']+96<=value['ownedFds']<=MAX_OWNED
  and 16<=value['externalFdReserve']<=256 and 1<=value['seconds']<=600
  and 1<=value['readBytes']<=MAX_READ_BYTES and 1<=value['writeBytes']<=MAX_WRITE_BYTES)
 return MappingProxyType(dict(value))

def metadata(info):
 row={k:getattr(info,k,None) for k in FIELDS}
 require(all(type(x) is int and x>=0 for x in row.values()));return row

class SeedBackend:
 """One explicit stage-owned adapter; all opens/enumerators are tracked.

 Backing/key descriptors are metadata-only. Writes are limited to this exact
 release's fresh Store/Source children. Existing protected parents never get
 chmod/chown. Original BK owns directory/read FDs; the tracked OS wrapper also
 owns every returned/unreturned FD. Known raw close is captured at construction
 for unwind even after admission/namespace/deadline failure. Unknown close is
 once-only and sticky. No native default, command or arbitrary reader exists.
 """
 def __init__(self,*,request_value,budget,os_module,sys_module,read_backend_module,getdents64,clock):
  require(not UNRELEASED and len(_CLOSE_SCOPES)<64)
  self.request=request(request_value);self.budget=budgets(budget)
  require(type(read_backend_module) is ModuleType and type(getdents64) is read_backend_module.LinuxAMD64Getdents64
   and not read_backend_module.UNRELEASED_RESOURCES and getattr(os_module,'name',None)=='posix'
   and getattr(sys_module,'platform',None)=='linux' and getattr(sys_module,'byteorder',None)=='little'
   and callable(clock))
  names=('open','lstat','fstat','get_inheritable','pread','write','fsync','fchmod','fchown','mkdir','close','sysconf','geteuid','getegid')
  calls={name:getattr(os_module,name,None) for name in names};require(all(callable(c) for c in calls.values()))
  dir_support=getattr(os_module,'supports_dir_fd',())
  require(calls['open'] in dir_support and calls['mkdir'] in dir_support and calls['geteuid']()==calls['getegid']()==0)
  if calls['lstat'] not in dir_support:
   # CPython3.12 omits lstat from the set despite its dir_fd API. Require the
   # exact saved stat primitive in BOTH real support sets, never a truth flag.
   saved_stat=getattr(os_module,'stat',None);follow_support=getattr(os_module,'supports_follow_symlinks',())
   require(type(dir_support) in (set,frozenset) and type(follow_support) in (set,frozenset)
    and callable(saved_stat) and saved_stat in dir_support and saved_stat in follow_support)
   def nofollow_stat(path,*,dir_fd=None):
    if dir_fd is None:absolute(path)
    else:
     component(path);require(type(dir_fd) is int and 0<=dir_fd<2**31)
    return saved_stat(path,dir_fd=dir_fd,follow_symlinks=False)
   calls['lstat']=nofollow_stat
  flags={name:getattr(os_module,name,None) for name in ('O_RDONLY','O_RDWR','O_CREAT','O_EXCL','O_NOFOLLOW','O_CLOEXEC','O_NONBLOCK','O_DIRECTORY')}
  require(type(flags['O_RDONLY']) is int and flags['O_RDONLY']==0 and all(type(v) is int and v>0 for k,v in flags.items() if k!='O_RDONLY'))
  values=[v for k,v in flags.items() if k!='O_RDONLY'];require(all(not a&b for i,a in enumerate(values) for b in values[i+1:]))
  available=calls['sysconf']('SC_OPEN_MAX')
  require(type(available) is int and available>=self.budget['ownedFds']+self.budget['externalFdReserve'])
  now=clock();require(type(now) in (int,float) and math.isfinite(now))
  self._clock,self._start,self._deadline=clock,now,now+self.budget['seconds']
  self._calls,self._flags=MappingProxyType(calls),MappingProxyType(flags)
  self._raw_close=calls['close'];self._fds={};self._attempted=set();self._registered={};self._active=True;self._busy=False;self._released=False
  self._unknown=False;self._created=set();self._created_files=0;self._created_dirs=0;self._source_files=0;self._source_dirs=0
  self._read_bytes=0;self._written_bytes=0;self.peak_owned=0
  self._bk=read_backend_module;self._bk_class=read_backend_module.ReadOnlySourceBackend
  self._bk_unknowns=read_backend_module.UNRELEASED_RESOURCES
  self._bk_methods=dict(vars(self._bk_class))
  self._getdents_class=read_backend_module.LinuxAMD64Getdents64
  self._getdents_methods=dict(vars(self._getdents_class));self._getdents_instance=dict(vars(getdents64))
  io=SimpleNamespace(name='posix',**{k:flags[k] for k in ('O_RDONLY','O_NOFOLLOW','O_CLOEXEC','O_NONBLOCK','O_DIRECTORY')},
   open=self._os_open,close=self._os_close,lstat=calls['lstat'],fstat=calls['fstat'],get_inheritable=calls['get_inheritable'],pread=calls['pread'])
  io.supports_dir_fd={io.open}
  self._read_backend=self._bk_class(os_module=io,sys_module=sys_module,getdents64=getdents64)
  # Capture plain ownership and original raw close before the first open. No
  # original BK.close/_fd or live self._dispose callback participates in unwind.
  owner=self;owner_dict=object.__getattribute__(self,'__dict__');r=self._read_backend
  read_dict=object.__getattribute__(r,'__dict__');read_owned=r._owned;read_attempted=r._close_attempted
  fds,attempted,registered=self._fds,self._attempted,self._registered
  raw_close,unknowns,error_type=self._raw_close,UNRELEASED,SeedBackendUnavailable
  read_class=self._bk_class;getdents=getdents64;retained=[False]
  bk_module,saved_methods=self._bk,self._bk_methods;read_calls,read_flags=r._calls,r._flags
  bk_dict=vars(bk_module);bk_unknowns=self._bk_unknowns
  def cleanup(fd=None,*,observe=False):
   current_owner=current_read=None
   try:
    current_owner=object.__getattribute__(owner,'__dict__');current_read=object.__getattribute__(r,'__dict__')
    valid=(current_owner is owner_dict and current_read is read_dict and type(r) is read_class
     and current_owner.get('_fds') is fds and current_owner.get('_attempted') is attempted
     and current_owner.get('_registered') is registered and current_owner.get('_read_backend') is r
     and current_owner.get('_bk') is bk_module and current_owner.get('_bk_class') is read_class
     and current_owner.get('_bk_methods') is saved_methods
     and current_owner.get('_bk_unknowns') is bk_unknowns and bk_dict.get('UNRELEASED_RESOURCES') is bk_unknowns
     and current_owner.get('_cleanup') is cleanup and current_owner.get('_cleanup_original') is cleanup
     and current_owner.get('_register_original') is register
     and current_read.get('_owned') is read_owned and current_read.get('_close_attempted') is read_attempted
     and current_read.get('_getdents64') is getdents and current_read.get('_unknown') is False
     and current_read.get('_calls') is read_calls and current_read.get('_flags') is read_flags
     and type(fds) is dict and type(registered) is dict and type(attempted) is set
     and type(read_owned) is set and type(read_attempted) is set
     and all(type(x) is int and 0<=x<2**31 for collection in (fds,registered,attempted,read_owned,read_attempted) for x in collection)
     and set(fds)==set(registered)
     and attempted<=set(fds) and read_attempted<=read_owned and read_owned<=set(fds)
     and read_attempted==attempted.intersection(read_owned))
    if valid:
     for handle,binding in registered.items():
      if not(type(handle) is int and 0<=handle<2**31 and type(binding) is tuple and len(binding)==4
       and fds[handle] is binding[0] and type(binding[0]) is dict
       and binding[0].get('path')==binding[1] and binding[0].get('directory') is binding[2]
       and (handle in read_owned) is binding[3]):valid=False;break
    enumeration=current_read.get('_enumeration') if valid else None
    if valid and not(enumeration is None or type(enumeration) is int and enumeration in read_owned):valid=False
   except BaseException:valid=False
   if not valid:
    owner_dict['_active']=False;owner_dict['_unknown']=True
    if not retained[0]:
     retained[0]=True
     unknowns.append((owner,'ownership-boundary',(owner_dict,current_owner,r,read_dict,current_read,
      fds,attempted,registered,read_owned,read_attempted,bk_unknowns,bk_dict.get('UNRELEASED_RESOURCES')),raw_close))
    raise error_type('company_seed_backend_ownership_unknown')
   if observe:return None
   if not(type(fd) is int and fd in registered and fd not in attempted):raise error_type('company_seed_backend_fd')
   attempted.add(fd)
   if fd in read_owned:read_attempted.add(fd)
   try:
    if raw_close(fd) is not None:raise error_type('company_seed_backend_close_result')
   except BaseException:
    owner_dict['_active']=False;owner_dict['_unknown']=True
    unknowns.append((owner,'fd-close',(fd,registered[fd],r,read_owned,read_attempted),raw_close))
    raise error_type('company_seed_backend_close_unknown') from None
   del fds[fd];del registered[fd];attempted.remove(fd)
   read_owned.discard(fd);read_attempted.discard(fd)
   if enumeration==fd:read_dict['_enumeration']=None
  def register(fd,row,readonly):
   if not(type(fd) is int and 0<=fd<2**31 and fd not in fds and fd not in attempted):
    owner_dict['_active']=False;owner_dict['_unknown']=True
    unknowns.append((owner,'open-result',(fd,row,r,fds,attempted,registered),raw_close))
    raise error_type('company_seed_backend_open_unknown')
   fds[fd]=row;registered[fd]=(row,row['path'],row['directory'],readonly)
   if readonly:read_owned.add(fd)
   owner_dict['peak_owned']=max(owner_dict['peak_owned'],len(fds))
  self._cleanup=self._cleanup_original=cleanup;self._register_original=register
  _CLOSE_SCOPES[id(self)]=(self,cleanup,register)
  data=self.request['dataDir'];release=self.request['releaseSha256']
  self.store_parent=data+'/company/platform-releases';self.source_parent=data+'/company/source-releases'
  self.store_root=self.store_parent+'/'+release;self.source_root=self.source_parent+'/'+release
  self._metadata_only={self.request['backingFile'],'/etc/autosoft/storage.key'}
  self._files={'/etc/autosoft/'+n for n in ('installation.intent.json','installation.json','installation.storage-receipt.json','storage.key')}
  self._files|={data+'/config/installation.json',*(data+'/config/runtime-layout/'+n for n in ('intent.json','layout.json','confirmed.json')),self.request['backingFile']}
  self._dirs={data,data+'/config',data+'/config/runtime-layout',data+'/config/repository-seed',data+'/runtime',data+'/runtime/storage',data+'/company',self.store_parent,self.source_parent}
  self._dirs|={data+'/runtime/'+n for n in BROKER_DIRECTORIES}
  for path in tuple(self._files|self._dirs|{self.store_root,self.source_root}):self._dirs.update(str(x) for x in PurePosixPath(path).parents)
  self._broker={data+'/runtime/'+n for n in BROKER_DIRECTORIES}
  self.request_sha256=hashlib.sha256((json.dumps(dict(self.request),sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()

 def _unknown_resource(self,kind,value):
  self._unknown=True;self._active=False;UNRELEASED.append((self,kind,value,self._raw_close))

 def _ready(self):
  scope=_CLOSE_SCOPES.get(id(self));require(type(scope) is tuple and len(scope)==3 and scope[0] is self)
  scope[1](observe=True)
  now=self._clock()
  current_methods=dict(vars(self._bk_class))
  getdents_methods=dict(vars(self._getdents_class));getdents_instance=vars(self._read_backend.__dict__['_getdents64'])
  require(self._active and not self._released and not self._unknown and not UNRELEASED
   and type(now) in (int,float) and math.isfinite(now) and self._start<=now<=self._deadline
   and self._bk.ReadOnlySourceBackend is self._bk_class and set(current_methods)==set(self._bk_methods)
   and all(current_methods[k] is self._bk_methods[k] for k in self._bk_methods)
   and self._bk.LinuxAMD64Getdents64 is self._getdents_class and set(getdents_methods)==set(self._getdents_methods)
   and all(getdents_methods[k] is self._getdents_methods[k] for k in self._getdents_methods)
   and set(getdents_instance)==set(self._getdents_instance)
   and all(getdents_instance[k] is self._getdents_instance[k] for k in self._getdents_instance)
   and not self._bk_unknowns)

 def _read_kind(self,path):
  absolute(path)
  if path in self._files:return 'file'
  if path in self._dirs:return 'directory'
  if path in (self.store_root,self.source_root,self.source_root+'/source'):return 'directory'
  if path.startswith(self.store_root+'/'):
   require(path[len(self.store_root)+1:] in STORE_LEAVES);return 'file'
  if path.startswith(self.source_root+'/source/'):
   return None # A finite typed member; upstream signed inventory decides file/directory.
  if path in (self.source_root+'/intent.json',self.source_root+'/bytes-verified.json'):return 'file'
  require(False)

 def _protected(self,path,info,directory):
  value=metadata(info);require(stat.S_IFMT(value['st_mode'])==(stat.S_IFDIR if directory else stat.S_IFREG)
   and value['st_uid']==value['st_gid']==(10001 if path in self._broker else 0)
   and not stat.S_IMODE(value['st_mode'])&0o022 and (directory or value['st_nlink']==1))
  return value

 def _os_open(self,path,flags,*args,**kwargs):
  self._ready();require(len(self._fds)<self.budget['ownedFds'])
  parent=kwargs.get('dir_fd');name='/' if parent is None else component(path) if path!='.' else '.'
  if parent is None:require(path=='/');full='/'
  else:
   require(parent in self._fds and self._fds[parent]['directory'])
   full=self._fds[parent]['path'] if name=='.' else str(PurePosixPath(self._fds[parent]['path'])/name)
  register=_CLOSE_SCOPES[id(self)][2]
  row=dict(path=full,directory=bool(flags&self._flags['O_DIRECTORY']),created=bool(flags&self._flags['O_CREAT']),maximum=0,written=0)
  readonly=not bool(flags&(self._flags['O_RDWR']|self._flags['O_CREAT']))
  fd=self._calls['open'](path,flags,*args,**kwargs)
  register(fd,row,readonly);self._ready();return fd

 def _os_close(self,fd):
  self._cleanup_original(fd)

 def _dispose(self,fd):
  self._cleanup_original(fd)

 def _open_read(self,parent,name,directory):
  self._ready();require(type(directory) is bool)
  flags=self._flags['O_RDONLY']|self._flags['O_NOFOLLOW']|self._flags['O_CLOEXEC']|self._flags['O_NONBLOCK']
  if directory:flags|=self._flags['O_DIRECTORY']
  fd=self._os_open(name,flags) if parent is None else self._os_open(name,flags,dir_fd=parent)
  self._ready();require(self._calls['get_inheritable'](fd) is False);self._ready();return fd

 def _operation(self,function,*,returned_fd=False):
  self._ready();require(not self._busy);self._busy=True;before=set(self._fds);kept=None;result=None;error=None
  cleanup=_CLOSE_SCOPES[id(self)][1];original_fds=self._fds;original_attempted=self._attempted
  try:
   result=function();self._ready()
   if returned_fd:require(type(result) is int and result in self._fds and result not in before);kept=result
  except BaseException as caught:self._active=False;error=caught
  finally:
   for fd in reversed(tuple(original_fds)):
    if fd not in before and fd!=kept and fd not in original_attempted:
     try:cleanup(fd)
     except BaseException as caught:
      if error is None:error=caught
   self._busy=False
  if error is not None:raise error
  require(not self._unknown and not UNRELEASED);return result

 def _walk(self,path,directory):
  path=absolute(path);kind=self._read_kind(path);require(kind is None or kind==('directory' if directory else 'file'))
  fd=self._open_read(None,'/',True);chain=[('/',fd,self._protected('/',self._calls['fstat'](fd),True))]
  parts=PurePosixPath(path).parts[1:]
  for index,name in enumerate(parts):
   self._ready();parent=fd;isdir=index<len(parts)-1 or directory
   full=str(PurePosixPath(chain[-1][0])/name)
   before=self._protected(full,self._calls['lstat'](name,dir_fd=parent),isdir)
   fd=self._open_read(parent,name,isdir)
   require(before==metadata(self._calls['fstat'](fd))==metadata(self._calls['lstat'](name,dir_fd=parent)))
   chain.append((full,fd,before))
  for name,handle,identity in chain:
   require(identity==metadata(self._calls['fstat'](handle))==metadata(self._calls['lstat'](name)))
  return fd

 def open(self,path,kind):
  require(type(kind) is str and kind in ('file','directory'))
  return self._operation(lambda:self._walk(path,kind=='directory'),returned_fd=True)

 def lstat(self,path):
  def observe():
   kind=self._read_kind(path)
   if kind is None:
    parent=str(PurePosixPath(path).parent);fd=self._walk(parent,True);info=self._calls['lstat'](PurePosixPath(path).name,dir_fd=fd)
    require(stat.S_IFMT(info.st_mode) in (stat.S_IFDIR,stat.S_IFREG));directory=stat.S_ISDIR(info.st_mode)
   else:directory=kind=='directory'
   fd=self._walk(path,directory);return metadata(self._calls['fstat'](fd))
  return self._operation(observe)

 def _fd(self,fd):
  require(type(fd) is int and fd in self._fds and fd not in self._attempted);return self._fds[fd]

 def fstat(self,fd):return self._operation(lambda:metadata(self._calls['fstat'](fd)) if self._fd(fd) else None)
 def inheritable(self,fd):
  def observe():
   self._fd(fd);value=self._calls['get_inheritable'](fd);require(type(value) is bool);return value
  return self._operation(observe)

 def _pread(self,fd,count,offset):
  row=self._fd(fd);require(not row['directory'] and row['path'] not in self._metadata_only
   and type(count) is int and 0<count<=CHUNK and type(offset) is int and 0<=offset<=32*1024**2
   and offset+count<=32*1024**2+1 and self._read_bytes+count<=self.budget['readBytes'])
  self._read_bytes+=count;before=metadata(self._calls['fstat'](fd))
  require(before==metadata(self._calls['lstat'](row['path'])))
  raw=self._calls['pread'](fd,count,offset);require(type(raw) is bytes and len(raw)<=count)
  require(before==metadata(self._calls['fstat'](fd))==metadata(self._calls['lstat'](row['path'])));return raw

 def pread(self,fd,count,offset):return self._operation(lambda:self._pread(fd,count,offset))
 def read(self,fd,maximum):
  def capture():
   row=self._fd(fd);require(type(maximum) is int and 0<=maximum<=32*1024**2 and not row['directory'] and row['path'] not in self._metadata_only)
   before=metadata(self._calls['fstat'](fd));require(before['st_size']<=maximum);out=[];offset=0
   while offset<before['st_size']:
    self._ready();count=min(CHUNK,before['st_size']-offset);raw=self._pread(fd,count,offset);require(len(raw)==count);out.append(raw);offset+=count
   require(self._pread(fd,1,offset)==b'' and before==metadata(self._calls['fstat'](fd)));return b''.join(out)
  return self._operation(capture)

 def names(self,fd,maximum):
  def enumerate_names():
   row=self._fd(fd);require(row['directory'] and type(maximum) is int and 0<=maximum<=8192)
   cap=min(maximum,self.budget['sourceFiles']+self.budget['sourceDirectories']+16,2560)
   require(fd in self._read_backend._owned)
   r=self._read_backend;state=r.__dict__;before=metadata(self._calls['fstat'](fd))
   require(state['_enumeration'] is None)
   enumeration=self._open_read(fd,'.',True);state['_enumeration']=enumeration
   require(metadata(self._calls['fstat'](enumeration))==before)
   names=self._bk_methods['_directory_records'](r,enumeration,cap+1)
   self._ready()
   require(before==metadata(self._calls['fstat'](fd))==metadata(self._calls['fstat'](enumeration)))
   require(type(names) is list and len(names)<=cap and len(names)==len(set(names)))
   for name in names:component(name)
   return sorted(names)
  return self._operation(enumerate_names)

 def _write_policy(self,path,directory,uid,gid,mode):
  require(type(uid) is int and type(gid) is int and uid==gid==0 and type(mode) is int and mode==(0o700 if directory else 0o400))
  if path==self.store_root or path==self.source_root:require(directory);return 'root',0
  if path.startswith(self.store_root+'/'):
   require(not directory and path[len(self.store_root)+1:] in STORE_LEAVES)
   name=PurePosixPath(path).name
   maximum=32*1024**2 if name=='platform-sources.tar.gz' else 1024**2 if name in ('approved-mirrors.json','images.lock.json','runtime-manifest.json','company-sources.json','company-deployment.json','platform-sources.json') else 4096 if name=='company-signing-public-key.pem' else 16384 if name in ('release.json','release.sig') else 65536
   return 'store',maximum
  if path==self.source_root+'/source':require(directory);return 'source-root',0
  if path.startswith(self.source_root+'/source/'):
   relative=path[len(self.source_root+'/source/'):];require(len(relative)<=256 and len(PurePosixPath(relative).parts)<=16)
   return 'source',0 if directory else 8*1024**2
  require(not directory and path in (self.source_root+'/intent.json',self.source_root+'/bytes-verified.json'));return 'journal',65536

 def _new(self,parent,name,uid,gid,mode,directory):
  row=self._fd(parent);require(row['directory']);component(name);path=str(PurePosixPath(row['path'])/name)
  kind,maximum=self._write_policy(path,directory,uid,gid,mode)
  require(row['path'] in (self.store_parent,self.source_parent) or row['path'] in self._created)
  require(stat.S_IMODE(self._calls['fstat'](parent).st_mode)==0o700)
  require((self._created_dirs<self.budget['sourceDirectories']+3) if directory else (self._created_files<self.budget['sourceFiles']+14))
  if kind=='source':require(self._source_dirs<self.budget['sourceDirectories'] if directory else self._source_files<self.budget['sourceFiles'])
  # Admission includes the read-only open after mkdir, before its first effect.
  require(len(self._fds)<self.budget['ownedFds'])
  before=metadata(self._calls['fstat'](parent));require(before==metadata(self._calls['lstat'](row['path'])))
  if directory:
   require(self._calls['mkdir'](name,mode,dir_fd=parent) is None)
   self._created.add(path);self._created_dirs+=1
   if kind=='source':self._source_dirs+=1
   fd=self._open_read(parent,name,True)
  else:
   fd=self._os_open(name,self._flags['O_RDWR']|self._flags['O_CREAT']|self._flags['O_EXCL']|self._flags['O_NOFOLLOW']|self._flags['O_CLOEXEC']|self._flags['O_NONBLOCK'],mode,dir_fd=parent)
   self._created.add(path);self._created_files+=1
   if kind=='source':self._source_files+=1
  target=self._fds[fd];target.update(created=True,maximum=maximum)
  require(self._calls['get_inheritable'](fd) is False)
  require(self._calls['fchown'](fd,uid,gid) is None and self._calls['fchmod'](fd,mode) is None)
  info=self._protected(path,self._calls['fstat'](fd),directory)
  require(info==metadata(self._calls['lstat'](name,dir_fd=parent)) and stat.S_IMODE(info['st_mode'])==mode
   and info['st_dev']==before['st_dev'] and (directory or info['st_size']==0))
  return fd

 def mkdir(self,parent,name,uid,gid,mode):return self._operation(lambda:self._new(parent,name,uid,gid,mode,True),returned_fd=True)
 def create(self,parent,name,uid,gid,mode):return self._operation(lambda:self._new(parent,name,uid,gid,mode,False),returned_fd=True)
 def write(self,fd,raw):
  def put():
   row=self._fd(fd);require(row['created'] and row['path'] in self._created and not row['directory']
    and type(raw) is bytes and 0<len(raw)<=CHUNK and row['written']+len(raw)<=row['maximum']
    and self._written_bytes+len(raw)<=self.budget['writeBytes'])
   before=metadata(self._calls['fstat'](fd));require(before==metadata(self._calls['lstat'](row['path'])) and before['st_size']==row['written'])
   amount=self._calls['write'](fd,raw);require(type(amount) is int and 0<amount<=len(raw))
   row['written']+=amount;self._written_bytes+=amount
   after=self._protected(row['path'],self._calls['fstat'](fd),False)
   require(after==metadata(self._calls['lstat'](row['path'])) and after['st_size']==row['written']);return amount
  return self._operation(put)

 def sync(self,fd):
  def flush():self._fd(fd);require(self._calls['fsync'](fd) is None)
  return self._operation(flush)
 def chmod(self,fd,mode):
  def seal():
   row=self._fd(fd);require(row['created'] and row['path'] in self._created and row['directory']
    and type(mode) is int and mode==0o500 and stat.S_IMODE(self._calls['fstat'](fd).st_mode)==0o700)
   require(self._calls['fchmod'](fd,mode) is None)
   require(stat.S_IMODE(self._calls['fstat'](fd).st_mode)==mode)
  return self._operation(seal)
 def close(self,fd):
  # Captured original close remains usable after an operation expired admission.
  scope=_CLOSE_SCOPES.get(id(self));require(type(scope) is tuple and len(scope)==3 and scope[0] is self)
  scope[1](fd)
 def require_released(self):
  # Observation at both worker admission and completion. Empty ownership does
  # not revive failed admission or expire a healthy adapter. Deadline and any
  # prior failed operation continue to deny later IO through _ready().
  scope=_CLOSE_SCOPES.get(id(self));require(type(scope) is tuple and len(scope)==3 and scope[0] is self)
  scope[1](observe=True)
  require(not self._fds and not self._attempted and not self._unknown and not UNRELEASED
   and not self._bk_unknowns and not self._read_backend.__dict__['_owned']
   and not self._read_backend.__dict__['_close_attempted'] and self._read_backend.__dict__['_enumeration'] is None)
  return self
