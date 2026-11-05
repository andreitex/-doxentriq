"""Injected RAM syscalls only; no native adapter, installer, disk or process."""
import ast
import copy
import importlib.util
from pathlib import Path, PurePosixPath
import stat
import sys
import time
from types import ModuleType, SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
SB=load('company_seed_backend_controls','deploy/installer/company_seed_backend.py')
BK=load('company_seed_backend_original_readonly','scripts/company_source_guard_backend.py')
Store=load('company_seed_backend_original_store','scripts/company_platform_store.py')
Source=load('company_seed_backend_original_source','scripts/company_source_tree.py')

def original_seed_files():
 # Exact existing pure B interface, with no bootstrap ambient imports or effects.
 raw=(ROOT/'scripts/bootstrap.py').read_bytes();tree=ast.parse(raw)
 names={'SeedUnavailable','_seed_require','_seed_path','_seed_identity','SeedFiles'}
 nodes=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in names]
 assert len(nodes)==len(names)
 module=ModuleType('seed_files_exact_fixture');module.__dict__.update(stat=stat,re=SB.re,SEED_FIELDS=SB.FIELDS,SEED_UNRELEASED=[])
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<unchanged SeedFiles definitions>','exec'),module.__dict__);return module
B=original_seed_files()

def request():
 return dict(schemaVersion=1,mode='full-installation',operationId='a'*32,releaseSha256='b'*64,
  bundleRoot='/opt/autosoft-company/incoming/bundle',sourceRoot='/opt/autosoft-company/incoming/source',
  keyPath='/opt/autosoft-company/bootstrap/company.pem',dataDir='/srv/data',backingFile='/var/lib/autosoft.luks',
  capacityGiB=32,runscVersion='20260101.1',runscSha512='c'*128)
def budget(**kw):
 row=dict(sourceFiles=4,sourceDirectories=2,ownedFds=128,externalFdReserve=32,seconds=60,readBytes=4*1024**2,writeBytes=1024**2);row.update(kw);return row
class Buffer:
 def __init__(self,size):self.data=bytearray(size)
 @property
 def raw(self):return bytes(self.data)
class RAM:
 def __init__(self):
  self.nodes={};self.fds={};self.cursors={};self.events=[];self.serial=0;self.nextfd=20;self.tick=100
  self.failure_close=None;self.failure_write=False;self.failure_fstat=None;self.failure_inherit=None;self.failure_sync=None
  self.partial_write=0;self.bad_open=None;self.fd_limit=8192;self.drift=None;self.call_hook=None
  for p in ('/','/srv','/srv/data','/srv/data/config','/srv/data/config/runtime-layout','/srv/data/config/repository-seed',
   '/srv/data/company','/srv/data/company/platform-releases','/srv/data/company/source-releases','/srv/data/runtime',
   '/srv/data/runtime/storage','/etc','/etc/autosoft','/var','/var/lib'):self.add(p,True,0o700 if p not in ('/','/srv','/etc','/var','/var/lib') else 0o755)
  for name in SB.BROKER_DIRECTORIES:self.add('/srv/data/runtime/'+name,True,0o700,uid=10001)
  for p in ('/etc/autosoft/installation.intent.json','/etc/autosoft/installation.json','/etc/autosoft/installation.storage-receipt.json',
   '/srv/data/config/installation.json','/srv/data/config/runtime-layout/intent.json','/srv/data/config/runtime-layout/layout.json',
   '/srv/data/config/runtime-layout/confirmed.json'):self.add(p,False,0o600,b'{}\n')
  self.add('/etc/autosoft/storage.key',False,0o600,b'private-key-fixture');self.add('/var/lib/autosoft.luks',False,0o600,b'backing-fixture')
  self.os=SimpleNamespace(name='posix',O_RDONLY=0,O_RDWR=2,O_CREAT=64,O_EXCL=128,O_NOFOLLOW=256,O_CLOEXEC=512,O_NONBLOCK=1024,O_DIRECTORY=2048,
   open=self.open,lstat=self.lstat,fstat=self.fstat,get_inheritable=self.inheritable,pread=self.pread,write=self.write,
   fsync=self.sync,fchmod=self.chmod,fchown=self.chown,mkdir=self.mkdir,close=self.close,
   sysconf=lambda name:self.fd_limit,geteuid=lambda:0,getegid=lambda:0)
  self.os.supports_dir_fd={self.os.open,self.os.mkdir,self.os.lstat}
  self.system=SimpleNamespace(platform='linux',byteorder='little')
  self.ctypes=SimpleNamespace(c_long='long',c_void_p='pointer',c_uint='int',sizeof=lambda x:4 if x=='int' else 8,
   CFUNCTYPE=lambda *a,**kw:lambda x:self.getdents,create_string_buffer=Buffer,byref=lambda x:x,get_errno=lambda:0,set_errno=lambda x:None)
  self.getter=BK.LinuxAMD64Getdents64(ctypes_module=self.ctypes,libc=object(),sys_module=self.system,machine_module=SimpleNamespace(machine=lambda:'x86_64'))
 def adapter(self,**kw):
  args=dict(request_value=request(),budget=budget(),os_module=self.os,sys_module=self.system,read_backend_module=BK,getdents64=self.getter,clock=lambda:1);args.update(kw)
  return SB.SeedBackend(**args)
 def add(self,path,directory,mode,raw=b'',uid=0):
  self.serial+=1;self.nodes[path]=dict(raw=raw,info=dict(st_dev=9,st_ino=self.serial,st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|mode,
   st_uid=uid,st_gid=uid,st_nlink=2 if directory else 1,st_size=4096 if directory else len(raw),st_mtime_ns=100,st_ctime_ns=100))
 def update(self,path,*,mtime=True):
  self.tick+=1;self.nodes[path]['info']['st_ctime_ns']=self.tick
  if mtime:self.nodes[path]['info']['st_mtime_ns']=self.tick
 def at(self,name,dir_fd):return name if dir_fd is None else self.fds[dir_fd][0] if name=='.' else str(PurePosixPath(self.fds[dir_fd][0])/name)
 def lstat(self,name,*,dir_fd=None):
  path=self.at(name,dir_fd);self.events.append(('lstat',path))
  if path not in self.nodes:raise FileNotFoundError(path)
  return SimpleNamespace(**copy.copy(self.nodes[path]['info']))
 def fstat(self,fd):
  path,node=self.fds[fd]
  if path==self.failure_fstat:raise OSError('fstat injected')
  return SimpleNamespace(**copy.copy(node['info']))
 def open(self,name,flags,mode=0,*,dir_fd=None):
  path=self.at(name,dir_fd);self.events.append(('open',path,flags))
  if flags & self.os.O_CREAT:
   if path in self.nodes:raise FileExistsError(path)
   self.add(path,False,mode);self.update(str(PurePosixPath(path).parent))
  if path not in self.nodes:raise FileNotFoundError(path)
  if stat.S_ISLNK(self.nodes[path]['info']['st_mode']):raise OSError('nofollow injected')
  if flags&self.os.O_DIRECTORY and not stat.S_ISDIR(self.nodes[path]['info']['st_mode']):raise NotADirectoryError(path)
  fd=self.nextfd;self.nextfd+=1;self.fds[fd]=(path,self.nodes[path]);self.cursors[fd]=0
  if self.call_hook:self.call_hook(path)
  return fd if self.bad_open is None else self.bad_open
 def inheritable(self,fd):return self.fds[fd][0]==self.failure_inherit
 def pread(self,fd,count,offset):
  path,node=self.fds[fd];self.events.append(('pread',path,count,offset));raw=node['raw'][offset:offset+count]
  if self.drift==path:self.update(path)
  return raw
 def mkdir(self,name,mode,*,dir_fd):
  path=self.at(name,dir_fd);self.events.append(('mkdir',path))
  if path in self.nodes:raise FileExistsError(path)
  self.add(path,True,mode);parent=self.fds[dir_fd][0];self.nodes[parent]['info']['st_nlink']+=1;self.update(parent)
 def write(self,fd,raw):
  path,node=self.fds[fd];self.events.append(('write',path,len(raw)))
  if self.failure_write:raise OSError('write injected')
  count=min(len(raw),self.partial_write) if self.partial_write else len(raw);node['raw']+=raw[:count];node['info']['st_size']=len(node['raw']);self.update(path);return count
 def sync(self,fd):
  path=self.fds[fd][0];self.events.append(('sync',path))
  if path==self.failure_sync:raise OSError('sync injected')
 def chmod(self,fd,mode):
  path,node=self.fds[fd];self.events.append(('chmod',path,mode));node['info']['st_mode']=stat.S_IFMT(node['info']['st_mode'])|mode;self.update(path,mtime=False)
 def chown(self,fd,uid,gid):
  path,node=self.fds[fd];self.events.append(('chown',path,uid,gid));node['info']['st_uid']=uid;node['info']['st_gid']=gid;self.update(path,mtime=False)
 def close(self,fd):
  path=self.fds[fd][0];self.events.append(('close',path,fd))
  if path==self.failure_close:raise OSError('close injected')
  del self.fds[fd];self.cursors.pop(fd,None)
 def names(self,path):return sorted(p.rsplit('/',1)[-1] for p in self.nodes if p!='/' and str(PurePosixPath(p).parent)==path)
 def getdents(self,number,fd,buffer,size):
  assert number==217;path=self.fds[fd][0];names=['.','..',*self.names(path)];index=self.cursors[fd];out=b''
  while index<len(names):
   name=names[index];target=path if name=='.' else str(PurePosixPath(path).parent) if name=='..' else str(PurePosixPath(path)/name)
   info=self.nodes[target]['info'];length=(19+len(name)+1+7)//8*8
   record=info['st_ino'].to_bytes(8,'little')+(index+1).to_bytes(8,'little')+length.to_bytes(2,'little')+bytes([4 if stat.S_ISDIR(info['st_mode']) else 8])+name.encode()+b'\0'
   record=record.ljust(length,b'\0')
   if len(out)+length>size:break
   out+=record;index+=1
  self.cursors[fd]=index;buffer.data[:len(out)]=out;return len(out)

class SeedBackendControls(unittest.TestCase):
 def setUp(self):
  self.ram=RAM();self.adapters=[];self.bk_members=dict(vars(BK.ReadOnlySourceBackend));self.dispose_member=SB.SeedBackend._dispose
 def adapter(self,**kwargs):
  result=self.ram.adapter(**kwargs);self.adapters.append(result);return result
 def tearDown(self):
  # Test-local RAM unknown references only; product exports no reset/replay.
  SB.UNRELEASED.clear();BK.UNRELEASED_RESOURCES.clear();B.SEED_UNRELEASED.clear();Store.UNRELEASED.clear();Source.UNRELEASED.clear()
  SB._CLOSE_SCOPES.clear()
  for name,value in self.bk_members.items():
   if vars(BK.ReadOnlySourceBackend).get(name) is not value:setattr(BK.ReadOnlySourceBackend,name,value)
  SB.SeedBackend._dispose=self.dispose_member
 def dispose(self,b):
  for fd in reversed(tuple(b._fds)):
   if fd not in b._attempted:b.close(fd)
  return b.require_released()
 def fresh(self,b,source=False):
  p=b.source_parent if source else b.store_parent;fd=b.open(p,'directory');root=b.mkdir(fd,request()['releaseSha256'],0,0,0o700);return fd,root
 def effects(self):return [x for x in self.ram.events if x[0] in ('mkdir','write','chown','chmod') or x[0]=='open' and x[2]&self.ram.os.O_CREAT]

 def test_effect_free_explicit_construction_no_native_default(self):
  b=self.adapter();self.assertEqual(self.ram.events,[]);self.assertFalse(b._fds);self.assertIs(self.dispose(b),b)
  with self.assertRaises(TypeError):SB.SeedBackend()
 def test_full_request_typed_paths_and_release_are_bound(self):
  for field,value in (('dataDir','//srv/data'),('backingFile','/srv/data/backing'),('backingFile','/'),('bundleRoot','/tmp/source'),('sourceRoot','/opt/autosoft-company/incoming/'+'/'.join(['x'*200]*5)),('keyPath','/etc/company.pem'),('capacityGiB',True),('releaseSha256','a'*63)):
   q=request();q[field]=value
   with self.subTest(field=field),self.assertRaises(SB.SeedBackendUnavailable):self.adapter(request_value=q)
  self.assertFalse(self.ram.events)
 def test_missing_original_syscall_and_foreign_backend_class_denied(self):
  for kwargs in ({'os_module':None},{'sys_module':SimpleNamespace(platform='win32',byteorder='little')},{'read_backend_module':SimpleNamespace()},{'getdents64':object()}):
   with self.subTest(kwargs=kwargs),self.assertRaises((SB.SeedBackendUnavailable,AttributeError)):self.adapter(**kwargs)
  self.assertFalse(self.effects())
 def test_upper_source_capacity_on_1024_limit_denies_before_open(self):
  self.ram.fd_limit=1024
  with self.assertRaises(SB.SeedBackendUnavailable):self.adapter(budget=budget(sourceFiles=2048,sourceDirectories=512,ownedFds=2660))
  self.assertEqual(self.ram.events,[])
 def test_boolean_or_inadequate_numeric_budget_denied(self):
  for kwargs in ({'ownedFds':True},{'sourceFiles':2049},{'ownedFds':99},{'readBytes':0},{'seconds':601}):
   with self.subTest(kwargs=kwargs),self.assertRaises(SB.SeedBackendUnavailable):self.adapter(budget=budget(**kwargs))
 def test_original_seedfiles_reads_exact_host_with_all_transients_closed(self):
  b=self.adapter();f=B.SeedFiles(SB,b,clock=lambda:1);path='/etc/autosoft/installation.json'
  row=f.hold(path,mode=0o600);self.assertEqual(row['raw'],b'{}\n');f.check(readback=True);f.close();self.assertIs(b.require_released(),b);self.assertFalse(self.ram.fds)
 def test_backing_and_storage_key_metadata_only_without_read(self):
  for path in ('/var/lib/autosoft.luks','/etc/autosoft/storage.key'):
   b=self.adapter();fd=b.open(path,'file');self.assertEqual(b.fstat(fd)['st_nlink'],1)
   with self.assertRaises(SB.SeedBackendUnavailable):b.read(fd,4096)
   b.close(fd);b.require_released()
  self.assertFalse([e for e in self.ram.events if e[0]=='pread'])
 def test_runtime_repository_uid_is_readonly_and_writes_denied(self):
  b=self.adapter();fd=b.open('/srv/data/runtime/repository','directory');self.assertEqual(b.fstat(fd)['st_uid'],10001)
  with self.assertRaises(SB.SeedBackendUnavailable):b.mkdir(fd,'new',10001,10001,0o700)
  self.assertFalse(self.effects());self.dispose(b)
 def test_unrelated_reads_and_cross_release_writes_denied(self):
  b=self.adapter()
  with self.assertRaises(SB.SeedBackendUnavailable):b.open('/etc/shadow','file')
  self.dispose(b);b=self.adapter();fd=b.open(b.store_parent,'directory')
  with self.assertRaises(SB.SeedBackendUnavailable):b.mkdir(fd,'c'*64,0,0,0o700)
  self.assertFalse(self.effects());self.dispose(b)
 def test_original_storefiles_emit_intent_payload_seal_then_known_close(self):
  b=self.adapter();io=Store.StoreFiles(SB,b,clock=lambda:1);io.hold(b.store_parent,mode=0o700)
  root=io.create(b.store_parent,request()['releaseSha256']);io.create(root,'intent.json',b'{}\n');io.create(root,'release.json',b'signed-raw-fixture')
  io.check(readback=True);io.finalize_directory(root);io.close();self.assertIs(b.require_released(),b)
  self.assertEqual(self.ram.nodes[root+'/release.json']['raw'],b'signed-raw-fixture');self.assertEqual(stat.S_IMODE(self.ram.nodes[root]['info']['st_mode']),0o500)
  self.assertFalse(self.ram.fds)
 def test_original_sourcefiles_nested_create_pread_inventory_and_seal(self):
  b=self.adapter();io=Source.SourceFiles(SB,b,clock=lambda:1);io.hold(b.source_parent,mode=0o700)
  root=io.create(b.source_parent,request()['releaseSha256']);io.create(root,'intent.json',b'{}\n');tree=io.create(root,'source');folder=io.create(tree,'scripts')
  io.create(folder,'safe.py',b'# inert\n');io.inventory(folder,['safe.py']);io.check(readback=True)
  io.seal_directory(folder);io.seal_directory(tree);io.seal_directory(root);io.close();self.assertIs(b.require_released(),b);self.assertFalse(self.ram.fds)
 def test_exclusive_existing_release_and_partial_file_are_preserved(self):
  path='/srv/data/company/platform-releases/'+'b'*64;self.ram.add(path,True,0o700);self.ram.add(path+'/sentinel',False,0o400,b'preserve')
  b=self.adapter();fd=b.open(b.store_parent,'directory')
  with self.assertRaises(FileExistsError):b.mkdir(fd,'b'*64,0,0,0o700)
  self.assertEqual(self.ram.nodes[path+'/sentinel']['raw'],b'preserve');self.assertFalse([e for e in self.ram.events if e[0]=='chown']);self.dispose(b)
 def test_no_existing_file_chmod_or_chown(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file')
  with self.assertRaises(SB.SeedBackendUnavailable):b.chmod(fd,0o500)
  self.assertFalse([e for e in self.ram.events if e[0] in ('chown','chmod')]);self.dispose(b)
 def test_created_root_uid_only_and_boolean_mode_denied_before_effect(self):
  for args in ((10001,10001,0o700),(0,0,True)):
   b=self.adapter();fd=b.open(b.source_parent,'directory')
   with self.assertRaises(SB.SeedBackendUnavailable):b.mkdir(fd,'b'*64,*args)
   self.dispose(b)
  self.assertFalse(self.effects())
 def test_partial_write_progress_and_exact_pread_without_position_mutation(self):
  b=self.adapter();parent,root=self.fresh(b);fd=b.create(root,'release.json',0,0,0o400);self.ram.partial_write=2
  self.assertEqual(b.write(fd,b'abcd'),2);self.assertEqual(b.write(fd,b'cd'),2);self.assertEqual(b.pread(fd,4,0),b'abcd');self.assertEqual(b.read(fd,4),b'abcd');self.dispose(b)
 def test_write_budget_denied_before_syscall_preserves_exact_partial(self):
  b=self.adapter(budget=budget(writeBytes=3));parent,root=self.fresh(b);fd=b.create(root,'release.json',0,0,0o400)
  self.assertEqual(b.write(fd,b'ab'),2)
  with self.assertRaises(SB.SeedBackendUnavailable):b.write(fd,b'cd')
  self.assertEqual(self.ram.nodes[b.store_root+'/release.json']['raw'],b'ab');self.assertEqual(len([e for e in self.ram.events if e[0]=='write']),1);self.dispose(b)
 def test_read_chunk_total_and_empty_tail_bound(self):
  b=self.adapter(budget=budget(readBytes=3));fd=b.open('/etc/autosoft/installation.json','file')
  with self.assertRaises(SB.SeedBackendUnavailable):b.read(fd,3)
  self.assertEqual(len([e for e in self.ram.events if e[0]=='pread']),1);self.dispose(b)
 def test_names_clamp_zero_and_overflow_never_unbounded(self):
  b=self.adapter();fd=b.open(b.store_parent,'directory');self.assertEqual(b.names(fd,0),[]);self.assertEqual(b.names(fd,8192),[])
  for i in range(23):self.ram.add(b.store_parent+'/extra'+str(i),True,0o700)
  with self.assertRaises(SB.SeedBackendUnavailable):b.names(fd,8192)
  self.dispose(b)
 def test_nonempty_zero_inventory_denied_with_sentinel(self):
  b=self.adapter();fd=b.open(b.store_parent,'directory');self.ram.add(b.store_parent+'/existing',True,0o700)
  with self.assertRaises(SB.SeedBackendUnavailable):b.names(fd,0)
  self.dispose(b)
 def test_symlink_ancestor_and_hardlink_file_denied_without_writes(self):
  self.ram.nodes['/etc/autosoft']['info']['st_mode']=stat.S_IFLNK|0o777;b=self.adapter()
  with self.assertRaises(SB.SeedBackendUnavailable):b.open('/etc/autosoft/installation.json','file')
  self.dispose(b);self.ram.nodes['/etc/autosoft']['info']['st_mode']=stat.S_IFDIR|0o700
  self.ram.nodes['/etc/autosoft/installation.json']['info']['st_nlink']=2;b=self.adapter()
  with self.assertRaises(SB.SeedBackendUnavailable):b.open('/etc/autosoft/installation.json','file')
  self.dispose(b);self.assertFalse(self.effects())
 def test_content_identity_drift_denies_then_all_owned_close(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file');self.ram.drift='/etc/autosoft/installation.json'
  with self.assertRaises(SB.SeedBackendUnavailable):b.pread(fd,3,0)
  self.dispose(b);self.assertFalse(self.ram.fds)
 def test_open_postcheck_failure_closes_unreturned_and_all_transient_fds(self):
  self.ram.failure_inherit='/etc/autosoft/installation.json';b=self.adapter()
  with self.assertRaises((SB.SeedBackendUnavailable,BK.SourceBackendUnavailable)):b.open('/etc/autosoft/installation.json','file')
  self.assertFalse(self.ram.fds);self.assertFalse(b._fds);self.assertIs(b.require_released(),b)
 def test_transient_directory_enumerator_close_unknown_retains_exact_fd_once(self):
  b=self.adapter();fd=b.open(b.store_parent,'directory');self.ram.failure_close=b.store_parent
  with self.assertRaises((SB.SeedBackendUnavailable,BK.SourceBackendUnavailable)):b.names(fd,0)
  self.assertTrue(SB.UNRELEASED);failed=tuple(b._attempted);self.assertEqual(len(failed),1)
  for value in failed:
   with self.assertRaises(SB.SeedBackendUnavailable):b.close(value)
  self.assertEqual(len([e for e in self.ram.events if e[0]=='close' and e[2]==failed[0]]),1)
  self.assertTrue(any(row[0] is b for row in SB.UNRELEASED));self.assertTrue(b._fds)
 def test_raw_close_captured_before_os_namespace_mutation(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file');self.ram.os.close=lambda fd:(_ for _ in ()).throw(AssertionError('ambient close'))
  b.close(fd);self.assertIs(b.require_released(),b);self.assertFalse(self.ram.fds)
 def test_fsync_failure_retains_partial_and_no_delete_or_replay(self):
  b=self.adapter();parent,root=self.fresh(b);fd=b.create(root,'intent.json',0,0,0o400);b.write(fd,b'partial');self.ram.failure_sync=b.store_root+'/intent.json'
  with self.assertRaises(OSError):b.sync(fd)
  self.assertEqual(self.ram.nodes[b.store_root+'/intent.json']['raw'],b'partial');self.dispose(b)
  self.assertFalse(hasattr(b,'unlink'));self.assertFalse(hasattr(b,'chown'));self.assertFalse(hasattr(b,'reset'))
 def test_deadline_refusal_before_write_and_known_closes_still_allowed(self):
  now=[1];b=self.adapter(clock=lambda:now[0]);parent,root=self.fresh(b);fd=b.create(root,'intent.json',0,0,0o400);now[0]=62
  with self.assertRaises(SB.SeedBackendUnavailable):b.write(fd,b'x')
  self.assertFalse([e for e in self.ram.events if e[0]=='write']);self.dispose(b);self.assertFalse(self.ram.fds)
 def test_empty_release_observation_preserves_worker_admission(self):
  b=self.adapter();self.assertIs(b.require_released(),b)
  fd=b.open(b.store_parent,'directory');b.close(fd);self.assertIs(b.require_released(),b)
  fd=b.open(b.source_parent,'directory');b.close(fd);self.assertIs(b.require_released(),b)
 def test_empty_release_observation_never_restarts_failed_admission(self):
  b=self.adapter()
  with self.assertRaises(SB.SeedBackendUnavailable):b.open('/etc/shadow','file')
  self.assertIs(self.dispose(b),b)
  with self.assertRaises(SB.SeedBackendUnavailable):b.open(b.store_parent,'directory')

 def test_readonly_unreturned_fd_class_drift_uses_only_captured_raw_close(self):
  b=self.adapter();calls=[]
  def changed(*args):calls.append('changed');raise AssertionError('changed BK callback')
  def hook(path):
   if path=='/etc/autosoft/installation.json':BK.ReadOnlySourceBackend._fd=changed;BK.ReadOnlySourceBackend.close=changed;SB.SeedBackend._dispose=changed
  self.ram.call_hook=hook
  with self.assertRaises(SB.SeedBackendUnavailable):b.open('/etc/autosoft/installation.json','file')
  self.assertEqual(calls,[]);self.assertFalse(self.ram.fds);self.assertFalse(b._fds);self.assertIs(b.require_released(),b)
 def test_readonly_public_close_preserves_other_caller_fds_after_method_drift(self):
  b=self.adapter();a=b.open('/etc/autosoft/installation.json','file');c=b.open('/etc/autosoft/installation.intent.json','file');calls=[]
  BK.ReadOnlySourceBackend._fd=lambda *args:calls.append('changed')
  BK.ReadOnlySourceBackend.close=lambda *args:calls.append('changed');SB.SeedBackend._dispose=lambda *args:calls.append('changed')
  b.close(a);self.assertIn(c,self.ram.fds);self.assertEqual(calls,[]);b.close(c);self.assertIs(b.require_released(),b)
 def test_write_unreturned_fd_class_drift_preserves_partial_and_caller_fds(self):
  b=self.adapter();parent,root=self.fresh(b);calls=[]
  def hook(path):
   if path==b.store_root+'/intent.json':BK.ReadOnlySourceBackend._fd=lambda *a:calls.append('changed');SB.SeedBackend._dispose=lambda *a:calls.append('changed')
  self.ram.call_hook=hook
  with self.assertRaises(SB.SeedBackendUnavailable):b.create(root,'intent.json',0,0,0o400)
  self.assertEqual(calls,[]);self.assertEqual(set(self.ram.fds),{parent,root});self.assertEqual(self.ram.nodes[b.store_root+'/intent.json']['raw'],b'')
  b.close(root);b.close(parent);self.assertIs(b.require_released(),b)
 def test_write_public_close_has_no_live_bk_or_dispose_callbacks(self):
  b=self.adapter();parent,root=self.fresh(b);fd=b.create(root,'intent.json',0,0,0o400);calls=[]
  BK.ReadOnlySourceBackend._fd=lambda *a:calls.append('changed');BK.ReadOnlySourceBackend.close=lambda *a:calls.append('changed');SB.SeedBackend._dispose=lambda *a:calls.append('changed')
  b.close(fd);self.assertEqual(set(self.ram.fds),{parent,root});self.assertEqual(calls,[]);b.close(root);b.close(parent);b.require_released()
 def test_replaced_read_ownership_is_unknown_without_foreign_callbacks(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file');original=b._read_backend._owned;calls=[]
  class Opaque:
   def __iter__(self):calls.append('iter');raise AssertionError('foreign')
   def __contains__(self,value):calls.append('contains');raise AssertionError('foreign')
  foreign=Opaque();b._read_backend._owned=foreign;before=len([e for e in self.ram.events if e[0]=='close'])
  with self.assertRaises(SB.SeedBackendUnavailable):b.close(fd)
  self.assertEqual(calls,[]);self.assertIn(fd,original);self.assertIn(fd,self.ram.fds)
  self.assertEqual(len([e for e in self.ram.events if e[0]=='close']),before);self.assertTrue(any(row[0] is b and row[1]=='ownership-boundary' for row in SB.UNRELEASED))
 def test_replaced_attempt_set_retains_original_and_current_refs(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file');original=b._read_backend._close_attempted;foreign=set();b._read_backend._close_attempted=foreign
  with self.assertRaises(SB.SeedBackendUnavailable):b.close(fd)
  retained=SB.UNRELEASED[-1][2];self.assertIs(retained[9],original);self.assertIs(retained[4]['_close_attempted'],foreign);self.assertIn(fd,self.ram.fds)
 def test_registered_owner_dictionary_replacement_never_guesses_close(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file');original=b._fds;replacement={};b._fds=replacement
  with self.assertRaises(SB.SeedBackendUnavailable):b.close(fd)
  retained=SB.UNRELEASED[-1][2];self.assertIs(retained[5],original);self.assertIs(retained[1]['_fds'],replacement);self.assertIn(fd,original);self.assertIn(fd,self.ram.fds)
 def test_unregistered_read_owner_member_denies_all_guessed_numeric_closes(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file');b._read_backend._owned.add(99999);before=len([e for e in self.ram.events if e[0]=='close'])
  with self.assertRaises(SB.SeedBackendUnavailable):b.close(fd)
  self.assertEqual(len([e for e in self.ram.events if e[0]=='close']),before);self.assertIn(fd,self.ram.fds);self.assertTrue(SB.UNRELEASED)
 def test_cleanup_reference_replacement_cannot_invoke_foreign_callback(self):
  b=self.adapter();fd=b.open('/etc/autosoft/installation.json','file');calls=[];b._cleanup_original=lambda *a,**k:calls.append('changed')
  with self.assertRaises(SB.SeedBackendUnavailable):b.close(fd)
  self.assertEqual(calls,[]);self.assertIn(fd,self.ram.fds);self.assertTrue(SB.UNRELEASED)
 def test_known_enumerator_parse_failure_raw_closes_only_transient_fd(self):
  b=self.adapter();fd=b.open(b.store_parent,'directory');self.ram.add(b.store_parent+'/invalid..',True,0o700)
  with self.assertRaises((SB.SeedBackendUnavailable,BK.SourceBackendUnavailable)):b.names(fd,0)
  self.assertEqual(set(self.ram.fds),{fd});self.assertIsNone(b._read_backend._enumeration);b.close(fd);b.require_released()
 def test_write_close_unknown_is_once_and_other_known_fds_remain_closable(self):
  b=self.adapter();parent,root=self.fresh(b);fd=b.create(root,'intent.json',0,0,0o400);self.ram.failure_close=b.store_root+'/intent.json'
  with self.assertRaises(SB.SeedBackendUnavailable):b.close(fd)
  with self.assertRaises(SB.SeedBackendUnavailable):b.close(fd)
  b.close(root);b.close(parent);self.assertEqual(set(self.ram.fds),{fd});self.assertEqual(len([e for e in self.ram.events if e[0]=='close' and e[2]==fd]),1)
  with self.assertRaises(SB.SeedBackendUnavailable):b.require_released()
 def test_write_postcreate_failure_raw_closes_registered_unreturned_fd(self):
  def fail_chown(fd,uid,gid):
   if stat.S_ISREG(self.ram.fstat(fd).st_mode):raise OSError('new chown injected')
   return self.ram.chown(fd,uid,gid)
  self.ram.os.fchown=fail_chown;b=self.adapter();parent,root=self.fresh(b)
  with self.assertRaises(OSError):b.create(root,'intent.json',0,0,0o400)
  self.assertEqual(set(self.ram.fds),{parent,root});self.assertEqual(self.ram.nodes[b.store_root+'/intent.json']['raw'],b'');b.close(root);b.close(parent);b.require_released()



class StatCompatibilityControls(unittest.TestCase):
 setUp=SeedBackendControls.setUp
 tearDown=SeedBackendControls.tearDown
 adapter=SeedBackendControls.adapter
 dispose=SeedBackendControls.dispose
 fresh=SeedBackendControls.fresh
 effects=SeedBackendControls.effects

 def fallback(self):
  self.stat_calls=[];original=self.ram.lstat
  def captured_stat(path,*,dir_fd=None,follow_symlinks=True):
   self.assertIs(follow_symlinks,False);self.stat_calls.append((path,dir_fd,follow_symlinks))
   return original(path,dir_fd=dir_fd)
  self.ram.os.stat=captured_stat
  self.ram.os.supports_dir_fd={self.ram.os.open,self.ram.os.mkdir,captured_stat}
  self.ram.os.supports_follow_symlinks={captured_stat}
  return captured_stat

 def test_qualified_lstat_path_keeps_original_callback_without_stat_capabilities(self):
  def forbidden(*a,**kw):raise AssertionError('qualified lstat needs no stat fallback')
  self.ram.os.stat=forbidden;self.ram.os.supports_follow_symlinks=set()
  b=self.adapter();self.assertIs(b._calls['lstat'],self.ram.os.lstat)
  fd=b.open('/etc/autosoft/installation.intent.json','file');b.close(fd)
  self.assertIs(self.dispose(b),b);self.assertEqual(self.effects(),[])

 def test_stat_fallback_accepts_three_twelve_memberships_and_reads_full9_nofollow(self):
  selected=self.fallback();self.assertNotIn(self.ram.os.lstat,self.ram.os.supports_dir_fd)
  self.assertIn(selected,self.ram.os.supports_dir_fd);self.assertIn(selected,self.ram.os.supports_follow_symlinks)
  b=self.adapter();fd=b.open('/etc/autosoft/installation.intent.json','file')
  self.assertEqual(b.pread(fd,32,0),self.ram.nodes['/etc/autosoft/installation.intent.json']['raw'][:32])
  self.assertEqual(set(b.fstat(fd)),set(SB.FIELDS));b.close(fd);self.assertIs(self.dispose(b),b)
  self.assertTrue(self.stat_calls);self.assertTrue(any(dir_fd is not None for _,dir_fd,_ in self.stat_calls))
  self.assertTrue(all(no_follow is False for _,_,no_follow in self.stat_calls));self.assertFalse(self.ram.fds)
  self.assertEqual(self.effects(),[])

 def test_fallback_store_write_and_seal_keep_original_exclusive_resource_policy(self):
  self.fallback();b=self.adapter();parent,root=self.fresh(b)
  fd=b.create(root,'intent.json',0,0,0o400);self.assertEqual(b.write(fd,b'bounded'),7)
  b.sync(fd);b.close(fd);b.chmod(root,0o500);b.sync(root)
  self.assertEqual(self.ram.nodes[b.store_root+'/intent.json']['raw'],b'bounded')
  self.assertEqual(stat.S_IMODE(self.ram.nodes[b.store_root]['info']['st_mode']),0o500)
  b.close(root);b.close(parent);self.assertIs(self.dispose(b),b);self.assertFalse(self.ram.fds)

 def test_fallback_requires_same_stat_function_in_both_plain_support_sets(self):
  for denial in ('dir','follow','noncallable','nonplain-dir','nonplain-follow'):
   with self.subTest(denial=denial):
    self.ram=RAM();selected=self.fallback()
    if denial=='dir':self.ram.os.supports_dir_fd.discard(selected)
    elif denial=='follow':self.ram.os.supports_follow_symlinks.clear()
    elif denial=='noncallable':self.ram.os.stat=None
    elif denial=='nonplain-dir':self.ram.os.supports_dir_fd=list(self.ram.os.supports_dir_fd)
    else:self.ram.os.supports_follow_symlinks=list(self.ram.os.supports_follow_symlinks)
    with self.assertRaises(ValueError):self.adapter()
    self.assertEqual(self.ram.events,[]);self.assertEqual(self.stat_calls,[])

 def test_fallback_fixed_path_dirfd_grammar_denies_before_stat_callback(self):
  self.fallback();b=self.adapter();selected=b._calls['lstat']
  for path,fd in (('/etc//autosoft',None),('relative',None),('..',7),('../bad',7),('/',7),('safe',True),('safe',-1),('safe',2**31),('safe/child',7)):
   with self.subTest(path=path,fd=fd),self.assertRaises(ValueError):selected(path,dir_fd=fd)
  self.assertEqual(self.stat_calls,[]);self.assertEqual(self.ram.events,[]);self.dispose(b)

 def test_fallback_uses_captured_stat_after_os_callback_replacement(self):
  self.fallback();b=self.adapter();foreign=[]
  def replacement(*a,**kw):foreign.append((a,kw));raise AssertionError('replacement stat/lstat')
  self.ram.os.stat=self.ram.os.lstat=replacement
  fd=b.open('/etc/autosoft/installation.intent.json','file');b.close(fd);self.dispose(b)
  self.assertEqual(foreign,[]);self.assertTrue(self.stat_calls);self.assertFalse(self.ram.fds)

 def test_fallback_symlink_ancestor_and_hardlink_refusals_preserve_no_write(self):
  for altered in ('symlink','hardlink'):
   with self.subTest(altered=altered):
    self.ram=RAM();self.fallback()
    if altered=='symlink':self.ram.nodes['/etc/autosoft']['info']['st_mode']=stat.S_IFLNK|0o777
    else:self.ram.nodes['/etc/autosoft/installation.intent.json']['info']['st_nlink']=2
    b=self.adapter()
    with self.assertRaises((ValueError,OSError)):b.open('/etc/autosoft/installation.intent.json','file')
    self.dispose(b);self.assertEqual(self.effects(),[]);self.assertFalse(self.ram.fds)

 def test_fallback_metadata_drift_denies_and_raw_cleanup_remains_known(self):
  self.fallback();original=self.ram.os.stat
  def changed(path,*,dir_fd=None,follow_symlinks=True):
   info=original(path,dir_fd=dir_fd,follow_symlinks=follow_symlinks)
   if path=='installation.intent.json':self.ram.nodes['/etc/autosoft/installation.intent.json']['info']['st_ino']+=1
   return info
  self.ram.os.stat=changed;self.ram.os.supports_dir_fd.add(changed);self.ram.os.supports_follow_symlinks.add(changed)
  b=self.adapter()
  with self.assertRaises(ValueError):b.open('/etc/autosoft/installation.intent.json','file')
  self.dispose(b);self.assertEqual(self.effects(),[]);self.assertFalse(self.ram.fds)

 def test_fallback_stat_exception_closes_known_transients_without_retry(self):
  self.fallback();original=self.ram.os.stat
  def fail(path,*,dir_fd=None,follow_symlinks=True):
   if path=='etc':raise OSError('injected saved stat')
   return original(path,dir_fd=dir_fd,follow_symlinks=follow_symlinks)
  self.ram.os.stat=fail;self.ram.os.supports_dir_fd.add(fail);self.ram.os.supports_follow_symlinks.add(fail)
  b=self.adapter()
  with self.assertRaises(OSError):b.open('/etc/autosoft/installation.intent.json','file')
  self.dispose(b);self.assertFalse(self.ram.fds);self.assertEqual(self.effects(),[])




class StatDirectoryControls(unittest.TestCase):
 setUp=SeedBackendControls.setUp
 tearDown=SeedBackendControls.tearDown
 adapter=SeedBackendControls.adapter
 dispose=SeedBackendControls.dispose
 effects=SeedBackendControls.effects
 fallback=StatCompatibilityControls.fallback

 def test_stat_fallback_directory_inventory_knownclose_and_regular_ancestor_refusal(self):
  self.fallback();b=self.adapter();fd=b.open('/etc/autosoft','directory')
  expected=sorted(PurePosixPath(path).name for path in self.ram.nodes if str(PurePosixPath(path).parent)=='/etc/autosoft')
  self.assertEqual(b.names(fd,len(expected)),expected);b.close(fd);self.assertIs(self.dispose(b),b)
  self.assertFalse(self.ram.fds);self.assertTrue(self.stat_calls)
  self.assertTrue(all(no_follow is False for _,_,no_follow in self.stat_calls));self.assertEqual(self.effects(),[])
  self.ram=RAM();self.fallback();self.ram.nodes['/etc/autosoft']['info']['st_mode']=stat.S_IFREG|0o700
  b=self.adapter()
  with self.assertRaises((ValueError,OSError)):b.open('/etc/autosoft/installation.intent.json','file')
  self.dispose(b);self.assertFalse(self.ram.fds);self.assertEqual(self.effects(),[])


if __name__=='__main__':unittest.main(verbosity=2)
