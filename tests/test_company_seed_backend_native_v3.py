"""Affected V2 admission/carrier controls only; no native station or SSH.

The fourteen original V1 bodies and their historical raw lane remain unchanged.
The preparer here receives entirely synthetic metadata/syscalls. Reaching its
first exclusive mkdir boundary is neither a write nor native device authority.
"""
import ast
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat
import sys
from types import ModuleType, SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path)
 value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
 return value

W=load('seed_backend_native_v2_probe_controls','deploy/validation/company-seed-backend-native-v2.py')
C=load('seed_backend_native_v2_carrier_controls','scripts/company_seed_backend_native_client_v2.py')
SOURCES={path:((ROOT/'tests/fixtures/company_seed_backend_before_stat_compat.py').read_bytes() if path=='deploy/installer/company_seed_backend.py' else (ROOT/path).read_bytes()) for path in W.INPUT_PINS}

def scope():
 return dict(schemaVersion=1,status='DISABLED_SOURCE_PROPOSAL',nativeOneAttempt=False,
  operationId='0'*32,root=W.PREFIX+'0'*32,notBefore=0,expiresAt=0,maxAttempts=1,
  maxSeconds=60,maxInputBytes=W.MAX_INPUT,maxOutputBytes=W.MAX_OUTPUT,maxWriteBytes=W.MAX_WRITES,
  maxFds=192,deviceMajorMinor=[253,3],dmUuid=W.DM_UUID.decode(),
  inputPinsSha256=W.sha(W.canonical(W.INPUT_PINS)),releaseSha256=W.RELEASE)

class FirstExclusiveBoundary(Exception):pass

class MapperStation(W.NativeStation):
 """Execute the actual preparer admission against explicit inert observations."""
 def __init__(self,**changes):
  self.target=SimpleNamespace(st_mode=stat.S_IFBLK|0o660,st_uid=0,st_gid=6,st_rdev=64771,
   st_dev=6,st_ino=553,st_nlink=1,st_size=0,st_mtime_ns=11,st_ctime_ns=11)
  for key,value in changes.items():setattr(self.target,key,value)
  self.validation=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0,
   st_dev=64771,st_ino=44,st_nlink=2,st_size=0,st_mtime_ns=9,st_ctime_ns=9)
  self.resource_calls=[];self.device_opens=[];self.device_closes=[];self.mkdir_calls=[]
  self.resource=SimpleNamespace(**{name:index for index,name in enumerate(('RLIMIT_AS','RLIMIT_CPU','RLIMIT_NOFILE','RLIMIT_FSIZE','RLIMIT_CORE'))},
   setrlimit=lambda which,bounds:self.resource_calls.append((which,bounds)))
  self.signal=SimpleNamespace(SIGALRM=14,ITIMER_REAL=0,signal=lambda *a:None,setitimer=lambda *a:None)
  self.os=SimpleNamespace(name='posix',getresuid=lambda:(0,0,0),getresgid=lambda:(0,0,0),
   major=lambda dev:253,minor=lambda dev:3,O_PATH=1,O_NOFOLLOW=2,O_CLOEXEC=4)
  self.sys=SimpleNamespace(platform='linux',byteorder='little')
  self.machine=SimpleNamespace(machine=lambda:'x86_64')
  self.clock=lambda:1;self.end=60;self.alarm=False;self.fixtureCreated=False;self.effectAttempted=False
  self.calls=dict(fstat=lambda fd:self.validation if fd==7 else self.target,
   lstat=lambda path:self.target,readlink=lambda path:'../dm-3',getpid=lambda:77,
   fstatvfs=lambda fd:SimpleNamespace(f_bavail=1024,f_frsize=4096))
  self.records={W.VALIDATION:(7,self.meta(self.validation))}
 def hold(self,path,directory,mode=None):
  assert path==W.VALIDATION and directory is True
  return 7
 def small(self,path,maximum):
  if path=='/proc/77/mountinfo':return b'24 1 253:3 / /srv/autosoft rw,nosuid,nodev - xfs /dev/mapper/autosoft-data rw\n'
  assert path=='/sys/devices/virtual/block/dm-3/dm/uuid'
  return W.DM_UUID
 def open(self,path,flags):
  self.device_opens.append((path,flags));return 8
 def close(self,fd):self.device_closes.append(fd)
 def mkdir(self,parent,name):
  self.mkdir_calls.append((parent,name));raise FirstExclusiveBoundary()

class MapperAdmissionControls(unittest.TestCase):
 def tearDown(self):W.UNKNOWN.clear();C.UNRELEASED.clear()
 def test_root_disk_block_device_reaches_first_exclusive_boundary_after_full9(self):
  station=MapperStation()
  with self.assertRaises(FirstExclusiveBoundary):station.prepare(scope(),SOURCES,W.canonical(scope()))
  self.assertEqual(station.device_opens,[('/dev/dm-3',7)])
  self.assertEqual(station.device_closes,[8])
  self.assertEqual(station.mkdir_calls,[(W.VALIDATION,PurePosixPath(scope()['root']).name)])
  self.assertFalse(station.fixtureCreated);self.assertFalse(station.effectAttempted)
  self.assertEqual([bounds for _,bounds in station.resource_calls],[(268435456,268435456),(60,61),(192,192),(262144,262144),(0,0)])
 def test_wrong_uid_gid_type_or_device_refuses_before_mapper_open_or_first_write(self):
  for change in ({'st_uid':10001},{'st_gid':0},{'st_gid':7},{'st_mode':stat.S_IFREG|0o660},{'st_rdev':64772},{'st_uid':False},{'st_gid':6.0}):
   with self.subTest(change=change):
    station=MapperStation(**change)
    with self.assertRaises(ValueError):station.prepare(scope(),SOURCES,W.canonical(scope()))
    self.assertEqual(station.device_opens,[]);self.assertEqual(station.mkdir_calls,[])
    self.assertFalse(station.fixtureCreated);self.assertFalse(station.effectAttempted)
 def test_path_fd_full9_mapper_drift_still_denies_before_first_write(self):
  station=MapperStation();original=station.calls['fstat']
  def drift(fd):
   if fd!=8:return original(fd)
   return SimpleNamespace(**dict(vars(station.target),st_ino=station.target.st_ino+1))
  station.calls['fstat']=drift
  with self.assertRaises(ValueError):station.prepare(scope(),SOURCES,W.canonical(scope()))
  self.assertEqual(station.device_opens,[('/dev/dm-3',7)]);self.assertEqual(station.mkdir_calls,[])
 def test_fresh_v2_disabled_packet_binds_exact_worker_and_keeps_caps(self):
  raw=W.canonical(scope());worker=(ROOT/'deploy/validation/company-seed-backend-native-v2.py').read_bytes()
  built=C.build(raw,worker,SOURCES)
  self.assertEqual(C.unpack(built['packet'],packed_pin=(C.sha(built['packet']),len(built['packet'])),
   scope_pin=(C.sha(raw),len(raw)),worker_pin=C.WORKER_PIN),(raw,worker,SOURCES))
  self.assertEqual(W.validate_scope(raw,1,allow_disabled=True)['nativeOneAttempt'],False)
  with self.assertRaises(ValueError):W.validate_scope(raw,1)
  self.assertEqual((C.MAX_COMPRESSED,C.MAX_EXPANDED,C.MAX_COMMAND,C.MAX_OUTPUT),(131072,262144,131072,16384))
  with self.assertRaises(ValueError):C.packet(raw,(ROOT/'deploy/validation/company-seed-backend-native-v1.py').read_bytes(),SOURCES)
  args=C.fixed_argv(C.ROOT/'.local'/('company-seed-backend-native-dispatch-v2-'+'a'*32))
  self.assertEqual(len(args),9);self.assertIn('-T',args)
  self.assertLess(len(C.subprocess.list2cmdline(args).encode('utf-16-le'))//2+1,4096)
  self.assertLessEqual(len(built['packet']),C.MAX_COMPRESSED);self.assertLessEqual(len(built['command']),C.MAX_COMMAND)
 def test_original_v1_fourteen_bodies_and_whole_test_remain_historical_unchanged(self):
  raw=(ROOT/'tests/test_company_seed_backend_native_v1.py').read_bytes()
  self.assertEqual((hashlib.sha256(raw).hexdigest(),len(raw)),('39c7c96ea2ad53dd0f2edf0dfbb919fd05191750f223a3502440b9da55faa466',11894))
  tree=ast.parse(raw)
  names=[f.name for c in tree.body if isinstance(c,ast.ClassDef) for f in c.body if isinstance(f,ast.FunctionDef) and f.name.startswith('test_')]
  self.assertEqual(len(names),14);self.assertEqual(len(set(names)),14)



# V2 MapperAdmissionControls above stay byte-exact and use historical bytes.
# Only the four new V3Controls below are selected by this proposal's runner.
W3=load('seed_backend_native_v3_probe_controls','deploy/validation/company-seed-backend-native-v3.py')
C3=load('seed_backend_native_v3_carrier_controls','scripts/company_seed_backend_native_client_v3.py')
SB3=load('seed_backend_native_v3_fixture_sb','deploy/installer/company_seed_backend.py')
BK3=load('seed_backend_native_v3_fixture_bk','scripts/company_source_guard_backend.py')
SOURCES3={path:(ROOT/path).read_bytes() for path in W3.INPUT_PINS}

def scope3(disabled=True):
 value=scope();op='0'*32 if disabled else 'a'*32
 value.update(operationId=op,root=W3.PREFIX+op,
  status='DISABLED_SOURCE_PROPOSAL' if disabled else 'ROOT_AUTHORIZED_ONE_SYNTHETIC_SEED_BACKEND_PROBE',
  nativeOneAttempt=not disabled,expiresAt=0 if disabled else 1000,
  inputPinsSha256=W3.sha(W3.canonical(W3.INPUT_PINS)))
 return value

# Extract explicit RAM and preparer fixture definitions only. No previous
# tests, native preparation, original Store/Source/P/SeedStorage or OS is run.
fixture3=ModuleType('explicit_sb_v3_ram_fixture')
fixture3.__dict__.update(copy=__import__('copy'),stat=stat,PurePosixPath=PurePosixPath,
 SimpleNamespace=SimpleNamespace,SB=SB3,BK=BK3,W=W3)
old_fixture=ast.parse((ROOT/'tests/test_company_seed_backend.py').read_bytes())
ram_nodes=[n for n in old_fixture.body if isinstance(n,ast.ClassDef) and n.name in ('Buffer','RAM')]
station_nodes=[n for n in ast.parse((ROOT/'tests/test_company_seed_backend_native_v1.py').read_bytes()).body if isinstance(n,ast.ClassDef) and n.name=='InjectedStation']
assert len(ram_nodes)==2 and len(station_nodes)==1
exec(compile(ast.Module(body=ram_nodes+station_nodes,type_ignores=[]),'<explicit V3 fixture definitions only>','exec'),vars(fixture3))

class V3Controls(unittest.TestCase):
 def tearDown(self):
  W3.UNKNOWN.clear();C3.UNRELEASED.clear();SB3.UNRELEASED.clear();BK3.UNRELEASED_RESOURCES.clear();SB3._CLOSE_SCOPES.clear()
  for name in tuple(sys.modules):
   if name.startswith('company_seed_backend_probe_'):del sys.modules[name]
 def station(self):return fixture3.InjectedStation(fixture3.RAM())
 def test_v3_current_backend_admitted_and_historical_backend_refused_before_prepare(self):
  W3.source_admission(SOURCES3)
  self.assertEqual(W3.INPUT_PINS['deploy/installer/company_seed_backend.py'],dict(sha256='ae7be5f73b5e279cde64f12bf031d0cb84576ac045f90e423775a093891fe768',bytes=28806))
  old=(ROOT/'tests/fixtures/company_seed_backend_before_stat_compat.py').read_bytes()
  old_sources=dict(SOURCES3,**{'deploy/installer/company_seed_backend.py':old});station=self.station()
  result=W3.run(W3.canonical(scope3(False)),old_sources,station=station)
  self.assertEqual(result['phase'],'source-admission');self.assertFalse(station.fixtureCreated);self.assertFalse(station.effectAttempted)
  self.assertFalse(station.ram.fds)
 def test_current_stat_fallback_complete_tiny_protocol_and_knownclose_under_ram(self):
  station=self.station();ram=station.ram;old=ram.lstat;calls=[]
  def captured_stat(path,*,dir_fd=None,follow_symlinks=True):
   self.assertIs(follow_symlinks,False);calls.append((path,dir_fd,follow_symlinks));return old(path,dir_fd=dir_fd)
  ram.os.stat=captured_stat;ram.os.supports_dir_fd={ram.os.open,ram.os.mkdir,captured_stat};ram.os.supports_follow_symlinks={captured_stat}
  result=W3.run(W3.canonical(scope3(False)),SOURCES3,station=station)
  self.assertEqual(result['status'],'SYNTHETIC_SEED_BACKEND_OBSERVED_ONLY');self.assertEqual(result['outputFiles'],17)
  self.assertTrue(result['conflictRefused']);self.assertTrue(result['allOwnedResourcesKnownReleased']);self.assertFalse(ram.fds)
  self.assertTrue(calls);self.assertTrue(all(follow is False for _,_,follow in calls))
  self.assertEqual(len(station.adapters),2);self.assertEqual(len(result['preparedDirectories']),6)
  self.assertTrue(all(stat.S_IMODE(row['st_mode'])==0o500 for row in result['preparedDirectories'].values()))
  self.assertTrue(all(stat.S_IMODE(row['metadata']['st_mode'])==0o400 for row in result['outputs'].values()))
  for name in ('signatureCreated','parentAuthorityQualified','storageAuthorityQualified','installerActivated','nativeCapacityQualified','automaticRetry'):self.assertIs(result[name],False)
 def test_v3_disabled_packet_exact_roundtrip_caps_and_old_worker_refusal(self):
  raw=W3.canonical(scope3());worker=(ROOT/'deploy/validation/company-seed-backend-native-v3.py').read_bytes()
  built=C3.build(raw,worker,SOURCES3)
  self.assertEqual(C3.unpack(built['packet'],packed_pin=(C3.sha(built['packet']),len(built['packet'])),scope_pin=(C3.sha(raw),len(raw)),worker_pin=C3.WORKER_PIN),(raw,worker,SOURCES3))
  self.assertEqual((C3.MAX_COMPRESSED,C3.MAX_EXPANDED,C3.MAX_COMMAND,C3.MAX_OUTPUT),(131072,262144,131072,16384))
  with self.assertRaises(ValueError):C3.packet(raw,(ROOT/'deploy/validation/company-seed-backend-native-v2.py').read_bytes(),SOURCES3)
  with self.assertRaises(ValueError):W3.validate_scope(raw,1)
  argv=C3.fixed_argv(C3.ROOT/'.local'/('company-seed-backend-native-dispatch-v3-'+'a'*32))
  self.assertEqual(len(argv),9);self.assertIn('-T',argv);self.assertLess(len(C3.subprocess.list2cmdline(argv).encode('utf-16-le'))//2+1,4096)
 def test_v3_closed_scope_rejects_consumed_namespace_alias_and_member_drift(self):
  raw=W3.canonical(scope3());self.assertEqual(W3.validate_scope(raw,1,allow_disabled=True)['operationId'],'0'*32)
  for change in ({'root':W.PREFIX+'0'*32},{'maxFds':True},{'maxWriteBytes':262145},{'extra':True}):
   value=scope3();value.update(change)
   with self.subTest(change=change),self.assertRaises(ValueError):W3.validate_scope(W3.canonical(value),1,allow_disabled=True)
  bad=dict(SOURCES3,**{'scripts/company_source_guard_backend.py':b'changed'})
  with self.assertRaises(ValueError):W3.source_admission(bad)


if __name__=='__main__':unittest.main(verbosity=2)
