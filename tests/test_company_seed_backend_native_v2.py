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
SOURCES={path:(ROOT/path).read_bytes() for path in W.INPUT_PINS}

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

if __name__=='__main__':unittest.main(verbosity=2)
