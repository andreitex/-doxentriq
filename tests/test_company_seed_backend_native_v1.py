"""Pure/injected proposal controls; no Linux OS, Plink or original stage run."""
import ast,copy,gzip,hashlib,importlib.util,io,json,stat,sys,threading,time
from pathlib import Path,PurePosixPath
from types import ModuleType,SimpleNamespace
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
W=load('seed_backend_native_probe_controls','deploy/validation/company-seed-backend-native-v1.py')
C=load('seed_backend_native_carrier_controls','scripts/company_seed_backend_native_client_v1.py')
SB=load('seed_backend_native_fixture_sb','deploy/installer/company_seed_backend.py')
BK=load('seed_backend_native_fixture_bk','scripts/company_source_guard_backend.py')
sources={p:(ROOT/p).read_bytes() for p in W.INPUT_PINS}
def scope(disabled=False):
 op='0'*32 if disabled else 'a'*32
 return dict(schemaVersion=1,status='DISABLED_SOURCE_PROPOSAL' if disabled else 'ROOT_AUTHORIZED_ONE_SYNTHETIC_SEED_BACKEND_PROBE',nativeOneAttempt=not disabled,operationId=op,root=W.PREFIX+op,
  notBefore=0,expiresAt=0 if disabled else 1000,maxAttempts=1,maxSeconds=60,maxInputBytes=W.MAX_INPUT,maxOutputBytes=W.MAX_OUTPUT,maxWriteBytes=W.MAX_WRITES,maxFds=192,
  deviceMajorMinor=[253,3],dmUuid=W.DM_UUID.decode(),inputPinsSha256=W.sha(W.canonical(W.INPUT_PINS)),releaseSha256=W.RELEASE)

# Only the explicit RAM syscall fixture definitions are extracted. No existing
# suite or Store/Source/SeedStorage operation is executed or inherited.
fixture_raw=(ROOT/'tests/test_company_seed_backend.py').read_bytes();fixture_tree=ast.parse(fixture_raw)
fixture=ModuleType('explicit_seed_backend_probe_ram');fixture.__dict__.update(copy=copy,stat=stat,PurePosixPath=PurePosixPath,SimpleNamespace=SimpleNamespace,SB=SB,BK=BK)
fixture_nodes=[n for n in fixture_tree.body if isinstance(n,ast.ClassDef) and n.name in ('Buffer','RAM')]
assert len(fixture_nodes)==2
exec(compile(ast.Module(body=fixture_nodes,type_ignores=[]),'<explicit RAM fixture only>','exec'),vars(fixture))

class InjectedStation(W.NativeStation):
 def __init__(self,ram):
  self.ram=ram;ram.os.fstatvfs=lambda fd:SimpleNamespace(f_bavail=1024,f_frsize=4096)
  ram.os.readlink=lambda p:'../dm-3';ram.os.getpid=lambda:77
  super().__init__(os_module=ram.os,sys_module=ram.system,ctypes_module=ram.ctypes,libc=object(),machine_module=SimpleNamespace(machine=lambda:'x86_64'),resource_module=None,signal_module=None,clock=lambda:1,wall=lambda:1)
  for p in ('/srv/autosoft','/srv/autosoft/validation'):
   ram.add(p,True,0o755)
 def prepare(self,value,sources,raw):
  # The native encrypted mapper/resource branch is deliberately not qualified.
  self.hold(W.VALIDATION,True);root,_=self.mkdir(W.VALIDATION,PurePosixPath(value['root']).name);self.fixtureCreated=True
  self.put(root,'scope.json',raw);inputs,_=self.mkdir(root,'inputs')
  for i,(_,data) in enumerate(sorted(sources.items())):self.put(inputs,str(i)+'.source',data)
  self.data,_=self.mkdir(root,'data');company,_=self.mkdir(self.data,'company')
  self.mkdir(company,'platform-releases');self.mkdir(company,'source-releases');self.check()
  self.mutable_parents={company+'/platform-releases',company+'/source-releases'}

class ProbeControls(unittest.TestCase):
 def setUp(self):self.rams=[]
 def tearDown(self):
  # Synthetic-only unknown registries; no product reset or native retry.
  W.UNKNOWN.clear();C.UNRELEASED.clear();SB.UNRELEASED.clear();BK.UNRELEASED_RESOURCES.clear();SB._CLOSE_SCOPES.clear()
  for key in list(sys.modules):
   if key.startswith('company_seed_backend_probe_'):del sys.modules[key]
 def station(self):
  ram=fixture.RAM();self.rams.append(ram);return InjectedStation(ram)
 def test_disabled_exact_scope_and_unset_op_never_admit_run(self):
  raw=W.canonical(scope(True));self.assertEqual(W.validate_scope(raw,1,allow_disabled=True)['operationId'],'0'*32)
  with self.assertRaises(ValueError):W.validate_scope(raw,1)
  st=self.station();result=W.run(raw,sources,station=st);self.assertEqual(result['status'],'SYNTHETIC_SEED_BACKEND_UNAVAILABLE');self.assertFalse(result['possibleFixtureEffect'])
 def test_closed_scope_types_bounds_expiry_and_root_refusal(self):
  changes=({'maxAttempts':2},{'maxSeconds':True},{'root':'/srv/autosoft/old-data'},{'expiresAt':90},{'inputPinsSha256':'0'*64},{'releaseSha256':'c'*64},{'extra':True},{'deviceMajorMinor':[253,True]})
  for change in changes:
   v=scope();v.update(change)
   with self.subTest(change=change),self.assertRaises(ValueError):W.validate_scope(W.canonical(v),1)
 def test_source_admission_wrong_hash_alias_or_text_denies_before_effect(self):
  for bad in ({**sources,next(iter(sources)):b'changed'},{**sources,'extra.py':b'extra'},{k:v.decode() for k,v in sources.items()}):
   st=self.station();result=W.run(W.canonical(scope()),bad,station=st);self.assertEqual(result['phase'],'source-admission');self.assertFalse(st.effectAttempted)
 def test_real_adapter_protocol_tiny_store_source_seal_readback_conflict(self):
  st=self.station();result=W.run(W.canonical(scope()),sources,station=st)
  self.assertEqual(result['status'],'SYNTHETIC_SEED_BACKEND_OBSERVED_ONLY');self.assertEqual(len(result['outputs']),17)
  self.assertEqual(result['storeFiles'],12);self.assertEqual(result['sourceFiles'],3);self.assertTrue(result['conflictRefused']);self.assertTrue(result['allOwnedResourcesKnownReleased'])
  self.assertEqual(len(st.adapters),2);self.assertFalse(st.ram.fds);self.assertEqual(len(result['preparedDirectories']),6)
  self.assertTrue(all(stat.S_IMODE(row['st_mode'])==0o500 for row in result['preparedDirectories'].values()))
  self.assertTrue(all(stat.S_IMODE(row['metadata']['st_mode'])==0o400 for row in result['outputs'].values()))
  for name in ('descriptorReservationGuaranteed','diskReservationGuaranteed','signatureCreated','parentAuthorityQualified','storageAuthorityQualified','installerActivated','nativeCapacityQualified','automaticRetry'):self.assertIs(result[name],False)
  old=[e for e in st.ram.events if len(e)>1 and isinstance(e[1],str) and (e[1].startswith('/etc/') or e[1]=='/var/lib/autosoft.luks')]
  self.assertEqual(old,[])
 def test_preparer_returned_close_failure_latches_and_other_closes_attempt(self):
  st=self.station();st.ram.failure_close=W.PREFIX+'a'*32+'/scope.json';result=W.run(W.canonical(scope()),sources,station=st)
  self.assertEqual(result['status'],'SYNTHETIC_SEED_BACKEND_UNAVAILABLE');self.assertFalse(result['allOwnedResourcesKnownReleased']);self.assertTrue(W.UNKNOWN)
  failures=[e for e in st.ram.events if e[0]=='close' and e[1]==st.ram.failure_close];self.assertEqual(len(failures),1)
 def test_preparer_descriptor_budget_leaves_external_room_and_denies_before_open(self):
  st=self.station();flags=st.os.O_RDONLY|st.os.O_DIRECTORY|st.os.O_CLOEXEC
  for _ in range(W.MAX_PREPARER_FDS):st.open('/',flags)
  before=len(st.ram.events)
  with self.assertRaises(ValueError):st.open('/',flags)
  self.assertEqual(len(st.ram.events),before);self.assertEqual(W.MAX_PREPARER_FDS,32);self.assertLessEqual(W.BUDGET['ownedFds']+W.MAX_PREPARER_FDS+3,192)
  st.finish();self.assertFalse(st.ram.fds);self.assertFalse(st.owned)
 def test_existing_fresh_namespace_refused_preserves_sentinel(self):
  st=self.station();path=W.PREFIX+'a'*32;st.ram.add(path,True,0o700);st.ram.add(path+'/sentinel',False,0o400,b'preserve')
  result=W.run(W.canonical(scope()),sources,station=st);self.assertEqual(result['status'],'SYNTHETIC_SEED_BACKEND_UNAVAILABLE');self.assertEqual(st.ram.nodes[path+'/sentinel']['raw'],b'preserve');self.assertFalse(st.adapters)
 def test_root_inode_replacement_between_adapters_denies(self):
  st=self.station();original=st.adapter;calls=[0]
  def adapter(*args):
   calls[0]+=1
   if calls[0]==2:st.ram.nodes[W.PREFIX+'a'*32]['info']['st_ino']+=1000
   return original(*args)
  st.adapter=adapter;result=W.run(W.canonical(scope()),sources,station=st);self.assertEqual(result['status'],'SYNTHETIC_SEED_BACKEND_UNAVAILABLE');self.assertEqual(result['phase'],'independent-readback')
 def test_staged_source_byte_drift_with_stable_metadata_denies(self):
  st=self.station();original=st.adapter
  def adapter(*args):
   path=W.PREFIX+'a'*32+'/inputs/0.source';raw=st.ram.nodes[path]['raw'];st.ram.nodes[path]['raw']=b'!'+raw[1:];return original(*args)
  st.adapter=adapter;result=W.run(W.canonical(scope()),sources,station=st);self.assertEqual(result['status'],'SYNTHETIC_SEED_BACKEND_UNAVAILABLE');self.assertFalse(st.adapters)
 def test_packet_roundtrip_exact_two_sources_and_command_geometry(self):
  worker=(ROOT/'deploy/validation/company-seed-backend-native-v1.py').read_bytes();raw=W.canonical(scope(True));built=C.build(raw,worker,sources)
  got=C.unpack(built['packet'],packed_pin=(C.sha(built['packet']),len(built['packet'])),scope_pin=(C.sha(raw),len(raw)),worker_pin=C.WORKER_PIN)
  self.assertEqual(got,(raw,worker,sources));self.assertLessEqual(len(built['packet']),131072);self.assertLessEqual(len(built['command']),131072)
  self.assertIn(b'/usr/bin/python3 -I -B -c ',built['command']);self.assertIn(b'setitimer(signal.ITIMER_REAL,60)',built['command']);self.assertIn(b'(192,192)',built['command'])
  argv=C.fixed_argv(C.ROOT/'.local'/('company-seed-backend-native-dispatch-v1-'+'a'*32));self.assertIn('-T',argv);self.assertEqual(len(argv),9);self.assertLess(len(C.subprocess.list2cmdline(argv).encode('utf-16-le'))//2+1,4096)
 def test_packet_hash_concatenated_tail_header_bool_and_expanded_caps_refuse(self):
  raw=W.canonical(scope(True));worker=(ROOT/'deploy/validation/company-seed-backend-native-v1.py').read_bytes();packet=C.packet(raw,worker,sources)
  cases=[(packet,('0'*64,len(packet))),(packet+gzip.compress(b'extra'),None),(gzip.compress(b'x'*(C.MAX_EXPANDED+1)),None)]
  expanded=gzip.decompress(packet);length=int.from_bytes(expanded[:4],'big');header=C.decode(expanded[4:4+length],16384);header['worker']['bytes']=True;h=C.canonical(header)
  cases.append((gzip.compress(len(h).to_bytes(4,'big')+h+expanded[4+length:]),None))
  for data,pin in cases:
   with self.subTest(length=len(data)),self.assertRaises(ValueError):C.unpack(data,packed_pin=pin or (C.sha(data),len(data)),scope_pin=(C.sha(raw),len(raw)),worker_pin=C.WORKER_PIN)
 def test_default_dispatch_denial_never_calls_process(self):
  with mock.patch.object(C.subprocess,'Popen',side_effect=AssertionError('native process')):
   with self.assertRaises(ValueError):C.dispatch_once(C.ROOT/'.local'/'unused',expected_command=('0'*64,1),expected_packet=('0'*64,1),expected_scope=('0'*64,1),explicit_action=None)
 def test_injected_three_pipe_supervisor_binary_eof_and_owned_reap(self):
  class Process:
   def __init__(self):self.stdin=io.BytesIO();self.stdout=io.BytesIO(b'bounded result');self.stderr=io.BytesIO();self.kills=0
   def wait(self,timeout):return 0
   def kill(self):self.kills+=1
  p=Process();r=C.supervise(['fixed'],b'packet',factory=lambda *a,**k:p)
  self.assertTrue(r['localLifetimeKnown']);self.assertEqual(r['stdout'],b'bounded result');self.assertEqual(r['captureEof'],['stderr','stdout']);self.assertTrue(r['threadsJoined']);self.assertTrue(r['pipesClosed']);self.assertFalse(r['remoteCancellationProven']);self.assertEqual(p.kills,0)
 def test_supervisor_output_overflow_retains_bounded_unknown_without_retry(self):
  class Process:
   def __init__(self):self.stdin=io.BytesIO();self.stdout=io.BytesIO(b'x'*(C.MAX_OUTPUT+1));self.stderr=io.BytesIO()
   def wait(self,timeout):return 0
   def kill(self):pass
  r=C.supervise(['fixed'],b'packet',factory=lambda *a,**k:Process())
  self.assertFalse(r['localLifetimeKnown']);self.assertLessEqual(len(r['stdout']),C.MAX_OUTPUT);self.assertIn('stdout_overflow',r['errors']);self.assertTrue(C.UNRELEASED);self.assertFalse(r['automaticRetry'])

if __name__=='__main__':unittest.main(verbosity=2)
