"""Synthetic catalog/process/resource controls only; no native tool origins."""
import ast,copy,gzip,hashlib,importlib.util,io,json,stat,sys
from pathlib import Path
from types import ModuleType,SimpleNamespace
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
W=load('readonly_seed_runner_probe','deploy/validation/company-seed-runner-native-v1.py')
C=load('readonly_seed_runner_probe_client','scripts/company_seed_runner_native_client_v1.py')
R=load('readonly_seed_runner_original_fixture','deploy/installer/company_seed_runner.py')
sources={p:(ROOT/p).read_bytes() for p in W.INPUT_PINS}
# Exact explicit fake kernel/process fixtures, never an old suite or native API.
raw=(ROOT/'tests/test_company_seed_runner.py').read_bytes();tree=ast.parse(raw);fixture=ModuleType('explicit_readonly_runner_fixture')
fixture.__dict__.update(R=R,stat=stat,hashlib=hashlib,ModuleType=ModuleType,SimpleNamespace=SimpleNamespace,DATA='/srv/autosoft/data',BACKING='/var/lib/autosoft.img')
nodes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name in ('Clock','Harness')];assert len(nodes)==2
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<explicit kernel fixture>','exec'),vars(fixture))
OUTPUT=b'ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nControlGroup=\nLoadState=not-found\n'
def tool_catalog(h):
 return W.canonical({p:dict(sha256=hashlib.sha256(h.nodes[p]['raw']).hexdigest(),bytes=len(h.nodes[p]['raw']),identity=dict(h.nodes[p]['info'])) for p in W.TOOLS})
def scope(raw,disabled=False):
 return dict(schemaVersion=1,status='DISABLED_SOURCE_PROPOSAL' if disabled else 'ROOT_AUTHORIZED_ONE_READONLY_SEED_RUNNER_PROBE',nativeOneAttempt=not disabled,operationId='0'*32 if disabled else 'a'*32,notBefore=0,expiresAt=0 if disabled else 1000,
  maxAttempts=1,maxSeconds=70,maxInputBytes=131072,maxOutputBytes=16384,maxFds=96,toolCatalogSha256=W.sha(raw),sourcePinsSha256=W.sha(W.canonical(W.INPUT_PINS)),commandSha256=W.sha(W.canonical(list(W.VECTOR))))
def Resource():
 r=ModuleType('explicit_fake_resource');r.RLIMIT_AS=1;r.RLIMIT_CPU=2;r.RLIMIT_NOFILE=3;r.RLIMIT_FSIZE=4;r.RLIMIT_CORE=5;r.values={4:(0,16777216)};r.events=[];r.bad_restore=False
 def getrlimit(key):return r.values[key]
 def setrlimit(key,value):
  r.events.append((key,value))
  if r.bad_restore and key==4 and value[0]==0 and r.values.get(key,(0,))[0]>0:raise OSError('injected restoration failure')
  r.values[key]=value
 r.getrlimit=getrlimit;r.setrlimit=setrlimit;return r
class Controls(unittest.TestCase):
 def tearDown(self):
  W.UNKNOWN.clear();C.UNRELEASED.clear();R.UNRELEASED.clear()
  for key in list(sys.modules):
   if key.startswith('seed_runner_probe_'):del sys.modules[key]
 def setup(self):
  h=fixture.Harness();h.stdout=OUTPUT;resource=Resource();h.signal.SIGALRM=14;h.signal.ITIMER_REAL=0
  h.signal.signal=lambda *a:None;h.signal.setitimer=lambda *a:None
  original=h.fstat
  def fstat(fd):
   value=original(fd)
   if h.fds[fd]['role']=='executable':value.st_nlink=0
   return value
  h.os.fstat=fstat
  base=h.subprocess.Popen
  class Popen(base):
   def __init__(self,*args,**kwargs):
    assert resource.getrlimit(resource.RLIMIT_FSIZE)[0]==0
    super().__init__(*args,**kwargs)
  h.subprocess.Popen=Popen
  station=W.NativeStation(os_module=h.os,sys_module=h.sys,subprocess_module=h.subprocess,select_module=h.select,signal_module=h.signal,io_module=h.io,fcntl_module=h.fcntl,resource_module=resource,clock=h.clock,wall=lambda:1)
  return h,resource,station
 def run_probe(self,h,station,raw=None,change=None):
  raw=tool_catalog(h) if raw is None else raw;value=scope(raw)
  if change:value.update(change)
  return W.run(W.canonical(value),raw,sources,station=station)
 def test_disabled_unset_scope_denies_before_proc_tool_or_process(self):
  h,r,st=self.setup();raw=tool_catalog(h);v=scope(raw,True)
  self.assertEqual(W.scope(W.canonical(v),1,allow_disabled=True)['operationId'],'0'*32)
  result=W.run(W.canonical(v),raw,sources,station=st);self.assertEqual(result['phase'],'source-catalog-admission');self.assertFalse(h.log);self.assertFalse(h.starts)
 def test_independent_digest_missing_extra_and_boolean_catalog_denial(self):
  for mode in ('digest','missing','extra','boolean','uid','mode','link'):
   h,r,st=self.setup();v=json.loads(tool_catalog(h));change=None
   if mode=='digest':change={'toolCatalogSha256':'0'*64}
   elif mode=='missing':del v[W.TOOLS[-1]]
   elif mode=='extra':v['/bin/sh']=v[W.TOOLS[0]]
   elif mode=='boolean':v[W.TOOLS[0]]['bytes']=True
   elif mode=='uid':v[W.TOOLS[0]]['identity']['st_uid']=1
   elif mode=='mode':v[W.TOOLS[0]]['identity']['st_mode']=stat.S_IFREG|0o777
   else:v[W.TOOLS[0]]['identity']['st_nlink']=2
   result=self.run_probe(h,st,W.canonical(v),change);self.assertEqual(result['phase'],'source-catalog-admission');self.assertFalse(h.log);self.assertFalse(h.starts)
 def test_noncanonical_duplicate_keys_and_nonfinite_catalog_denied(self):
  h,r,st=self.setup();raw=tool_catalog(h)
  for bad in (raw[:-1],raw.replace(b'"bytes":128',b'"bytes":128,"bytes":128',1),raw.replace(b'"bytes":128',b'"bytes":NaN',1)):
   with self.assertRaises(ValueError):W.catalog(bad,W.sha(bad))
  self.assertFalse(h.log)
 def test_changed_sources_or_scope_command_denies_before_callbacks(self):
  h,r,st=self.setup();raw=tool_catalog(h);v=scope(raw)
  changed=dict(sources);changed[next(iter(changed))]=b'untrusted'
  result=W.run(W.canonical(v),raw,changed,station=st);self.assertEqual(result['phase'],'source-catalog-admission');self.assertFalse(h.log)
  h,r,st=self.setup();result=self.run_probe(h,st,change={'commandSha256':'0'*64});self.assertEqual(result['phase'],'source-catalog-admission');self.assertFalse(h.log)
 def test_selected_tool_cap_is_independent_of_unused_catalog_rows(self):
  h,r,st=self.setup();v=json.loads(tool_catalog(h));v[W.TOOLS[0]]['bytes']=16777217;v[W.TOOLS[0]]['identity']['st_size']=16777217
  result=self.run_probe(h,st,W.canonical(v));self.assertEqual(result['phase'],'source-catalog-admission');self.assertFalse(h.starts)
 def test_original_runner_fixed_query_memfd_restore_and_known_release(self):
  h,r,st=self.setup();result=self.run_probe(h,st)
  self.assertEqual(result['status'],'NATIVE_READONLY_SEED_RUNNER_OBSERVED_ONLY');self.assertEqual(result['command'],list(W.VECTOR));self.assertEqual(len(h.starts),1);self.assertEqual(result['commandCalls'],1);self.assertFalse(h.fds);self.assertFalse(st.memfds)
  self.assertEqual(r.getrlimit(r.RLIMIT_FSIZE),(0,len(h.tool)));self.assertIn((r.RLIMIT_FSIZE,(len(h.tool),len(h.tool))),r.events)
  argv,kw=h.starts[0];self.assertEqual(kw['env'],R.ENV);self.assertIs(kw['close_fds'],True);self.assertEqual(len(kw['pass_fds']),1)
  self.assertEqual(result['stdoutSha256'],W.sha(OUTPUT));self.assertEqual(result['fields']['LoadState'],'not-found')
  for k in ('dynamicLoaderQualified','toolOriginSelfAuthenticated','serviceAbsenceQualified','parentAuthorityQualified','storageAuthorityQualified','nativeCapacityQualified','installerActivated','automaticRetry'):self.assertIs(result[k],False)
 def test_restoration_failure_preserves_exact_refs_and_never_launches(self):
  h,r,st=self.setup();r.bad_restore=True;result=self.run_probe(h,st)
  self.assertEqual(result['status'],'NATIVE_READONLY_SEED_RUNNER_UNAVAILABLE');self.assertFalse(result['allOwnedResourcesKnownReleased']);self.assertFalse(h.starts);self.assertTrue(any(x[0] is st and x[1]=='memfd-fsize-restoration' for x in W.UNKNOWN))
 def test_raw_memfd_close_failure_once_and_no_second_probe(self):
  h,r,st=self.setup();h.fail_close='executable';result=self.run_probe(h,st)
  self.assertEqual(result['status'],'NATIVE_READONLY_SEED_RUNNER_UNAVAILABLE');self.assertFalse(result['allOwnedResourcesKnownReleased']);self.assertTrue(st.attempted)
  failed=next(iter(st.attempted));self.assertEqual(len([x for x in h.log if x==('close',failed)]),1)
  again=self.run_probe(h,st);self.assertEqual(again['status'],'NATIVE_READONLY_SEED_RUNNER_UNAVAILABLE');self.assertEqual(len(h.starts),1)
 def test_unreturned_memfd_postcheck_failure_known_raw_close(self):
  h,r,st=self.setup();raw_fstat=st.saved['fstat']
  def fail(fd):
   if h.fds[fd]['role']=='executable':raise OSError('post acquisition metadata')
   return raw_fstat(fd)
  st.saved['fstat']=fail
  result=self.run_probe(h,st);self.assertEqual(result['status'],'NATIVE_READONLY_SEED_RUNNER_UNAVAILABLE');self.assertFalse(h.starts);self.assertFalse(h.fds);self.assertFalse(st.memfds)
 def test_closed_projection_refuses_extra_duplicate_pid_and_stderr(self):
  for bad in (OUTPUT+b'Extra=x\n',OUTPUT+b'MainPID=0\n',OUTPUT.replace(b'MainPID=0',b'MainPID=True')):
   with self.assertRaises(ValueError):W.projected(bad)
  h,r,st=self.setup();h.stderr=b'warning';result=self.run_probe(h,st);self.assertEqual(result['status'],'NATIVE_READONLY_SEED_RUNNER_UNAVAILABLE');self.assertFalse(h.fds)
 def test_packet_catalog_bound_before_any_compile_roundtrip_and_caps(self):
  h,r,st=self.setup();cat=tool_catalog(h);raw=W.canonical(scope(cat,True));worker=(ROOT/'deploy/validation/company-seed-runner-native-v1.py').read_bytes()
  built=C.build(raw,worker,cat,sources);result=C.unpack(built['packet'],packed_pin=(C.sha(built['packet']),len(built['packet'])),scope_pin=(C.sha(raw),len(raw)),worker_pin=C.WORKER_PIN)
  self.assertEqual(result,(raw,worker,cat,sources));self.assertLess(len(built['packet']),131072);self.assertIn(b'(0,16777216)',built['command']);self.assertIn(b'ITIMER_REAL,70',built['command']);self.assertIn(b'-I -B -c',built['command'])
  with self.assertRaises(ValueError):C.build(raw,worker,cat.replace(b'"bytes":128',b'"bytes":129',1),sources)
 def test_concatenated_packet_wrong_pin_and_unset_dispatch_refuse(self):
  h,r,st=self.setup();cat=tool_catalog(h);raw=W.canonical(scope(cat,True));worker=(ROOT/'deploy/validation/company-seed-runner-native-v1.py').read_bytes();packed=C.packet(raw,worker,cat,sources)
  for data,pin in ((packed,('0'*64,len(packed))),(packed+gzip.compress(b'tail'),None)):
   with self.assertRaises(ValueError):C.unpack(data,packed_pin=pin or (C.sha(data),len(data)),scope_pin=(C.sha(raw),len(raw)),worker_pin=C.WORKER_PIN)
  with mock.patch.object(C.subprocess,'Popen',side_effect=AssertionError('native')):
   with self.assertRaises(ValueError):C.dispatch_once(C.ROOT/'.local'/'unused',expected_command=('0'*64,1),expected_packet=('0'*64,1),expected_scope=('0'*64,1),explicit_action=None)

if __name__=='__main__':unittest.main(verbosity=2)
