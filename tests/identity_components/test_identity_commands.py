import importlib.util,json
from pathlib import Path
from types import SimpleNamespace
import unittest

BASE=Path(__file__).resolve().parent
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,(Path(__file__).resolve().parents[2]/'deploy/installer'/path.replace('original/','') if not path.startswith('test_') else BASE/path));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
R=load('identity_original_render','original/company_render_commands.py')
M=load('identity_commands','company_identity_commands.py');C=M.identity_commands(R)

class FakeIO:
 def __init__(self):self.root='/protected/identity';self.copy_hashes={'provision.mjs':'a'*64,'ca.crt':'b'*64};self.events=[]
 def check(self):pass
 def record(self,phase,event,values):self.events.append((phase,event,values))

class Simulated(C):
 def __init__(self,fail=None):
  super().__init__(FakeIO(),'a'*32,'platform@sha256:'+'c'*64,'d'*64,'e'*64,'sha256:'+'f'*64)
  self.image_id='sha256:'+'1'*64;self.calls=[];self.started=False;self.fail=fail
 def _check(self):R.require(not self.failed)
 def _docker(self,args,*,stdin=b'',timeout=30):
  self.calls.append((args,stdin,timeout))
  if args[:2]==['network','inspect']:
   ids={self.keycloak_id:{}}
   if self.container and self.started:ids[self.container]={}
   if self.fail=='foreign-network':ids['9'*64]={}
   return json.dumps([dict(Id=self.network_id,Name='autosoft_identity',Driver='bridge',Internal=self.fail!='public-network',Containers=ids)]).encode()
  if args[:2]==['container','inspect'] and args[2]==self.keycloak_id:
   return json.dumps([dict(Id=self.keycloak_id,Image=self.keycloak_image_id,
     State={'Running':True},HostConfig={'Privileged':False,'PortBindings':{}},
     Config={'Labels':{'com.docker.compose.service':'keycloak','com.docker.compose.project':'autosoft'}},
     NetworkSettings={'Networks':{'autosoft_identity':{'NetworkID':self.network_id,'Aliases':['keycloak']}}})]).encode()
  if args[:2]==['container','create']:
   if self.fail=='create-unknown':raise TimeoutError('synthetic unavailable outcome')
   self.started=False;return (('2' if self.phase=='provision' else '3')*64+'\n').encode()
  if args[:2]==['container','inspect']:
   row=dict(Id=self.container,Name='/'+self.name,Image=self.image_id,
    Config=dict(Image=self.image,User='10001:10001',Entrypoint=['node'],Cmd=['/opt/doxentriq/provision.mjs'],
     Labels={'com.doxentriq.identity':self.name},OpenStdin=True,Tty=False,Env=['NODE_EXTRA_CA_CERTS=/etc/doxentriq/ca.crt','NODE_OPTIONS=']),
    HostConfig=dict(NetworkMode=self.network_id,Privileged=False,ReadonlyRootfs=True,Memory=134217728,PidsLimit=64,NanoCpus=1000000000,
     CapDrop=['ALL'],CapAdd=[],SecurityOpt=['no-new-privileges'],PortBindings={},Tmpfs={},LogConfig={'Type':'none'},RestartPolicy={'Name':'no'},
     Binds=[self.io.root+'/provision.mjs:/opt/doxentriq/provision.mjs:ro',self.io.root+'/ca.crt:/etc/doxentriq/ca.crt:ro']),
    State=dict(Status='exited' if self.started else 'created',ExitCode=0,Pid=0,OOMKilled=False,Error=''),
    Mounts=[dict(Type='bind',Source=self.io.root+'/ca.crt',Destination='/etc/doxentriq/ca.crt',RW=False),
     dict(Type='bind',Source=self.io.root+'/provision.mjs',Destination='/opt/doxentriq/provision.mjs',RW=False)])
   if self.fail=='foreign-mount':row['Mounts'].append(dict(Type='bind',Source='/run/docker.sock',Destination='/socket',RW=True))
   if self.fail=='image-drift':row['Image']='sha256:'+'9'*64
   return json.dumps([row]).encode()
  if args[:2]==['container','start']:
   self.started=True
   if self.fail=='start-unknown':raise TimeoutError('synthetic uncertain external action')
   if self.fail=='bad-output':return b'untrusted unexpected diagnostics'
   if self.phase=='provision':return b'Scoped app realm provisioner configured.\n'
   payload=json.loads(stdin)
   return (json.dumps(dict(scope='INITIAL_IDENTITY_POLICY_READBACK',ownerSubject=payload['ownerSubject'],configuredPolicyVerified=True,browserMfaQualified=False,publicStartupAllowed=False))+'\n').encode()
  if args[:2]==['container','rm']:
   if self.fail=='remove-unknown':raise TimeoutError('synthetic unknown cleanup')
   return (self.container+'\n').encode()
  if args[:2]==['container','ls']:return b''
  raise AssertionError(args)

class LifecycleTests(unittest.TestCase):
 def test_only_equivalent_pinned_docker_hub_spellings_match(self):
  suffix='@sha256:'+'a'*64
  for name in ('caddy','library/caddy','docker.io/caddy','docker.io/library/caddy'):
   self.assertTrue(M.pinned_reference_present('docker.io/library/caddy'+suffix,[name+suffix]))
  self.assertTrue(M.pinned_reference_present('docker.io/company/platform'+suffix,['company/platform'+suffix]))
  for name in ('evil.example/library/caddy'+suffix,'ghcr.io/library/caddy'+suffix,'other/caddy'+suffix,'docker.io/library/other'+suffix,'caddy@sha256:'+'b'*64):
   self.assertFalse(M.pinned_reference_present('docker.io/library/caddy'+suffix,[name]))
  with self.assertRaises(ValueError):M.canonical_digest_reference('caddy:latest'+suffix)

 def test_provision_and_distinct_readonly_verification_with_no_public_start(self):
  c=Simulated();secret='synthetic-protected-input'
  first=c.run_phase('provision',json.dumps({'bootstrapPassword':secret}).encode())
  second=c.run_phase('verify',json.dumps({'action':'verify-initial','ownerSubject':'11111111-1111-4111-8111-111111111111','bootstrapPassword':secret}).encode())
  self.assertFalse(first['configuredPolicyVerified']);self.assertTrue(second['configuredPolicyVerified'])
  self.assertFalse(second['publicStartupAllowed']);self.assertIsNone(c.container);c.close()
  self.assertEqual(len(c.io.events),10)
  for args,stdin,timeout in c.calls:
   self.assertNotIn(secret,' '.join(args))
   if stdin:self.assertEqual(args[:4],['container','start','--attach','--interactive'])
   if args[:2]==['container','create']:
    self.assertIn('--pull=never',args);self.assertNotIn('--rm',args);self.assertNotIn('--publish',args)
    self.assertIn('--user=10001:10001',args);self.assertIn('--entrypoint=node',args)
  self.assertNotIn(secret,json.dumps(c.io.events))

 def test_missing_docker_healthcheck_does_not_invent_unreachable_prerequisite(self):
  c=Simulated();c._infrastructure();self.assertEqual(len(c.calls),2)

 def test_uncertain_create_or_start_never_retries_or_removes(self):
  for mode in ('create-unknown','start-unknown'):
   with self.subTest(mode=mode):
    c=Simulated(mode)
    with self.assertRaises(TimeoutError):c.run_phase('provision',b'{}')
    count=len(c.calls)
    with self.assertRaises(ValueError):c.run_phase('provision',b'{}')
    self.assertEqual(count,len(c.calls));self.assertTrue(c.failed)
    self.assertFalse(any(args[:2]==['container','rm'] for args,_,_ in c.calls))
    with self.assertRaises(ValueError):c.close()

 def test_unexpected_network_or_container_profile_never_starts(self):
  for mode in ('foreign-network','public-network','foreign-mount','image-drift'):
   with self.subTest(mode=mode):
    c=Simulated(mode)
    with self.assertRaises(ValueError):c.run_phase('provision',b'{}')
    self.assertFalse(any(args[:2]==['container','start'] for args,_,_ in c.calls))

 def test_invalid_helper_output_retains_container_and_start_intent(self):
  c=Simulated('bad-output')
  with self.assertRaises(ValueError):c.run_phase('provision',b'{}')
  self.assertIsNotNone(c.container);self.assertEqual(c.io.events[-1][1],'start-intent')
  self.assertFalse(any(args[:2]==['container','rm'] for args,_,_ in c.calls))

 def test_unconfirmed_removal_is_not_success(self):
  c=Simulated('remove-unknown')
  with self.assertRaises(TimeoutError):c.run_phase('provision',b'{}')
  self.assertIsNotNone(c.container);self.assertEqual(c.io.events[-1][1],'completed')

 def test_verification_cannot_run_without_provisioning(self):
  c=Simulated()
  with self.assertRaises(ValueError):c.run_phase('verify',b'{"action":"verify-initial"}')
  self.assertEqual(c.calls,[])

if __name__=='__main__':unittest.main(verbosity=2)
