"""Real original Bash/HeldParent and effect parsers; modeled host/source transport.

Private /etc and /opt mount namespaces. Never creates LUKS, packages, Docker or
services. This is component evidence, not signed installation qualification.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
ENV=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL='C',LANG='C',HOME='/',TZ='UTC')
def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


def foundation_worker(mode,trace):
    return ('ROOT='+repr(str(ROOT))+'\nMODE='+repr(mode)+'\nTRACE='+repr(str(trace))+'\n'+r'''
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
def load(name,relative):
 s=importlib.util.spec_from_file_location(name,Path(ROOT)/relative);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
T=load('native_handoff_contract','tests/test_company_foundation_handoff.py');W=T.W;P=T.P
W.COMPANY_FINGERPRINT='a'*64
p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
for name in('describe','foundation-only','verify','handoff-action','inspect-completed'):g.add_argument('--'+name,action='store_true')
for name in('request','worker-sha','predecessor','full-request-sha','guided-package-sha'):p.add_argument('--'+name)
p.add_argument('--parent',nargs=7);a=p.parse_args()
native=W.NativeState();raw=native.read(a.request,4096);request=W.validate(json.loads(raw),W.COMPANY_FINGERPRINT);assert W.canonical(request)==raw
f=T.Fixture();assert request==f.request
assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==a.worker_sha
def trace(value):
 with Path(TRACE).open('a',encoding='utf8')as stream:stream.write(json.dumps(value,sort_keys=True)+'\n')
if a.describe:print(request['operationId']);raise SystemExit(0)
if a.foundation_only or a.verify:
 arguments=P.ParentInput.from_argv(a.parent)
 assert arguments.request==W.sha(raw)and arguments.stage=='foundation'and arguments.action==W.sha(('foundation-v1:'+W.sha(raw)+':'+a.worker_sha).encode())
 evidence=Path('/opt/autosoft-company/evidence')/request['operationId']
 with P.hold_parent(arguments)as parent:
  if a.foundation_only:
   native.mkdir(evidence);native.write(evidence/'intent.json',raw);native.write(evidence/'result.json',W.canonical(f.result));trace(dict(effect='foundation',session=arguments.session))
  else:
   assert native.read(evidence/'intent.json')==raw and native.read(evidence/'result.json')==W.canonical(f.result)
   native.write(evidence/'verified',f"foundation-verified-v1\noperation={request['operationId']}\noutcome={W.sha(W.canonical(f.result))}\n".encode())
  parent.check()
 print(W.sha(W.canonical(f.result)));raise SystemExit(0)
class Composite:
 def journal_gid(self):return f.state.journal_gid()
 def __getattr__(self,name):
  def call(path,*args,**kwargs):
   selected=native if str(path).startswith(('/etc/autosoft-install-admission','/opt/autosoft-company'))else f.state
   return getattr(selected,name)(path,*args,**kwargs)
  return call
state=Composite();f.worker.state=state;f.worker.modules['installer_parent.py']=P
if a.handoff_action:
 prior=W.completed_foundation(state,P,request,a.worker_sha,a.predecessor,a.full_request_sha)
 print(W.handoff_action(request,a.worker_sha,a.predecessor,a.full_request_sha,a.guided_package_sha,prior[0]));raise SystemExit(0)
assert a.inspect_completed
if MODE=='bad-runtime':f.f.responses[('/usr/bin/docker','info','--format','{{.DockerRootDir}}')]=b'/var/lib/docker\n'
if MODE=='bad-source':f.files.rows[str(f.f.root/'scripts/install.sh')]['raw']=b'changed source'
W.host_bindings=lambda *_:(f.proof,{}) # Only catalog transport is modeled.
arguments=P.ParentInput.from_argv(a.parent)
source_reads=set();failure=[]
f.files.on_read=lambda files,fd:source_reads.add(files.fds[fd][0])
try:
 result=f.worker.inspect_completed(request,arguments,a.worker_sha,a.predecessor,a.full_request_sha,a.guided_package_sha)
except BaseException as error:
 # Fixed synthetic fixture diagnostics only: no exception text, arguments,
 # credentials or locals. Preserve the original exception and parent behavior.
 current=error;seen=set()
 while current is not None and id(current)not in seen and len(failure)<4:
  seen.add(id(current));frames=[];tb=current.__traceback__
  while tb is not None:
   frames.append(dict(file=Path(tb.tb_frame.f_code.co_filename).name[:80],function=tb.tb_frame.f_code.co_name[:64],line=tb.tb_lineno));tb=tb.tb_next
  failure.append(dict(type=type(current).__name__[:64],frames=frames[-6:]));current=current.__context__
 raise
finally:trace(dict(effect='handoff-observation',session=arguments.session,stage=arguments.stage,observations=len(f.f.calls),
 outputFdsClosed=not f.files.fds,sourceTargetRead=str(f.f.root/'scripts/install.sh')in source_reads,
 lastCommand=[part[:256]for part in f.f.calls[-1][:5]]if f.f.calls else[],failure=failure))
print(W.sha(W.canonical(result)))
''').encode()


def fixture(mode,case):
    case=Path(case);assert os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])and case.resolve()==case
    for name in('etc','opt'):
        (case/name).mkdir(mode=0o700)
        subprocess.run(['/usr/bin/mount','--bind',str(case/name),'/'+name],check=True,timeout=10)
    T=load('native_guided_original','tests/test_company_guided_entry_native.py')
    F=load('native_handoff_original_parsers','tests/test_company_foundation_handoff.py')
    B=load('native_guided_producer','deploy/installer/build-guided-private-package.py')
    N=load('native_guided_retention_producer','deploy/installer/build-native-retention-package.py')
    base=Path('/opt/autosoft-company');base.mkdir(mode=0o700)
    for name in('bootstrap','requests','evidence'):(base/name).mkdir(mode=0o700)
    package=base/'bootstrap';request=F.Fixture().request;operation=request['operationId']
    foundation=base/'requests'/(operation+'-foundation.json');full=base/'requests'/(operation+'.json')
    for path,value in((foundation,request),(full,dict(request,mode='full-installation',releaseSha256='c'*64))):
        path.write_bytes(F.W.canonical(value));path.chmod(0o600)
    trace=case/'trace.jsonl';worker=foundation_worker(mode,trace);private=T.private_worker('success')
    lock=(ROOT/'scripts/install-lock.sh').read_bytes()
    entry=(ROOT/'deploy/installer/company-install.sh').read_bytes().replace(b'# @EMBED_INSTALL_LOCK@',lock)
    entry=entry.replace(b'@WORKER_SHA256@',hashlib.sha256(worker).hexdigest().encode()).replace(b'@HOST_CATALOGS_AVAILABLE@',b'true').replace(b'@HOST_CATALOG_FAMILY@',b'vendor-v1')
    # Known test interruption only after the original foundation command returns.
    entry+=b'\nexit 23\n'
    records={'company-install.sh':entry,'company_install.py':worker,'company-native-retention.py':private,
        'company-prepare.sh':N.assemble_entry(ROOT,private,reader=lambda p,n:p.read_bytes(),preparation=True),
        'company-private-quota.sh':N.assemble_entry(ROOT,private,reader=lambda p,n:p.read_bytes(),quota=True),
        'installation-status.py':(ROOT/'scripts/installation-status.py').read_bytes()}
    records['company-guided-private.sh']=B.entry(ROOT,records,reader=lambda p,n:p.read_bytes())
    for name,raw in records.items():(package/name).write_bytes(raw);(package/name).chmod(0o400)
    command=['/bin/bash','--noprofile','--norc',str(package/'company-guided-private.sh')]
    def invoke(flag,session=None):
        return subprocess.run(command+[flag,str(foundation),str(full)]+([session]if session else[]),env=ENV,stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
    def snapshot(root):return {str(p):[hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns]for p in root.rglob('*')if p.is_file()}
    first=invoke('--install-private');assert first.returncode==23,first.stderr.decode()
    sessions=Path('/etc/autosoft-install-admission/sessions');old=list(sessions.iterdir());assert len(old)==1
    predecessor=old[0].name;evidence=base/'evidence'/operation
    assert (old[0]/'complete').is_file()and(evidence/'verified').is_file()
    if mode=='missing-complete':(old[0]/'complete').rename(old[0]/'preserved-complete')
    elif mode=='prepared':
        (evidence/'company-configuration').mkdir(mode=0o700);(evidence/'company-configuration/intent.json').write_text('preserved');(evidence/'company-configuration/intent.json').chmod(0o600)
    elif mode=='changed-worker':(package/'company_install.py').write_bytes(worker+b'\n')
    elif mode=='changed-guided-intent':
        path=base/('guided-'+operation+'.intent');path.write_bytes(path.read_bytes().replace(b'package=',b'changed='))
    elif mode=='changed-full':full.write_bytes(full.read_bytes().replace(b'"capacityGiB":32',b'"capacityGiB":64'))
    elif mode=='wrong-session':predecessor='s-123456789012'
    old_before=snapshot(old[0]);foundation_before={str(p):p.read_bytes().hex()for p in evidence.iterdir()if p.is_file()}
    second=invoke('--continue-after-foundation',predecessor)
    before=snapshot(case);retry=invoke('--continue-after-foundation',predecessor);after=snapshot(case)
    observations=[json.loads(line)for line in trace.read_text().splitlines()]
    report=dict(mode=mode,exit=second.returncode,stdout=second.stdout.decode(),stderr=second.stderr.decode(),
        retryExit=retry.returncode,retryUnchanged=before==after,oldSessionUnchanged=snapshot(old[0])==old_before,
        foundationUnchanged=all(Path(name).read_bytes().hex()==raw for name,raw in foundation_before.items()),
        observations=observations,sessions=len(list(sessions.iterdir())),completed=len(list(sessions.rglob('complete'))),
        preparationExists=(evidence/'company-configuration/executed.json').exists())
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n')


@unittest.skipUnless(sys.platform=='linux'and getattr(os,'geteuid',lambda:-1)()==0,'Linux root private namespaces required')
class NativeHandoff(unittest.TestCase):
    def case(self,mode):
        root=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);st=root.lstat()
        self.assertTrue(root.resolve()==root and str(root).startswith('/srv/')and st.st_uid==st.st_gid==0 and st.st_mode&0o777==0o700)
        case=root/uuid.uuid4().hex;case.mkdir(mode=0o700)
        done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],capture_output=True,timeout=600)
        self.assertEqual(done.returncode,0,done.stderr.decode());r=json.loads((case/'report.json').read_bytes())
        self.assertTrue(r['oldSessionUnchanged']and r['foundationUnchanged']and r['retryUnchanged'])
        self.assertNotEqual(r['retryExit'],0);self.assertEqual(sum(x['effect']=='foundation'for x in r['observations']),1)
        return r
    def test_completed_foundation_uses_new_parent_real_verifiers_then_original_children(self):
        r=self.case('success');self.assertEqual(r['exit'],0,r['stderr']);self.assertEqual((r['sessions'],r['completed']),(4,4))
        checks=[x for x in r['observations']if x['effect']=='handoff-observation'];self.assertEqual(len(checks),2)
        self.assertTrue(all(x['stage']=='foundation-handoff'and x['observations']>10 and x['outputFdsClosed']for x in checks))
        self.assertNotEqual(checks[0]['session'],r['observations'][0]['session']);self.assertTrue(r['preparationExists'])
    def test_runtime_drift_stops_at_read_only_handoff(self):
        r=self.case('bad-runtime');self.assertNotEqual(r['exit'],0);self.assertEqual(r['completed'],1);self.assertFalse(r['preparationExists'])
        checks=[x for x in r['observations']if x['effect']=='handoff-observation'];self.assertEqual(len(checks),1)
        self.assertEqual(checks[0]['observations'],5);self.assertTrue(checks[0]['outputFdsClosed'])
        self.assertEqual(checks[0]['lastCommand'],['/usr/bin/docker','info','--format','{{.DockerRootDir}}'])
        self.assertTrue(any(e['type']=='FoundationUnavailable'and any(f['function']=='measure'for f in e['frames'])for e in checks[0]['failure']))
    def test_source_drift_stops_at_read_only_handoff(self):
        r=self.case('bad-source');self.assertNotEqual(r['exit'],0);self.assertEqual(r['completed'],1);self.assertFalse(r['preparationExists'])
        checks=[x for x in r['observations']if x['effect']=='handoff-observation'];self.assertEqual(len(checks),1)
        self.assertEqual(checks[0]['observations'],0);self.assertTrue(checks[0]['outputFdsClosed']and checks[0]['sourceTargetRead'])
        self.assertTrue(any(e['type']=='FoundationUnavailable'and any(f['function']=='read'for f in e['frames'])for e in checks[0]['failure']))
    def test_changed_worker_is_refused_without_new_session(self):self.assertEqual(self.case('changed-worker')['sessions'],1)
    def test_changed_full_request_is_refused_without_new_session(self):self.assertEqual(self.case('changed-full')['sessions'],1)
    def test_changed_guided_intent_is_refused_without_new_session(self):self.assertEqual(self.case('changed-guided-intent')['sessions'],1)
    def test_missing_completion_is_preserved_without_new_session(self):self.assertEqual(self.case('missing-complete')['sessions'],1)
    def test_partial_preparation_is_preserved_without_new_session(self):self.assertEqual(self.case('prepared')['sessions'],1)
    def test_wrong_completed_session_is_refused_without_new_session(self):self.assertEqual(self.case('wrong-session')['sessions'],1)


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
