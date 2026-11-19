"""Real Bash/HeldParent/completed-journal composition, modeled source/effects.

This verifies explicit handoff and no replay, not native Git/configuration or
encrypted runtime qualification. Original effect readers have separate tests.
Only fixture /etc and /opt are mounted inside a private mount namespace.
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
    spec=importlib.util.spec_from_file_location(name,ROOT/relative);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m


def worker(mode,trace):
    quota=load('prep_handoff_quota_fixture','tests/test_company_quota_entry_native.py').worker('identity-verifier-failure'if mode=='mixed-history'else'success')
    return ('ROOT='+repr(str(ROOT))+'\nMODE='+repr(mode)+'\nTRACE='+repr(str(trace))+'\nQUOTA='+repr(quota)+'\n'+r'''
import argparse,hashlib,importlib.util,json,os,sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
def load(name,relative):
 s=importlib.util.spec_from_file_location(name,Path(ROOT)/relative);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
H=load('prep_native_handoff','deploy/installer/company_preparation_handoff.py')
F=load('prep_native_foundation','deploy/installer/company_install.py')
P=load('prep_native_parent','scripts/installer_parent.py')
Q=load('prep_native_configuration','deploy/installer/company_configuration.py')
S=load('prep_native_station','deploy/installer/company_native_station.py')
W=load('prep_native_writer','deploy/installer/company_configuration_worker.py')
Records=load('prep_native_records','deploy/installer/company_retention_records.py')
commands=(('configuration-action','configure-foundation','verify-configuration'),('repository-action','seed-repository','verify-repository'),('runtime-pair-action','initialize-runtime-pair','verify-runtime-pair'))
mapping={name:(stage,index)for stage,names in zip(H.STAGES,commands)for index,name in enumerate(names)}
if sys.argv[1]not in mapping and sys.argv[1]not in H.COMMANDS:exec(QUOTA);raise SystemExit(0)
p=argparse.ArgumentParser();p.add_argument('command');p.add_argument('--request');p.add_argument('--parent',nargs=7)
p.add_argument('--predecessor');p.add_argument('--guided-package-sha');a=p.parse_args();S.baseline()
raw=S.read_protected(a.request,4096);request=json.loads(raw);request_sha=Q.sha(raw)
worker_sha=Q.sha(S.read_protected(__file__,2*1024**2))
def trace(value):
 with Path(TRACE).open('a')as stream:stream.write(json.dumps(value,sort_keys=True)+'\n')
def result(stage):
 return dict(scope='MODELED_PREPARATION_EFFECT_ONLY',stage=stage,requestSha256=request_sha,actionSha256=actions[stage],
  workerSha256=worker_sha,session=a.parent[3]if a.command in mapping else a.predecessor,revision='original')
actions={stage:Q.sha(('modeled:'+stage+':'+request_sha+':'+worker_sha).encode())for stage in H.STAGES}
if a.command in mapping:
 stage,index=mapping[a.command];action=actions[stage]
 if index==0:print(action);raise SystemExit(0)
 arguments=P.ParentInput.from_argv(a.parent);directory='/opt/autosoft-company/evidence/'+request['operationId']+'/'+stage
 intended=Q.canonical(dict(requestSha256=request_sha,actionSha256=action,session=arguments.session,workerSha256=worker_sha))
 body=Q.canonical(result(stage))
 with P.hold_parent(arguments)as parent:
  assert arguments.request==request_sha and arguments.stage==stage and arguments.action==action
  if index==1:
   os.mkdir(directory,0o700);W.write(Records,directory,'intent.json',intended);W.write(Records,directory,'executed.json',body)
   trace(dict(effect=stage,session=arguments.session))
  else:
   assert S.read_protected(directory+'/intent.json',4096)==intended and S.read_protected(directory+'/executed.json',32768)==body
  parent.check()
 if index==2:
  W.write(Records,directory,'verified.json',body)
  marker=H.MAGICS[H.STAGES.index(stage)]+'\nrequest='+request_sha+'\nsession='+arguments.session+'\nstage='+stage+'\naction='+action+'\noutcome='+Q.sha(body)+'\n'
  W.write(Records,directory,'confirmation',marker.encode(),mode=0o600)
 raise SystemExit(0)
@contextmanager
def authenticated(*args,**kwargs):
 assert kwargs['files'] is source_files and kwargs['crypto'] is source_crypto
 trace(dict(observation='source-enter'))
 try:yield SimpleNamespace(metadata={'releaseSha256':request['releaseSha256']})
 finally:
  trace(dict(observation='source-close'))
  if MODE=='source-close-failure':raise ValueError('fixed modeled source close failure')
@contextmanager
def assembly(held):yield SimpleNamespace(modules={Q.BOOTSTRAP:SimpleNamespace(SeedCommands=lambda *_:SimpleNamespace(text=lambda *_:None))})
@contextmanager
def cli(*args,**kwargs):
 yield SimpleNamespace(original_modules=dict(verifier=SimpleNamespace(authenticated_platform_source=authenticated,require_platform_source=lambda held:held),parent=P,entry=SimpleNamespace(fresh_installation_modules=assembly)))
source_files=object();source_crypto=object() # Explicit modeled source transports, never native grants.
station=SimpleNamespace(stage_inputs=lambda *_a,**_k:dict(parent_system=P.NativeSystem(),runner_module=None,runner=None,files=source_files,crypto=source_crypto),require_released=lambda *_:None)
def observed(stage):
 trace(dict(observation=stage));value=result(stage)
 if MODE=='bad-'+stage:value['revision']='changed'
 return value
H.configuration=lambda *_a,**_k:observed(H.STAGES[0])
H.repository=lambda *_a,**_k:observed(H.STAGES[1])
H.pair=lambda *_a,**_k:observed(H.STAGES[2])
modules=dict(foundation_worker=F,station=station,cli=SimpleNamespace(authenticated_cli=cli),configuration=Q,
 configuration_worker=SimpleNamespace(foundation=lambda *_a,**_k:'f'*64),crypto=None)
try:
 H.run(a.command,modules,b'fixed modeled delivery',dict(fingerprint='a'*64),request,raw,worker_sha,a.parent,
  a.predecessor,a.guided_package_sha,host_catalogs={'fixture':'no host effects'})
except BaseException as error:
 if a.command==H.COMMANDS[1]:
  rows=[];seen=set();current=error
  while current is not None and id(current)not in seen and len(rows)<4:
   seen.add(id(current));frames=[];tb=current.__traceback__
   while tb is not None:
    frames.append(dict(file=Path(tb.tb_frame.f_code.co_filename).name[:80],function=tb.tb_frame.f_code.co_name[:64],line=tb.tb_lineno));tb=tb.tb_next
   rows.append(dict(type=type(current).__name__[:64],frames=frames[-6:]));current=current.__context__
  trace(dict(failureWitness=rows,session=a.parent[3],stage=a.parent[5]))
 raise
if a.command==H.COMMANDS[1]:trace(dict(observation='handoff-closed',session=a.parent[3],stage=a.parent[5]))
''').encode()


def fixture(mode,case):
    case=Path(case);assert os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])and case.resolve()==case
    for name in ('etc','opt'):
        (case/name).mkdir(mode=0o700)
        subprocess.run(['/usr/bin/mount','--bind',str(case/name),'/'+name],check=True,timeout=10)
    T=load('prep_handoff_guided_fixture','tests/test_company_guided_entry_native.py')
    B=load('prep_handoff_guided_builder','deploy/installer/build-guided-private-package.py')
    N=load('prep_handoff_native_builder','deploy/installer/build-native-retention-package.py')
    base=Path('/opt/autosoft-company');base.mkdir(mode=0o700)
    for name in ('bootstrap','requests','evidence'):(base/name).mkdir(mode=0o700)
    package=base/'bootstrap';operation='d'*32;foundation=base/'requests'/(operation+'-foundation.json');full=base/'requests'/(operation+'.json')
    for path,kind in ((foundation,'foundation-only'),(full,'full-installation')):
        path.write_bytes((json.dumps(T.request(operation,kind),sort_keys=True,separators=(',',':'))+'\n').encode());path.chmod(0o600)
    trace=case/'trace.jsonl';foundation_raw=T.foundation_worker('success');native=worker(mode,trace)
    entry=(ROOT/'deploy/installer/company-install.sh').read_bytes().replace(b'# @EMBED_INSTALL_LOCK@',(ROOT/'scripts/install-lock.sh').read_bytes())
    entry=entry.replace(b'@WORKER_SHA256@',hashlib.sha256(foundation_raw).hexdigest().encode()).replace(b'@HOST_CATALOGS_AVAILABLE@',b'true').replace(b'@HOST_CATALOG_FAMILY@',b'vendor-v1')
    # Test interruption happens after the real preparation parent completes.
    records={'company-install.sh':entry,'company_install.py':foundation_raw,'company-native-retention.py':native,
        'company-prepare.sh':N.assemble_entry(ROOT,native,reader=lambda p,n:p.read_bytes(),preparation=True)+b'\nexit 23\n',
        'company-private-quota.sh':N.assemble_entry(ROOT,native,reader=lambda p,n:p.read_bytes(),quota=True),
        'installation-status.py':(ROOT/'scripts/installation-status.py').read_bytes()}
    records['company-guided-private.sh']=B.entry(ROOT,records,reader=lambda p,n:p.read_bytes())
    for name,raw in records.items():(package/name).write_bytes(raw);(package/name).chmod(0o400)
    command=['/bin/bash','--noprofile','--norc',str(package/'company-guided-private.sh')]
    def invoke(flag,session=None):
        return subprocess.run(command+[flag,str(foundation),str(full)]+([session]if session else[]),env=ENV,stdin=subprocess.DEVNULL,capture_output=True,timeout=210)
    def snapshot(root):
        return {str(p):[hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns]for p in root.rglob('*')if p.is_file()}
    first=invoke('--install-private');assert first.returncode==23,first.stderr.decode()
    sessions=Path('/etc/autosoft-install-admission/sessions');old=list(sessions.iterdir());assert len(old)==2
    previous=next(p for p in old if(p/'fresh-runtime-pair.confirmed').exists());predecessor=previous.name
    evidence=base/'evidence'/operation
    assert (previous/'complete').is_file()
    if mode=='missing-completion':(previous/'complete').rename(previous/'preserved-completion')
    elif mode=='private-partial':
        (evidence/'company-platform-store').mkdir(mode=0o700);(evidence/'company-platform-store/planned.json').write_bytes(b'preserve');(evidence/'company-platform-store/planned.json').chmod(0o400)
    elif mode=='changed-worker':(package/'company-native-retention.py').write_bytes(native+b'\n')
    elif mode=='changed-guided-intent':
        p=base/('guided-'+operation+'.intent');p.write_bytes(p.read_bytes().replace(b'package=',b'changed='))
    elif mode=='wrong-session':predecessor=old[0].name if old[0]!=previous else old[1].name
    old_before={str(p):snapshot(p)for p in old};evidence_before=snapshot(evidence)
    second=invoke('--continue-after-preparation',predecessor)
    before=snapshot(case);retry=invoke('--continue-after-preparation',predecessor);after=snapshot(case)
    status_before=snapshot(case);status=invoke('--private-status');status_unchanged=snapshot(case)==status_before
    observations=[json.loads(line)for line in trace.read_text().splitlines()]
    preserved=all(Path(name).is_file()and [hashlib.sha256(Path(name).read_bytes()).hexdigest(),Path(name).stat().st_ino,Path(name).stat().st_mtime_ns,Path(name).stat().st_ctime_ns]==value for name,value in evidence_before.items())
    report=dict(mode=mode,exit=second.returncode,stdout=second.stdout.decode(),stderr=second.stderr.decode(),retryExit=retry.returncode,
        retryUnchanged=before==after,oldSessionUnchanged=all(snapshot(p)==old_before[str(p)]for p in old),oldEvidenceUnchanged=preserved,
        sessions=len(list(sessions.iterdir())),complete=len(list(sessions.rglob('complete'))),observations=observations,
        statusExit=status.returncode,statusStdout=status.stdout.decode(),statusUnchanged=status_unchanged,
        privateStarted=(evidence/'company-platform-store/executed.json').exists(),predecessor=previous.name)
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n')


@unittest.skipUnless(sys.platform=='linux'and getattr(os,'geteuid',lambda:-1)()==0,'Linux root private namespace required')
class NativePreparationHandoff(unittest.TestCase):
    def case(self,mode):
        root=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);info=root.lstat()
        self.assertTrue(root.resolve()==root and str(root).startswith('/srv/')and info.st_uid==info.st_gid==0 and info.st_mode&0o777==0o700)
        case=root/uuid.uuid4().hex;case.mkdir(mode=0o700)
        done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],capture_output=True,timeout=660)
        self.assertEqual(done.returncode,0,done.stderr.decode());r=json.loads((case/'report.json').read_bytes())
        self.assertTrue(r['retryUnchanged']and r['oldSessionUnchanged']and r['oldEvidenceUnchanged']and r['statusUnchanged']);self.assertNotEqual(r['retryExit'],0)
        self.assertEqual([row['effect']for row in r['observations']if 'effect'in row],['company-configuration','repository-seed','fresh-runtime-pair'])
        return r
    def test_completed_preparation_uses_new_parent_without_replaying_any_stage(self):
        r=self.case('success');self.assertEqual(r['exit'],0,r['stderr']);self.assertEqual((r['sessions'],r['complete']),(4,4));self.assertTrue(r['privateStarted'])
        closed=[row for row in r['observations']if row.get('observation')=='handoff-closed'];self.assertEqual(len(closed),2)
        self.assertTrue(all(row['stage']=='preparation-handoff'and row['session']!=r['predecessor']for row in closed))
    def test_each_current_effect_mismatch_stops_before_private_child(self):
        for stage in ('company-configuration','repository-seed','fresh-runtime-pair'):
            with self.subTest(stage=stage):
                r=self.case('bad-'+stage);self.assertNotEqual(r['exit'],0);self.assertFalse(r['privateStarted']);self.assertEqual((r['sessions'],r['complete']),(3,2))
                observed=[row['observation']for row in r['observations']if 'observation'in row]
                self.assertIn(stage,observed);self.assertNotIn('handoff-closed',observed);self.assertEqual(observed[-2:],[stage,'source-close'])
                witnesses=[row for row in r['observations']if 'failureWitness'in row];self.assertEqual(len(witnesses),1)
                self.assertTrue(any(error['type']=='ValueError'and any(frame['function']=='run'for frame in error['frames'])for error in witnesses[0]['failureWitness']))
                self.assertIn('Handoff session',r['stderr'])
    def test_source_close_failure_cannot_confirm_new_handoff(self):
        r=self.case('source-close-failure');self.assertNotEqual(r['exit'],0);self.assertEqual((r['sessions'],r['complete']),(3,2));self.assertFalse(r['privateStarted'])
        self.assertIn('fresh-runtime-pair',[row.get('observation')for row in r['observations']]);self.assertNotIn('handoff-closed',[row.get('observation')for row in r['observations']])
        witnesses=[row for row in r['observations']if 'failureWitness'in row];self.assertEqual(len(witnesses),1)
        self.assertTrue(any(error['type']=='ValueError'and any(frame['function']=='authenticated'for frame in error['frames'])for error in witnesses[0]['failureWitness']))
    def test_mixed_completed_history_only_guides_the_actual_unfinished_private_session(self):
        r=self.case('mixed-history');self.assertNotEqual(r['exit'],0);self.assertEqual((r['sessions'],r['complete']),(4,3))
        self.assertEqual(r['statusExit'],0);self.assertIn('company-private-quota.sh --recover-private-quota',r['statusStdout'])
        self.assertNotIn('--continue-after-foundation',r['statusStdout']);self.assertNotIn('--continue-after-preparation',r['statusStdout'])
        self.assertGreaterEqual(r['statusStdout'].count('Completed session'),2)
    def test_missing_completed_record_refuses_before_new_session(self):self.assertEqual(self.case('missing-completion')['sessions'],2)
    def test_partial_private_work_refuses_before_new_session(self):self.assertEqual(self.case('private-partial')['sessions'],2)
    def test_changed_worker_refuses_before_new_session(self):self.assertEqual(self.case('changed-worker')['sessions'],2)
    def test_changed_guided_binding_refuses_before_new_session(self):self.assertEqual(self.case('changed-guided-intent')['sessions'],2)
    def test_wrong_predecessor_refuses_before_new_session(self):self.assertEqual(self.case('wrong-session')['sessions'],2)


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
