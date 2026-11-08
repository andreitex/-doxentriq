"""Native Bash admission/recovery and original HeldParent, synthetic effects.

Requires a disposable root-owned /srv fixture and private mount namespaces.
Only the fixture's /etc and /opt are replaced. No Docker, package installation,
LUKS, real business configuration, provider call or application startup occurs.
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
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',ROOT if (ROOT/'scripts/installer_parent.py').exists() else ROOT.parents[2]))


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


def worker(mode):
    return ('ROOT='+repr(str(ROOT))+'\nBASE='+repr(str(BASE))+'\nMODE='+repr(mode)+'\n'+r'''
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
S=load('preparation_station',Path(BASE)/'deploy/installer/company_native_station.py')
P=load('preparation_parent',Path(BASE)/'scripts/installer_parent.py')
R=load('preparation_records',Path(BASE)/'deploy/installer/company_retention_records.py')
W=load('preparation_writer',Path(ROOT)/'deploy/installer/company_configuration_worker.py')
S.baseline()
p=argparse.ArgumentParser();p.add_argument('command');p.add_argument('--request');p.add_argument('--parent',nargs=7);a=p.parse_args()
raw=S.read_protected(a.request,4096);request=json.loads(raw);sha=hashlib.sha256(raw).hexdigest()
stages=('company-configuration','repository-seed','fresh-runtime-pair')
actions=dict(zip(stages,('a'*64,'b'*64,'c'*64)))
mapping={}
for stage,commands in zip(stages,(('configuration-action','configure-foundation','verify-configuration'),('repository-action','seed-repository','verify-repository'),('runtime-pair-action','initialize-runtime-pair','verify-runtime-pair'))):
 for index,name in enumerate(commands):mapping[name]=(stage,index)
stage,index=mapping[a.command];action=actions[stage]
if index==0:print(action);raise SystemExit(0)
arguments=P.ParentInput.from_argv(a.parent)
operation='/opt/autosoft-company/evidence/'+request['operationId'];directory=operation+'/'+stage
worker_sha=hashlib.sha256(S.read_protected(__file__,2097152)).hexdigest()
data=json.dumps(dict(session=arguments.session,stage=stage,workerSha256=worker_sha),sort_keys=True).encode()
intended=json.dumps(dict(request=sha,action=action,worker=worker_sha,session=arguments.session),sort_keys=True).encode()
with P.hold_parent(arguments) as parent:
 assert arguments.request==sha and arguments.stage==stage and arguments.action==action
 for previous in stages[:stages.index(stage)]:
  evidence=P.record(parent.files[parent.session_path+'/'+previous+'.confirmed'][2],'install-stage-confirmed-v1',('session','stage','action','outcome','independently_confirmed'))
  prior=S.read_protected(operation+'/'+previous+'/executed.json',32768)
  assert evidence==dict(session=arguments.session,stage=previous,action=actions[previous],outcome=hashlib.sha256(prior).hexdigest(),independently_confirmed='true')
 if index==1:
  os.mkdir(directory,0o700);W.write(R,directory,'intent.json',intended)
  if MODE=='missing-execute' and stage==stages[0]:raise SystemExit(21)
  # Explicit synthetic effect, exclusive creation makes replay observable.
  target=Path(directory)/'effect';fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o400)
  os.write(fd,stage.encode());os.fsync(fd);os.close(fd)
  W.write(R,directory,'executed.json',data)
 else:
  assert S.read_protected(directory+'/intent.json',4096)==intended
  assert S.read_protected(directory+'/effect',4096)==stage.encode()
  assert S.read_protected(directory+'/executed.json',32768)==data
 parent.check()
if index==1:
 if MODE in ('stop-after-execute','changed-request','tampered-record') and stage==stages[0]:raise SystemExit(23)
else:
 existed=os.path.lexists(directory+'/verified.json')
 W.write_observation(R,S,directory,'verified.json',data)
 if MODE=='partial-verification' and stage==stages[0] and not existed:raise SystemExit(24)
 session='s-XXXXXXXXXXXX' if MODE=='stale-confirmation' else arguments.session
 magic={'company-configuration':'configuration','repository-seed':'repository','fresh-runtime-pair':'runtime-pair'}[stage]+'-verified-v1'
 marker=(magic+'\nrequest='+sha+'\nsession='+session+'\nstage='+stage+'\naction='+action+'\noutcome='+hashlib.sha256(data).hexdigest()+'\n').encode()
 W.write_observation(R,S,directory,'confirmation',marker,mode=0o600)
''').encode()


def fixture(mode,case):
    case=Path(case)
    assert sys.platform=='linux' and os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    assert str(case).startswith('/srv/') and case.resolve()==case
    for name in ('etc','opt'):
        target=case/name;target.mkdir(mode=0o700)
        subprocess.run(['/usr/bin/mount','--bind',str(target),'/'+name],check=True,timeout=10)
    base=Path('/opt/autosoft-company');package=base/'bootstrap';package.mkdir(mode=0o700,parents=True)
    operation='e'*32;(base/'requests').mkdir(mode=0o700);(base/'evidence').mkdir(mode=0o700)
    evidence=base/'evidence'/operation;evidence.mkdir(mode=0o700)
    request=base/'requests'/(operation+'.json');request.write_text(json.dumps({'operationId':operation})+'\n');request.chmod(0o600)
    raw=worker(mode);target=package/'company-native-retention.py';target.write_bytes(raw);target.chmod(0o400)
    B=load('preparation_entry_builder',ROOT/'deploy/installer/build-native-retention-package.py')
    entry=B.assemble_entry(ROOT,raw,reader=lambda path,maximum:path.read_bytes(),preparation=True)
    script=package/'company-prepare.sh';script.write_bytes(entry);script.chmod(0o400)
    env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',TZ='UTC')
    subprocess.run(['/bin/bash','--noprofile','--norc','-c','source "$1"; install_lock_initialize /etc/autosoft-install-admission','fixture',str(ROOT/'scripts/install-lock.sh')],env=env,check=True,timeout=15)
    argv=['/bin/bash','--noprofile','--norc',str(script),'--prepare-foundation',str(request)]
    if mode=='finalization-interrupted':
        script.write_bytes(entry.replace(b'  install_lock_complete "$session" "$final_outcome"',b'  _il_fail synthetic_completion_interruption'))
    first=subprocess.run(argv,env=env,capture_output=True,timeout=150)
    admission=Path('/etc/autosoft-install-admission');sessions=list((admission/'sessions').iterdir());assert len(sessions)==1
    def counts():return dict(sessions=len(list((admission/'sessions').iterdir())),effects=len(list(evidence.rglob('effect'))),confirmed=len(list(admission.rglob('*.confirmed'))),complete=len(list(admission.rglob('complete'))))
    report=dict(mode=mode,firstExit=first.returncode,firstStdout=first.stdout.decode(),firstStderr=first.stderr.decode(),before=counts())
    snapshots={str(p):p.read_bytes() for p in evidence.rglob('*') if p.is_file()}
    if mode=='changed-request':request.write_text(json.dumps({'operationId':operation,'changed':True})+'\n')
    if mode=='tampered-record':
        changed=evidence/'company-configuration'/'executed.json';changed.write_bytes(b'changed');snapshots[str(changed)]=b'changed'
    if mode=='finalization-interrupted':script.write_bytes(entry)
    recovery=subprocess.run([*argv[:4],'--recover-preparation',str(request),sessions[0].name],env=env,capture_output=True,timeout=150)
    report.update(recoveryExit=recovery.returncode,recoveryStdout=recovery.stdout.decode(),recoveryStderr=recovery.stderr.decode(),after=counts(),
        originalRecordsPreserved=all(Path(p).read_bytes()==raw for p,raw in snapshots.items()))
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n')


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root private namespace qualification required')
class NativePreparation(unittest.TestCase):
    def case(self,mode):
        base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);info=base.lstat()
        assert str(base).startswith('/srv/') and base.resolve()==base and info.st_uid==info.st_gid==0 and info.st_mode&0o777==0o700
        case=base/uuid.uuid4().hex;case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],capture_output=True,timeout=330)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        report=json.loads((case/'report.json').read_text());self.assertTrue(report['originalRecordsPreserved']);return report
    def test_success_three_original_parent_confirmations_and_completed_rerun_refused(self):
        r=self.case('success');self.assertEqual(r['firstExit'],0,r['firstStderr'])
        self.assertEqual(r['before'],dict(sessions=1,effects=3,confirmed=3,complete=1));self.assertNotEqual(r['recoveryExit'],0)
        self.assertEqual(r['before'],r['after'])
    def test_interrupted_execute_is_only_verified_then_remaining_steps_run_once(self):
        r=self.case('stop-after-execute');self.assertNotEqual(r['firstExit'],0)
        self.assertEqual(r['before'],dict(sessions=1,effects=1,confirmed=0,complete=0))
        self.assertEqual(r['recoveryExit'],0,r['recoveryStderr']);self.assertEqual(r['after'],dict(sessions=1,effects=3,confirmed=3,complete=1))
    def test_partial_verification_remeasures_and_retains_exact_observation(self):
        r=self.case('partial-verification');self.assertNotEqual(r['firstExit'],0)
        self.assertEqual(r['recoveryExit'],0,r['recoveryStderr']);self.assertEqual(r['after']['effects'],3)
    def test_missing_execute_never_replayed_or_confirmed(self):
        r=self.case('missing-execute');self.assertNotEqual(r['recoveryExit'],0);self.assertEqual(r['before'],r['after'])
        self.assertEqual(r['after']['effects'],0)
    def test_changed_request_refused_without_effect(self):
        r=self.case('changed-request');self.assertNotEqual(r['recoveryExit'],0);self.assertEqual(r['before'],r['after'])
    def test_tampered_execution_preserved_and_refused(self):
        r=self.case('tampered-record');self.assertNotEqual(r['recoveryExit'],0);self.assertEqual(r['before'],r['after'])
    def test_stale_confirmation_never_acknowledged(self):
        r=self.case('stale-confirmation');self.assertNotEqual(r['firstExit'],0);self.assertNotEqual(r['recoveryExit'],0)
        self.assertEqual(r['before'],r['after']);self.assertEqual(r['after']['confirmed'],0)
    def test_all_confirmations_survive_interrupted_finalization(self):
        r=self.case('finalization-interrupted');self.assertNotEqual(r['firstExit'],0)
        self.assertEqual(r['before'],dict(sessions=1,effects=3,confirmed=3,complete=0))
        self.assertEqual(r['recoveryExit'],0,r['recoveryStderr']);self.assertEqual(r['after'],dict(sessions=1,effects=3,confirmed=3,complete=1))


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
