"""Real Bash/lock/parent/record IO, with explicitly synthetic trusted effects.

Each case runs in its own private mount namespace over fresh /etc and /opt.
No actual services or live admission files are touched. This is not signed
Store/Source, encrypted-foundation, clean-VM or full-installer qualification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


def synthetic_worker(root,mode):
    # The company test harness deliberately pins this trusted synthetic worker.
    # Production packaging has no alternate-worker flag or test mode.
    header='ROOT='+repr(str(root))+'\nMODE='+repr(mode)+'\n'
    return (header+r'''
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
R=load('native_entry_records',Path(ROOT)/'deploy/installer/company_retention_records.py')
S=load('native_entry_station',Path(ROOT)/'deploy/installer/company_native_station.py')
P=load('native_entry_parent',Path(ROOT)/'scripts/installer_parent.py')
S.baseline()
p=argparse.ArgumentParser();p.add_argument('command');p.add_argument('--request');p.add_argument('--stage');p.add_argument('--persist',action='store_true');p.add_argument('--parent',nargs=7);a=p.parse_args()
request_raw=S.read_protected(a.request,4096);request=json.loads(request_raw);stage=a.stage
directory=R.stage_path(request['operationId'],stage);identity='f'*64
def record(command,plan_raw,parent=None,result=None):
 return dict(schemaVersion=1,scope='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY',command=command,deliveryIdentitySha256=identity,
  binding=R.binding(request,request_raw,stage,None if command=='plan-stage' else plan_raw,parent),
  planBase64=__import__('base64').b64encode(plan_raw).decode() if command=='plan-stage' else None,
  result=result,outcomeSha256=result['operationOutcomeSha256'] if result else None,stageAcknowledged=False,fullInstallationCompleted=False,nativeQualified=False)
if a.command=='plan-stage':
 stage_request=dict(scope='SYNTHETIC_TRUSTED_STAGE_TEST_ONLY',stage=stage)
 plan=R.canonical(dict(schemaVersion=1,scope='RETENTION_STAGE_PLAN_ONLY',stage=stage,installationRequestSha256=R.sha(request_raw),
  operationId=R.operation(request,stage),storeOperationId=request['operationId'],stageRequest=stage_request,
  stageRequestSha256=R.sha(R.canonical(stage_request)),actionSha256=R.sha(('synthetic:'+stage).encode())))
 raw=R.canonical(record('plan-stage',plan));R.planning_record(raw,request,request_raw,stage,identity)
 R.prepare_stage(request['operationId'],stage);R.write_record(directory,'planned.json',raw);R.write_record(directory,'plan.json',plan)
 print(json.loads(plan)['actionSha256']);sys.exit(0)
plan=S.read_protected(directory+'/plan.json',16384)
with P.hold_parent(P.ParentInput.from_argv(a.parent)) as parent:
 parent.check()
 if a.command=='execute-verify':
  effect=Path(directory)/'synthetic-effect'
  with effect.open('xb') as stream:stream.write(b'actual exclusive fixture file\n');stream.flush();os.fsync(stream.fileno())
  outcome=dict(scope='SYNTHETIC_NATIVE_FILE_ONLY',sha256=R.sha(effect.read_bytes()))
  result=dict(operationResult=outcome,operationOutcomeSha256=R.sha(R.canonical(outcome)),stagePlanSha256=R.sha(plan),
   ownedResourcesKnownReleased=True,stageAcknowledged=False,nativeAuthorized=False,effectsIndependentlyConfirmed=False)
  executed=R.canonical(record('execute-stage',plan,a.parent,result))
  # Use the actual exclusive executed.json publisher, not Path.write_bytes.
  X=load('native_entry_store',Path(ROOT)/'deploy/installer/company_cli_executed_record_store.py')
  try:
   X.store_executed_record(directory,expected_directory_metadata=S.metadata(os.stat(directory)),completed_record_raw=executed,
    os_module=os,sys_module=sys,fcntl_module=S.fcntl,clock=S.time.monotonic)
  except BaseException:
   trace=__import__('traceback');trace.print_exc()
   if X.UNRELEASED:
    failure=X.UNRELEASED[-1]
    trace.print_exception(failure.get('error'))
    print('fixture publisher calls',failure.get('calls'),'rows',[(row['name'],row['role'],row['identity'],row['flags'],row['uncertain']) for row in failure.get('rows',[])],file=sys.stderr)
   raise
  result['retainedEffectsObservation']=dict(operationResult=outcome,operationOutcomeSha256=R.sha(R.canonical(outcome)),
   exactEffectsReread=effect.read_bytes()==b'actual exclusive fixture file\n',ownedReadHandlesKnownReleased=True,
   outerContextsRequireClosure=True,stageAcknowledged=False,nativeQualified=False)
  verified=record('verify-stage',plan,a.parent,result)
  if MODE=='stale-verification':verified['binding']['session']='s-Zzz123Def456'
  R.write_record(directory,'verified.json',R.canonical(verified));parent.check()
  if MODE=='child-failure':sys.exit(17)
 elif a.command=='inspect-completion':
  marker=R.completion(S.read_protected(directory+'/executed.json',32768),S.read_protected(directory+'/verified.json',32768),
    plan,request,request_raw,stage,a.parent,identity)
  parent.check()
 else:raise ValueError('unknown fixture command')
if a.command=='inspect-completion':R.write_record(directory,'confirmation',marker,mode=0o600)
''').encode()


def namespace_case(case_directory,mode):
    case=Path(case_directory)
    require=lambda value: (_ for _ in ()).throw(ValueError('unsafe-native-fixture')) if not value else None
    require(sys.platform=='linux' and os.geteuid()==os.getegid()==0
        and os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
        and str(case).startswith('/srv/') and case.is_dir() and not case.is_symlink())
    for name in ('etc','opt'):
        target=case/name;target.mkdir(mode=0o700)
        subprocess.run(['/usr/bin/mount','--bind',str(target),'/'+name],check=True,timeout=10)
    package=Path('/opt/autosoft-company/bootstrap');package.mkdir(mode=0o700,parents=True)
    for name in ('evidence','requests'):(package.parent/name).mkdir(mode=0o700)
    operation='e'*32;request=dict(schemaVersion=1,mode='SYNTHETIC_PARENT_PROTOCOL_ONLY',operationId=operation,releaseSha256='d'*64)
    request_path=package.parent/'requests'/f'{operation}.json';request_path.write_text(json.dumps(request,sort_keys=True,separators=(',',':'))+'\n');request_path.chmod(0o600)
    builder=load('native_entry_fixture_builder',ROOT/'deploy/installer/build-native-retention-package.py')
    raw=synthetic_worker(ROOT,mode);worker=package/'company-native-retention.py';worker.write_bytes(raw);worker.chmod(0o400)
    entry=package/'company-retention.sh';entry.write_bytes(builder.assemble_entry(ROOT,raw,reader=lambda p,n:p.read_bytes()));entry.chmod(0o400)
    if mode=='tampered-worker':worker.chmod(0o600);worker.write_bytes(raw+b'\n#changed\n');worker.chmod(0o400)
    env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LANG='C',LC_ALL='C',HOME='/',TZ='UTC')
    initialization='source "$1"; install_lock_initialize /etc/autosoft-install-admission'
    subprocess.run(['/bin/bash','--noprofile','--norc','-c',initialization,'fixture',str(ROOT/'scripts/install-lock.sh')],env=env,check=True,timeout=15)
    result=subprocess.run(['/bin/bash','--noprofile','--norc',str(entry),'--retention-only',str(request_path)],env=env,capture_output=True,timeout=90)
    sessions=list(Path('/etc/autosoft-install-admission/sessions').iterdir())
    confirmed=[str(path.relative_to('/etc/autosoft-install-admission')) for path in Path('/etc/autosoft-install-admission').rglob('*.confirmed')]
    completed=list(Path('/etc/autosoft-install-admission').rglob('complete'))
    effects=list((package.parent/'evidence').rglob('synthetic-effect'))
    evidence=list((package.parent/'evidence').rglob('executed.json'))
    verified=list((package.parent/'evidence').rglob('verified.json'))
    report=dict(mode=mode,exitCode=result.returncode,sessions=len(sessions),confirmed=confirmed,completed=len(completed),
        effects=len(effects),executed=len(evidence),verified=len(verified),stdout=result.stdout.decode(),stderr=result.stderr.decode(),
        scope='Real private-namespace Bash parent/lock/publisher with synthetic trusted file effects only')
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report));return 0


NATIVE=sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0 and bool(os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT'))


@unittest.skipUnless(NATIVE,'requires explicit protected Linux native validation root')
class NativeEntryTests(unittest.TestCase):
    def run_case(self,mode):
        base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        self.assertTrue(str(base).startswith('/srv/') and base.is_dir() and not base.is_symlink())
        case=Path(tempfile.mkdtemp(prefix='entry-'+mode+'-',dir=base))
        env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LANG='C',LC_ALL='C',HOME='/',TZ='UTC')
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','--','/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),
            '--namespace-case',str(case),'--mode',mode],env=env,capture_output=True,timeout=110)
        (case/'outer.stdout').write_bytes(result.stdout);(case/'outer.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        return json.loads((case/'report.json').read_text())

    def test_success_confirms_two_stages_only_after_exit_and_exact_record_inspection(self):
        report=self.run_case('success')
        self.assertEqual(report['exitCode'],0,report['stderr'])
        self.assertEqual(len(report['confirmed']),2);self.assertEqual(report['completed'],1);self.assertEqual(report['effects'],2)
        self.assertIn('Full platform installation is pending',report['stdout'])

    def test_child_failure_after_writing_success_records_never_confirms(self):
        report=self.run_case('child-failure')
        self.assertNotEqual(report['exitCode'],0);self.assertEqual(report['confirmed'],[]);self.assertEqual(report['completed'],0)
        self.assertEqual(report['effects'],1);self.assertEqual(report['executed'],1)
        self.assertEqual(report['verified'],1)

    def test_stale_verification_session_never_confirms_or_runs_next_stage(self):
        report=self.run_case('stale-verification')
        self.assertNotEqual(report['exitCode'],0);self.assertEqual(report['confirmed'],[]);self.assertEqual(report['completed'],0)
        self.assertEqual(report['effects'],1)
        self.assertEqual(report['executed'],1);self.assertEqual(report['verified'],1)

    def test_changed_worker_is_denied_before_admission(self):
        report=self.run_case('tampered-worker')
        self.assertNotEqual(report['exitCode'],0);self.assertEqual(report['sessions'],0);self.assertEqual(report['effects'],0)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--namespace-case':
        p=argparse.ArgumentParser();p.add_argument('--namespace-case');p.add_argument('--mode',choices=('success','child-failure','stale-verification','tampered-worker'),required=True)
        a=p.parse_args();raise SystemExit(namespace_case(a.namespace_case,a.mode))
    unittest.main()
