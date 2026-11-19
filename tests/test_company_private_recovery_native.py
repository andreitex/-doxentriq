"""Private-session resume through original Bash/HeldParent, with synthetic effects.

Each fixture owns a private mount namespace for /etc and /opt. No host services,
encrypted storage, credentials, signed installation or real identity are used.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

Q=load('private_recovery_quota_fixture',ROOT/'tests/test_company_quota_entry_native.py')

def worker(mode):
    raw=Q.worker(mode).decode()
    anchor="operation='/opt/autosoft-company/evidence/'+request['operationId'];directory=operation+'/'+stage"
    assert raw.count(anchor)==1
    raw=raw.replace(anchor,anchor+"\nwith open('/opt/autosoft-company/calls','a') as log:log.write(json.dumps(dict(command=a.command,stage=stage))+'\\n')")
    anchor="  W.write(R,directory,'executed.json',json.dumps({'session':arguments.session,'stage':stage}).encode())"
    assert raw.count(anchor)==1
    raw=raw.replace(anchor,"  if MODE=='identity-unknown' and stage=='company-initial-identity':\n   W.write(R,directory,'intent.json',b'preserve');raise SystemExit(23)\n"+anchor+"\n  if stage in R.STAGES and not(MODE=='source-unverified'and stage=='company-source-materialize'):W.write(R,directory,'verified.json',b'closed-synthetic-verification')")
    anchor="  actual=json.loads(S.read_protected(directory+'/executed.json',32768));assert actual=={'session':arguments.session,'stage':stage}"
    assert raw.count(anchor)==1
    raw=raw.replace(anchor,anchor+"\n  if stage in R.STAGES:assert S.read_protected(directory+'/verified.json',32768)==b'closed-synthetic-verification'\n  if MODE=='identity-workspace' and stage=='company-initial-identity':\n   IO=load('actual_identity_operation_io','deploy/installer/company_identity_io.py')\n   try:\n    held=IO.IdentityIO('/opt/autosoft-company/data',request['operationId'],b'synthetic-source',b'synthetic-ca',check_authority=parent.check)\n   except FileExistsError:\n    parent.check()\n    with open('/opt/autosoft-company/calls','a')as log:log.write(json.dumps(dict(command='actual-identity-workspace-refused',stage=stage))+'\\n')\n    raise\n   held.close()")
    anchor=" if MODE=='source-child-failure'"
    assert raw.count(anchor)==1
    raw=raw.replace(anchor," if MODE=='source-unverified' and stage=='company-source-materialize':raise SystemExit(23)\n if MODE=='identity-workspace' and stage=='company-initial-identity':raise SystemExit(23)\n"+anchor)
    compile(raw,'<private recovery synthetic effects>','exec');return raw.encode()

def fixture(case_name,case):
    case=Path(case)
    assert sys.platform=='linux' and os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']) and case.resolve()==case
    for name in ('etc','opt'):
        target=case/name;target.mkdir(mode=0o700)
        subprocess.run(['/usr/bin/mount','--bind',str(target),'/'+name],check=True,timeout=10)
    base=Path('/opt/autosoft-company');package=base/'bootstrap';package.mkdir(mode=0o700,parents=True)
    operation='e'*32
    for name in ('requests','evidence','data'):(base/name).mkdir(mode=0o700)
    (base/'data/company').mkdir(mode=0o700)
    evidence=base/'evidence'/operation;evidence.mkdir(mode=0o700)
    request=base/'requests'/(operation+'.json');request.write_text(json.dumps({'operationId':operation})+'\n');request.chmod(0o600)
    first_quota=case_name not in ('six-stage','scope-changed')
    mode={'retention-closed':'source-child-failure','retention-unverified':'source-unverified',
        'worker-changed':'startup-child-failure','identity-unknown':'identity-unknown','identity-workspace':'identity-workspace',
        'completed':'success','finalization':'success'}.get(case_name,'infrastructure-child-failure')
    raw=worker(mode);target=package/'company-native-retention.py';target.write_bytes(raw);target.chmod(0o400)
    B=load('private_recovery_builder',ROOT/'deploy/installer/build-native-retention-package.py')
    def assemble(quota):return B.assemble_entry(ROOT,target.read_bytes(),reader=lambda path,maximum:path.read_bytes(),**({'quota':True}if quota else{'initialization':True}))
    entry=assemble(first_quota);script=package/'company-initialize.sh'
    if case_name=='finalization':
        anchor=b'  install_lock_complete "$session" "$final_outcome"'
        assert entry.count(anchor)==1;entry=entry.replace(anchor,b'  false # synthetic interruption after all stage confirmations')
    script.write_bytes(entry);script.chmod(0o400)
    env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',TZ='UTC')
    subprocess.run(['/bin/bash','--noprofile','--norc','-c','source "$1"; install_lock_initialize /etc/autosoft-install-admission','fixture',str(ROOT/'scripts/install-lock.sh')],env=env,check=True,timeout=15)
    def invoke(flag,session=None):
        args=['/bin/bash','--noprofile','--norc',str(script),flag,str(request)]
        if session is not None:args.append(session)
        return subprocess.run(args,env=env,capture_output=True,timeout=90)
    if case_name=='binding-preexisting':
        prior=evidence/'private-session';prior.write_bytes(b'preserved-existing-binding\n');prior.chmod(0o600)
    first=invoke('--retain-render-initialize-and-start-quota'if first_quota else'--retain-render-and-initialize-private')
    admission=Path('/etc/autosoft-install-admission');sessions=list((admission/'sessions').iterdir());assert len(sessions)==1
    session=sessions[0].name
    def snapshot():
        calls=[json.loads(line)for line in (base/'calls').read_text().splitlines()]
        effects=[row for row in calls if row['command']in('execute-verify','inspect-stored-startup','render-configuration','initialize-private-infrastructure','provision-initial-identity','activate-private-quota')]
        return dict(confirmed=len(list(admission.rglob('*.confirmed'))),completed=len(list(admission.rglob('complete'))),
            executed=len(list(evidence.rglob('executed.json'))),calls=calls,effects=effects,
            evidence={p.relative_to(evidence).as_posix():p.read_bytes().hex()for p in evidence.rglob('*')if p.is_file()})
    before=snapshot();binding=evidence/'private-session'
    if case_name=='worker-changed':
        target.write_bytes(raw+b'\n# changed packaged worker\n');target.chmod(0o400)
        script.write_bytes(assemble(first_quota));script.chmod(0o400)
    elif case_name=='request-changed':request.write_text(json.dumps({'operationId':operation,'changed':True})+'\n')
    elif case_name=='scope-changed':script.write_bytes(assemble(True));script.chmod(0o400)
    elif case_name=='binding-partial':binding.write_bytes(b'private-continuation-session-v1\n')
    elif case_name=='binding-missing':binding.rename(evidence/'preserved-missing-binding')
    elif case_name=='partial-verification':
        path=evidence/'company-private-infrastructure/verified.json';path.write_bytes(b'partial');path.chmod(0o400)
    elif case_name=='partial-confirmation':
        path=evidence/'company-private-infrastructure/confirmation';path.write_bytes(b'partial');path.chmod(0o600)
    elif case_name=='orphan-confirmation':
        path=sessions[0]/'company-initial-identity.confirmed';path.write_bytes(b'partial');path.chmod(0o600)
    elif case_name=='stage-order':
        path=sessions[0]/'company-initial-identity.intent';path.write_bytes(b'partial');path.chmod(0o600)
    elif case_name=='identity-workspace':
        path=base/'data/company'/('identity-'+operation);path.mkdir(mode=0o700);(path/'partial').write_bytes(b'preserve')
    elif case_name=='finalization':script.write_bytes(assemble(first_quota));script.chmod(0o400)
    injected=snapshot()
    second=invoke('--recover-private-quota'if first_quota or case_name=='scope-changed'else'--recover-private-initialization',session)
    after=snapshot()
    report=dict(case=case_name,firstExit=first.returncode,firstStderr=first.stderr.decode(),secondExit=second.returncode,
        secondStdout=second.stdout.decode(),secondStderr=second.stderr.decode(),before=before,injected=injected,after=after,
        sessions=len(list((admission/'sessions').iterdir())),sameSession=all(json.loads(p.read_text())['session']==session for p in evidence.rglob('executed.json')),
        workspacePreserved=(base/'data/company'/('identity-'+operation)/'partial').read_bytes()==b'preserve'if case_name=='identity-workspace'else None)
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n')

@unittest.skipUnless(sys.platform=='linux'and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class PrivateRecovery(unittest.TestCase):
    def run_case(self,mode):
        root=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);info=root.lstat()
        assert root.resolve()==root and info.st_uid==info.st_gid==0 and info.st_mode&0o777==0o700
        case=root/uuid.uuid4().hex;case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],stdin=subprocess.DEVNULL,capture_output=True,timeout=210)
        self.assertEqual(result.returncode,0,result.stderr.decode());return json.loads((case/'report.json').read_text())
    def assert_resume(self,mode,count):
        r=self.run_case(mode);self.assertNotEqual(r['firstExit'],0,r['firstStderr']);self.assertEqual(r['secondExit'],0,r['secondStderr'])
        self.assertEqual((r['sessions'],r['after']['confirmed'],r['after']['completed'],r['after']['executed']),(1,count,1,count))
        self.assertTrue(r['sameSession']);self.assertEqual(len(r['after']['effects']),count)
        for row in r['before']['effects']:self.assertEqual(r['after']['effects'].count(row),1)
        return r
    def assert_refused(self,mode):
        r=self.run_case(mode);self.assertNotEqual(r['secondExit'],0,r['secondStdout'])
        self.assertEqual(r['sessions'],1);self.assertEqual(r['injected']['effects'],r['after']['effects'])
        self.assertEqual(r['injected']['evidence'],r['after']['evidence'])
        self.assertEqual(r['injected']['confirmed'],r['after']['confirmed']);return r
    def test_six_stage_pending_infrastructure_only_verifies(self):self.assert_resume('six-stage',6)
    def test_seven_stage_resume_keeps_exact_session_and_effect_prefix(self):self.assert_resume('seven-stage',7)
    def test_retention_closed_records_can_be_inspected_without_reexecution(self):self.assert_resume('retention-closed',7)
    def test_retention_missing_closed_verification_is_preserved(self):self.assert_refused('retention-unverified')
    def test_changed_worker_refused_even_with_two_retention_stages_confirmed(self):
        r=self.assert_refused('worker-changed');self.assertEqual(r['before']['confirmed'],2);self.assertIn('original_private_package_required',r['secondStderr'])
    def test_changed_request_refused(self):self.assert_refused('request-changed')
    def test_six_stage_cannot_be_extended_to_seven_during_recovery(self):self.assert_refused('scope-changed')
    def test_existing_initial_binding_is_never_overwritten(self):
        r=self.assert_refused('binding-preexisting');self.assertNotEqual(r['firstExit'],0)
        self.assertEqual(r['before']['executed'],0);self.assertEqual(r['before']['evidence']['private-session'],b'preserved-existing-binding\n'.hex())
    def test_partial_session_binding_preserved(self):self.assert_refused('binding-partial')
    def test_missing_session_binding_preserved(self):self.assert_refused('binding-missing')
    def test_partial_verification_refused_without_verifier_reentry(self):
        r=self.assert_refused('partial-verification');self.assertNotIn('verify-private-infrastructure',[x['command']for x in r['after']['calls'][len(r['before']['calls']):]])
    def test_partial_confirmation_preserved(self):self.assert_refused('partial-confirmation')
    def test_orphan_confirmation_refused(self):self.assert_refused('orphan-confirmation')
    def test_later_stage_intent_refused_after_pending_stage(self):self.assert_refused('stage-order')
    def test_unknown_identity_effect_is_never_replayed(self):self.assert_refused('identity-unknown')
    def test_real_identity_io_refuses_owned_workspace_collision(self):
        r=self.assert_refused('identity-workspace');self.assertTrue(r['workspacePreserved'])
        self.assertEqual([row['command']for row in r['after']['calls']].count('actual-identity-workspace-refused'),1)
        self.assertIn('ParentUnavailable',r['secondStderr'])
    def test_completed_session_recovery_refused(self):
        r=self.assert_refused('completed');self.assertEqual(r['firstExit'],0,r['firstStderr'])
    def test_interrupted_finalization_reuses_all_confirmations_without_mutation(self):self.assert_resume('finalization',7)

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
