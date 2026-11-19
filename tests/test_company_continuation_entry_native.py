"""Actual three-stage Bash admission with explicit synthetic trusted effects.

Private mount namespaces replace /etc and /opt only inside each fixture. No
host services, real signed releases, encrypted volumes or platform are touched.
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


def worker(mode):
    return ('ROOT='+repr(str(ROOT))+'\nMODE='+repr(mode)+'\n'+r'''
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,Path(ROOT)/path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
S=load('continuation_station','deploy/installer/company_native_station.py')
P=load('continuation_parent','scripts/installer_parent.py')
R=load('continuation_records','deploy/installer/company_retention_records.py')
W=load('continuation_writer','deploy/installer/company_configuration_worker.py')
S.baseline()
p=argparse.ArgumentParser();p.add_argument('command');p.add_argument('--request');p.add_argument('--stage');p.add_argument('--persist',action='store_true');p.add_argument('--parent',nargs=7);a=p.parse_args()
raw=S.read_protected(a.request,4096);request=json.loads(raw);sha=hashlib.sha256(raw).hexdigest()
actions={'company-platform-store':'a'*64,'company-source-materialize':'b'*64,'company-stored-startup':'c'*64}
outcomes={'company-platform-store':'d'*64,'company-source-materialize':'e'*64,'company-stored-startup':'f'*64}
stage=a.stage or 'company-stored-startup';action=actions[stage]
operation='/opt/autosoft-company/evidence/'+request['operationId'];directory=operation+'/'+stage
if a.command=='continuation-ready':
 if MODE=='preflight-failure':raise ValueError('synthetic prerequisite failure')
 print('ready');raise SystemExit(0)
if a.command in ('plan-stage','startup-action'):
 if a.command=='plan-stage':os.mkdir(directory,0o700)
 print(action);raise SystemExit(0)
arguments=P.ParentInput.from_argv(a.parent)
with P.hold_parent(arguments) as parent:
 parent.check();assert arguments.stage==stage and arguments.action==action and arguments.request==sha
 prior=() if stage=='company-platform-store' else ('company-platform-store',) if stage=='company-source-materialize' else ('company-platform-store','company-source-materialize')
 for name in prior:
  path=parent.session_path+'/'+name+'.confirmed'
  evidence=P.record(parent.files[path][2],'install-stage-confirmed-v1',('session','stage','action','outcome','independently_confirmed'))
  assert evidence==dict(session=arguments.session,stage=name,action=actions[name],outcome=outcomes[name],independently_confirmed='true')
 if a.command in ('execute-verify','inspect-stored-startup'):
  if stage=='company-stored-startup':os.mkdir(directory,0o700)
  W.write(R,directory,'executed.json',json.dumps({'session':arguments.session,'stage':stage}).encode())
 else:
  actual=json.loads(S.read_protected(directory+'/executed.json',32768));assert actual=={'session':arguments.session,'stage':stage}
 parent.check()
if a.command in ('execute-verify','inspect-stored-startup'):
 if MODE=='source-child-failure' and stage=='company-source-materialize':raise SystemExit(23)
 if MODE=='startup-child-failure' and stage=='company-stored-startup':raise SystemExit(23)
else:
 session='s-XXXXXXXXXXXX' if MODE=='stale-startup-confirmation' and stage=='company-stored-startup' else arguments.session
 magic='stored-startup-verified-v1' if stage=='company-stored-startup' else 'retention-verified-v1'
 marker=magic+'\nrequest='+sha+'\nsession='+session+'\nstage='+stage+'\naction='+action+'\noutcome='+outcomes[stage]+'\n'
 if stage!='company-stored-startup':marker+='verification='+'1'*64+'\n'
 W.write(R,directory,'confirmation',marker.encode(),mode=0o600)
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
    operation='e'*32
    (base/'requests').mkdir(mode=0o700);(base/'evidence').mkdir(mode=0o700);(base/'evidence'/operation).mkdir(mode=0o700)
    request=base/'requests'/(operation+'.json');request.write_text(json.dumps({'operationId':operation})+'\n');request.chmod(0o600)
    raw=worker(mode);target=package/'company-native-retention.py';target.write_bytes(raw);target.chmod(0o400)
    spec=importlib.util.spec_from_file_location('continuation_builder',ROOT/'deploy/installer/build-native-retention-package.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    entry=builder.assemble_entry(ROOT,raw,reader=lambda path,maximum:path.read_bytes(),continuation=True)
    script=package/'company-continue.sh';script.write_bytes(entry);script.chmod(0o400)
    env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',TZ='UTC')
    subprocess.run(['/bin/bash','--noprofile','--norc','-c','source "$1"; install_lock_initialize /etc/autosoft-install-admission','fixture',str(ROOT/'scripts/install-lock.sh')],env=env,check=True,timeout=15)
    argv=['/bin/bash','--noprofile','--norc',str(script),'--retain-and-inspect-startup',str(request)]
    result=subprocess.run(argv,env=env,capture_output=True,timeout=90)
    admission=Path('/etc/autosoft-install-admission');sessions=list((admission/'sessions').iterdir())
    evidence=[json.loads(path.read_text()) for path in (base/'evidence').rglob('executed.json')]
    report=dict(mode=mode,exitCode=result.returncode,stderr=result.stderr.decode(),stdout=result.stdout.decode(),
        sessions=len(sessions),confirmed=len(list(admission.rglob('*.confirmed'))),
        completed=len(list(admission.rglob('complete'))),executed=len(evidence),
        effectSessions=sorted({row['session'] for row in evidence}),stageOrder=[p.name for p in admission.rglob('*.intent')])
    if mode=='startup-child-failure':
        retry=subprocess.run(argv,env=env,capture_output=True,timeout=90)
        report.update(retryExit=retry.returncode,retrySessions=len(list((admission/'sessions').iterdir())),
            retryEffects=len(list((base/'evidence').rglob('executed.json'))))
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n')


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class NativeContinuationEntryTests(unittest.TestCase):
    def run_case(self,mode):
        base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);info=base.lstat()
        assert str(base).startswith('/srv/') and base.resolve()==base and info.st_uid==info.st_gid==0 and info.st_mode&0o777==0o700
        case=base/uuid.uuid4().hex;case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=210)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        return json.loads((case/'report.json').read_text())

    def test_success_three_confirmations_share_one_live_parent_session(self):
        r=self.run_case('success');self.assertEqual(r['exitCode'],0,r['stderr'])
        self.assertEqual((r['sessions'],r['confirmed'],r['completed'],r['executed']),(1,3,1,3))
        self.assertEqual(len(r['effectSessions']),1);self.assertIn('activation remain incomplete',r['stdout'])

    def test_source_failure_does_not_reach_startup(self):
        r=self.run_case('source-child-failure');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['confirmed'],r['completed'],r['executed']),(1,0,2))

    def test_startup_failure_preserves_two_confirmations_and_refuses_automatic_rerun(self):
        r=self.run_case('startup-child-failure');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['confirmed'],r['completed'],r['executed']),(2,0,3))
        self.assertNotEqual(r['retryExit'],0);self.assertEqual((r['retrySessions'],r['retryEffects']),(1,3))

    def test_stale_confirmation_never_completes_session(self):
        r=self.run_case('stale-startup-confirmation');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['confirmed'],r['completed'],r['executed']),(2,0,3))

    def test_missing_prerequisite_creates_no_session_or_effect(self):
        r=self.run_case('preflight-failure');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['sessions'],r['confirmed'],r['executed']),(0,0,0))


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
