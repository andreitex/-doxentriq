"""Real admission parent with synthetic trusted effects in private namespaces.

This exercises the runtime-pair companion Bash entry, child exit and closed confirmation
binding. It does not replace or qualify signed source, LUKS or full activation.
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
S=load('seed_entry_station','deploy/installer/company_native_station.py')
P=load('seed_entry_parent','scripts/installer_parent.py')
R=load('seed_entry_records','deploy/installer/company_retention_records.py')
W=load('seed_entry_writer','deploy/installer/company_configuration_worker.py')
S.baseline()
p=argparse.ArgumentParser();p.add_argument('command');p.add_argument('--request');p.add_argument('--parent',nargs=7);a=p.parse_args()
raw=S.read_protected(a.request,4096);request=json.loads(raw);sha=hashlib.sha256(raw).hexdigest();action='a'*64
directory='/opt/autosoft-company/evidence/'+request['operationId']+'/fresh-runtime-pair'
if a.command=='runtime-pair-action':
 if MODE=='preflight-failure':raise ValueError('synthetic prerequisite failure')
 print(action);raise SystemExit(0)
arguments=P.ParentInput.from_argv(a.parent)
with P.hold_parent(arguments) as parent:
 parent.check()
 assert arguments.stage=='fresh-runtime-pair' and arguments.action==action and arguments.request==sha
 if a.command=='initialize-runtime-pair':
  os.mkdir(directory,0o700)
  W.write(R,directory,'executed.json',b'{}\n')
 else:
  assert a.command=='verify-runtime-pair' and S.read_protected(directory+'/executed.json',32768)==b'{}\n'
 parent.check()
if a.command=='initialize-runtime-pair':
 if MODE=='child-failure':raise SystemExit(23)
else:
 session='f'*32 if MODE=='stale-confirmation' else arguments.session
 marker=('runtime-pair-verified-v1\nrequest='+sha+'\nsession='+session+'\nstage=fresh-runtime-pair\naction='+action+'\noutcome='+'b'*64+'\n').encode()
 W.write(R,directory,'confirmation',marker,mode=0o600)
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
    entry=(ROOT/'deploy/installer/company-runtime-pair.sh').read_bytes().replace(b'# @EMBED_INSTALL_LOCK@',(ROOT/'scripts/install-lock.sh').read_bytes())
    entry=entry.replace(b'@WORKER_SHA256@',hashlib.sha256(raw).hexdigest().encode())
    script=package/'company-runtime-pair.sh';script.write_bytes(entry);script.chmod(0o400)
    env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',TZ='UTC')
    subprocess.run(['/bin/bash','--noprofile','--norc','-c','source "$1"; install_lock_initialize /etc/autosoft-install-admission','fixture',str(ROOT/'scripts/install-lock.sh')],env=env,check=True,timeout=15)
    result=subprocess.run(['/bin/bash','--noprofile','--norc',str(script),'--initialize-runtime-pair',str(request)],env=env,capture_output=True,timeout=90)
    admission=Path('/etc/autosoft-install-admission')
    report=dict(mode=mode,exitCode=result.returncode,stderr=result.stderr.decode(),stdout=result.stdout.decode(),
        sessions=len(list((admission/'sessions').iterdir())),confirmed=len(list(admission.rglob('*.confirmed'))),
        completed=len(list(admission.rglob('complete'))),executed=len(list((base/'evidence').rglob('executed.json'))))
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class NativeRuntimePairEntryTests(unittest.TestCase):
    def run_case(self,mode):
        base=Path(os.environ['DOXENTRIQ_PAIR_TEST_ROOT']);assert str(base).startswith('/srv/') and base.resolve()==base
        case=base/uuid.uuid4().hex;case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=110)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        return json.loads((case/'report.json').read_text())
    def test_success_confirms_after_child_exit_and_verification(self):
        r=self.run_case('success');self.assertEqual(r['exitCode'],0,r['stderr']);self.assertEqual((r['confirmed'],r['completed'],r['executed']),(1,1,1))
        self.assertIn('activation remain incomplete',r['stdout'])
    def test_child_failure_after_effect_never_confirms(self):
        r=self.run_case('child-failure');self.assertNotEqual(r['exitCode'],0);self.assertEqual((r['confirmed'],r['completed'],r['executed']),(0,0,1))
    def test_stale_confirmation_never_confirms(self):
        r=self.run_case('stale-confirmation');self.assertNotEqual(r['exitCode'],0);self.assertEqual((r['confirmed'],r['completed'],r['executed']),(0,0,1))
    def test_prerequisite_failure_creates_no_session(self):
        r=self.run_case('preflight-failure');self.assertNotEqual(r['exitCode'],0);self.assertEqual((r['sessions'],r['confirmed'],r['executed']),(0,0,0))


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
