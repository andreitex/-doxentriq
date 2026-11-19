"""Actual three-child Bash composition and HeldParent; synthetic effects only.

Private mount namespaces replace fixture /etc and /opt. No packages, Docker,
encrypted volume, credentials, VM or public services are touched.
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
ENV=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LANG='C',LC_ALL='C',HOME='/',TZ='UTC')

def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m

def foundation_worker(mode):
    return ('ROOT='+repr(str(ROOT))+'\nMODE='+repr(mode)+'\n'+r'''
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,Path(ROOT)/path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
P=load('guided_original_parent','scripts/installer_parent.py')
p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
for n in ('describe','foundation-only','verify'):g.add_argument('--'+n,action='store_true')
p.add_argument('--request');p.add_argument('--worker-sha');p.add_argument('--parent',nargs=7);a=p.parse_args()
raw=Path(a.request).read_bytes();request=json.loads(raw);sha=hashlib.sha256(raw).hexdigest()
if a.describe:print(request['operationId']);raise SystemExit(0)
arguments=P.ParentInput.from_argv(a.parent)
with P.hold_parent(arguments)as parent:
 assert arguments.request==sha and arguments.stage=='foundation'
 assert arguments.action==hashlib.sha256(('foundation-v1:'+sha+':'+a.worker_sha).encode()).hexdigest()
 directory=Path('/opt/autosoft-company/evidence')/request['operationId']
 result=json.dumps(dict(stage='foundation',session=arguments.session),sort_keys=True).encode()
 if a.foundation_only:
  directory.mkdir(mode=0o700)
  for name,value in(('intent.json',raw),('result.json',result)):
   with (directory/name).open('xb')as f:f.write(value);f.flush();os.fsync(f.fileno())
   (directory/name).chmod(0o400)
  if MODE=='status-changed-on-failure':
   Path(__file__).with_name('installation-status.py').write_bytes(b"from pathlib import Path\nPath('/opt/autosoft-company/status-executed').write_text('must never execute')\n")
   raise SystemExit(21)
  if MODE=='foundation-failure':raise SystemExit(21)
 else:
  assert (directory/'intent.json').read_bytes()==raw and (directory/'result.json').read_bytes()==result
  marker=('foundation-verified-v1\noperation='+request['operationId']+'\noutcome='+hashlib.sha256(result).hexdigest()+'\n').encode()
  with (directory/'verified').open('xb')as f:f.write(marker);f.flush();os.fsync(f.fileno())
  (directory/'verified').chmod(0o600)
 parent.check()
''').encode()

def private_worker(mode):
    prepare=load('guided_preparation_fixture','tests/test_company_preparation_entry_native.py')
    quota=load('guided_quota_fixture','tests/test_company_quota_entry_native.py')
    prep=prepare.worker('stop-after-execute'if mode=='preparation-failure'else'success')
    private=quota.worker('identity-verifier-failure'if mode=='private-failure'else'success')
    commands=('configuration-action','configure-foundation','verify-configuration','repository-action','seed-repository','verify-repository','runtime-pair-action','initialize-runtime-pair','verify-runtime-pair')
    result='import sys\nif sys.argv[1] in '+repr(commands)+':\n exec('+repr(prep)+')\nelse:\n exec('+repr(private)+')\n'
    if mode=='request-changed-between':
        result+="if sys.argv[1]=='verify-runtime-pair':\n from pathlib import Path\n q=Path(sys.argv[sys.argv.index('--request')+1]);q.write_bytes(q.read_bytes().replace(b'full-installation',b'changed-installation'))\n"
    return result.encode()

def request(operation,mode):
    return dict(schemaVersion=1,mode=mode,operationId=operation,releaseSha256=('a'if mode=='foundation-only'else'b')*64,
        bundleRoot='/opt/autosoft-company/incoming/'+('foundation'if mode=='foundation-only'else'full')+'/company-release',
        sourceRoot='/opt/autosoft-company/incoming/'+('foundation'if mode=='foundation-only'else'full'),
        keyPath='/opt/autosoft-company/bootstrap/company.pem',dataDir='/srv/guided-data',backingFile='/var/lib/guided.luks',
        capacityGiB=32,runscVersion='20261108.0',runscSha512='c'*128)

def fixture(mode,case):
    case=Path(case)
    assert sys.platform=='linux'and os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])and case.resolve()==case
    for name in('etc','opt'):
        child=case/name;child.mkdir(mode=0o700)
        subprocess.run(['/usr/bin/mount','--bind',str(child),'/'+name],check=True,timeout=10)
    base=Path('/opt/autosoft-company');base.mkdir(mode=0o700)
    package=base/'bootstrap';package.mkdir(mode=0o700)
    for name in('requests','evidence'):(base/name).mkdir(mode=0o700)
    operation='d'*32;foundation=base/'requests'/(operation+'-foundation.json');full=base/'requests'/(operation+'.json')
    for target,kind in((foundation,'foundation-only'),(full,'full-installation')):
        value=request(operation,kind)
        if mode=='request-mismatch'and target==full:value['dataDir']='/srv/different'
        raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        if mode=='noncanonical-request'and target==full:raw=raw.replace(b'"schemaVersion":1',b'"schemaVersion":1,"schemaVersion":1')
        target.write_bytes(raw);target.chmod(0o600)
    B=load('guided_fixture_builder','deploy/installer/build-guided-private-package.py')
    N=load('guided_fixture_native_builder','deploy/installer/build-native-retention-package.py')
    foundation_raw=foundation_worker(mode);native_raw=private_worker(mode)
    lock=(ROOT/'scripts/install-lock.sh').read_bytes()
    entry=(ROOT/'deploy/installer/company-install.sh').read_bytes().replace(b'# @EMBED_INSTALL_LOCK@',lock)
    entry=entry.replace(b'@WORKER_SHA256@',hashlib.sha256(foundation_raw).hexdigest().encode()).replace(b'@HOST_CATALOGS_AVAILABLE@',b'true').replace(b'@HOST_CATALOG_FAMILY@',b'vendor-v1')
    records={'company-install.sh':entry,'company_install.py':foundation_raw,'company-native-retention.py':native_raw,
        'company-prepare.sh':N.assemble_entry(ROOT,native_raw,reader=lambda p,n:p.read_bytes(),preparation=True),
        'company-private-quota.sh':N.assemble_entry(ROOT,native_raw,reader=lambda p,n:p.read_bytes(),quota=True),
        'installation-status.py':(ROOT/'scripts/installation-status.py').read_bytes()}
    records['company-guided-private.sh']=B.entry(ROOT,records,reader=lambda p,n:p.read_bytes())
    for name,raw in records.items():(package/name).write_bytes(raw);(package/name).chmod(0o400)
    if mode in('changed-worker','changed-entry'):
        target=package/('company-native-retention.py'if mode=='changed-worker'else'company-private-quota.sh')
        target.write_bytes(target.read_bytes()+b'\n')
    if mode=='existing-guided':
        prior=base/('guided-'+operation+'.intent');prior.write_bytes(b'preserved partial intent\n');prior.chmod(0o600)
    if mode=='prior-unfinished-session':
        digest=hashlib.sha256(foundation.read_bytes()).hexdigest()
        subprocess.run(['/bin/bash','--noprofile','--norc','-c',
            'source "$1"; install_lock_initialize /etc/autosoft-install-admission; install_lock_acquire /etc/autosoft-install-admission "$2" 30; install_lock_release',
            'fixture',str(ROOT/'scripts/install-lock.sh'),digest],env=ENV,check=True,timeout=30)
    def invoke(flag):return subprocess.run(['/bin/bash','--noprofile','--norc',str(package/'company-guided-private.sh'),flag,str(foundation),str(full)],env=ENV,stdin=subprocess.DEVNULL,capture_output=True,timeout=210)
    def snapshot():
        return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()for root in(case/'etc',case/'opt')for p in root.rglob('*')if p.is_file()}
    flag='--full-installation'if mode=='unsupported-full'else'--install-private'
    first=invoke(flag)
    before=snapshot();second=invoke(flag);after=snapshot()
    status_before=snapshot();status=invoke('--private-status');status_after=snapshot()
    admission=Path('/etc/autosoft-install-admission');session_dir=admission/'sessions'
    sessions=list(session_dir.iterdir())if session_dir.exists()else[]
    evidence=base/'evidence'/operation
    executions=[json.loads(p.read_bytes())for p in evidence.rglob('executed.json')]if evidence.exists()else[]
    report=dict(mode=mode,exit=first.returncode,stdout=first.stdout.decode(),stderr=first.stderr.decode(),
        retryExit=second.returncode,retryUnchanged=before==after,statusExit=status.returncode,statusUnchanged=status_before==status_after,
        sessions=len(sessions),confirmed=len(list(admission.rglob('*.confirmed'))),complete=len(list(admission.rglob('complete'))),
        stages=sorted(p.parent.name for p in evidence.rglob('executed.json'))if evidence.exists()else[],
        effectSessions=sorted({r['session']for r in executions}),foundationExists=(evidence/'result.json').exists(),statusExecuted=(base/'status-executed').exists())
    (case/'report.json').write_text(json.dumps(report,indent=2)+'\n')

@unittest.skipUnless(sys.platform=='linux'and getattr(os,'geteuid',lambda:-1)()==0,'Linux root private namespaces required')
class NativeGuided(unittest.TestCase):
    def case(self,mode):
        root=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);st=root.lstat()
        self.assertTrue(root.resolve()==root and str(root).startswith('/srv/')and st.st_uid==st.st_gid==0 and st.st_mode&0o777==0o700)
        case=root/uuid.uuid4().hex;case.mkdir(mode=0o700)
        done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],capture_output=True,timeout=660)
        self.assertEqual(done.returncode,0,done.stderr.decode());r=json.loads((case/'report.json').read_bytes())
        self.assertNotEqual(r['retryExit'],0);self.assertTrue(r['retryUnchanged']);self.assertTrue(r['statusUnchanged']);return r
    def test_fresh_three_original_children_finish_eleven_confirmations_without_nested_lock(self):
        r=self.case('success');self.assertEqual(r['exit'],0,r['stderr']);self.assertEqual((r['sessions'],r['confirmed'],r['complete']),(3,11,3))
        self.assertEqual(len(r['stages']),10);self.assertEqual(len(r['effectSessions']),2);self.assertEqual(r['statusExit'],0)
        self.assertIn('not a completed platform installation',r['stdout'])
    def test_foundation_failure_never_starts_preparation(self):
        r=self.case('foundation-failure');self.assertNotEqual(r['exit'],0);self.assertEqual((r['sessions'],r['confirmed'],r['complete']),(1,0,0));self.assertEqual(r['stages'],[])
        self.assertIn('automatic foundation replay is unavailable',r['stderr'])
    def test_interrupted_preparation_reports_original_exact_recovery_without_replay(self):
        r=self.case('preparation-failure');self.assertNotEqual(r['exit'],0);self.assertEqual((r['sessions'],r['confirmed'],r['complete']),(2,1,1))
        self.assertEqual(r['stages'],['company-configuration']);self.assertIn('company-prepare.sh --recover-preparation /opt/autosoft-company/requests/'+'d'*32+'.json s-',r['stderr'])
    def test_private_identity_verification_failure_never_starts_quota(self):
        r=self.case('private-failure');self.assertNotEqual(r['exit'],0);self.assertEqual((r['sessions'],r['confirmed'],r['complete']),(3,9,2))
        self.assertNotIn('company-private-quota',r['stages']);self.assertIn('--recover-private-quota',r['stderr'])
    def test_request_changed_after_preparation_cannot_start_private_phase(self):
        r=self.case('request-changed-between');self.assertNotEqual(r['exit'],0);self.assertEqual((r['sessions'],r['confirmed'],r['complete']),(2,4,2))
        self.assertIn('guided_full_request_changed',r['stderr'])
    def test_mismatched_request_refuses_before_any_child(self):self.assertEqual(self.case('request-mismatch')['sessions'],0)
    def test_noncanonical_request_refuses_before_any_child(self):self.assertEqual(self.case('noncanonical-request')['sessions'],0)
    def test_changed_worker_refuses_before_any_child(self):self.assertEqual(self.case('changed-worker')['sessions'],0)
    def test_changed_entry_refuses_before_any_child(self):self.assertEqual(self.case('changed-entry')['sessions'],0)
    def test_status_changed_by_failed_child_is_never_executed_as_recovery_guidance(self):
        r=self.case('status-changed-on-failure');self.assertNotEqual(r['exit'],0);self.assertEqual(r['sessions'],1)
        self.assertFalse(r['statusExecuted']);self.assertNotEqual(r['statusExit'],0);self.assertEqual(r['stages'],[])
    def test_retained_guided_intent_is_preserved_without_replay(self):self.assertEqual(self.case('existing-guided')['sessions'],0)
    def test_existing_unfinished_admission_is_reported_before_any_child(self):
        r=self.case('prior-unfinished-session');self.assertEqual((r['sessions'],r['confirmed'],r['complete']),(1,0,0))
        self.assertFalse(r['foundationExists']);self.assertIn('automatic foundation replay is unavailable',r['stdout'])
        self.assertIn('guided_existing_work_preserved_no_replay',r['stderr'])
    def test_full_installation_mode_stays_refused_without_child(self):self.assertEqual(self.case('unsupported-full')['sessions'],0)

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
