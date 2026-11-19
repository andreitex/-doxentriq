"""Original configuration observer with real Linux files in a private namespace.

Host command/mount responses and signed-source acquisition are modeled. Exact
host identity, placement, secret/catalog and retention readers remain original.
No host command, backing file, encrypted volume or platform service is created.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m


def fixture(mode,case):
    case=Path(case);assert os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])and case.resolve()==case
    (case/'etc').mkdir(mode=0o700)
    subprocess.run(['/usr/bin/mount','--bind',str(case/'etc'),'/etc'],check=True,timeout=10)
    Q=load('configuration_observer_original','deploy/installer/company_configuration.py')
    H=load('configuration_observer_handoff','deploy/installer/company_preparation_handoff.py')
    S=load('configuration_observer_startup','scripts/startup_binding.py');L=S.L;files=L.NativeFiles()
    B=load('configuration_observer_bootstrap','scripts/bootstrap.py')
    F=load('configuration_observer_foundation','deploy/installer/company_install.py')
    data=case/'data';data.mkdir(mode=0o700);operation='c'*32
    root=data/'company/host-releases'/('install-'+operation);root.mkdir(mode=0o700,parents=True)
    for name in ('company','company/host-releases'):(data/name).chmod(0o700)
    for name in ('config','quota','runtime','runtime/builds','company/platform-releases','company/source-releases'):(data/name).mkdir(mode=0o700)
    os.chown(data/'runtime/builds',10001,10001)
    host=Path('/etc/autosoft');host.mkdir(mode=0o700)
    backing=case/'backing.luks';assert not backing.exists()
    intent=S.I.create_intent(host,str(data),str(root),str(backing),32,files=files,
        uuid_factory=lambda:uuid.UUID('12345678-1234-4234-8234-123456789012'))
    final=dict(data_dir=str(data),install_root=str(root),storage_file=str(backing),installation_id=intent['installation_id'])
    files.write(host/'installation.json',final)
    files.write(host/'installation.storage-receipt.json',dict(final,creation_stage='new-luks-created',luks_uuid='87654321-4321-4321-8321-210987654321'))
    mount=dict(target=str(data/'runtime/builds'),filesystem='tmpfs',maximumBytes=2147483648,uid=10001,gid=10001,mode=0o700,nosuid=True,nodev=True)
    L.prepare(data,files=files,build_mount=lambda _:mount)
    # Preparation has already seeded a repository; configuration must not try
    # to impose its former empty-repository condition or rerun the wizard.
    (data/'runtime/repository/preserved-document').write_bytes(b'synthetic retained document')
    os.chown(data/'runtime/repository/preserved-document',10001,10001)
    config=dict(installation_id=intent['installation_id'],company_public_fingerprint='a'*64,
        sso='none',certificate_mode='selfsigned',notification_email='',company_registry='')
    files.write(data/'config/installation.json',config)
    captured={name:Q.canonical({'fixture':name})for name in Q.CONFIGS}
    for name,raw in captured.items():
        target=data/'config'/name;target.write_bytes(raw);target.chmod(0o600 if name=='approved-mirrors.json'else 0o644)
    for name in ('secrets',*('secrets/'+name for name in ('platform','mysql','keycloak','registry','runtime','packager','grafana','dns'))):
        (data/name).mkdir(mode=0o700)
    for name,raw,mode_bits in (('config/models.json',b'{}\n',0o644),('secrets/platform/openai-key',b'synthetic-only',0o600),
            ('secrets/platform/anthropic-key',b'',0o600),('secrets/dns.env',b'\n',0o600)):
        path=data/name;path.write_bytes(raw);path.chmod(mode_bits)
    request=dict(dataDir=str(data),operationId=operation,backingFile=str(backing),capacityGiB=32,releaseSha256='b'*64)
    held=SimpleNamespace(metadata={'signingKeyFingerprint':'a'*64},configs=captured)
    reads=[];checks=[];calls=[]
    def command(argv):
        calls.append(tuple(argv))
        if argv[0]=='/usr/bin/systemctl':
            value=dict(ActiveState='inactive',SubState='dead',MainPID='0',ControlPID='0',ControlGroup='',LoadState='loaded')
            if argv[-1].endswith('.timer'):
                for name in ('MainPID','ControlPID','ControlGroup'):value.pop(name)
            return ''.join(key+'='+val+'\n'for key,val in value.items())
        if argv==['/usr/bin/docker','ps','-aq','--no-trunc']:return ''
        assert argv==['/usr/bin/findmnt','-n','-o','TARGET,FSTYPE,OPTIONS,SIZE','--bytes','--target',str(data/'runtime/builds')]
        return str(data/'runtime/builds')+' tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=700 2147483648\n'
    def call(path,name,*args,**kwargs):
        assert(path,name)==(Q.LAYOUT,'verify');reads.append('original-layout-verify');return L.verify(*args,**kwargs)
    assembly=SimpleNamespace(modules={Q.BOOTSTRAP:B,Q.LAYOUT:L,Q.STARTUP:S},call=call)
    def snapshot():
        return {str(p):[hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns]
            for base in (data,host)for p in base.rglob('*')if p.is_file()}
    def observe():
        with patch.object(S,'encrypted_proof',lambda *_a,**_k:dict(scope='modeled-mounted-storage',target=str(data))):
            return H.configuration(dict(configuration=Q,foundation_worker=F),assembly,held,request,Q.canonical(request),'d'*64,
                command,'e'*64,lambda:checks.append('live-parent-source-check'))
    initial=observe()
    if mode=='secret-changed':(data/'secrets/platform/openai-key').write_bytes(b'changed synthetic-only')
    elif mode=='signed-catalog-changed':(data/'config/images.lock.json').write_bytes(b'changed catalog')
    elif mode=='layout-owner-changed':os.chown(data/'runtime/repository',0,0)
    elif mode=='retention-populated':(data/'company/platform-releases/unexpected').write_bytes(b'preserve')
    before=snapshot();error=None;frames=[];current=None
    try:current=observe()
    except ValueError as failure:
        error=type(failure).__name__;tb=failure.__traceback__
        while tb is not None:frames.append(tb.tb_frame.f_code.co_name);tb=tb.tb_next
    report=dict(mode=mode,unchanged=snapshot()==before,initial=initial,current=current,error=error,frames=frames,
        originalLayoutReads=len(reads),authorityChecks=len(checks),modeledCommandCount=len(calls),backingAbsent=not backing.exists())
    (case/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')


@unittest.skipUnless(sys.platform=='linux'and getattr(os,'geteuid',lambda:-1)()==0,'Linux root private namespace required')
class NativeConfigurationObserver(unittest.TestCase):
    def case(self,mode):
        root=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);info=root.lstat()
        self.assertTrue(root.resolve()==root and str(root).startswith('/srv/')and info.st_uid==info.st_gid==0 and info.st_mode&0o777==0o700)
        case=root/uuid.uuid4().hex;case.mkdir(mode=0o700)
        done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],capture_output=True,timeout=90)
        self.assertEqual(done.returncode,0,done.stderr.decode());r=json.loads((case/'report.json').read_bytes())
        self.assertTrue(r['unchanged']and r['backingAbsent']);self.assertGreaterEqual(r['authorityChecks'],3);return r
    def test_real_configuration_secret_layout_and_retention_readers_preserve_populated_repository(self):
        r=self.case('success');self.assertIsNone(r['error']);self.assertEqual(r['initial'],r['current']);self.assertEqual(r['originalLayoutReads'],2)
        self.assertFalse(r['current']['servicesStarted']or r['current']['fullInstallationCompleted'])
    def test_real_secret_change_cannot_match_previous_configuration_outcome(self):
        r=self.case('secret-changed');self.assertIsNone(r['error']);self.assertNotEqual(r['initial']['wizardOutputsSha256'],r['current']['wizardOutputsSha256'])
    def test_changed_signed_catalog_refuses_at_configuration_binding(self):
        r=self.case('signed-catalog-changed');self.assertIsNotNone(r['error']);self.assertIn('configuration',r['frames']);self.assertEqual(r['originalLayoutReads'],1)
    def test_actual_repository_owner_change_refuses_original_layout_reader(self):
        r=self.case('layout-owner-changed');self.assertIsNotNone(r['error']);self.assertIn('directory',r['frames']);self.assertEqual(r['originalLayoutReads'],2)
    def test_populated_retention_parent_refuses_without_deleting_its_file(self):
        r=self.case('retention-populated');self.assertIsNotNone(r['error']);self.assertIn('retention_parents',r['frames'])


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
