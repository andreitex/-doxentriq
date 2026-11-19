"""Native files/locks with synthetic storage/parent evidence, never VM acceptance.

Each case owns a fresh root0700 directory beneath the explicit /srv test root.
The pair fixture additionally uses a private mount namespace and a build tmpfs.
It creates no mapper, host service or actual platform admission namespace.
"""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value


R=load('pair_native_original','scripts/runtime_pair_init.py')
W=load('pair_native_worker','deploy/installer/company_runtime_pair_worker.py')


def fresh_root():
    base=Path(os.environ['DOXENTRIQ_PAIR_TEST_ROOT'])
    assert str(base).startswith('/srv/') and base.resolve()==base
    info=base.lstat();assert info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700
    result=base/uuid.uuid4().hex;result.mkdir(mode=0o700);return result


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class BackingPolicyNativeTests(unittest.TestCase):
    def setUp(self):
        self.root=fresh_root();self.files=R.NativeFiles();self.files.require_root()
        self.backing=self.root/'ciphertext';self.key=self.root/'key';self.config=self.root/'config';self.receipt=self.root/'receipt'
        for path in (self.backing,self.key,self.config,self.receipt):path.write_bytes(b'synthetic-test-only');path.chmod(0o600)
        self.records={self.backing:None,self.key:None,self.config:1024,self.receipt:1024}
        self.descriptors=set(os.listdir('/proc/self/fd'))
    def tearDown(self):self.assertEqual(set(os.listdir('/proc/self/fd')),self.descriptors)
    def held(self):return R.S._controls(self.files,{self.root:(0,0,{0o700})},self.records,backing_file=self.backing)
    def test_backing_bytes_can_change_without_resizing_or_replacing(self):
        before=self.backing.stat()
        with self.held():
            fd=os.open(self.backing,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:os.pwrite(fd,b'X',0);os.fsync(fd)
            finally:os.close(fd)
            # Some kernels coalesce rapid write timestamps into one clock tick.
            # Make the metadata transition deterministic inside this fixture.
            os.utime(self.backing,ns=(before.st_atime_ns,before.st_mtime_ns+1000000))
        after=self.backing.stat()
        self.assertEqual(R.C.identity(before)[:7],R.C.identity(after)[:7])
        self.assertNotEqual(R.C.identity(before)[7:],R.C.identity(after)[7:])
    def test_key_configuration_and_receipt_timestamps_remain_strict(self):
        for path in (self.key,self.config,self.receipt):
            with self.subTest(path=path.name),self.assertRaises(ValueError):
                with self.held():
                    before=path.stat();os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns+1000000))
    def test_backing_resize_is_refused(self):
        with self.assertRaises(ValueError):
            with self.held():
                with self.backing.open('ab') as f:f.write(b'x');f.flush();os.fsync(f.fileno())
    def test_backing_replacement_is_refused(self):
        with self.assertRaises(ValueError):
            with self.held():
                raw=self.backing.read_bytes();self.backing.rename(self.root/'old-ciphertext');self.backing.write_bytes(raw);self.backing.chmod(0o600)
    def test_backing_mode_change_is_refused(self):
        with self.assertRaises(ValueError):
            with self.held():self.backing.chmod(0o400)


class SyntheticParent(R.ParentStageAuthority):
    """Only this private component fixture; no original-parent qualification."""
    @contextmanager
    def hold(self,request):
        self.request=dict(request)
        self.evidence=dict(scope='INSTALLER_PARENT_STAGE_ONLY',stage=R.STAGE,
            installationId=request['installationId'],requestSha256=R.C.digest(request),
            parentSessionId='s-Abc123Def456',parentIntentSha256='a'*64,nativeAuthorized=False)
        yield dict(self.evidence)
    def check(self,request,evidence):assert request==self.request and evidence==self.evidence


def pair_fixture(root):
    root=Path(root);assert str(root).startswith('/srv/') and root.resolve()==root
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    os.umask(0o077)
    data,host,install=root/'data',root/'host',root/'company-source'
    for path in (data,host,install,data/'config',data/'quota',data/'runtime',data/'runtime/builds'):path.mkdir(mode=0o700)
    builds=data/'runtime/builds'
    subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=2g,uid=10001,gid=10001,mode=0700,nosuid,nodev',
        'doxentriq-pair-builds-fixture',str(builds)],check=True,timeout=5)
    def fixed_findmnt(args):
        assert args==['/usr/bin/findmnt','-n','-o','TARGET,FSTYPE,OPTIONS,SIZE','--bytes','--target',str(builds)]
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=5,env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'))
        assert result.returncode==0 and len(result.stdout)<32768 and not result.stderr
        return result.stdout.decode('ascii')
    files=R.NativeFiles();files.require_root()
    build_mount=lambda path:R.S.L.builds_proof(path,command=fixed_findmnt)
    R.S.L.prepare(data,files=files,build_mount=build_mount)
    identifier='64a2a5f8-04b9-43b5-9807-122d866db1f1'
    backing=root/'synthetic-backing';backing.touch(mode=0o600)
    with backing.open('r+b') as f:f.truncate(32*1024**3)
    key=host/'storage.key';key.write_bytes(b'synthetic-not-an-unlock-key');key.chmod(0o600)
    intent=dict(schemaVersion=1,scope=R.S.I.SCOPE,installation_id=identifier,
        directory=R.C.directory_binding(files.protected(host,directory=True)),
        proposal=dict(data_dir=str(data),install_root=str(install),storage_file=str(backing),capacity_gib=32))
    final={k:intent['proposal'][k] for k in ('data_dir','install_root','storage_file')};final['installation_id']=identifier
    receipt=dict(final,creation_stage='new-luks-created',luks_uuid='45fb163d-e8ec-452b-aec0-ffdc391be9fa')
    for path,value in ((host/R.S.I.INTENT,intent),(host/'installation.json',final),
        (host/'installation.storage-receipt.json',receipt),(data/'config/installation.json',dict(installation_id=identifier))):
        files.write(path,value)
    source='synthetic-not-encrypted-storage'
    def layout(data,files):return R.S.L.verify(data,files=files,build_mount=build_mount)
    def mount(data,receipt,command):return dict(source=source,fixtureOnly=True)
    def no_command(args):raise AssertionError('unexpected fixture command')
    inputs=dict(host_directory=host,files=files,command=no_command,mount=mount,layout=layout,
        quota_mount=lambda data,command:source,gate_factory=R.C.Gate,allocation_factory=R.A.Allocation,
        read_state=R.Q.load_state,write_state=R.Q.save_state,clock=time.monotonic,timeout=50)
    before=set(os.listdir('/proc/self/fd'))
    result=R.initialize(data,install,authority=SyntheticParent(),**inputs)
    assert result['nativeAuthorized'] is False and result['status']=='effects-confirmed'
    measured,digest=W.inspect_completed(R,data,install,authority=SyntheticParent(),inputs=inputs)
    assert measured==result and len(digest)==64 and set(os.listdir('/proc/self/fd'))==before
    assert (data/'quota/projects.json').read_bytes()==R.EMPTY_BYTES
    existing={p.relative_to(data).as_posix():p.read_bytes() for p in data.rglob('*') if p.is_file()}
    try:R.initialize(data,install,authority=SyntheticParent(),**inputs)
    except ValueError:pass
    else:raise AssertionError('fresh rerun was adopted')
    assert existing=={p.relative_to(data).as_posix():p.read_bytes() for p in data.rglob('*') if p.is_file()}
    assert set(os.listdir('/proc/self/fd'))==before
    print(json.dumps(dict(nativeFilesAndLocks=True,syntheticParentAndStorage=True,
        signedStageQualified=False,encryptedStorageQualified=False,rerunRefused=True)))


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class PairNativeTests(unittest.TestCase):
    def test_real_pair_files_locks_and_readonly_confirmation(self):
        root=fresh_root()
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,
            '--pair-fixture',str(root)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        report=json.loads(result.stdout);self.assertTrue(report['nativeFilesAndLocks']);self.assertFalse(report['signedStageQualified'])


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--pair-fixture':pair_fixture(sys.argv[2])
    else:unittest.main(verbosity=2)
