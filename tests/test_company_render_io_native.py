"""Native filesystem fixtures, synthetic crypto/container commands only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import unittest
import uuid
from datetime import datetime,timezone
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
N=load('render_io','deploy/installer/company_render_io.py')
B=load('render_bootstrap','scripts/bootstrap.py')
C=load('render_commands','deploy/installer/company_render_commands.py')
V=load('render_verify','deploy/installer/company_render_verify.py')


class SyntheticCommands:
    DEVNULL=-3
    def __init__(self,io,*,missing=False):self.io=io;self.missing=missing;self.calls=[]
    def preflight(self):
        if self.missing:raise ValueError('missing local caddy image')
    def close(self):pass
    def verify_command(self,args):self.run(['openssl',*args[1:]],check=True)
    def verify_bcrypt(self):self.io.check()
    def socket_stat(self):return SimpleNamespace(st_gid=991)
    def run(self,args,**kw):
        self.calls.append(list(args))
        if args[0]=='htpasswd':return SimpleNamespace(returncode=0,stdout='platform:$2b$12$'+'a'*53+'\n',stderr='')
        assert tuple(args) in C.grammar(self.io)
        names=[]
        for flag in ('-keyout','-out'):
            if flag in args:
                path=args[args.index(flag)+1];name=path[len(self.io.root)+1:];fd=self.io.command_output(name)
                os.write(fd,('-----BEGIN SYNTHETIC FIXTURE-----\n'+name+'\n-----END SYNTHETIC FIXTURE-----\n').encode());names.append(name)
        if names:self.io.finish_command(names,True)
        text='CA:TRUE Certificate Sign' if '-ext' in args else '-----BEGIN PUBLIC KEY-----\n'+'A'*80+'\n-----END PUBLIC KEY-----\n' if '-pubout' in args or '-pubkey' in args else ''
        return SimpleNamespace(returncode=0,stdout=text,stderr='')
    def check_output(self,args,*,text):
        self.calls.append(list(args));return json.dumps({'apps':{'http':{'servers':{'srv0':{'routes':[{'handle':[{'handler':'static_response'}]}]}}}}})


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux root filesystem fixture required')
class Native(unittest.TestCase):
    def setUp(self):
        self.parent=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        info=self.parent.lstat()
        assert self.parent.is_absolute() and self.parent.resolve()==self.parent
        assert info.st_uid==info.st_gid==0 and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700
        self.base=self.parent/uuid.uuid4().hex;self.base.mkdir(mode=0o700)
        self.cfg=dict(certificate_mode='selfsigned',sso='none',admin_origin='https://admin.fixture.internal',
            apps_base_url='https://apps.fixture.internal',auth_origin='https://auth.apps.fixture.internal',
            owner_subject=str(uuid.uuid4()),job_budget_usd='2',monthly_budget_usd='30')
        self.spec=N.plan(self.cfg)
        for name in sorted(self.spec['directories']-set(self.spec['freshDirectories'])-{''},key=lambda n:(n.count('/'),n)):
            (self.base/name).mkdir(mode=0o700)
        image='fixture@sha256:'+'a'*64
        images={name:image for name in ('caddy','mysql','redis','rabbitmq','registry','dependency_proxy')}
        manifest=dict(schemaVersion=1,templates={'node':dict(toolchainImage=image,runtimeImage='registry:5000/base/node@sha256:'+'a'*64)},
            scannerImage=image,serviceImages={name:image for name in ('mysql','redis','rabbitmq','registry','dependency-proxy')},
            registry='registry:5000',dependencyProxy='http://dependency-proxy:3128',allowedPackageHosts=['registry.npmjs.org'])
        catalog=dict(schemaVersion=1,pricesVerifiedAt=datetime.now(timezone.utc).isoformat(),models=[dict(qualified=True,tier='strong')])
        values={'config/installation.json':json.dumps(self.cfg),'config/images.lock.json':json.dumps(images),
            'config/runtime-manifest.json':json.dumps(manifest),'config/approved-mirrors.json':'[]','config/models.json':json.dumps(catalog),
            'secrets/platform/openai-key':'synthetic-not-a-credential','secrets/platform/anthropic-key':'','secrets/dns.env':'\n'}
        for name,value in values.items():
            p=self.base/name;p.write_text(value);p.chmod(0o600 if name.startswith('secrets/') else 0o644)
        self.source={name:(ROOT/name).read_bytes() for name in ['deploy/config/'+n for n in N.TEMPLATES]+['scripts/keycloak-start.sh']}
        self.handles=[];self.checks=0
    def tearDown(self):
        for value in self.handles:
            if value.files or value.dirs:value.close(check=False)
        assert self.base.parent==self.parent and self.base.name.isalnum();shutil.rmtree(self.base)
    def authority(self):self.checks+=1
    def open(self,**kw):
        value=N.RenderIO(self.base,'/authenticated/source',self.source,self.cfg,check_authority=self.authority,
            process_factory=kw.pop('process_factory',SyntheticCommands),**kw)
        self.handles.append(value);return value
    def render(self,value):
        B.render(value.data,value.source,render_io=value,
            verify_layout=lambda _:dict(scope='RUNTIME_PLACEMENT_ONLY',status='verified',changed=False,backupReady=False))
    def test_original_renderer_complete_and_independent_manifest(self):
        value=self.open();self.render(value);manifest=value.manifest();value.close()
        self.assertGreater(len(manifest['files']),100)
        other=self.open(readonly=True,expected=manifest);self.assertEqual(other.manifest(),manifest);other.close()
        self.assertGreater(self.checks,100)
    def test_missing_image_refuses_before_outputs(self):
        before=set(self.base.rglob('*'))
        with self.assertRaisesRegex(ValueError,'missing local'):self.open(process_factory=lambda io:SyntheticCommands(io,missing=True))
        self.assertEqual(before,set(self.base.rglob('*')))
    def test_existing_output_preserved(self):
        p=self.base/'tls/ca.key';p.write_bytes(b'preserve');p.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'already exists'):self.open()
        self.assertEqual(p.read_bytes(),b'preserve')
    def test_symlink_and_hardlink_inputs_refused(self):
        p=self.base/'config/models.json';p.unlink();p.symlink_to(self.base/'config/images.lock.json')
        with self.assertRaises((ValueError,OSError)):self.open()
        p.unlink();os.link(self.base/'config/images.lock.json',p)
        with self.assertRaises(ValueError):self.open()
    def test_unknown_path_and_traversal_refused(self):
        value=self.open()
        with self.assertRaises(ValueError):value.write(value.data/'config/unexpected','x')
        with self.assertRaises(ValueError):value.data/'../outside'
        self.assertFalse((self.base/'config/unexpected').exists())
    def test_directory_drift_before_next_write_refused(self):
        value=self.open();(self.base/'config/foreign').write_text('foreign')
        with self.assertRaises(ValueError):value.write(value.data/'config/Caddyfile','x')
        self.assertFalse((self.base/'config/Caddyfile').exists())
    def test_same_transaction_rewrite_only_two_declared_files(self):
        value=self.open();p=value.data/'config/Caddyfile';value.write(p,'first')
        with self.assertRaises(ValueError):value.write(p,'second')
        self.assertEqual((self.base/'config/Caddyfile').read_text(),'first')
    def test_expired_authority_before_write_refused(self):
        value=self.open();value.deadline=0
        with self.assertRaises(ValueError):value.write(value.data/'config/Caddyfile','x')
        self.assertFalse((self.base/'config/Caddyfile').exists())
    def test_readonly_verifier_rejects_content_and_permission_changes(self):
        value=self.open();self.render(value);manifest=value.manifest();value.close()
        p=self.base/'config/caddy.json';p.write_text('{}');p.chmod(0o666)
        with self.assertRaises(ValueError):self.open(readonly=True,expected=manifest)
    def test_partial_command_preserved_and_poisoned(self):
        value=self.open();fd=value.command_output('tls/ca.key');os.write(fd,b'partial')
        with self.assertRaises(ValueError):value.finish_command(['tls/ca.key'],False);value.check()
        self.assertEqual((self.base/'tls/ca.key').read_bytes(),b'partial')
    def test_fifo_input_refused_without_blocking(self):
        p=self.base/'config/models.json';p.unlink();os.mkfifo(p,0o600)
        before=len(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
    def test_wrong_directory_owner_does_not_leak_descriptor(self):
        p=self.base/'tls';os.chown(p,999,999)
        before=len(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
    def test_unsafe_intermediate_ancestor_does_not_leak_descriptor(self):
        inner=self.base/'nested';inner.mkdir(mode=0o700);os.chown(self.base,999,999)
        before=len(os.listdir('/proc/self/fd'))
        try:
            with self.assertRaises(ValueError):
                N.RenderIO(inner,'/authenticated/source',self.source,self.cfg,
                    check_authority=self.authority,process_factory=SyntheticCommands)
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        finally:os.chown(self.base,0,0)
    def test_full_readonly_relationship_verification(self):
        value=self.open();self.render(value);manifest=value.manifest();value.close()
        other=self.open(readonly=True,expected=manifest)
        result=V.verify(B,other,source_verifier=lambda data,cfg:None)
        self.assertEqual(result['status'],'independently-verified');other.close()
    def test_existing_model_config_metadata_cannot_change(self):
        value=self.open();self.render(value)
        p=self.base/'config/models.json';os.chmod(p,0o600)
        with self.assertRaises(ValueError):value.manifest()
    def test_unplanned_owner_transition_refused(self):
        value=self.open()
        with self.assertRaises(ValueError):value.chown(value.data/'secrets/platform/openai-key',999,999)
        self.assertEqual((self.base/'secrets/platform/openai-key').stat().st_uid,0)


if __name__=='__main__':unittest.main(verbosity=2)
