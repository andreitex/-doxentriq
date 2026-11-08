"""Real protected files; synthetic Docker only; no admission authority claimed."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import unittest
import uuid

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,(Path(__file__).resolve().parents[2]/'deploy/installer'/path.replace('original/','') if not path.startswith('test_') else HERE/path))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
E=load('split_evidence','company_identity_evidence.py')
I=load('split_io','company_identity_io.py')
M=load('split_commands','company_identity_commands.py')
R=load('split_render','original/company_render_commands.py')
S=load('split_operation','company_identity_split.py')
F=load('split_existing_fake','test_identity_commands.py')
C=M.identity_commands(R,E)

class Simulated(C):
    instances=[]
    mode=None
    after_result=None
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.calls=[];self.started=False;self.fail=self.mode
        self.instances.append(self)
    def _check(self):
        R.require(not self.failed);self.io.check();self._prior()
    def preflight(self):
        self.image_id='sha256:'+('9' if self.mode=='wrong-local-image' else '1')*64
        self.io.labels(False);self._check();self._infrastructure()
    def _docker(self,args,*,stdin=b'',timeout=30):
        self._check()
        result=F.Simulated._docker(self,args,stdin=stdin,timeout=timeout)
        if self.mode=='late-provision-change' and args[:2]==['container','create']:
            (self.prior.path/'004-provision-completed.json').write_bytes(b'changed during verification')
        if self.after_result is not None and args[:2]==['container','start']:
            self.after_result()
        return result


@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root files required')
class SplitTests(unittest.TestCase):
    def setUp(self):
        parent=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        for path in (parent,*parent.parents):
            value=path.lstat()
            self.assertTrue(stat.S_ISDIR(value.st_mode) and value.st_uid==value.st_gid==0 and not value.st_mode&0o022)
        self.data=parent/uuid.uuid4().hex;self.data.mkdir(mode=0o700)
        (self.data/'company').mkdir(mode=0o700)
        self.operation=uuid.uuid4().hex;self.verify_operation=uuid.uuid4().hex
        self.source=b'fixed synthetic identity helper';self.ca=b'fixed synthetic CA'
        self.expected=dict(operationId=self.operation,sourceSha256=E.sha(self.source),caSha256=E.sha(self.ca),
            image='platform@sha256:'+'c'*64,imageId='sha256:'+'1'*64,networkId='d'*64,keycloakId='e'*64)
        self.owner='11111111-1111-4111-8111-111111111111'
        self.payload=json.dumps(dict(action='verify-initial',ownerSubject=self.owner,bootstrapPassword='synthetic-protected-input')).encode()
        self.authorized=True
        Simulated.mode=None;Simulated.after_result=None;Simulated.instances=[]
        io=I.IdentityIO(self.data,self.operation,self.source,self.ca,check_authority=self.authority)
        commands=Simulated(io,self.operation,self.expected['image'],self.expected['networkId'],self.expected['keycloakId'],'sha256:'+'f'*64)
        try:
            commands.preflight();commands.run_phase('provision',b'{}')
        finally:
            commands.close();io.close()
        self.path=Path(io.root);self.before=self.inventory()
        Simulated.instances=[]

    def authority(self):
        E.require(self.authorized)

    def inventory(self):
        return {p.name:(E.identity(p.lstat()),p.read_bytes()) for p in self.path.iterdir()}

    def run_verification(self,**overrides):
        args=dict(data=self.data,expected=self.expected,verification_operation=self.verify_operation,
            source=self.source,ca=self.ca,payload=self.payload,check_authority=self.authority,
            io_module=I,evidence_module=E,commands_class=Simulated,keycloak_image_id='sha256:'+'f'*64)
        args.update(overrides);return S.verify_provisioned(**args)

    def test_separate_verification_reads_completed_provision_without_rewriting_it(self):
        baseline=len(os.listdir('/proc/self/fd'));result=self.run_verification()
        self.assertEqual(self.before,self.inventory())
        self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)
        self.assertEqual(result['scope'],'SEPARATE_INITIAL_IDENTITY_POLICY_READBACK')
        self.assertEqual(result['ownerSubject'],self.owner)
        self.assertTrue(result['configuredPolicyVerified'])
        for name in ('publicStartupAllowed','parentAuthorityEstablished','browserMfaQualified'):
            self.assertFalse(result[name])
        commands=Simulated.instances[-1]
        self.assertTrue(commands.io.closed);self.assertTrue(commands.prior.closed)
        created=[args for args,_,_ in commands.calls if args[:2]==['container','create']]
        self.assertEqual(len(created),1)
        self.assertIn('doxentriq-identity-'+self.verify_operation+'-verify',created[0])
        files=list(Path(commands.io.root).iterdir())
        self.assertEqual(len(files),7)
        self.assertTrue(all('provision-' not in p.name for p in files))
        self.assertNotIn(b'synthetic-protected-input',b''.join(p.read_bytes() for p in files))
        self.assertFalse(any('publish' in arg for args,_,_ in commands.calls for arg in args))

    def test_partial_provision_never_creates_verification_directory(self):
        (self.path/'005-provision-removed.json').unlink()
        with self.assertRaises(ValueError):self.run_verification()
        self.assertEqual(Simulated.instances,[])
        self.assertFalse((self.data/'company'/('identity-'+self.verify_operation)).exists())

    def test_wrong_expected_bindings_fail_before_verification_creation(self):
        for key,value in [('image','other@sha256:'+'c'*64),('networkId','9'*64),('keycloakId','9'*64)]:
            changed=dict(self.expected);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.run_verification(expected=changed)
        with self.assertRaises(ValueError):self.run_verification(source=b'changed helper')
        with self.assertRaises(ValueError):self.run_verification(ca=b'changed CA')
        self.assertFalse((self.data/'company'/('identity-'+self.verify_operation)).exists())

    def test_same_operation_and_duplicate_payload_fields_are_refused(self):
        with self.assertRaises(ValueError):self.run_verification(verification_operation=self.operation)
        with self.assertRaises(ValueError):self.run_verification(payload=b'{"action":"verify-initial","action":"provision"}')
        self.assertEqual(self.before,self.inventory())
        self.assertEqual(Simulated.instances,[])

    def test_wrong_locally_resolved_image_never_creates_container(self):
        Simulated.mode='wrong-local-image'
        with self.assertRaises(ValueError):self.run_verification()
        self.assertEqual(Simulated.instances[-1].calls,[])
        self.assertEqual(self.before,self.inventory())

    def test_prior_change_during_create_prevents_start_and_retains_uncertain_container(self):
        Simulated.mode='late-provision-change'
        baseline=len(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):self.run_verification()
        commands=Simulated.instances[-1]
        self.assertFalse(any(args[:2] in (['container','start'],['container','rm']) for args,_,_ in commands.calls))
        self.assertIsNotNone(commands.container)
        self.assertTrue(commands.io.closed and commands.prior.closed)
        self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)

    def test_unknown_start_is_retained_and_cannot_be_retried_or_adopted(self):
        Simulated.mode='start-unknown'
        with self.assertRaises(ValueError):self.run_verification()
        commands=Simulated.instances[-1]
        self.assertIsNotNone(commands.container)
        self.assertFalse(any(args[:2]==['container','rm'] for args,_,_ in commands.calls))
        self.assertTrue((Path(commands.io.root)/'003-verify-start-intent.json').exists())
        self.assertFalse((Path(commands.io.root)/'004-verify-completed.json').exists())
        before=list(commands.calls)
        with self.assertRaises(FileExistsError):self.run_verification()
        self.assertEqual(before,commands.calls)

    def test_completed_verification_cannot_be_silently_adopted(self):
        self.run_verification()
        with self.assertRaises(FileExistsError):self.run_verification()
        self.assertEqual(len(Simulated.instances),1)
        self.assertEqual(self.before,self.inventory())

    def test_authority_loss_after_helper_result_prevents_success(self):
        def lose_authority():self.authorized=False
        Simulated.after_result=staticmethod(lose_authority)
        baseline=len(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):self.run_verification()
        self.assertTrue(Simulated.instances[-1].io.closed)
        self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)

    def test_sibling_creation_does_not_accept_changed_predecessor(self):
        original=I.IdentityIO
        target=self.path/'ca.crt'
        class MutatingIO(original):
            def __init__(inner,*args,**kwargs):
                super().__init__(*args,**kwargs)
                target.write_bytes(b'changed CA')
        from types import SimpleNamespace
        with self.assertRaises(ValueError):self.run_verification(io_module=SimpleNamespace(IdentityIO=MutatingIO))
        self.assertEqual(Simulated.instances,[])



    def test_workspace_boundary_opens_exact_ancestor_reader_only_after_creation(self):
        station=load('split_exact_station','company_native_station.py')
        guard=self.data/'company/host-releases/fixed/guard.sh';guard.parent.mkdir(mode=0o700,parents=True)
        guard.write_bytes(b'fixed signed guard fixture');guard.chmod(0o400)
        observed=[]
        @contextmanager
        def host():
            self.assertTrue((self.data/'company'/('identity-'+self.verify_operation)).is_dir())
            with station.held_file(guard,1024) as (_,_,check):
                observed.append('opened-after-workspace');check();yield;check()
                observed.append('closed-after-helper')
        result=self.run_verification(workspace_context=host)
        self.assertTrue(result['configuredPolicyVerified'])
        self.assertEqual(observed,['opened-after-workspace','closed-after-helper'])

    def test_host_boundary_failure_before_helper_never_creates_container(self):
        @contextmanager
        def host():
            raise ValueError('synthetic host drift before helper');yield
        with self.assertRaises(ValueError):self.run_verification(workspace_context=host)
        self.assertEqual(Simulated.instances,[])
        self.assertEqual(self.before,self.inventory())

    def test_host_boundary_close_failure_prevents_success_after_helper_removal(self):
        @contextmanager
        def host():
            yield;raise ValueError('synthetic host drift after helper')
        with self.assertRaises(ValueError):self.run_verification(workspace_context=host)
        commands=Simulated.instances[-1]
        self.assertIsNone(commands.container);self.assertTrue(commands.io.closed)
        self.assertTrue(commands.prior.closed);self.assertEqual(self.before,self.inventory())

if __name__=='__main__':unittest.main(verbosity=2)
