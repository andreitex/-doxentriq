"""Actual held source/infrastructure/storage files around identity workspace creation.

Signatures, Docker, mount proof and journal admission are explicit synthetic
collaborators. Actual verifier issuance, file descriptors and invariant readers
run unchanged. This is not real signing, encrypted storage or installation.
"""
from contextlib import contextmanager, nullcontext
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
def load(name,path):
    s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s)
    sys.modules[name]=m;s.loader.exec_module(m);return m

def fixture(case,mode):
    case=Path(case);assert os.geteuid()==0 and case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    etc=case/'etc';etc.mkdir(mode=0o700)
    subprocess.run(['/usr/bin/mount','--bind',str(etc),'/etc'],check=True,timeout=10)
    T=load('identity_ancestry_infra','tests/test_company_infrastructure_composition_native.py')
    test=T.Composition();test.setUp();data=test.data
    S=load('identity_ancestry_startup','scripts/startup_binding.py')
    RW=load('identity_ancestry_invariant','deploy/installer/company_render_worker.py')
    N=load('identity_ancestry_station','deploy/installer/company_native_station.py')
    W=load('identity_ancestry_worker','deploy/installer/company_identity_worker.py')
    X=load('identity_ancestry_fake','tests/identity_components/test_identity_split.py')
    V=load('identity_ancestry_verifier','scripts/verify-release.py')
    P=load('identity_ancestry_parser','scripts/platform_source.py')
    F=load('identity_ancestry_schema_fixture','tests/test_company_release_schema4.py').Fixture(V,P)
    # Unlike the legacy fixture's portable metadata adapter, use actual protected
    # descriptors/UIDs/modes for every source input and every ancestor here.
    for name,gitmode in F.modes.items():(F.sources/name).chmod(0o755 if gitmode=='100755' else 0o644)
    company=data/'company';company.mkdir(mode=0o700)
    hostroot=company/'host-releases/fixed';hostroot.mkdir(mode=0o700,parents=True)
    guard=hostroot/'guard.sh';guard.write_bytes(b'fixed guard fixture');guard.chmod(0o400)
    host=Path('/etc/autosoft');host.mkdir(mode=0o700)
    backing=case/'ciphertext-fixture';backing.write_bytes(b'no actual encrypted volume');backing.chmod(0o600)
    records={host/'installation.intent.json':{},host/'installation.json':dict(storage_file=str(backing)),
        host/'installation.storage-receipt.json':{},host/'storage.key':None,data/'config/installation.json':{}}
    for path,value in records.items():
        path.write_bytes(b'synthetic key' if value is None else S.C.canonical(value));path.chmod(0o600)
    # These setup additions precede the initial infrastructure execution/manifest.
    manifest=test.args['manifest']
    for name in ('','config'):
        manifest['directories'][name]=dict(identity=list(test.I.identity((data/name).lstat())),children=sorted(p.name for p in (data/name).iterdir()))
    config=data/'config/installation.json'
    manifest['files']['config/installation.json']=dict(identity=list(test.I.identity(config.lstat())),sha256=test.I.sha(config.read_bytes()))
    component=test.execute()
    E=test.modules['infrastructure_evidence'].infrastructure_evidence(test.I,T.P)
    files=S.L.NativeFiles()
    @contextmanager
    def storage_context(*a,**kw):
        dirs={p:(0,0,{p.stat().st_mode&0o777}) for p in (data,company,hostroot,host,data/'config')}
        with S._controls(files,dirs,{**{p:32768 for p in records},backing:None},backing_file=backing):
            yield dict(installationId='fixture',mountSource='synthetic-mount-proof')
    # Journal locks and mount proof are intentionally synthetic; original
    # invariant_records and its native protected-file handles remain active.
    startup=SimpleNamespace(fresh_storage_context=storage_context,C=S.C)
    inputs=dict(host_directory=host,files=files,command=lambda *a:None,mount=None,layout=None,
        gate_factory=lambda _:SimpleNamespace(inspect_initialized=lambda *a,**k:nullcontext({})),
        allocation_factory=lambda _:SimpleNamespace(inspect_initialized=lambda *a,**k:nullcontext({})),read_state=lambda *a:None)
    modules=dict(configuration=load('identity_ancestry_configuration','deploy/installer/company_configuration.py'),
        identity_io=X.I,identity_evidence=X.E)
    observed=[]
    try:
        with V.authenticated_platform_source(F.bundle,F.public,F.fingerprint,expected_architecture='x86_64',
                source_root=F.sources,files=V.NativeFiles(),crypto=F.crypto) as held:
            with RW.invariant_records(startup,inputs,str(data),str(hostroot)) as (_,check_storage):
                def authority():V.require_platform_source(held);check_storage()
                with E(str(data),str(test.records),manifest,T.P.canonical(component),T.P.digest(component),
                        tool_binding=T.F.TOOLS,check_authority=authority) as retained:
                    assert not any(n=='company' or n.startswith('company/') for n in retained.inputs.nodes)
                    def all_checks():authority();retained.check()
                    @contextmanager
                    def host_boundary():
                        assert (company/('identity-'+W.operation_ids(modules['configuration'],dict(operationId='a'*32))[0])).is_dir()
                        with N.held_file(guard,1024) as (_,_,check_host):
                            all_checks();check_host();observed.append('host-open')
                            yield
                            all_checks();check_host();observed.append('host-close')
                    X.Simulated.mode=None;X.Simulated.instances=[];X.Simulated.after_result=None
                    if mode=='source-drift':
                        X.Simulated.after_result=staticmethod(lambda:(F.sources/'scripts/platform_source.py').write_bytes(b'changed'))
                    if mode=='storage-drift':X.Simulated.after_result=staticmethod(lambda:config.write_bytes(b'changed'))
                    args=dict(data=str(data),request=dict(operationId='a'*32),source=held.files['scripts/keycloak-provision.mjs'],
                        ca=retained.read('tls/ca.crt'),image='platform@sha256:'+'c'*64,component=component,binding={},authority=all_checks,
                        payload=b'{}',workspace_context=host_boundary)
                    with patch.object(W,'bound_commands',return_value=X.Simulated):result=W.provision_component(modules,**args)
                    assert result['recordsSha256'];all_checks()
        assert mode=='success' and observed==['host-open','host-close']
        report=dict(status='passed',helperCalls=len(X.Simulated.instances),scope='NATIVE_ANCESTRY_SYNTHETIC_AUTHORITY')
    except (ValueError,OSError):
        assert mode!='success'
        assert X.Simulated.instances and X.Simulated.instances[-1].io.closed
        report=dict(status='drift-refused',scope='NATIVE_ANCESTRY_SYNTHETIC_AUTHORITY')
    finally:test.tearDown()
    (case/'report.json').write_text(json.dumps(report)+'\n')

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root required')
class NativeAncestry(unittest.TestCase):
    def run_case(self,mode):
        case=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])/uuid.uuid4().hex;case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',str(case),mode],
            capture_output=True,timeout=180)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        return json.loads((case/'report.json').read_text())
    def test_actual_source_inputs_storage_records_and_infrastructure_remain_held(self):
        self.assertEqual(self.run_case('success')['status'],'passed')
    def test_source_change_during_helper_never_returns_success(self):
        self.assertEqual(self.run_case('source-drift')['status'],'drift-refused')
    def test_storage_change_during_helper_never_returns_success(self):
        self.assertEqual(self.run_case('storage-drift')['status'],'drift-refused')

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
