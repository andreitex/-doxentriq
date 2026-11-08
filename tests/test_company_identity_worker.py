"""Identity successor input/closure controls; no host authority or live effects."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',ROOT if (ROOT/'scripts/bootstrap.py').exists() else ROOT.parents[2]))
def load(name,relative):
    path=ROOT/relative
    if not path.exists():path=BASE/relative
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
# Exercise the actual worker exports and literal-True validator captured by
# the company producer. Only trust material and external effects are synthetic.
B=load('identity_package_test','deploy/installer/build-native-retention-package.py')
def read_source(path,limit):
    relative=path.relative_to(ROOT);selected=ROOT/relative
    return (selected if selected.exists() else BASE/relative).read_bytes()
from types import ModuleType
package=ModuleType('identity_packaged_contract')
exec(compile(B.assemble(ROOT,'a'*64,reader=read_source),'<identity test package>','exec'),package.__dict__)
def captured(name):
    import base64
    row=package.PACKAGE['programs'][name];raw=base64.b64decode(row['base64'],validate=True)
    assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
    value=ModuleType('identity_contract_'+name);exec(compile(raw,'<captured '+name+'>','exec'),value.__dict__)
    return value
W,I,P,Q=(captured(n) for n in ('identity_worker','infrastructure_worker','infrastructure_policy','configuration'))
CONFIG=dict(owner_subject='aaaaaaaa-bbbb-bbbb-bbbb-cccccccccccc',admin_origin='https://admin.example.invalid',sso='none')


class Bindings(unittest.TestCase):
    def test_actual_captured_validator_accepts_only_literal_true(self):
        Q.require(True)
        for value in (False,None,1,'yes',{'x'},__import__('re').fullmatch('x','x')):
            with self.subTest(type=type(value).__name__),self.assertRaises(ValueError):Q.require(value)
    def test_valid_provision_binding_passes_strict_captured_validator(self):
        request=dict(operationId='a'*32);source=b'helper';ca=b'ca';image='registry.example/platform@sha256:'+'b'*64
        component=dict(networkIds=dict(identity='c'*64),containerIds=dict(keycloak='d'*64))
        expected=dict(operationId=W.operation_ids(Q,request)[0],sourceSha256=Q.sha(source),caSha256=Q.sha(ca),
            image=image,imageId='sha256:'+'e'*64,networkId='c'*64,keycloakId='d'*64)
        args=dict(request=request,source=source,ca=ca,image=image,component=component)
        self.assertEqual(W.validate_provision(Q,dict(expected=expected,recordsSha256='f'*64),**args),expected)
        for value in (dict(expected=expected,recordsSha256='bad'),
                      dict(expected=dict(expected,imageId='bad'),recordsSha256='f'*64)):
            with self.assertRaises(ValueError):W.validate_provision(Q,value,**args)
    def test_current_infrastructure_inputs_pass_the_same_strict_validator(self):
        self.assertEqual(I.platform_value(Q,b'ID=rocky\nVERSION_ID="10.2"\n'),
            dict(osId='rocky',versionId='10.2',architecture='x86_64'))
        self.assertEqual(len(I.action(Q,b'{}','a'*64)),64)

    def test_original_request_requires_source_bundle_and_key_outside_data_company(self):
        R=load('identity_request_paths','deploy/installer/company_full_cli_request.py')
        value=dict(schemaVersion=1,mode='full-installation',operationId='a'*32,releaseSha256='b'*64,
            sourceRoot='/opt/autosoft-company/incoming/source',bundleRoot='/opt/autosoft-company/incoming/bundle',
            keyPath='/opt/autosoft-company/bootstrap/public.pem',dataDir='/srv/customer-data',backingFile='/srv/data-volume.luks',
            capacityGiB=32,runscVersion='20261101.0',runscSha512='c'*128)
        raw=Q.canonical(value);self.assertEqual(R.validate_request(raw,request_sha256=Q.sha(raw)),value)
        for name in ('sourceRoot','bundleRoot','keyPath'):
            wrong=dict(value,**{name:'/srv/customer-data/company/retained'+('.pem' if name=='keyPath' else '')});raw=Q.canonical(wrong)
            with self.assertRaises(ValueError):R.validate_request(raw,request_sha256=Q.sha(raw))
    def test_schema2_tool_provenance_remains_distinct_and_complete(self):
        b=dict(scope='COMPANY_ENGINE_TOOL_BINDING_V2_ONLY',catalogSha256='a'*64,profileSha256='b'*64,
            qualificationReportSha256='c'*64,sourceManifestSha256='d'*64,distributionMetadataSha256='e'*64,
            platform=dict(osId='rocky',versionId='10.2',architecture='x86_64'),
            installedToolsVerified=False,qualificationEvidenceVerified=False,parentAuthorityEstablished=False)
        result=P.tool_context(b);self.assertEqual(result['scope'],b['scope'])
        self.assertEqual(result['sourceManifestSha256'],'d'*64);self.assertEqual(result['distributionMetadataSha256'],'e'*64)
        for changed in (dict(b,sourceManifestSha256='bad'),dict(b,parentAuthorityEstablished=True),dict(b,platform=dict(b['platform'],osId='debian'))):
            with self.assertRaises(ValueError):P.tool_context(changed)
    def test_action_and_distinct_operations_bind_request_and_worker(self):
        self.assertEqual(len({W.action(Q,r,h) for r,h in ((b'one','a'*64),(b'two','a'*64),(b'one','b'*64))}),3)
        ids=W.operation_ids(Q,{'operationId':'a'*32});self.assertNotEqual(*ids)
        self.assertNotEqual(ids,W.operation_ids(Q,{'operationId':'b'*32}))
    def test_payloads_are_bounded_and_only_use_exact_protected_inputs(self):
        calls=[]
        def read(name):calls.append(name);return b'a'*43
        first,second=W.payloads(Q,SimpleNamespace(read=read),CONFIG)
        self.assertEqual(len(calls),3);self.assertNotIn('action',json.loads(first))
        self.assertEqual(json.loads(second)['action'],'verify-initial')
        self.assertEqual(json.loads(second)['adminOrigin'],CONFIG['admin_origin']);self.assertEqual(json.loads(second)['ssoAliases'],[])
        for raw in (b'bad',b'a'*32+b'\n',b'a'*129,b'\xff'*40):
            with self.assertRaises(ValueError):W.payloads(Q,SimpleNamespace(read=lambda name:raw),CONFIG)
    def test_verified_sso_configuration_controls_exact_alias_set(self):
        for sso,expected in (('none',[]),('google',['google']),('microsoft',['microsoft']),('both',['google','microsoft'])):
            _,payload=W.payloads(Q,SimpleNamespace(read=lambda name:b'a'*43),dict(CONFIG,sso=sso))
            self.assertEqual(json.loads(payload)['ssoAliases'],expected)
    def test_invalid_admin_origin_and_sso_refused_before_secret_reads(self):
        for wrong in (dict(CONFIG,admin_origin='http://admin.example.invalid'),dict(CONFIG,admin_origin='https://admin.example.invalid/path'),
            dict(CONFIG,admin_origin='https://user:pass@admin.example.invalid'),dict(CONFIG,sso='unexpected')):
            with self.assertRaises(ValueError):W.payloads(Q,SimpleNamespace(read=lambda _:self.fail('credentials read before input refusal')),wrong)
    def test_owner_identifier_refused_before_credentials_are_read(self):
        with self.assertRaises(ValueError):W.payloads(Q,SimpleNamespace(read=lambda name:self.fail('read too early')),{'owner_subject':'owner'})
    def test_execution_record_cannot_assert_policy_or_public_startup(self):
        value=W.execution_record(Q,{'releaseSha256':'a'*64},b'{}','b'*64,'s-abcdefghijkl',b'infra',{})
        for name in ('configuredPolicyVerified','browserMfaQualified','publicStartupAllowed','backupReady'):self.assertIs(value[name],False)
        self.assertEqual(value['infrastructureOutcomeSha256'],Q.sha(b'infra'))
    def test_infrastructure_record_reconstructed_from_current_bindings(self):
        request=dict(operationId='a'*32,releaseSha256='b'*64);session='s-abcdefghijkl';worker='c'*64;request_raw=Q.canonical(request)
        parent=SimpleNamespace(arguments=SimpleNamespace(session=session));component={'synthetic':'component'};host={'synthetic':'host'}
        value=I.outcome(Q,request,request_raw,worker,session,b'render',component,host);raw=Q.canonical(value)
        records={'intent.json':I.intended_record(Q,request_raw,worker,session),'executed.json':raw,'verified.json':raw}
        modules=dict(configuration=Q,station=SimpleNamespace(read_protected=lambda p,n:records[Path(p).name]),infrastructure_worker=I,render_worker=None)
        self.assertEqual(W.infrastructure_record(modules,parent,request,request_raw,worker,b'render')[2],raw)
        records['verified.json']=Q.canonical(dict(value,session='s-XXXXXXXXXXXX'))
        with self.assertRaises(ValueError):W.infrastructure_record(modules,parent,request,request_raw,worker,b'render')
    def test_provision_observation_cannot_select_another_network_or_source(self):
        request={'operationId':'a'*32};component={'networkIds':{'identity':'b'*64},'containerIds':{'keycloak':'c'*64}}
        image='platform@sha256:'+'d'*64
        expected=dict(operationId=W.operation_ids(Q,request)[0],sourceSha256=Q.sha(b'source'),caSha256=Q.sha(b'ca'),
            image=image,imageId='sha256:'+'e'*64,networkId='b'*64,keycloakId='c'*64)
        value=dict(expected=expected,recordsSha256='f'*64)
        args=dict(request=request,source=b'source',ca=b'ca',image=image,component=component)
        self.assertEqual(W.validate_provision(Q,value,**args),expected)
        for key in ('operationId','sourceSha256','caSha256','networkId','keycloakId','image'):
            with self.assertRaises(ValueError):W.validate_provision(Q,dict(value,expected=dict(expected,**{key:'different'})),**args)


class ToolPins(unittest.TestCase):
    def test_docker_bytes_must_match_company_pin_before_execution(self):
        M=load('identity_commands_pin_test','deploy/installer/company_identity_commands.py')
        data=b'approved synthetic executable';identity=(1,2,0o100755,0,0,1,len(data),3,4)
        class Original:
            def _tool(self,name):self.tools[name]=(71,identity)
        D=SimpleNamespace(require=P.require,TOOLS={'docker':'/usr/bin/docker'},NativeCommands=Original,ident=lambda v:identity)
        policy=SimpleNamespace(tool_pins=lambda b:{'docker':b})
        pin=dict(path='/usr/bin/docker',bytes=len(data),sha256=Q.sha(data))
        C=W.bound_commands(dict(render_commands=D,identity_commands=M,identity_evidence=None,infrastructure_policy=policy),pin)
        instance=object.__new__(C);instance.tools={}
        with patch.object(W.os,'pread',return_value=data,create=True),patch.object(W.os,'fstat',return_value=object()):instance._tool('docker')
        with patch.object(W.os,'pread',return_value=b'x'*len(data),create=True),patch.object(W.os,'fstat',return_value=object()):
            with self.assertRaises(ValueError):instance._tool('docker')
        with self.assertRaises(ValueError):instance._tool('other')


class ComponentClosure(unittest.TestCase):
    def test_provision_cannot_return_before_helper_and_files_close(self):
        events=[]
        class IO:
            def __init__(self,*a,**k):events.append('io-open')
            def check(self):events.append('io-check')
            def close(self):events.append('io-close')
        class Commands:
            def __init__(self,*a):self.image_id='sha256:'+'d'*64;self.container=None
            def preflight(self):events.append('preflight')
            def run_phase(self,*a):events.append('provision');return dict(phase='provision',configuredPolicyVerified=False,publicStartupAllowed=False)
            def close(self):events.append('commands-close')
        @contextmanager
        def evidence(*a,**k):
            self.assertIn('io-close',events);yield SimpleNamespace(observation=lambda:{'closed':'fixture'})
        @contextmanager
        def workspace():
            self.assertIn('io-open',events);self.assertNotIn('preflight',events)
            events.append('host-open');yield;events.append('host-close')
        modules=dict(configuration=Q,identity_io=SimpleNamespace(IdentityIO=IO),identity_evidence=SimpleNamespace(ProvisionEvidence=evidence))
        component=dict(networkIds={'identity':'a'*64},containerIds={'keycloak':'b'*64},imageIds={'keycloak':'sha256:'+'c'*64})
        args=dict(data='/protected',request={'operationId':'a'*32},source=b'source',ca=b'ca',image='platform@sha256:'+'e'*64,
            component=component,binding={},authority=lambda:events.append('authority'),payload=b'{}',workspace_context=workspace)
        with patch.object(W,'bound_commands',return_value=Commands):result=W.provision_component(modules,**args)
        self.assertLess(events.index('commands-close'),events.index('io-close'));self.assertIn('recordsSha256',result)
        self.assertLess(events.index('commands-close'),events.index('host-close'));self.assertLess(events.index('host-close'),events.index('io-close'))
        events.clear()
        with patch.object(W,'bound_commands',return_value=Commands),patch.object(IO,'close',side_effect=ValueError('unknown-close')):
            with self.assertRaises(ValueError):W.provision_component(modules,**args)


if __name__=='__main__':unittest.main(verbosity=2)
