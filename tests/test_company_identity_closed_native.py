"""Actual closed identity files; predecessor parent/record transport is synthetic."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value
E=load('closed_identity_evidence','deploy/installer/company_identity_evidence.py')
IO=load('closed_identity_io','deploy/installer/company_identity_io.py')
W=load('closed_identity_worker','deploy/installer/company_identity_worker.py')
Q=load('closed_identity_configuration','deploy/installer/company_configuration.py')
N=load('closed_identity_predecessor','deploy/installer/company_identity_predecessor.py')

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class ClosedIdentity(unittest.TestCase):
    def setUp(self):
        self.data=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])/uuid.uuid4().hex;self.data.mkdir(mode=0o700)
        (self.data/'company').mkdir(mode=0o700)
        self.request=dict(operationId='a'*32,releaseSha256='b'*64);self.owner='aaaaaaaa-bbbb-bbbb-bbbb-cccccccccccc'
        self.source=b'synthetic helper';self.ca=b'synthetic CA';self.image='registry.example/platform@sha256:'+'c'*64
        self.component=dict(networkIds=dict(identity='d'*64),containerIds=dict(keycloak='e'*64))
        self.expected=dict(operationId=W.operation_ids(Q,self.request)[0],sourceSha256=Q.sha(self.source),caSha256=Q.sha(self.ca),
            image=self.image,imageId='sha256:'+'f'*64,networkId='d'*64,keycloakId='e'*64)
        self.verification=dict(self.expected,operationId=W.operation_ids(Q,self.request)[1])
        output=(json.dumps(dict(scope='INITIAL_IDENTITY_POLICY_READBACK',ownerSubject=self.owner,
            configuredPolicyVerified=True,browserMfaQualified=False,publicStartupAllowed=False),separators=(',',':'))+'\n').encode()
        for phase,expected,message in (('provision',self.expected,E.MESSAGE),('verify',self.verification,output)):
            io=IO.IdentityIO(self.data,expected['operationId'],self.source,self.ca,check_authority=lambda:None)
            try:
                io.record(phase,'intent',{k:v for k,v in expected.items() if k!='operationId'})
                for event in E.EVENTS[1:]:
                    value=dict(containerId=('1' if phase=='provision' else '2')*64)
                    if event=='completed':value['outputSha256']=Q.sha(message)
                    io.record(phase,event,value)
            finally:io.close()
        self.path=self.data/'company'/('identity-'+self.verification['operationId'])
    def read(self,owner=None):
        return E.VerificationEvidence(self.data,self.verification,owner_subject=owner or self.owner,check_authority=lambda:None)
    def test_closed_verification_has_no_live_policy_or_authority(self):
        with self.read() as held:
            value=held.observation();self.assertEqual(value['containerId'],'2'*64)
            self.assertEqual(value['scope'],'IDENTITY_VERIFICATION_RECORD_OBSERVATION_ONLY')
            for flag in ('publicStartupAllowed','parentAuthorityEstablished','livePolicyVerified'):self.assertFalse(value[flag])
    def test_missing_removed_record_refuses_completion(self):
        (self.path/'005-verify-removed.json').unlink()
        with self.assertRaises(ValueError):self.read()
    def test_wrong_owner_and_provision_phase_refused(self):
        with self.assertRaises(ValueError):self.read('bbbbbbbb-bbbb-bbbb-bbbb-cccccccccccc')
        with self.assertRaises(ValueError):E.ProvisionEvidence(self.data,self.verification,check_authority=lambda:None)
    def predecessor(self,change=None):
        request_raw=Q.canonical(self.request);worker='3'*64;session='s-abcdefghijkl';infra=b'infrastructure'
        with E.ProvisionEvidence(self.data,self.expected,check_authority=lambda:None) as held:
            provision=dict(expected=self.expected,recordsSha256=Q.sha(Q.canonical(held.observation())))
        executed=Q.canonical(W.execution_record(Q,self.request,request_raw,worker,session,infra,provision))
        verification=dict(scope='SEPARATE_INITIAL_IDENTITY_POLICY_READBACK',provisionRecordsSha256=provision['recordsSha256'],
            provisionOperationId=self.expected['operationId'],verificationOperationId=self.verification['operationId'],
            verificationContainerId='2'*64,ownerSubject=self.owner,configuredPolicyVerified=True,browserMfaQualified=False,
            parentAuthorityEstablished=False,publicStartupAllowed=False)
        verified=dict(scope='NATIVE_INITIAL_IDENTITY_POLICY_VERIFIED',executionSha256=Q.sha(executed),infrastructureOutcomeSha256=Q.sha(infra),
            verification=verification,configuredPolicyVerified=True,browserMfaQualified=False,publicStartupAllowed=False,backupReady=False)
        if change:change(verified)
        prefix='/opt/autosoft-company/evidence/'+self.request['operationId']+'/'+W.STAGE+'/'
        records={prefix+'executed.json':executed,prefix+'verified.json':Q.canonical(verified),
            prefix+'intent.json':Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=W.action(Q,request_raw,worker),session=session,workerSha256=worker))}
        @contextmanager
        def held_records(q,s,expected):
            def check():self.assertEqual(expected,records)
            check();yield check;check()
        def confirmed(p,parent,stage,action,outcome):
            self.assertEqual((stage,action,outcome),(W.STAGE,W.action(Q,request_raw,worker),Q.sha(records[prefix+'verified.json'])))
        modules=dict(configuration=Q,station=SimpleNamespace(read_protected=lambda name,limit:records[name]),identity_worker=W,
            infrastructure_worker=SimpleNamespace(decode=lambda q,raw:json.loads(raw),held_records=held_records),
            render_worker=SimpleNamespace(confirmed=confirmed),identity_evidence=E)
        parent=SimpleNamespace(arguments=SimpleNamespace(session=session),check=lambda:None)
        return N.confirmed_identity(modules,parent,self.request,request_raw,worker,infra,data=self.data,source=self.source,
            ca=self.ca,image=self.image,component=self.component,owner_subject=self.owner,authority=lambda:None,parent_module=object())
    def test_predecessor_reconstructs_both_closed_runs(self):
        with self.predecessor() as (value,check):
            check();self.assertFalse(value['publicStartupAllowed']);self.assertFalse(value['livePolicyVerified'])
    def test_flags_do_not_override_wrong_container_or_owner(self):
        for key,value in [('verificationContainerId','4'*64),('ownerSubject','bbbbbbbb-bbbb-bbbb-bbbb-cccccccccccc')]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                with self.predecessor(lambda row:row['verification'].update({key:value})):pass
    def test_late_record_change_refuses_and_closes_handles(self):
        baseline=set(os.listdir('/proc/self/fd'))
        with self.assertRaises(ValueError):
            with self.predecessor() as (_,check):
                (self.path/'004-verify-completed.json').write_bytes(b'changed');check()
        self.assertEqual(set(os.listdir('/proc/self/fd')),baseline)

if __name__=='__main__':unittest.main(verbosity=2)
