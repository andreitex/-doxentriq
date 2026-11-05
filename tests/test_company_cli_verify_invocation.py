"""Bounded pure original-R/ASET1 composition; no CLI, IO, process or ACK."""
import hashlib
import json
from pathlib import Path
import sys
from types import MappingProxyType, ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
D = Path(__file__).resolve().parents[1]/'deploy/installer'


def load(name, path):
    module = ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), vars(module))
    return module


R = load('verify_request_original_r', ROOT/'deploy/installer/company_full_cli_request.py')
S = load('verify_request_original_aset1', ROOT/'deploy/installer/company_bash_execution_status.py')
V = load('verify_request_candidate', D/'company_cli_verify_invocation.py')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class VerifyInvocationControls(unittest.TestCase):
    def setUp(self):
        self.builder = V.prepare_verification_builder(R,S)
        self.request = dict(schemaVersion=1, mode='full-installation', operationId='1'*32,
            releaseSha256='b'*64, bundleRoot='/opt/autosoft-company/incoming/bundle',
            sourceRoot='/opt/autosoft-company/incoming/source', keyPath='/opt/autosoft-company/bootstrap/key.pem',
            dataDir='/srv/autosoft', backingFile='/var/lib/autosoft-data.luks', capacityGiB=128,
            runscVersion='20261005.0', runscSha512='c'*128)
        self.request_raw = canonical(self.request)
        self.base = dict(requestSha256=digest(self.request_raw), releaseSha256='b'*64,
            deliverySha256=digest(b'raw delivery'), planSha256='d'*64, actionSha256='e'*64,
            inputSha256='f'*64, stage='company-platform-store', session='s-ABCDEF123456',
            parentPid=100, childPid=101, parentStart=1000, childStart=1001,
            bootId='11111111-1111-1111-1111-111111111111')
        self.call = dict(schemaVersion=1, scope='FULL_RETENTION_CLI_INVOCATION_ONLY', command='execute-stage',
            stage=self.base['stage'], requestSha256=self.base['requestSha256'], releaseSha256='b'*64,
            operationId='1'*32, storeOperationId='1'*32, planSha256='d'*64, outcomeSha256=None,
            parent=['100','11','12',self.base['session'],self.base['requestSha256'],self.base['stage'],'e'*64])
        self.identity = digest(b'composite delivery identity')
        self.stderr = b'diagnostic\x00\xff\n'
        self.operation = dict(scope='SYNTHETIC_TEST_ONLY', artifact='unchanged-public-fixture')
        self.value = dict(schemaVersion=1, scope='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY', command='execute-stage',
            deliveryIdentitySha256=self.identity, binding=self.binding(), planBase64=None,
            result=dict(operationResult=self.operation, operationOutcomeSha256=digest(canonical(self.operation)),
                stagePlanSha256='d'*64, ownedResourcesKnownReleased=True, stageAcknowledged=False, nativeAuthorized=False),
            outcomeSha256=digest(canonical(self.operation)), stageAcknowledged=False,
            fullInstallationCompleted=False, nativeQualified=False)

    def binding(self):
        result = {key:self.call[key] for key in ('stage','requestSha256','releaseSha256','operationId','storeOperationId','planSha256')}
        result.update(session=self.base['session'],actionSha256=self.base['actionSha256'])
        return result

    def arguments(self, exit_code=0):
        invocation, record = canonical(self.call), canonical(self.value)
        status = S.encode_execution_status(self.base, execute_invocation_raw=invocation,
            completed_record_raw=record, expected_delivery_identity_sha256=self.identity,
            stdout=record, stderr=self.stderr, exit_code=exit_code)
        return dict(request_raw=self.request_raw, execute_invocation_raw=invocation,
            completed_record_raw=record, execution_status_raw=status, expected_binding=self.base,
            expected_delivery_identity_sha256=self.identity, stdout=record, stderr=self.stderr,
            expected_exit_code=exit_code)

    def test_store_derives_exact_fresh_verify_bytes_and_preserves_parent(self):
        original_call, original_record = canonical(self.call), canonical(self.value)
        expected = dict(self.call, command='verify-stage', outcomeSha256=digest(canonical(self.operation)))
        result = self.builder(**self.arguments())
        self.assertIs(type(result), MappingProxyType)
        self.assertEqual(result['invocation'],canonical(expected))
        self.assertEqual(result['invocationSha256'],digest(canonical(expected)))
        self.assertEqual(result['completedRecordSha256'],digest(original_record))
        self.assertEqual(result['executeInvocationSha256'],digest(original_call))
        self.assertEqual(canonical(self.call),original_call)
        self.assertEqual(canonical(self.value),original_record)
        for key in ('executionEvidenceIssued','parentWaitQualified','stageAcknowledged','installerActivated'):
            self.assertIs(result[key],False)
        with self.assertRaises(TypeError):result['outcomeSha256']='0'*64

    def test_source_preserves_separate_source_and_store_operations(self):
        self.base['stage']='company-source-materialize'
        self.call.update(stage=self.base['stage'],operationId='2'*32)
        self.call['parent'][5]=self.base['stage']
        self.value['binding']=self.binding()
        actual=json.loads(self.builder(**self.arguments())['invocation'])
        self.assertEqual(actual['operationId'],'2'*32)
        self.assertEqual(actual['storeOperationId'],'1'*32)
        self.assertEqual(actual['parent'],self.call['parent'])

    def test_consistent_status_cannot_rescue_forged_outcome_or_wrong_plan(self):
        self.value['outcomeSha256']=self.value['result']['operationOutcomeSha256']='0'*64
        args=self.arguments()  # ASET1 syntax binding accepts this DATA fixture.
        S.bind_execution_status(args['execution_status_raw'], **{k:args[k] for k in
            ('expected_binding','execute_invocation_raw','completed_record_raw','expected_delivery_identity_sha256','stdout','stderr','expected_exit_code')})
        with self.assertRaises(V.VerifyInvocationUnavailable):self.builder(**args)
        self.value['outcomeSha256']=self.value['result']['operationOutcomeSha256']=digest(canonical(self.operation))
        self.value['result']['stagePlanSha256']='0'*64
        with self.assertRaises(V.VerifyInvocationUnavailable):self.builder(**self.arguments())

    def test_changed_record_and_cross_request_are_refused(self):
        args=self.arguments()
        self.value['result']['operationResult']['artifact']='substituted'
        args['completed_record_raw']=args['stdout']=canonical(self.value)
        with self.assertRaises(S.ExecutionStatusUnavailable):self.builder(**args)
        args=self.arguments()
        other=dict(self.request,operationId='3'*32)
        args['request_raw']=canonical(other)
        with self.assertRaises(R.FullCliRequestUnavailable):self.builder(**args)

    def test_nonzero_and_boolean_exit_cannot_prepare_success_verification(self):
        with self.assertRaises(V.VerifyInvocationUnavailable):self.builder(**self.arguments(exit_code=1))
        args=self.arguments();args['expected_exit_code']=False
        with self.assertRaises(V.VerifyInvocationUnavailable):self.builder(**args)

    def test_replaced_validator_is_refused_before_it_runs(self):
        calls=[]
        args=self.arguments()
        with patch.object(S,'bind_execution_status',lambda *a,**k:calls.append((a,k))):
            with self.assertRaises(V.VerifyInvocationUnavailable):self.builder(**args)
        self.assertEqual(calls,[])
        self.assertEqual(self.builder(**args)['scope'],'FRESH_VERIFY_INVOCATION_DATA_ONLY')

    def test_foreign_class_origin_is_refused_without_equality(self):
        calls=[]
        class Foreign:
            def __eq__(self,other):calls.append(other);raise AssertionError('foreign equality')
        class Injected:pass
        Injected.__module__=Foreign()
        with patch.object(R,'Injected',Injected,create=True):
            with self.assertRaises(V.VerifyInvocationUnavailable):V.prepare_verification_builder(R,S)
        self.assertEqual(calls,[])


if __name__ == '__main__':
    unittest.main(verbosity=2)
