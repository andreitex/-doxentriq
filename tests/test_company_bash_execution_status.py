"""Pure ASET1 controls with constructed canonical execute-contract fixtures.

No original CLI/reader/old codec import, subprocess, pipe, native operation,
signing, closure issuer or Bash wait occurs. Exact supplied bytes are DATA.
"""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

D = Path(__file__).resolve().parents[1]/'deploy/installer'
spec = importlib.util.spec_from_file_location('private_pure_aset1_controls', D / 'company_bash_execution_status.py')
S = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = S
spec.loader.exec_module(S)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def binding():
    return dict(requestSha256='a' * 64, releaseSha256='b' * 64,
        deliverySha256=digest(b'independently supplied raw delivery'), planSha256='d' * 64,
        actionSha256='e' * 64, inputSha256='f' * 64, stage='company-platform-store',
        session='s-ABCDEF123456', parentPid=100, childPid=101, parentStart=1000,
        childStart=1001, bootId='11111111-1111-1111-1111-111111111111')


def invocation(base):
    return dict(schemaVersion=1, scope='FULL_RETENTION_CLI_INVOCATION_ONLY', command='execute-stage',
        stage=base['stage'], requestSha256=base['requestSha256'], releaseSha256=base['releaseSha256'],
        operationId='1' * 32, storeOperationId='1' * 32, planSha256=base['planSha256'], outcomeSha256=None,
        parent=[str(base['parentPid']), '11', '12', base['session'], base['requestSha256'], base['stage'], base['actionSha256']])


def record(base, call, identity):
    bound = {key: call[key] for key in ('stage', 'requestSha256', 'releaseSha256', 'operationId', 'storeOperationId', 'planSha256')}
    bound.update(session=base['session'], actionSha256=base['actionSha256'])
    outcome = dict(scope='SYNTHETIC_CONTRACT_FIXTURE_ONLY', value='no effects')
    outcome_hash = digest(canonical(outcome))
    return dict(schemaVersion=1, scope='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY', command='execute-stage',
        deliveryIdentitySha256=identity, binding=bound, planBase64=None,
        result=dict(operationResult=outcome, operationOutcomeSha256=outcome_hash,
            stagePlanSha256=base['planSha256'], ownedResourcesKnownReleased=True,
            stageAcknowledged=False, nativeAuthorized=False), outcomeSha256=outcome_hash,
        stageAcknowledged=False, fullInstallationCompleted=False, nativeQualified=False)


class ExecutionStatusControls(unittest.TestCase):
    def setUp(self):
        self.base = binding()
        self.identity = digest(b'independently supplied C composite delivery identity')
        self.call = invocation(self.base)
        self.value = record(self.base, self.call, self.identity)
        self.invocation_raw = canonical(self.call)
        self.record_raw = canonical(self.value)
        self.stderr = b'public diagnostic\0\xff\n'
        self.raw = self.encode()

    def encode(self, **changes):
        args = dict(execute_invocation_raw=self.invocation_raw, completed_record_raw=self.record_raw,
            expected_delivery_identity_sha256=self.identity, stdout=self.record_raw, stderr=self.stderr, exit_code=0)
        args.update(changes)
        return S.encode_execution_status(self.base, **args)

    def bind(self, raw=None, **changes):
        args = dict(expected_binding=self.base, execute_invocation_raw=self.invocation_raw,
            completed_record_raw=self.record_raw, expected_delivery_identity_sha256=self.identity,
            stdout=self.record_raw, stderr=self.stderr, expected_exit_code=0)
        args.update(changes)
        return S.bind_execution_status(self.raw if raw is None else raw, **args)

    def reject(self, call):
        with self.assertRaises(S.ExecutionStatusUnavailable):
            call()

    def altered(self, index, text):
        parts = self.raw[:-1].decode('ascii').split('|')
        parts[index] = text
        return ('|'.join(parts) + '\n').encode('ascii')

    def test_exact21_tokens_derive_both_new_digests_from_whole_supplied_bytes(self):
        result = self.bind()
        parts = self.raw[:-1].decode('ascii').split('|')
        self.assertEqual(len(parts), 21)
        self.assertEqual(parts[0], 'ASET1')
        self.assertEqual(parts[1:14], [str(self.base[key]) for key in S.BASE_BINDING_FIELDS])
        self.assertEqual(parts[14:16], [digest(self.invocation_raw), digest(self.record_raw)])
        self.assertEqual(parts[16:], [digest(self.record_raw), str(len(self.record_raw)), digest(self.stderr), str(len(self.stderr)), '0'])
        self.assertEqual(result['sha256'], digest(self.raw))
        self.assertEqual(result['binding']['completedRecordSha256'], result['stdout']['sha256'])
        self.assertLessEqual(len(self.raw), 2048)

    def test_stdout_must_equal_record_bytes_even_when_length_and_json_shape_match(self):
        other = dict(self.value, outcomeSha256='0' * 64)
        substitute = canonical(other)
        self.assertEqual(len(substitute), len(self.record_raw))
        self.reject(lambda: self.encode(stdout=substitute))
        self.reject(lambda: self.bind(stdout=substitute))
        self.reject(lambda: self.encode(stdout=self.record_raw + b'x'))

    def test_invocation_changed_bytes_and_matching_record_cannot_bind_old_frame(self):
        call = dict(self.call, operationId='2' * 32, storeOperationId='2' * 32)
        changed_call = canonical(call)
        self.reject(lambda: self.encode(execute_invocation_raw=changed_call))
        changed_record = canonical(record(self.base, call, self.identity))
        raw = self.encode(execute_invocation_raw=changed_call, completed_record_raw=changed_record, stdout=changed_record)
        self.assertNotEqual(raw, self.raw)
        self.reject(lambda: self.bind(execute_invocation_raw=changed_call, completed_record_raw=changed_record, stdout=changed_record))
        self.assertEqual(self.bind(raw, execute_invocation_raw=changed_call, completed_record_raw=changed_record, stdout=changed_record)['frame'], raw)

    def test_record_substitution_and_each_stream_hash_count_tamper_refuse(self):
        changed = dict(self.value, result=dict(self.value['result'], note='different completed record'))
        changed_raw = canonical(changed)
        self.reject(lambda: self.bind(completed_record_raw=changed_raw, stdout=changed_raw))
        self.reject(lambda: self.bind(stderr=self.stderr + b'x'))
        for index, value in ((14, '0' * 64), (15, '0' * 64), (16, '0' * 64), (17, str(len(self.record_raw) + 1)),
                             (18, '0' * 64), (19, str(len(self.stderr) + 1))):
            self.reject(lambda index=index, value=value: self.bind(self.altered(index, value)))

    def test_all_old13_expected_binding_fields_are_independently_checked(self):
        for key in S.BASE_BINDING_FIELDS:
            changed = dict(self.base)
            if key.endswith('Sha256'):
                changed[key] = '0' * 64
            elif key == 'stage':
                changed[key] = 'company-source-materialize'
            elif key == 'session':
                changed[key] = 's-ZYXWVU654321'
            elif key == 'bootId':
                changed[key] = '22222222-2222-2222-2222-222222222222'
            else:
                changed[key] += 100
            self.reject(lambda changed=changed: self.bind(expected_binding=changed))

    def test_composite_delivery_identity_is_independent_of_raw_delivery_sha(self):
        self.assertNotEqual(self.identity, self.base['deliverySha256'])
        self.assertEqual(self.bind()['binding']['deliverySha256'], self.base['deliverySha256'])
        self.reject(lambda: self.encode(expected_delivery_identity_sha256=self.base['deliverySha256']))
        self.reject(lambda: self.bind(expected_delivery_identity_sha256='0' * 64))
        changed = canonical(dict(self.value, deliveryIdentitySha256='0' * 64))
        self.reject(lambda: self.encode(completed_record_raw=changed, stdout=changed))

    def test_caller_hash_overrides_and_extra_authority_fields_are_not_an_api(self):
        for key in ('executeInvocationSha256', 'completedRecordSha256', 'knownReaderCloses', 'actualWaitKnown'):
            changed = dict(self.base)
            changed[key] = '0' * 64
            self.reject(lambda changed=changed: S.encode_execution_status(changed,
                execute_invocation_raw=self.invocation_raw, completed_record_raw=self.record_raw,
                expected_delivery_identity_sha256=self.identity, stdout=self.record_raw, stderr=self.stderr, exit_code=0))
        with self.assertRaises(TypeError):
            self.encode(completed_record_sha256='0' * 64)
        with self.assertRaises(TypeError):
            self.bind(execute_invocation_sha256='0' * 64)

    def test_invocation_closed_schema_command_outcome_and_overlap_refuse(self):
        variants = [dict(self.call, extra='x'), {k: v for k, v in self.call.items() if k != 'scope'},
            dict(self.call, schemaVersion=True), dict(self.call, command='verify-stage'), dict(self.call, outcomeSha256='0' * 64)]
        for key in ('requestSha256', 'releaseSha256', 'planSha256'):
            variants.append(dict(self.call, **{key: '0' * 64}))
        variants.extend((dict(self.call, stage='company-source-materialize'), dict(self.call, scope='different'),
            dict(self.call, operationId='z' * 32), dict(self.call, storeOperationId='2' * 32)))
        for value in variants:
            self.reject(lambda value=value: self.encode(execute_invocation_raw=canonical(value)))

    def test_parent7_exact_pid_fd_session_request_stage_action_binding(self):
        for index, value in ((0, '102'), (0, '0100'), (1, '2'), (1, '1048576'), (2, '11'),
                             (3, 's-ZYXWVU654321'), (4, '0' * 64), (5, 'company-source-materialize'), (6, '0' * 64)):
            parent = list(self.call['parent'])
            parent[index] = value
            self.reject(lambda parent=parent: self.encode(execute_invocation_raw=canonical(dict(self.call, parent=parent))))
        for parent in (None, [], self.call['parent'][:-1], self.call['parent'] + ['extra'], [True] + self.call['parent'][1:]):
            self.reject(lambda parent=parent: self.encode(execute_invocation_raw=canonical(dict(self.call, parent=parent))))

    def test_record_closed11_execute_binding8_and_serialized_flags_refuse(self):
        values = [dict(self.value, extra='x'), {k: v for k, v in self.value.items() if k != 'scope'},
            dict(self.value, schemaVersion=True), dict(self.value, command='describe'), dict(self.value, planBase64='YQ=='),
            dict(self.value, outcomeSha256='g' * 64), dict(self.value, result=None)]
        for key in ('stageAcknowledged', 'fullInstallationCompleted', 'nativeQualified'):
            values.append(dict(self.value, **{key: True}))
        for key in S.RECORD_BINDING_FIELDS:
            bound = dict(self.value['binding'])
            bound[key] = 'different'
            values.append(dict(self.value, binding=bound))
        values.append(dict(self.value, binding=dict(self.value['binding'], unknown='x')))
        for value in values:
            raw = canonical(value)
            self.reject(lambda raw=raw: self.encode(completed_record_raw=raw, stdout=raw))

    def test_noncanonical_duplicate_constants_floats_and_unpaired_surrogates_refuse(self):
        for name, raw in (('execute_invocation_raw', self.invocation_raw), ('completed_record_raw', self.record_raw)):
            bads = (raw[:-1], raw + b' ', raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                    json.dumps(json.loads(raw), indent=2).encode() + b'\n')
            for bad in bads:
                args = {name: bad}
                if name == 'completed_record_raw':
                    args['stdout'] = bad
                self.reject(lambda args=args: self.encode(**args))
        for result in ({'value': float('nan')}, {'value': 1.5}, {'value': '\ud800'}):
            # NaN construction is test-only; codec refuses before canonical data.
            raw = json.dumps(dict(self.value, result=result), sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n'
            self.reject(lambda raw=raw: self.encode(completed_record_raw=raw, stdout=raw))

    def test_exact_buffer_caps_accept_and_oversize_mutability_refuse(self):
        empty = dict(self.value, result={'note': ''})
        gap = 32768 - len(canonical(empty))
        exact = canonical(dict(empty, result={'note': 'x' * gap}))
        self.assertEqual(len(exact), 32768)
        raw = self.encode(completed_record_raw=exact, stdout=exact, stderr=b'e' * 8192)
        result = self.bind(raw, completed_record_raw=exact, stdout=exact, stderr=b'e' * 8192)
        self.assertEqual((result['stdout']['bytes'], result['stderr']['bytes']), (32768, 8192))
        for changes in (dict(completed_record_raw=exact + b'x', stdout=exact + b'x'), dict(stderr=b'e' * 8193),
                        dict(execute_invocation_raw=b'x' * 4097), dict(stdout=bytearray(self.record_raw)),
                        dict(stderr=memoryview(self.stderr)), dict(completed_record_raw=bytearray(self.record_raw))):
            self.reject(lambda changes=changes: self.encode(**changes))

    def test_decode_exit_byte_and_bind_require_independent_exact_exit(self):
        for code in (0, 1, 127, 255):
            raw = self.encode(exit_code=code)
            self.assertEqual(S.decode_execution_status(raw)['exitCode'], code)
            self.assertEqual(self.bind(raw, expected_exit_code=code)['exitCode'], code)
            self.reject(lambda raw=raw, code=code: self.bind(raw, expected_exit_code=(code + 1) % 256))
        for value in (True, False, -1, 256, '0', 0.0):
            self.reject(lambda value=value: self.encode(exit_code=value))
            self.reject(lambda value=value: self.bind(expected_exit_code=value))

    def test_frame_domain_token_count_ascii_line_endings_and_types(self):
        class Bytes(bytes):
            pass
        for raw in (self.raw.replace(b'ASET1', b'ASBT1'), self.raw.replace(b'ASET1', b'CBSD1'), self.raw[:-1],
                    self.raw + self.raw, self.raw + b'\n', self.raw[:-1] + b'|0\n', self.raw.replace(b'\n', b'\r\n'),
                    self.raw.replace(b'ASET1', b'ASET1\0'), self.raw.replace(b'ASET1', b'ASET1\xff'), b'x' * 2049,
                    bytearray(self.raw), memoryview(self.raw), Bytes(self.raw)):
            self.reject(lambda raw=raw: S.decode_execution_status(raw))

    def test_digest_width_lowerhex_and_canonical_numeric_tokens(self):
        for index in (1, 14, 15, 16, 18):
            for text in ('A' * 64, 'a' * 63, 'a' * 65, 'z' * 64):
                self.reject(lambda index=index, text=text: S.decode_execution_status(self.altered(index, text)))
        for index in (9, 10, 11, 12, 17, 19, 20):
            for text in ('00', '01', '+1', '-0', '1.0', 'True', ' 1', '1 ', '9' * 30):
                self.reject(lambda index=index, text=text: S.decode_execution_status(self.altered(index, text)))
        for index, text in ((17, '32769'), (19, '8193'), (20, '256')):
            self.reject(lambda index=index, text=text: S.decode_execution_status(self.altered(index, text)))

    def test_foreign_key_hash_eq_and_value_coercion_callbacks_never_run(self):
        calls = []
        class Key:
            def __hash__(self): calls.append('hash'); return hash('requestSha256')
            def __eq__(self, other): calls.append('eq'); return other == 'requestSha256'
        class Foreign:
            def __str__(self): calls.append('str'); raise AssertionError('foreign str')
            def __int__(self): calls.append('int'); raise AssertionError('foreign int')
            def __len__(self): calls.append('len'); raise AssertionError('foreign len')
            def __eq__(self, other): calls.append('eq'); raise AssertionError('foreign eq')
        bad = {k: v for k, v in self.base.items() if k != 'requestSha256'}
        bad[Key()] = 'a' * 64
        calls.clear()
        self.reject(lambda: self.bind(expected_binding=bad))
        self.reject(lambda: S.encode_execution_status(bad, execute_invocation_raw=self.invocation_raw,
            completed_record_raw=self.record_raw, expected_delivery_identity_sha256=self.identity,
            stdout=self.record_raw, stderr=self.stderr, exit_code=0))
        for key in ('requestSha256', 'stage', 'parentPid'):
            changed = dict(self.base)
            changed[key] = Foreign()
            self.reject(lambda changed=changed: self.bind(expected_binding=changed))
        for key in ('execute_invocation_raw', 'completed_record_raw', 'expected_delivery_identity_sha256', 'stdout', 'stderr', 'exit_code'):
            self.reject(lambda key=key: self.encode(**{key: Foreign()}))
        self.assertEqual(calls, [])

    def test_output_deeply_immutable_and_base_binding_detached(self):
        result = self.bind()
        self.base['requestSha256'] = '0' * 64
        self.assertEqual(result['binding']['requestSha256'], 'a' * 64)
        for target, key in ((result, 'scope'), (result['binding'], 'parentPid'), (result['stdout'], 'bytes'), (result['stderr'], 'sha256')):
            with self.assertRaises(TypeError):
                target[key] = 'changed'

    def test_original_captured_callbacks_constants_and_error_survive_public_replacement(self):
        original = S.ExecutionStatusUnavailable
        calls = []
        with patch.object(S, 'ExecutionStatusUnavailable', lambda *a: calls.append('error')), \
             patch.object(S, 'MAX_FRAME', 1), patch.object(S, 'BINDING_FIELDS', ('changed',)), \
             patch.object(S.hashlib, 'sha256', lambda *a: calls.append('hash')), \
             patch.object(S.json, 'loads', lambda *a, **k: calls.append('loads')), \
             patch.object(S.json, 'dumps', lambda *a, **k: calls.append('dumps')):
            self.assertEqual(self.bind()['frame'], self.raw)
            with self.assertRaises(original):
                S.decode_execution_status(b'bad')
        self.assertEqual(calls, [])
        self.assertFalse(hasattr(S, '_make_codec'))

    def test_schema_fields_match_frozen_original_contract_without_import(self):
        root = D.parents[1]
        old = root / 'tests/fixtures/company_bash_status_v1.source.txt'
        values = {}
        for node in ast.parse(old.read_bytes()).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ('BINDING_FIELDS', 'MAX_FRAME', 'STDOUT_CAP', 'STDERR_CAP', 'TOTAL_CAP'):
                        values[target.id] = ast.literal_eval(node.value)
        self.assertEqual(S.BASE_BINDING_FIELDS, values.pop('BINDING_FIELDS'))
        for key, value in values.items():
            self.assertEqual(getattr(S, key), value)
        original_request = ast.parse((root / 'deploy/installer/company_full_cli_request.py').read_bytes())
        node = next(n for n in original_request.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'INVOCATION_FIELDS' for t in n.targets))
        self.assertEqual(set(S.INVOCATION_FIELDS), set(ast.literal_eval(node.value.args[0])))
        reader = ast.parse((root / 'deploy/installer/company_cli_record.py').read_bytes())
        sets = [set(ast.literal_eval(n)) for n in ast.walk(reader) if isinstance(n, ast.Set) and all(isinstance(v, ast.Constant) and type(v.value) is str for v in n.elts)]
        self.assertIn(set(S.RECORD_FIELDS), sets)

    def test_source_stage_separate_operation_and_repeated_data_do_not_issue_authority(self):
        base = dict(self.base, stage='company-source-materialize')
        call = invocation(base)
        call['operationId'] = '2' * 32
        rec = canonical(record(base, call, self.identity))
        args = dict(execute_invocation_raw=canonical(call), completed_record_raw=rec,
            expected_delivery_identity_sha256=self.identity, stdout=rec, stderr=b'', exit_code=0)
        raw = S.encode_execution_status(base, **args)
        self.assertEqual(S.encode_execution_status(base, **args), raw)
        result = S.bind_execution_status(raw, expected_binding=base, expected_exit_code=0,
            **{k: v for k, v in args.items() if k != 'exit_code'})
        self.assertEqual(result['scope'], 'ASET1_EXECUTION_STATUS_DATA_ONLY')
        for key in ('invocationOriginQualified', 'completedRecordOriginQualified', 'deliveryIdentityOriginQualified',
                    'parentOriginQualified', 'parentWaitQualified', 'syscallEofQualified', 'knownCleanupQualified',
                    'sourceClosureQualified', 'crossProcessEvidenceIssued', 'stageAcknowledged'):
            self.assertIs(result[key], False)
        tree = ast.parse((D / 'company_bash_execution_status.py').read_bytes())
        imports = [alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names]
        self.assertEqual(imports, ['hashlib', 'json', 're'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
