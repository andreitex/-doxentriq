"""ASET1 execution-status DATA codec; no IO, wait, issuer or ACK.

The caller independently supplies original Bash wait DATA, immutable invocation,
original closed CLI record, composite delivery identity and captured streams.
This codec cannot establish their origins, actual EOF or known resource closure.
Matching hashes, JSON and frames confer none of those authorities.
"""
import hashlib
import json
import re
from types import MappingProxyType

MAX_FRAME = 2048
STDOUT_CAP = 32768
STDERR_CAP = 8192
TOTAL_CAP = 40960
INVOCATION_CAP = 4096
BASE_BINDING_FIELDS = ('requestSha256', 'releaseSha256', 'deliverySha256',
    'planSha256', 'actionSha256', 'inputSha256', 'stage', 'session', 'parentPid',
    'childPid', 'parentStart', 'childStart', 'bootId')
BINDING_FIELDS = BASE_BINDING_FIELDS + ('executeInvocationSha256', 'completedRecordSha256')
STAGES = ('company-platform-store', 'company-source-materialize')
INVOCATION_FIELDS = ('schemaVersion', 'scope', 'command', 'stage', 'requestSha256',
    'releaseSha256', 'operationId', 'storeOperationId', 'planSha256', 'outcomeSha256', 'parent')
RECORD_FIELDS = ('schemaVersion', 'scope', 'command', 'deliveryIdentitySha256', 'binding',
    'planBase64', 'result', 'outcomeSha256', 'stageAcknowledged', 'fullInstallationCompleted', 'nativeQualified')
RECORD_BINDING_FIELDS = ('stage', 'requestSha256', 'releaseSha256', 'operationId',
    'storeOperationId', 'planSha256', 'session', 'actionSha256')


class ExecutionStatusUnavailable(ValueError):
    pass


def _make_codec(error_type):
    base_fields, fields, stages = BASE_BINDING_FIELDS, BINDING_FIELDS, STAGES
    invocation_fields, record_fields, record_binding_fields = INVOCATION_FIELDS, RECORD_FIELDS, RECORD_BINDING_FIELDS
    maximum, out_cap, err_cap, total_cap, invocation_cap = MAX_FRAME, STDOUT_CAP, STDERR_CAP, TOTAL_CAP, INVOCATION_CAP
    proxy, match, raw_hash = MappingProxyType, re.fullmatch, hashlib.sha256
    loads, dumps = json.loads, json.dumps

    def need(value):
        if value is not True:
            raise error_type('company-execution-status-data-unavailable')

    def digest(raw):
        return raw_hash(raw).hexdigest()

    def unsigned(value, minimum, maximum):
        need(type(value) is int and minimum <= value <= maximum)
        return value

    def hash_value(value):
        need(type(value) is str and len(value) == 64 and match('[a-f0-9]{64}', value) is not None)
        return value

    def closed(value, keys):
        # Exact key types precede set/dict lookup: foreign hash/eq cannot run.
        need(type(value) is dict and all(type(key) is str for key in value) and set(value) == set(keys))

    def binding_value(value, keys):
        closed(value, keys)
        result = {key: value[key] for key in keys}
        for key in base_fields[:6]:
            hash_value(result[key])
        if keys == fields:
            for key in fields[13:]:
                hash_value(result[key])
        need(type(result['stage']) is str and result['stage'] in stages)
        need(type(result['session']) is str and match('s-[A-Za-z0-9]{12}', result['session']) is not None)
        need(type(result['bootId']) is str and match('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', result['bootId']) is not None)
        for key in ('parentPid', 'childPid'):
            unsigned(result[key], 2, 2**31 - 1)
        for key in ('parentStart', 'childStart'):
            unsigned(result[key], 2, 2**64 - 1)
        need(result['parentPid'] != result['childPid'])
        return result

    def canonical(value):
        return dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'

    def decode_json(raw, cap):
        need(type(raw) is bytes and 0 < len(raw) <= cap)
        def pairs(rows):
            result = {}
            for key, item in rows:
                need(type(key) is str and key not in result)
                result[key] = item
            return result
        try:
            value = loads(raw.decode('ascii'), object_pairs_hook=pairs,
                parse_constant=lambda _: need(False), parse_float=lambda _: need(False))
            need(type(value) is dict and canonical(value) == raw)
        except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
            raise error_type('company-execution-status-data-unavailable') from None
        return value

    def result_data(value, count, depth=0):
        # Original C._wire result limits. These are syntax/caps, never release.
        count[0] += 1
        need(depth <= 16 and count[0] <= 2048)
        if value is None or type(value) is bool:
            return
        if type(value) is int:
            need(-2**63 <= value < 2**64)
            return
        if type(value) is str:
            need(len(value) <= out_cap)
            try:
                count[1] += len(value.encode('utf8'))
            except UnicodeError:
                raise error_type('company-execution-status-data-unavailable') from None
            need(count[1] <= out_cap)
            return
        if type(value) is dict:
            need(len(value) <= 128 and all(type(key) is str and key.isascii() and 0 < len(key) <= 128 for key in value))
            count[1] += sum(len(key) for key in value)
            need(count[1] <= out_cap)
            for item in value.values():
                result_data(item, count, depth + 1)
            return
        need(type(value) is list and len(value) <= 128)
        for item in value:
            result_data(item, count, depth + 1)

    def parse_uint(text, minimum, maximum):
        need(type(text) is str and 1 <= len(text) <= len(str(maximum)) and match('0|[1-9][0-9]*', text) is not None)
        return unsigned(int(text), minimum, maximum)

    def execution_bytes(base, invocation_raw, record_raw, expected_identity):
        hash_value(expected_identity)
        invocation = decode_json(invocation_raw, invocation_cap)
        closed(invocation, invocation_fields)
        need(type(invocation['schemaVersion']) is int and invocation['schemaVersion'] == 1
             and invocation['scope'] == 'FULL_RETENTION_CLI_INVOCATION_ONLY'
             and invocation['command'] == 'execute-stage' and invocation['outcomeSha256'] is None)
        for key in ('requestSha256', 'releaseSha256', 'planSha256'):
            hash_value(invocation[key])
            need(invocation[key] == base[key])
        need(type(invocation['stage']) is str and invocation['stage'] == base['stage'])
        for key in ('operationId', 'storeOperationId'):
            need(type(invocation[key]) is str and match('[a-f0-9]{32}', invocation[key]) is not None)
        need(invocation['stage'] != stages[0] or invocation['operationId'] == invocation['storeOperationId'])
        parent = invocation['parent']
        need(type(parent) is list and len(parent) == 7 and all(type(item) is str and 0 < len(item) <= 64 for item in parent))
        parent_pid = parse_uint(parent[0], 2, 2**31 - 1)
        directory_fd = parse_uint(parent[1], 3, 1048575)
        lock_fd = parse_uint(parent[2], 3, 1048575)
        need(directory_fd != lock_fd and parent_pid == base['parentPid']
             and parent[3:] == [base['session'], base['requestSha256'], base['stage'], base['actionSha256']])
        record = decode_json(record_raw, out_cap)
        closed(record, record_fields)
        need(type(record['schemaVersion']) is int and record['schemaVersion'] == 1
             and record['scope'] == 'FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY' and record['command'] == 'execute-stage'
             and record['planBase64'] is None and record['stageAcknowledged'] is False
             and record['fullInstallationCompleted'] is False and record['nativeQualified'] is False)
        # C._identity is a composite, unlike the old frame's raw delivery SHA.
        hash_value(record['deliveryIdentitySha256'])
        need(record['deliveryIdentitySha256'] == expected_identity)
        hash_value(record['outcomeSha256'])
        expected = {key: invocation[key] for key in record_binding_fields[:6]}
        expected.update(session=base['session'], actionSha256=base['actionSha256'])
        closed(record['binding'], record_binding_fields)
        need(all(type(value) is str for value in record['binding'].values()) and record['binding'] == expected)
        need(type(record['result']) is dict)
        result_data(record['result'], [0, 0])
        bound = dict(base)
        bound.update(executeInvocationSha256=digest(invocation_raw), completedRecordSha256=digest(record_raw))
        return bound

    def streams(stdout, stderr, record_raw):
        need(type(stdout) is bytes and type(stderr) is bytes and type(record_raw) is bytes
             and len(stdout) <= out_cap and len(stderr) <= err_cap and len(stdout) + len(stderr) <= total_cap)
        need(stdout == record_raw)  # Mandatory actual whole-body equality.
        return digest(stdout), len(stdout), digest(stderr), len(stderr)

    def frame(binding, out_hash, out_bytes, err_hash, err_bytes, exit_code):
        parts = ['ASET1'] + [str(binding[key]) for key in fields] + [out_hash, str(out_bytes), err_hash, str(err_bytes), str(exit_code)]
        raw = ('|'.join(parts) + '\n').encode('ascii')
        need(len(raw) <= maximum)
        return raw

    def encode_execution_status(binding, *, execute_invocation_raw, completed_record_raw,
            expected_delivery_identity_sha256, stdout, stderr, exit_code):
        base = binding_value(binding, base_fields)
        unsigned(exit_code, 0, 255)
        bound = execution_bytes(base, execute_invocation_raw, completed_record_raw, expected_delivery_identity_sha256)
        out_hash, out_bytes, err_hash, err_bytes = streams(stdout, stderr, completed_record_raw)
        return frame(bound, out_hash, out_bytes, err_hash, err_bytes, exit_code)

    def decode_execution_status(raw):
        """Syntax only. bind_execution_status is required for independent bytes."""
        need(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b'\n') and raw.count(b'\n') == 1
             and b'\r' not in raw and b'\0' not in raw)
        try:
            parts = raw[:-1].decode('ascii').split('|')
        except UnicodeError:
            raise error_type('company-execution-status-data-unavailable') from None
        need(len(parts) == 21 and parts[0] == 'ASET1')
        bound = dict(zip(fields, parts[1:16]))
        for key in ('parentPid', 'childPid'):
            bound[key] = parse_uint(bound[key], 2, 2**31 - 1)
        for key in ('parentStart', 'childStart'):
            bound[key] = parse_uint(bound[key], 2, 2**64 - 1)
        bound = binding_value(bound, fields)
        out_hash, out_bytes = hash_value(parts[16]), parse_uint(parts[17], 0, out_cap)
        err_hash, err_bytes = hash_value(parts[18]), parse_uint(parts[19], 0, err_cap)
        exit_code = parse_uint(parts[20], 0, 255)
        need(out_bytes + err_bytes <= total_cap and frame(bound, out_hash, out_bytes, err_hash, err_bytes, exit_code) == raw)
        return proxy(dict(scope='ASET1_EXECUTION_STATUS_DATA_ONLY', frame=raw, sha256=digest(raw), bytes=len(raw), binding=proxy(bound),
            stdout=proxy(dict(sha256=out_hash, bytes=out_bytes)), stderr=proxy(dict(sha256=err_hash, bytes=err_bytes)), exitCode=exit_code,
            invocationOriginQualified=False, completedRecordOriginQualified=False, deliveryIdentityOriginQualified=False,
            parentOriginQualified=False, parentWaitQualified=False, syscallEofQualified=False, knownCleanupQualified=False,
            sourceClosureQualified=False, crossProcessEvidenceIssued=False, stageAcknowledged=False))

    def bind_execution_status(raw, *, expected_binding, execute_invocation_raw, completed_record_raw,
            expected_delivery_identity_sha256, stdout, stderr, expected_exit_code):
        base = binding_value(expected_binding, base_fields)
        unsigned(expected_exit_code, 0, 255)
        expected = execution_bytes(base, execute_invocation_raw, completed_record_raw, expected_delivery_identity_sha256)
        out_hash, out_bytes, err_hash, err_bytes = streams(stdout, stderr, completed_record_raw)
        result = decode_execution_status(raw)
        need(all(result['binding'][key] == expected[key] for key in fields) and result['exitCode'] == expected_exit_code
             and result['stdout']['sha256'] == out_hash and result['stdout']['bytes'] == out_bytes
             and result['stderr']['sha256'] == err_hash and result['stderr']['bytes'] == err_bytes)
        return result

    return encode_execution_status, decode_execution_status, bind_execution_status


encode_execution_status, decode_execution_status, bind_execution_status = _make_codec(ExecutionStatusUnavailable)
del _make_codec
