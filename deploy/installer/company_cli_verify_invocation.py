"""Derive a fresh verification invocation from bound immutable execution DATA.

Company authentication of this module and the original request/status modules
precedes construction. Status, closure flags and hashes confer no live parent,
execution evidence, approval, acknowledgement or installation authority.
No IO, process, runtime default or effect is selected here.
"""
import hashlib
import json
from types import FunctionType, MappingProxyType, ModuleType


class VerifyInvocationUnavailable(ValueError):
    pass


def prepare_verification_builder(request_module, status_module):
    """Capture original pure validators; all origin qualification is external."""
    error = VerifyInvocationUnavailable
    function_kind, module_kind, proxy = FunctionType, ModuleType, MappingProxyType
    digest, dumps, loads = hashlib.sha256, json.dumps, json.loads
    snapshots, functions = [], []

    def need(value):
        if value is not True:
            raise error('company-cli-verify-invocation-unavailable')

    def same(current, expected):
        need(type(current) is dict and all(type(key) is str for key in current)
             and len(current) == len(expected)
             and all(key in current and current[key] is value for key, value in expected))

    for module in (request_module, status_module):
        need(type(module) is module_kind)
        table = tuple(vars(module).items())
        need(len(table) <= 512 and all(type(key) is str for key, value in table))
        module_name = dict(table).get('__name__')
        need(type(module_name) is str)
        classes = []
        for value in dict(table).values():
            if type(value) is not type:
                continue
            owner_name = type.__getattribute__(value, '__module__')
            need(type(owner_name) is str)
            if owner_name == module_name:
                entries = tuple(vars(value).items())
                need(len(entries) <= 128 and all(type(key) is str for key, item in entries))
                classes.append((value, entries))
        snapshots.append((module, table, tuple(classes)))

    def original(module, name):
        value = vars(module).get(name)
        need(type(value) is function_kind and value.__globals__ is vars(module))
        closure = value.__closure__
        cells = () if closure is None else tuple(cell.cell_contents for cell in closure)
        functions.append((value, value.__code__, closure, cells,
                          value.__defaults__, value.__kwdefaults__, tuple(vars(value).items())))
        return value

    validate_request = original(request_module, 'validate_request')
    validate_invocation = original(request_module, 'validate_invocation')
    bind_status = original(status_module, 'bind_execution_status')

    def guard():
        for module, table, classes in snapshots:
            same(dict(vars(module)), table)
            for kind, entries in classes:
                same(dict(vars(kind)), entries)
        for value, code, closure, cells, defaults, kwdefaults, attributes in functions:
            need(value.__code__ is code and value.__closure__ is closure
                 and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults)
            same(dict(vars(value)), attributes)
            if closure is not None:
                need(len(closure) == len(cells)
                     and all(cell.cell_contents is saved for cell, saved in zip(closure, cells)))

    def canonical(value):
        return dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False).encode('ascii') + b'\n'

    def build(*, request_raw, execute_invocation_raw, completed_record_raw,
              execution_status_raw, expected_binding, expected_delivery_identity_sha256,
              stdout, stderr, expected_exit_code):
        """Pure DATA preparation. A fresh verifier must hold genuine evidence."""
        guard()
        for raw, cap in ((request_raw,4096),(execute_invocation_raw,4096),
                         (completed_record_raw,32768),(execution_status_raw,2048)):
            need(type(raw) is bytes and 0 < len(raw) <= cap)
        # A failed execute status cannot produce a success-verification request.
        # The supplied zero remains DATA, not an original Bash wait observation.
        need(type(expected_exit_code) is int and expected_exit_code == 0)
        request_sha = digest(request_raw).hexdigest()
        validated_request = validate_request(request_raw, request_sha256=request_sha)
        guard()
        need(type(validated_request) is dict)
        invocation = validate_invocation(execute_invocation_raw,
            invocation_sha256=digest(execute_invocation_raw).hexdigest(),
            request_raw=request_raw, request_sha256=request_sha)
        guard()
        need(type(invocation) is dict and invocation['command'] == 'execute-stage')
        bound = bind_status(execution_status_raw, expected_binding=expected_binding,
            execute_invocation_raw=execute_invocation_raw, completed_record_raw=completed_record_raw,
            expected_delivery_identity_sha256=expected_delivery_identity_sha256,
            stdout=stdout, stderr=stderr, expected_exit_code=expected_exit_code)
        guard()
        need(type(bound) is proxy and bound['scope'] == 'ASET1_EXECUTION_STATUS_DATA_ONLY')
        # The original status validator has bounded and canonicalized these
        # exact bytes. Rederive the outcome from the whole operation result;
        # there is no caller-selected outcome or replacement parent argv.
        record = loads(completed_record_raw)
        result = record['result']
        need(type(result) is dict and type(result.get('operationResult')) is dict)
        outcome = digest(canonical(result['operationResult'])).hexdigest()
        need(result.get('operationOutcomeSha256') == record['outcomeSha256'] == outcome
             and result.get('stagePlanSha256') == invocation['planSha256'])
        verify = dict(invocation)
        verify.update(command='verify-stage', outcomeSha256=outcome,
                      parent=list(invocation['parent']))
        raw = canonical(verify)
        need(len(raw) <= 4096)
        checked = validate_invocation(raw, invocation_sha256=digest(raw).hexdigest(),
            request_raw=request_raw, request_sha256=request_sha)
        guard()
        need(type(checked) is dict and canonical(checked) == raw)
        return proxy(dict(scope='FRESH_VERIFY_INVOCATION_DATA_ONLY', invocation=raw,
            invocationSha256=digest(raw).hexdigest(), invocationBytes=len(raw),
            executeInvocationSha256=digest(execute_invocation_raw).hexdigest(),
            completedRecordSha256=digest(completed_record_raw).hexdigest(),
            executionStatusSha256=digest(execution_status_raw).hexdigest(),
            outcomeSha256=outcome, executionEvidenceIssued=False, parentWaitQualified=False,
            stageAcknowledged=False, installerActivated=False))

    guard()
    return build


def main(argv=None):
    raise VerifyInvocationUnavailable('company-cli-verify-invocation-main-unconfigured')


if __name__ == '__main__':
    raise SystemExit(74)
