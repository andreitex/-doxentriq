"""Packaged native Store/Source worker; not a complete installation command.

IT authenticates the emitted worker out of band and runs it in a clean isolated
root Python process. Only signed schema4 source is eligible. Execute/verify must
be a direct child of the trusted Bash admission parent. This worker never ACKs
that parent and never activates services, overwrites a stage or retries effects.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from types import ModuleType

PACKAGE = None  # @NATIVE_RETENTION_PACKAGE@
STAGES = ('company-platform-store', 'company-source-materialize')


def require(value, reason='native-retention-unavailable'):
    if value is not True:
        raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def load_package(package=PACKAGE):
    require(type(package) is dict and set(package) == {'programs', 'delivery', 'authentication'})
    captured = {}
    for name, row in package['programs'].items():
        require(type(name) is str and re.fullmatch('[a-z_]+', name) is not None
                and set(row) == {'bytes', 'sha256', 'base64'})
        raw = base64.b64decode(row['base64'], validate=True)
        require(0 < len(raw) <= 131072 and len(raw) == row['bytes'] and sha(raw) == row['sha256'])
        captured[name] = raw
    require(set(captured) == {'cli', 'delivery', 'record', 'store', 'crypto', 'station', 'request', 'records'})
    delivery = base64.b64decode(package['delivery'], validate=True)
    auth = dict(package['authentication'])
    require(len(delivery) == auth['delivery_pin']['bytes'] and sha(delivery) == auth['delivery_pin']['sha256'])
    auth['bootstrap_records'] = {path: base64.b64decode(raw, validate=True) for path, raw in auth['bootstrap_records'].items()}
    modules = {}
    # Validate every byte capture before executing any of them. The whole
    # package's company delivery authenticity is an external prerequisite.
    for name, raw in captured.items():
        module = ModuleType('company_native_' + name)
        require(module.__name__ not in sys.modules)
        module.__file__ = '<company packaged ' + name + '>'
        sys.modules[module.__name__] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        modules[name] = module
    auth.update(delivery_module=modules['delivery'], running_cli_raw=captured['cli'])
    return modules, delivery, auth


def invocation(request, request_raw, stage, command, *, parent=None, plan=None, outcome=None):
    return canonical(dict(schemaVersion=1, scope='FULL_RETENTION_CLI_INVOCATION_ONLY',
        command=command, stage=stage, requestSha256=sha(request_raw),
        releaseSha256=request['releaseSha256'], operationId=request['operationId'] if stage == STAGES[0]
            else sha(('source:'+request['operationId']).encode())[:32],
        storeOperationId=request['operationId'], planSha256=sha(plan) if plan else None,
        outcomeSha256=outcome, parent=parent))


def run_stage(modules, delivery, auth, command, request_raw, invocation_raw, *, plan=None, execution=None):
    C, S = modules['cli'], modules['station']
    reader = modules['record'].prepare_record_reader(C, expected_command=command)
    collaborators = None
    with C.authenticated_cli(delivery, **auth) as controller:
        collaborators = S.stage_inputs(controller, request_raw, modules['crypto'])
        supplied = dict(collaborators)
        if command == 'plan-stage':
            supplied.pop('parent_system_module')
            supplied.pop('parent_system')
        observation = controller.dispatch(command, request_raw=request_raw,
            request_sha256=sha(request_raw), invocation_raw=invocation_raw,
            invocation_sha256=sha(invocation_raw), plan_raw=plan,
            execution_evidence=execution, **supplied)
        S.require_released(collaborators)
    S.require_released(collaborators)
    return observation, reader(observation)['record']


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('plan-stage', 'execute-verify', 'inspect-completion'))
    p.add_argument('--request', required=True)
    p.add_argument('--stage', choices=STAGES, required=True)
    p.add_argument('--parent', nargs=7)
    p.add_argument('--persist', action='store_true')
    a = p.parse_args(argv)
    require(type(PACKAGE) is dict, 'company-packaged-worker-required')
    modules, delivery, auth = load_package()
    S = modules['station']
    S.baseline()
    require(re.fullmatch(r'/opt/autosoft-company/requests/[a-f0-9]{32}\.json', a.request) is not None)
    request_raw = S.read_protected(a.request, 4096)
    request = modules['request'].validate_request(request_raw, request_sha256=sha(request_raw))
    require(Path(a.request).stem == request['operationId'] and request['operationId'] != '0'*32)
    directory = Path('/opt/autosoft-company/evidence') / request['operationId'] / a.stage
    R = modules['records']
    identity = R.delivery_identity(auth)
    if a.command == 'plan-stage':
        require(a.parent is None)
        _, raw = run_stage(modules, delivery, auth, 'plan-stage', request_raw,
            invocation(request, request_raw, a.stage, 'plan-stage'))
        # The original closed planning record is DATA, not execution evidence.
        if a.persist:
            plan, action = R.planning_record(raw, request, request_raw, a.stage, identity)
            R.prepare_stage(request['operationId'], a.stage)
            R.write_record(str(directory), 'planned.json', raw)
            R.write_record(str(directory), 'plan.json', plan)
            print(action)
        else:
            sys.stdout.buffer.write(raw)
        return
    require(a.parent is not None)
    plan = S.read_protected(directory / 'plan.json', 16384)
    require(canonical(json.loads(plan)) == plan)
    if a.command == 'inspect-completion':
        require(not a.persist)
        # Origin and child-exit qualification remain the trusted Bash parent's
        # responsibility. Independently hold its live pidfd/lock evidence here.
        with modules['cli'].authenticated_cli(delivery, **auth) as controller:
            P = controller.original_modules['parent']
            parent_input = P.ParentInput.from_argv(a.parent)
            require(parent_input.request == sha(request_raw) and parent_input.stage == a.stage)
            with P.hold_parent(parent_input) as parent:
                parent.check()
                planned = S.read_protected(directory / 'planned.json', 32768)
                require(R.planning_record(planned, request, request_raw, a.stage, identity)[0] == plan)
                marker = R.completion(S.read_protected(directory / 'executed.json',32768),
                    S.read_protected(directory / 'verified.json',32768), plan,
                    request, request_raw, a.stage, a.parent, identity)
                parent.check()
        R.write_record(str(directory), 'confirmation', marker, mode=0o600)
        return
    require(not os.path.lexists(directory / 'executed.json'), 'stage-already-executed-reconciliation-required')
    call = invocation(request, request_raw, a.stage, 'execute-stage', parent=a.parent, plan=plan)
    observation, executed = run_stage(modules, delivery, auth, 'execute-stage', request_raw, call, plan=plan)
    result = json.loads(executed)
    # Existing protected exclusive-file protocol, not a new completion format.
    before = S.metadata(os.stat(directory, follow_symlinks=False))
    modules['store'].store_executed_record(str(directory), expected_directory_metadata=before,
        completed_record_raw=executed, os_module=os, sys_module=sys,
        fcntl_module=S.fcntl, clock=time.monotonic)
    require(S.read_protected(directory / 'executed.json', 32768) == executed)
    verification_call = invocation(request, request_raw, a.stage, 'verify-stage', parent=a.parent,
        plan=plan, outcome=result['outcomeSha256'])
    _, verified = run_stage(modules, delivery, auth, 'verify-stage', request_raw, verification_call,
        plan=plan, execution=observation)
    check = json.loads(verified)
    require(check['outcomeSha256'] == result['outcomeSha256']
            and check['result']['operationResult'] == result['result']['operationResult'])
    # The original closed verification record goes to the trusted Bash parent.
    # Only that parent may confirm after observing this process exit successfully.
    if a.persist:
        R.completion(executed, verified, plan, request, request_raw, a.stage, a.parent, identity)
        R.write_record(str(directory), 'verified.json', verified)
    else:
        sys.stdout.buffer.write(verified)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('native-retention-unavailable; preserve partial effects and parent admission evidence', file=sys.stderr)
        sys.exit(74)
