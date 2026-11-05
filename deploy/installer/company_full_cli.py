"""Fixed full-retention controller; independently trusted entry is mandatory.

This module never authenticates its own first execution. The company supplies
the executing CLI/validator origin, independent delivery and V/P bootstrap pins,
and explicit trusted source/crypto/station/evidence collaborators. One context
owns one Q/F composition and its original V/P registries. Separate Bash worker
processes reauthenticate the same bytes. No Python ACK or full-install API exists.

The unconfigured template main refuses before IO. Native constructors are an
explicit API only; libc/interpreter/tool provenance, resource reservation and a
bounded OpenSSL supervisor remain company prerequisites, not flags in JSON.
"""
from contextlib import contextmanager, _GeneratorContextManager
import hashlib
import json
from pathlib import PurePosixPath
import re
import sys
from types import GeneratorType, MappingProxyType, ModuleType
import uuid

CLI = 'deploy/installer/company_full_cli.py'
REQUEST = 'deploy/installer/company_full_cli_request.py'
LOCK = 'scripts/install-lock.sh'
PUBLISHER = 'deploy/installer/build-full-package.py'
COMPOSITION = 'deploy/installer/company_full_package_loader.py'
STAGES = 'deploy/installer/company_stage_scope.py'
WORKER = 'deploy/installer/company_full_retention_worker.py'
EFFECTS = 'deploy/installer/company_retention_effects.py'
PARENT_SYSTEM = 'deploy/installer/company_parent_system.py'
SEED_BACKEND = 'deploy/installer/company_seed_backend.py'
SEED_RUNNER = 'deploy/installer/company_seed_runner.py'
LAUNCH_PATHS = (CLI, REQUEST, LOCK, PUBLISHER, COMPOSITION, STAGES, WORKER,
                EFFECTS, PARENT_SYSTEM, SEED_BACKEND, SEED_RUNNER)
BOOTSTRAP_PATHS = ('scripts/verify-release.py', 'scripts/installer_parent.py')
COMMANDS = ('describe', 'plan-stage', 'execute-stage', 'verify-stage')
MAX_BOOTSTRAP = 131072
MAX_RESULT = 32768
MAX_PLAN = 16384
UNRELEASED = []
_CLIS, _OBSERVATIONS = set(), set()
_CLI_OWNERS = {}
_OBSERVATION_RECORDS = {}
_CLOSED_OWNERS = {}
_EXPIRED_OWNERS = set()
_ATTEMPTS, _REQUESTS = {}, {}
_EFFECT_RETURNS = {}
_CM_OWNERS = {}
_NESTED_OWNERS = {}
MAX_CONTEXTS, MAX_OBSERVATIONS = 64, 1024
# A company-generated entry may bind this separately after reviewing delivery,
# native station and protected evidence IO. No config is read from the request.
CONFIGURED_MAIN = None


class FullCliUnavailable(ValueError):
    pass


def require(value):
    if value is not True:
        raise FullCliUnavailable('company-full-cli-unavailable')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _hash(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)


def _pin(value):
    require(type(value) is dict and set(value) == {'bytes', 'sha256'}
            and type(value['bytes']) is int and 0 < value['bytes'] <= MAX_BOOTSTRAP)
    _hash(value['sha256'])
    return dict(value)


def _namespace(module):
    require(type(module) is ModuleType)
    return {key: value for key, value in vars(module).items() if key != '__builtins__'}


def _same(module, expected):
    current = _namespace(module)
    require(set(current) == set(expected) and all(current[key] is expected[key] for key in expected))


def _decode(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    try:
        value = json.loads(raw)
        require(type(value) is dict and canonical(value) == raw)
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise FullCliUnavailable('company-full-cli-unavailable') from None
    return value


def _wire(value, depth=0, count=None):
    # Original Worker exposes an immutable source-closure mapping. Convert only
    # bounded exact builtin/plain values, never arbitrary JSON default methods.
    if count is None: count = [0, 0]
    count[0] += 1
    require(depth <= 16 and count[0] <= 2048)
    if value is None or type(value) is bool: return value
    if type(value) is int:
        require(-2**63 <= value < 2**64)
        return value
    if type(value) is str:
        require(len(value) <= MAX_RESULT)
        count[1] += len(value.encode('utf-8'))
        require(count[1] <= MAX_RESULT)
        return value
    if type(value) in (dict, MappingProxyType):
        require(len(value) <= 128 and all(type(key) is str and key.isascii()
                and 0 < len(key) <= 128 for key in value))
        count[1] += sum(len(key) for key in value)
        require(count[1] <= MAX_RESULT)
        return {key: _wire(item, depth+1, count) for key, item in value.items()}
    require(type(value) in (list, tuple) and len(value) <= 128)
    return [_wire(item, depth+1, count) for item in value]


def _bootstrap(records, pins, package_pins):
    # These are independent entry captures, never first extracted from the
    # candidate signed operational catalog or from its unsigned source tree.
    require(type(records) is dict and type(pins) is dict
            and set(records) == set(pins) == set(BOOTSTRAP_PATHS))
    captured = {}
    for path in BOOTSTRAP_PATHS:
        pin = _pin(pins[path])
        require(type(package_pins) is dict and path in package_pins and pin == _pin(package_pins[path]))
        raw = records[path]
        require(type(raw) is bytes and len(raw) == pin['bytes'] and sha(raw) == pin['sha256'])
        captured[path] = raw
    return MappingProxyType(captured)


def parse_argv(argv):
    """Fixed modes and protected logical paths only; no execution here."""
    require(type(argv) in (list, tuple) and 3 <= len(argv) <= 9
            and all(type(value) is str and value.isascii() and 0 < len(value) <= 1024
                    and '\0' not in value for value in argv))
    require(argv[0].startswith('--') and argv[0][2:] in COMMANDS and len(argv) % 2 == 1)
    command = argv[0][2:]
    pairs = list(zip(argv[1::2], argv[2::2]))
    require(len({name for name, value in pairs}) == len(pairs))
    fields = dict(pairs)
    wanted = {'--request'} if command == 'describe' else {'--request', '--invocation'}
    if command in ('execute-stage', 'verify-stage'):
        wanted.add('--plan')
    if command == 'verify-stage':
        wanted.add('--execution')
    require(set(fields) == wanted)
    request = re.fullmatch('/opt/autosoft-company/requests/([a-f0-9]{32})\\.json', fields['--request'])
    require(request is not None)
    operation = request.group(1)
    for name, value in fields.items():
        require(str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts)
        if name != '--request':
            leaf = {'--invocation': 'invocation.json', '--plan': 'plan.json', '--execution': 'executed.json'}[name]
            pattern = '/opt/autosoft-company/evidence/' + operation + '/(company-platform-store|company-source-materialize)/' + re.escape(leaf)
            require(re.fullmatch(pattern, value) is not None)
    stages = {PurePosixPath(value).parent.name for name, value in fields.items() if name != '--request'}
    require(len(stages) <= 1)
    return dict(command=command, operationId=operation, paths=fields,
                stage=next(iter(stages)) if stages else None)


def _register(path, raw, prefix, owned):
    name = prefix + path.replace('/', '_').replace('.', '_').replace('-', '_')
    require(name not in sys.modules)
    module = ModuleType(name)
    module.__file__ = '<independently admitted full CLI ' + path + '>'
    owned.append((name, module))
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def _retain(value, reason, *references):
    record = _CLI_OWNERS.get(id(value))
    require(type(record) is tuple and record[0] is value)
    state = record[1]
    _EXPIRED_OWNERS.add(id(value))
    dict.__setitem__(state, '_active', False)
    if dict.get(state, '_retained') is not True:
        dict.__setitem__(state, '_retained', True)
        UNRELEASED.append((value, reason, record, state.get('_composition_cm'),
                           state.get('_composition'), state.get('_raw'), *references))


def _owned_state(value):
    record = _CLI_OWNERS.get(id(value))
    require(type(record) is tuple and record[0] is value and type(value) is record[2])
    methods = dict(vars(record[2]))
    require(set(methods) == set(record[3]) and all(methods[key] is record[3][key] for key in methods))
    state = object.__getattribute__(value, '__dict__')
    require(type(state) is dict and state is record[1])
    require(all(dict.get(state, name) is ref for name, ref in record[4].items()))
    if record[5] is not None:
        expected, registrations, delivery, catalog = record[5]
        for name in ('_modules', '_snapshots', '_class_snapshots'):
            current = dict.get(state, name)
            require(type(current) is dict and all(type(key) is str for key in current)
                    and set(current) == {row[0] for row in expected})
        for path, module, namespace, classes in expected:
            require(state['_modules'][path] is module)
            _identity_items(state['_snapshots'][path], namespace)
            current = state['_class_snapshots'][path]
            require(type(current) is dict and len(current) == len(classes)
                    and all(any(key is kind for kind, old in classes) for key in current))
            for kind, old in classes: _identity_items(current[kind], old)
        current = state['_owned']
        require(type(current) is list)
        if id(value) in _CLOSED_OWNERS:
            require(len(current) == 0)
        else:
            require(len(current) == len(registrations)
                    and all(row is original for row, original in zip(current, registrations)))
        _identity_items(state['_delivery_snapshot'], delivery)
        _plain_match(state['_catalog'], catalog)
        attempts = dict.get(state, '_used')
        require(type(attempts) is set and all(type(row) is tuple and len(row) == 2
                and all(type(part) is str for part in row) for row in attempts)
                and attempts == _ATTEMPTS[id(value)])
        _cm_state(value)
        _nested_state(value)
    return state


def _identity_items(current, expected):
    require(type(current) is dict and all(type(key) is str for key in current)
            and set(current) == {key for key, value in expected})
    require(all(current[key] is value for key, value in expected))


def _plain_match(current, expected):
    require(type(current) is type(expected))
    if type(expected) is dict:
        require(all(type(key) is str for key in current) and set(current) == set(expected))
        for key in expected: _plain_match(current[key], expected[key])
    else:
        require(type(expected) in (str, int) and current == expected)


def _cm_state(value):
    record = _CM_OWNERS[id(value)]
    cm, state, kind, methods, instance, generator, enter, exit = record
    require(type(cm) is kind)
    _identity_items(dict(vars(kind)), methods)
    current = object.__getattribute__(cm, '__dict__')
    require(type(current) is dict and current is state)
    _identity_items(current, instance)
    require(type(generator) is GeneratorType and current['gen'] is generator)
    return record


def _nested_state(value):
    # Q/F preserve namespace identities, but an existing class object can have
    # its methods replaced without changing its module row. Check captured
    # original nested classes before calling any Q/F/V/P/L/BK boundary.
    for module, namespace, classes in _NESTED_OWNERS[id(value)]:
        _identity_items(_namespace(module), namespace)
        for kind, methods in classes: _identity_items(dict(vars(kind)), methods)


def _observation_record(value):
    record = _OBSERVATION_RECORDS.get(id(value))
    require(type(record) is tuple and len(record) == 8 and record[0] is value and type(value) is record[2])
    methods = dict(vars(record[2]))
    require(set(methods) == set(record[3]) and all(methods[key] is record[3][key] for key in methods))
    state = object.__getattribute__(value, '__dict__')
    require(type(state) is dict and state is record[1]
            and dict.get(state, '_owner') is record[4]
            and dict.get(state, '_record') is record[5]
            and dict.get(state, '_command') is record[6])
    owner_state = _owned_state(record[4])
    require(owner_state is record[7])
    return record


def _closed_owner(record):
    # Closure is issued only by this context's known finalizer. Public mutable
    # owner flags cannot manufacture it on a still-open or failed context.
    closed = _CLOSED_OWNERS.get(id(record[4]))
    require(type(closed) is tuple and closed[0] is _CLI_OWNERS[id(record[4])]
            and dict.get(record[7], '_closed') is True
            and dict.get(record[7], '_retained') is False
            and dict.get(record[7], '_failed') is False)
    return closed[1]


class CliObservation:
    """Privately issued result; terminal bytes require known CLI scope closure."""
    def __init__(self):
        self._owner = None

    def completed_record(self):
        record = _observation_record(self)
        _closed_owner(record)
        return record[5]


class FullCli:
    def __init__(self):
        require(len(_CLI_OWNERS) < MAX_CONTEXTS)
        self._active = self._closed = self._retained = self._busy = self._failed = False
        self._modules, self._raw, self._snapshots = {}, {}, {}
        self._class_snapshots = {}
        self._owned = []
        self._composition_cm = self._composition = None
        self._request_raw = None
        self._used = set()
        self._observations = []
        _CLI_OWNERS[id(self)] = (self, vars(self), type(self), dict(vars(type(self))),
            {name: getattr(self, name) for name in ('_modules', '_snapshots', '_class_snapshots', '_owned', '_used', '_observations')}, None)
        _ATTEMPTS[id(self)] = set()
        _EFFECT_RETURNS[id(self)] = []

    def _unknown(self):
        # Plain exact ledgers are checked before touching any context close.
        for path, module in self._modules.items():
            for name in ('UNRELEASED', 'UNRELEASED_RESOURCES'):
                if name in self._snapshots[path]:
                    original = self._snapshots[path][name]
                    current = vars(module).get(name)
                    if type(original) is not list or current is not original or len(original) != 0:
                        return True
        if self._composition is not None:
            F = self._F
            for module, name in ((F, 'UNRELEASED'),
                    (self._V, 'UNRELEASED_HANDLES'), (self._BK, 'UNRELEASED_RESOURCES'),
                    (self._entry.modules[F.GUARD], 'UNRELEASED_HANDLES')):
                value = vars(module).get(name)
                if type(value) is not list or len(value) != 0:
                    return True
        return False

    def recheck(self):
        issued = type(self) is FullCli and id(self) in _CLIS
        try:
            _owned_state(self)
            require(issued and id(self) not in _EXPIRED_OWNERS and self._active and not UNRELEASED)
            _same(self._delivery_module, self._delivery_snapshot)
            for path, module in self._modules.items():
                _same(module, self._snapshots[path])
                require(sys.modules.get(module.__name__) is module)
                for kind, old in self._class_snapshots[path].items():
                    current = dict(vars(kind))
                    require(set(current) == set(old) and all(current[key] is old[key] for key in old))
            require(not self._unknown())
            self._Q.FullComposition.recheck(self._composition)
            require(self._composition.entry is self._entry
                    and self._entry.modules[self._F.VERIFIER] is self._V
                    and self._entry.modules[self._F.PARENT] is self._P)
        except BaseException:
            if issued:
                _EXPIRED_OWNERS.add(id(self))
                dict.__setitem__(_CLI_OWNERS[id(self)][1], '_active', False)
                dict.__setitem__(_CLI_OWNERS[id(self)][1], '_failed', True)
            raise
        return self

    @property
    def original_modules(self):
        self.recheck()
        return MappingProxyType(dict(full_entry=self._F, verifier=self._V, parent=self._P,
                                     backend=self._BK, entry=self._entry))

    def native_stage_inputs(self, request_raw, *, os_module, sys_module, platform_module,
            select_module, ctypes_module, libc, subprocess_module, signal_module,
            io_module, fcntl_module, tool_catalog, backend_budget, runner_budget, clock,
            files, crypto):
        """Construct actual reviewed PS/SB/SR with explicit company station refs.

        No library is loaded and no source/crypto fallback is selected. Caller
        supplies explicit original-V files/crypto with a bounded, independently
        authenticated OpenSSL supervisor; SeedRunner cannot run OpenSSL.
        Capacity reservation and initial OS/libc/ELF provenance remain external.
        """
        self.recheck()
        request = self._modules[REQUEST].validate_request(request_raw, request_sha256=sha(request_raw))
        require(files is not None and crypto is not None and callable(clock))
        created = []
        try:
            dents = self._BK.LinuxAMD64Getdents64(ctypes_module=ctypes_module, libc=libc,
                sys_module=sys_module, machine_module=platform_module)
            created.append(dents)
            backend = self._modules[SEED_BACKEND].SeedBackend(request_value=request,
                budget=backend_budget, os_module=os_module, sys_module=sys_module,
                read_backend_module=self._BK, getdents64=dents, clock=clock)
            created.append(backend)
            runner = self._modules[SEED_RUNNER].SeedRunner(tool_catalog=tool_catalog,
                data_directory=request['dataDir'], storage_file=request['backingFile'], budget=runner_budget,
                os_module=os_module, sys_module=sys_module, subprocess_module=subprocess_module,
                select_module=select_module, signal_module=signal_module, io_module=io_module,
                fcntl_module=fcntl_module, clock=clock,
                station_contract=self._modules[SEED_RUNNER].STATION_CONTRACT)
            created.append(runner)
            system = self._modules[PARENT_SYSTEM].ParentSystem(self._P, os_module=os_module,
                sys_module=sys_module, platform_module=platform_module, select_module=select_module,
                ctypes_module=ctypes_module, libc=libc, backend_module=self._BK,
                getdents64=dents, clock=clock)
            created.append(system)
            self.recheck()
            return dict(files=files, crypto=crypto, backend_module=self._modules[SEED_BACKEND], backend=backend,
                runner_module=self._modules[SEED_RUNNER], runner=runner,
                parent_system_module=self._modules[PARENT_SYSTEM], parent_system=system, clock=clock)
        except BaseException:
            # Constructor failure may leave a tracked but unreturned resource.
            # Never invent successful release or invoke replacement cleanup.
            _retain(self, 'station-construction-unknown', tuple(created), os_module, libc, files, crypto)
            raise

    def _evidence(self, evidence, binding, evidence_module=None):
        if type(evidence) is CliObservation:
            original = _observation_record(evidence)
            require(original[6] == 'execute-stage'
                    and _closed_owner(original) == self._identity)
            record = _decode(original[5], MAX_RESULT)
        else:
            # A future separate Bash verification process needs genuine held
            # protected evidence plus direct-child disposition from trusted IO.
            # A dict, serialized true flag or public clone is never accepted.
            require(type(evidence_module) is ModuleType)
            kind = vars(evidence_module).get('HeldExecutionEvidence')
            validator = vars(evidence_module).get('require_known_execution')
            require(type(kind) is type and type(evidence) is kind and callable(validator))
            snapshot = _namespace(evidence_module)
            methods = dict(vars(kind))
            getter = methods.get('record_bytes')
            require(type(getter) is property and callable(getter.fget))
            raw = None
            try:
                require(validator(evidence) is evidence)
                _same(evidence_module, snapshot)
                current = dict(vars(kind))
                require(set(current) == set(methods) and all(current[key] is methods[key] for key in methods)
                        and type(evidence) is kind)
                raw = getter.fget(evidence)
                _same(evidence_module, snapshot)
                current = dict(vars(kind))
                require(set(current) == set(methods) and all(current[key] is methods[key] for key in methods))
                require(validator(evidence) is evidence and getter.fget(evidence) == raw)
                _same(evidence_module, snapshot)
                current = dict(vars(kind))
                require(set(current) == set(methods) and all(current[key] is methods[key] for key in methods)
                        and type(evidence) is kind)
            except BaseException:
                _retain(self, 'held-execution-evidence-unknown', evidence_module, evidence,
                        kind, validator, snapshot, methods, getter, raw)
                raise
            record = _decode(raw, MAX_RESULT)
        require(record['command'] == 'execute-stage'
                and record['binding'] == binding and record['deliveryIdentitySha256'] == self._identity)
        return record

    def dispatch(self, command, *, request_raw, request_sha256, invocation_raw=None,
            invocation_sha256=None, plan_raw=None, execution_evidence=None, evidence_module=None,
            files=None, crypto=None, backend_module=None, backend=None, runner_module=None,
            runner=None, parent_system_module=None, parent_system=None, clock=None):
        """Actual fixed describe/plan/execute/fresh-verify using original Worker.

        Every Worker call reissues its genuine HPS/assembly and closes original
        source/P/B/adapters before return. The Q/F scope remains owned here;
        completed_record becomes usable only after its separate known close.
        Separate process evidence requires independently trusted held IO, not a
        serialized completion flag. No method writes confirmation or ACK.
        """
        issued = type(self) is FullCli and id(self) in _CLIS
        try:
            self.recheck()
            require(self._busy is False and type(command) is str and command in COMMANDS)
            self._busy = True
            R, W = self._modules[REQUEST], self._modules[WORKER]
            request = R.validate_request(request_raw, request_sha256=request_sha256)
            if self._request_raw is None:
                self._request_raw = request_raw
            if id(self) not in _REQUESTS: _REQUESTS[id(self)] = request_raw
            require(request_raw == self._request_raw == _REQUESTS[id(self)])
            payload = None
            invocation = None
            if command == 'describe':
                require(('describe', command) not in self._used)
                self._used.add(('describe', command))
                _ATTEMPTS[id(self)].add(('describe', command))
                require(all(value is None for value in (invocation_raw, invocation_sha256, plan_raw,
                    execution_evidence, evidence_module, files, crypto, backend_module, backend,
                    runner_module, runner, parent_system_module, parent_system, clock)))
                payload = dict(operationId=request['operationId'], requestSha256=request_sha256,
                    releaseSha256=request['releaseSha256'], supportedStages=list(W.STAGES),
                    requiresQuietVerifiedFoundation=True, fullInstallationCompleted=False)
                binding = dict(requestSha256=request_sha256, releaseSha256=request['releaseSha256'])
            else:
                invocation = R.validate_invocation(invocation_raw, invocation_sha256=invocation_sha256,
                    request_raw=request_raw, request_sha256=request_sha256)
                require(invocation['command'] == command and callable(clock))
                token = (invocation['stage'], command)
                require(token not in self._used)
                self._used.add(token)  # Any attempted stage is consumed on error.
                _ATTEMPTS[id(self)].add(token)
                common = dict(entry=self._entry, full_entry_module=self._F, stage_module=self._modules[STAGES],
                    request_raw=request_raw, request_sha256=request_sha256, operational_catalog=self._catalog,
                    key_fingerprint=self._fingerprint, expected_architecture='amd64',
                    files=files, crypto=crypto, backend_module=backend_module, backend=backend,
                    runner_module=runner_module, runner=runner, operation_id=invocation['operationId'],
                    store_operation_id=invocation['storeOperationId'], clock=clock)
                binding = {key: invocation[key] for key in ('stage', 'requestSha256', 'releaseSha256',
                    'operationId', 'storeOperationId', 'planSha256')}
                if command == 'plan-stage':
                    require(all(value is None for value in (plan_raw, execution_evidence, evidence_module,
                        parent_system_module, parent_system)))
                    payload = W.plan_stage(invocation['stage'], **common)
                    require(type(payload) is bytes and 0 < len(payload) <= MAX_PLAN)
                else:
                    require(type(plan_raw) is bytes and 0 < len(plan_raw) <= MAX_PLAN
                            and sha(plan_raw) == invocation['planSha256'])
                    plan = _decode(plan_raw, MAX_PLAN)
                    require(plan['stage'] == invocation['stage'] and plan['installationRequestSha256'] == request_sha256)
                    parent = self._P.ParentInput.from_argv(invocation['parent'])
                    require(parent.action == plan['actionSha256'])
                    binding.update(session=parent.session, actionSha256=parent.action)
                    common.update(expected_plan=plan_raw, parent_arguments=parent,
                        parent_system_module=parent_system_module, parent_system=parent_system)
                    if command == 'execute-stage':
                        require(execution_evidence is None and evidence_module is None)
                        payload = W.execute_stage(invocation['stage'], **common)
                    else:
                        evidence = self._evidence(execution_evidence, binding, evidence_module)
                        require(evidence['outcomeSha256'] == invocation['outcomeSha256'])
                        payload = W.verify_stage(invocation['stage'], effect_verifier_module=self._modules[EFFECTS],
                            expected_outcome_sha256=invocation['outcomeSha256'], **common)
                    # Preserve the exact successful original W return before
                    # projection/emission can fail. This is not ACK or replay
                    # authority; post-return refusal retains this context.
                    returned = (command, invocation_raw, plan_raw, W, payload)
                    _EFFECT_RETURNS[id(self)].append(returned)
                    require(type(payload) is dict and payload['ownedResourcesKnownReleased'] is True
                            and payload['stageAcknowledged'] is False and payload['nativeAuthorized'] is False)
                    require(payload['stagePlanSha256'] == invocation['planSha256'])
                    _hash(payload['operationOutcomeSha256'])
                    outcome_raw = canonical(payload['operationResult'])
                    require(sha(outcome_raw) == payload['operationOutcomeSha256'])
                    _EFFECT_RETURNS[id(self)][-1] = (*returned, outcome_raw, payload['operationOutcomeSha256'])
            self.recheck()
            record = dict(schemaVersion=1, scope='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY', command=command,
                deliveryIdentitySha256=self._identity, binding=binding,
                planBase64=None, result=_wire(payload) if type(payload) is dict else None,
                outcomeSha256=payload.get('operationOutcomeSha256') if type(payload) is dict else None,
                stageAcknowledged=False, fullInstallationCompleted=False, nativeQualified=False)
            if type(payload) is bytes:
                import base64
                record['planBase64'] = base64.b64encode(payload).decode('ascii')
            raw = canonical(record)
            require(len(raw) <= MAX_RESULT)
            observation = CliObservation()
            require(len(_OBSERVATIONS) < MAX_OBSERVATIONS)
            observation._owner, observation._record, observation._command = self, raw, command
            _OBSERVATION_RECORDS[id(observation)] = (observation, vars(observation), type(observation),
                dict(vars(type(observation))), self, raw, command, _CLI_OWNERS[id(self)][1])
            self._observations.append(observation)
            _OBSERVATIONS.add(id(observation))
            return observation
        except BaseException:
            if issued:
                _EXPIRED_OWNERS.add(id(self))
                state = _CLI_OWNERS[id(self)][1]
                dict.__setitem__(state, '_active', False)
                dict.__setitem__(state, '_failed', True)
                if _EFFECT_RETURNS[id(self)]:
                    _retain(self, 'post-worker-return-refusal', tuple(_EFFECT_RETURNS[id(self)]))
            raise
        finally:
            if issued:
                dict.__setitem__(_CLI_OWNERS[id(self)][1], '_busy', False)


@contextmanager
def authenticated_cli(delivery_raw, *, delivery_module, delivery_pin, launch_pins,
        package_pins, operational_catalog, fingerprint, full_package_pin,
        bootstrap_records, bootstrap_pins, running_cli_raw):
    """Admit independent V/P bytes and all captures before a single compile.

    delivery_module and the running CLI are already independently authenticated
    company bootstrap code. Raw input equality is not initial origin proof.
    Package V/P bytes must equal that independently captured bootstrap pair.
    This factory alone owns launch modules and one original Q/F composition.
    """
    require(not UNRELEASED and type(delivery_module) is ModuleType)
    bootstrap = _bootstrap(bootstrap_records, bootstrap_pins, package_pins)
    snapshot = _namespace(delivery_module)
    require(tuple(delivery_module.LAUNCH_PATHS) == LAUNCH_PATHS)
    value = delivery_module.validate_delivery(delivery_raw, delivery_pin=delivery_pin,
        launch_pins=launch_pins, package_pins=package_pins, operational_catalog=operational_catalog,
        fingerprint=fingerprint, full_package_pin=full_package_pin)
    _same(delivery_module, snapshot)
    captures = value['launchCaptures']
    require(type(running_cli_raw) is bytes and running_cli_raw == captures[CLI])
    for path in BOOTSTRAP_PATHS:
        require(value['fullCaptures'][path] == bootstrap[path])
    controller = FullCli()
    controller._raw = MappingProxyType(dict(captures))
    controller._bootstrap = bootstrap
    controller._catalog, controller._fingerprint = value['operationalCatalog'], fingerprint
    controller._delivery_module, controller._delivery_snapshot = delivery_module, snapshot
    controller._identity = sha(canonical(dict(delivery=delivery_pin, package=package_pins,
        operational=operational_catalog, bootstrap=bootstrap_pins, fingerprint=fingerprint)))
    # Capture this finalizer before dispatch. It is never looked up on a changed
    # caller object, and uses original Q and owned module identities on unwind.
    body_good = False
    try:
        prefix = 'company_full_cli_' + uuid.uuid4().hex + '_'
        for path in LAUNCH_PATHS:
            if path not in (CLI, LOCK):
                controller._modules[path] = _register(path, captures[path], prefix, controller._owned)
        controller._snapshots.update({path: _namespace(module) for path, module in controller._modules.items()})
        controller._class_snapshots.update({path: {kind: dict(vars(kind)) for kind in vars(module).values()
            if type(kind) is type and kind.__module__ == module.__name__}
            for path, module in controller._modules.items()})
        Q, PB = controller._modules[COMPOSITION], controller._modules[PUBLISHER]
        controller._Q = Q
        cm = Q.authenticated_full_package(value['fullPackage'], package_module=PB,
            package_pins=package_pins, operational_catalog=operational_catalog, key_fingerprint=fingerprint)
        controller._composition_cm = cm
        kind = type(cm)
        require(kind is _GeneratorContextManager)
        methods = tuple(vars(kind).items())
        state = object.__getattribute__(cm, '__dict__')
        require(type(state) is dict and type(state.get('gen')) is GeneratorType)
        enter, exit = dict(methods)['__enter__'], dict(methods)['__exit__']
        require(callable(enter) and callable(exit))
        _CM_OWNERS[id(controller)] = (cm, state, kind, methods, tuple(state.items()), state['gen'], enter, exit)
        controller._composition = enter(cm)
        _CM_OWNERS[id(controller)] = (cm, state, kind, methods, tuple(state.items()), state['gen'], enter, exit)
        controller._F = controller._composition.modules[Q.FULL_ENTRY]
        controller._entry = controller._composition.entry
        F = controller._F
        controller._V, controller._P, controller._BK = (controller._entry.modules[path] for path in
            (F.VERIFIER, F.PARENT, F.BACKEND))
        controller._origin = controller._entry.origin
        controller._L = controller._entry.modules[F.LOADER]
        nested = (*controller._composition.modules.values(), *controller._entry.modules.values())
        require(len(nested) == 9 and len({id(module) for module in nested}) == 9)
        _NESTED_OWNERS[id(controller)] = tuple((module, tuple(_namespace(module).items()),
            tuple((kind, tuple(vars(kind).items())) for kind in vars(module).values()
                if type(kind) is type and kind.__module__ == module.__name__)) for module in nested)
        # Initial configuration and original context references are immutable
        # admission state, alongside the plain owned collections above.
        _CLI_OWNERS[id(controller)][4].update({name: getattr(controller, name) for name in
            ('_raw', '_bootstrap', '_catalog', '_fingerprint', '_delivery_module',
             '_delivery_snapshot', '_identity', '_Q', '_F', '_entry', '_V', '_P',
             '_BK', '_L', '_origin', '_composition_cm', '_composition')})
        record = _CLI_OWNERS[id(controller)]
        trust = (tuple((path, module, tuple(controller._snapshots[path].items()),
                       tuple((kind, tuple(old.items())) for kind, old in controller._class_snapshots[path].items()))
                       for path, module in controller._modules.items()),
                 tuple(controller._owned), tuple(snapshot.items()), json.loads(canonical(controller._catalog)))
        _CLI_OWNERS[id(controller)] = (*record[:5], trust)
        controller._active = True
        _CLIS.add(id(controller))
        controller.recheck()
        yield controller
        controller.recheck()
        body_good = True
    finally:
        state = _CLI_OWNERS[id(controller)][1]
        dict.__setitem__(state, '_active', False)
        if not body_good:
            dict.__setitem__(state, '_failed', True)
        _CLIS.discard(id(controller))
        failed = False
        try:
            _owned_state(controller)
            require(dict.get(state, '_retained') is False)
            for path, module in controller._modules.items():
                _same(module, controller._snapshots[path])
                for kind, old in controller._class_snapshots[path].items():
                    current = dict(vars(kind))
                    require(set(current) == set(old) and all(current[key] is old[key] for key in old))
            require(not controller._unknown())
            if controller._composition is not None:
                cm_record = _cm_state(controller)
                controller._Q.FullComposition.recheck(controller._composition)
                cm_record[7](cm_record[0], None, None, None)
                require(cm_record[5].gi_frame is None
                        and controller._composition._active is False
                        and controller._composition not in controller._Q._COMPOSITIONS
                        and controller._entry not in controller._F._ISSUED_ENTRIES
                        and controller._origin not in controller._L._ENTRIES)
            registrations = _CLI_OWNERS[id(controller)][5][1] if _CLI_OWNERS[id(controller)][5] is not None else tuple(controller._owned)
            for name, module in reversed(registrations):
                require(sys.modules.get(name) is module)
                del sys.modules[name]
            controller._owned.clear()
            dict.__setitem__(state, '_closed', True)
            if body_good and dict.get(state, '_failed') is False:
                _CLOSED_OWNERS[id(controller)] = (_CLI_OWNERS[id(controller)], controller._identity)
        except BaseException as error:
            failed = True
            _retain(controller, 'cli-composition-release-unknown', error)
        if failed:
            raise FullCliUnavailable('company-full-cli-release-unknown')


def main(argv=None):
    # The new source API is usable only through explicitly admitted inputs.
    # No request/catalog/serialized record can configure initial native trust.
    require(CONFIGURED_MAIN is not None)
    raise FullCliUnavailable('company-full-cli-main-unconfigured')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except BaseException:
        print('company-full-cli-unavailable; retain partial evidence', file=sys.stderr)
        raise SystemExit(74)
