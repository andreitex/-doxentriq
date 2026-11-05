"""Publish an original, fully closed CLI record through explicit trusted IO.

The company authenticates this module, the original CLI/record reader and the
IO issuer before calling it. ModuleType/type checks do not establish that origin.
The IO issuer must privately track its inputs/outputs and known release; this
module cannot prove unrelated caller resource closure. No native IO, executable
selection, evidence issuer or ACK is provided. The template main always refuses.
"""
import hashlib
import json
import re
from types import FunctionType, MappingProxyType, ModuleType

MAX_RECORD = 32768
MAX_REQUEST = 4096
MAX_INVOCATION = 4096
MAX_PLAN = 16384
MAX_PUBLISHERS = 64
UNRELEASED = []


class RecordPublishUnavailable(ValueError):
    pass


def _factory(unknown, exception):
    # All operational and failure helpers use this finite captured namespace.
    # Public ledger replacement/clearing cannot restart a failed publisher.
    module_type, function_type, proxy = ModuleType, FunctionType, MappingProxyType
    raw_sha, loads, dumps, match = hashlib.sha256, json.loads, json.dumps, re.fullmatch
    records, used_io, retained = {}, [], []
    failed = False
    command = 'execute-stage'
    fields = ('request_raw', 'request_sha256', 'invocation_raw', 'invocation_sha256',
              'plan_raw', 'files', 'crypto', 'backend_module', 'backend',
              'runner_module', 'runner', 'parent_system_module', 'parent_system', 'clock')
    limits = (MAX_RECORD, MAX_REQUEST, MAX_INVOCATION, MAX_PLAN, MAX_PUBLISHERS)

    def need(value):
        if value is not True:
            raise exception('company-cli-record-publish-unavailable')

    def namespace(module):
        need(type(module) is module_type)
        value = dict(vars(module))
        need(len(value) <= 512 and all(type(key) is str for key in value))
        return tuple(value.items())

    def same(module, original):
        current = namespace(module)
        need(len(current) == len(original))
        current = dict(current)
        need(all(key in current and current[key] is item for key, item in original))

    def classes(module):
        result = []
        name = vars(module).get('__name__')
        need(type(name) is str)
        for key, item in namespace(module):
            if type(item) is type:
                owner = type.__getattribute__(item, '__module__')
                need(type(owner) is str)
            if type(item) is type and owner == name:
                table = tuple(vars(item).items())
                need(len(table) <= 128 and all(type(name) is str for name, value in table))
                result.append((item, table))
        return tuple(result)

    def class_same(kind, original):
        need(type(kind) is type)
        current = dict(vars(kind))
        need(all(type(key) is str for key in current) and len(current) == len(original))
        need(all(key in current and current[key] is item for key, item in original))

    def function(module, name):
        value = vars(module).get(name)
        need(type(value) is function_type and value.__globals__ is vars(module))
        return value

    def decode(raw, maximum):
        need(type(raw) is bytes and 0 < len(raw) <= maximum)
        def pairs(rows):
            value = {}
            for key, item in rows:
                need(type(key) is str and key not in value)
                value[key] = item
            return value
        try:
            value = loads(raw.decode('ascii'), object_pairs_hook=pairs,
                          parse_constant=lambda value: need(False))
            need(type(value) is dict and dumps(value, sort_keys=True, separators=(',', ':'),
                ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n' == raw)
        except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
            raise exception('company-cli-record-publish-unavailable') from None
        return value

    def pin(raw, expected, maximum):
        need(type(expected) is str and match('[a-f0-9]{64}', expected) is not None)
        decode(raw, maximum)
        need(raw_sha(raw).hexdigest() == expected)

    def guard(record):
        need(not failed and not retained and type(unknown) is list and not unknown)
        class_same(publisher_kind, publisher_methods)
        for module, original, kinds in record['modules']:
            same(module, original)
            for kind, table in kinds:
                class_same(kind, table)
        need(type(record['io']) is record['io_kind']
             and object.__getattribute__(record['io'], '__dict__') is record['io_state'])

    def retain(record, reason, error=None):
        nonlocal failed
        failed = True
        record['failed'] = True
        row = (record, reason, error, record.get('cli'), record.get('observation'),
               record.get('raw'), record.get('written'), record.get('io'))
        retained.append(row)
        unknown.append(row)

    def owned(value):
        record = records.get(id(value))
        need(type(value) is publisher_kind and type(record) is dict and record['value'] is value)
        need(record['failed'] is False)
        try:
            class_same(publisher_kind, publisher_methods)
            guard(record)
        except BaseException as error:
            retain(record, 'publisher-boundary-unavailable', error)
            raise exception('company-cli-record-publish-unavailable') from None
        return record

    def io_check(record, name):
        guard(record)
        need(record['io_checks'][name](record['io']) is record['io'])
        guard(record)

    def boundary(record, name, *args):
        io_check(record, 'require_publisher_io')
        record['io_attempts'].append((name, args))
        result = record['io_methods'][name](record['io'], *args)
        # Preserve an actual successful return before a post-call identity
        # check can refuse. It is retained DATA, never an issuance/retry flag.
        record['io_returns'].append((name, args, result))
        guard(record)
        return result

    class RecordPublisher:
        __slots__ = ()

        def execute(self, cli):
            record = owned(self)
            need(record['phase'] == 'prepared')
            record['phase'] = 'execute-attempted'  # Consumed before the original call.
            record['cli'] = cli
            try:
                need(type(cli) is record['cli_kind'])
                guard(record)
                need(record['recheck'](cli) is cli)
                guard(record)
                state = object.__getattribute__(cli, '__dict__')
                need(type(state) is dict and type(state.get('_identity')) is str
                     and match('[a-f0-9]{64}', state['_identity']) is not None)
                record['delivery_identity'] = state['_identity']
                observation = record['dispatch'](cli, command, **dict(record['arguments']))
                record['observation'] = observation  # Retain the exact returned instance first.
                guard(record)
                need(type(observation) is record['observation_kind'])
                record['phase'] = 'executed'
            except BaseException as error:
                retain(record, 'original-dispatch-unavailable', error)
                raise exception('company-cli-record-publish-unavailable') from None
            return self

        def publish(self):
            record = owned(self)
            need(record['phase'] == 'executed')
            record['phase'] = 'publish-attempted'
            close_attempted = False
            try:
                guard(record)
                need(boundary(record, 'release_inputs') is record['io'])
                io_check(record, 'require_inputs_released')
                # This saved original reader calls original completed_record:
                # public flags or an arbitrary IO callback cannot close the CLI.
                data = record['reader'](record['observation'])
                guard(record)
                need(type(data) is proxy and type(data.get('record')) is bytes)
                raw = data['record']
                record['raw'] = raw
                value = decode(raw, limits[0])
                need(value['command'] == command and value['binding'] == record['binding']
                     and value['deliveryIdentitySha256'] == record['delivery_identity'])
                need(type(value['outcomeSha256']) is str
                     and match('[a-f0-9]{64}', value['outcomeSha256']) is not None)
                written = boundary(record, 'write_stdout', raw)
                record['written'] = written
                need(type(written) is int and written == len(raw))
                close_attempted = True
                need(boundary(record, 'close_outputs') is record['io'])
                io_check(record, 'require_released')
                record['phase'] = 'published'
                return proxy(dict(scope='ORIGINAL_CLI_RECORD_PUBLISHED_DATA_ONLY', command=command,
                    recordSha256=raw_sha(raw).hexdigest(), recordBytes=len(raw),
                    outcomeSha256=value['outcomeSha256'], outputsKnownReleased=True,
                    crossProcessEvidenceIssued=False, parentTerminalQualified=False,
                    stageAcknowledged=False, installerActivated=False))
            except BaseException as error:
                # Do not retry a partial write or an uncertain close. Safe
                # original output disposal is attempted once only while its
                # complete original boundary remains admitted.
                cleanup_error = None
                if not close_attempted:
                    try:
                        guard(record)
                        close_attempted = True
                        need(boundary(record, 'close_outputs') is record['io'])
                    except BaseException as problem:
                        cleanup_error = problem
                retain(record, 'record-publication-unavailable', (error, cleanup_error))
                raise exception('company-cli-record-publish-unavailable') from None

    publisher_kind = RecordPublisher
    publisher_methods = tuple(vars(publisher_kind).items())

    def prepare_publish(cli_module, record_reader_module, *, dispatch_arguments, io_module, io):
        """Capture exact execute arguments and authenticated collaborators once.

        IO contract: exact privately issued PublisherIO with module-level
        require_publisher_io/require_inputs_released/require_released validators,
        and original release_inputs/write_stdout/close_outputs methods. These
        validators must consult their private ownership registry, not flags.
        Initial IO authenticity and complete coverage of unrelated inputs remain
        external prerequisites. There is no native/default IO constructor here.
        """
        need(not failed and not retained and type(unknown) is list and not unknown)
        need(len(records) < limits[4] and type(dispatch_arguments) is dict
             and all(type(key) is str for key in dispatch_arguments)
             and set(dispatch_arguments) == set(fields))
        args = tuple((name, dispatch_arguments[name]) for name in fields)
        values = dict(args)
        pin(values['request_raw'], values['request_sha256'], limits[1])
        pin(values['invocation_raw'], values['invocation_sha256'], limits[2])
        plan = decode(values['plan_raw'], limits[3])
        invocation = decode(values['invocation_raw'], limits[2])
        need(invocation.get('command') == command
             and invocation.get('planSha256') == raw_sha(values['plan_raw']).hexdigest()
             and invocation.get('requestSha256') == values['request_sha256']
             and type(invocation.get('parent')) is list and len(invocation['parent']) == 7)
        binding_keys = ('stage', 'requestSha256', 'releaseSha256', 'operationId',
                        'storeOperationId', 'planSha256')
        need(all(key in invocation for key in binding_keys))
        binding = {key: invocation[key] for key in binding_keys}
        need(type(invocation['parent'][3]) is str and type(invocation['parent'][6]) is str)
        binding.update(session=invocation['parent'][3], actionSha256=invocation['parent'][6])
        need(plan.get('actionSha256') == binding['actionSha256'])
        original = namespace(cli_module)
        cli_kind = vars(cli_module).get('FullCli')
        observation_kind = vars(cli_module).get('CliObservation')
        need(type(cli_kind) is type and type(observation_kind) is type)
        cli_methods = dict(vars(cli_kind))
        dispatch, recheck = cli_methods.get('dispatch'), cli_methods.get('recheck')
        need(type(dispatch) is function_type and dispatch.__globals__ is vars(cli_module)
             and type(recheck) is function_type and recheck.__globals__ is vars(cli_module))
        reader_namespace = namespace(record_reader_module)
        prepare_reader = function(record_reader_module, 'prepare_record_reader')
        io_namespace = namespace(io_module)
        io_kind = vars(io_module).get('PublisherIO')
        need(type(io_kind) is type and type(io) is io_kind)
        io_state = object.__getattribute__(io, '__dict__')
        need(type(io_state) is dict and not any(item is io for item in used_io))
        methods = dict(vars(io_kind))
        io_methods = {name: methods.get(name) for name in ('release_inputs', 'write_stdout', 'close_outputs')}
        need(all(type(value) is function_type and value.__globals__ is vars(io_module)
                 for value in io_methods.values()))
        io_checks = {name: function(io_module, name) for name in
                     ('require_publisher_io', 'require_inputs_released', 'require_released')}
        modules = [(cli_module, original, classes(cli_module)),
                   (record_reader_module, reader_namespace, classes(record_reader_module)),
                   (io_module, io_namespace, classes(io_module))]
        for name in ('backend_module', 'runner_module', 'parent_system_module'):
            module = values[name]
            modules.append((module, namespace(module), classes(module)))
        record = dict(value=None, failed=False, phase='preparing', modules=tuple(modules),
            arguments=args, argumentPins=tuple((name, len(values[name]), raw_sha(values[name]).hexdigest())
                for name in ('request_raw', 'invocation_raw', 'plan_raw')),
            binding=binding, cli_kind=cli_kind, observation_kind=observation_kind,
            dispatch=dispatch, recheck=recheck, io=io, io_kind=io_kind, io_state=io_state,
            io_methods=io_methods, io_checks=io_checks, reader=None, cli=None,
            observation=None, raw=None, written=None, delivery_identity=None,
            io_attempts=[], io_returns=[])
        try:
            guard(record)
            io_check(record, 'require_publisher_io')
            record['reader'] = prepare_reader(cli_module, expected_command=command)
            need(type(record['reader']) is function_type)
            guard(record)
            value = object.__new__(publisher_kind)
            record.update(value=value, phase='prepared')
            records[id(value)] = record
            used_io.append(io)
            return value
        except BaseException as error:
            retain(record, 'publisher-admission-unavailable', error)
            raise exception('company-cli-record-publish-unavailable') from None

    return publisher_kind, prepare_publish


RecordPublisher, prepare_publish = _factory(UNRELEASED, RecordPublishUnavailable)
del _factory


def main(argv=None):
    raise RecordPublishUnavailable('company-cli-record-publish-main-unconfigured')


if __name__ == '__main__':
    raise SystemExit(74)
