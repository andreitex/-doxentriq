"""Fixed execute-child composition; independently authenticated origins required.

This helper owns only the original CLI factory context. PublisherIO, source files,
crypto, station resources and the exclusive endpoint/OFD graph are explicitly
supplied company prerequisites. No native selection, child process, completion
issuer, Bash wait/ACK or configured main is provided here.
"""
import contextlib
from types import CellType, FunctionType, GeneratorType, MappingProxyType, ModuleType

UNRELEASED = []
AUTH_FIELDS = ('delivery_module', 'delivery_pin', 'launch_pins', 'package_pins',
    'operational_catalog', 'fingerprint', 'full_package_pin', 'bootstrap_records',
    'bootstrap_pins', 'running_cli_raw')
STATION_FIELDS = ('os_module', 'sys_module', 'platform_module', 'select_module',
    'ctypes_module', 'libc', 'subprocess_module', 'signal_module', 'io_module',
    'fcntl_module', 'tool_catalog', 'backend_budget', 'runner_budget', 'clock', 'files')
COLLABORATORS = ('files', 'crypto', 'backend_module', 'backend', 'runner_module',
    'runner', 'parent_system_module', 'parent_system', 'clock')


class StageChildUnavailable(ValueError):
    pass


def _factory(public, exception):
    registry, retained = {}, []
    used = failed = False
    module_type, function_type, proxy = ModuleType, FunctionType, MappingProxyType
    cm_kind, generator_type = contextlib._GeneratorContextManager, GeneratorType
    cm_table = tuple(vars(cm_kind).items())
    cm_lineage = type.__getattribute__(cm_kind, '__mro__')
    cm_metatype = type(cm_kind)  # Original stdlib ABCMeta, not caller selection.
    if type(cm_metatype) is not type or len(cm_lineage) > 8 or any(type(owner) not in (type, cm_metatype) for owner in cm_lineage):
        raise exception('company-cli-stage-child-unavailable')
    cm_tables = tuple((owner, tuple(type.__getattribute__(owner, '__dict__').items())) for owner in (*cm_lineage,cm_metatype))
    if any(len(table) > 128 or any(type(key) is not str for key, value in table) for owner, table in cm_tables):
        raise exception('company-cli-stage-child-unavailable')
    enter, exit = dict(cm_table)['__enter__'], dict(cm_table)['__exit__']
    wrapper_namespace = tuple(vars(contextlib).items())
    auth_fields, station_fields, collaborators = AUTH_FIELDS, STATION_FIELDS, COLLABORATORS

    def need(value):
        if value is not True:
            raise exception('company-cli-stage-child-unavailable')

    def items(current, expected):
        need(type(current) is dict and all(type(key) is str for key in current)
             and len(current) == len(expected)
             and all(key in current and current[key] is value for key, value in expected))

    def capture(module):
        need(type(module) is module_type)
        namespace = tuple(vars(module).items())
        need(len(namespace) <= 512 and all(type(key) is str for key, value in namespace))
        name = dict(namespace).get('__name__');need(type(name) is str)
        classes = []
        for item in dict(namespace).values():
            if type(item) is type:
                owner = type.__getattribute__(item, '__module__');need(type(owner) is str)
                if owner == name:
                    table = tuple(vars(item).items())
                    need(len(table) <= 128 and all(type(key) is str for key, value in table))
                    classes.append((item, table))
        return (module, namespace, tuple(classes))

    def guard(record):
        need(not failed and not retained)
        items(dict(vars(kind)), kind_table)
        need(type.__getattribute__(cm_kind, '__mro__') is cm_lineage)
        for owner, table in cm_tables:items(dict(type.__getattribute__(owner, '__dict__')), table)
        items(dict(vars(contextlib)), wrapper_namespace)
        for module, namespace, classes in record['modules']:
            items(dict(vars(module)), namespace)
            for owner, table in classes:items(dict(vars(owner)), table)
        for value, code, closure, definitions, defaults, keyword_defaults in record['functions']:
            need(value.__code__ is code and value.__closure__ is closure
                 and value.__defaults__ is defaults and value.__kwdefaults__ is keyword_defaults)
            items(dict(vars(value)), definitions)
        need(record['auth_cell'].cell_contents is record['auth_generator'])

    def function(module, name):
        value = vars(module).get(name)
        need(type(value) is function_type and value.__globals__ is vars(module))
        return value

    def method(owner, name, module):
        need(type(owner) is type)
        value = vars(owner).get(name)
        need(type(value) is function_type and value.__globals__ is vars(module))
        return value

    def closed_dict(value, fields):
        need(type(value) is dict and all(type(key) is str for key in value)
             and set(value) == set(fields))
        return tuple((name, value[name]) for name in fields)

    def copy_plain(value, counter, depth=0):
        counter[0] += 1;need(counter[0] <= 4096 and depth <= 12)
        if type(value) is dict:
            need(len(value) <= 2048 and all(type(key) is str and len(key) <= 1024 for key in value))
            return {key:copy_plain(item, counter, depth+1) for key, item in value.items()}
        if type(value) in (list, tuple):
            need(len(value) <= 2048)
            return [copy_plain(item, counter, depth+1) for item in value]
        need(type(value) in (bytes, str, int))
        if type(value) is bytes:need(len(value) <= 1048576);counter[1] += len(value)
        if type(value) is str:need(len(value) <= 1024);counter[1] += len(value)
        if type(value) is int:need(0 <= value <= 2**64-1)
        need(counter[1] <= 2097152)
        return value

    def cm_check(record):
        cm, state, saved, generator = record['cm'], record['cm_state'], record['cm_items'], record['generator']
        need(type(cm) is cm_kind and type(generator) is generator_type)
        need(object.__getattribute__(cm, '__dict__') is state)
        items(state, saved)
        need(state.get('gen') is generator)
        need(generator.gi_code is record['auth_code'])
        if generator.gi_frame is not None:
            frame = generator.gi_frame
            need(frame.f_globals is vars(record['C']) and frame.f_locals.get('delivery_raw') is record['delivery'])
            need(all(frame.f_locals.get(name) is value for name, value in record['auth'].items()))

    def retain(record, reason, problem):
        nonlocal failed
        failed = True;record['failed'] = True
        row = (record, reason, problem, record.get('cm'), record.get('cli'),
               record.get('collaborators'), record.get('publisher'), record.get('result'))
        retained.append(row);public.append(row)

    def issued(value):
        record = registry.get(id(value))
        need(type(record) is dict and record['value'] is value)
        try:
            need(type(value) is kind and record['failed'] is False)
            guard(record)
        except BaseException as problem:
            retain(record, 'issued-boundary-unavailable', problem)
            raise exception('company-cli-stage-child-unavailable') from None
        return record

    def boundary(record, name, action, *args, _saved_as=None, **kwargs):
        guard(record);record['attempts'].append((name, action, args, kwargs))
        result = action(*args, **kwargs)
        record['returns'].append((name, result))  # Preserve actual return before guard.
        if _saved_as is not None:record[_saved_as] = result
        guard(record)
        return result

    def close_cli(record, problem=None):
        need(record['entered'] is True and record['exit_attempted'] is False)
        guard(record);cm_check(record)
        record['exit_attempted'] = True
        result = exit(record['cm'], None if problem is None else type(problem), problem,
                      None if problem is None else problem.__traceback__)
        record['returns'].append(('cli-exit', result))
        guard(record);cm_check(record)
        need(record['generator'].gi_frame is None)
        if problem is None:
            cli = record['cli']
            state = boundary(record, 'cli-owned-state', record['owned_state'], cli)
            owner = dict.get(record['cli_owners'], id(cli))
            closed = dict.get(record['closed_owners'], id(cli))
            need(type(owner) is tuple and len(owner) == 6 and owner[0] is cli
                 and type(closed) is tuple and len(closed) == 2 and closed[0] is owner
                 and owner[1] is state and dict.get(state, '_closed') is True
                 and dict.get(state, '_failed') is False and dict.get(state, '_retained') is False)
            record['cli_known_closed'] = True

    class ExecuteChild:
        __slots__ = ()

        def run(self):
            """Execute once, close original CLI, release crypto, publish DATA only."""
            record = issued(self)
            need(record['phase'] == 'prepared')
            record['phase'] = 'attempted'
            try:
                actual = boundary(record, 'captured-inputs', record['getter'], record['io'], _saved_as='captures')
                need(type(actual) is proxy and all(type(key) is str for key in actual)
                     and set(actual) == {'request_raw', 'invocation_raw', 'plan_raw'}
                     and type(actual['request_raw']) is bytes and 0 < len(actual['request_raw']) <= 4096)
                # The factory is the saved original C wrapper and generator;
                # no caller context-manager or observation is accepted.
                cm = boundary(record, 'cli-factory', record['auth_factory'], record['delivery'], _saved_as='cm', **record['auth'])
                record['cm_owned'] = True
                need(type(cm) is cm_kind)
                state = object.__getattribute__(cm, '__dict__')
                need(type(state) is dict and type(state.get('gen')) is generator_type)
                record.update(cm_state=state, cm_items=tuple(state.items()), generator=state['gen'])
                cm_check(record)
                record['enter_attempted'] = True
                cli = enter(cm)
                record['cli'] = cli;record['entered'] = True
                record['cm_items'] = tuple(state.items())
                guard(record);cm_check(record)
                need(type(cli) is record['cli_kind'])
                need(boundary(record, 'cli-recheck', record['recheck'], cli) is cli)
                args = dict(record['station']);args['crypto'] = record['crypto']
                values = boundary(record, 'native-stage-inputs', record['native_inputs'], cli, actual['request_raw'], **args)
                record['collaborators'] = values
                closed_dict(values, collaborators)
                need(values['crypto'] is record['crypto'] and values['files'] is args['files'] and values['clock'] is args['clock'])
                publisher = boundary(record, 'captured-prepare', record['prepare'], record['C'], record['R'], record['P'],
                    io_module=record['I'], io=record['io'], collaborators=values)
                record['publisher'] = publisher
                need(type(publisher) is record['publisher_kind'])
                need(boundary(record, 'original-execute', record['execute'], publisher, cli) is publisher)
                close_cli(record)
                need(boundary(record, 'crypto-release', record['crypto_release'], record['crypto']) is record['crypto'])
                result = boundary(record, 'original-publish', record['publish'], publisher)
                record['result'] = result
                need(type(result) is proxy and record['cli_known_closed'] is True)
                need(boundary(record, 'io-release', record['io_release'], record['io']) is record['io'])
                record['phase'] = 'published-data'
                return result
            except BaseException as problem:
                release_problem = None
                if record['entered'] and not record['exit_attempted']:
                    try:close_cli(record, problem)
                    except BaseException as caught:release_problem = caught
                retain(record, 'execute-child-unavailable', (problem, release_problem))
                raise exception('company-cli-stage-child-unavailable') from None

    kind = ExecuteChild;kind_table = tuple(vars(kind).items())

    def prepare_execute_child(cli_module, record_reader_module, publisher_module, captured_module, *,
            io_module, io, crypto_module, crypto, delivery_raw, authentication, station):
        """Bind external trusted inputs once; borrow IO, files and crypto scopes."""
        nonlocal used
        need(not used and not failed and not retained and type(public) is list and not public)
        auth_rows = closed_dict(authentication, auth_fields)
        station_rows = closed_dict(station, station_fields)
        need(type(delivery_raw) is bytes and 0 < len(delivery_raw) <= 1048576)
        auth_budget = [0, 0]
        auth = {name:(value if name == 'delivery_module' else copy_plain(value, auth_budget)) for name, value in auth_rows}
        native = {name:(copy_plain(value, [0, 0]) if name in ('tool_catalog', 'backend_budget', 'runner_budget') else value)
                  for name, value in station_rows}
        modules = tuple(capture(module) for module in (cli_module, record_reader_module, publisher_module,
            captured_module, io_module, crypto_module, auth['delivery_module']))
        modules += tuple(capture(native[name]) for name in station_fields if name.endswith('_module'))
        cli_kind = vars(cli_module).get('FullCli');publisher_kind = vars(publisher_module).get('RecordPublisher')
        io_kind = vars(io_module).get('PublisherIO');crypto_kind = vars(crypto_module).get('ReleaseCrypto')
        need(type(io_kind) is type and type(io) is io_kind and type(crypto_kind) is type and type(crypto) is crypto_kind)
        auth_factory = vars(cli_module).get('authenticated_cli')
        need(type(auth_factory) is function_type and auth_factory.__globals__ is vars(contextlib))
        wrapped = auth_factory.__dict__.get('__wrapped__')
        need(type(wrapped) is function_type and wrapped.__globals__ is vars(cli_module))
        closure = auth_factory.__closure__
        need(type(closure) is tuple and len(closure) == 1 and type(closure[0]) is CellType
             and closure[0].cell_contents is wrapped)
        getter = vars(io_kind).get('captured_inputs')
        need(type(getter) is property and type(getter.fget) is function_type and getter.fget.__globals__ is vars(io_module))
        cli_owners, closed_owners = vars(cli_module).get('_CLI_OWNERS'), vars(cli_module).get('_CLOSED_OWNERS')
        need(type(cli_owners) is dict and type(closed_owners) is dict)
        record = dict(value=None, failed=False, phase='preparing', modules=modules, C=cli_module, R=record_reader_module,
            P=publisher_module, I=io_module, io=io, crypto=crypto, delivery=delivery_raw, auth=auth, station=native,
            auth_factory=auth_factory, auth_generator=wrapped, cli_kind=cli_kind, publisher_kind=publisher_kind,
            auth_cell=closure[0],auth_code=wrapped.__code__,
            getter=getter.fget, native_inputs=method(cli_kind, 'native_stage_inputs', cli_module),
            recheck=method(cli_kind, 'recheck', cli_module), owned_state=function(cli_module, '_owned_state'),
            cli_owners=cli_owners, closed_owners=closed_owners,
            prepare=function(captured_module, 'prepare_captured_publish'),
            execute=method(publisher_kind, 'execute', publisher_module),publish=method(publisher_kind, 'publish', publisher_module),
            crypto_release=method(crypto_kind, 'require_released', crypto_module),io_release=function(io_module, 'require_released'),
            io_admission=function(io_module, 'require_publisher_io'),
            cm=None,cli=None,collaborators=None,publisher=None,result=None,captures=None,attempts=[],returns=[],
            entered=False,enter_attempted=False,exit_attempted=False,cli_known_closed=False,cm_owned=False)
        functions=(auth_factory,wrapped,record['getter'],record['native_inputs'],record['recheck'],record['owned_state'],
            record['prepare'],record['execute'],record['publish'],record['crypto_release'],record['io_release'],record['io_admission'])
        functions += tuple(value for owner, table in cm_tables for name, value in table
            if name in ('__init__','__enter__','__exit__') and type(value) is function_type)
        record['functions']=tuple((value,value.__code__,value.__closure__,tuple(vars(value).items()),value.__defaults__,value.__kwdefaults__) for value in functions)
        used = True  # Consumed before any external validator or acquisition.
        try:
            guard(record)
            need(boundary(record, 'io-admission', record['io_admission'], io) is io)
            need(boundary(record, 'crypto-admission', record['crypto_release'], crypto) is crypto)
            value = object.__new__(kind);record.update(value=value,phase='prepared');registry[id(value)] = record
            return value
        except BaseException as problem:
            retain(record, 'prepare-unavailable', problem)
            raise exception('company-cli-stage-child-unavailable') from None

    return ExecuteChild, prepare_execute_child


ExecuteChild, prepare_execute_child = _factory(UNRELEASED, StageChildUnavailable)
del _factory


def main(argv=None):
    raise StageChildUnavailable('company-cli-stage-child-main-unconfigured')


if __name__ == '__main__':
    raise SystemExit(74)
