"""Own the original IO scope around an actual prepared execute child.

Initial executing/source/station origins and the full endpoint copy graph are
trusted entry obligations. This entry selects no native defaults or process.
The original publisher writes the record after CLI, crypto and input release;
output closure and this IO context's exit follow that write. A sibling must
capture actual EOF and the original Bash must wait before any terminal use.
"""
import contextlib
from types import (BuiltinFunctionType, CellType, FunctionType, GeneratorType,
                   GenericAlias, GetSetDescriptorType, MappingProxyType, ModuleType)

UNRELEASED = []
IO_FIELDS = ('directory', 'directory_identity', 'input_pins', 'outputs', 'seconds', 'protected_fds')
CRYPTO_FIELDS = ('openssl_pin', 'budget', 'station_contract', 'protected_fds')
STATION_FIELDS = ('os_module', 'sys_module', 'platform_module', 'select_module',
    'ctypes_module', 'libc', 'subprocess_module', 'signal_module', 'io_module',
    'fcntl_module', 'tool_catalog', 'backend_budget', 'runner_budget', 'clock', 'files')


class FixedChildUnavailable(ValueError):
    pass


def _factory(namespace, public, error_kind, primitives):
    (type, dict, tuple, list, set, str, int, float, bool, bytes, len, all, any,
     vars, object, id, enumerate, BaseException, property, classmethod, staticmethod) = primitives
    fn, builtin, modulekind, proxy = FunctionType, BuiltinFunctionType, ModuleType, MappingProxyType
    gettype, new_error, init_error = type.__getattribute__, BaseException.__new__, BaseException.__init__
    traceback_getter = gettype(BaseException, '__dict__')['__traceback__']
    cm_kind = contextlib._GeneratorContextManager; cm_meta = type(cm_kind)
    io_fields, crypto_fields, station_fields = IO_FIELDS, CRYPTO_FIELDS, STATION_FIELDS
    registry, retained = {}, []; used = failed = False

    def deny():
        value = new_error(error_kind); init_error(value, 'company-fixed-execute-child-unavailable'); raise value
    def need(value):
        if value is not True: deny()
    def is_kind(value, kinds):
        return any(type(value) is expected for expected in kinds)
    def same(current, items):
        need(is_kind(current, (dict, proxy)) and len(current) == len(items)
             and all(type(key) is str for key in current)
             and all(key in current and current[key] is value for key, value in items))
    def function(value):
        if type(value) is builtin: return None
        need(type(value) is fn)
        return value, value.__code__, value.__closure__, value.__defaults__, value.__kwdefaults__, tuple(vars(value).items())
    def function_same(row):
        if row is None: return
        value, code, closure, defaults, kwdefaults, items = row
        need(value.__code__ is code and value.__closure__ is closure and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults)
        same(vars(value), items)
    def tables(kind):
        need(is_kind(kind, (type, cm_meta))); mro = gettype(kind, '__mro__')
        need(len(mro) <= 8 and all(is_kind(owner, (type, cm_meta)) for owner in mro))
        rows = tuple((owner, gettype(owner, '__bases__'), gettype(owner, '__mro__'), tuple(gettype(owner, '__dict__').items())) for owner in mro)
        need(all(len(items) <= 128 and all(type(key) is str for key, value in items) for owner, bases, lineage, items in rows)); callbacks = []
        for owner, bases, lineage, items in rows:
            for name, value in items:
                if type(value) is fn: callbacks.append(function(value))
                elif type(value) is property:
                    for getter in (value.fget, value.fset, value.fdel):
                        if getter is not None: callbacks.append(function(getter))
                elif is_kind(value, (classmethod, staticmethod)):
                    target = value.__func__
                    if type(target) is type: need(name == '__class_getitem__' and target is GenericAlias)
                    else: callbacks.append(function(target))
        return rows, tuple(callbacks)
    def table_same(row):
        for owner, bases, mro, items in row[0]:
            need(gettype(owner, '__bases__') is bases and gettype(owner, '__mro__') is mro); same(gettype(owner, '__dict__'), items)
        for value in row[1]: function_same(value)
    def capture(module):
        need(type(module) is modulekind); items = tuple(vars(module).items())
        need(len(items) <= 512 and all(type(key) is str for key, value in items)); name = dict(items).get('__name__'); need(type(name) is str)
        classes, callbacks = [], []
        for key, value in items:
            if type(value) is fn: callbacks.append(function(value))
            elif type(value) is type:
                origin = gettype(value, '__module__'); need(type(origin) is str)
                if origin == name: classes.append(tables(value))
        return module, items, tuple(classes), tuple(callbacks)
    def capture_same(row):
        module, items, classes, callbacks = row; same(vars(module), items)
        for value in classes: table_same(value)
        for value in callbacks: function_same(value)
    def method(kind, name, module):
        need(type(kind) is type); value = gettype(kind, '__dict__').get(name)
        need(type(value) is fn and value.__globals__ is vars(module)); return value
    def getter(kind, name, module):
        need(type(kind) is type); value = gettype(kind, '__dict__').get(name)
        need(type(value) is property and type(value.fget) is fn and value.fget.__globals__ is vars(module)); return value.fget
    def closed(value, fields):
        need(type(value) is dict and len(value) == len(fields) and all(type(key) is str for key in value) and set(value) == set(fields))
        return {key: value[key] for key in fields}
    def copy_plain(value, budget, depth=0):
        budget[0] += 1; need(budget[0] <= 4096 and depth <= 12)
        if is_kind(value, (dict, proxy)):
            need(len(value) <= 2048 and all(type(key) is str and len(key) <= 1024 for key in value))
            return {key: copy_plain(item, budget, depth+1) for key, item in value.items()}
        if is_kind(value, (tuple, list)):
            need(len(value) <= 2048); return tuple(copy_plain(item, budget, depth+1) for item in value)
        need(is_kind(value, (bytes, str, int, float)))
        if type(value) is bytes: need(len(value) <= 1048576); budget[1] += len(value)
        if type(value) is str: need(len(value) <= 4096); budget[1] += len(value)
        if type(value) is int: need(0 <= value < 2**64)
        if type(value) is float: need(0 <= value <= 300)
        need(budget[1] <= 2097152); return value
    def plain_snapshot(value):
        if type(value) is dict:
            return value, tuple((key, item, plain_snapshot(item)) for key, item in value.items())
        if type(value) is tuple: return value, tuple((None, item, plain_snapshot(item)) for item in value)
        return None
    def plain_same(row):
        if row is None: return
        value, items = row
        if type(value) is dict: same(value, tuple((key, item) for key, item, child in items))
        else: need(type(value) is tuple and len(value) == len(items) and all(value[index] is item for index, (key, item, child) in enumerate(items)))
        for key, item, child in items: plain_same(child)
    def retain(record, phase, problem):
        nonlocal failed
        failed = True; record['failed'] = True
        row = (record, phase, problem, record.get('cm'), record.get('io'), record.get('crypto'), record.get('result'), tuple(record['returns']))
        retained.append(row); public.append(row)
    def guard(record):
        same(namespace, record['own_items']); table_same(kind_tables); table_same(record['error_tables'])
        need(type(record['preparation']) is record['preparation_kind'])
        for row in record['own_functions']: function_same(row)
        for row in record['modules']: capture_same(row)
        for row in record['tables']: table_same(row)
        for row in record['functions']: function_same(row)
        for row in record['plain']: plain_same(row)
        same(record['station'], record['station_items'])
        if record.get('hold_cell') is not None: need(record['hold_cell'].cell_contents is record['hold_generator'])
        if record.get('bootstrap') is not None and record.get('bootstrap_kind') is not None: need(type(record['bootstrap']) is record['bootstrap_kind'])
        if record.get('io') is not None: need(type(record['io']) is record['io_kind'])
        if record.get('crypto') is not None: need(type(record['crypto']) is record['crypto_kind'])
    def boundary(record, phase, callback, *args, _save=None, **kwargs):
        guard(record); record['attempts'].append((phase, callback, args, kwargs)); value = callback(*args, **kwargs)
        record['returns'].append((phase, value))
        if _save is not None: record[_save] = value
        if _save == 'cm': record['cm_owned'] = True
        guard(record); return value
    def live(record):
        need(not failed and not retained and not record['failed'])
        value = boundary(record, 'original-signed-preparation', record['capture_preparation'], record['preparation'])
        need(value is record['preparation_data'])
    def cm_check(record, entered=False):
        need(type(record['cm']) is cm_kind)
        state = record['cm_dict_getter'].__get__(record['cm'], cm_kind); need(state is record['cm_state'])
        same(state, record['cm_enter_items'] if entered else record['cm_initial_items'])
        generator = record['generator']; need(type(generator) is GeneratorType and state.get('gen') is generator and generator.gi_code is record['hold_generator'].__code__)
        if generator.gi_frame is not None:
            frame = generator.gi_frame; need(frame.f_globals is vars(record['I']) and frame.f_locals.get('directory') is record['directory'])
            need(all(frame.f_locals.get(key) is value for key, value in record['io_arguments'].items()))
    def exit_io(record, problem=None):
        need(record['entered'] and not record['exit_attempted']); guard(record); cm_check(record, True); record['exit_attempted'] = True
        value = record['exit'](record['cm'], None if problem is None else type(problem), problem, None if problem is None else traceback_getter.__get__(problem, BaseException))
        record['returns'].append(('original-io-context-exit', value)); guard(record); cm_check(record, True)
        need(record['generator'].gi_frame is None)
        need(boundary(record, 'original-io-released', record['io_release'], record['io']) is record['io'])
        record['io_known_closed'] = True
    def owned(value):
        record = registry.get(id(value)); need(type(record) is dict and record['value'] is value)
        try: need(type(value) is kind and not record['failed']); live(record)
        except BaseException as problem: retain(record, 'issued-boundary', problem); deny()
        return record

    class FixedExecuteChild:
        __slots__ = ()
        def run(self):
            record = owned(self)
            try:
                need(record['phase'] == 'prepared'); record['phase'] = 'attempted'
                cm = boundary(record, 'original-io-factory', record['hold_io'], record['directory'], _save='cm', **record['io_arguments'])
                need(type(cm) is cm_kind); state = record['cm_dict_getter'].__get__(cm, cm_kind)
                need(type(state) is dict and len(state) <= 8 and all(type(key) is str for key in state)); generator = state.get('gen'); need(type(generator) is GeneratorType)
                record.update(cm_state=state, cm_initial_items=tuple(state.items()), cm_enter_items=tuple((key, value) for key, value in state.items() if key not in ('args', 'kwds', 'func')), generator=generator); cm_check(record)
                record['enter_attempted'] = True
                io = record['enter'](cm); record['returns'].append(('original-io-context-enter', io)); record['io'] = io; record['entered'] = True
                guard(record); cm_check(record, True); need(boundary(record, 'original-io-admission', record['io_admission'], io) is io)
                crypto = object.__new__(record['crypto_kind']); record['crypto'] = crypto; record['crypto_owned'] = True
                need(boundary(record, 'original-crypto-initialize', record['crypto_init'], crypto, **record['crypto_arguments']) is None)
                need(boundary(record, 'original-initial-crypto-release', record['crypto_release'], crypto) is crypto)
                need(boundary(record, 'original-bootstrap-prepare-child', record['prepare_child'], record['bootstrap'], io=io, crypto=crypto,
                    delivery_raw=record['delivery'], authentication=record['authentication'], station=record['station']) is record['bootstrap'])
                result = boundary(record, 'original-bootstrap-run-child', record['run_child'], record['bootstrap'], _save='result')
                need(type(result) is proxy); need(boundary(record, 'original-final-crypto-release', record['crypto_release'], crypto) is crypto)
                exit_io(record); live(record); record['phase'] = 'closed'
                return proxy(dict(scope='FIXED_EXECUTE_CHILD_CLOSED_DATA_ONLY', publication=result,
                    originalIoContextKnownReleased=True, sourceContextBorrowed=True,
                    bashWaitObserved=False, streamEofObserved=False, recordDurablyStored=False,
                    executionEvidenceIssued=False, stageAcknowledged=False, installerActivated=False))
            except BaseException as problem:
                cleanup_problem = None
                if record['entered'] and not record['exit_attempted']:
                    try: exit_io(record, problem)
                    except BaseException as caught: cleanup_problem = caught
                retain(record, 'fixed-child-run', (problem, cleanup_problem)); deny()

    kind = FixedExecuteChild; kind_tables = tables(kind)

    def prepare_fixed_execute_child(preparation_module, signed_preparation, *, io_configuration, crypto_configuration, station):
        nonlocal used
        need(not used and not failed and not retained and type(public) is list and not public)
        io_config = closed(io_configuration, io_fields); crypto_config = closed(crypto_configuration, crypto_fields); supplied = closed(station, station_fields)
        budget = [0, 0]; io_config = copy_plain(io_config, budget); crypto_config = copy_plain(crypto_config, budget)
        native = {key: copy_plain(value, budget) if key in ('tool_catalog', 'backend_budget', 'runner_budget') else value for key, value in supplied.items()}
        native_plain = tuple(plain_snapshot(native[key]) for key in ('tool_catalog', 'backend_budget', 'runner_budget'))
        modules = tuple(capture(value) for value in (preparation_module, contextlib, *tuple(native[key] for key in station_fields if key.endswith('_module'))))
        preparation_kind = vars(preparation_module).get('SignedExecutePreparation'); need(type(preparation_kind) is type and type(signed_preparation) is preparation_kind)
        capture_preparation = method(preparation_kind, 'capture_preparation', preparation_module)
        bootstrap_getter = getter(preparation_kind, 'bootstrap', preparation_module); modules_getter = getter(preparation_kind, 'construction_modules', preparation_module)
        record = dict(value=None, preparation=signed_preparation, preparation_kind=preparation_kind, modules=modules,
            tables=(tables(preparation_kind), tables(cm_kind), tables(cm_meta)), functions=tuple(function(value) for value in (capture_preparation, bootstrap_getter, modules_getter, native['clock'])),
            own_items=tuple(namespace.items()), own_functions=tuple(function(value) for value in namespace.values() if type(value) is fn), error_tables=tables(error_kind),
            capture_preparation=capture_preparation, bootstrap=None, cm=None, io=None, crypto=None, result=None, station=native, station_items=tuple(native.items()),
            cm_owned=False, crypto_owned=False, enter_attempted=False, entered=False, exit_attempted=False, io_known_closed=False,
            failed=False, phase='preparing', attempts=[], returns=[], plain=(plain_snapshot(io_config), plain_snapshot(crypto_config), *native_plain))
        used = True
        try:
            data = boundary(record, 'original-preparation-capture', capture_preparation, signed_preparation, _save='preparation_data')
            need(type(data) is proxy and all(type(key) is str for key in data) and type(data['deliveryRaw']) is bytes and type(data['authentication']) is proxy)
            construction = boundary(record, 'original-construction-modules', modules_getter, signed_preparation, _save='construction')
            need(type(construction) is proxy and len(construction) == 2 and all(type(key) is str for key in construction) and set(construction) == {'io', 'crypto'})
            I, X = construction['io'], construction['crypto']; record['modules'] += (capture(I), capture(X)); record['I'] = I
            bootstrap = boundary(record, 'original-prepared-bootstrap', bootstrap_getter, signed_preparation, _save='bootstrap')
            bootstrap_kind = type(bootstrap); record['bootstrap_kind'] = bootstrap_kind
            need(type(bootstrap_kind) is type)
            B = gettype(bootstrap_kind, '__dict__').get('prepare_child'); need(type(B) is fn); bootstrap_module = B.__globals__; need(type(bootstrap_module) is dict)
            record['tables'] += (tables(bootstrap_kind),)
            prepare_child, run_child = gettype(bootstrap_kind, '__dict__').get('prepare_child'), gettype(bootstrap_kind, '__dict__').get('run_child')
            need(type(prepare_child) is type(run_child) is fn and run_child.__globals__ is bootstrap_module)
            io_kind, crypto_kind = vars(I).get('PublisherIO'), vars(X).get('ReleaseCrypto'); need(type(io_kind) is type(crypto_kind) is type)
            hold = vars(I).get('hold_publisher_io'); need(type(hold) is fn and hold.__globals__ is vars(contextlib))
            wrapped = vars(hold).get('__wrapped__'); need(type(wrapped) is fn and wrapped.__globals__ is vars(I)); cells = hold.__closure__
            need(type(cells) is tuple and len(cells) == 1 and type(cells[0]) is CellType and cells[0].cell_contents is wrapped)
            descriptor = None
            for owner, bases, lineage, items in tables(cm_kind)[0]:
                candidate = dict(items).get('__dict__')
                if candidate is not None: descriptor = candidate; break
            need(type(descriptor) is GetSetDescriptorType)
            io_release, io_admission = vars(I).get('require_released'), vars(I).get('require_publisher_io')
            need(type(io_release) is type(io_admission) is fn and io_release.__globals__ is io_admission.__globals__ is vars(I))
            auth = copy_plain(data['authentication'], budget); record['plain'] += (plain_snapshot(auth),)
            directory = io_config.pop('directory'); io_config.update({key: native[key] for key in ('os_module', 'sys_module', 'fcntl_module', 'select_module', 'clock')})
            crypto_config.update({key: native[key] for key in ('os_module', 'sys_module', 'subprocess_module', 'select_module', 'signal_module', 'fcntl_module', 'clock')})
            record['plain'] = (plain_snapshot(io_config), plain_snapshot(crypto_config), *native_plain, plain_snapshot(auth))
            callbacks = (hold, wrapped, io_release, io_admission, method(crypto_kind, '__init__', X), method(crypto_kind, 'require_released', X), prepare_child, run_child)
            record.update(io_kind=io_kind, crypto_kind=crypto_kind, hold_io=hold, hold_generator=wrapped, hold_cell=cells[0], io_release=io_release, io_admission=io_admission,
                crypto_init=callbacks[4], crypto_release=callbacks[5], prepare_child=prepare_child, run_child=run_child, directory=directory, io_arguments=io_config, crypto_arguments=crypto_config,
                authentication=auth, delivery=data['deliveryRaw'], station=native, cm_dict_getter=descriptor,
                enter=gettype(cm_kind, '__dict__')['__enter__'], exit=gettype(cm_kind, '__dict__')['__exit__'])
            record['functions'] += tuple(function(value) for value in (*callbacks, record['enter'], record['exit']))
            live(record); value = object.__new__(kind); record.update(value=value, phase='prepared'); registry[id(value)] = record; guard(record); return value
        except BaseException as problem: retain(record, 'fixed-child-prepare', problem); deny()

    def main(argv=None): deny()
    return FixedExecuteChild, prepare_fixed_execute_child, main


FixedExecuteChild, prepare_fixed_execute_child, main = _factory(globals(), UNRELEASED, FixedChildUnavailable,
    (type, dict, tuple, list, set, str, int, float, bool, bytes, len, all, any, vars, object, id, enumerate, BaseException, property, classmethod, staticmethod))
del _factory


if __name__ == '__main__':
    raise SystemExit(74)
