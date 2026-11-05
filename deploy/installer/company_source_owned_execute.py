"""Own an original verifier context through a privately prepared execute child.

Initial source/module/reader/crypto/station origins and reader output protocol are
externally authenticated. No source adoption, native defaults, issuer or ACK.
"""
import sys
import contextlib
from types import (BuiltinFunctionType, CellType, FunctionType, GeneratorType,
                   GenericAlias, GetSetDescriptorType, MappingProxyType, ModuleType)

UNRELEASED = []
SOURCE_FIELDS = ('directory', 'public_key', 'fingerprint', 'source_root')
IO_FIELDS = ('directory', 'directory_identity', 'input_pins', 'outputs', 'seconds', 'protected_fds')
CRYPTO_FIELDS = ('openssl_pin', 'budget', 'station_contract', 'protected_fds')
STATION_FIELDS = ('os_module', 'sys_module', 'platform_module', 'select_module', 'ctypes_module',
    'libc', 'subprocess_module', 'signal_module', 'io_module', 'fcntl_module', 'tool_catalog',
    'backend_budget', 'runner_budget', 'clock', 'files')
READER_FIELDS = ('lstat', 'open', 'fstat', 'cloexec', 'read', 'close')


class SourceOwnerUnavailable(ValueError):
    pass


def _factory(namespace, public, error_kind, primitives):
    (type, dict, tuple, list, set, str, int, float, bool, bytes, len, all, any,
     vars, object, id, enumerate, zip, BaseException, property, classmethod, staticmethod) = primitives
    fn, builtin, modulekind, proxy = FunctionType, BuiltinFunctionType, ModuleType, MappingProxyType
    gettype, new_error, init_error = type.__getattribute__, BaseException.__new__, BaseException.__init__
    traceback_getter = gettype(BaseException, '__dict__')['__traceback__']
    cm_kind = contextlib._GeneratorContextManager; cm_meta = type(cm_kind)
    source_fields, io_fields, crypto_fields, station_fields, reader_fields = SOURCE_FIELDS, IO_FIELDS, CRYPTO_FIELDS, STATION_FIELDS, READER_FIELDS
    registry, views, retained = {}, {}, []; used = failed = False

    def deny():
        value = new_error(error_kind); init_error(value, 'company-source-owned-execute-unavailable'); raise value
    def need(value):
        if value is not True: deny()
    def kinds(value, expected):
        return any(type(value) is kind for kind in expected)
    def same(current, items):
        need(kinds(current, (dict, proxy)) and len(current) == len(items) and all(type(key) is str for key in current)
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
        need(kinds(kind, (type, cm_meta))); mro = gettype(kind, '__mro__')
        need(len(mro) <= 8 and all(kinds(owner, (type, cm_meta)) for owner in mro))
        rows = tuple((owner, gettype(owner, '__bases__'), gettype(owner, '__mro__'), tuple(gettype(owner, '__dict__').items())) for owner in mro)
        need(all(len(items) <= 128 and all(type(key) is str for key, value in items) for owner, bases, lineage, items in rows)); callbacks = []
        for owner, bases, lineage, items in rows:
            for name, value in items:
                if type(value) is fn: callbacks.append(function(value))
                elif type(value) is property:
                    for getter in (value.fget, value.fset, value.fdel):
                        if getter is not None: callbacks.append(function(getter))
                elif kinds(value, (classmethod, staticmethod)):
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
        if kinds(value, (dict, proxy)):
            need(len(value) <= 2048 and all(type(key) is str and len(key) <= 1024 for key in value))
            return {key: copy_plain(item, budget, depth+1) for key, item in value.items()}
        if kinds(value, (tuple, list)):
            need(len(value) <= 2048); return tuple(copy_plain(item, budget, depth+1) for item in value)
        need(kinds(value, (bytes, str, int, float)))
        if type(value) is bytes: need(len(value) <= 1048576); budget[1] += len(value)
        if type(value) is str: need(len(value) <= 4096); budget[1] += len(value)
        if type(value) is int: need(0 <= value < 2**64)
        if type(value) is float: need(0 <= value <= 300)
        need(budget[1] <= 2097152); return value
    def plain_snapshot(value):
        if type(value) is dict: return value, tuple((key, item, plain_snapshot(item)) for key, item in value.items())
        if type(value) is tuple: return value, tuple((None, item, plain_snapshot(item)) for item in value)
        return None
    def plain_same(row):
        if row is None: return
        value, items = row
        if type(value) is dict: same(value, tuple((key, item) for key, item, child in items))
        else: need(type(value) is tuple and len(value) == len(items) and all(value[index] is item for index, (key, item, child) in enumerate(items)))
        for key, item, child in items: plain_same(child)

    class RetainedOwner:
        __slots__ = ('__record',)

    def retain(record, phase, problem):
        nonlocal failed
        failed = True; record['failed'] = True
        if record['primary'] is None:
            record['primary'] = (phase, problem)
            keeper = object.__new__(RetainedOwner); object.__setattr__(keeper, '_RetainedOwner__record', record)
            retained.append(keeper); public.append(keeper)
        elif record['cleanup_error'] is None: record['cleanup_error'] = (phase, problem)
    def guard(record):
        same(namespace, record['own_items']); table_same(owner_tables); table_same(reader_tables); table_same(crypto_view_tables); table_same(retention_tables)
        table_same(record['error_tables'])
        need(type(record['files']) is record['files_kind'] and type(record['source_crypto']) is record['source_crypto_kind'])
        for row in record['own_functions']: function_same(row)
        for row in record['modules']: capture_same(row)
        for row in record['tables']: table_same(row)
        for row in record['functions']: function_same(row)
        for row in record['plain']: plain_same(row)
        same(record['station'], record['station_items'])
        need(record['source_cell'].cell_contents is record['source_generator'])
        if record['hps'] is not None: need(type(record['hps']) is record['hps_kind'])
        if record['child'] is not None: need(type(record['child']) is record['child_kind'])
        need(vars(record['V']).get('_ISSUED_PLATFORM_SOURCES') is record['source_issued'] and vars(record['V']).get('UNRELEASED_HANDLES') is record['source_unreleased'])
    def boundary(record, phase, callback, *args, _save=None, **kwargs):
        guard(record); need(len(record['returns']) < 24); record['last_attempt'] = (phase, callback, args, kwargs)
        try: value = callback(*args, **kwargs)
        except BaseException as problem:
            record['last_error'] = (phase, problem); raise
        record['returns'].append((phase, value))
        if _save is not None: record[_save] = value
        if _save == 'cm': record['cm_owned'] = True
        guard(record); return value
    def source_live(record):
        need(record['entered'] and not record['exit_attempted'] and not record['reader_unknown'])
        need(boundary(record, 'original-live-platform-source', record['require_source'], record['hps']) is record['hps'])
    def lookup(value, *, cleanup=False):
        record = registry.get(id(value)); need(type(record) is dict and record['value'] is value)
        try:
            need(type(value) is owner_kind); guard(record)
            if not cleanup: need(not record['failed'] and not failed and not retained)
        except BaseException as problem: retain(record, 'owned-boundary', problem); deny()
        return record
    def cm_check(record, entered=False):
        cm = record['cm']; need(type(cm) is cm_kind)
        state = record['cm_dict_getter'].__get__(cm, cm_kind); need(state is record['cm_state'])
        same(state, record['cm_enter_items'] if entered else record['cm_initial_items'])
        generator = record['generator']; need(type(generator) is GeneratorType and state.get('gen') is generator and generator.gi_code is record['source_generator'].__code__)
        if generator.gi_frame is not None:
            frame = generator.gi_frame; need(frame.f_globals is vars(record['V']))
            need(all(frame.f_locals.get(key) is value for key, value in record['source_arguments'].items() if not entered or key != 'public_key'))
            if entered: need(frame.f_locals.get('public_key') is record['source_public_key'] and frame.f_locals.get('backend') is record['reader_view'])
    def reader_record(value):
        record = views.get(id(value)); need(type(record) is dict and record['reader_view'] is value and type(value) is ReaderView); return record
    def row(record, fd):
        need(type(fd) is int and fd >= 3)
        found = [item for item in record['reader_rows'] if item['fd'] == fd and not item['known_closed']]
        need(len(found) == 1 and not found[0]['ambiguous']); return found[0]
    def reader_call(record, name, *args):
        guard(record); need(record['reader_calls'] < 65536); record['reader_calls'] += 1
        callback = record['reader_callbacks'][name]; record['last_reader_attempt'] = (name, callback, args)
        if name in ('fstat', 'cloexec', 'read'): need(not row(record, args[0])['attempted'])
        if name == 'read':
            need(type(args[1]) is type(args[2]) is int and 0 < args[1] <= 65536 and 0 <= args[2] < 2**64)
        try: value = callback(record['files'], *args)
        except BaseException as problem:
            record['last_reader_error'] = (name, problem)
            if name == 'open': record['reader_unknown'] = True
            raise
        record['last_reader_return'] = (name, value)
        open_item = None
        if name == 'open':
            matching = [item for item in record['reader_rows'] if item['fd'] == value and not item['known_closed']] if type(value) is int else ()
            for previous in matching: previous['ambiguous'] = True
            if type(value) is not int or value < 3 or len(record['reader_rows']) >= 512:
                record['reader_unknown'] = True; record['unknown_reader_return'] = value; deny()
            open_item = dict(fd=value, returned=value, ambiguous=bool(matching), delivered_to_verifier=False,
                postguard_error=None, attempted=False, close_return=None, close_error=None, known_closed=False)
            record['reader_rows'].append(open_item)
            if matching:
                record['reader_unknown'] = True; record['unknown_reader_return'] = value; deny()
        try: guard(record)
        except BaseException as problem:
            if open_item is not None:
                open_item['ambiguous'] = True; open_item['postguard_error'] = problem
                record['reader_unknown'] = True; record['unknown_reader_return'] = value
            raise
        if open_item is not None: open_item['delivered_to_verifier'] = True
        if name == 'read':
            need(type(value) is bytes and len(value) <= args[1]); record['reader_bytes'] += len(value); need(record['reader_bytes'] <= 2**34)
        if name == 'cloexec': need(type(value) is bool)
        return value
    def close_reader(record, fd):
        item = None
        try:
            guard(record); item = row(record, fd); need(item['delivered_to_verifier'] and not item['attempted']); item['attempted'] = True
            callback = record['reader_callbacks']['close']; record['last_reader_attempt'] = ('close', callback, (fd,))
            value = callback(record['files'], fd); item['close_return'] = value; record['last_reader_return'] = ('close', value)
            guard(record); need(value is None); item['known_closed'] = True
        except BaseException as problem:
            record['reader_unknown'] = True; record['last_reader_error'] = ('close', problem)
            if item is not None: item['close_error'] = problem
            raise

    class ReaderView:
        __slots__ = ()
        def lstat(self, path): return reader_call(reader_record(self), 'lstat', path)
        def open(self, parent, name, directory): return reader_call(reader_record(self), 'open', parent, name, directory)
        def fstat(self, fd): return reader_call(reader_record(self), 'fstat', fd)
        def cloexec(self, fd): return reader_call(reader_record(self), 'cloexec', fd)
        def read(self, fd, amount, offset): return reader_call(reader_record(self), 'read', fd, amount, offset)
        def close(self, fd): return close_reader(reader_record(self), fd)
    class CryptoView:
        __slots__ = ()
        def verify(self, message, signature, key):
            record = views.get(id(self)); need(type(record) is dict and record['crypto_view'] is self and type(self) is CryptoView)
            return boundary(record, 'original-source-signature-verify', record['crypto_verify'], record['source_crypto'], message, signature, key)

    def source_exit(record, *, abort=False):
        need(record['entered'] and not record['exit_attempted']); guard(record); cm_check(record, True)
        need(not record['child_attempted'] or record['child_success'])
        record['exit_attempted'] = True
        try: value = record['exit'](record['cm'], None, None, None)
        except BaseException as problem:
            record['exit_error'] = problem; raise
        record['exit_return'] = value; record['returns'].append(('original-source-context-exit', value))
        guard(record); cm_check(record, True); need(record['generator'].gi_frame is None)
        active = boundary(record, 'original-terminal-source-active', record['active_getter'], record['hps'])
        need(active is False and record['hps'] not in record['source_issued'] and not record['source_unreleased'])
        need(not record['reader_unknown'] and all(item['known_closed'] for item in record['reader_rows']))
        record['known_closed'] = True; record['phase'] = 'aborted' if abort else 'closed'
    class SourceOwnedExecute:
        __slots__ = ()
        def open(self):
            record = lookup(self)
            try:
                need(record['phase'] == 'prepared'); record['phase'] = 'opening'
                need(boundary(record, 'original-initial-source-crypto-release', record['crypto_release'], record['source_crypto']) is record['source_crypto'])
                cm = boundary(record, 'original-platform-source-factory', record['auth_factory'], _save='cm', **record['source_arguments'])
                need(type(cm) is cm_kind); state = record['cm_dict_getter'].__get__(cm, cm_kind)
                need(type(state) is dict and len(state) <= 8 and all(type(key) is str for key in state)); generator = state.get('gen'); need(type(generator) is GeneratorType)
                record.update(cm_state=state,cm_initial_items=tuple(state.items()),cm_enter_items=tuple((key,value) for key,value in state.items() if key not in ('args','kwds','func')),generator=generator); cm_check(record)
                record['enter_attempted'] = True
                hps = record['enter'](cm); record['hps'] = hps; record['entered'] = True; record['returns'].append(('original-platform-source-enter', hps))
                frame = record['generator'].gi_frame; record['source_public_key'] = None if frame is None else frame.f_locals.get('public_key')
                guard(record); cm_check(record, True); source_live(record)
                inputs = boundary(record, 'original-source-inputs-prepare', record['inputs_prepare'], record['V'], hps,
                    package_module=record['PB'],delivery_module=record['D'],cli_module=record['C'],_save='inputs')
                need(type(inputs) is record['inputs_kind']); source_live(record)
                preparation = boundary(record, 'original-signed-execute-prepare', record['signed_prepare'], record['I'], inputs, record['M'],
                    root=record['root'],package_module=record['PB'],delivery_module=record['D'],cli_module=record['C'],sys_module=record['interpreter_sys'],_save='preparation')
                need(type(preparation) is record['preparation_kind']); source_live(record)
                child = boundary(record, 'original-fixed-child-prepare', record['child_prepare'], record['S'], preparation,
                    io_configuration=record['io_configuration'],crypto_configuration=record['crypto_configuration'],station=record['station'],_save='child')
                need(type(child) is record['child_kind']); source_live(record); record['phase'] = 'ready'; return self
            except BaseException as problem: retain(record, 'source-owner-open', problem); deny()
        def run(self, original_execute_role_permit):
            record = lookup(self)
            try:
                need(record['phase'] == 'ready'); source_live(record)
                permit = boundary(record, 'original-execute-startup-permit', record['require_permit'], original_execute_role_permit, self, role='execute', _save='permit')
                need(permit is original_execute_role_permit); source_live(record); record['child_attempted'] = True; record['phase'] = 'running'
                result = boundary(record, 'original-fixed-child-run', record['child_run'], record['child'], _save='publication')
                need(type(result) is proxy); record['child_success'] = True
                need(boundary(record, 'original-final-source-crypto-release', record['crypto_release'], record['source_crypto']) is record['source_crypto'])
                source_exit(record); guard(record)
                record['result'] = proxy(dict(scope='SOURCE_OWNED_EXECUTE_PUBLICATION_DATA_ONLY',publication=result,
                    originalSourceContextKnownClosed=True,initialOriginsQualified=False,completeCopyGraphQualified=False,
                    bashWaitObserved=False,streamEofObserved=False,recordDurablyStored=False,executionEvidenceIssued=False,stageAcknowledged=False))
                return record['result']
            except BaseException as problem: retain(record, 'source-owner-run', problem); deny()
        def abort(self):
            record = lookup(self, cleanup=True)
            try:
                if record['known_closed']: return self
                need(not record['child_attempted'] and not record['exit_attempted'])
                if record['cm_owned']:
                    need(record['entered']); source_exit(record, abort=True)
                else:
                    need(not record['enter_attempted'] and not record['reader_rows'] and not record['reader_unknown']); record['known_closed'] = True; record['phase'] = 'aborted'
                record['aborted'] = True; return self
            except BaseException as problem: retain(record, 'source-owner-abort', problem); deny()
        def require_released(self):
            record = lookup(self, cleanup=True)
            try: need(record['known_closed'] and record['phase'] in ('closed','aborted') and not record['reader_unknown']); return self
            except BaseException as problem: retain(record, 'source-owner-release-observation', problem); deny()

    owner_kind = SourceOwnedExecute; owner_tables = tables(owner_kind); reader_tables = tables(ReaderView); crypto_view_tables = tables(CryptoView); retention_tables = tables(RetainedOwner)
    def prepare_source_owned_execute(verifier_module,inputs_module,composition_module,signed_preparation_module,fixed_child_module,startup_join_module,
            *,package_module,delivery_module,cli_module,source_files_module,source_files,source_crypto_module,source_crypto,
            source_parameters,root,io_configuration,crypto_configuration,station):
        nonlocal used
        need(not used and not failed and not retained and type(public) is list and not public)
        budget = [0,0]; parameters = copy_plain(closed(source_parameters,source_fields),budget)
        need(all(type(value) is str and 0 < len(value) <= 4096 and value.isascii() for value in parameters.values()))
        need(len(parameters['fingerprint']) == 64 and all(char in '0123456789abcdef' for char in parameters['fingerprint']))
        need(type(root) is str and 0 < len(root) <= 4096 and root.isascii())
        io_config = copy_plain(closed(io_configuration,io_fields),budget); crypto_config = copy_plain(closed(crypto_configuration,crypto_fields),budget)
        supplied = closed(station,station_fields); native = {key:copy_plain(value,budget) if key in ('tool_catalog','backend_budget','runner_budget') else value for key,value in supplied.items()}
        V,I,M,S,E,J,PB,D,C,F,X = verifier_module,inputs_module,composition_module,signed_preparation_module,fixed_child_module,startup_join_module,package_module,delivery_module,cli_module,source_files_module,source_crypto_module
        modules = tuple(capture(value) for value in (V,I,M,S,E,J,PB,D,C,F,X,contextlib,sys,*tuple(native[key] for key in station_fields if key.endswith('_module'))))
        files_kind = type(source_files); need(type(files_kind) is type); files_origin = gettype(files_kind,'__module__')
        need(type(files_origin) is str and files_origin == vars(F)['__name__'] and any(value is files_kind for value in vars(F).values()))
        reader_callbacks = {name:method(files_kind,name,F) for name in reader_fields}
        crypto_kind = vars(X).get('ReleaseCrypto'); need(type(crypto_kind) is type and type(source_crypto) is crypto_kind)
        hps_kind = vars(V).get('HeldPlatformSource'); need(type(hps_kind) is type)
        auth = vars(V).get('authenticated_platform_source'); need(type(auth) is fn and auth.__globals__ is vars(contextlib))
        wrapped = vars(auth).get('__wrapped__'); need(type(wrapped) is fn and wrapped.__globals__ is vars(V))
        cells = auth.__closure__; need(type(cells) is tuple and len(cells) == 1 and type(cells[0]) is CellType and cells[0].cell_contents is wrapped)
        cm_tables = tables(cm_kind); descriptor = None
        for owner,bases,mro,items in cm_tables[0]:
            candidate = dict(items).get('__dict__')
            if candidate is not None: descriptor = candidate; break
        need(type(descriptor) is GetSetDescriptorType)
        callbacks = {name:value for name,value in (
            ('require_source',vars(V).get('require_platform_source')),('inputs_prepare',vars(I).get('prepare_authenticated_cli_inputs')),
            ('signed_prepare',vars(S).get('prepare_signed_execute')),('child_prepare',vars(E).get('prepare_fixed_execute_child')),
            ('require_permit',vars(J).get('require_startup_permit')))}
        need(all(type(value) is fn and value.__globals__ is vars(module) for value,module in zip(callbacks.values(),(V,I,S,E,J))))
        input_kind, preparation_kind, child_kind = vars(I).get('SourceInputs'),vars(S).get('SignedExecutePreparation'),vars(E).get('FixedExecuteChild')
        need(all(type(value) is type for value in (input_kind,preparation_kind,child_kind)))
        issued,unreleased = vars(V).get('_ISSUED_PLATFORM_SOURCES'),vars(V).get('UNRELEASED_HANDLES'); need(type(issued) is set and type(unreleased) is list and not unreleased)
        record = dict(value=None,interpreter_sys=sys,V=V,I=I,M=M,S=S,E=E,J=J,PB=PB,D=D,C=C,files=source_files,files_kind=files_kind,
            source_crypto=source_crypto,source_crypto_kind=crypto_kind,hps_kind=hps_kind,inputs_kind=input_kind,preparation_kind=preparation_kind,child_kind=child_kind,
            modules=modules,tables=(tables(files_kind),tables(crypto_kind),tables(hps_kind),cm_tables,tables(cm_meta)),functions=(),plain=(),error_tables=tables(error_kind),
            own_items=tuple(namespace.items()),own_functions=tuple(function(value) for value in namespace.values() if type(value) is fn),
            failed=False,primary=None,cleanup_error=None,phase='prepared',root=root,io_configuration=io_config,crypto_configuration=crypto_config,station=native,station_items=tuple(native.items()),
            reader_callbacks=reader_callbacks,reader_rows=[],reader_unknown=False,unknown_reader_return=None,reader_calls=0,reader_bytes=0,
            last_reader_attempt=None,last_reader_return=None,last_reader_error=None,last_attempt=None,last_error=None,returns=[],
            cm=None,cm_owned=False,enter_attempted=False,entered=False,exit_attempted=False,exit_return=None,exit_error=None,source_public_key=None,known_closed=False,aborted=False,
            hps=None,inputs=None,preparation=None,child=None,child_attempted=False,child_success=False,permit=None,publication=None,result=None,
            source_issued=issued,source_unreleased=unreleased,auth_factory=auth,source_generator=wrapped,source_cell=cells[0],cm_dict_getter=descriptor,
            enter=gettype(cm_kind,'__dict__')['__enter__'],exit=gettype(cm_kind,'__dict__')['__exit__'],
            active_getter=getter(hps_kind,'active',V),crypto_verify=method(crypto_kind,'verify',X),crypto_release=method(crypto_kind,'require_released',X),child_run=method(child_kind,'run',E),**callbacks)
        reader_view,crypto_view = object.__new__(ReaderView),object.__new__(CryptoView); record.update(reader_view=reader_view,crypto_view=crypto_view)
        views[id(reader_view)] = views[id(crypto_view)] = record
        arguments = dict(parameters,expected_architecture='x86_64',files=reader_view,crypto=crypto_view,owner_uid=0,owner_gid=0); record['source_arguments'] = arguments
        record['plain'] = (plain_snapshot(parameters),plain_snapshot(io_config),plain_snapshot(crypto_config),*tuple(plain_snapshot(native[key]) for key in ('tool_catalog','backend_budget','runner_budget')))
        record['functions'] = tuple(function(value) for value in (*reader_callbacks.values(),*callbacks.values(),auth,wrapped,record['enter'],record['exit'],record['active_getter'],record['crypto_verify'],record['crypto_release'],record['child_run']))
        used = True; value = object.__new__(owner_kind); record['value'] = value; registry[id(value)] = record
        try: guard(record); return value
        except BaseException as problem: retain(record,'source-owner-prepare',problem); deny()
    def main(argv=None): deny()
    return SourceOwnedExecute,prepare_source_owned_execute,main


SourceOwnedExecute,prepare_source_owned_execute,main = _factory(globals(),UNRELEASED,SourceOwnerUnavailable,
    (type,dict,tuple,list,set,str,int,float,bool,bytes,len,all,any,vars,object,id,enumerate,zip,BaseException,property,classmethod,staticmethod))
del _factory

if __name__ == '__main__':
    raise SystemExit(74)
