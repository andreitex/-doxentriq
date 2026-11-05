"""Fixed execute-child source bootstrap; company admission is external.

The independently authenticated company Bash entry must authenticate this code
and supply all ten exact byte captures with independent package pins. Matching
hashes do not establish their initial origin. Only eight fixed program captures
execute here; original V/P raw bytes are passed to original FullCLI admission.
The returned module references remain mutable and are guarded around setup/use.
Registrations last for this dedicated worker-process lifetime. This bootstrap
owns no native handles, IO context, crypto resources or execution evidence.
"""
import hashlib
import sys
from types import FunctionType, MappingProxyType, ModuleType

PROGRAM_PATHS = (
    ('cli', 'deploy/installer/company_full_cli.py'),
    ('delivery', 'deploy/installer/build-full-cli-package.py'),
    ('record', 'deploy/installer/company_cli_record.py'),
    ('io', 'deploy/installer/company_cli_record_io.py'),
    ('publisher', 'deploy/installer/company_cli_record_publish.py'),
    ('captured', 'deploy/installer/company_cli_captured_publish.py'),
    ('crypto', 'deploy/installer/company_release_crypto.py'),
    ('stage', 'deploy/installer/company_cli_stage_child.py'),
)
BOOTSTRAP_PATHS = (('verifier', 'scripts/verify-release.py'),
                   ('parent', 'scripts/installer_parent.py'))
AUTHENTICATION_FIELDS = ('delivery_pin', 'launch_pins', 'package_pins',
    'operational_catalog', 'fingerprint', 'full_package_pin')
MAX_CAPTURE = 131072
MAX_TOTAL = 262144
UNRELEASED = []


class ExecuteBootstrapUnavailable(ValueError):
    pass


def _factory(public, error_type, own_namespace):
    programs, pair = PROGRAM_PATHS, BOOTSTRAP_PATHS
    labels = tuple(label for label, path in (*programs, *pair))
    auth_fields = AUTHENTICATION_FIELDS
    module_kind, function_kind, proxy = ModuleType, FunctionType, MappingProxyType
    trusted_sys, raw_hash, raw_compile, raw_exec = sys, hashlib.sha256, compile, exec
    registry, retained = {}, []
    used = failed = False

    def need(value):
        if value is not True:
            raise error_type('company-cli-execute-bootstrap-unavailable')

    def plain_rows(value, fields):
        need(type(value) is dict and all(type(key) is str for key in value)
             and len(value) == len(fields) and set(value) == set(fields))
        return tuple((key, value[key]) for key in fields)

    def same(current, expected):
        need(type(current) is dict and all(type(key) is str for key in current)
             and len(current) == len(expected)
             and all(key in current and current[key] is value for key, value in expected))

    def function_row(value):
        return (value, value.__code__, value.__closure__, value.__defaults__,
                value.__kwdefaults__, tuple(vars(value).items()))

    def snapshot(module):
        need(type(module) is module_kind)
        namespace = tuple(vars(module).items())
        need(len(namespace) <= 512 and all(type(key) is str for key, value in namespace))
        name = dict(namespace).get('__name__');need(type(name) is str)
        classes, functions = [], []
        for value in dict(namespace).values():
            if type(value) is function_kind:
                functions.append(function_row(value))
                wrapped = vars(value).get('__wrapped__')
                if type(wrapped) is function_kind:functions.append(function_row(wrapped))
            elif type(value) is type:
                origin = type.__getattribute__(value, '__module__');need(type(origin) is str)
                if origin == name:
                    table = tuple(vars(value).items())
                    need(len(table) <= 128 and all(type(key) is str for key, item in table))
                    classes.append((value, table))
                    for key, item in table:
                        if type(item) is function_kind:functions.append(function_row(item))
                        elif type(item) is property and type(item.fget) is function_kind:
                            functions.append(function_row(item.fget))
        return (module, namespace, tuple(classes), tuple(functions))

    def guard(record):
        need(not failed and not retained and record['failed'] is False)
        same(own_namespace, record['own_namespace'])
        same(dict(vars(kind)), kind_table)
        for value, code, closure, defaults, keyword_defaults, definitions in record['own_functions']:
            need(value.__code__ is code and value.__closure__ is closure
                 and value.__defaults__ is defaults and value.__kwdefaults__ is keyword_defaults)
            same(dict(vars(value)), definitions)
        need(trusted_sys.modules is record['sys_modules'] and type(record['sys_modules']) is dict)
        for name, module in record['registrations']:
            need(dict.get(record['sys_modules'], name) is module)
        for module, namespace, classes, functions in record['snapshots']:
            same(dict(vars(module)), namespace)
            for owner, table in classes:same(dict(vars(owner)), table)
            for value, code, closure, defaults, keyword_defaults, definitions in functions:
                need(value.__code__ is code and value.__closure__ is closure
                     and value.__defaults__ is defaults and value.__kwdefaults__ is keyword_defaults)
                same(dict(vars(value)), definitions)

    def retain(record, phase, problem):
        nonlocal failed
        failed = True;record['failed'] = True
        row = (record, phase, problem, tuple(record['registrations']),
               record.get('child'), tuple(record['returns']))
        retained.append(row);public.append(row)

    def owned(value):
        record = dict.get(registry, id(value))
        need(type(record) is dict and record['value'] is value)
        try:
            need(type(value) is kind)
            guard(record)
        except BaseException as problem:
            retain(record, 'issued-boundary', problem)
            raise error_type('company-cli-execute-bootstrap-unavailable') from None
        return record

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

    class ExecuteBootstrap:
        __slots__ = ()

        @property
        def construction_modules(self):
            """Guarded original IO/Crypto references, not source capabilities."""
            record = owned(self)
            need(record['phase'] == 'captured')
            return proxy({label:record['modules'][label] for label in ('io', 'crypto')})

        def prepare_child(self, *, io, crypto, delivery_raw, authentication, station):
            """Inject original D/C/V/P; caller supplies only six auth fields."""
            record = owned(self)
            need(record['phase'] == 'captured')
            record['phase'] = 'preparing'  # No reprepare after any setup attempt.
            record['borrowed'] = (io, crypto, delivery_raw, authentication, station)
            try:
                rows = plain_rows(authentication, auth_fields)
                need(type(delivery_raw) is bytes and 0 < len(delivery_raw) <= 1048576)
                auth_counter = [0, 0]
                auth = {key:copy_plain(value, auth_counter) for key, value in rows}
                auth.update(delivery_module=record['modules']['delivery'],
                    running_cli_raw=record['captures']['cli'],
                    bootstrap_records={path:record['captures'][label] for label, path in pair},
                    bootstrap_pins={path:dict(record['pins'][label]) for label, path in pair})
                record['authentication'] = auth
                guard(record)
                modules = record['modules']
                child = record['prepare'](modules['cli'], modules['record'], modules['publisher'],
                    modules['captured'], io_module=modules['io'], io=io,
                    crypto_module=modules['crypto'], crypto=crypto, delivery_raw=delivery_raw,
                    authentication=auth, station=station)
                record['child'] = child;record['returns'].append(('prepare-child', child))
                guard(record)
                need(type(child) is record['child_kind'])
                record['phase'] = 'prepared'
                return self
            except BaseException as problem:
                retain(record, 'prepare-child', problem)
                raise error_type('company-cli-execute-bootstrap-unavailable') from None

        def run_child(self):
            """Run exactly our saved original child; retain actual return DATA."""
            record = owned(self)
            need(record['phase'] == 'prepared')
            record['phase'] = 'attempted'
            try:
                guard(record)
                result = record['run'](record['child'])
                record['returns'].append(('run-child', result));record['result'] = result
                guard(record)
                need(type(result) is proxy)
                record['phase'] = 'returned-data'
                return result
            except BaseException as problem:
                retain(record, 'run-child', problem)
                raise error_type('company-cli-execute-bootstrap-unavailable') from None

    kind = ExecuteBootstrap;kind_table = tuple(vars(kind).items())

    def capture_execute_bootstrap(captures, pins, *, sys_module):
        """Admit every independent pin before compile; one dedicated context."""
        nonlocal used
        need(not used and not failed and not retained and type(public) is list and not public)
        raw_rows = plain_rows(captures, labels);pin_rows = plain_rows(pins, labels)
        need(sys_module is trusted_sys and type(sys_module) is module_kind
             and type(trusted_sys.modules) is dict)
        saved_raw, saved_pins, total = {}, {}, 0
        for (label, raw), (pin_label, pin) in zip(raw_rows, pin_rows):
            need(label == pin_label and type(raw) is bytes and 0 < len(raw) <= MAX_CAPTURE)
            fields = dict(plain_rows(pin, ('bytes', 'sha256')))
            digest = fields['sha256']
            need(type(fields['bytes']) is int and fields['bytes'] == len(raw)
                 and type(digest) is str and len(digest) == 64
                 and all(character in '0123456789abcdef' for character in digest)
                 and raw_hash(raw).hexdigest() == digest)
            total += len(raw);need(total <= MAX_TOTAL)
            saved_raw[label] = raw;saved_pins[label] = fields
        record = dict(value=None, failed=False, phase='capturing', captures=saved_raw,
            pins=saved_pins, registrations=[], snapshots=(), modules={}, returns=[],
            child=None, result=None, borrowed=None, sys_modules=trusted_sys.modules,
            own_namespace=tuple(own_namespace.items()),
            own_functions=tuple(function_row(value) for value in (*own_namespace.values(), *dict(kind_table).values())
                if type(value) is function_kind)
                + tuple(function_row(value.fget) for key, value in kind_table
                    if type(value) is property and type(value.fget) is function_kind))
        prefix = '_company_execute_bootstrap_' + format(id(record), 'x') + '_'
        need(all(prefix + label not in record['sys_modules'] for label, path in programs))
        used = True  # All ten pins admitted; consumed before first compilation.
        try:
            for label, path in programs:
                name = prefix + label
                module = module_kind(name);module.__file__ = '<independently admitted execute bootstrap ' + path + '>'
                record['modules'][label] = module
                record['registrations'].append((name, module))
                dict.__setitem__(record['sys_modules'], name, module)
                raw_exec(raw_compile(saved_raw[label], module.__file__, 'exec'), vars(module))
                need(trusted_sys.modules is record['sys_modules']
                     and dict.get(record['sys_modules'], name) is module)
            record['snapshots'] = tuple(snapshot(record['modules'][label]) for label, path in programs)
            stage = record['modules']['stage'];child_kind = vars(stage).get('ExecuteChild')
            prepare = vars(stage).get('prepare_execute_child')
            need(type(child_kind) is type and type(prepare) is function_kind
                 and prepare.__globals__ is vars(stage))
            run = vars(child_kind).get('run')
            need(type(run) is function_kind and run.__globals__ is vars(stage))
            record.update(child_kind=child_kind, prepare=prepare, run=run)
            value = object.__new__(kind);record.update(value=value,phase='captured')
            registry[id(value)] = record;guard(record)
            return value
        except BaseException as problem:
            retain(record, 'capture-programs', problem)
            raise error_type('company-cli-execute-bootstrap-unavailable') from None

    return ExecuteBootstrap, capture_execute_bootstrap


ExecuteBootstrap, capture_execute_bootstrap = _factory(UNRELEASED, ExecuteBootstrapUnavailable, globals())
del _factory


def main(argv=None):
    raise ExecuteBootstrapUnavailable('company-cli-execute-bootstrap-main-unconfigured')


if __name__ == '__main__':
    raise SystemExit(74)
