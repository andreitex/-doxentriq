"""Explicit protected input capture and pipe-output IO for the record publisher.

Initial module/OS/interpreter/endpoint origin and complete OFD-copy ownership
are independently authenticated company-entry prerequisites. This adapter owns
only its new input descriptors and the two expressly transferred pipe writers.
It neither adopts parent descriptors nor issues terminal evidence or ACK. There
is no native construction, tool selection, process or filesystem-write default.
"""
from contextlib import contextmanager
import hashlib
import math
import re
import stat
from types import FunctionType, GetSetDescriptorType, MappingProxyType, MethodDescriptorType, ModuleType

FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
LEAVES = (('request.json', 'request_raw', 4096), ('invocation.json', 'invocation_raw', 4096),
          ('plan.json', 'plan_raw', 16384))
MAX_ROWS, MAX_INPUT, MAX_OUTPUT = 16, 24576, 32768
MAX_POLL, MAX_WRITE, MAX_READ = 1024, 1024, 128
UNRELEASED = []


class RecordIOUnavailable(ValueError):
    pass


def _factory(public, error):
    # Private lifetime ledgers/latch survive replacement or in-place clearing
    # of public diagnostics. Saved callbacks are the only syscall dispatch.
    registry, retained = {}, []
    failed = False
    used = False
    fields, leaves = FIELDS, LEAVES
    row_limit, input_limit, output_limit = MAX_ROWS, MAX_INPUT, MAX_OUTPUT
    poll_limit, write_limit, read_limit = MAX_POLL, MAX_WRITE, MAX_READ
    proxy, module_type = MappingProxyType, ModuleType
    raw_sha, finite, match = hashlib.sha256, math.isfinite, re.fullmatch
    isdir, isreg, isfifo, modebits = stat.S_ISDIR, stat.S_ISREG, stat.S_ISFIFO, stat.S_IMODE
    getattribute = object.__getattribute__
    function_type, descriptor_type, dict_descriptor_type = FunctionType, MethodDescriptorType, GetSetDescriptorType
    transient_types = (BlockingIOError, InterruptedError)
    raw_errno = vars(OSError)['errno'].__get__

    def need(value):
        if value is not True:
            raise error('company-cli-record-io-unavailable')

    def shape(value, wanted):
        need(type(value) is dict and all(type(key) is str for key in value)
             and set(value) == set(wanted))

    def metadata(value):
        shape(value, fields)
        need(all(type(value[key]) is int and value[key] >= 0 for key in fields))
        return tuple(value[key] for key in fields)

    def observed(record, value):
        need(type(value) is record['stat_kind'])
        result = tuple(getattribute(value, key) for key in fields)
        need(all(type(item) is int and item >= 0 for item in result))
        return result

    def original(record):
        current = dict(vars(kind))
        need(all(type(key) is str for key in current) and len(current) == len(methods)
             and all(key in current and current[key] is item for key, item in methods))
        need(type(record['value']) is kind and getattribute(record['value'], '__dict__') is record['state'])
        need(type(record['rows']) is list and len(record['rows']) <= row_limit
             and all(type(row) is dict for row in record['rows']))
        namespace_check(record['namespaces'])
        if record['poll_tables'] is not None:
            poll_guard(record)

    def poll_guard(record):
        poll = record['poll']
        need(type(poll) is record['poll_kind'])
        for owner, saved in record['poll_tables']:
            current = dict(vars(owner))
            need(all(type(key) is str for key in current) and len(current) == len(saved)
                 and all(key in current and current[key] is item for key, item in saved))
        if record['poll_dict_getter'] is not None:
            current = record['poll_dict_getter'].__get__(poll, record['poll_kind'])
            need(type(current) is dict and current is record['poll_state'])
            need(all(type(key) is str for key in current))
            expected = {key for key, item in record['poll_state_before']}
            if record['poll_registered']:
                expected.add('fd')
                need(type(current.get('fd')) is int and current['fd'] == record['outputs']['stdout']['fd'])
            need(set(current) == expected)
            need(all(current[key] is item for key, item in record['poll_state_before']))

    def prepare_poll(record, poll):
        helper_kind = type(poll)
        need(type(helper_kind) is type)
        lineage = type.__getattribute__(helper_kind, '__mro__')
        need(type(lineage) is tuple and len(lineage) <= 8 and all(type(owner) is type for owner in lineage))
        tables = tuple((owner, tuple(vars(owner).items())) for owner in lineage)
        need(all(len(table) <= 128 and all(type(key) is str for key, item in table) for owner, table in tables))
        definitions = {}
        for name in ('register', 'poll', '__dict__'):
            definitions[name] = next((dict(table)[name] for owner, table in tables if name in dict(table)), None)
        need(all(type(definitions[name]) in (function_type, descriptor_type) for name in ('register', 'poll')))
        getter = definitions['__dict__']
        need(getter is None or type(getter) is dict_descriptor_type)
        state = None if getter is None else getter.__get__(poll, helper_kind)
        need(state is None or (type(state) is dict and len(state) <= 16
             and all(type(key) is str and key not in ('poll', 'register', 'fd') for key in state)))
        record.update(poll_kind=helper_kind, poll_tables=tables, poll_dict_getter=getter,
            poll_state=state, poll_state_before=() if state is None else tuple(state.items()),
            poll_register=definitions['register'].__get__(poll, helper_kind),
            poll_call=definitions['poll'].__get__(poll, helper_kind))
        poll_guard(record)

    def namespace_check(namespaces):
        for module, namespace in namespaces:
            current = dict(vars(module))
            need(all(type(key) is str for key in current) and len(current) == len(namespace)
                 and all(key in current and current[key] is item for key, item in namespace))

    def issued(value):
        record = registry.get(id(value))
        # Unissued values refuse before any foreign type/state observation.
        need(type(record) is dict and record['value'] is value)
        try:
            need(type(value) is kind)
            original(record)
        except BaseException as problem:
            retain(record, 'issued-boundary-unavailable', value, problem)
            raise error('company-cli-record-io-unavailable') from None
        return record

    def retain(record, reason, *refs):
        nonlocal failed
        failed = True
        record['failed'] = True
        item = (record, reason, *refs)
        retained.append(item)
        public.append(item)

    def tick(record):
        current = record['clock']()
        original(record)
        need(type(current) in (int, float) and finite(current)
             and record['last'] <= current < record['end']-1)
        record['last'] = current

    def live(record):
        original(record)
        need(record['failed'] is False and not failed and not retained)
        tick(record)

    def own(record, fd, role, expected=None):
        # A returned descriptor is registered before metadata admission. Invalid
        # or aliased acquisition values are retained; never guessed or closed.
        record['returns'].append((role, fd))
        need(type(fd) is int and 3 <= fd <= 1048575 and fd not in record['protected']
             and len(record['rows']) < row_limit
             and not any(row['fd'] == fd and row['closed'] is False for row in record['rows']))
        row = dict(fd=fd, role=role, identity=expected, attempted=False, closed=False)
        record['rows'].append(row)
        return row

    def call(record, operation, *args, **kwargs):
        result = record[operation](*args, **kwargs)
        record['observations'].append((operation, args, kwargs, result))
        original(record)
        return result

    def close_row(record, row, accepting=False):
        # No live module/class/adapter lookup on unwind. These are the private
        # original rows and raw callbacks saved before acquisition.
        if row['closed']:
            return
        need(row['attempted'] is False)
        row['attempted'] = True
        try:
            if row['identity'] is not None:
                actual = observed(record, record['fstat'](row['fd']))
                need(actual[:6] == row['identity'][:6])
            result = record['close'](row['fd'])
            need(result is None)
            row['closed'] = True
        except BaseException as problem:
            retain(record, 'close-unknown', row, problem, record['close'], record['fstat'])
            raise error('company-cli-record-io-close-unknown') from None
        if accepting:
            try:
                original(record)
            except BaseException as problem:
                retain(record, 'known-close-boundary-drift', row, result, problem)
                raise error('company-cli-record-io-boundary-unavailable') from None

    def close_roles(record, outputs):
        problems = []
        for row in reversed(record['rows']):
            selected = row['role'] in ('stdout', 'stderr')
            if selected == outputs and row['closed'] is False:
                if row['attempted']:
                    problems.append(row)
                    continue
                try:
                    close_row(record, row, accepting=True)
                except BaseException as problem:
                    problems.append((row, problem))
        need(not problems)

    def endpoint(record, row, whole=False):
        actual = observed(record, call(record, 'fstat', row['fd']))
        old = row['identity']
        need(actual == old if whole else actual[:6] == old[:6])
        flags = call(record, 'fcntl', row['fd'], 3)
        fdflags = call(record, 'fcntl', row['fd'], 1)
        need(type(flags) is int and flags == row['flags'] and type(fdflags) is int and fdflags == 1)

    def read_file(record, row):
        expected = row['identity']
        need(observed(record, call(record, 'fstat', row['fd'])) == expected)
        body, offset = [], 0
        while offset < row['bytes']:
            live(record)
            record['reads'] += 1
            need(record['reads'] <= read_limit)
            raw = call(record, 'pread', row['fd'], min(4096, row['bytes']-offset), offset)
            need(type(raw) is bytes and 0 < len(raw) <= min(4096, row['bytes']-offset))
            body.append(raw)
            offset += len(raw)
        record['reads'] += 1
        need(record['reads'] <= read_limit)
        tail = call(record, 'pread', row['fd'], 1, offset)
        need(type(tail) is bytes and tail == b'')
        value = b''.join(body)
        need(raw_sha(value).hexdigest() == row['sha256']
             and observed(record, call(record, 'fstat', row['fd'])) == expected)
        return value

    def input_guard(record):
        live(record)
        need(record['inputs_released'] is False)
        for row in record['rows']:
            if row['role'] in ('stdout', 'stderr'):
                continue
            need(row['closed'] is False and row['attempted'] is False
                 and observed(record, call(record, 'fstat', row['fd'])) == row['identity'])
            actual = call(record, 'stat', row['name'], dir_fd=row['parent'], follow_symlinks=False)
            need(observed(record, actual) == row['identity'])
            flags = call(record, 'fcntl', row['fd'], 3)
            fdflags = call(record, 'fcntl', row['fd'], 1)
            need(type(flags) is int and flags == row['flags'] and type(fdflags) is int and fdflags == 1)
        for name, key, cap in leaves:
            row = record['files'][name]
            need(read_file(record, row) == record['captured'][key])

    def acquire(record, name, flags, parent, role):
        live(record)
        record['attempts'].append(('open', name, flags, parent))
        fd = record['open'](name, flags, dir_fd=parent)
        row = own(record, fd, role)
        original(record)
        row.update(name=name, parent=parent)
        return row

    def admit_file(record, row, directory, cap=None, expected=None):
        actual = observed(record, call(record, 'fstat', row['fd']))
        path = observed(record, call(record, 'stat', row['name'], dir_fd=row['parent'], follow_symlinks=False))
        need(actual == path and actual[3:5] == (0, 0))
        if directory:
            need(isdir(actual[2]) and modebits(actual[2]) in (448, 493) and actual[5] >= 2)
        else:
            need(isreg(actual[2]) and modebits(actual[2]) == 256 and actual[5] == 1
                 and 0 < actual[6] <= cap)
        if expected is not None:
            need(actual == expected)
        flags = call(record, 'fcntl', row['fd'], 3)
        fdflags = call(record, 'fcntl', row['fd'], 1)
        required = 131072 | 2048 | (65536 if directory else 0)
        need(type(flags) is int and (flags & ~32768) == required
             and type(fdflags) is int and fdflags == 1)
        row.update(identity=actual, flags=flags)

    class PublisherIO:
        @property
        def captured_inputs(self):
            record = issued(self)
            try:
                input_guard(record)
                return proxy(dict(record['captured']))
            except BaseException as problem:
                retain(record, 'input-capture-drift', problem)
                raise error('company-cli-record-io-unavailable') from None

        def release_inputs(self):
            record = issued(self)
            need(record['input_close_attempted'] is False)
            record['input_close_attempted'] = True
            problem = None
            try:
                input_guard(record)
            except BaseException as caught:
                problem = caught
                retain(record, 'input-release-observation-unavailable', caught)
            try:
                close_roles(record, False)
            except BaseException as caught:
                if problem is None:
                    problem = caught
            if problem is not None:
                raise error('company-cli-record-io-unavailable') from None
            record['inputs_released'] = True
            return self

        def write_stdout(self, raw):
            record = issued(self)
            need(record['write_attempted'] is False)
            record['write_attempted'] = True
            record['output_raw'] = raw
            try:
                live(record)
                need(record['inputs_released'] is True and type(raw) is bytes and 0 < len(raw) <= output_limit)
                row = record['outputs']['stdout']
                need(row['closed'] is False and row['attempted'] is False)
                endpoint(record, row)
                while True:
                    live(record)
                    record['polls'] += 1
                    need(record['polls'] <= poll_limit)
                    try:
                        events = call(record, 'poll_call', min(100, max(1, int((record['end']-1-record['last'])*1000))))
                    except transient_types as problem:
                        need(any(type(problem) is item for item in transient_types))
                        number = raw_errno(problem, OSError)
                        need(type(number) is int and number in (4, 11))
                        continue
                    need(type(events) is list and len(events) <= 1)
                    if not events:
                        continue
                    event = events[0]
                    need(type(event) is tuple and len(event) == 2 and type(event[0]) is int
                         and event[0] == row['fd'] and type(event[1]) is int and event[1] == 4)
                    endpoint(record, row)
                    record['writes'] += 1
                    need(record['writes'] <= write_limit)
                    try:
                        result = record['write'](row['fd'], raw)
                    except transient_types as problem:
                        # Only known zero-byte transient syscall outcomes can
                        # repeat within this same write attempt/deadline.
                        need(any(type(problem) is item for item in transient_types))
                        number = raw_errno(problem, OSError)
                        need(type(number) is int and number in (4, 11))
                        continue
                    record['accepted'] = result  # Preserve before further refusal.
                    original(record)
                    need(type(result) is int and result == len(raw))
                    endpoint(record, row)
                    return result
            except BaseException as problem:
                retain(record, 'output-write-unavailable', raw, record['accepted'], problem)
                raise error('company-cli-record-io-unavailable') from None

        def close_outputs(self):
            # Cleanup deliberately uses only captured raw callbacks/private rows;
            # changed public OS/class bindings are never invoked on unwind.
            record = registry.get(id(self))
            need(type(self) is kind and type(record) is dict and record['value'] is self)
            need(record['output_close_attempted'] is False)
            record['output_close_attempted'] = True
            close_roles(record, True)
            original(record)
            record['outputs_released'] = True
            return self

    kind = PublisherIO
    methods = tuple(vars(kind).items())

    def require_publisher_io(value):
        issued(value)
        return value

    def require_inputs_released(value):
        record = issued(value)
        need(record['inputs_released'] is True and all(row['closed'] is True for row in record['rows']
             if row['role'] not in ('stdout', 'stderr')))
        return value

    def require_released(value):
        # No external namespace/callback is needed to observe privately known
        # descriptor closure after a failed operation. This never revives IO.
        record = registry.get(id(value))
        need(type(value) is kind and type(record) is dict and record['value'] is value)
        need(all(row['closed'] is True for row in record['rows']) and record['acquisition_unknown'] is False)
        return value

    @contextmanager
    def hold_publisher_io(directory, *, directory_identity, input_pins, outputs,
            os_module, sys_module, fcntl_module, select_module,
            clock, seconds, protected_fds=()):
        nonlocal used
        need(not used and not failed and not retained and type(public) is list and not public)
        need(type(directory) is str and match('/opt/autosoft-company/evidence/[a-f0-9]{32}/(company-platform-store|company-source-materialize)', directory) is not None
             and directory.split('/')[4] != '0'*32)
        expected = metadata(directory_identity)
        shape(input_pins, tuple(name for name, key, cap in leaves))
        for name, key, cap in leaves:
            shape(input_pins[name], ('bytes', 'sha256'))
            need(type(input_pins[name]['bytes']) is int and 0 < input_pins[name]['bytes'] <= cap
                 and type(input_pins[name]['sha256']) is str and match('[a-f0-9]{64}', input_pins[name]['sha256']) is not None)
        need(sum(input_pins[name]['bytes'] for name, key, cap in leaves) <= input_limit)
        pins = {name: (input_pins[name]['bytes'], input_pins[name]['sha256']) for name, key, cap in leaves}
        shape(outputs, ('stdout', 'stderr'))
        handoff = []
        for role in ('stdout', 'stderr'):
            row = outputs[role]
            shape(row, ('fd', 'identity', 'flags', 'fdFlags'))
            identity = metadata(row['identity'])
            need(type(row['fd']) is int and 3 <= row['fd'] <= 1048575 and isfifo(identity[2])
                 and identity[3:6] == (0, 0, 1) and modebits(identity[2]) == 384
                 and type(row['flags']) is int and row['flags'] == 2049
                 and type(row['fdFlags']) is int and row['fdFlags'] == 1)
            handoff.append((role, row['fd'], identity, row['flags']))
        need(handoff[0][1] != handoff[1][1] and handoff[0][2][:2] != handoff[1][2][:2])
        need(type(protected_fds) in (tuple, list) and len(protected_fds) <= 16
             and all(type(fd) is int and 3 <= fd <= 1048575 for fd in protected_fds)
             and len(set(protected_fds)) == len(protected_fds)
             and not any(row[1] in protected_fds for row in handoff))
        supplied = (os_module, sys_module, fcntl_module, select_module)
        need(all(type(module) is module_type for module in supplied))
        namespaces = tuple((module, tuple(vars(module).items())) for module in supplied)
        need(all(all(type(key) is str for key, item in namespace) for module, namespace in namespaces))
        raw_operations = dict(open=os_module.open, stat=os_module.stat, fstat=os_module.fstat,
            pread=os_module.pread, close=os_module.close, write=os_module.write,
            fcntl=fcntl_module.fcntl, poll_factory=select_module.poll,
            uname=os_module.uname, clock=clock)
        need(all(callable(value) for value in raw_operations.values()))
        constants = ('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK', 'O_DIRECTORY')
        values = tuple(getattr(os_module, name) for name in constants)
        need(all(type(value) is int for value in values) and values == (0, 131072, 524288, 2048, 65536))
        # One valid acquisition attempt per independently authenticated module
        # lifetime. Pure structural refusal above does not consume the entry;
        # before the first external callback, valid admission is irrevocable.
        used = True
        uname_kind, stat_kind = os_module.uname_result, os_module.stat_result
        need(type(uname_kind) is type and type(stat_kind) is type)
        uname = raw_operations['uname']()
        namespace_check(namespaces)
        need(type(uname) is uname_kind)
        machine = getattribute(uname, 'machine')
        need(type(sys_module.platform) is str and sys_module.platform == 'linux'
             and type(machine) is str and machine == 'x86_64')
        need(type(fcntl_module.F_GETFL) is int and fcntl_module.F_GETFL == 3
             and type(fcntl_module.F_GETFD) is int and fcntl_module.F_GETFD == 1)
        raw_open, raw_stat = raw_operations['open'], raw_operations['stat']
        for group, callback in ((os_module.supports_dir_fd, raw_open), (os_module.supports_dir_fd, raw_stat),
                                (os_module.supports_follow_symlinks, raw_stat)):
            need(type(group) in (set, frozenset) and any(item is callback for item in group))
        need(type(seconds) is int and 2 <= seconds <= 300 and callable(clock))
        started = raw_operations['clock']()
        namespace_check(namespaces)
        need(type(started) in (int, float) and finite(started))
        value = object.__new__(kind)
        record = dict(value=value, state=getattribute(value, '__dict__'), rows=[], returns=[], attempts=[], observations=[],
            namespaces=namespaces, protected=tuple(protected_fds), clock=clock, last=started, end=started+seconds,
            open=raw_open, stat=raw_stat, fstat=raw_operations['fstat'], pread=raw_operations['pread'],
            close=raw_operations['close'], write=raw_operations['write'], fcntl=raw_operations['fcntl'],
            stat_kind=stat_kind,
            poll=None, poll_call=None, poll_register=None, poll_tables=None, poll_kind=None,
            poll_dict_getter=None, poll_state=None, poll_state_before=(), poll_registered=False,
            reads=0, polls=0, writes=0, failed=False, acquisition_unknown=False,
            files={}, outputs={}, captured={}, input_close_attempted=False,
            output_close_attempted=False, inputs_released=False, outputs_released=False,
            write_attempted=False, output_raw=None, accepted=None)
        need(all(callable(record[key]) for key in ('open', 'stat', 'fstat', 'pread', 'close', 'write', 'fcntl')))
        registry[id(value)] = record
        body_complete = False
        try:
            original(record)
            # Ownership transfers here, before any adapter IO. No dup/adoption
            # of P.ParentInput handles or baseline descriptors is performed.
            for role, fd, identity, flags in handoff:
                row = own(record, fd, role, identity)
                row['flags'] = flags
                record['outputs'][role] = row
            for row in record['outputs'].values():
                endpoint(record, row, True)
            directories = directory.split('/')[1:]
            parent = None
            for name in ['/', *directories]:
                row = acquire(record, name, 0 | 131072 | 524288 | 2048 | 65536, parent, 'directory')
                admit_file(record, row, True, expected=expected if name == directories[-1] else None)
                parent = row['fd']
            for name, key, cap in leaves:
                row = acquire(record, name, 0 | 131072 | 524288 | 2048, parent, 'input')
                admit_file(record, row, False, cap=cap)
                need(row['identity'][6] == pins[name][0])
                row.update(bytes=pins[name][0], sha256=pins[name][1])
                record['files'][name] = row
                record['captured'][key] = read_file(record, row)
            poll = raw_operations['poll_factory']()
            record['poll'] = poll
            original(record)
            prepare_poll(record, poll)
            record['poll_registered'] = True
            call(record, 'poll_register', record['outputs']['stdout']['fd'], 4)
            original(record)
            input_guard(record)
            yield value
            original(record)
            need(all(row['closed'] is True for row in record['rows']))
            body_complete = True
        except BaseException as problem:
            # An acquisition failure can have an unreturned owned outcome. Keep
            # original args/callbacks/returns; never infer or numerically retry it.
            if record['poll'] is None:
                record['acquisition_unknown'] = True
            retain(record, 'io-scope-unavailable', problem, tuple(record['attempts']), tuple(record['returns']))
            raise error('company-cli-record-io-unavailable') from None
        finally:
            problems = []
            for row in reversed(record['rows']):
                if not row['closed'] and not row['attempted']:
                    try:
                        close_row(record, row)
                    except BaseException as problem:
                        problems.append((row, problem))
            if problems:
                retain(record, 'scope-disposal-unknown', tuple(problems))
            if body_complete:
                need(not problems and all(row['closed'] for row in record['rows']))

    return kind, hold_publisher_io, require_publisher_io, require_inputs_released, require_released


PublisherIO, hold_publisher_io, require_publisher_io, require_inputs_released, require_released = _factory(UNRELEASED, RecordIOUnavailable)
del _factory


def main(argv=None):
    raise RecordIOUnavailable('company-cli-record-io-main-unconfigured')


if __name__ == '__main__':
    raise SystemExit(74)
