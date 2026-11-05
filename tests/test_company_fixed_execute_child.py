"""Actual original child APIs with three declared pre-auth RAM source seams.

No prior unittest classes, native files, sockets, processes or OpenSSL are used.
Only explicitly pinned named RAM helper definitions are selected from fixtures.
"""
import ast
import hashlib
import json
from pathlib import Path
import stat
import sys
from types import CodeType, FunctionType, GetSetDescriptorType, MappingProxyType, ModuleType, SimpleNamespace, TracebackType
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
DATA = '/srv/seed-data'
OPERATION = 'a' * 32
LOGICAL = ('/opt/autosoft-company/incoming/release', '/opt/autosoft-company/bootstrap/company.pem',
           '/opt/autosoft-company/incoming/source')
FIXTURE_PINS = {
    'tests/test_company_signed_execute_preparation.py': 'cf686a40862af0032a857eacb899583c39006082dd8966f0af0a08217683ea57',
    'tests/test_authenticated_seed.py': 'a542927968dadce36f7218f7ccb8a0210a8656ad84c8e7182873734d1bce782e',
    'scripts/test-installer-parent.py': '7a4cca80c1d0d584d17e3e156d4bcfd496b49d1640011532c7c0156dd662f7a3',
    'tests/test_company_seed_runner.py': 'fe44538e9f2c120f0dc5022d1f5b862d7283513b704be030214d223ac80f8ea8',
    'tests/test_company_release_crypto.py': '81fd35ce5e2c509a02025508bfd7b6fc844e8ed79d6fb853f3e7c17be8758807',
    'tests/test_company_cli_record_io.py': '53184cc1c97ea0687ae0b687aaaf33e02bbf57cd229c7765ea77e57ef95e554d',
}
RETAINED_FIXTURES = []  # Exact failed RAM scopes stay referenced; no release claim.


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def seed_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def named_fixture(path, names, assignments=(), supplied=None):
    raw = (ROOT / path).read_bytes()
    assert len(raw) <= 65536 and sha(raw) == FIXTURE_PINS[path]
    nodes = []
    for node in ast.parse(raw).body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            nodes.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in assignments for target in node.targets):
            nodes.append(node)
    assert {node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.ClassDef))} == set(names)
    value = ModuleType('fixed_child_named_' + path.replace('/', '_').replace('.', '_'))
    value.__file__ = str(ROOT / path)
    value.ROOT = ROOT
    if supplied:
        vars(value).update(supplied)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<explicit bounded named RAM fixture definitions>', 'exec'), vars(value))
    return value


SIGNED = named_fixture('tests/test_company_signed_execute_preparation.py',
    {'fixture_basis', 'helper_profile', 'contains', 'Fixture'},
    ('ROOT', 'HERE', 'BASIS', 'BASIS_PIN', 'PROFILE_PIN', 'T', 'HELPERS'))


def failure_observation(namespaces, primary):
    """Bounded metadata from known original ledgers; never exception text."""
    traceback_getter = BaseException.__dict__['__traceback__'].__get__
    cause_getter = BaseException.__dict__['__cause__'].__get__
    context_getter = BaseException.__dict__['__context__'].__get__
    classes = [(ValueError, 'ValueError'), (AssertionError, 'AssertionError'), (TypeError, 'TypeError'),
               (AttributeError, 'AttributeError'), (KeyError, 'KeyError'), (OSError, 'OSError')]
    names = ('FixedChildUnavailable', 'ExecuteBootstrapUnavailable', 'StageChildUnavailable',
             'CapturedPublishUnavailable', 'RecordPublishUnavailable', 'FullCliUnavailable',
             'WorkerUnavailable', 'SourceUnavailable', 'RecordIOUnavailable', 'ReleaseCryptoUnavailable')
    roots, work = [], [(primary, 0)]
    for label, namespace in namespaces:
        if type(label) is not str or type(namespace) is not dict:
            raise ValueError('diagnostic-shape')
        for name in names:
            kind = dict.get(namespace, name)
            if type(kind) is type and any(base is BaseException for base in type.__getattribute__(kind, '__mro__')):
                classes.append((kind, name))
        rows = dict.get(namespace, 'UNRELEASED')
        if type(rows) is list and len(rows) <= 16:
            roots.append(dict(module=label, rows=len(rows), shapeKnown=True))
            work.extend((row, 0) for row in rows)
        else:
            roots.append(dict(module=label, rows=None, shapeKnown=False))
    phases = frozenset(('prepared', 'preparing', 'attempted', 'captured', 'returned-data', 'closed',
                       'published-data', 'failed', 'fixed-child-run', 'run-child', 'prepare-child',
                       'execute-child-unavailable', 'original-dispatch-unavailable', 'record-publication-unavailable',
                       'publisher-boundary-unavailable', 'publisher-admission-unavailable', 'issued-boundary',
                       'issued-boundary-unavailable', 'cli-composition-release-unknown', 'post-worker-return-refusal'))
    errors, phase_data, seen, examined, exhausted = [], [], set(), 0, False
    while work:
        value, depth = work.pop()
        if id(value) in seen:
            continue
        seen.add(id(value)); examined += 1
        if examined > 256 or depth > 8:
            exhausted = True
            break
        kind = type(value)
        is_error = type(kind) is type and any(base is BaseException for base in type.__getattribute__(kind, '__mro__'))
        if is_error:
            if len(errors) >= 16:
                exhausted = True
                break
            label = next((name for original, name in classes if kind is original), 'OtherOriginalError')
            trace, frames = traceback_getter(value, kind), []
            for unused in range(8):
                if trace is None:
                    break
                if type(trace) is not TracebackType:
                    raise ValueError('diagnostic-trace-shape')
                code = trace.tb_frame.f_code
                if type(code) is not CodeType or type(code.co_filename) is not str or type(code.co_name) is not str:
                    raise ValueError('diagnostic-code-shape')
                if len(code.co_filename) > 512 or len(code.co_name) > 128 or type(trace.tb_lineno) is not int:
                    raise ValueError('diagnostic-code-cap')
                frames.append(dict(filename=code.co_filename, line=trace.tb_lineno, function=code.co_name))
                trace = trace.tb_next
            errors.append(dict(errorClass=label, traceback=frames, tracebackTruncated=trace is not None))
            work.extend((item, depth+1) for item in (cause_getter(value, kind), context_getter(value, kind)) if item is not None)
        elif kind is tuple or kind is list:
            if len(value) > 96:
                exhausted = True
            else:
                work.extend((item, depth+1) for item in value)
        elif type(value) is dict:
            if len(value) > 96 or any(type(key) is not str for key in value):
                exhausted = True
            else:
                for key in ('phase', 'reason'):
                    item = dict.get(value, key)
                    if type(item) is str and item in phases:
                        phase_data.append(dict(field=key, value=item))
                work.extend((item, depth+1) for item in value.values())
        elif type(value) is str and value in phases:
            phase_data.append(dict(field='retained-label', value=value))
    result = dict(scope='FIXED_CHILD_FAILURE_METADATA_DATA_ONLY', roots=roots, errors=errors,
                  phases=phase_data[:32], examinedNodes=examined, boundedTraversalExhausted=exhausted,
                  cleanupQualified=False, executionEvidenceIssued=False, stageAcknowledged=False)
    raw = json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(raw) > 16384:
        return b'{"scope":"FIXED_CHILD_FAILURE_METADATA_DATA_ONLY","diagnosticUnavailable":true,"reason":"metadata-cap"}'
    return raw


class Fixture:
    serial = 0

    def __init__(self, *, fault=None):
        Fixture.serial += 1
        self.module_name = 'fixed_execute_ram_station_' + str(Fixture.serial)
        self.adapter = ModuleType(self.module_name)
        sys.modules[self.module_name] = self.adapter
        self.aliases = None
        self.source_profiles = {}
        self.source_prefixes = {}
        self.restores = []
        self.fault = fault
        self.fixed = None
        self.run_result = None
        self.entry_record = None
        self.native_calls = []
        self.mount_calls = []
        self.completed_raw = None
        self.plan_cli = None
        self.execute_cli = None
        self.plan = None
        self.parent = None
        self.plan_parent = None

        def source_profile(basis):
            virtual = Path(ROOT.anchor) / ('authenticated-cli-inputs-fixture-' + str(SIGNED.T.Fixture.serial))
            self.aliases = MappingProxyType(dict(zip(LOGICAL, (str(virtual / 'bundle'),
                                                             str(virtual / 'keys' / 'company.pem'),
                                                             str(virtual / 'source')))))
            cli_path, verifier_path, startup_path = ('deploy/installer/company_full_cli.py',
                                                    'scripts/verify-release.py', 'scripts/startup_binding.py')
            additions = {
                cli_path: ("\ndef _fixed_fixture_native_stage_inputs(self,request_raw,**station):\n"
                           " import " + self.module_name + " as fixture\n"
                           " return fixture.native(self,request_raw,station)\n"
                           "FullCli.native_stage_inputs=_fixed_fixture_native_stage_inputs\n").encode(),
                verifier_path: ("\nfrom types import MappingProxyType as _fixed_fixture_proxy\n"
                                "_fixed_fixture_aliases=_fixed_fixture_proxy(" + repr(dict(self.aliases)) + ")\n"
                                "_fixed_fixture_original_authenticated_platform_source=authenticated_platform_source\n"
                                "def authenticated_platform_source(directory,public_key,fingerprint,*,expected_architecture,source_root,files=None,crypto=None,owner_uid=0,owner_gid=0):\n"
                                " values=(directory,public_key,source_root)\n"
                                " require(all(type(value) in (str,type(Path('.'))) for value in values))\n"
                                " logical=tuple(str(value).replace('\\\\','/') for value in values)\n"
                                " expected=" + repr(LOGICAL) + "\n"
                                " if logical==expected:\n"
                                "  directory,public_key,source_root=tuple(_fixed_fixture_aliases[path] for path in expected)\n"
                                " else:require(not any(path in _fixed_fixture_aliases for path in logical))\n"
                                " return _fixed_fixture_original_authenticated_platform_source(directory,public_key,fingerprint,expected_architecture=expected_architecture,source_root=source_root,files=files,crypto=crypto,owner_uid=owner_uid,owner_gid=owner_gid)\n").encode(),
                startup_path: ("\n_fixed_fixture_original_encrypted_proof=encrypted_proof\n"
                               "def encrypted_proof(data,receipt,*,command=Q.output):\n"
                               " import " + self.module_name + " as fixture\n"
                               " return fixture.encrypted(data,receipt,command)\n").encode(),
            }
            for path, addition in additions.items():
                original = basis.values[path]
                basis.values[path] = original + addition
                self.source_prefixes[path] = original
                self.source_profiles[path] = basis.values[path]
                assert basis.values[path].startswith(original)

        self.signed = SIGNED.Fixture(source_profile)
        self.base = self.signed.base
        self.diagnostic_files_kind = type(self.base.files)
        self.diagnostic_files_table = tuple(vars(self.diagnostic_files_kind).items())
        self.diagnostic_files_dict_getter = dict(self.diagnostic_files_table)['__dict__']
        assert type(self.diagnostic_files_dict_getter) is GetSetDescriptorType
        self.diagnostic_files_state = self.diagnostic_files_dict_getter.__get__(self.base.files, self.diagnostic_files_kind)
        self.preparation = self.signed.prepare()
        self.bootstrap = self.preparation.bootstrap
        self.modules = self.preparation.construction_modules
        self.crypto_module = self.modules['crypto']
        self.io_module = self.modules['io']
        self.programs = {name.rsplit('_', 1)[1]: module for name, module in self.signed.registrations().items()}
        self.C = self.programs['cli']
        self.E = SIGNED.T.load(self.base.prefix + '_fixed_entry', ROOT / 'deploy/installer/company_fixed_execute_child.py')
        bootstrap_function = vars(type(self.bootstrap))['run_child']
        assert type(bootstrap_function) is FunctionType
        self.diagnostic_namespaces = [('Entry', vars(self.E)), ('Bootstrap', bootstrap_function.__globals__),
            ('StageChild', vars(self.programs['stage'])), ('Captured', vars(self.programs['captured'])),
            ('Publisher', vars(self.programs['publisher'])), ('C', vars(self.C)),
            ('IO', vars(self.io_module)), ('Crypto', vars(self.crypto_module))]
        self.admitted_data = self.preparation.capture_preparation()
        self._ram_primitives()
        self._seed_storage()
        self.adapter.native = self.native
        self.adapter.encrypted = self.encrypted
        self._plan_stage()

    def _ram_primitives(self):
        seed = named_fixture('tests/test_company_seed_runner.py', {'Clock', 'Harness'},
                             supplied={'R': SimpleNamespace(FIELDS=FIELDS, TOOLS=('/usr/bin/openssl',))})
        crypto = named_fixture('tests/test_company_release_crypto.py', {'Harness'},
                               supplied={'T': seed, 'C': self.crypto_module})
        self.h = crypto.Harness()
        self.h.reuse = False
        self.h.fd = 300
        self.h.os.O_RDONLY = 0
        self.h.os.O_RDWR = 2
        self.h.os.O_NOFOLLOW = 131072
        self.h.os.O_CLOEXEC = 524288
        self.h.os.O_DIRECTORY = 65536
        self.h.os.O_NONBLOCK = 2048
        self.h.os.O_LARGEFILE = 0
        self.h.os.stat_result = self.h.os.uname_result = SimpleNamespace
        io = named_fixture('tests/test_company_cli_record_io.py', {'RAM'}, ('PATH', 'FIELDS'))
        self.r = io.RAM(self.io_module)
        self.io_path = io.PATH
        self.r.offset = 200
        self.r.handles[1000] = self.r.handles.pop(40)
        self.r.handles[1001] = self.r.handles.pop(41)
        h, r = self.h, self.r
        original_popen = h.subprocess.Popen
        class Popen(original_popen):
            def __init__(self, argv, **kwargs):
                if h.starts:
                    h.pid += 1
                h.killed = h.reaped = h.descendant = False
                original_popen.__init__(self, argv, **kwargs)
        h.subprocess.Popen = Popen
        os_module = h.os
        original = {name: getattr(os_module, name) for name in ('open', 'stat', 'fstat', 'pread', 'close', 'write')}
        def opened(name, flags, *, dir_fd=None):
            if dir_fd in r.handles or dir_fd is None and name in r.metas and flags & 2048:
                return r.open(name, flags, dir_fd=dir_fd)
            return original['open'](name, flags, dir_fd=dir_fd)
        def observed(name, *, dir_fd=None, follow_symlinks=True):
            if type(name) is str and name.startswith('/proc/self/fd/'):
                return original['stat'](name)
            return r.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        def descriptor(fd):
            return r.fstat(fd) if fd in r.handles else original['fstat'](fd)
        def read(fd, amount, offset):
            return r.pread(fd, amount, offset) if fd in r.handles else original['pread'](fd, amount, offset)
        def closed(fd):
            return r.close(fd) if fd in r.handles else original['close'](fd)
        def written(fd, raw):
            return r.write(fd, raw) if fd in r.handles else original['write'](fd, raw)
        for name, value in (('open', opened), ('stat', observed), ('fstat', descriptor), ('pread', read), ('close', closed), ('write', written)):
            setattr(os_module, name, value)
        os_module.supports_dir_fd = {opened, observed}
        os_module.supports_follow_symlinks = {observed}
        self.h.fcntl.F_GETFL, self.h.fcntl.F_GETFD = 3, 1
        original_fcntl = self.h.fcntl.fcntl
        def flags(fd, command, *args):
            return r.fcntl(fd, command) if fd in r.handles else original_fcntl(fd, command, *args)
        self.h.fcntl.fcntl = flags
        class Poll:
            __slots__ = ('fd',)
            def __init__(self):
                pass
            def register(self, fd, mask):
                self.fd = fd
                r.hook('register', fd, mask)
            def unregister(self, fd):
                assert fd == self.fd
                del self.fd
            def poll(self, milliseconds):
                h.clock.now += milliseconds / 1000
                if r.poll_events:
                    value = r.poll_events.pop(0)
                    if isinstance(value, BaseException):
                        raise value
                    return value
                return [(self.fd, 4 if self.fd in r.handles else 1)]
        self.h.select.poll = Poll
        self.platform = ModuleType('fixed_ram_platform')
        self.ctypes = ModuleType('fixed_ram_ctypes')
        self.platform.machine = lambda: 'x86_64'
        def clock():
            h.clock.now += 0.000001
            r.hook('clock')
            return h.clock.now
        self.clock = clock
        self.station = dict(os_module=self.h.os, sys_module=self.h.sys,
            platform_module=self.platform, select_module=self.h.select, ctypes_module=self.ctypes,
            libc=object(), subprocess_module=self.h.subprocess, signal_module=self.h.signal,
            io_module=self.h.io, fcntl_module=self.h.fcntl, tool_catalog={}, backend_budget={}, runner_budget={},
            clock=clock, files=self.base.files)
        self.crypto_configuration = dict(openssl_pin=self.h.pin(), budget=dict(calls=16, seconds=240),
            station_contract=self.crypto_module.STATION_CONTRACT, protected_fds=(0, 1, 2, 1000, 1001))

    def _seed_storage(self):
        seed = named_fixture('tests/test_authenticated_seed.py', {'SeedBackend', 'SeedRunner', 'parse_index'},
                             supplied={'B': SimpleNamespace(SEED_FIELDS=FIELDS)})
        self.backend_module = ModuleType(self.module_name + '_adapters')
        base_backend, base_runner = seed.SeedBackend, seed.SeedRunner
        class SeedBackend(base_backend):
            def chmod(self, fd, mode):
                node = self.handles[fd]
                node['info']['st_mode'] = stat.S_IFMT(node['info']['st_mode']) | mode
                self.tick += 1
                node['info']['st_ctime_ns'] = self.tick
            def require_released(self):
                if self.handles:
                    raise ValueError('RAM backend still holds descriptors')
                return self
        class SeedRunner(base_runner):
            def require_released(self):
                if self.unknown:
                    raise ValueError('RAM command release unknown')
                return self
        self.backend_module.SeedBackend = SeedBackend
        self.backend_module.SeedRunner = SeedRunner
        self.backend = SeedBackend()
        self.runner = SeedRunner(self.backend)
        fs = self.backend
        installation = DATA + '/company/host-releases/install-' + OPERATION
        for path, mode in ((DATA, 0o700), (DATA + '/config', 0o700), (DATA + '/config/runtime-layout', 0o700),
                           (DATA + '/config/repository-seed', 0o700), (DATA + '/runtime', 0o755),
                           (DATA + '/runtime/storage', 0o700), ('/etc/autosoft', 0o700), (installation, 0o700),
                           (DATA + '/company/platform-releases', 0o700), (DATA + '/company/source-releases', 0o700)):
            fs.directory(path, mode=mode)
        tree = ast.parse((ROOT / 'scripts/runtime_layout.py').read_bytes())
        names = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
                                  and any(isinstance(target, ast.Name) and target.id == 'BROKER_DIRECTORIES' for target in node.targets)))
        for name in names:
            fs.directory(DATA + '/runtime/' + name, 10001, 10001)
        def binding(path):
            return {key: str(fs.nodes[path]['info'][key]) for key in FIELDS[:5]}
        proposal = dict(data_dir=DATA, install_root=installation, storage_file='/srv/backing.luks', capacity_gib=32)
        intent = dict(schemaVersion=1, scope='HOST_INSTALLATION_IDENTITY_ONLY',
            installation_id='12345678-1234-4234-8234-123456789012', directory=binding('/etc/autosoft'), proposal=proposal)
        final = dict(data_dir=DATA, install_root=installation, storage_file=proposal['storage_file'], installation_id=intent['installation_id'])
        self.receipt = dict(final, creation_stage='new-luks-created', luks_uuid='87654321-4321-4321-8321-210987654321')
        initial = dict(schemaVersion=1, scope='RUNTIME_PLACEMENT_ONLY',
            dataRootSha256=sha(seed_bytes(dict(path=DATA, device=1, inode=fs.nodes[DATA]['info']['st_ino'],
                                           mode=fs.nodes[DATA]['info']['st_mode'], uid=0, gid=0))),
            directories=list(names), controls={'config': binding(DATA + '/config'), 'base': binding(DATA + '/config/runtime-layout')})
        build_mount = dict(target=DATA + '/runtime/builds', filesystem='tmpfs', maximumBytes=2147483648,
                           uid=10001, gid=10001, mode=0o700, nosuid=True, nodev=True)
        layout = dict(intentSha256=sha(seed_bytes(initial)),
            directories={name: binding(DATA + '/runtime' if name == 'runtime' else DATA + '/runtime/' + name)
                         for name in ('runtime', 'storage', *names)}, buildMount=build_mount)
        for path, value in (('/etc/autosoft/installation.intent.json', intent), ('/etc/autosoft/installation.json', final),
                            ('/etc/autosoft/installation.storage-receipt.json', self.receipt),
                            (DATA + '/config/installation.json', {'installation_id': final['installation_id']}),
                            (DATA + '/config/runtime-layout/intent.json', initial),
                            (DATA + '/config/runtime-layout/layout.json', layout),
                            (DATA + '/config/runtime-layout/confirmed.json', {'layoutSha256': sha(seed_bytes(layout))})):
            fs.file(path, canonical(value))
        fs.file('/srv/backing.luks', b'', size=32 * 1024**3)
        fs.file('/etc/autosoft/storage.key', b'public-fixture-never-read')
        self.mount = MappingProxyType(dict(target=DATA, filesystem='xfs', source='/dev/mapper/autosoft-data',
            storageFile='/srv/backing.luks', luksUuid=self.receipt['luks_uuid'], options=('nodev', 'nosuid', 'prjquota', 'rw'),
            mapperIdentity=tuple(str(value) for value in range(1, 10)), mapperPathIdentity=tuple(str(value) for value in range(1, 10))))
        self.request = dict(schemaVersion=1, mode='full-installation', operationId=OPERATION,
            releaseSha256=sha(self.base.release_raw), bundleRoot=LOGICAL[0], keyPath=LOGICAL[1], sourceRoot=LOGICAL[2],
            dataDir=DATA, backingFile='/srv/backing.luks', capacityGiB=32, runscVersion='20261005.0', runscSha512='c' * 128)
        self.request_raw = canonical(self.request)

    def native(self, cli, request_raw, station):
        assert request_raw == self.request_raw and station['files'] is self.base.files and station['clock'] is self.clock
        cli.recheck()
        self.native_calls.append(cli)
        self.execute_cli = cli
        cli_state = object.__getattribute__(cli, '__dict__')
        cli_modules = dict.get(cli_state, '_modules')
        assert type(cli_modules) is dict and type(cli_modules[self.C.WORKER]) is ModuleType
        self.diagnostic_namespaces.append(('Worker', vars(cli_modules[self.C.WORKER])))
        self.parent_basis = named_fixture('scripts/test-installer-parent.py', {'shell', 'encoded', 'FakeSystem'},
                                         supplied={'P': cli._P, 'ARGS': cli._P.ParentInput(42, 11, 12, 's-Abc123Def456',
                                             sha(self.request_raw), 'company-platform-store', json.loads(self.plan)['actionSha256'])})
        base = self.parent_basis.FakeSystem
        class ParentSystem(base):
            def require_released(self):
                if self.descriptors:
                    raise ValueError('RAM parent descriptors live')
                return self
        self.backend_module.ParentSystem = ParentSystem
        self.parent = ParentSystem()
        return dict(files=station['files'], crypto=station['crypto'], backend_module=self.backend_module,
                    backend=self.backend, runner_module=self.backend_module, runner=self.runner,
                    parent_system_module=self.backend_module, parent_system=self.parent, clock=self.clock)

    def encrypted(self, data, receipt, command):
        assert str(data).replace('\\', '/') == DATA and receipt == self.receipt
        assert getattr(command, '__self__', None) is not None and command.__self__.runner is self.runner
        self.mount_calls.append((str(data), dict(receipt), command))
        return {key: list(value) if type(value) is tuple else value for key, value in self.mount.items()}

    def _authentication(self):
        auth = {key: dict(value) if type(value) is MappingProxyType else value
                for key, value in self.admitted_data['authentication'].items()}
        for key in ('launch_pins', 'package_pins', 'operational_catalog'):
            auth[key] = {path: dict(row) for path, row in auth[key].items()}
        auth.update(delivery_module=self.programs['delivery'], running_cli_raw=self.admitted_data['programCaptures']['cli'],
                    bootstrap_records={path: self.admitted_data['programCaptures'][label]
                                       for label, path in (('verifier', 'scripts/verify-release.py'), ('parent', 'scripts/installer_parent.py'))},
                    bootstrap_pins={path: dict(self.admitted_data['programPins'][label])
                                    for label, path in (('verifier', 'scripts/verify-release.py'), ('parent', 'scripts/installer_parent.py'))})
        return auth

    def _plan_stage(self):
        self.planning_crypto = self.crypto_module.ReleaseCrypto(**dict(self.crypto_configuration,
            os_module=self.h.os, sys_module=self.h.sys, subprocess_module=self.h.subprocess, select_module=self.h.select,
            signal_module=self.h.signal, fcntl_module=self.h.fcntl, clock=self.clock))
        invocation = dict(schemaVersion=1, scope='FULL_RETENTION_CLI_INVOCATION_ONLY', command='plan-stage', stage='company-platform-store',
            requestSha256=sha(self.request_raw), releaseSha256=self.request['releaseSha256'], operationId=OPERATION,
            storeOperationId=OPERATION, planSha256=None, parent=None, outcomeSha256=None)
        invocation_raw = canonical(invocation)
        with self.C.authenticated_cli(self.admitted_data['deliveryRaw'], **self._authentication()) as cli:
            self.plan_cli = cli
            observation = cli.dispatch('plan-stage', request_raw=self.request_raw, request_sha256=sha(self.request_raw),
                invocation_raw=invocation_raw, invocation_sha256=sha(invocation_raw), files=self.base.files,
                crypto=self.planning_crypto, backend_module=self.backend_module, backend=self.backend,
                runner_module=self.backend_module, runner=self.runner, clock=self.clock)
        plan_record = json.loads(observation.completed_record())
        import base64
        self.plan = base64.b64decode(plan_record['planBase64'])
        parent = ['42', '11', '12', 's-Abc123Def456', sha(self.request_raw), 'company-platform-store', json.loads(self.plan)['actionSha256']]
        execute = dict(invocation, command='execute-stage', planSha256=sha(self.plan), parent=parent)
        self.invocation_raw = canonical(execute)
        self.r.bodies = dict(zip(('request.json', 'invocation.json', 'plan.json'),
                                (self.request_raw, self.invocation_raw, self.plan)))
        for name, raw in self.r.bodies.items():
            self.r.metas[self.io_path + '/' + name]['st_size'] = len(raw)
        self.io_configuration = dict(directory=self.io_path, directory_identity=dict(self.r.metas[self.io_path]),
            input_pins={name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in self.r.bodies.items()},
            outputs={role: dict(fd=fd, identity=dict(self.r.handles[fd]['identity']), flags=2049, fdFlags=1)
                     for role, fd in (('stdout', 1000), ('stderr', 1001))}, seconds=30, protected_fds=())

    def prepare(self, **changes):
        args = dict(io_configuration=self.io_configuration, crypto_configuration=self.crypto_configuration, station=self.station)
        args.update(changes)
        self.fixed = self.E.prepare_fixed_execute_child(self.signed.M, self.preparation, **args)
        return self.fixed

    def dispose(self):
        for restore in reversed(self.restores):
            restore()
        try:
            self.signed.dispose()
        except BaseException as primary:
            try:
                observed = json.loads(failure_observation(self.diagnostic_namespaces, primary))
                assert type(self.base.files) is self.diagnostic_files_kind
                table = type.__getattribute__(self.diagnostic_files_kind, '__dict__')
                assert len(table) == len(self.diagnostic_files_table) and all(table.get(key) is value for key, value in self.diagnostic_files_table)
                state = self.diagnostic_files_dict_getter.__get__(self.base.files, self.diagnostic_files_kind)
                assert state is self.diagnostic_files_state and type(state) is dict
                held = dict.get(state, 'held')
                assert type(held) is dict and len(held) <= 256
                shape = all(type(fd) is int and 3 <= fd <= 1048575 and type(row) is tuple and len(row) == 2 for fd, row in held.items())
                observed['ramSourceHandles'] = dict(stateIdentityKnown=True, heldCount=len(held), rowsShapeKnown=shape,
                    descriptorSample=tuple(sorted(held))[:16] if shape else (), ownedClosureQualified=False)
                raw = json.dumps(observed, sort_keys=True, separators=(',', ':')).encode('ascii')
                if len(raw) > 16384:
                    raise ValueError('diagnostic-cap')
            except BaseException:
                raw = b'{"scope":"FIXED_CHILD_CLEANUP_FAILURE_METADATA_DATA_ONLY","diagnosticUnavailable":true}'
            sys.stdout.write('FIXTURE_CLEANUP_FAILURE_DATA=' + raw.decode('ascii') + '\n')
            raise
        if sys.modules.get(self.module_name) is self.adapter:
            del sys.modules[self.module_name]


class Controls(unittest.TestCase):
    def _callTestMethod(self, method):
        try:
            return unittest.TestCase._callTestMethod(self, method)
        except BaseException as primary:
            fixture = dict.get(object.__getattribute__(self, '__dict__'), '_diagnostic_fixture')
            try:
                raw = failure_observation(fixture.diagnostic_namespaces, primary)
            except BaseException:
                raw = b'{"scope":"FIXED_CHILD_FAILURE_METADATA_DATA_ONLY","diagnosticUnavailable":true,"reason":"observer-refused"}'
            sys.stdout.write('FIXTURE_FAILURE_DATA=' + raw.decode('ascii') + '\n')
            raise

    def fixture(self, **kwargs):
        value = Fixture(**kwargs)
        self._diagnostic_fixture = value
        self.addCleanup(value.dispose)
        return value

    def refused(self, f, action):
        with self.assertRaises(f.E.FixedChildUnavailable):
            action()

    def test_actual_original_record_forwarded_after_cli_crypto_and_input_release(self):
        f = self.fixture()
        child = f.prepare()
        observed = []
        def at_write(fd, raw):
            self.assertIn(id(f.execute_cli), f.C._CLOSED_OWNERS)
            self.assertFalse(f.backend.handles or f.parent.descriptors or f.h.fds)
            record = f.E.UNRELEASED[-1][0] if f.E.UNRELEASED else None
            self.assertFalse(record)
            self.assertEqual(raw, f.execute_cli._observations[-1].completed_record())
            self.assertFalse(any(row['path'] is not None for row in f.r.handles.values()))
            observed.append(raw)
        f.r.hooks['write'] = at_write
        result = child.run()
        self.assertEqual(len(f.r.writes), 1)
        raw = f.r.writes[0][1]
        self.assertEqual(observed, [raw])
        self.assertEqual(result['publication']['recordSha256'], sha(raw))
        self.assertTrue(result['originalIoContextKnownReleased'])
        self.assertFalse(f.r.handles or f.h.fds or f.backend.handles or f.parent.descriptors)
        self.assertFalse(result['executionEvidenceIssued'] or result['stageAcknowledged'] or result['installerActivated'])
        self.assertIs(f.base.V.require_platform_source(f.base.source), f.base.source)

    def test_partial_original_write_retains_actual_raw_once_and_never_retries(self):
        f = self.fixture()
        child = f.prepare()
        f.r.write_results = [1]
        self.refused(f, child.run)
        self.assertEqual(len(f.r.writes), 1)
        raw = f.r.writes[0][1]
        self.assertEqual(raw, f.execute_cli._observations[-1].completed_record())
        f.E.UNRELEASED.clear()
        self.refused(f, child.run)
        self.assertEqual(len(f.r.writes), 1)

    def test_unknown_input_close_prevents_record_emission_and_keeps_owned_io(self):
        f = self.fixture()
        child = f.prepare()
        def failed(fd):
            if fd in f.r.handles and f.r.handles[fd]['path'] is not None:
                f.r.fail_close.add(fd)
        f.r.hooks['fstat'] = failed
        self.refused(f, child.run)
        self.assertFalse(f.r.writes)
        row = f.E.UNRELEASED[-1][0]
        self.assertIsNotNone(row['io'])
        self.assertFalse(row['io_known_closed'])

    def test_unknown_output_close_keeps_actual_write_and_once_close(self):
        f = self.fixture()
        child = f.prepare()
        f.r.fail_close.add(1000)
        self.refused(f, child.run)
        self.assertEqual(len(f.r.writes), 1)
        self.assertEqual(f.r.close_calls.count(1000), 1)
        row = f.E.UNRELEASED[-1][0]
        self.assertIsNotNone(row['io'])
        self.assertFalse(row['io_known_closed'])
        f.E.UNRELEASED.clear()
        self.refused(f, child.run)
        self.assertEqual(f.r.close_calls.count(1000), 1)

    def test_crypto_constructor_refusal_retains_allocated_original_instance(self):
        f = self.fixture()
        f.h.uid_value = 0
        def uid():
            return f.h.uid_value
        f.h.os.getuid = uid
        child = f.prepare()
        f.h.uid_value = True
        self.refused(f, child.run)
        self.assertFalse(f.r.writes)
        row = f.E.UNRELEASED[-1][0]
        self.assertTrue(row['entered'] and row['crypto_owned'])
        self.assertIs(type(row['crypto']), f.crypto_module.ReleaseCrypto)
        self.assertTrue(any(phase == 'original-crypto-initialize' for phase, callback, args, kwargs in row['attempts']))
        self.assertFalse(any(phase == 'original-crypto-initialize' for phase, returned in row['returns']))

    def test_expired_source_refuses_before_any_io_acquisition(self):
        f = self.fixture()
        child = f.prepare()
        f.base.close_source()
        before = len(f.r.opens)
        self.refused(f, child.run)
        self.assertEqual(len(f.r.opens), before)
        self.assertFalse(f.r.writes)

    def test_unissued_signed_preparation_clone_refuses_before_io_or_crypto(self):
        f = self.fixture()
        clone = f.signed.M.SignedExecutePreparation()
        before = len(f.r.opens)
        self.refused(f, lambda: f.E.prepare_fixed_execute_child(f.signed.M, clone,
            io_configuration=f.io_configuration, crypto_configuration=f.crypto_configuration, station=f.station))
        self.assertEqual(len(f.r.opens), before)
        self.assertFalse(f.r.writes)

    def test_changed_encrypted_receipt_binding_is_refused_without_output(self):
        f = self.fixture()
        child = f.prepare()
        path = '/etc/autosoft/installation.storage-receipt.json'
        value = json.loads(f.backend.nodes[path]['raw'])
        value['luks_uuid'] = '11111111-1111-4111-8111-111111111111'
        f.backend.file(path, canonical(value))
        self.refused(f, child.run)
        self.assertFalse(f.r.writes)

    def test_unconfigured_main_and_public_child_clone_have_no_io_effects(self):
        f = self.fixture()
        before = len(f.r.opens)
        self.refused(f, f.E.main)
        clone = f.E.FixedExecuteChild()
        self.refused(f, clone.run)
        self.assertEqual(len(f.r.opens), before)
        self.assertFalse(f.r.writes)


if __name__ == '__main__':
    unittest.main(verbosity=2)
