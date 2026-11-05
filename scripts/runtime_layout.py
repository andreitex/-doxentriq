"""Company runtime placement only; never initialize admission or quota state."""
import importlib.util
import os
from pathlib import Path
import stat

if '__company_captured_dependencies__' in globals():
    from types import MappingProxyType, ModuleType
    _captured_dependencies = __company_captured_dependencies__
    if type(_captured_dependencies) is not MappingProxyType or set(_captured_dependencies) != {'scripts/quota_runtime.py'}:
        raise ValueError('company-captured-dependencies-unavailable')
    if any(type(_captured_dependencies[key]) is not ModuleType for key in _captured_dependencies):
        raise ValueError('company-captured-dependencies-unavailable')
    Q = _captured_dependencies['scripts/quota_runtime.py']
else:
    _spec = importlib.util.spec_from_file_location('runtime_layout_quota', Path(__file__).resolve().with_name('quota_runtime.py'))
    Q = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(Q)
    C = Q._allocation.C
C = Q._allocation.C

# Reviewed production broker first path components. Root-owned storage is separate.
BROKER_DIRECTORIES = (
    'access-operations', 'access-pending', 'access-policies', 'access-used-approvals',
    'active', 'app-accounts', 'artifacts', 'builds', 'connector-secrets', 'connectors',
    'fences', 'identity-policies', 'jwks-rotations', 'jwks-stops', 'migration-imports',
    'migration-snapshots', 'observations', 'operations', 'receipts', 'recovery-grants',
    'reports', 'repository', 'resources', 'secrets', 'security', 'sources',
    'tls-rotations', 'used-approvals',
)
SCOPE = 'RUNTIME_PLACEMENT_ONLY'


class NativeFiles(C.NativeFiles):
    def directory(self, path, uid, gid, modes):
        path = Path(path)
        before = path.lstat()
        C.require(path.is_absolute() and path.resolve(strict=True) == path)
        C.require(stat.S_ISDIR(before.st_mode) and before.st_uid == uid and before.st_gid == gid and stat.S_IMODE(before.st_mode) in modes)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.compare_opened(before, self.descriptor(fd))
            C.require(C.identity(path.lstat()) == C.identity(before))
        finally:
            os.close(fd)
        return before

    def names(self, path, maximum):
        before = path.lstat()
        C.require(path.resolve(strict=True) == path and stat.S_ISDIR(before.st_mode))
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = self.descriptor(fd); self.compare_opened(before, opened)
            result = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    result.append(entry.name); C.require(len(result) <= maximum)
            C.require(C.identity(self.descriptor(fd)) == C.identity(opened))
            C.require(C.identity(path.lstat()) == C.identity(before))
            return result
        finally:
            os.close(fd)

    def permission(self, path, expected, uid, gid, mode):
        C.require(C.identity(path.lstat()) == C.identity(expected))
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.compare_opened(expected, self.descriptor(fd))
            os.fchown(fd, uid, gid); os.fchmod(fd, mode); os.fsync(fd)
            actual = self.descriptor(fd)
            self.compare_opened(path.lstat(), actual)
            C.require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino))
        finally:
            os.close(fd)
        self.sync_directory(path.parent)
        return self.directory(path, uid, gid, {mode})


def builds_proof(path, command=Q.output):
    """Retain the existing dedicated 2GiB nosuid/nodev UID10001 tmpfs boundary."""
    fields = command(['/usr/bin/findmnt', '-n', '-o', 'TARGET,FSTYPE,OPTIONS,SIZE', '--bytes', '--target', str(path)]).strip().split()
    C.require(len(fields) == 4 and fields[0] == str(path) and fields[1] == 'tmpfs')
    options = set(fields[2].split(','))
    C.require({'rw', 'nosuid', 'nodev', 'uid=10001', 'gid=10001'} <= options)
    keys = [value.split('=', 1)[0] for value in fields[2].split(',')]
    C.require(len(keys) == len(set(keys)) and 'ro' not in options)
    C.require(bool({'mode=700', 'mode=0700'} & options))
    C.require(fields[3].isascii() and fields[3].isdecimal() and 0 < int(fields[3]) <= 2147483648)
    return dict(target=str(path), filesystem='tmpfs', maximumBytes=2147483648, uid=10001, gid=10001, mode=0o700, nosuid=True, nodev=True)


def validate_build_mount(value):
    types = {'target': str, 'filesystem': str, 'maximumBytes': int, 'uid': int,
             'gid': int, 'mode': int, 'nosuid': bool, 'nodev': bool}
    C.fields(value, types)
    C.require(all(type(value[name]) is expected for name, expected in types.items()),
              'Build mount evidence has an invalid field type')
    return value


def prepare(data, *, files=None, build_mount=builds_proof):
    """Fresh finite placement or exact read-only rerun; ambiguous state is retained.

    No populated storage, admission/allocator evidence or legacy layout is adopted.
    Interrupted placement is intentionally not repaired by render.
    """
    files = files or NativeFiles(); files.require_root()
    data = Path(data); root_hash = files.root(data)
    config, runtime = data / 'config', data / 'runtime'
    files.protected(config, directory=True, private=True)
    C.require(config.stat().st_dev == data.stat().st_dev)
    C.require(os.path.lexists(runtime)) # Foundation creates the protected parent.
    original_runtime = files.directory(runtime, 0, 0, {0o700, 0o755})
    C.require(runtime.stat().st_dev == data.stat().st_dev)
    allowed = set(BROKER_DIRECTORIES) | {'storage'}
    names = set(files.names(runtime, len(allowed)))
    C.require(names <= allowed, 'Unexpected runtime child requires company review')
    for name in ('projects.json', 'allocation', 'checkpoint-admission'):
        C.require(not os.path.lexists(data / 'quota' / name), 'Existing or partial quota/admission state requires separately reviewed startup wiring')
    storage = runtime / 'storage'
    if os.path.lexists(storage):
        files.directory(storage, 0, 0, {0o700})
        C.require(storage.stat().st_dev == data.stat().st_dev and files.names(storage, 0) == [])
    mount = validate_build_mount(build_mount(runtime / 'builds'))
    C.require(mount == dict(target=str(runtime / 'builds'), filesystem='tmpfs', maximumBytes=2147483648, uid=10001, gid=10001, mode=0o700, nosuid=True, nodev=True))
    files.directory(runtime / 'builds', 10001, 10001, {0o700})
    base = config / 'runtime-layout'
    if os.path.lexists(base):
        files.protected(base, directory=True, private=True)
        C.require(set(files.names(base, 3)) == {'intent.json', 'layout.json', 'confirmed.json'}, 'Partial layout is retained without automatic repair')
        initial = C.fields(files.read(base / 'intent.json'), {'schemaVersion', 'scope', 'dataRootSha256', 'directories', 'controls'})
        C.require(type(initial['schemaVersion']) is int, 'Layout schema version must be an exact integer')
        controls = _controls(files, data, base, root_hash)
        C.require(initial == dict(schemaVersion=1, scope=SCOPE, dataRootSha256=root_hash, directories=list(BROKER_DIRECTORIES), controls=controls))
        bound = C.fields(files.read(base / 'layout.json'), {'intentSha256', 'directories', 'buildMount'})
        validate_build_mount(bound['buildMount'])
        C.require(bound['intentSha256'] == C.digest(initial) and bound['buildMount'] == mount)
        confirmed = C.fields(files.read(base / 'confirmed.json'), {'layoutSha256'})
        C.require(confirmed['layoutSha256'] == C.digest(bound))
        C.require(names == allowed)
        _verify(files, data, bound['directories'], initial)
        return {'scope': SCOPE, 'status': 'verified', 'changed': False, 'backupReady': False}
    # Only fresh, empty known directories may receive an initial owner/mode.
    old = {}
    for name in names - {'storage'}:
        path = runtime / name
        info = path.lstat()
        uid = 10001 if name == 'builds' else info.st_uid
        C.require(uid in (0, 10001))
        old[name] = files.directory(path, uid, uid, {0o700})
        C.require(name == 'builds' or old[name].st_dev == data.stat().st_dev)
        C.require(files.names(path, 0) == [], 'Populated broker storage cannot be adopted by fresh placement')
    files.mkdir(base)
    initial = dict(schemaVersion=1, scope=SCOPE, dataRootSha256=root_hash, directories=list(BROKER_DIRECTORIES),
                   controls=_controls(files, data, base, root_hash))
    files.write(base / 'intent.json', initial) # Durable intent precedes owner/mode changes.
    before = files.directory(runtime, 0, 0, {0o700, 0o755})
    C.require(C.directory_binding(before) == C.directory_binding(original_runtime))
    if stat.S_IMODE(before.st_mode) != 0o755: files.permission(runtime, before, 0, 0, 0o755)
    if not os.path.lexists(storage): files.mkdir(storage)
    for name in BROKER_DIRECTORIES:
        path = runtime / name
        if name == 'builds': continue
        if not os.path.lexists(path): files.mkdir(path)
        before = files.directory(path, path.lstat().st_uid, path.lstat().st_gid, {0o700})
        C.require(before.st_uid == before.st_gid and before.st_uid in (0, 10001))
        if name in old: C.require(C.directory_binding(before) == C.directory_binding(old[name]))
        if before.st_uid != 10001: files.permission(path, before, 10001, 10001, 0o700)
    bound = dict(intentSha256=C.digest(initial), directories=_bindings(files, data), buildMount=mount)
    _verify(files, data, bound['directories'], initial)
    files.write(base / 'layout.json', bound)
    files.write(base / 'confirmed.json', {'layoutSha256': C.digest(bound)})
    C.require(files.read(base / 'layout.json') == bound and files.read(base / 'confirmed.json') == {'layoutSha256': C.digest(bound)})
    _verify(files, data, bound['directories'], initial)
    return {'scope': SCOPE, 'status': 'verified', 'changed': True, 'backupReady': False}


def _bindings(files, data):
    runtime = data / 'runtime'
    result = {'runtime': C.directory_binding(files.directory(runtime, 0, 0, {0o755})),
              'storage': C.directory_binding(files.directory(runtime / 'storage', 0, 0, {0o700}))}
    result.update({name: C.directory_binding(files.directory(runtime / name, 10001, 10001, {0o700})) for name in BROKER_DIRECTORIES})
    return result


def _controls(files, data, base, root_hash):
    C.require(files.root(data) == root_hash, 'Encrypted data root identity changed')
    controls = {name: C.directory_binding(files.protected(path, directory=True, private=True))
                for name, path in (('config', data / 'config'), ('base', base))}
    C.require(all(info['st_dev'] == str(data.stat().st_dev) for info in controls.values()))
    return controls


def _verify(files, data, bound, initial):
    C.require(_controls(files, data, data / 'config/runtime-layout', initial['dataRootSha256']) == initial['controls'])
    C.require(type(bound) is dict and set(bound) == {'runtime', 'storage'} | set(BROKER_DIRECTORIES))
    C.require(_bindings(files, data) == bound, 'Runtime directory identity or permissions changed')
    C.require(set(files.names(data / 'runtime', len(BROKER_DIRECTORIES) + 1)) == set(BROKER_DIRECTORIES) | {'storage'})
    C.require(all(info['st_dev'] == bound['runtime']['st_dev'] for name, info in bound.items() if name != 'builds'))


def _readonly_directory_guard(files, paths):
    """Hold finite read-only directory FDs; permit contents, never identity drift."""
    from contextlib import contextmanager
    import sys

    @contextmanager
    def held():
        handles = []
        errors = []
        try:
            C.require(type(paths) is dict and 0 < len(paths) <= 64)
            for path, (uid, gid, modes) in paths.items():
                before = files.directory(path, uid, gid, modes)
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                handles.append((path, fd, before, uid, gid, modes))
                files.compare_opened(before, files.descriptor(fd))
            yield {path: C.directory_binding(before) for path, _, before, _, _, _ in handles}
            for path, fd, before, uid, gid, modes in handles:
                current = files.directory(path, uid, gid, modes)
                opened = files.descriptor(fd)
                files.compare_opened(current, opened)
                C.require(C.directory_binding(opened) == C.directory_binding(before),
                          'Directory identity or permissions changed during verification')
        finally:
            for _, fd, _, _, _, _ in reversed(handles):
                try: os.close(fd)
                except BaseException as failure: errors.append(failure)
            if errors and sys.exc_info()[1] is None: raise errors[0]
    return held()


def verify(data, *, files=None, build_mount=builds_proof):
    """Read-only placement verification, including already initialized storage.

    Build tmpfs may have a new device/inode after reboot. Its historical owner,
    mode and closed mount semantics stay exact; current identity stays held for
    this invocation. Permanent directory identities are never relaxed.
    """
    files = files or NativeFiles(); files.require_root()
    data = Path(data); root_hash = files.root(data)
    config, runtime = data / 'config', data / 'runtime'
    base = config / 'runtime-layout'
    paths = {}
    for path in (*reversed(data.parents), data):
        info = files.protected(path, directory=True)
        paths[path] = (info.st_uid, info.st_gid, {stat.S_IMODE(info.st_mode)})
    paths.update({config: (0, 0, {0o700}), base: (0, 0, {0o700}),
                  runtime: (0, 0, {0o755}), runtime / 'storage': (0, 0, {0o700})})
    paths.update({runtime / name: (10001, 10001, {0o700}) for name in BROKER_DIRECTORIES})
    with _readonly_directory_guard(files, paths) as held:
        C.require(set(files.names(base, 3)) == {'intent.json', 'layout.json', 'confirmed.json'},
                  'Partial layout is retained without automatic repair')
        initial = C.fields(files.read(base / 'intent.json'), {'schemaVersion', 'scope', 'dataRootSha256', 'directories', 'controls'})
        C.require(type(initial['schemaVersion']) is int and initial['schemaVersion'] == 1,
                  'Layout schema version must be an exact integer')
        controls = _controls(files, data, base, root_hash)
        C.require(initial == dict(schemaVersion=1, scope=SCOPE, dataRootSha256=root_hash,
                                  directories=list(BROKER_DIRECTORIES), controls=controls))
        bound = C.fields(files.read(base / 'layout.json'), {'intentSha256', 'directories', 'buildMount'})
        confirmed = C.fields(files.read(base / 'confirmed.json'), {'layoutSha256'})
        C.require(type(bound['intentSha256']) is str and bound['intentSha256'] == C.digest(initial))
        C.require(type(confirmed['layoutSha256']) is str and confirmed['layoutSha256'] == C.digest(bound))
        saved_mount = validate_build_mount(bound['buildMount'])
        mount = validate_build_mount(build_mount(runtime / 'builds'))
        expected_mount = dict(target=str(runtime / 'builds'), filesystem='tmpfs', maximumBytes=2147483648,
                              uid=10001, gid=10001, mode=0o700, nosuid=True, nodev=True)
        C.require(saved_mount == expected_mount and mount == expected_mount)
        saved = C.fields(bound['directories'], {'runtime', 'storage'} | set(BROKER_DIRECTORIES))
        expected_fields = {'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'}
        for name, binding in saved.items():
            C.fields(binding, expected_fields)
            C.require(all(type(value) is str and value.isascii() and value.isdecimal()
                          and str(int(value)) == value for value in binding.values()),
                      'Directory binding fields must be canonical decimal strings')
            path = runtime if name == 'runtime' else runtime / name
            if name == 'builds':
                C.require(binding['st_mode'] == str(stat.S_IFDIR | 0o700)
                          and binding['st_uid'] == binding['st_gid'] == '10001')
            else:
                C.require(binding == held[path], 'Permanent runtime directory binding changed')
                C.require(binding['st_dev'] == held[runtime]['st_dev'])
        C.require(set(files.names(runtime, len(BROKER_DIRECTORIES) + 1)) == set(BROKER_DIRECTORIES) | {'storage'})
        C.require(held[config]['st_dev'] == held[base]['st_dev'] == held[data]['st_dev'] == held[runtime]['st_dev'])
        # Compare current observations twice while all directory FDs remain held.
        C.require(validate_build_mount(build_mount(runtime / 'builds')) == mount,
                  'Build mount semantics changed during verification')
        C.require(_controls(files, data, base, root_hash) == controls)
        C.require(C.digest(files.read(base / 'intent.json')) == C.digest(initial)
                  and C.digest(files.read(base / 'layout.json')) == C.digest(bound)
                  and C.digest(files.read(base / 'confirmed.json')) == C.digest(confirmed),
                  'Layout records changed during verification')
        C.require(set(files.names(base, 3)) == {'intent.json', 'layout.json', 'confirmed.json'})
        C.require(set(files.names(runtime, len(BROKER_DIRECTORIES) + 1)) == set(BROKER_DIRECTORIES) | {'storage'})
    return {'scope': SCOPE, 'status': 'verified', 'changed': False, 'backupReady': False}
