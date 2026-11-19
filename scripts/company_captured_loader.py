"""Compose captured company startup code; no installer or native authority.

The independently authenticated company entry must pin this module and the three
entry captures before calling trusted_entry_modules. Those bootstrap pins do not
come from the candidate release. Later signed rows cannot establish initial
verifier trust. Private issuance protects the trusted Python API from accidental
substitution; it is not isolation from hostile code in the same interpreter.
"""
from contextlib import contextmanager
import hashlib
import re
import sys
from types import MappingProxyType, ModuleType
import uuid

V_PATH = 'scripts/verify-release.py'
IP_PATH = 'scripts/installer_parent.py'
GUARD_PATH = 'scripts/company_source_guard.py'
ENTRY_PATHS = (V_PATH, IP_PATH, GUARD_PATH)
OPERATIONAL_PATHS = (
    'scripts/bootstrap.py', 'scripts/checkpoint_admission.py',
    'scripts/company_platform_store.py', 'scripts/company_source_tree.py',
    'scripts/identity.py',
    'scripts/installation_identity.py', IP_PATH, 'scripts/platform_source.py',
    'scripts/quota_allocation.py', 'scripts/quota_runtime.py',
    'scripts/registry_manifest.py', 'scripts/resolve-images.py',
    'scripts/runtime_layout.py', 'scripts/runtime_pair_init.py',
    'scripts/startup_binding.py', V_PATH,
)
EDGES = MappingProxyType({
    'scripts/bootstrap.py': ('scripts/registry_manifest.py', 'scripts/runtime_layout.py', 'scripts/installation_identity.py', 'scripts/identity.py'),
    'scripts/installation_identity.py': ('scripts/checkpoint_admission.py',),
    'scripts/quota_allocation.py': ('scripts/checkpoint_admission.py',),
    'scripts/quota_runtime.py': ('scripts/quota_allocation.py',),
    'scripts/runtime_layout.py': ('scripts/quota_runtime.py',),
    'scripts/startup_binding.py': ('scripts/runtime_layout.py', 'scripts/installation_identity.py'),
    'scripts/runtime_pair_init.py': ('scripts/startup_binding.py',),
})
COMPILE_ORDER = (
    'scripts/checkpoint_admission.py', 'scripts/registry_manifest.py',
    'scripts/resolve-images.py', 'scripts/platform_source.py',
    'scripts/identity.py',
    'scripts/installation_identity.py', 'scripts/quota_allocation.py',
    'scripts/quota_runtime.py', 'scripts/runtime_layout.py',
    'scripts/startup_binding.py', 'scripts/runtime_pair_init.py',
    'scripts/bootstrap.py', 'scripts/company_platform_store.py',
    'scripts/company_source_tree.py',
)
MAX_CODE_BYTES = 8 * 1024**2
MAX_OPERATIONAL_BYTES = 16 * 1024**2
UNRELEASED = []
_ENTRIES, _ASSEMBLIES = set(), set()


class CapturedLoaderUnavailable(ValueError):
    pass


def require(value):
    if not value:
        raise CapturedLoaderUnavailable('company-captured-loader-unavailable')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _catalog(value, paths, *, logical=False):
    require(type(value) is dict and set(value) == set(paths))
    result = {}
    for path in paths:
        row = value[path]
        require(type(row) is dict and set(row) == ({'bytes', 'sha256', 'gitMode'} if logical else {'bytes', 'sha256'}))
        require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_CODE_BYTES
                and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']) is not None)
        if logical:
            require(type(row['gitMode']) is str and row['gitMode'] in ('100644', '100755'))
        result[path] = MappingProxyType(dict(row))
    require(sum(row['bytes'] for row in result.values()) <= MAX_OPERATIONAL_BYTES)
    return MappingProxyType(result)


def _same(raw, row):
    require(type(raw) is bytes and len(raw) == row['bytes'] and sha(raw) == row['sha256'])


def _globals(module):
    return {key: value for key, value in vars(module).items() if key != '__builtins__'}


def _check_globals(module, snapshot):
    current = _globals(module)
    require(set(current) == set(snapshot) and all(current[key] is snapshot[key] for key in snapshot))


def _register(path, raw, prefix, owned, dependencies=None):
    name = prefix + path[8:-3].replace('-', '_')
    require(name not in sys.modules)
    module = ModuleType(name)
    module.__file__ = '<captured company ' + path + '>'
    if dependencies is not None:
        module.__company_captured_dependencies__ = MappingProxyType(dict(dependencies))
    # Own the exact object before any execution can fail. No sibling loaders or
    # source-path reparsing are used, and main entries are never invoked.
    owned.append((name, module))
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def _release(owner, owned):
    errors = []
    for name, module in reversed(owned):
        if sys.modules.get(name) is module:
            del sys.modules[name]
        else:
            errors.append((owner, name, module, sys.modules.get(name)))
    owned.clear()
    if errors:
        UNRELEASED.extend(errors)
        raise CapturedLoaderUnavailable('company-captured-loader-unavailable')


class TrustedEntry:
    """Only the entry factory issues executing-byte/module-origin records."""
    def __init__(self):
        self._active = False

    def recheck(self):
        issued = type(self) is TrustedEntry and self in _ENTRIES
        try:
            require(issued and self._active and not UNRELEASED)
            for path, module in self._modules.items():
                require(sys.modules.get(module.__name__) is module)
                _same(self._raw[path], self._pins[path])
                _check_globals(module, self._snapshots[path])
        except BaseException:
            if issued:
                TrustedEntry._expire(self)
            raise
        return self

    @property
    def modules(self):
        self.recheck()
        return self._modules

    def _expire(self):
        self._active = False
        _ENTRIES.discard(self)


@contextmanager
def trusted_entry_modules(captures, *, bootstrap_pins, operational_catalog, key_fingerprint):
    """Execute separately trusted embedded bytes once and retain their origin.

    bootstrap_pins and the operational catalog are chosen by the authenticated
    company entry/package, independently of candidate self-reported rows. This
    function verifies equality to that trust input, not its external provenance.
    Future company_install delegation must keep this context live; the current
    foundation loader is deliberately not wired to it.
    """
    require(not UNRELEASED and type(captures) is dict and set(captures) == set(ENTRY_PATHS))
    pins = _catalog(bootstrap_pins, ENTRY_PATHS)
    catalog = _catalog(operational_catalog, OPERATIONAL_PATHS, logical=True)
    require(type(key_fingerprint) is str and re.fullmatch('[a-f0-9]{64}', key_fingerprint) is not None)
    raw = dict(captures)
    # Every entry capture/catalog member is validated before executing the first.
    for path in ENTRY_PATHS:
        _same(raw[path], pins[path])
    for path in (V_PATH, IP_PATH):
        require(all(pins[path][key] == catalog[path][key] for key in ('bytes', 'sha256')))
    entry = TrustedEntry()
    owned = []
    try:
        prefix = 'company_entry_' + uuid.uuid4().hex + '_'
        modules = {path: _register(path, raw[path], prefix, owned) for path in ENTRY_PATHS}
        entry._raw, entry._pins, entry._catalog = MappingProxyType(raw), pins, catalog
        entry._modules = MappingProxyType(modules)
        entry._snapshots = {path: _globals(module) for path, module in modules.items()}
        entry._fingerprint, entry._active = key_fingerprint, True
        _ENTRIES.add(entry)
        entry.recheck()
        yield entry
        entry.recheck()
    finally:
        entry._expire()
        _release(entry, owned)


def _source(entry, held, guard):
    entry.recheck()
    V, G = entry._modules[V_PATH], entry._modules[GUARD_PATH]
    require(V.require_platform_source(held) is held)
    require(G.require_company_source_guard(guard, verifier_module=V, held=held) is guard)
    require(held.metadata['signingKeyFingerprint'] == entry._fingerprint)
    entry.recheck()


def _capture(entry, held, guard):
    _source(entry, held, guard)
    V = entry._modules[V_PATH]
    header = V.decode(held.configs['platform-sources.json'], 1024**2, canonical_only=True)
    require(type(header) is dict and type(header.get('files')) is list and 0 < len(header['files']) <= 2048)
    signed = {}
    for row in header['files']:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'gitMode'}
                and type(row['path']) is str and row['path'] not in signed)
        signed[row['path']] = row
    values, modes, physical = held.files, held.git_modes, guard.files
    require(set(values) == set(physical) and all(values[path] == physical[path] for path in values))
    require(dict(guard.git_modes) == dict(modes))
    captured = {}
    # Complete admission, including the last privileged member, precedes exec.
    for path in OPERATIONAL_PATHS:
        require(path in values and path in modes and path in signed)
        expected = entry._catalog[path]
        row = signed[path]
        require(type(row['bytes']) is int and type(row['sha256']) is str and type(row['gitMode']) is str
                and all(row[key] == expected[key] for key in ('bytes', 'sha256', 'gitMode'))
                and modes[path] == expected['gitMode'])
        _same(values[path], expected)
        captured[path] = values[path]
    for path in (V_PATH, IP_PATH):
        require(captured[path] == entry._raw[path])
    _source(entry, held, guard)
    return MappingProxyType(captured)


class CapturedAssembly:
    def __init__(self):
        self._active = False

    def recheck(self):
        issued = type(self) is CapturedAssembly and self in _ASSEMBLIES
        try:
            require(issued and self._active and not UNRELEASED)
            _source(self._entry, self._source, self._guard)
            for path, module in self._modules.items():
                require(sys.modules.get(module.__name__) is module)
                _same(self._raw[path], self._entry._catalog[path])
                _check_globals(module, self._snapshots[path])
            _source(self._entry, self._source, self._guard)
        except BaseException:
            if issued:
                CapturedAssembly._expire(self)
            raise
        return self

    @property
    def modules(self):
        self.recheck()
        return self._modules

    def call(self, path, name, *args, **kwargs):
        """Synchronous call only; returned lifetimes remain the caller's duty."""
        issued = type(self) is CapturedAssembly and self in _ASSEMBLIES
        try:
            self.recheck()
            require(type(path) is str and path in self._modules and type(name) is str and not name.startswith('_'))
            function = getattr(self._modules[path], name)
            require(callable(function))
            value = function(*args, **kwargs)
            self.recheck()
            return value
        except BaseException:
            if issued:
                CapturedAssembly._expire(self)
            raise

    def _expire(self):
        self._active = False
        _ASSEMBLIES.discard(self)


@contextmanager
def captured_startup_modules(held, *, entry, source_guard):
    """Live composition only; source guards/stage/native authority stay external."""
    require(type(entry) is TrustedEntry and entry in _ENTRIES)
    raw = _capture(entry, held, source_guard)
    assembly = CapturedAssembly()
    owned = []
    try:
        modules = {path: entry._modules[path] for path in (V_PATH, IP_PATH)}
        prefix = 'company_captured_' + held.metadata['releaseSha256'] + '_' + uuid.uuid4().hex + '_'
        for path in COMPILE_ORDER:
            _source(entry, held, source_guard)
            dependencies = {key: modules[key] for key in EDGES.get(path, ())}
            modules[path] = _register(path, raw[path], prefix, owned, dependencies if path in EDGES else None)
            _source(entry, held, source_guard)
        assembly._entry, assembly._source, assembly._guard = entry, held, source_guard
        assembly._raw, assembly._modules = raw, MappingProxyType(modules)
        assembly._snapshots = {path: _globals(module) for path, module in modules.items()}
        assembly._active = True
        _ASSEMBLIES.add(assembly)
        assembly.recheck()
        yield assembly
        assembly.recheck()
    finally:
        assembly._expire()
        _release(assembly, owned)


# This separately issued route breaks the fresh-install source-creation cycle.
# It admits signed captured code, not native writes, stage or storage authority.
_FRESH_ASSEMBLIES = set()
_FRESH_BOUND_GUARDS = {}
_FRESH_UNKNOWN_FIELDS = ('UNRELEASED', 'UNRELEASED_HANDLES', 'UNRELEASED_RESOURCES',
                         'SEED_UNRELEASED', '_COMMAND_UNCERTAIN')


def _fresh_source(entry, held):
    require(type(entry) is TrustedEntry and entry in _ENTRIES)
    entry.recheck()
    V = entry._modules[V_PATH]
    require(V.require_platform_source(held) is held)
    require(held.metadata['signingKeyFingerprint'] == entry._fingerprint)
    entry.recheck()


def _fresh_capture(entry, held):
    _fresh_source(entry, held)
    V = entry._modules[V_PATH]
    header = V.decode(held.configs['platform-sources.json'], 1024**2, canonical_only=True)
    require(type(header) is dict and type(header.get('files')) is list
            and 0 < len(header['files']) <= 2048)
    signed = {}
    for row in header['files']:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'gitMode'}
                and type(row['path']) is str and row['path'] not in signed)
        signed[row['path']] = row
    values, modes = held.files, held.git_modes
    captured = {}
    # All fifteen rows, including the final privileged member, precede exec.
    for path in OPERATIONAL_PATHS:
        require(path in values and path in modes and path in signed)
        expected, row = entry._catalog[path], signed[path]
        require(type(row['bytes']) is int and type(row['sha256']) is str
                and type(row['gitMode']) is str
                and all(row[key] == expected[key] for key in ('bytes', 'sha256', 'gitMode'))
                and modes[path] == expected['gitMode'])
        _same(values[path], expected)
        captured[path] = values[path]
    for path in (V_PATH, IP_PATH):
        require(captured[path] == entry._raw[path])
    _fresh_source(entry, held)
    return MappingProxyType(captured)


def _fresh_unknown(assembly):
    modules = dict(assembly._modules)
    modules[GUARD_PATH] = assembly._entry._modules[GUARD_PATH]
    for name, module in assembly._owned:
        modules.setdefault(name, module)
    for path, module in modules.items():
        snapshot = assembly._snapshots.get(path, {})
        if any(bool(vars(module).get(name)) or bool(snapshot.get(name))
               for name in _FRESH_UNKNOWN_FIELDS):
            return True
    return False


def _retain_fresh(assembly, reason):
    if not assembly._retained:
        assembly._retained = True
        UNRELEASED.append((assembly, reason, assembly._modules, assembly._raw,
                           assembly._entry, assembly._source, assembly._guard,
                           tuple(assembly._owned)))


class FreshInstallationAssembly:
    """Company-entry-only code composition; never filesystem authorization.

    Only captured_fresh_installation_modules issues this exact class. The
    physical binding is one-way; keep that original guard live until this
    assembly context has closed. Retained/reboot callers use the existing
    physically guarded captured_startup_modules route.
    """
    def __init__(self):
        self._active = False
        self._retained = False

    def _expire(self):
        self._active = False
        _FRESH_ASSEMBLIES.discard(self)
        _FRESH_BOUND_GUARDS.pop(self, None)

    def recheck(self):
        issued = type(self) is FreshInstallationAssembly and self in _FRESH_ASSEMBLIES
        try:
            require(issued and self._active and not UNRELEASED)
            require(self._guard is _FRESH_BOUND_GUARDS.get(self))
            if _fresh_unknown(self):
                _retain_fresh(self, 'fresh-operational-release-unknown')
                require(False)
            _fresh_source(self._entry, self._source)
            if self._guard is not None:
                _source(self._entry, self._source, self._guard)
            for path, module in self._modules.items():
                require(sys.modules.get(module.__name__) is module)
                _same(self._raw[path], self._entry._catalog[path])
                _check_globals(module, self._snapshots[path])
            _fresh_source(self._entry, self._source)
            if self._guard is not None:
                _source(self._entry, self._source, self._guard)
        except BaseException:
            if issued:
                FreshInstallationAssembly._expire(self)
            raise
        return self

    @property
    def modules(self):
        FreshInstallationAssembly.recheck(self)
        return self._modules

    def bind_source_guard(self, guard):
        """Bind original G to the same source once, without recompilation."""
        issued = type(self) is FreshInstallationAssembly and self in _FRESH_ASSEMBLIES
        try:
            FreshInstallationAssembly.recheck(self)
            require(self._guard is None)
            physical = _capture(self._entry, self._source, guard)
            require(dict(physical) == dict(self._raw))
            self._guard = guard
            _FRESH_BOUND_GUARDS[self] = guard
            FreshInstallationAssembly.recheck(self)
        except BaseException:
            if issued:
                FreshInstallationAssembly._expire(self)
            raise
        return self

    def call(self, path, name, *args, **kwargs):
        """Synchronous code use only; live parent/storage obligations remain."""
        issued = type(self) is FreshInstallationAssembly and self in _FRESH_ASSEMBLIES
        try:
            FreshInstallationAssembly.recheck(self)
            require(type(path) is str and path in self._modules
                    and type(name) is str and not name.startswith('_'))
            function = getattr(self._modules[path], name)
            require(callable(function))
            value = function(*args, **kwargs)
            FreshInstallationAssembly.recheck(self)
            return value
        except BaseException:
            if issued:
                FreshInstallationAssembly._expire(self)
            raise


@contextmanager
def captured_fresh_installation_modules(held, *, entry):
    """Explicit separately trusted company-entry API, no flags/path fallback.

    Candidate rows cannot establish initial company trust. Genuine original
    verifier issuance and the independent entry catalog admit captured bytes;
    every effect still needs its original parent and storage capabilities.
    """
    require(type(entry) is TrustedEntry and entry in _ENTRIES)
    raw = _fresh_capture(entry, held)
    assembly, owned = FreshInstallationAssembly(), []
    assembly._owned = owned
    assembly._entry, assembly._source, assembly._guard = entry, held, None
    assembly._raw, assembly._modules, assembly._snapshots = raw, MappingProxyType({}), {}
    try:
        modules = {path: entry._modules[path] for path in (V_PATH, IP_PATH)}
        assembly._modules = MappingProxyType(modules)
        prefix = 'company_fresh_' + held.metadata['releaseSha256'] + '_' + uuid.uuid4().hex + '_'
        for path in COMPILE_ORDER:
            _fresh_source(entry, held)
            dependencies = {key: modules[key] for key in EDGES.get(path, ())}
            modules[path] = _register(path, raw[path], prefix, owned,
                                      dependencies if path in EDGES else None)
            _fresh_source(entry, held)
        assembly._modules = MappingProxyType(modules)
        assembly._snapshots = {path: _globals(module) for path, module in modules.items()}
        assembly._active = True
        _FRESH_ASSEMBLIES.add(assembly)
        assembly.recheck()
        yield assembly
        assembly.recheck()
    finally:
        try:
            if assembly._active:
                assembly.recheck()
            if _fresh_unknown(assembly):
                _retain_fresh(assembly, 'fresh-operational-release-unknown')
        finally:
            assembly._expire()
            _release(assembly, owned)
