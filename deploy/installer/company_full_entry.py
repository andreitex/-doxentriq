"""Scoped full-entry composition; no full installer activation or native default.

The company entry must authenticate this file and package_pins independently
before executing it. Candidate release rows cannot establish that initial trust.
This API preserves trusted Python module identity; it is not hostile-interpreter
isolation. All caller-owned parent/source/backend contexts must outlive their use.
"""
import base64
from contextlib import contextmanager
import hashlib
import re
import sys
from types import MappingProxyType, ModuleType
import uuid

LOADER = 'scripts/company_captured_loader.py'
VERIFIER = 'scripts/verify-release.py'
PARENT = 'scripts/installer_parent.py'
GUARD = 'scripts/company_source_guard.py'
BACKEND = 'scripts/company_source_guard_backend.py'
MATERIALIZER = 'scripts/installer_materialize.py'
PACKAGE_PATHS = (LOADER, VERIFIER, PARENT, GUARD, BACKEND, MATERIALIZER)
MAX_CAPTURE_BYTES = 131072
MAX_PACKAGE_BYTES = 512 * 1024
UNRELEASED = []
_ISSUED_ENTRIES = set()


class FullEntryUnavailable(ValueError):
    pass


def require(value):
    if not value:
        raise FullEntryUnavailable('company-full-entry-unavailable')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pins(value):
    require(type(value) is dict and set(value) == set(PACKAGE_PATHS))
    result = {}
    for path in PACKAGE_PATHS:
        row = value[path]
        require(type(row) is dict and set(row) == {'bytes', 'sha256'}
                and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_CAPTURE_BYTES
                and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']) is not None)
        result[path] = MappingProxyType(dict(row))
    require(sum(row['bytes'] for row in result.values()) <= MAX_PACKAGE_BYTES)
    return MappingProxyType(result)


def decode_exact_embedded_records(records, *, package_pins):
    """Capture the closed six-member package before executing its first byte.

    Pins are the separately authenticated company package's trust input. Matching
    supplied pins alone does not authenticate their external origin.
    """
    require(type(records) is dict and set(records) == set(PACKAGE_PATHS))
    pins = _pins(package_pins)
    captured = {}
    for path in PACKAGE_PATHS:
        row = records[path]
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'base64'}
                and type(row['bytes']) is int and row['bytes'] == pins[path]['bytes']
                and type(row['sha256']) is str and row['sha256'] == pins[path]['sha256'])
        encoded = row['base64']
        require(type(encoded) is str and encoded.isascii()
                and len(encoded) == 4 * ((row['bytes'] + 2) // 3))
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise FullEntryUnavailable('company-full-entry-unavailable') from None
        require(base64.b64encode(raw).decode('ascii') == encoded
                and len(raw) == row['bytes'] and sha(raw) == pins[path]['sha256'])
        captured[path] = raw
    require(sum(map(len, captured.values())) <= MAX_PACKAGE_BYTES)
    return MappingProxyType(captured), pins


def _globals(module):
    return {key: value for key, value in vars(module).items() if key != '__builtins__'}


def _register(path, raw, prefix, owned):
    name = prefix + path[8:-3].replace('-', '_')
    require(name not in sys.modules)
    module = ModuleType(name)
    module.__file__ = '<trusted full-entry package ' + path + '>'
    owned.append((name, module))
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def _module_unknown(entry):
    names = {LOADER: 'UNRELEASED', VERIFIER: 'UNRELEASED_HANDLES',
             GUARD: 'UNRELEASED_HANDLES', BACKEND: 'UNRELEASED_RESOURCES',
             MATERIALIZER: 'UNRELEASED_HANDLES'}
    snapshots = getattr(entry, '_snapshots', {})
    return any(bool(vars(module).get(names[path]))
               or bool(snapshots.get(path, {}).get(names[path]))
               for path, module in entry._modules.items() if path in names)


def _retain(entry, reason):
    if not entry._retained:
        entry._retained = True
        UNRELEASED.append((entry, reason, entry._modules, entry._raw))


def _release(entry, owned):
    errors = []
    for name, module in reversed(owned):
        if sys.modules.get(name) is module:
            del sys.modules[name]
        else:
            errors.append((name, module, sys.modules.get(name)))
    owned.clear()
    if errors:
        _retain(entry, ('module-registration-unknown', tuple(errors)))
        raise FullEntryUnavailable('company-full-entry-unavailable')


class FullEntry:
    """Only authenticated_entry_modules issues a live package composition."""
    def __init__(self):
        self._active = False
        self._retained = False
        self._modules = MappingProxyType({})
        self._raw = MappingProxyType({})

    def _expire(self):
        self._active = False
        _ISSUED_ENTRIES.discard(self)
        owned = getattr(self, '_owned_origin', None)
        if owned is not None:
            loader, origin = owned
            if type(origin) is loader.TrustedEntry:
                loader.TrustedEntry._expire(origin)

    def recheck(self):
        issued = type(self) is FullEntry and self in _ISSUED_ENTRIES
        try:
            require(issued and self._active and not UNRELEASED)
            require(type(self._modules) is MappingProxyType and set(self._modules) == set(PACKAGE_PATHS)
                    and all(type(module) is ModuleType for module in self._modules.values()))
            if _module_unknown(self):
                _retain(self, 'owned-module-release-unknown')
                require(False)
            require(type(self._origin) is self._modules[LOADER].TrustedEntry)
            self._modules[LOADER].TrustedEntry.recheck(self._origin)
            for path, module in self._modules.items():
                require(sys.modules.get(module.__name__) is module
                        and sha(self._raw[path]) == self._pins[path]['sha256']
                        and len(self._raw[path]) == self._pins[path]['bytes'])
                current, expected = _globals(module), self._snapshots[path]
                require(set(current) == set(expected) and all(current[key] is expected[key] for key in expected))
            for path in (VERIFIER, PARENT, GUARD):
                require(self._origin.modules[path] is self._modules[path])
            self._modules[LOADER].TrustedEntry.recheck(self._origin)
        except BaseException:
            if issued:
                FullEntry._expire(self)
            raise
        return self

    @property
    def modules(self):
        FullEntry.recheck(self)
        return self._modules

    @property
    def origin(self):
        FullEntry.recheck(self)
        return self._origin

    @contextmanager
    def compose(self, held, *, source_guard):
        """Keep original source/guard authority through the returned assembly.

        This does not construct a backend or parent, attest their release, or
        authorize any installer stage. After the guard closes, its caller must
        independently call the exact backend.require_released before outer ack.
        """
        issued = type(self) is FullEntry and self in _ISSUED_ENTRIES
        try:
            require(issued)
            FullEntry.recheck(self)
            with self._modules[LOADER].captured_startup_modules(held, entry=self._origin, source_guard=source_guard) as assembly:
                FullEntry.recheck(self)
                yield assembly
                FullEntry.recheck(self)
        except BaseException:
            if issued:
                FullEntry._expire(self)
            raise

    def activate_full(self):
        """Future full worker/parent/storage authority is deliberately absent."""
        if type(self) is FullEntry and self in _ISSUED_ENTRIES:
            FullEntry._expire(self)
        raise FullEntryUnavailable('company-full-activation-unavailable')

    @contextmanager
    def fresh_installation_modules(self, held):
        """Keep one signed fresh assembly; no native/stage/full activation.

        The company entry chooses this explicit route, never a missing-guard
        fallback or administrator-selected path. All fifteen operational rows
        must match its independent catalog before compilation. Once the caller
        binds physical source, that original guard must outlive the assembly.
        Keep this package context, original source and stage/storage contexts
        live through use and attest their owned release before outer ack.
        """
        issued = type(self) is FullEntry and self in _ISSUED_ENTRIES
        try:
            require(issued)
            FullEntry.recheck(self)
            with self._modules[LOADER].captured_fresh_installation_modules(
                    held, entry=self._origin) as assembly:
                FullEntry.recheck(self)
                yield assembly
                FullEntry.recheck(self)
        except BaseException:
            if issued:
                FullEntry._expire(self)
            raise


@contextmanager
def authenticated_entry_modules(records, *, package_pins, operational_catalog, key_fingerprint):
    """Compose separately trusted package captures with original V/IP/Guard.

    All six raw captures match independent pins before the first compile. The
    loader then owns the original verifier, parent and guard modules. Backend
    and foundation materializer remain separately trusted modules, with their
    own release obligations. No code is imported from candidate siblings.
    """
    require(not UNRELEASED)
    raw, pins = decode_exact_embedded_records(records, package_pins=package_pins)
    require(type(key_fingerprint) is str and re.fullmatch('[a-f0-9]{64}', key_fingerprint) is not None)
    entry, owned = FullEntry(), []
    entry._raw, entry._pins = raw, pins
    try:
        prefix = 'company_full_entry_' + uuid.uuid4().hex + '_'
        modules = {}
        entry._modules = MappingProxyType(modules)
        for path in (LOADER, BACKEND, MATERIALIZER):
            modules[path] = _register(path, raw[path], prefix, owned)
        loader = modules[LOADER]
        require(tuple(loader.ENTRY_PATHS) == (VERIFIER, PARENT, GUARD))
        with loader.trusted_entry_modules({path: raw[path] for path in loader.ENTRY_PATHS},
                bootstrap_pins={path: dict(pins[path]) for path in loader.ENTRY_PATHS},
                operational_catalog=operational_catalog, key_fingerprint=key_fingerprint) as origin:
            modules.update(origin.modules)
            entry._origin = origin
            entry._owned_origin = (loader, origin)
            entry._snapshots = {path: _globals(module) for path, module in modules.items()}
            entry._active = True
            _ISSUED_ENTRIES.add(entry)
            entry.recheck()
            yield entry
            entry.recheck()
    except BaseException:
        if _module_unknown(entry):
            _retain(entry, 'owned-module-release-unknown')
        raise
    finally:
        FullEntry._expire(entry)
        _release(entry, owned)
