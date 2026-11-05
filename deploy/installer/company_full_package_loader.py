"""Compose a bounded full-installation package; no CLI or native activation.

The company entry must independently authenticate this loader, package_module
and its trust inputs before executing them. This API checks equality to that
external trust; package self-hashes cannot establish the initial company origin.
It preserves trusted Python identities and is not hostile-interpreter isolation.
"""
import base64
from contextlib import contextmanager
import hashlib
import sys
from types import MappingProxyType, ModuleType
import uuid

FULL_ENTRY = 'deploy/installer/company_full_entry.py'
STORED_STARTUP = 'deploy/installer/company_stored_startup.py'
FULL_PLAN = 'deploy/installer/company_full_plan.py'
INNER_PATHS = ('scripts/company_captured_loader.py', 'scripts/verify-release.py',
    'scripts/installer_parent.py', 'scripts/company_source_guard.py',
    'scripts/company_source_guard_backend.py', 'scripts/installer_materialize.py')
PACKAGE_PATHS = (*INNER_PATHS, FULL_ENTRY, STORED_STARTUP, FULL_PLAN)
UNRELEASED = []
_COMPOSITIONS = set()


class FullCompositionUnavailable(ValueError):
    pass


def require(value):
    if value is not True:
        raise FullCompositionUnavailable('company-full-composition-unavailable')


def _globals(module):
    return {name: value for name, value in vars(module).items() if name != '__builtins__'}


def _register(path, raw, prefix, owned):
    name = prefix + path.replace('/', '_').replace('.', '_')
    require(name not in sys.modules)
    module = ModuleType(name)
    module.__file__ = '<trusted full package ' + path + '>'
    owned.append((name, module))
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def _retain(composition, reason):
    if not composition._retained:
        composition._retained = True
        UNRELEASED.append((composition, reason, composition._modules, composition._raw))


def _unknown(composition):
    return any(bool(vars(module).get('UNRELEASED'))
               or bool(composition._snapshots.get(path, {}).get('UNRELEASED'))
               for path, module in composition._modules.items())


class FullComposition:
    """Private live composition; no release or stage authority is issued."""
    def __init__(self):
        self._active = False
        self._retained = False
        self._modules = MappingProxyType({})
        self._raw = MappingProxyType({})
        self._snapshots = {}

    def _expire(self):
        self._active = False
        _COMPOSITIONS.discard(self)

    def recheck(self):
        issued = type(self) is FullComposition and self in _COMPOSITIONS
        try:
            require(issued and self._active and not UNRELEASED)
            require(self._package_module.validate_package is self._package_validator
                    and not self._package_module.UNRELEASED)
            package_current = _globals(self._package_module)
            require(set(package_current) == set(self._package_snapshot)
                    and all(package_current[name] is self._package_snapshot[name] for name in package_current))
            if _unknown(self):
                _retain(self, 'owned-module-release-unknown')
                require(False)
            F = self._modules[FULL_ENTRY]
            require(type(self._entry) is F.FullEntry)
            F.FullEntry.recheck(self._entry)
            for path, module in self._modules.items():
                require(type(module) is ModuleType and sys.modules.get(module.__name__) is module)
                current, expected = _globals(module), self._snapshots[path]
                require(set(current) == set(expected) and all(current[name] is expected[name] for name in expected))
            F.FullEntry.recheck(self._entry)
        except BaseException:
            if issued:
                FullComposition._expire(self)
            raise
        return self

    @property
    def entry(self):
        FullComposition.recheck(self)
        return self._entry

    @property
    def modules(self):
        FullComposition.recheck(self)
        return self._modules

    @contextmanager
    def fresh_foundation(self, held, request):
        """Borrow original HPS and keep one original fresh assembly and plan.

        A caller may later bind its original physical source guard to the
        returned assembly, which must remain live through this scope's exit.
        Source/parent/storage handles and release attestations remain caller
        obligations. This method starts no process and acknowledges no stage.
        """
        FullComposition.recheck(self)
        F, K = self._modules[FULL_ENTRY], self._modules[FULL_PLAN]
        try:
            with F.FullEntry.fresh_installation_modules(self._entry, held) as assembly:
                with K.planned_foundation(self._entry, held, request,
                                         entry_module=F, assembly=assembly) as plan:
                    FullComposition.recheck(self)
                    yield assembly, plan
                    FullComposition.recheck(self)
            FullComposition.recheck(self)
        except BaseException:
            FullComposition._expire(self)
            raise


@contextmanager
def authenticated_full_package(raw, *, package_module, package_pins,
                               operational_catalog, key_fingerprint):
    """Validate every capture/catalog row before executing the first module.

    package_module is the separately authenticated inert company publisher API.
    Its closed, canonical schema validates against independent nine-member pins,
    fifteen-member catalog and key fingerprint. The six original entry captures
    compile once inside F. The three outer modules are owned by this context.
    Foundation-only packages and F's six-member contract remain unchanged.
    """
    require(not UNRELEASED and type(package_module) is ModuleType
            and not package_module.UNRELEASED and tuple(package_module.PACKAGE_PATHS) == PACKAGE_PATHS)
    package_snapshot = _globals(package_module)
    validator = package_module.validate_package
    value = validator(raw, package_pins=package_pins,
                      operational_catalog=operational_catalog, fingerprint=key_fingerprint)
    require(package_module.validate_package is validator)
    package_current = _globals(package_module)
    require(set(package_current) == set(package_snapshot)
            and all(package_current[name] is package_snapshot[name] for name in package_current)
            and not package_module.UNRELEASED)
    records = value['records']
    captures = MappingProxyType({path: base64.b64decode(records[path]['base64'], validate=True)
                                for path in PACKAGE_PATHS})
    # Verify the copied rows again before compilation; no dynamic imports of
    # candidate siblings or helper calls can occur between capture and exec.
    for path in PACKAGE_PATHS:
        require(len(captures[path]) == records[path]['bytes']
                and hashlib.sha256(captures[path]).hexdigest() == records[path]['sha256'])
    composition, owned = FullComposition(), []
    composition._raw = captures
    composition._package_module, composition._package_validator = package_module, validator
    composition._package_snapshot = package_snapshot
    try:
        prefix = 'company_full_package_' + uuid.uuid4().hex + '_'
        modules = {}
        composition._modules = MappingProxyType(modules)
        for path in (FULL_ENTRY, STORED_STARTUP, FULL_PLAN):
            modules[path] = _register(path, captures[path], prefix, owned)
        F = modules[FULL_ENTRY]
        require(tuple(F.PACKAGE_PATHS) == INNER_PATHS)
        inner_records = {path: dict(records[path]) for path in INNER_PATHS}
        inner_pins = {path: {name: records[path][name] for name in ('bytes', 'sha256')}
                      for path in INNER_PATHS}
        with F.authenticated_entry_modules(inner_records, package_pins=inner_pins,
                operational_catalog=value['operationalCatalog'], key_fingerprint=value['keyFingerprint']) as entry:
            composition._entry = entry
            composition._snapshots = {path: _globals(module) for path, module in modules.items()}
            composition._active = True
            _COMPOSITIONS.add(composition)
            composition.recheck()
            yield composition
            composition.recheck()
    except BaseException:
        if _unknown(composition):
            _retain(composition, 'owned-module-release-unknown')
        raise
    finally:
        FullComposition._expire(composition)
        errors = []
        for name, module in reversed(owned):
            if sys.modules.get(name) is module:
                del sys.modules[name]
            else:
                errors.append((name, module, sys.modules.get(name)))
        owned.clear()
        if errors:
            _retain(composition, ('module-registration-unknown', tuple(errors)))
            raise FullCompositionUnavailable('company-full-composition-unavailable')
