"""Stage-local genuine source/assembly ownership; no installer or ACK authority.

The caller independently authenticates the original F package/module and this
module before use. The original F/V/IP registries are retained, while every
stage reacquires its own original-V source and original-F fresh assembly. No
parent, storage, physical backend, process or completion adapter is selected.
"""
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import time
from types import MappingProxyType, ModuleType
from weakref import WeakKeyDictionary

STAGES = ('company-platform-store', 'company-source-materialize', 'repository-seed',
          'fresh-runtime-pair', 'company-stored-startup')
REQUEST_FIELDS = frozenset(('schemaVersion', 'mode', 'operationId', 'releaseSha256',
    'bundleRoot', 'sourceRoot', 'keyPath', 'dataDir', 'backingFile', 'capacityGiB',
    'runscVersion', 'runscSha512'))
IDENTITY_FIELDS = ('releaseSha256', 'platformManifestSha256', 'sourceRevision',
    'sourceTree', 'fileCount', 'totalBytes', 'archiveSha256', 'archiveBytes',
    'signingKeyFingerprint')
UNRELEASED = []
_COORDINATORS, _SCOPES = set(), set()
_CLOSED = WeakKeyDictionary()


class StageScopeUnavailable(ValueError):
    pass


def require(value):
    if value is not True:
        raise StageScopeUnavailable('company-stage-scope-unavailable')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _now(clock):
    value = clock()
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0)
    return value


def _path(value):
    require(type(value) is str and 1 < len(value) <= 1024 and value.isascii()
            and not value.startswith('//') and re.fullmatch('/[A-Za-z0-9_./-]+', value) is not None)
    path = PurePosixPath(value)
    require(path.as_posix() == value and '..' not in path.parts and len(path.parts) <= 32
            and all(len(part) <= 255 for part in path.parts))
    return value


def _request(raw, expected):
    require(type(raw) is bytes and 0 < len(raw) <= 4096 and type(expected) is str
            and re.fullmatch('[a-f0-9]{64}', expected) is not None and sha(raw) == expected)
    try:
        value = json.loads(raw)
        require(type(value) is dict and set(value) == REQUEST_FIELDS and canonical(value) == raw)
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise StageScopeUnavailable('company-stage-scope-unavailable') from None
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and type(value['mode']) is str and value['mode'] == 'full-installation')
    for name, pattern in (('operationId', '[a-f0-9]{32}'), ('releaseSha256', '[a-f0-9]{64}'),
                          ('runscVersion', '[0-9]{8}\\.[0-9]{1,8}'), ('runscSha512', '[a-f0-9]{128}')):
        require(type(value[name]) is str and re.fullmatch(pattern, value[name]) is not None)
    for name in ('bundleRoot', 'sourceRoot', 'keyPath', 'dataDir', 'backingFile'):
        _path(value[name])
    require(type(value['capacityGiB']) is int and 32 <= value['capacityGiB'] <= 4096)
    require(value['bundleRoot'].startswith('/opt/autosoft-company/incoming/')
            and value['sourceRoot'].startswith('/opt/autosoft-company/incoming/')
            and value['keyPath'].startswith('/opt/autosoft-company/bootstrap/')
            and value['keyPath'].endswith('.pem'))
    data, backing = value['dataDir'], value['backingFile']
    require(data.startswith('/srv/') and not data.startswith('/srv/autosoft-company/')
            and data != '/srv/autosoft-company' and backing != data
            and not backing.startswith(data + '/') and not data.startswith(backing + '/')
            and backing != '/opt/autosoft-company' and not backing.startswith('/opt/autosoft-company/')
            and not '/opt/autosoft-company'.startswith(backing + '/'))
    return MappingProxyType(value)


def _catalog(value, paths):
    require(type(value) is dict and set(value) == set(paths))
    copied = {}
    for path in paths:
        row = value[path]
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'gitMode'}
                and type(row['bytes']) is int and 0 < row['bytes'] <= 8 * 1024**2
                and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']) is not None
                and type(row['gitMode']) is str and row['gitMode'] == '100644')
        copied[path] = MappingProxyType(dict(row))
    require(sum(row['bytes'] for row in copied.values()) <= 16 * 1024**2)
    return MappingProxyType(copied)


def _retain(coordinator, reason, *references):
    UNRELEASED.append((coordinator, reason, *references))
    coordinator._expire()


class _SourceFiles:
    """Stable truthy view of the explicit original-V six-method read protocol."""
    __slots__ = ('_lstat', '_open', '_fstat', '_cloexec', '_read', '_close')

    def __init__(self, files):
        for name in ('lstat', 'open', 'fstat', 'cloexec', 'read', 'close'):
            method = getattr(files, name)
            require(callable(method))
            setattr(self, '_' + name, method)

    def __bool__(self): return True
    def lstat(self, path): return self._lstat(path)
    def open(self, parent, name, directory): return self._open(parent, name, directory)
    def fstat(self, fd): return self._fstat(fd)
    def cloexec(self, fd): return self._cloexec(fd)
    def read(self, fd, amount, offset): return self._read(fd, amount, offset)
    def close(self, fd): return self._close(fd)


class _SourceCrypto:
    """Stable truthy view of the explicit original-V verification method."""
    __slots__ = ('_verify',)

    def __init__(self, crypto):
        self._verify = getattr(crypto, 'verify')
        require(callable(self._verify))

    def __bool__(self): return True
    def verify(self, raw, signature, public): return self._verify(raw, signature, public)


def _guard_closed(coordinator, guard, held):
    # A malformed original object is ownership unknown, never evidence of close.
    # Exact type checks precede field observations and any backend callback.
    try:
        G = coordinator._G
        BK = coordinator._BK
        known = (type(guard) is G.HeldCompanySource and guard._verifier is coordinator._V
                 and guard._source is held and type(guard._backend) is BK.ReadOnlySourceBackend
                 and guard._closed is True and type(guard._owned) is list and not guard._owned
                 and guard.active is False and type(G.UNRELEASED_HANDLES) is list
                 and not G.UNRELEASED_HANDLES and type(BK.UNRELEASED_RESOURCES) is list
                 and not BK.UNRELEASED_RESOURCES)
        return known and BK.ReadOnlySourceBackend.require_released(guard._backend) is guard._backend
    except BaseException:
        return False


class StageCoordinator:
    """Issued lifetime/byte binding only; durable progress belongs to original P."""
    def __init__(self):
        self._active = False

    def _expire(self):
        self._active = False
        _COORDINATORS.discard(self)

    def recheck(self):
        issued = type(self) is StageCoordinator and self in _COORDINATORS
        try:
            require(issued and self._active and not UNRELEASED and _now(self._clock) <= self._deadline
                    and bool(self._files) is True and bool(self._crypto) is True)
            F = self._F
            require(type(self._entry) is F.FullEntry)
            F.FullEntry.recheck(self._entry)
            require(self._entry.origin is self._origin
                    and self._origin._fingerprint == self._fingerprint
                    and dict(self._origin._catalog) == dict(self._catalog)
                    and self._entry.modules[F.VERIFIER] is self._V
                    and self._entry.modules[F.PARENT] is self._P
                    and self._entry.modules[F.GUARD] is self._G
                    and self._entry.modules[F.BACKEND] is self._BK
                    and sha(self._request_raw) == self._request_sha256)
        except BaseException:
            if issued:
                self._expire()
            raise
        return self

    @contextmanager
    def source_stage(self, stage):
        """Reauthenticate incoming signed bytes; never adopt stored/partial trees.

        Within this source scope, nest G first and scope.assembly() inside G if
        physical binding is needed. G must close before this source scope exits.
        Its backend.require_released(), parent and storage remain caller duties.
        A stage observation is not a confirmation or permission for the next
        effect. Original P must independently verify every prior durable result.
        """
        issued = type(self) is StageCoordinator and self in _COORDINATORS
        scope = source_cm = held = None
        source_entered = False
        try:
            StageCoordinator.recheck(self)
            require(type(stage) is str and stage in self._stages and self._live_scope is None
                    and stage not in self._used
                    and stage == self._stages[len(self._used)])
            self._used.add(stage) # Attempt consumed before any source IO.
            scope = StageScope()
            scope._coordinator, scope._stage = self, stage
            scope._assembly_live, scope._assembly_used, scope._guards = None, False, []
            self._live_scope = scope
            require(bool(self._files) is True and bool(self._crypto) is True)
            # V uses adapter-or-native selection. These explicit narrow views
            # cannot reevaluate a stateful supplied adapter's truthiness in V.
            files, crypto = _SourceFiles(self._files), _SourceCrypto(self._crypto)
            source_cm = self._V.authenticated_platform_source(
                self._request['bundleRoot'], self._request['keyPath'], self._fingerprint,
                expected_architecture=self._architecture, source_root=self._request['sourceRoot'],
                files=files, crypto=crypto, owner_uid=0, owner_gid=0)
            held = source_cm.__enter__(); source_entered = True
            require(type(held) is self._V.HeldPlatformSource
                    and self._V.require_platform_source(held) is held)
            identity = {name: held.metadata[name] for name in IDENTITY_FIELDS}
            require(identity['releaseSha256'] == self._request['releaseSha256']
                    and identity['signingKeyFingerprint'] == self._fingerprint)
            if self._source_identity is None:
                self._source_identity = MappingProxyType(identity)
            else:
                require(identity == dict(self._source_identity))
            scope._held, scope._active = held, True
            _SCOPES.add(scope)
            StageCoordinator.recheck(self)
            yield scope
            StageScope.recheck(scope)
            require(scope._assembly_live is None)
        except BaseException:
            if issued:
                self._expire()
            raise
        finally:
            if scope is not None:
                scope._active = False
                _SCOPES.discard(scope)
            # An improperly nested externally owned G/assembly still needs its
            # source alive. Retain exact references; never close HPS underneath.
            if scope is not None:
                guards = live = None
                try:
                    guards, live = scope._guards, scope._assembly_live
                    outer_closed = (type(guards) is list and live is None
                                    and all(_guard_closed(self, guard, held) for guard in guards))
                except BaseException:
                    outer_closed = False
                if not outer_closed:
                    _retain(self, 'outer-guard-or-assembly-still-live', source_cm, held, scope,
                            guards, live)
                    raise StageScopeUnavailable('company-stage-scope-unavailable')
            if source_entered:
                try:
                    source_cm.__exit__(None, None, None)
                except BaseException:
                    _retain(self, 'source-close-unknown', source_cm, held, scope)
                    raise
            elif source_cm is not None and self._V.UNRELEASED_HANDLES:
                _retain(self, 'source-acquisition-release-unknown', source_cm, scope, self._V,
                        tuple(self._V.UNRELEASED_HANDLES))
            if scope is not None:
                self._live_scope = None
                if self._active and source_entered:
                    StageCoordinator.recheck(self)
                    require(not held.active and held not in self._V._ISSUED_PLATFORM_SOURCES)
                    _CLOSED[scope] = MappingProxyType(dict(schemaVersion=1,
                        scope='SOURCE_ASSEMBLY_CLOSED_ONLY', stage=stage,
                        installationRequestSha256=self._request_sha256,
                        releaseSha256=self._source_identity['releaseSha256'],
                        ownedSourceAssemblyClosed=True, parentStorageBackendReleaseConfirmed=False,
                        effectsConfirmed=False, stageAcknowledged=False, nativeAuthorized=False))


class StageScope:
    """One stage's original source; fresh assembly is nested and owned here."""
    def __init__(self):
        self._active = False

    def recheck(self):
        issued = type(self) is StageScope and self in _SCOPES
        try:
            require(issued and self._active)
            c = self._coordinator
            StageCoordinator.recheck(c)
            require(c._live_scope is self and c._V.require_platform_source(self._held) is self._held)
        except BaseException:
            if issued:
                self._active = False
                self._coordinator._expire()
            raise
        return self

    @property
    def source(self):
        StageScope.recheck(self)
        return self._held

    @contextmanager
    def assembly(self):
        """One original-F fresh assembly; caller may bind original G inside it.

        Correct order: source_stage -> original G context -> assembly context.
        The original assembly still checks all fifteen rows before any compile.
        No operational function is called by this coordinator.
        """
        cm = assembly = None
        entered = False
        issued = type(self) is StageScope and self in _SCOPES
        try:
            StageScope.recheck(self)
            require(not self._assembly_used and self._assembly_live is None)
            self._assembly_used = True
            c = self._coordinator
            cm = c._F.FullEntry.fresh_installation_modules(c._entry, self._held)
            self._assembly_live = (cm, None)
            assembly = cm.__enter__(); entered = True
            self._assembly_live = (cm, assembly)
            StageScope.recheck(self)
            yield assembly
            StageScope.recheck(self)
            assembly.recheck()
        except BaseException:
            if issued:
                self._active = False
                self._coordinator._expire()
                if not entered:
                    c = self._coordinator
                    L = c._entry._modules[c._F.LOADER]
                    if cm is not None and (L.UNRELEASED or c._F.UNRELEASED):
                        _retain(c, 'assembly-acquisition-release-unknown', cm, self._held, self, L)
                    else:
                        self._assembly_live = None
            raise
        finally:
            if entered:
                try:
                    guard = assembly._guard
                    if guard is not None:
                        self._guards.append(guard)
                    cm.__exit__(None, None, None)
                    self._assembly_live = None
                except BaseException:
                    _retain(self._coordinator, 'assembly-close-unknown', cm, assembly, self._held, self)
                    raise

    @property
    def closed_observation(self):
        require(type(self) is StageScope and self in _CLOSED)
        return _CLOSED[self]


@contextmanager
def stage_coordinator(entry, *, full_entry_module, request_raw, request_sha256,
                      operational_catalog, key_fingerprint, expected_architecture,
                      files, crypto, stages=STAGES, clock=time.monotonic, timeout=900):
    """Bind independent package/request pins, not their external trust provenance.

    F/module and files/crypto references come from a separately authenticated
    company entry. This factory never imports them, constructs native fallbacks,
    starts an installer, creates a durable stage record or interprets child exit.
    Timeout bounds boundary admissions, not kernel IO or external cancellation.
    In-memory overlap/replay refusal supplements original P's durable latch.
    """
    require(type(full_entry_module) is ModuleType and type(entry) is full_entry_module.FullEntry)
    full_entry_module.FullEntry.recheck(entry)
    require(not UNRELEASED and files is not None and bool(files) is True
            and crypto is not None and bool(crypto) is True
            and type(stages) is tuple and 0 < len(stages) <= len(STAGES)
            and all(type(stage) is str and stage in STAGES for stage in stages)
            and len(set(stages)) == len(stages)
            and tuple(stage for stage in STAGES if stage in stages) == stages
            and type(key_fingerprint) is str and re.fullmatch('[a-f0-9]{64}', key_fingerprint) is not None
            and type(expected_architecture) is str and expected_architecture in ('amd64', 'x86_64')
            and callable(clock) and type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 900)
    request = _request(request_raw, request_sha256)
    origin = entry.origin
    L = entry.modules[full_entry_module.LOADER]
    catalog = _catalog(operational_catalog, L.OPERATIONAL_PATHS)
    require(dict(origin._catalog) == dict(catalog) and origin._fingerprint == key_fingerprint)
    coordinator = StageCoordinator()
    coordinator._F, coordinator._entry, coordinator._origin = full_entry_module, entry, origin
    coordinator._V, coordinator._P = (entry.modules[path] for path in
        (full_entry_module.VERIFIER, full_entry_module.PARENT))
    coordinator._G = entry.modules[full_entry_module.GUARD]
    coordinator._BK = entry.modules[full_entry_module.BACKEND]
    coordinator._request, coordinator._request_raw, coordinator._request_sha256 = request, request_raw, request_sha256
    coordinator._catalog, coordinator._fingerprint, coordinator._architecture = catalog, key_fingerprint, 'x86_64'
    coordinator._files, coordinator._crypto, coordinator._stages = files, crypto, stages
    coordinator._clock, coordinator._deadline = clock, _now(clock) + timeout
    coordinator._used, coordinator._live_scope, coordinator._source_identity = set(), None, None
    coordinator._active = True
    _COORDINATORS.add(coordinator)
    try:
        StageCoordinator.recheck(coordinator)
        yield coordinator
        StageCoordinator.recheck(coordinator)
        require(coordinator._live_scope is None)
    finally:
        coordinator._expire()
