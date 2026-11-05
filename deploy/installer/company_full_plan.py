"""Plan a schema4 foundation from the original, authenticated full entry.

The company package must authenticate this module and entry_module before use.
This is an in-process planning API. It starts no process, supplies no native
backend and grants no host effects or stage acknowledgement. Its caller keeps
the original entry, verifier source and fresh assembly live through this scope.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import PurePosixPath
import re
from types import MappingProxyType, ModuleType

BASE = '/opt/autosoft-company'
PHASES = ('packages', 'storage', 'prepare', 'activate')
COMMAND_LIMIT = 65536
PATH_LIMIT = 1024
FULL_CAPACITY_CHECK = (b'\nrequire_host_capacity full "$(awk \'/MemTotal:/ {print $2}\' /proc/meminfo)" '
                       b'"$(getconf _NPROCESSORS_ONLN)"\n')
_PLANS = set()


class FullPlanUnavailable(ValueError):
    pass


def require(value):
    if value is not True:
        raise FullPlanUnavailable('company-full-plan-unavailable')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _path(value):
    require(type(value) is str and 0 < len(value) <= PATH_LIMIT
            and not value.startswith('//')
            and re.fullmatch('/[A-Za-z0-9_./-]+', value) is not None)
    path = PurePosixPath(value)
    require(path.as_posix() == value and value != '/' and '..' not in path.parts
            and len(path.parts) <= 32 and all(len(part) <= 255 for part in path.parts))
    return value


def validate_request(request):
    """Closed full-installation inputs; deployment configuration follows later."""
    names = {'schemaVersion', 'mode', 'operationId', 'releaseSha256', 'bundleRoot',
             'sourceRoot', 'keyPath', 'dataDir', 'backingFile', 'capacityGiB',
             'runscVersion', 'runscSha512'}
    require(type(request) is dict and set(request) == names)
    require(type(request['schemaVersion']) is int and request['schemaVersion'] == 1
            and type(request['mode']) is str and request['mode'] == 'full-installation')
    for name, pattern in (('operationId', '[a-f0-9]{32}'), ('releaseSha256', '[a-f0-9]{64}'),
                          ('runscVersion', '[0-9]{8}\\.[0-9]{1,8}'), ('runscSha512', '[a-f0-9]{128}')):
        require(type(request[name]) is str and re.fullmatch(pattern, request[name]) is not None)
    for name in ('bundleRoot', 'sourceRoot', 'keyPath', 'dataDir', 'backingFile'):
        _path(request[name])
    require(type(request['capacityGiB']) is int and 32 <= request['capacityGiB'] <= 4096)
    data, backing = request['dataDir'], request['backingFile']
    require(data.startswith('/srv/') and not data.startswith('/srv/autosoft-company/')
            and data != '/srv/autosoft-company' and backing != data
            and not backing.startswith(data + '/') and not data.startswith(backing + '/'))
    require(backing != BASE and not backing.startswith(BASE + '/') and not BASE.startswith(backing + '/'))
    for name in ('bundleRoot', 'sourceRoot'):
        require(request[name].startswith(BASE + '/incoming/')
                and not request[name].startswith(data + '/'))
    require(request['keyPath'].startswith(BASE + '/bootstrap/') and request['keyPath'].endswith('.pem'))
    return MappingProxyType(dict(request))


def _origin(entry_module, entry, held, assembly):
    # Reject public clones/subclasses before their callbacks or source access.
    require(type(entry_module) is ModuleType and type(entry) is entry_module.FullEntry)
    entry_module.FullEntry.recheck(entry)
    modules, origin = entry.modules, entry.origin
    L = modules[entry_module.LOADER]
    require(type(assembly) is L.FreshInstallationAssembly)
    L.FreshInstallationAssembly.recheck(assembly)
    require(assembly._entry is origin and assembly._source is held)
    V = modules[entry_module.VERIFIER]
    require(V.require_platform_source(held) is held
            and assembly.modules[entry_module.VERIFIER] is V
            and assembly.modules[entry_module.PARENT] is modules[entry_module.PARENT])
    entry_module.FullEntry.recheck(entry)
    L.FreshInstallationAssembly.recheck(assembly)
    return modules, L, V


class FoundationPlan:
    """Private issued, immutable plan; it owns no caller resources."""
    def __init__(self):
        self._active = False

    def _expire(self):
        self._active = False
        _PLANS.discard(self)

    def recheck(self):
        issued = type(self) is FoundationPlan and self in _PLANS
        try:
            require(issued and self._active)
            modules, _, V = _origin(self._entry_module, self._entry, self._held, self._assembly)
            require(modules[self._entry_module.MATERIALIZER] is self._materializer
                    and V is self._verifier
                    and self._held.metadata['releaseSha256'] == self._request['releaseSha256'])
        except BaseException:
            if issued:
                FoundationPlan._expire(self)
            raise
        return self

    @property
    def request(self):
        FoundationPlan.recheck(self)
        return self._request

    @property
    def files(self):
        FoundationPlan.recheck(self)
        return self._rows

    @property
    def roots(self):
        FoundationPlan.recheck(self)
        return self._roots

    @property
    def inventory_sha256(self):
        FoundationPlan.recheck(self)
        return self._inventory_sha256

    def phase_command(self, phase):
        """Return fixed argv, with captured code and seven separate arguments.

        The native supervisor must separately admit resources, live parent and
        storage capabilities and bounded process execution. A returned command
        is not an execution grant. Each command enforces the full host capacity
        check before invoking the existing foundation phase.
        """
        FoundationPlan.recheck(self)
        require(type(phase) is str and phase in PHASES)
        execution = (self._roots['stagingParent'] if phase == 'packages'
                     else self._roots['finalRoot'] if phase == 'activate'
                     else self._roots['stagedRoot'])
        request = self._request
        body = self._phase_bytes + FULL_CAPACITY_CHECK + ('company_' + phase + '_phase "$@"\n').encode()
        require(len(body) < COMMAND_LIMIT)
        argv = ('/bin/bash', '--noprofile', '--norc', '-c',
                body.decode('utf-8'),
                'company-full-foundation', execution, self._roots['finalRoot'],
                request['dataDir'], request['backingFile'], str(request['capacityGiB']),
                request['runscVersion'], request['runscSha512'])
        FoundationPlan.recheck(self)
        return argv


@contextmanager
def planned_foundation(entry, held, request, *, entry_module, assembly):
    """Capture the fixed 63-leaf projection without a schema3 impersonation.

    Source authority is the original V-issued schema4 handle, and the borrowed
    fresh assembly belongs to this exact entry/source. No archive is copied;
    the original held archive and later artifact store remain separate. Default
    foundation-only installation and retained/reboot routes are unchanged.
    """
    request = validate_request(request)
    modules, _, V = _origin(entry_module, entry, held, assembly)
    M = modules[entry_module.MATERIALIZER]
    rows, release = M.capture_platform_foundation(held, verifier=V)
    require(release == request['releaseSha256'] and len(rows) == 63)
    install = rows['scripts/install.sh']
    require(install.startswith(b'#!/usr/bin/env bash\n# Candidate phase definitions only.')
            and all(install.count(('company_' + phase + '_phase() {').encode()) == 1 for phase in PHASES))
    raw = b'\n'.join(rows[name] for name in ('scripts/lib.sh', 'scripts/install-runtime-gate.sh', 'scripts/install.sh'))
    require(len(raw) < COMMAND_LIMIT and b'\0' not in raw)
    raw.decode('utf-8', 'strict')
    plan = FoundationPlan()
    plan._entry_module, plan._entry, plan._held, plan._assembly = entry_module, entry, held, assembly
    plan._verifier, plan._materializer, plan._request, plan._rows = V, M, request, rows
    plan._phase_bytes = raw
    operation = request['operationId']
    parent = request['dataDir'] + '/company/host-releases'
    plan._roots = MappingProxyType(dict(stagingParent=BASE + '/staging',
        stagedRoot=BASE + '/staging/install-' + operation, finalParent=parent,
        finalRoot=parent + '/install-' + operation, evidenceRoot=BASE + '/evidence/' + operation))
    plan._inventory_sha256 = digest(canonical({name: dict(bytes=len(value), sha256=digest(value))
                                               for name, value in sorted(rows.items())}))
    plan._active = True
    _PLANS.add(plan)
    try:
        plan.recheck()
        yield plan
        plan.recheck()
    finally:
        FoundationPlan._expire(plan)
