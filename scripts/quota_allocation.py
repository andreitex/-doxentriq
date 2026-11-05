"""Protected cross-process allocation journal; no automatic initialization/replay.

This is a HOST_QUOTA_ONLY writer boundary, not a complete backup barrier.
The caller must independently validate the encrypted XFS mount before using it.
Native ownership, flock and durability require separate Linux qualification.
"""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import time
import threading
import uuid

if '__company_captured_dependencies__' in globals():
    from types import MappingProxyType, ModuleType
    _captured_dependencies = __company_captured_dependencies__
    if type(_captured_dependencies) is not MappingProxyType or set(_captured_dependencies) != {'scripts/checkpoint_admission.py'}:
        raise ValueError('company-captured-dependencies-unavailable')
    if any(type(_captured_dependencies[key]) is not ModuleType for key in _captured_dependencies):
        raise ValueError('company-captured-dependencies-unavailable')
    C = _captured_dependencies['scripts/checkpoint_admission.py']
else:
    _spec = importlib.util.spec_from_file_location('quota_allocation_checkpoint', Path(__file__).resolve().with_name('checkpoint_admission.py'))
    C = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(C)
SCOPE = 'HOST_QUOTA_ONLY'
MAX_COMMITS = 20000
EMPTY_STATE = {'nextProjectId': 10000, 'projects': {}}


class Allocation:
    def __init__(self, data, *, files=None, locks=None, clock=time.monotonic, sleep=time.sleep):
        self.data = Path(data)
        self.files, self.locks = files or C.NativeFiles(), locks or C.NativeLocks()
        self.clock, self.sleep = clock, sleep
        self.root_hash = self.files.root(self.data)
        self.device = self.files.protected(self.data, directory=True).st_dev
        self.base = self.data / 'quota/allocation'
        self.projects = self.data / 'quota/projects.json'

    def _paths(self):
        return {'quota': self.data / 'quota', 'runtime': self.data / 'runtime', 'base': self.base,
                'commits': self.base / 'commits', 'storage': self.data / 'runtime/storage'}

    def _placement(self, initial=None):
        C.require(self.files.root(self.data) == self.root_hash)
        for name, path in self._paths().items():
            info = self.files.protected(path, directory=True, private=name not in ('quota', 'runtime'))
            C.require(info.st_dev == self.device, 'Allocation paths must remain on the validated data filesystem')
            if initial is not None:
                C.require(C.directory_binding(info) == initial['directories'][name], 'Allocation directory was replaced')

    def initialize(self, installation_id, *, read_state, write_state):
        """Explicit root/fresh-only initialization after caller mount proof.

        Refuse existing allocation metadata, projects, pending evidence or storage.
        Interrupted initialization is retained and cannot be restarted implicitly.
        The separate checkpoint Gate must be explicitly initialized by the company.
        """
        self.files.require_root()
        C.require(type(installation_id) is str and str(uuid.UUID(installation_id)) == installation_id)
        C.require(not os.path.lexists(self.base) and not os.path.lexists(self.projects))
        C.require(self.files.root(self.data) == self.root_hash)
        for path, private in ((self.data / 'quota', True), (self.data / 'runtime', False), (self.data / 'runtime/storage', True)):
            C.require(self.files.protected(path, directory=True, private=private).st_dev == self.device)
        C.require(set(self.files.inventory(self.data / 'quota', 1)) <= {'checkpoint-admission'})
        storage = self.data / 'runtime/storage'
        self.files.protected(storage, directory=True, private=True)
        C.require(self.files.inventory(storage, 0) == [], 'Existing storage prevents fresh allocation initialization')
        self.files.mkdir(self.base)
        self.files.mkdir(self.base / 'commits')
        self.files.create_lock(self.base / 'allocation.lock')
        self._placement()
        initial = dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.root_hash,
                       installationId=installation_id,
                       directories={name: C.directory_binding(self.files.protected(path, directory=True)) for name, path in self._paths().items()},
                       lock=C.lock_binding(self.files.protected(self.base / 'allocation.lock', private=True)))
        self.files.write(self.base / 'initialization.json', initial)
        C.require(not os.path.lexists(self.projects))
        write_state(self.projects, {'nextProjectId': 10000, 'projects': {}})
        C.require(C.canonical(read_state(self.projects)) == C.canonical(EMPTY_STATE))
        self._placement(initial)
        pointer = self._pointer(initial, 0, EMPTY_STATE)
        self.files.write(self.base / 'state.json', pointer)
        self.files.write(self.base / 'initialized.json', {'initializationSha256': C.digest(initial)})

    def _pointer(self, initial, sequence, value):
        return dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.root_hash,
                    installationId=initial['installationId'], sequence=sequence,
                    projectsSha256=C.digest(value), nextProjectId=value['nextProjectId'])

    def _state(self, fd, expected):
        self.files.check_lock(self.base / 'allocation.lock', fd, expected)
        names = self.files.inventory(self.base, 5)
        C.require(set(names) == {'allocation.lock', 'initialization.json', 'initialized.json', 'state.json', 'commits'})
        initial = C.fields(self.files.read(self.base / 'initialization.json'),
                           {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'directories', 'lock'})
        C.require(type(initial['schemaVersion']) is int and initial['schemaVersion'] == 1 and initial['scope'] == SCOPE and initial['dataRootSha256'] == self.root_hash)
        C.require(type(initial['installationId']) is str and str(uuid.UUID(initial['installationId'])) == initial['installationId'])
        C.fields(initial['directories'], set(self._paths()))
        self._placement(initial)
        C.require(C.lock_binding(self.files.descriptor(fd)) == initial['lock'] == C.lock_binding(self.files.protected(self.base / 'allocation.lock', private=True)), 'Held allocation lock differs from initialization')
        done = C.fields(self.files.read(self.base / 'initialized.json'), {'initializationSha256'})
        C.require(done['initializationSha256'] == C.digest(initial))
        pointer = C.fields(self.files.read(self.base / 'state.json'), {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'sequence', 'projectsSha256', 'nextProjectId'})
        C.require(type(pointer['schemaVersion']) is int and pointer['schemaVersion'] == 1 and pointer['scope'] == SCOPE and pointer['dataRootSha256'] == self.root_hash and pointer['installationId'] == initial['installationId'])
        C.require(type(pointer['sequence']) is int and 0 <= pointer['sequence'] <= MAX_COMMITS)
        C.require(type(pointer['nextProjectId']) is int and 10000 <= pointer['nextProjectId'] < 2**31)
        C.hash_value(pointer['projectsSha256'])
        commits = self.files.inventory(self.base / 'commits', MAX_COMMITS + 1)
        C.require(len(commits) == pointer['sequence'] and set(commits) == {f'{n:010d}' for n in range(1, pointer['sequence'] + 1)}, 'Partial allocation commit cannot be replayed')
        if pointer['sequence']:
            path = self.base / 'commits' / f'{pointer["sequence"]:010d}'
            C.require(set(self.files.inventory(path, 2)) == {'intent.json', 'confirmed.json'})
            intent = C.fields(self.files.read(path / 'intent.json'), {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'sequence', 'previousPointerSha256', 'projectsSha256', 'nextProjectId'})
            C.require(type(intent['schemaVersion']) is int and intent['schemaVersion'] == 1 and intent['scope'] == SCOPE and intent['dataRootSha256'] == self.root_hash and intent['installationId'] == initial['installationId'])
            C.hash_value(intent['previousPointerSha256'])
            C.require(type(intent['sequence']) is int and intent['sequence'] == pointer['sequence'] and type(intent['nextProjectId']) is int and intent['nextProjectId'] == pointer['nextProjectId'] and intent['projectsSha256'] == pointer['projectsSha256'])
            confirmed = C.fields(self.files.read(path / 'confirmed.json'), {'intentSha256'})
            C.require(confirmed['intentSha256'] == C.digest(intent))
        else:
            C.require(pointer == self._pointer(initial, 0, EMPTY_STATE))
        self.files.check_lock(self.base / 'allocation.lock', fd, expected)
        self._placement(initial)
        return initial, pointer

    @contextmanager
    def acquire(self, timeout=5):
        C.require(type(timeout) in (int, float) and 0 < timeout <= 10)
        self.files.protected(self.base, directory=True, private=True)
        fd, expected = self.files.open_lock(self.base / 'allocation.lock')
        acquired = False; lease = None
        try:
            deadline = self.clock() + timeout
            while True:
                self.files.check_lock(self.base / 'allocation.lock', fd, expected)
                if self.locks.try_acquire(fd, False):
                    acquired = True
                    break
                C.require(self.clock() < deadline, 'Allocation wait expired without resetting state')
                self.sleep(min(.01, max(0, deadline - self.clock())))
            initial, pointer = self._state(fd, expected)
            lease = AllocationLease(self, fd, expected, initial, pointer)
            yield lease
            self._state(fd, expected)
        finally:
            try:
                if lease is not None: lease._invalidate()
            finally:
                try:
                    if acquired: self.locks.release(fd)
                finally:
                    self.files.close_lock(fd)


    def _inspection(self, installation_id, lease, read_state):
        initial, pointer = self._state(lease.fd, lease.expected)
        C.require(initial['installationId'] == installation_id,
                  'Allocation initialization belongs to another installation')
        C.require(set(self.files.inventory(self.data / 'quota', 3)) ==
                  {'checkpoint-admission', 'allocation', 'projects.json'},
                  'Unexplained quota evidence requires company reconciliation')
        before = self.files.protected(self.projects, private=True)
        value = lease.read_state(read_state)
        C.require(C.identity(self.files.protected(self.projects, private=True)) == C.identity(before))
        C.require(len(value['projects']) <= 10000)
        project_ids = set()
        for key, row in value['projects'].items():
            C.require(type(key) is str and key.count('/') == 1)
            app, name = key.split('/')
            C.require(str(uuid.UUID(app)) == app and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', name) is not None)
            C.fields(row, {'projectId', 'sizeMb', 'status'})
            C.require(type(row['projectId']) is int and 10000 <= row['projectId'] < value['nextProjectId']
                      and row['projectId'] not in project_ids)
            C.require(type(row['sizeMb']) is int and 1 <= row['sizeMb'] <= 32768)
            C.require(type(row['status']) is str and row['status'] == 'active',
                      'Pending allocation outcomes require company reconciliation')
            project_ids.add(row['projectId'])
        records = []

        def record(path):
            info = self.files.protected(path, private=True)
            result = self.files.read(path)
            C.require(C.identity(self.files.protected(path, private=True)) == C.identity(info))
            records.append(dict(path=str(path.relative_to(self.base)), value=result,
                                identity=[str(item) for item in C.identity(info)]))
            return result

        for name in ('initialization.json', 'initialized.json', 'state.json'):
            record(self.base / name)
        previous = self._pointer(initial, 0, EMPTY_STATE)
        for sequence in range(1, pointer['sequence'] + 1):
            path = self.base / 'commits' / f'{sequence:010d}'
            C.require(set(self.files.inventory(path, 2)) == {'intent.json', 'confirmed.json'},
                      'Partial historical allocation commit requires company reconciliation')
            records.append(dict(path=str(path.relative_to(self.base)),
                                directory=C.directory_binding(self.files.protected(path, directory=True, private=True))))
            intent = C.fields(record(path / 'intent.json'),
                              {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'sequence',
                               'previousPointerSha256', 'projectsSha256', 'nextProjectId'})
            C.require(type(intent['schemaVersion']) is int and intent['schemaVersion'] == 1
                      and intent['scope'] == SCOPE and intent['dataRootSha256'] == self.root_hash
                      and intent['installationId'] == installation_id)
            C.require(type(intent['sequence']) is int and intent['sequence'] == sequence
                      and type(intent['nextProjectId']) is int
                      and previous['nextProjectId'] <= intent['nextProjectId'] < 2**31)
            C.hash_value(intent['projectsSha256']); C.hash_value(intent['previousPointerSha256'])
            C.require(intent['previousPointerSha256'] == C.digest(previous),
                      'Historical allocation pointer chain differs')
            confirmed = C.fields(record(path / 'confirmed.json'), {'intentSha256'})
            C.require(type(confirmed['intentSha256']) is str and confirmed['intentSha256'] == C.digest(intent))
            previous = {key: intent[key] for key in pointer}
        C.require(C.canonical(previous) == C.canonical(pointer))
        self.files.check_lock(self.base / 'allocation.lock', lease.fd, lease.expected)
        self._placement(initial)
        return dict(scope=SCOPE, installationId=installation_id, initializationSha256=C.digest(initial),
                    pointerSha256=C.digest(pointer), historySha256=C.digest(records),
                    projectsSha256=C.digest(value), projectsIdentity=[str(item) for item in C.identity(before)],
                    sequence=pointer['sequence'], projectCount=len(value['projects']), backupReady=False)

    @contextmanager
    def inspect_initialized(self, installation_id, *, read_state, timeout=5):
        """Read-only evidence; expose no AllocationLease or commit authority."""
        import math
        C.require(type(installation_id) is str and str(uuid.UUID(installation_id)) == installation_id)
        C.require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 10)
        with self.acquire(timeout=timeout) as lease:
            expected = self._inspection(installation_id, lease, read_state)
            yield json.loads(C.canonical(expected))
            C.require(C.canonical(self._inspection(installation_id, lease, read_state)) == C.canonical(expected),
                      'Allocation evidence changed during read-only inspection')


class AllocationLease:
    """Nonconcurrent scoped lease; owned by the provision call that acquired it."""
    def __init__(self, allocation, fd, expected, initial, pointer):
        self.allocation, self.fd, self.expected = allocation, fd, expected
        self.initial, self.pointer = initial, pointer
        self.live = True
        self.process, self.thread = os.getpid(), threading.get_ident()
        self._mutex = threading.Lock()

    @contextmanager
    def _call(self):
        C.require(self.live and os.getpid() == self.process and threading.get_ident() == self.thread,
                  'The exact live allocation scope in its owning process/thread is required')
        C.require(self._mutex.acquire(timeout=5), 'Allocation lease call did not complete within five seconds')
        try:
            C.require(self.live)
            yield
        finally:
            self._mutex.release()

    def _invalidate(self):
        self.live = False # Refuse stale calls before releasing/reusing the descriptor.
        C.require(self._mutex.acquire(timeout=5), 'Allocation lease still has an unconfirmed active call')
        self._mutex.release()

    def _check(self):
        C.require(self.live and os.getpid() == self.process and threading.get_ident() == self.thread)
        initial, pointer = self.allocation._state(self.fd, self.expected)
        C.require(C.canonical(initial) == C.canonical(self.initial) and C.canonical(pointer) == C.canonical(self.pointer))

    def read_state(self, read_state):
        with self._call():
            return self._read_state(read_state)

    def _read_state(self, read_state):
        self._check()
        value = read_state(self.allocation.projects)
        C.require(type(value) is dict and set(value) == {'nextProjectId', 'projects'})
        C.require(type(value['nextProjectId']) is int and value['nextProjectId'] == self.pointer['nextProjectId'] and type(value['projects']) is dict)
        C.require(C.digest(value) == self.pointer['projectsSha256'], 'Projects state does not match durable allocation evidence')
        self._check()
        return value

    def commit(self, value, *, read_state, write_state):
        with self._call():
            return self._commit(value, read_state=read_state, write_state=write_state)

    def _commit(self, value, *, read_state, write_state):
        """Retain intent before projects write; never repair a partial commit."""
        value = json.loads(C.canonical(value)) # Freeze proposal before any callback/write.
        old = self._read_state(read_state)
        C.require(type(value) is dict and set(value) == {'nextProjectId', 'projects'} and type(value['nextProjectId']) is int)
        C.require(value['nextProjectId'] >= old['nextProjectId'] and type(value['projects']) is dict and set(old['projects']) <= set(value['projects']))
        for key, record in old['projects'].items():
            new = value['projects'][key]
            C.require(new == record or record['status'] == 'pending' and new == dict(record, status='active'), 'Previously allocated IDs and limits must be preserved')
        C.require(self.pointer['sequence'] < MAX_COMMITS)
        proposed = self.allocation._pointer(self.initial, self.pointer['sequence'] + 1, value)
        intent = dict(proposed, previousPointerSha256=C.digest(self.pointer))
        path = self.allocation.base / 'commits' / f'{proposed["sequence"]:010d}'
        self._check()
        self.allocation.files.mkdir(path)
        self.allocation.files.write(path / 'intent.json', intent)
        write_state(self.allocation.projects, value)
        C.require(C.canonical(read_state(self.allocation.projects)) == C.canonical(value), 'Projects commit readback differs')
        self.allocation._placement(self.initial)
        self.allocation.files.check_lock(self.allocation.base / 'allocation.lock', self.fd, self.expected)
        self.allocation.files.write(path / 'confirmed.json', {'intentSha256': C.digest(intent)})
        self.allocation.files.replace(self.allocation.base / 'state.json', proposed)
        self.pointer = proposed
        self._check()
