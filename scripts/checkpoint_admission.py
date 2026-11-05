"""Standalone durable admission primitive; no backup or quota integration.

Readiness covers only operations admitted through this module. Process exit,
lock release, cancellation, expiry and lost responses never complete an intent.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

SCOPE = 'PRIMITIVE_ONLY'
MAX_RECORD = 65536
MAX_OPERATIONS = 10000
MAX_FENCES = 1000
HEX = re.compile(r'[a-f0-9]{64}')
IDENTIFIER = re.compile(r'[a-f0-9]{32}')
CHECKPOINT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')


class AdmissionUnavailable(ValueError):
    pass


def require(condition, message='Checkpoint admission cannot be independently confirmed'):
    if not condition:
        raise AdmissionUnavailable(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fields(value, names):
    require(type(value) is dict and set(value) == set(names))
    return value


def hash_value(value):
    require(type(value) is str and HEX.fullmatch(value) is not None)


def identifier(value):
    require(type(value) is str and IDENTIFIER.fullmatch(value) is not None)


def checkpoint(value):
    require(type(value) is str and CHECKPOINT.fullmatch(value) is not None)


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def lock_binding(info):
    return {key: str(getattr(info, key)) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size')}


def directory_binding(info):
    # Entries, size, link count and timestamps change during normal commits.
    return {key: str(getattr(info, key)) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')}


class NativeFiles:
    """Root-only Linux transport. Tests inject trust and directory-sync policy."""
    def require_root(self):
        require(os.name == 'posix' and os.geteuid() == 0, 'Explicit root operation on Linux is required')

    def compare_opened(self, path_info, descriptor_info):
        # Production Linux compares every field, including change time.
        require(identity(path_info) == identity(descriptor_info))

    def descriptor(self, fd):
        return os.fstat(fd)

    def inventory(self, path, maximum):
        before = self.protected(path, directory=True, private=True)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = self.descriptor(fd)
            self.compare_opened(before, opened)
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    require(len(names) <= maximum)
            require(identity(self.descriptor(fd)) == identity(opened))
            require(identity(self.protected(path, directory=True, private=True)) == identity(before))
            return names
        finally:
            os.close(fd)

    def protected(self, path, directory=False, private=False):
        path = Path(path)
        info = path.lstat()
        require(path.is_absolute() and path.resolve(strict=True) == path)
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        require(info.st_uid == 0 and not info.st_mode & 0o022)
        if not directory:
            require(info.st_gid == 0)
        if private:
            require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
        if not directory:
            require(info.st_nlink == 1)
        return info

    def root(self, data):
        self.require_root()
        data = Path(data)
        info = self.protected(data, directory=True)
        for parent in data.parents:
            self.protected(parent, directory=True)
        return digest(dict(path=str(data), device=info.st_dev, inode=info.st_ino, mode=info.st_mode, uid=info.st_uid, gid=info.st_gid))

    def sync_directory(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def mkdir(self, path):
        self.protected(path.parent, directory=True)
        path.mkdir(mode=0o700)
        self.sync_directory(path.parent)
        self.protected(path, directory=True, private=True)

    def read(self, path):
        before = self.protected(path, private=True)
        require(0 < before.st_size <= MAX_RECORD)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
        try:
            opened = os.fstat(fd)
            self.compare_opened(before, opened)
            blocks = []
            while sum(map(len, blocks)) <= MAX_RECORD:
                block = os.read(fd, 4096)
                if not block:
                    break
                blocks.append(block)
            raw = b''.join(blocks)
            require(identity(os.fstat(fd)) == identity(opened) and len(raw) == before.st_size)
        finally:
            os.close(fd)
        require(identity(self.protected(path, private=True)) == identity(before))
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result)
                result[key] = value
            return result
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False))
        require(type(value) is dict)
        return value

    def write(self, path, value):
        self.protected(path.parent, directory=True, private=True)
        raw = canonical(value) + b'\n'
        require(len(raw) <= MAX_RECORD)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0), 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        self.sync_directory(path.parent)
        require(canonical(self.read(path)) == canonical(value))

    def replace(self, path, value):
        before = identity(self.protected(path, private=True))
        temporary = path.parent / (path.name + '.' + uuid.uuid4().hex + '.pending')
        self.write(temporary, value)
        require(identity(self.protected(path, private=True)) == before)
        os.replace(temporary, path)
        self.sync_directory(path.parent)
        require(canonical(self.read(path)) == canonical(value))

    def create_lock(self, path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0), 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.sync_directory(path.parent)
        self.protected(path, private=True)

    def open_lock(self, path):
        before = self.protected(path, private=True)
        require(before.st_size == 0)
        fd = os.open(path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
        try:
            opened = os.fstat(fd)
            self.compare_opened(before, opened)
            return fd, (identity(before), identity(opened))
        except BaseException:
            os.close(fd)
            raise

    def check_lock(self, path, fd, expected):
        require(identity(self.protected(path, private=True)) == expected[0] and identity(os.fstat(fd)) == expected[1],
                'Checkpoint lock identity changed')

    def close_lock(self, fd):
        os.close(fd)


class NativeLocks:
    def try_acquire(self, fd, shared):
        import fcntl
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    def release(self, fd):
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


class Gate:
    def __init__(self, data, *, files=None, locks=None, clock=time.monotonic, sleep=time.sleep):
        self.data = Path(data)
        self.files = files or NativeFiles()
        self.locks = locks or NativeLocks()
        self.clock, self.sleep = clock, sleep
        self.root_hash = self.files.root(self.data)
        self.base = self.data / 'quota/checkpoint-admission'
        self._initial = None
        self._held = {}
        self._held_mutex = threading.RLock()

    @contextmanager
    def _registry(self):
        require(self._held_mutex.acquire(timeout=5), 'Activity registry did not become available within five seconds')
        try:
            yield
        finally:
            self._held_mutex.release()

    def _control_paths(self):
        return {'quota': self.data / 'quota', 'base': self.base, 'operations': self.base / 'operations', 'fences': self.base / 'fences'}

    def _check_directories(self):
        paths = self._control_paths()
        self.files.protected(paths['quota'], directory=True)
        if self._initial is not None:
            for name, path in paths.items():
                info = self.files.protected(path, directory=True, private=name != 'quota')
                require(directory_binding(info) == self._initial['directories'][name], 'Initialized admission directory was replaced')

    def _check_held(self):
        with self._registry():
            for fd, (name, shared, expected) in tuple(self._held.items()):
                self.files.check_lock(self.base / name, fd, expected)
                if self._initial is not None:
                    require(lock_binding(self.files.descriptor(fd)) == self._initial['locks'][name], 'Held checkpoint lock differs from initialization')

    def _require_activity(self, fd, shared):
        with self._registry():
            held = self._held.get(fd)
            require(held is not None and held[0] == 'activity.lock' and held[1] is shared,
                    'The exact live activity lease is required')
            self._check_held()

    def _before_mutation(self):
        require(self.files.root(self.data) == self.root_hash)
        self._check_directories(); self._check_held()

    def _write(self, path, value):
        self._before_mutation(); self.files.write(path, value)

    def _replace(self, path, value):
        self._before_mutation(); self.files.replace(path, value)

    def _mkdir(self, path):
        self._before_mutation(); self.files.mkdir(path)

    def _record(self, path, names):
        return fields(self.files.read(path), names)

    def _directory(self, path, allowed=None, maximum=MAX_OPERATIONS):
        self.files.protected(path, directory=True, private=True)
        self._check_directories()
        names = self.files.inventory(path, maximum)
        if allowed is not None:
            require(set(names) <= set(allowed), 'Unexplained admission evidence blocks readiness')
        self._check_directories()
        return names

    def _state(self):
        require(self.files.root(self.data) == self.root_hash, 'Checkpoint data root changed')
        self._directory(self.base, {'coordinator.lock', 'activity.lock', 'initialization.json', 'initialized.json', 'state.json', 'operations', 'fences'}, 7)
        initial = self._record(self.base / 'initialization.json', {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'locks', 'directories'})
        require(initial['schemaVersion'] == 1 and type(initial['schemaVersion']) is int and initial['scope'] == SCOPE and initial['dataRootSha256'] == self.root_hash)
        require(type(initial['installationId']) is str and str(uuid.UUID(initial['installationId'])) == initial['installationId'])
        fields(initial['locks'], {'coordinator.lock', 'activity.lock'})
        fields(initial['directories'], {'quota', 'base', 'operations', 'fences'})
        self._initial = initial
        self._check_directories(); self._check_held()
        for name, binding in initial['locks'].items():
            require(binding == lock_binding(self.files.protected(self.base / name, private=True)), 'Initialized checkpoint lock was replaced')
        done = self._record(self.base / 'initialized.json', {'initializationSha256'})
        require(done['initializationSha256'] == digest(initial))
        state = self._record(self.base / 'state.json', {'schemaVersion', 'scope', 'dataRootSha256', 'generation', 'phase', 'fenceId', 'checkpointId'})
        require(type(state['schemaVersion']) is int and state['schemaVersion'] == 1 and state['scope'] == SCOPE and state['dataRootSha256'] == self.root_hash)
        require(type(state['generation']) is int and 0 <= state['generation'] < 2**31)
        require(state['phase'] in {'OPEN', 'CLOSED'})
        if state['phase'] == 'OPEN':
            require(state['fenceId'] is None and state['checkpointId'] is None)
        else:
            identifier(state['fenceId']); checkpoint(state['checkpointId'])
        return state

    @contextmanager
    def _lock(self, name, shared=False, timeout=5, wait=True):
        require(type(timeout) in (int, float) and 0 < timeout <= 50, 'Admission wait must be bounded to at most 50 seconds')
        self._check_directories()
        self.files.protected(self.base, directory=True, private=True)
        path = self.base / name
        fd, expected = self.files.open_lock(path)
        acquired = False
        deadline = self.clock() + timeout
        try:
            while True:
                self.files.check_lock(path, fd, expected)
                if self.locks.try_acquire(fd, shared):
                    acquired = True
                    self.files.check_lock(path, fd, expected)
                    break
                require(wait, 'An exclusive boundary prevents immediate admission')
                remaining = deadline - self.clock()
                require(remaining > 0, 'Admission wait expired; unresolved work is retained')
                self.sleep(min(0.01, remaining))
            with self._registry():
                self._held[fd] = (name, shared, expected)
            yield fd
            self.files.check_lock(path, fd, expected)
        finally:
            with self._registry():
                try:
                    if acquired:
                        self.locks.release(fd)
                finally:
                    self._held.pop(fd, None)
                    self.files.close_lock(fd)

    def initialize(self, installation_id):
        require(type(installation_id) is str and str(uuid.UUID(installation_id)) == installation_id)
        self.files.protected(self.data / 'quota', directory=True)
        require(not os.path.lexists(self.base), 'Existing admission storage will not be overwritten')
        self.files.mkdir(self.base)
        self.files.create_lock(self.base / 'coordinator.lock')
        self.files.create_lock(self.base / 'activity.lock')
        with self._lock('coordinator.lock'), self._lock('activity.lock'):
            self.files.mkdir(self.base / 'operations'); self.files.mkdir(self.base / 'fences')
            initial = dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.root_hash, installationId=installation_id,
                           locks={name: lock_binding(self.files.protected(self.base / name, private=True)) for name in ('coordinator.lock', 'activity.lock')},
                           directories={name: directory_binding(self.files.protected(path, directory=True, private=name != 'quota')) for name, path in self._control_paths().items()})
            self._initial = initial
            try:
                self._write(self.base / 'initialization.json', initial)
                self._write(self.base / 'state.json', self._open(0))
                self._write(self.base / 'initialized.json', dict(initializationSha256=digest(initial)))
                self._state()
            except BaseException:
                try:
                    self.files.write(self.base / 'initialization-unconfirmed.json', dict(initializationSha256=digest(initial)))
                except BaseException:
                    pass
                raise

    def _open(self, generation):
        return dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.root_hash, generation=generation, phase='OPEN', fenceId=None, checkpointId=None)

    def _bound(self, value, kind, names):
        fields(value, names)
        require(value['scope'] == SCOPE and value['dataRootSha256'] == self.root_hash and value['kind'] == kind)

    def _operation(self, operation_id, complete=False):
        identifier(operation_id)
        run = self.base / 'operations' / operation_id
        names = self._directory(run, {'intent.json', 'effect.json', 'completed.json', 'uncertain.json'}, 4)
        intent = self._record(run / 'intent.json', {'scope', 'kind', 'dataRootSha256', 'operationId', 'generation', 'requestSha256'})
        self._bound(intent, 'admission', intent.keys())
        require(intent['operationId'] == operation_id and type(intent['generation']) is int and 0 <= intent['generation'] < 2**31)
        hash_value(intent['requestSha256'])
        if 'uncertain.json' in names:
            uncertain = self._record(run / 'uncertain.json', {'intentSha256', 'stage'})
            require(uncertain == dict(intentSha256=digest(intent), stage='completion'))
            require(not complete, 'Unconfirmed operation completion blocks readiness')
        if 'effect.json' in names:
            effect = self._record(run / 'effect.json', {'intentSha256'})
            require(effect['intentSha256'] == digest(intent))
        if 'completed.json' in names:
            done = self._record(run / 'completed.json', {'intentSha256', 'status', 'outcomeSha256'})
            require(done['intentSha256'] == digest(intent) and done['status'] in {'confirmed', 'aborted_before_effect'})
            hash_value(done['outcomeSha256'])
            require(done['status'] != 'aborted_before_effect' or 'effect.json' not in names)
        else:
            require(not complete, 'Unresolved admission intent blocks readiness')
        return intent, names

    def _fence(self, fence):
        fields(fence, {'scope', 'kind', 'dataRootSha256', 'fenceId', 'checkpointId', 'generation'})
        self._bound(fence, 'closed-fence', fence.keys())
        identifier(fence['fenceId']); checkpoint(fence['checkpointId'])
        require(type(fence['generation']) is int and 0 < fence['generation'] < 2**31 - 1)
        return self.base / 'fences' / fence['fenceId']

    def _history(self, state, complete=False):
        for operation_id in self._directory(self.base / 'operations'):
            self._operation(operation_id, complete)
        found = False
        for fence_id in self._directory(self.base / 'fences', maximum=MAX_FENCES):
            identifier(fence_id)
            run = self.base / 'fences' / fence_id
            names = self._directory(run, {'intent.json', 'ready.json', 'terminal.json', 'reopen-intent.json', 'reopened.json'}, 5)
            fence = self.files.read(run / 'intent.json'); self._fence(fence)
            require(fence['fenceId'] == fence_id)
            if 'ready.json' in names:
                ready = self._record(run / 'ready.json', {'fenceSha256', 'readinessId', 'scope', 'backupReady'})
                require(ready['fenceSha256'] == digest(fence) and ready['scope'] == SCOPE and ready['backupReady'] is False)
                identifier(ready['readinessId'])
            if 'terminal.json' in names:
                terminal = self._record(run / 'terminal.json', {'fenceSha256', 'status', 'readinessId'})
                require(terminal['fenceSha256'] == digest(fence))
                require(terminal['status'] in {'aborted_before_readiness', 'primitive_scope_finished'})
                require((terminal['status'] == 'aborted_before_readiness' and 'ready.json' not in names and terminal['readinessId'] is None) or
                        (terminal['status'] == 'primitive_scope_finished' and 'ready.json' in names and terminal['readinessId'] == ready['readinessId']))
            if 'reopen-intent.json' in names:
                transition = self._record(run / 'reopen-intent.json', {'fenceSha256', 'terminalSha256', 'openStateSha256'})
                require('terminal.json' in names and transition == dict(fenceSha256=digest(fence), terminalSha256=digest(terminal), openStateSha256=digest(self._open(fence['generation'] + 1))))
            if 'reopened.json' in names:
                opened = self._record(run / 'reopened.json', {'reopenIntentSha256'})
                require('reopen-intent.json' in names and opened['reopenIntentSha256'] == digest(transition))
            if state['phase'] == 'CLOSED' and state['fenceId'] == fence_id:
                require(state['checkpointId'] == fence['checkpointId'] and state['generation'] == fence['generation'])
                found = True
            else:
                require('reopened.json' in names and fence['generation'] < state['generation'], 'Incomplete close or reopen retains admission closed')
        require(state['phase'] != 'CLOSED' or found, 'Closed fence intent is missing')

    def status(self):
        with self._lock('coordinator.lock'):
            state = self._state(); self._history(state)
            return dict(state, backupReady=False)

    def admit(self, request_sha256, timeout=5):
        hash_value(request_sha256)
        with self._lock('coordinator.lock', timeout=timeout):
            state = self._state(); self._history(state)
            require(state['phase'] == 'OPEN', 'Checkpoint admission is closed')
            require(len(self._directory(self.base / 'operations')) < MAX_OPERATIONS)
            # OPEN plus coordinator ownership normally guarantees immediate SH.
            # Never wait for an exclusive holder while monopolising coordinator.
            activity = self._lock('activity.lock', shared=True, timeout=timeout, wait=False)
            activity_fd = activity.__enter__()
            try:
                operation_id = uuid.uuid4().hex
                run = self.base / 'operations' / operation_id
                self._mkdir(run)
                intent = dict(scope=SCOPE, kind='admission', dataRootSha256=self.root_hash, operationId=operation_id, generation=state['generation'], requestSha256=request_sha256)
                self._write(run / 'intent.json', intent)
                return OperationLease(self, operation_id, intent, activity, activity_fd)
            except BaseException:
                activity.__exit__(None, None, None)
                raise

    def close(self, checkpoint_id, timeout=5):
        checkpoint(checkpoint_id)
        with self._lock('coordinator.lock', timeout=timeout):
            state = self._state(); self._history(state)
            require(state['phase'] == 'OPEN', 'Checkpoint admission is already closed')
            require(state['generation'] < 2**31 - 2)
            require(len(self._directory(self.base / 'fences', maximum=MAX_FENCES)) < MAX_FENCES)
            fence = dict(scope=SCOPE, kind='closed-fence', dataRootSha256=self.root_hash, fenceId=uuid.uuid4().hex, checkpointId=checkpoint_id, generation=state['generation'] + 1)
            run = self._fence(fence); self._mkdir(run)
            self._write(run / 'intent.json', fence)
            closed = dict(self._open(fence['generation']), phase='CLOSED', fenceId=fence['fenceId'], checkpointId=checkpoint_id)
            self._replace(self.base / 'state.json', closed)
            self._require_closed(fence)
            return dict(fence)

    def _require_closed(self, fence):
        run = self._fence(fence)
        state = self._state(); self._history(state)
        require(state['phase'] == 'CLOSED' and state['fenceId'] == fence['fenceId'] and state['generation'] == fence['generation'] and state['checkpointId'] == fence['checkpointId'], 'Stale or foreign checkpoint fence')
        require(canonical(self.files.read(run / 'intent.json')) == canonical(fence))
        return run, state

    def readiness(self, fence, timeout=5):
        # CLOSED was committed by close(); coordinator is not held while EX waits.
        require(type(timeout) in (int, float) and 0 < timeout <= 50)
        deadline = self.clock() + timeout
        activity = self._lock('activity.lock', timeout=timeout)
        activity_fd = activity.__enter__()
        try:
            with self._lock('coordinator.lock', timeout=deadline - self.clock()):
                run, state = self._require_closed(fence); self._history(state, complete=True)
                ready = dict(fenceSha256=digest(fence), readinessId=uuid.uuid4().hex, scope=SCOPE, backupReady=False)
                self._write(run / 'ready.json', ready)
                return ReadinessLease(self, dict(fence), ready, activity, activity_fd)
        except BaseException:
            activity.__exit__(None, None, None)
            raise

    def _reopen(self, fence, activity_fd, readiness_id=None, deadline=None):
        self._require_activity(activity_fd, shared=False)
        with self._lock('coordinator.lock', timeout=5 if deadline is None else deadline - self.clock()):
            run, state = self._require_closed(fence); self._history(state, complete=True)
            self._require_activity(activity_fd, shared=False)
            names = self._directory(run)
            if readiness_id is None:
                require('ready.json' not in names, 'Readiness was already granted; an abort cannot reopen it')
                status = 'aborted_before_readiness'
            else:
                identifier(readiness_id)
                ready = self.files.read(run / 'ready.json')
                require(ready['readinessId'] == readiness_id)
                status = 'primitive_scope_finished'
            terminal = dict(fenceSha256=digest(fence), status=status, readinessId=readiness_id)
            try:
                self._write(run / 'terminal.json', terminal)
                open_state = self._open(fence['generation'] + 1)
                transition = dict(fenceSha256=digest(fence), terminalSha256=digest(terminal), openStateSha256=digest(open_state))
                self._write(run / 'reopen-intent.json', transition)
                self._replace(self.base / 'state.json', open_state)
                self._write(run / 'reopened.json', dict(reopenIntentSha256=digest(transition)))
                self._history(self._state(), complete=True)
            except BaseException:
                # An unconfirmed transition is not a licence to retry or open.
                # If writing this marker also fails, retain its partial file and
                # all prior transition evidence; do not clean anything up.
                try:
                    self.files.write(run / 'reopen-unconfirmed.json', dict(fenceSha256=digest(fence)))
                except BaseException:
                    pass
                raise

    def abort_and_reopen(self, fence, timeout=5):
        require(type(timeout) in (int, float) and 0 < timeout <= 50)
        deadline = self.clock() + timeout
        with self._lock('activity.lock', timeout=timeout) as activity_fd:
            self._reopen(fence, activity_fd, deadline=deadline)


    def _inspection(self, installation_id):
        """Closed, read-only evidence while both inspection locks are held."""
        state = self._state()
        require(self._initial['installationId'] == installation_id,
                'Admission initialization belongs to another installation')
        require(state['phase'] == 'OPEN', 'Closed admission requires company reconciliation')
        self._history(state, complete=True)
        records = []

        def record(path):
            before = self.files.protected(path, private=True)
            value = self.files.read(path)
            require(identity(self.files.protected(path, private=True)) == identity(before))
            records.append(dict(path=str(path.relative_to(self.base)), value=value,
                                identity=[str(item) for item in identity(before)]))

        for name in ('initialization.json', 'initialized.json', 'state.json'):
            record(self.base / name)
        for directory, maximum, allowed in (
            ('operations', MAX_OPERATIONS, {'intent.json', 'effect.json', 'completed.json', 'uncertain.json'}),
            ('fences', MAX_FENCES, {'intent.json', 'ready.json', 'terminal.json', 'reopen-intent.json', 'reopened.json'}),
        ):
            for name in sorted(self._directory(self.base / directory, maximum=maximum)):
                identifier(name)
                path = self.base / directory / name
                records.append(dict(path=str(path.relative_to(self.base)),
                                    directory=directory_binding(self.files.protected(path, directory=True, private=True))))
                for leaf in sorted(self._directory(path, allowed, len(allowed))):
                    record(path / leaf)
        self._check_directories(); self._check_held()
        return dict(scope=SCOPE, installationId=installation_id, initializationSha256=digest(self._initial),
                    stateSha256=digest(state), historySha256=digest(records), generation=state['generation'],
                    phase='OPEN', backupReady=False)

    @contextmanager
    def inspect_initialized(self, installation_id, timeout=5):
        """Exclude admitted writers without creating a fence or readiness record.

        Activity EX is acquired before coordinator, allowing a prior SH owner to
        finish through coordinator. The supplied budget covers lock acquisition;
        count-bounded history reads and filesystem IO have no wall-clock claim.
        """
        import math
        require(type(installation_id) is str and str(uuid.UUID(installation_id)) == installation_id)
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 50)
        deadline = self.clock() + timeout
        with self._lock('activity.lock', timeout=timeout) as activity_fd:
            with self._lock('coordinator.lock', timeout=deadline - self.clock()):
                self._require_activity(activity_fd, shared=False)
                expected = self._inspection(installation_id)
                # The caller receives evidence, never a mutable operation lease.
                yield json.loads(canonical(expected))
                require(canonical(self._inspection(installation_id)) == canonical(expected),
                        'Admission evidence changed during read-only inspection')
                self._require_activity(activity_fd, shared=False)


class _Lease:
    def __init__(self, activity, activity_fd):
        self.activity, self.activity_fd = activity, activity_fd
        self.live = True
        self._mutex = threading.Lock()

    @contextmanager
    def _call(self):
        require(self._mutex.acquire(timeout=5), 'Concurrent lease call did not finish within five seconds')
        try:
            yield
        finally:
            self._mutex.release()

    def __enter__(self):
        with self._call():
            require(self.live)
            return self

    def release(self):
        with self._call():
            if self.live:
                self.live = False
                self.activity.__exit__(None, None, None)

    def __exit__(self, *_):
        self.release()


class OperationLease(_Lease):
    def __init__(self, gate, operation_id, intent, activity, activity_fd):
        super().__init__(activity, activity_fd)
        self.gate, self.operation_id, self.intent = gate, operation_id, intent

    def _event(self, name, value):
        with self._call():
            require(self.live, 'Released admission cannot claim completion')
            gate = self.gate
            gate._require_activity(self.activity_fd, shared=True)
            with gate._lock('coordinator.lock'):
                state = gate._state(); gate._history(state)
                gate._require_activity(self.activity_fd, shared=True)
                intent, names = gate._operation(self.operation_id)
                require(canonical(intent) == canonical(self.intent) and 'completed.json' not in names)
                run = gate.base / 'operations' / self.operation_id
                try:
                    gate._write(run / name, value)
                except BaseException:
                    if name == 'completed.json':
                        try:
                            gate.files.write(run / 'uncertain.json', dict(intentSha256=digest(intent), stage='completion'))
                        except BaseException:
                            pass
                    raise

    def mark_possible_effect(self):
        self._event('effect.json', dict(intentSha256=digest(self.intent)))

    def complete(self, outcome_sha256):
        hash_value(outcome_sha256)
        self._event('completed.json', dict(intentSha256=digest(self.intent), status='confirmed', outcomeSha256=outcome_sha256))

    def abort_before_effect(self):
        with self._call():
            require(self.live)
            gate = self.gate
            gate._require_activity(self.activity_fd, shared=True)
            with gate._lock('coordinator.lock'):
                state = gate._state(); gate._history(state)
                gate._require_activity(self.activity_fd, shared=True)
                intent, names = gate._operation(self.operation_id)
                require(canonical(intent) == canonical(self.intent) and 'effect.json' not in names and 'completed.json' not in names)
                run = gate.base / 'operations' / self.operation_id
                try:
                    gate._write(run / 'completed.json', dict(intentSha256=digest(intent), status='aborted_before_effect', outcomeSha256=digest(dict(operationId=self.operation_id, noEffectsAttempted=True))))
                except BaseException:
                    try:
                        gate.files.write(run / 'uncertain.json', dict(intentSha256=digest(intent), stage='completion'))
                    except BaseException:
                        pass
                    raise


class ReadinessLease(_Lease):
    def __init__(self, gate, fence, evidence, activity, activity_fd):
        super().__init__(activity, activity_fd)
        self.gate, self.fence, self.evidence = gate, fence, evidence

    def finish_scope_and_reopen(self):
        with self._call():
            require(self.live, 'Released readiness cannot reopen a checkpoint')
            self.gate._reopen(self.fence, self.activity_fd, self.evidence['readinessId'])
