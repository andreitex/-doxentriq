#!/usr/bin/env python3
"""Durable original-container resumption; never verifies or restores a backup.

Maintenance's exclusive lock must cover creation and reconciliation. A durable
start intent is also an at-most-once fence. No executor or general command API
is present here; callers supply exact-ID observation and start operations.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

ID = re.compile(r'^[a-f0-9]{64}$')
OP = re.compile(r'^[a-f0-9]{32}$')
MAX_ORIGINALS = 256
MAX_HISTORY = 4096
EVENTS = {'stop-intent', 'stopped', 'start-intent', 'running', 'uncertain'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def protected(path, directory=False):
    path = Path(path)
    value = path.lstat()
    if path.resolve(strict=True) != path or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        raise ValueError('Backup recovery storage is linked or special')
    if not directory and value.st_nlink != 1:
        raise ValueError('Backup recovery record has ambiguous ownership')
    if os.name == 'posix' and (value.st_uid != 0 or value.st_gid != 0 or value.st_mode & (0o022 if directory else 0o177)):
        raise ValueError('Backup recovery storage is not root protected')
    return value


def stable(value, handle=False):
    # Windows handle/path ctime differs; each path and each handle is instead
    # checked against itself. Atime changes caused by these reads are ignored.
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns')
    if not handle:
        keys += ('st_ctime_ns',)
    return tuple(getattr(value, key) for key in keys)


def read_record(path, maximum=256 * 1024):
    before = protected(path)
    if not 1 <= before.st_size <= maximum:
        raise ValueError('Backup recovery record exceeds its bound')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(descriptor)
        if stable(opened, True) != stable(before, True):
            raise ValueError('Backup recovery record changed before reading')
        with os.fdopen(descriptor, 'rb', closefd=False) as handle:
            raw = handle.read(maximum + 1)
        if len(raw) != before.st_size or stable(os.fstat(descriptor), True) != stable(opened, True):
            raise ValueError('Backup recovery record changed while reading')
    finally:
        os.close(descriptor)
    if stable(protected(path)) != stable(before):
        raise ValueError('Backup recovery record changed after reading')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate backup recovery field')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite recovery field')))


def write_record(path, value):
    protected(path.parent, directory=True)
    raw = canonical(value) + b'\n'
    if len(raw) > 256 * 1024:
        raise ValueError('Backup recovery record exceeds its bound')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb', closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    sync_directory(path.parent)
    if canonical(read_record(path)) != canonical(value):
        raise ValueError('Backup recovery record readback failed')


def mkdir(path):
    path.mkdir(mode=0o700)
    sync_directory(path.parent)
    protected(path, directory=True)


def fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('Backup recovery schema is unavailable')


def hash_field(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise ValueError('Backup recovery hash is invalid')


def observation(value):
    fields(value, {'profileSha256', 'stateSha256', 'running', 'cleanStopped'})
    hash_field(value['profileSha256']); hash_field(value['stateSha256'])
    if type(value['running']) is not bool or type(value['cleanStopped']) is not bool or (value['running'] and value['cleanStopped']):
        raise ValueError('Backup recovery observation is invalid')
    return json.loads(canonical(value))


class BackupJournal:
    def __init__(self, data):
        self.data = Path(data).absolute()
        root = protected(self.data, directory=True)
        for ancestor in self.data.parents:
            protected(ancestor, directory=True)
        self.root_binding = digest(dict(path=str(self.data), device=root.st_dev, inode=root.st_ino,
                                       mode=root.st_mode, uid=root.st_uid, gid=root.st_gid))
        self.base = self.data / 'backups/quiescence'
        self.active = self.base / 'active.json'
        self.run = None
        self.intent = None
        self.intent_hash = None

    def require_idle(self):
        # Missing-state inspection never initializes directories or records.
        parent = self.data
        for name in ('backups', 'quiescence'):
            parent = parent / name
            try:
                parent.lstat()
            except FileNotFoundError:
                return
            protected(parent, directory=True)
        try:
            self.active.lstat()
        except FileNotFoundError:
            return
        raise ValueError('Pending backup recovery blocks a fresh checkpoint')

    def begin(self, mode, originals):
        self.require_idle()
        if mode not in {'nightly', 'incremental'} or type(originals) is not dict or len(originals) > MAX_ORIGINALS:
            raise ValueError('Backup recovery intent is invalid')
        copied = {}
        for identifier, value in originals.items():
            hash_field(identifier)
            value = observation(value)
            if value['running'] is not True:
                raise ValueError('Backup originals must be independently running')
            copied[identifier] = value
        for path in (self.data / 'backups', self.base, self.base / 'runs'):
            try:
                protected(path, directory=True)
            except FileNotFoundError:
                mkdir(path)
        count = 0
        with os.scandir(self.base / 'runs') as entries:
            for entry in entries:
                count += 1
                if count >= MAX_HISTORY or not OP.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                    raise ValueError('Backup recovery history needs company review')
        operation = uuid.uuid4().hex
        self.run = self.base / 'runs' / operation
        mkdir(self.run)
        self.intent = dict(schemaVersion=1, operationId=operation, dataRootSha256=self.root_binding,
                           mode=mode, originals=copied, backupVerified=False)
        self.intent_hash = digest(self.intent)
        write_record(self.run / 'intent.json', self.intent)
        write_record(self.active, dict(schemaVersion=1, operationId=operation, intentSha256=self.intent_hash))

    def load(self):
        # All files and schemas are admitted before any recovery command.
        self.require_directories()
        try:
            self.active.lstat()
        except FileNotFoundError:
            return False
        pointer = read_record(self.active, 2048)
        fields(pointer, {'schemaVersion', 'operationId', 'intentSha256'})
        if type(pointer['schemaVersion']) is not int or pointer['schemaVersion'] != 1 or type(pointer['operationId']) is not str or not OP.fullmatch(pointer['operationId']):
            raise ValueError('Backup recovery pointer is invalid')
        hash_field(pointer['intentSha256'])
        self.run = self.base / 'runs' / pointer['operationId']
        protected(self.run, directory=True)
        intent = read_record(self.run / 'intent.json')
        fields(intent, {'schemaVersion', 'operationId', 'dataRootSha256', 'mode', 'originals', 'backupVerified'})
        if type(intent['schemaVersion']) is not int or intent['schemaVersion'] != 1 or intent['operationId'] != pointer['operationId'] or intent['dataRootSha256'] != self.root_binding or intent['mode'] not in {'nightly', 'incremental'} or intent['backupVerified'] is not False:
            raise ValueError('Backup recovery intent does not match this storage')
        if type(intent['originals']) is not dict or len(intent['originals']) > MAX_ORIGINALS:
            raise ValueError('Backup recovery original inventory is invalid')
        for identifier, value in intent['originals'].items():
            hash_field(identifier)
            if observation(value)['running'] is not True:
                raise ValueError('Backup recovery original was not running')
        self.intent, self.intent_hash = intent, digest(intent)
        if self.intent_hash != pointer['intentSha256']:
            raise ValueError('Backup recovery intent hash changed')
        allowed = {'intent.json', 'completed.json', 'checkpoint-failed.json'}
        allowed.update(f'{identifier}-{event}.json' for identifier in intent['originals'] for event in EVENTS)
        with os.scandir(self.run) as entries:
            for index, entry in enumerate(entries):
                if index >= 3 + MAX_ORIGINALS * len(EVENTS) or entry.name not in allowed:
                    raise ValueError('Backup recovery journal membership is invalid')
                protected(Path(entry.path))
                if entry.name != 'intent.json':
                    self.read_event(entry.name)
        for identifier in intent['originals']:
            events = {event: self.read_event(identifier + '-' + event + '.json') for event in EVENTS}
            if ((events['stopped'] and not events['stop-intent']) or
                    (events['start-intent'] and not events['stopped']) or
                    (events['running'] and not events['start-intent'])):
                raise ValueError('Backup recovery event order is invalid')
        return True

    def require_directories(self):
        for path in (self.data / 'backups', self.base):
            try:
                path.lstat()
            except FileNotFoundError:
                return
            protected(path, directory=True)
        protected(self.base / 'runs', directory=True)

    def read_event(self, name):
        try:
            value = read_record(self.run / name, 2048)
        except FileNotFoundError:
            return None
        event = name[:-5]
        expected = {'schemaVersion', 'intentSha256', 'event'}
        if event in {'checkpoint-failed', 'completed'}:
            expected.add('backupVerified')
        else:
            identifier, event = event.rsplit('-', 1) if event.endswith(('stopped', 'running', 'uncertain')) else (event[:64], event[65:])
            expected.add('containerId')
            if event in {'stopped', 'running'}:
                expected.add('stateSha256')
            elif event == 'uncertain':
                expected.add('phase')
        fields(value, expected)
        if type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or value['intentSha256'] != self.intent_hash or value['event'] != event:
            raise ValueError('Backup recovery event binding is invalid')
        if event in {'checkpoint-failed', 'completed'}:
            if value['backupVerified'] is not False:
                raise ValueError('Backup recovery cannot verify a backup')
        else:
            if identifier not in self.intent['originals'] or value['containerId'] != identifier or event not in EVENTS:
                raise ValueError('Backup recovery event ownership is invalid')
            if event in {'stopped', 'running'}:
                hash_field(value['stateSha256'])
            if event == 'uncertain' and value['phase'] not in {'stop', 'resume', 'observation'}:
                raise ValueError('Backup recovery phase is invalid')
        return value

    def record(self, event, identifier=None, state=None, phase=None):
        self.confirm_binding()
        value = dict(schemaVersion=1, intentSha256=self.intent_hash, event=event)
        name = event
        if identifier is None:
            if event not in {'checkpoint-failed', 'completed'}:
                raise ValueError('Backup recovery event is invalid')
            value['backupVerified'] = False
        else:
            if identifier not in self.intent['originals'] or event not in EVENTS:
                raise ValueError('Backup recovery event is invalid')
            name = identifier + '-' + event
            value['containerId'] = identifier
            if event in {'stopped', 'running'}:
                hash_field(state); value['stateSha256'] = state
            if event == 'uncertain':
                if phase not in {'stop', 'resume', 'observation'}:
                    raise ValueError('Backup recovery phase is invalid')
                value['phase'] = phase
        write_record(self.run / (name + '.json'), value)

    def confirm_binding(self):
        root = BackupJournal(self.data)
        if root.root_binding != self.root_binding:
            raise ValueError('Backup recovery data root changed')
        protected(self.run, directory=True)
        pointer = read_record(self.active, 2048)
        if canonical(pointer) != canonical(dict(schemaVersion=1, operationId=self.intent['operationId'], intentSha256=self.intent_hash)) or canonical(read_record(self.run / 'intent.json')) != canonical(self.intent):
            raise ValueError('Backup recovery intent or active pointer changed')

    def uncertain(self, identifier, phase):
        if self.read_event(identifier + '-uncertain.json') is None:
            self.record('uncertain', identifier, phase=phase)

    def failure(self):
        if self.read_event('checkpoint-failed.json') is None:
            self.record('checkpoint-failed')

    def finish(self):
        self.confirm_binding()
        if self.read_event('completed.json') is None:
            self.record('completed')
        pointer = read_record(self.active, 2048)
        if canonical(pointer) != canonical(dict(schemaVersion=1, operationId=self.intent['operationId'], intentSha256=self.intent_hash)):
            raise ValueError('Backup recovery active pointer changed')
        self.active.unlink()
        sync_directory(self.base)


def reconcile(data, observe, start=None):
    """Read-only when start=None; otherwise once-resume only confirmed originals."""
    journal = BackupJournal(data)
    if not journal.load():
        return dict(status='no_pending_recovery', backupVerified=False, startsDispatched=0, originals={})
    results, expected, starts = {}, {}, 0
    for identifier, original in journal.intent['originals'].items():
        try:
            current = observation(observe(identifier))
            if current['profileSha256'] != original['profileSha256']:
                raise ValueError('Original checkpoint process changed')
            stopped = journal.read_event(identifier + '-stopped.json')
            started = journal.read_event(identifier + '-start-intent.json')
            running = journal.read_event(identifier + '-running.json')
            stopping = journal.read_event(identifier + '-stop-intent.json')
            uncertain = journal.read_event(identifier + '-uncertain.json')
            if uncertain or (stopping and not stopped) or (started and not running):
                results[identifier] = 'uncertain'
                continue
            if not stopping:
                if stopped or started or running or not current['running'] or current['stateSha256'] != original['stateSha256']:
                    raise ValueError('Untouched original state changed')
                expected[identifier] = current
                results[identifier] = 'original_running'
            elif running:
                if not started or not current['running'] or current['stateSha256'] != running['stateSha256']:
                    raise ValueError('Resumed original state changed')
                expected[identifier] = current
                results[identifier] = 'original_running'
            else:
                if not current['cleanStopped'] or current['stateSha256'] != stopped['stateSha256']:
                    raise ValueError('Confirmed stopped original state changed')
                results[identifier] = 'confirmed_stopped'
                expected[identifier] = current
                if start is not None:
                    # Reobserve immediately before recording permission for a
                    # single exact-ID start. Never retry an incomplete intent.
                    if canonical(observation(observe(identifier))) != canonical(current):
                        raise ValueError('Original changed before resumption')
                    journal.record('start-intent', identifier)
                    starts += 1
                    start(identifier)
                    resumed = observation(observe(identifier))
                    if resumed['profileSha256'] != original['profileSha256'] or resumed['running'] is not True:
                        raise ValueError('Original restart is unconfirmed')
                    journal.record('running', identifier, state=resumed['stateSha256'])
                    expected[identifier] = resumed
                    results[identifier] = 'original_running'
        except Exception:
            results[identifier] = 'uncertain'
            if start is not None:
                try:
                    journal.uncertain(identifier, 'resume')
                except Exception:
                    pass  # Incomplete durable start intent remains the fence.
    # Every final observation runs, even after an earlier failure. Untouched
    # originals also have to retain their exact initial lifecycle state.
    for identifier in journal.intent['originals']:
        try:
            final = observation(observe(identifier))
            if identifier not in expected or canonical(final) != canonical(expected[identifier]):
                results[identifier] = 'uncertain'
                if identifier in expected and start is not None:
                    journal.uncertain(identifier, 'observation')
        except Exception:
            results[identifier] = 'uncertain'
            if start is not None:
                try:
                    journal.uncertain(identifier, 'observation')
                except Exception:
                    pass
    journal.confirm_binding()
    resolved = all(value == 'original_running' for value in results.values())
    if resolved and start is not None:
        journal.finish()
    return dict(status='originals_resumed_backup_unverified' if resolved and start is not None else 'pending_company_review',
                backupVerified=False, operationId=journal.intent['operationId'], mode=journal.intent['mode'],
                startsDispatched=starts, originals=results)
