"""Protected combined recovery cursor/index; no global writer readiness claim.

Initialization is an explicit company/root action after encrypted-mount proof.
Partial operations are retained and deny later capture; this module never repairs
or adopts legacy metadata. Filesystem IO is not bounded by the lock wait deadline.
"""
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

import checkpoint_admission as C
from recovery_chain import (CHECKPOINT_ID, binlog_number, checkpoint_time,
                            contiguous_logs, inventory, manifest_hash,
                            protected_recovery_bases, validate_chain)

SCOPE = 'RECOVERY_CATALOG_ONLY'
MAX_RECORD = 8 * 1024**2
MAX_HISTORY_BYTES = 512 * 1024**2
MAX_GENERATIONS = 4096
MAX_ARCHIVES = 4096
MAX_DOCUMENTS = 50000
MAX_ARCHIVE_BYTES = 256 * 1024**3
MAX_NEW_COMMIT_BYTES = 3 * MAX_RECORD  # generation, intent and confirmation


def copy(value):
    return json.loads(C.canonical(value))


def checkpoint(value):
    C.require(type(value) is str and CHECKPOINT_ID.fullmatch(value) is not None)
    return value


def utc(value):
    C.require(type(value) is str and value.endswith('Z'))
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    C.require(parsed.utcoffset().total_seconds() == 0)
    return parsed


def archive_pin(value):
    C.fields(value, {'sha256', 'bytes', 'identity'})
    C.hash_value(value['sha256'])
    C.require(type(value['bytes']) is int and 0 < value['bytes'] <= MAX_ARCHIVE_BYTES)
    C.require(type(value['identity']) is list and len(value['identity']) == 9
              and all(type(n) is str and re.fullmatch(r'-?[0-9]+', n) for n in value['identity']))
    C.require(int(value['identity'][6]) == value['bytes'])
    return value


class NativeFiles(C.NativeFiles):
    def open_directory(self, path):
        before = self.protected(path, directory=True, private=True)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.compare_opened(before, self.descriptor(fd))
            return fd, C.directory_binding(before)
        except BaseException:
            os.close(fd)
            raise

    def check_directory(self, path, fd, binding):
        C.require(C.directory_binding(self.protected(path, directory=True, private=True))
                  == C.directory_binding(self.descriptor(fd)) == binding,
                  'Held catalog directory was replaced')

    def read_record(self, path):
        before = self.protected(path, private=True)
        C.require(0 < before.st_size <= MAX_RECORD)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
        try:
            opened = self.descriptor(fd); self.compare_opened(before, opened)
            raw = bytearray()
            while block := os.read(fd, 65536):
                raw.extend(block); C.require(len(raw) <= MAX_RECORD)
            C.require(C.identity(self.descriptor(fd)) == C.identity(opened)
                      and len(raw) == before.st_size)
        finally:
            os.close(fd)
        C.require(C.identity(self.protected(path, private=True)) == C.identity(before))

        def pairs(rows):
            result = {}
            for key, value in rows:
                C.require(key not in result); result[key] = value
            return result
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                           parse_constant=lambda _: C.require(False))
        C.require(type(value) is dict)
        return value

    def write_record(self, path, value):
        self.protected(path.parent, directory=True, private=True)
        raw = C.canonical(value) + b'\n'; C.require(len(raw) <= MAX_RECORD)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                     | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0), 0o600)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:offset + 65536])
                C.require(type(count) is int and 0 < count <= len(raw) - offset); offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        self.sync_directory(path.parent)
        C.require(C.canonical(self.read_record(path)) == C.canonical(value))

    def publish_pointer(self, path, expected, value):
        """Replace only the exact previous pointer while retaining its read FD."""
        before = self.protected(path, private=True)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
        temporary = path.parent / ('pointer-' + uuid.uuid4().hex + '.pending')
        try:
            opened = self.descriptor(fd); self.compare_opened(before, opened)
            C.require(C.canonical(self.read_record(path)) == C.canonical(expected))
            self.write_record(temporary, value)
            C.require(C.identity(self.protected(path, private=True)) == C.identity(before)
                      and C.identity(self.descriptor(fd)) == C.identity(opened))
            os.replace(temporary, path)
            self.sync_directory(path.parent)
            # Replacing the sole pathname intentionally drops the OLD inode's
            # link count and changes ctime; its original identity/contents must
            # remain bound, while the NEW pathname receives complete readback.
            held = self.descriptor(fd)
            C.require(C.canonical(self.read_record(path)) == C.canonical(value)
                      and all(getattr(held, key) == getattr(opened, key) for key in
                              ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns'))
                      and held.st_nlink == 0)
        finally:
            os.close(fd)

    def encrypted_archive(self, path):
        """Stream and fsync an ordinary immutable encrypted output, never decrypt."""
        before = self.protected(path, private=True)
        C.require(0 < before.st_size <= MAX_ARCHIVE_BYTES)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
        try:
            opened = self.descriptor(fd); self.compare_opened(before, opened)
            hashed = hashlib.sha256(); size = 0
            while block := os.read(fd, 1024**2):
                size += len(block); C.require(size <= MAX_ARCHIVE_BYTES); hashed.update(block)
            self.sync_archive(fd)
            C.require(size == before.st_size and C.identity(self.descriptor(fd)) == C.identity(opened))
        finally:
            os.close(fd)
        self.sync_directory(path.parent)
        C.require(C.identity(self.protected(path, private=True)) == C.identity(before))
        return dict(sha256=hashed.hexdigest(), bytes=size,
                    identity=[str(n) for n in C.identity(before)])

    def sync_archive(self, fd):
        os.fsync(fd)

    def remove_archive(self, path, expected):
        """Exact protected file only; failure is not a retry authorization."""
        C.require(self.encrypted_archive(path) == expected)
        before = self.protected(path, private=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.compare_opened(before, self.descriptor(fd))
            C.require([str(n) for n in C.identity(self.protected(path, private=True))] == expected['identity'])
            path.unlink()
            self.sync_directory(path.parent)
            C.require(not os.path.lexists(path))
        finally:
            os.close(fd)


class RecoveryCatalog:
    def __init__(self, data, installation_id, *, files=None, locks=None,
                 clock=time.monotonic, sleep=time.sleep):
        C.require(type(installation_id) is str and str(uuid.UUID(installation_id)) == installation_id)
        self.data, self.installation_id = Path(data), installation_id
        self.files, self.locks = files or NativeFiles(), locks or C.NativeLocks()
        self.clock, self.sleep = clock, sleep
        self.root_hash = self.files.root(self.data)
        self.device = self.files.protected(self.data, directory=True).st_dev
        self.base = self.data / 'backups/recovery-catalog'

    def _paths(self):
        return dict(backups=self.data / 'backups', base=self.base,
                    generations=self.base / 'generations', operations=self.base / 'operations',
                    checkpoints=self.data / 'backups/checkpoints', incrementals=self.data / 'backups/incrementals')

    def _legacy(self):
        C.require(not any(os.path.lexists(self.data / 'backups' / name)
                          for name in ('binlog-cursor.json', 'recovery-index.json')),
                  'Legacy recovery metadata is retained; explicit company migration is required')

    def _placement(self, initial=None, anchors=()):
        C.require(self.files.root(self.data) == self.root_hash)
        self._legacy()
        for name, path in self._paths().items():
            info = self.files.protected(path, directory=True, private=True)
            C.require(info.st_dev == self.device, 'Catalog and archives must stay on the validated encrypted filesystem')
            if initial is not None:
                C.require(C.directory_binding(info) == initial['directories'][name])
        for name, fd, binding in anchors:
            self.files.check_directory(self._paths()[name], fd, binding)

    def _pointer(self, generation):
        return dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.root_hash,
                    installationId=self.installation_id, sequence=generation['sequence'],
                    generationSha256=C.digest(generation))

    def initialize(self):
        """Explicit fresh-only setup, never called by backup/acquire."""
        self.files.require_root(); self._legacy()
        C.require(not os.path.lexists(self.base), 'Partial/existing catalog is never reinitialized')
        backups = self.data / 'backups'
        C.require(self.files.protected(backups, directory=True, private=True).st_dev == self.device)
        C.require(set(self.files.inventory(backups, 2)) <= {'checkpoints', 'incrementals'},
                  'Existing backup evidence requires company migration')
        for name in ('checkpoints', 'incrementals'):
            path = backups / name
            if os.path.lexists(path):
                self.files.protected(path, directory=True, private=True)
                C.require(self.files.inventory(path, 0) == [], 'Existing archives will not be adopted')
            else:
                self.files.mkdir(path)
        self.files.mkdir(self.base)
        for name in ('generations', 'operations'): self.files.mkdir(self.base / name)
        self.files.create_lock(self.base / 'catalog.lock')
        self._placement()
        initial = dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.root_hash,
                       installationId=self.installation_id,
                       directories={name: C.directory_binding(self.files.protected(path, directory=True, private=True))
                                    for name, path in self._paths().items()},
                       lock=C.lock_binding(self.files.protected(self.base / 'catalog.lock', private=True)))
        self.files.write_record(self.base / 'initialization.json', initial)
        generation = dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.root_hash,
                          installationId=self.installation_id, sequence=0,
                          previousGenerationSha256=None, intentSha256=None, boundary=None,
                          cursor=None, archives={})
        self.files.write_record(self.base / 'generations/0000000000.json', generation)
        self.files.write_record(self.base / 'current.json', self._pointer(generation))
        self.files.write_record(self.base / 'initialized.json', dict(initializationSha256=C.digest(initial)))

    def _schema(self, value):
        C.require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
                  and value['scope'] == SCOPE and value['dataRootSha256'] == self.root_hash
                  and value['installationId'] == self.installation_id)

    def _archive_path(self, identifier, item):
        checkpoint(identifier)
        C.require(item['filename'] == identifier + '.tar.gpg' and item['kind'] in {'nightly', 'incremental'})
        return self._paths()['checkpoints' if item['kind'] == 'nightly' else 'incrementals'] / item['filename']

    def _projection(self, generation):
        C.fields(generation, {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'sequence',
                              'previousGenerationSha256', 'intentSha256', 'boundary', 'cursor', 'archives'})
        self._schema(generation)
        C.require(type(generation['sequence']) is int and 0 <= generation['sequence'] <= MAX_GENERATIONS)
        archives = generation['archives']
        C.require(type(archives) is dict and len(archives) <= MAX_ARCHIVES)
        for identifier, item in archives.items():
            checkpoint(identifier)
            C.fields(item, {'kind', 'filename', 'createdAt', 'manifestHash', 'baseCheckpointId', 'baseManifestHash',
                            'previousCheckpointId', 'previousManifestHash', 'lastFile', 'documentsSha256', 'archive'})
            self._archive_path(identifier, item); utc(item['createdAt']); binlog_number(item['lastFile'])
            for name in ('manifestHash', 'baseManifestHash', 'documentsSha256'): C.hash_value(item[name])
            checkpoint(item['baseCheckpointId']); archive_pin(item['archive'])
            base = archives.get(item['baseCheckpointId'])
            C.require(base is not None and base['kind'] == 'nightly'
                      and base['manifestHash'] == item['baseManifestHash'])
            if item['kind'] == 'nightly':
                C.require(item['baseCheckpointId'] == identifier and item['baseManifestHash'] == item['manifestHash']
                          and item['previousCheckpointId'] is None and item['previousManifestHash'] is None)
            else:
                checkpoint(item['previousCheckpointId']); C.hash_value(item['previousManifestHash'])
                previous = archives.get(item['previousCheckpointId'])
                C.require(previous is not None and previous['manifestHash'] == item['previousManifestHash']
                          and previous['baseCheckpointId'] == item['baseCheckpointId']
                          and utc(previous['createdAt']) <= utc(item['createdAt'])
                          and binlog_number(previous['lastFile']) <= binlog_number(item['lastFile']))
        # Walk each parent chain with a finite bound: equal-time cycles cannot hide.
        for identifier in archives:
            seen = set(); current = identifier
            while current is not None:
                C.require(current not in seen and len(seen) < MAX_ARCHIVES)
                seen.add(current); current = archives[current]['previousCheckpointId']
        cursor = generation['cursor']
        if not archives:
            C.require(cursor is None)
        else:
            C.fields(cursor, {'baseCheckpointId', 'baseManifestHash', 'lastFile', 'checkpointId',
                              'manifestHash', 'documents', 'completedAt'})
            checkpoint(cursor['checkpointId']); utc(cursor['completedAt'])
            C.require(type(cursor['documents']) is dict and len(cursor['documents']) <= MAX_DOCUMENTS)
            inventory(cursor['documents'], documents=True)
            item = archives.get(cursor['checkpointId']); C.require(item is not None)
            C.require(cursor['baseCheckpointId'] == item['baseCheckpointId'] and cursor['baseManifestHash'] == item['baseManifestHash']
                      and cursor['manifestHash'] == item['manifestHash'] and cursor['lastFile'] == item['lastFile']
                      and C.digest(cursor['documents']) == item['documentsSha256'])

    def _archive_inventory(self, generation, extra=None):
        expected = {'checkpoints': set(), 'incrementals': set()}
        for identifier, item in generation['archives'].items():
            path = self._archive_path(identifier, item)
            observed = self.files.protected(path, private=True)
            C.require(observed.st_dev == self.device and [str(n) for n in C.identity(observed)] == item['archive']['identity'],
                      'Referenced encrypted archive changed or is missing')
            expected['checkpoints' if item['kind'] == 'nightly' else 'incrementals'].add(path.name)
        if extra is not None:
            expected['checkpoints' if extra['kind'] == 'nightly' else 'incrementals'].add(extra['checkpointId'] + '.tar.gpg')
        for name in expected:
            C.require(set(self.files.inventory(self._paths()[name], MAX_ARCHIVES + 1)) == expected[name],
                      'Unknown/partial encrypted archives require company review')

    def _state(self, fd, expected, anchors):
        self.files.check_lock(self.base / 'catalog.lock', fd, expected)
        C.require(set(self.files.inventory(self.base, 6)) ==
                  {'catalog.lock', 'initialization.json', 'initialized.json', 'current.json', 'generations', 'operations'})
        initial = C.fields(self.files.read_record(self.base / 'initialization.json'),
                           {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'directories', 'lock'})
        self._schema(initial); C.fields(initial['directories'], set(self._paths()))
        self._placement(initial, anchors)
        C.require(initial['lock'] == C.lock_binding(self.files.descriptor(fd))
                  == C.lock_binding(self.files.protected(self.base / 'catalog.lock', private=True)))
        C.require(self.files.read_record(self.base / 'initialized.json') == {'initializationSha256': C.digest(initial)})
        pointer = C.fields(self.files.read_record(self.base / 'current.json'),
                           {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'sequence', 'generationSha256'})
        self._schema(pointer); C.hash_value(pointer['generationSha256'])
        count = pointer['sequence']; C.require(type(count) is int and 0 <= count <= MAX_GENERATIONS)
        C.require(set(self.files.inventory(self.base / 'generations', MAX_GENERATIONS + 1)) ==
                  {f'{n:010d}.json' for n in range(count + 1)}, 'Partial generation requires company review')
        C.require(set(self.files.inventory(self.base / 'operations', MAX_GENERATIONS)) ==
                  {f'{n:010d}' for n in range(1, count + 1)}, 'Unresolved capture/commit is retained')
        previous = None; total = 0
        for sequence in range(count + 1):
            path = self.base / 'generations' / f'{sequence:010d}.json'
            total += self.files.protected(path, private=True).st_size
            C.require(total <= MAX_HISTORY_BYTES, 'Catalog retained-history capacity requires company maintenance')
            generation = self.files.read_record(path); self._projection(generation)
            C.require(generation['sequence'] == sequence)
            if previous is None:
                C.require(generation['cursor'] is None and generation['archives'] == {}
                          and generation['previousGenerationSha256'] is None
                          and generation['intentSha256'] is None and generation['boundary'] is None)
            else:
                operation = self.base / 'operations' / f'{sequence:010d}'
                C.require(set(self.files.inventory(operation, 2)) == {'intent.json', 'confirmed.json'})
                total += sum(self.files.protected(operation / name, private=True).st_size
                             for name in ('intent.json', 'confirmed.json'))
                C.require(total <= MAX_HISTORY_BYTES, 'Catalog retained-history capacity requires company maintenance')
                intent = self.files.read_record(operation / 'intent.json')
                self._intent(intent, sequence, self._pointer(previous))
                C.require(intent['operationDirectory'] == C.directory_binding(
                    self.files.protected(operation, directory=True, private=True)))
                C.require(generation['previousGenerationSha256'] == C.digest(previous)
                          and generation['intentSha256'] == C.digest(intent))
                self._transition(previous, generation, intent)
                C.require(self.files.read_record(operation / 'confirmed.json') ==
                          dict(intentSha256=C.digest(intent), generationSha256=C.digest(generation),
                               pointerSha256=C.digest(self._pointer(generation))))
            previous = generation
        C.require(self._pointer(previous) == pointer)
        self._archive_inventory(previous)
        self._placement(initial, anchors); self.files.check_lock(self.base / 'catalog.lock', fd, expected)
        return initial, pointer, previous

    def _intent(self, intent, sequence, previous):
        C.fields(intent, {'schemaVersion', 'scope', 'dataRootSha256', 'installationId', 'sequence',
                          'previousPointerSha256', 'operationDirectory', 'request'})
        self._schema(intent)
        C.require(type(intent['sequence']) is int and intent['sequence'] == sequence
                  and intent['previousPointerSha256'] == C.digest(previous))
        C.fields(intent['operationDirectory'], {'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'})
        C.require(all(type(n) is str and re.fullmatch(r'-?[0-9]+', n)
                      for n in intent['operationDirectory'].values()))
        request = C.fields(intent['request'], {'kind', 'checkpointId', 'cutoff', 'removed'})
        C.require(request['kind'] in {'nightly', 'incremental', 'prune'})
        if request['kind'] == 'prune':
            C.require(request['checkpointId'] is None); utc(request['cutoff'])
            C.require(type(request['removed']) is list and request['removed'] == sorted(set(request['removed'])))
            for identifier in request['removed']: checkpoint(identifier)
        else:
            checkpoint(request['checkpointId'])
            C.require(request['cutoff'] is None and request['removed'] == [])

    def _transition(self, previous, generation, intent):
        request = intent['request']; old, new = previous['archives'], generation['archives']
        if request['kind'] == 'prune':
            protected = protected_recovery_bases(old, utc(request['cutoff']), previous['cursor']['baseCheckpointId'] if previous['cursor'] else None)
            removed = request['removed']; C.require(set(removed) <= set(old))
            C.require(all(old[name]['baseCheckpointId'] not in protected for name in removed))
            C.require(new == {name: item for name, item in old.items() if name not in removed}
                      and generation['cursor'] == previous['cursor'] and generation['boundary'] is None)
        else:
            identifier = request['checkpointId']; C.require(identifier not in old and set(new) == set(old) | {identifier})
            C.require(all(new[name] == item for name, item in old.items()) and new[identifier]['kind'] == request['kind'])
            C.require(generation['cursor']['checkpointId'] == identifier)
            self._boundary(generation['boundary'], request['kind'])
            if request['kind'] == 'incremental':
                cursor = previous['cursor']; C.require(cursor is not None)
                C.require(new[identifier]['previousCheckpointId'] == cursor['checkpointId']
                          and new[identifier]['previousManifestHash'] == cursor['manifestHash']
                          and new[identifier]['baseCheckpointId'] == cursor['baseCheckpointId'])

    def _boundary(self, value, mode):
        C.fields(value, {'scope', 'mode', 'originals', 'journalIntentSha256', 'globalWritersQuiesced'})
        C.require(value['scope'] == 'ORIGINAL_CONTAINER_BOUNDARY_ONLY' and value['mode'] == mode
                  and type(value['globalWritersQuiesced']) is bool and value['globalWritersQuiesced'] is False)
        C.hash_value(value['journalIntentSha256'])
        C.require(type(value['originals']) is dict and len(value['originals']) <= 256)
        for identifier, hashes in value['originals'].items():
            C.require(type(identifier) is str and re.fullmatch('[a-f0-9]{64}', identifier))
            C.fields(hashes, {'profileSha256', 'stateSha256'})
            C.hash_value(hashes['profileSha256']); C.hash_value(hashes['stateSha256'])

    @contextmanager
    def acquire(self, timeout=10):
        C.require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 30)
        self.files.require_root(); fd = None; acquired = False; anchors = []; lease = None
        try:
            for name, path in self._paths().items():
                handle, binding = self.files.open_directory(path); anchors.append((name, handle, binding))
            fd, expected = self.files.open_lock(self.base / 'catalog.lock')
            deadline = self.clock() + timeout
            while True:
                self.files.check_lock(self.base / 'catalog.lock', fd, expected)
                if self.locks.try_acquire(fd, False): acquired = True; break
                C.require(self.clock() < deadline, 'Catalog lock wait expired; no state reset')
                self.sleep(min(.01, max(0, deadline - self.clock())))
            initial, pointer, generation = self._state(fd, expected, anchors)
            lease = CatalogLease(self, fd, expected, anchors, initial, pointer, generation)
            yield lease
            self._state(fd, expected, anchors)
        finally:
            if lease is not None: lease.live = False
            failures = []
            if acquired:
                try: self.locks.release(fd)
                except BaseException as error: failures.append(error)
            handles = ([fd] if fd is not None else []) + [handle for _, handle, _ in reversed(anchors)]
            if lease is not None and lease.operation_anchor is not None:
                handles.append(lease.operation_anchor[1])
            for handle in handles:
                try: self.files.close_lock(handle)
                except BaseException as error: failures.append(error)
            if failures: raise C.AdmissionUnavailable('Catalog descriptor release is unconfirmed') from failures[0]


class CatalogLease:
    """One live, nonconcurrent original process/thread owns the EX scope."""
    def __init__(self, catalog, fd, expected, anchors, initial, pointer, generation):
        self.catalog, self.fd, self.expected, self.anchors = catalog, fd, expected, anchors
        self.initial, self.pointer, self.generation = initial, pointer, generation
        self.live = True; self.owner = (os.getpid(), threading.get_ident()); self.intent = None
        self.operation_anchor = None

    def _guard(self):
        C.require(self.live and self.owner == (os.getpid(), threading.get_ident()))
        catalog = self.catalog
        catalog._placement(self.initial, self.anchors)
        catalog.files.check_lock(catalog.base / 'catalog.lock', self.fd, self.expected)
        if self.operation_anchor is not None:
            catalog.files.check_directory(*self.operation_anchor)
        C.require(C.canonical(catalog.files.read_record(catalog.base / 'current.json')) == C.canonical(self.pointer))

    def read(self):
        self._guard(); C.require(self.intent is None)
        _, pointer, generation = self.catalog._state(self.fd, self.expected, self.anchors)
        C.require(pointer == self.pointer and generation == self.generation)
        return copy(generation)

    def _begin(self, request):
        self.read(); catalog = self.catalog
        C.require(self.operation_anchor is None, 'Exactly one mutation is admitted per catalog lease')
        C.require(self.pointer['sequence'] < MAX_GENERATIONS,
                  'Finite catalog generation capacity requires company maintenance before capture')
        total = sum(catalog.files.protected(catalog.base / 'generations' / f'{n:010d}.json', private=True).st_size
                    for n in range(self.pointer['sequence'] + 1))
        total += sum(catalog.files.protected(catalog.base / 'operations' / f'{n:010d}' / name, private=True).st_size
                     for n in range(1, self.pointer['sequence'] + 1) for name in ('intent.json', 'confirmed.json'))
        C.require(total + MAX_NEW_COMMIT_BYTES <= MAX_HISTORY_BYTES,
                  'Finite retained-history capacity cannot reserve a complete commit; company maintenance is required before capture')
        C.require(len(self.generation['archives']) < MAX_ARCHIVES or request['kind'] == 'prune',
                  'Finite archive-index capacity requires company maintenance before capture')
        sequence = self.pointer['sequence'] + 1
        operation = catalog.base / 'operations' / f'{sequence:010d}'
        catalog.files.mkdir(operation)  # Even failure before intent publication is retained.
        handle, binding = catalog.files.open_directory(operation)
        self.operation_anchor = (operation, handle, binding)
        intent = dict(schemaVersion=1, scope=SCOPE, dataRootSha256=catalog.root_hash,
                      installationId=catalog.installation_id, sequence=sequence,
                      previousPointerSha256=C.digest(self.pointer), operationDirectory=binding, request=copy(request))
        catalog._intent(intent, sequence, self.pointer)
        catalog.files.write_record(operation / 'intent.json', intent)
        self.intent = intent
        self._guard()
        return C.digest(intent)

    def begin_capture(self, identifier, mode):
        checkpoint(identifier); C.require(mode in ('nightly', 'incremental'))
        if mode == 'incremental': C.require(self.read()['cursor'] is not None, 'An anchored nightly catalog is required')
        return self._begin(dict(kind=mode, checkpointId=identifier, cutoff=None, removed=[]))

    def _proposal(self, cursor, archives, boundary):
        return dict(schemaVersion=1, scope=SCOPE, dataRootSha256=self.catalog.root_hash,
                    installationId=self.catalog.installation_id, sequence=self.intent['sequence'],
                    previousGenerationSha256=C.digest(self.generation), intentSha256=C.digest(self.intent),
                    boundary=copy(boundary), cursor=copy(cursor), archives=copy(archives))

    def _publish(self, proposed):
        self._guard(); catalog = self.catalog
        operation = catalog.base / 'operations' / f'{self.intent["sequence"]:010d}'
        C.require(set(catalog.files.inventory(operation, 1)) == {'intent.json'})
        C.require(catalog.files.read_record(operation / 'intent.json') == self.intent)
        catalog._projection(proposed); catalog._transition(self.generation, proposed, self.intent)
        catalog.files.write_record(catalog.base / 'generations' / f'{proposed["sequence"]:010d}.json', proposed)
        pointer = catalog._pointer(proposed)
        self._guard(); catalog.files.publish_pointer(catalog.base / 'current.json', self.pointer, pointer)
        self.pointer = pointer
        self._guard()
        return operation

    def _confirm(self, operation, proposed):
        catalog = self.catalog
        self._guard()
        catalog.files.write_record(operation / 'confirmed.json',
                                   dict(intentSha256=C.digest(self.intent), generationSha256=C.digest(proposed),
                                        pointerSha256=C.digest(self.pointer)))
        self.generation = proposed; self.intent = None
        self._guard(); catalog._state(self.fd, self.expected, self.anchors)

    def commit_capture(self, target, manifest, cursor, boundary):
        """Caller still holds its original-container boundary; exit is not evidence."""
        self._guard(); catalog = self.catalog
        C.require(self.intent is not None and self.intent['request']['kind'] in ('nightly', 'incremental'))
        manifest, cursor, boundary = copy(manifest), copy(cursor), copy(boundary)
        identifier = self.intent['request']['checkpointId']; mode = self.intent['request']['kind']
        C.require(type(manifest.get('schemaVersion')) is int and manifest['schemaVersion'] == 1
                  and manifest.get('checkpointId') == identifier and manifest.get('kind') == mode)
        utc(manifest['createdAt']); inventory(manifest['files'])
        if mode == 'nightly':
            validate_chain(manifest, []); documents = manifest['recoveryBase']['documents']
            last = manifest['recoveryBase']['binlogFile']; base_id, base_hash = identifier, manifest_hash(manifest)
            previous_id = previous_hash = None
        else:
            previous = self.generation['cursor']; C.require(previous is not None)
            C.require(manifest.get('baseCheckpointId') == previous['baseCheckpointId']
                      and manifest.get('baseManifestHash') == previous['baseManifestHash']
                      and manifest.get('previousCheckpointId') == previous['checkpointId']
                      and manifest.get('previousManifestHash') == previous['manifestHash'])
            C.require(utc(manifest['createdAt']) >= utc(self.generation['archives'][previous['checkpointId']]['createdAt']))
            last = contiguous_logs(previous['lastFile'], manifest['closedBinlogs'])
            C.require(manifest['lastClosedBinlog'] == last)
            documents = inventory(manifest['documents'], documents=True)
            C.require(manifest['deletedDocuments'] == sorted(set(previous['documents']) - set(documents)))
            changed = {name: value for name, value in documents.items() if previous['documents'].get(name) != value}
            C.require(changed == {name: value for name, value in manifest['files'].items() if name.startswith('runtime/storage/')})
            C.require({name for name in manifest['files'] if name.startswith('mysql/')} == {'mysql/' + name for name in manifest['closedBinlogs']})
            C.require(all(name.startswith(('runtime/storage/', 'mysql-keyring/')) or name == 'quota/projects.json'
                          or name in {'mysql/' + log for log in manifest['closedBinlogs']} for name in manifest['files']))
            base_id, base_hash = previous['baseCheckpointId'], previous['baseManifestHash']
            previous_id, previous_hash = previous['checkpointId'], previous['manifestHash']
        C.require(type(documents) is dict and len(documents) <= MAX_DOCUMENTS)
        expected_cursor = dict(baseCheckpointId=base_id, baseManifestHash=base_hash, lastFile=last,
                               checkpointId=identifier, manifestHash=manifest_hash(manifest), documents=documents,
                               completedAt=cursor.get('completedAt'))
        utc(expected_cursor['completedAt']); C.require(C.canonical(cursor) == C.canonical(expected_cursor))
        catalog._boundary(boundary, mode)
        target = Path(target); expected_target = catalog._paths()['checkpoints' if mode == 'nightly' else 'incrementals'] / (identifier + '.tar.gpg')
        C.require(target == expected_target)
        catalog._archive_inventory(self.generation, dict(kind=mode, checkpointId=identifier))
        pin = catalog.files.encrypted_archive(target)
        self._guard()
        archives = copy(self.generation['archives'])
        archives[identifier] = dict(kind=mode, filename=target.name, createdAt=manifest['createdAt'],
                                    manifestHash=manifest_hash(manifest), baseCheckpointId=base_id,
                                    baseManifestHash=base_hash, previousCheckpointId=previous_id,
                                    previousManifestHash=previous_hash, lastFile=last,
                                    documentsSha256=C.digest(documents), archive=pin)
        proposed = self._proposal(cursor, archives, boundary)
        operation = self._publish(proposed)
        C.require(catalog.files.encrypted_archive(target) == pin)
        self._confirm(operation, proposed)
        return dict(scope=SCOPE, checkpointId=identifier, generationSha256=C.digest(proposed),
                    archiveSha256=pin['sha256'], cursorAndIndexCommitted=True, globalWritersQuiesced=False, backupReady=False)

    def prune(self, cutoff):
        state = self.read(); catalog = self.catalog
        cutoff_text = cutoff.isoformat().replace('+00:00', 'Z'); utc(cutoff_text)
        current = state['cursor']['baseCheckpointId'] if state['cursor'] else None
        protected = protected_recovery_bases(state['archives'], cutoff, current)
        removed = sorted(name for name, item in state['archives'].items() if item['baseCheckpointId'] not in protected)
        if not removed: return []
        # Verify all originals before the durable pruning intent or pointer effect.
        for name in removed:
            item = state['archives'][name]
            C.require(catalog.files.encrypted_archive(catalog._archive_path(name, item)) == item['archive'])
        self._begin(dict(kind='prune', checkpointId=None, cutoff=cutoff_text, removed=removed))
        proposed = self._proposal(state['cursor'], {name: item for name, item in state['archives'].items() if name not in removed}, None)
        operation = self._publish(proposed)  # Current projection never references a file being removed.
        for name in removed:
            self._guard(); item = state['archives'][name]
            catalog.files.remove_archive(catalog._archive_path(name, item), item['archive'])
        self._confirm(operation, proposed)
        return removed
