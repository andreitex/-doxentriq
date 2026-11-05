"""Retained synthetic/injected recovery catalog controls, never real backups.

Linux directory FDs, root policy/flock, read-only-fd fsync and pointer replacement
are injected on Windows. Real bounded fixture reads, writes and writable file
fsync remain. Maintenance relative inventory names use POSIX normalization only
in the Windows source fixture; original product method bytes remain unchanged.
No native command, container operation, decrypt or actual backup deletion occurs.
"""
import ast
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import recovery_catalog as R
from backup_quiescence import QuiescedContainers
import backup_recovery

spec = importlib.util.spec_from_file_location('recovery_catalog_fixture', ROOT / 'test/test_checkpoint_admission.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
INSTALLATION = '64a2a5f8-04b9-43b5-9807-122d866db1f1'
DOC = 'runtime/storage/d9224505-f564-44e5-a697-16e1451fc44a/documents/file.txt'
STAMP = '2026-10-13T00:00:00Z'


class Files(B.Files, R.NativeFiles):
    def __init__(self):
        super().__init__(); self.directories = {}; self.next_directory = 20000
        self.on_archive = None; self.removed = []

    def open_directory(self, path):
        held = self.protected(path, directory=True, private=True)
        self.next_directory += 1; fd = self.next_directory
        self.directories[fd] = (Path(path), held)
        self.events.append(('directory-open', str(path)))
        return fd, R.C.directory_binding(held)

    def descriptor(self, fd):
        if fd in self.directories: return self.directories[fd][1]
        return super().descriptor(fd)

    def close_lock(self, fd):
        if fd in self.directories:
            self.events.append(('directory-close', str(self.directories.pop(fd)[0])))
            if self.failures.pop('directory-close', None):
                raise OSError('synthetic directory release acknowledgement unavailable')
        else: super().close_lock(fd)

    def check_directory(self, path, fd, binding):
        R.C.require(fd in self.directories)
        return R.NativeFiles.check_directory(self, path, fd, binding)

    def write_record(self, path, value):
        self.events.append(('record', path.name))
        failure = self.failures.pop('write-' + path.name, None)
        if failure == 'before': raise OSError('synthetic record creation unavailable')
        if failure == 'partial':
            with path.open('xb') as handle: handle.write(b'{')
            raise OSError('synthetic retained partial metadata')
        R.NativeFiles.write_record(self, path, value)
        if failure == 'after': raise OSError('synthetic durable record acknowledgement lost')

    def publish_pointer(self, path, expected, value):
        # Windows cannot replace the old pointer while its native read FD is
        # held. Inject that Linux transition only; retain actual exclusive temp,
        # file fsync, atomic replace, exact prior identity and complete readback.
        self.events.append(('pointer', value['sequence']))
        before = R.C.identity(self.protected(path, private=True))
        self.assert_pointer(path, expected)
        pending = path.parent / ('injected-pointer-' + uuid.uuid4().hex + '.pending')
        self.write_record(pending, value)
        failure = self.failures.pop('pointer', None)
        if failure == 'before': raise OSError('synthetic pointer publication unavailable')
        R.C.require(R.C.identity(self.protected(path, private=True)) == before)
        os.replace(pending, path); self.sync_directory(path.parent)
        self.assert_pointer(path, value)
        if failure == 'after': raise OSError('synthetic pointer acknowledgement lost')

    def assert_pointer(self, path, value):
        R.C.require(R.C.canonical(self.read_record(path)) == R.C.canonical(value))

    def encrypted_archive(self, path):
        self.events.append(('archive', path.name))
        failure = self.failures.pop('archive', None)
        if failure == 'before': raise OSError('synthetic archive verification unavailable')
        pin = R.NativeFiles.encrypted_archive(self, path)
        callback, self.on_archive = self.on_archive, None
        if callback: callback(path)
        if failure == 'after': raise OSError('synthetic archive verification acknowledgement lost')
        return pin

    def sync_archive(self, fd):
        # Linux fsync on the held read-only FD is injected on Windows. The
        # synthetic archive writer independently fsyncs its writable FD.
        self.events.append(('archive-readonly-fsync-policy', fd))

    def remove_archive(self, path, expected):
        # Retain synthetic bytes under another fixture directory. Never unlink
        # an archive in these controls or delete any actual/native backup.
        self.events.append(('remove', path.name))
        if self.failures.pop('remove', None): raise OSError('synthetic uncertain archive removal')
        R.C.require(self.encrypted_archive(path) == expected)
        destination = path.parents[2] / 'retained-synthetic-removals'
        destination.mkdir(exist_ok=True); path.rename(destination / path.name)
        self.removed.append(path.name)


class Fixture:
    def __init__(self, initialize=True):
        artifact = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local')))
        assert artifact.is_absolute() and artifact.resolve(strict=True) == artifact and artifact.is_dir()
        self.root = Path(tempfile.mkdtemp(prefix='recovery-catalog-v1-', dir=artifact)).resolve()
        self.data = self.root / 'data'; self.data.mkdir(); (self.data / 'backups').mkdir()
        self.files = Files(); self.clock = B.Clock(); self.locks = B.Locks(self.files)
        self.events = self.files.events; self.locks.events = self.events
        if initialize: self.catalog().initialize()
        self.events.clear()

    def catalog(self):
        return R.RecoveryCatalog(self.data, INSTALLATION, files=self.files, locks=self.locks,
                                 clock=self.clock.time, sleep=self.clock.sleep)

    def boundary(self, mode):
        return dict(scope='ORIGINAL_CONTAINER_BOUNDARY_ONLY', mode=mode,
                    originals={'a' * 64: dict(profileSha256='a' * 64, stateSha256='b' * 64)},
                    journalIntentSha256='c' * 64, globalWritersQuiesced=False)

    def manifest(self, identifier='20261013T000000Z-aaaaaaaa', previous=None, document='d' * 64):
        if previous is None:
            files = {'mysql/mysql-bin.000001': 'e' * 64, DOC: document}
            return dict(schemaVersion=1, kind='nightly', checkpointId=identifier, createdAt=STAMP,
                        files=files, recoveryBase=dict(binlogFile='mysql-bin.000001',
                                                     binlogSha256='e' * 64, documents={DOC: document}))
        number = R.binlog_number(previous['lastFile']) + 1; name = f'mysql-bin.{number:06d}'
        documents = {DOC: document}; changed = {} if previous['documents'] == documents else {DOC: document}
        return dict(schemaVersion=1, kind='incremental', checkpointId=identifier, createdAt=STAMP,
                    baseCheckpointId=previous['baseCheckpointId'], baseManifestHash=previous['baseManifestHash'],
                    previousCheckpointId=previous['checkpointId'], previousManifestHash=previous['manifestHash'],
                    closedBinlogs=[name], lastClosedBinlog=name, files={'mysql/' + name: 'f' * 64, **changed},
                    documents=documents, deletedDocuments=[])

    def cursor(self, manifest):
        base = manifest['kind'] == 'nightly'
        return dict(baseCheckpointId=manifest['checkpointId'] if base else manifest['baseCheckpointId'],
                    baseManifestHash=R.manifest_hash(manifest) if base else manifest['baseManifestHash'],
                    lastFile=manifest['recoveryBase']['binlogFile'] if base else manifest['lastClosedBinlog'],
                    checkpointId=manifest['checkpointId'], manifestHash=R.manifest_hash(manifest),
                    documents=manifest['recoveryBase']['documents'] if base else manifest['documents'], completedAt=STAMP)

    def archive(self, manifest):
        folder = 'checkpoints' if manifest['kind'] == 'nightly' else 'incrementals'
        path = self.data / 'backups' / folder / (manifest['checkpointId'] + '.tar.gpg')
        with path.open('xb') as handle:
            handle.write(b'SYNTHETIC-NOT-AN-ENCRYPTED-BACKUP:' + manifest['checkpointId'].encode())
            handle.flush(); os.fsync(handle.fileno())
        return path

    def commit(self, manifest=None):
        manifest = manifest or self.manifest()
        with self.catalog().acquire() as lease:
            lease.begin_capture(manifest['checkpointId'], manifest['kind'])
            path = self.archive(manifest)
            result = lease.commit_capture(path, manifest, self.cursor(manifest), self.boundary(manifest['kind']))
        return result

    def state(self):
        with self.catalog().acquire() as lease: return lease.read()


class CatalogControls(unittest.TestCase):
    def test_missing_state_never_auto_initializes(self):
        f = Fixture(False)
        with self.assertRaises(FileNotFoundError):
            with f.catalog().acquire(): pass
        self.assertFalse((f.data / 'backups/recovery-catalog').exists())

    def test_explicit_fresh_initialize_refuses_legacy_cursor_or_index_independently(self):
        for name in ('binlog-cursor.json', 'recovery-index.json'):
            f = Fixture(False); path = f.data / 'backups' / name; path.write_bytes(b'legacy-preserved')
            with self.assertRaisesRegex(ValueError, 'migration'): f.catalog().initialize()
            self.assertEqual(path.read_bytes(), b'legacy-preserved')
            self.assertFalse((f.data / 'backups/recovery-catalog').exists())

    def test_initializer_refuses_prior_archive_and_interrupted_initialization(self):
        f = Fixture(False); (f.data / 'backups/checkpoints').mkdir()
        path = f.data / 'backups/checkpoints/20261013T000000Z-aaaaaaaa.tar.gpg'; path.write_bytes(b'unknown')
        with self.assertRaises(ValueError): f.catalog().initialize()
        self.assertEqual(path.read_bytes(), b'unknown')
        f = Fixture(False); f.files.failures['write-initialization.json'] = 'partial'
        with self.assertRaises(OSError): f.catalog().initialize()
        with self.assertRaises(ValueError): f.catalog().initialize()
        self.assertEqual((f.data / 'backups/recovery-catalog/initialization.json').read_bytes(), b'{')

    def test_nightly_and_incremental_commit_one_combined_generation(self):
        f = Fixture(); result = f.commit(); state = f.state()
        self.assertTrue(result['cursorAndIndexCommitted']); self.assertFalse(result['backupReady'])
        self.assertEqual(state['sequence'], 1); self.assertEqual(state['cursor']['checkpointId'], next(iter(state['archives'])))
        increment = f.manifest('20261013T000000Z-bbbbbbbb', state['cursor'], '9' * 64)
        f.commit(increment); state = f.state()
        self.assertEqual(state['sequence'], 2); self.assertEqual(state['cursor']['lastFile'], 'mysql-bin.000002')
        self.assertEqual(state['cursor']['documents'], {DOC: '9' * 64})
        self.assertEqual(len(state['archives']), 2)
        self.assertFalse((f.data / 'backups/binlog-cursor.json').exists())
        self.assertFalse((f.data / 'backups/recovery-index.json').exists())

    def test_no_archive_effect_before_durable_capture_intent(self):
        f = Fixture(); f.files.failures['write-intent.json'] = 'before'
        with self.assertRaises(OSError): f.commit()
        self.assertEqual(list((f.data / 'backups/checkpoints').iterdir()), [])
        with self.assertRaises(ValueError): f.state()

    def test_archive_creation_failure_leaves_intent_without_advancing_pointer(self):
        f = Fixture()
        with self.assertRaises(RuntimeError):
            with f.catalog().acquire() as lease:
                lease.begin_capture('20261013T000000Z-aaaaaaaa', 'nightly')
                raise RuntimeError('synthetic encryption outcome unavailable')
        self.assertEqual(f.files.read_record(f.catalog().base / 'current.json')['sequence'], 0)
        with self.assertRaises(ValueError): f.state()

    def test_archive_hash_failure_retains_ciphertext_and_denies_replay(self):
        for stage in ('before', 'after'):
            f = Fixture(); f.files.failures['archive'] = stage
            with self.assertRaises(OSError): f.commit()
            self.assertEqual(len(list((f.data / 'backups/checkpoints').iterdir())), 1)
            with self.assertRaises(ValueError): f.state()

    def test_generation_partial_or_fsync_ack_failure_does_not_publish_success(self):
        for stage in ('partial', 'after'):
            f = Fixture(); f.files.failures['write-0000000001.json'] = stage
            with self.assertRaises(OSError): f.commit()
            self.assertEqual(f.files.read_record(f.catalog().base / 'current.json')['sequence'], 0)
            with self.assertRaises(ValueError): f.state()

    def test_pointer_failure_before_and_after_replace_is_closed(self):
        for stage in ('before', 'after'):
            f = Fixture(); f.files.failures['pointer'] = stage
            with self.assertRaises(OSError): f.commit()
            with self.assertRaises(ValueError): f.state()
            self.assertTrue((f.catalog().base / 'operations/0000000001/intent.json').exists())

    def test_missing_partial_confirmation_is_not_a_completed_catalog(self):
        for stage in ('before', 'partial'):
            f = Fixture(); f.files.failures['write-confirmed.json'] = stage
            with self.assertRaises(OSError): f.commit()
            with self.assertRaises((ValueError, json.JSONDecodeError)): f.state()

    def test_valid_independent_terminal_can_survive_lost_return_ack(self):
        f = Fixture(); f.files.failures['write-confirmed.json'] = 'after'
        with self.assertRaises(OSError): f.commit()
        self.assertEqual(f.state()['sequence'], 1)
        # Caller still failed; a valid record is not full backup or container readiness.
        self.assertFalse(f.state()['boundary']['globalWritersQuiesced'])

    def test_exact_archive_metadata_change_blocks_later_capture(self):
        f = Fixture(); f.commit(); path = next((f.data / 'backups/checkpoints').iterdir())
        path.write_bytes(b'mutated synthetic ciphertext')
        with self.assertRaises(ValueError): f.state()

    def test_partial_or_unknown_archive_is_never_adopted(self):
        f = Fixture(); path = f.data / 'backups/incrementals/partial.tar.gpg'; path.write_bytes(b'partial')
        with self.assertRaisesRegex(ValueError, 'Unknown'): f.state()
        self.assertEqual(path.read_bytes(), b'partial')

    def test_missing_cursor_or_partial_index_inside_rehashed_generation_is_denied(self):
        for mutate in (lambda v: v.update(cursor=None), lambda v: v['archives'].clear()):
            f = Fixture(); f.commit(); path = f.catalog().base / 'generations/0000000001.json'
            value = f.files.read_record(path); mutate(value); path.write_bytes(R.C.canonical(value) + b'\n')
            pointer = f.catalog()._pointer(value); (f.catalog().base / 'current.json').write_bytes(R.C.canonical(pointer) + b'\n')
            with self.assertRaises(ValueError): f.state()

    def test_typed_bool_generation_is_denied_even_with_matching_pointer(self):
        f = Fixture(); f.commit(); path = f.catalog().base / 'generations/0000000001.json'
        value = f.files.read_record(path); value['schemaVersion'] = True; path.write_bytes(R.C.canonical(value) + b'\n')
        (f.catalog().base / 'current.json').write_bytes(R.C.canonical(f.catalog()._pointer(value)) + b'\n')
        with self.assertRaises(ValueError): f.state()

    def test_incremental_parent_hash_gap_or_cursor_mismatch_never_commits(self):
        for field in ('previousManifestHash', 'closedBinlogs', 'documents'):
            f = Fixture(); f.commit(); previous = f.state()['cursor']; manifest = f.manifest('20261013T000000Z-bbbbbbbb', previous)
            if field == 'previousManifestHash': manifest[field] = '1' * 64
            elif field == 'closedBinlogs': manifest[field] = ['mysql-bin.000009']
            else: manifest[field] = {DOC: '1' * 64}
            with self.assertRaises(ValueError): f.commit(manifest)
            with self.assertRaises(ValueError): f.state()

    def test_finite_exclusive_wait_and_descriptor_release(self):
        f = Fixture()
        with f.catalog().acquire() as first:
            with self.assertRaisesRegex(ValueError, 'expired'):
                with f.catalog().acquire(timeout=.03): pass
            self.assertLessEqual(f.clock.now, .04)
            self.assertEqual(first.read()['sequence'], 0)
        self.assertEqual(f.files.handles, {}); self.assertEqual(f.files.directories, {})
        self.assertFalse(any(row[2] for row in f.events if row[0] == 'acquire'))

    def test_released_or_foreign_thread_lease_cannot_reuse_current_lock(self):
        f = Fixture()
        with f.catalog().acquire() as old: pass
        with f.catalog().acquire() as current:
            with self.assertRaises(ValueError): old.read()
            errors = []
            def foreign():
                try: current.read()
                except ValueError: errors.append(True)
            thread = threading.Thread(target=foreign); thread.start(); thread.join(1)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [True])

    def test_permanent_lock_and_directory_replacement_denied(self):
        for name in ('catalog.lock', 'operations'):
            f = Fixture(); base = f.catalog().base
            with self.assertRaises(ValueError):
                with f.catalog().acquire() as lease:
                    path = base / name
                    if name == 'catalog.lock':
                        # Windows cannot rename a held native file. Inject the
                        # displaced pathname while retaining the original FD.
                        f.files.displaced_locks.add(path)
                    else:
                        path.rename(f.root / ('retained-' + name)); path.mkdir()
                    lease.read()
            self.assertEqual(f.files.handles, {}); self.assertEqual(f.files.directories, {})

    def test_history_or_unknown_commit_inventory_does_not_reset(self):
        f = Fixture(); (f.catalog().base / 'operations/0000000001').mkdir()
        with self.assertRaisesRegex(ValueError, 'Unresolved'): f.state()
        self.assertEqual(f.files.read_record(f.catalog().base / 'current.json')['sequence'], 0)

    def test_pruning_preserves_current_chain_and_durably_removes_only_other_bases(self):
        f = Fixture(); first = f.manifest(); first['createdAt'] = '2026-01-01T00:00:00Z'; f.commit(first)
        inc = f.manifest('20261013T000000Z-bbbbbbbb', f.state()['cursor']); inc['createdAt'] = '2026-01-02T00:00:00Z'; f.commit(inc)
        latest = f.manifest('20261013T000000Z-cccccccc'); f.commit(latest)
        with f.catalog().acquire() as lease: removed = lease.prune(datetime(2026, 9, 1, tzinfo=timezone.utc))
        self.assertEqual(removed, sorted([first['checkpointId'], inc['checkpointId']]))
        self.assertEqual(set(f.state()['archives']), {latest['checkpointId']})
        self.assertEqual(len(f.files.removed), 2)
        self.assertTrue((f.data / 'retained-synthetic-removals' / (first['checkpointId'] + '.tar.gpg')).exists())

    def test_prune_delete_failure_leaves_pending_without_invalid_base_references(self):
        f = Fixture(); first = f.manifest(); first['createdAt'] = '2026-01-01T00:00:00Z'; f.commit(first)
        f.commit(f.manifest('20261013T000000Z-bbbbbbbb')); f.files.failures['remove'] = 'before'
        with self.assertRaises(OSError):
            with f.catalog().acquire() as lease: lease.prune(datetime(2026, 9, 1, tzinfo=timezone.utc))
        with self.assertRaises(ValueError): f.state()
        self.assertEqual(len(f.files.removed), 0)
        value = f.files.read_record(f.catalog().base / 'generations/0000000003.json')
        self.assertNotIn(first['checkpointId'], value['archives'])

    def test_generation_capacity_refuses_before_intent_or_archive_effect(self):
        f = Fixture()
        with patch.object(R, 'MAX_GENERATIONS', 0):
            with f.catalog().acquire() as lease:
                with self.assertRaisesRegex(ValueError, 'generation capacity'):
                    lease.begin_capture('20261013T000000Z-aaaaaaaa', 'nightly')
        self.assertEqual(list((f.catalog().base / 'operations').iterdir()), [])
        self.assertEqual(list((f.data / 'backups/checkpoints').iterdir()), [])

    def test_retained_byte_capacity_reserves_generation_before_intent(self):
        f = Fixture(); total = (f.catalog().base / 'generations/0000000000.json').stat().st_size
        with patch.object(R, 'MAX_HISTORY_BYTES', total + R.MAX_NEW_COMMIT_BYTES - 1):
            with f.catalog().acquire() as lease:
                with self.assertRaisesRegex(ValueError, 'retained-history capacity'):
                    lease.begin_capture('20261013T000000Z-aaaaaaaa', 'nightly')
        self.assertEqual(list((f.catalog().base / 'operations').iterdir()), [])
        self.assertFalse(any(row[0] == 'archive' for row in f.events))

    def test_archive_index_capacity_denies_before_new_intent(self):
        f = Fixture(); f.commit(); previous = f.state()['cursor']
        with patch.object(R, 'MAX_ARCHIVES', 1):
            with f.catalog().acquire() as lease:
                with self.assertRaisesRegex(ValueError, 'archive-index capacity'):
                    lease.begin_capture('20261013T000000Z-bbbbbbbb', 'incremental')
        self.assertEqual(f.state()['cursor'], previous)
        self.assertFalse((f.catalog().base / 'operations/0000000002').exists())

    def test_active_operation_directory_replacement_denied_before_publication(self):
        f = Fixture()
        with self.assertRaises(ValueError):
            with f.catalog().acquire() as lease:
                lease.begin_capture('20261013T000000Z-aaaaaaaa', 'nightly')
                path = f.catalog().base / 'operations/0000000001'
                path.rename(f.root / 'retained-original-operation'); path.mkdir()
                lease.commit_capture(f.archive(f.manifest()), f.manifest(), f.cursor(f.manifest()), f.boundary('nightly'))
        self.assertEqual(f.files.read_record(f.catalog().base / 'current.json')['sequence'], 0)
        self.assertEqual(f.files.directories, {})

    def test_directory_cleanup_attempts_all_owned_descriptors_after_failure(self):
        f = Fixture(); f.files.failures['directory-close'] = 'after'
        with self.assertRaisesRegex(ValueError, 'descriptor release'):
            with f.catalog().acquire() as lease: self.assertEqual(lease.read()['sequence'], 0)
        self.assertEqual(f.files.handles, {}); self.assertEqual(f.files.directories, {})


def maintenance_definitions():
    """Actual maintenance methods, with every process/service sink injected."""
    tree = ast.parse((ROOT / 'scripts/maintenance.py').read_bytes())
    wanted = {'Maintenance', 'write', 'sha256_file', 'checkpoint_ephemeral'}
    selected = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in wanted]
    class PosixInventory(ast.NodeTransformer):
        def visit_Call(self, node):
            self.generic_visit(node)
            if (isinstance(node.func, ast.Name) and node.func.id == 'str' and len(node.args) == 1
                    and isinstance(node.args[0], ast.Call) and isinstance(node.args[0].func, ast.Attribute)
                    and node.args[0].func.attr == 'relative_to'):
                return ast.copy_location(ast.Call(func=ast.Attribute(value=node.args[0], attr='as_posix', ctx=ast.Load()), args=[], keywords=[]), node)
            return node
    if os.name == 'nt':
        selected = [PosixInventory().visit(node) for node in selected]
        for node in selected: ast.fix_missing_locations(node)
    namespace = dict(base64=__import__('base64'), hashlib=__import__('hashlib'), json=json, os=os,
                     Path=Path, re=re, shutil=shutil, stat=stat, subprocess=__import__('subprocess'),
                     sys=sys, tarfile=tarfile, tempfile=tempfile, time=__import__('time'), uuid=uuid,
                     datetime=datetime, timedelta=timedelta, timezone=timezone,
                     NOW=lambda: datetime(2026, 10, 13, tzinfo=timezone.utc), STAMP=lambda: STAMP,
                     manifest_hash=R.manifest_hash, inventory=R.inventory, contiguous_logs=R.contiguous_logs,
                     validate_chain=R.validate_chain, catalog_records=R.C)
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<actual-maintenance-backup-methods>', 'exec'), namespace)
    return namespace


class MaintenanceFixture(Fixture):
    def __init__(self):
        super().__init__(); self.ns = maintenance_definitions(); self.fail_encrypt = False
        self.records = {}; self.actions = []
        for name in ('mysql', 'runtime/storage', 'mysql-keyring', 'secrets'): (self.data / name).mkdir(parents=True, exist_ok=True)
        (self.data / 'mysql/mysql-bin.000001').write_bytes(b'synthetic log one')
        (self.data / 'mysql/mysql-bin.000002').write_bytes(b'synthetic log two')
        (self.data / 'mysql/mysql-bin.index').write_text('mysql-bin.000001\n')
        doc = self.data / DOC; doc.parent.mkdir(parents=True); doc.write_bytes(b'synthetic document')
        (self.data / 'secrets/backup-key').write_bytes(b'synthetic-not-a-secret')
        self.add('a', 'mysql'); self.add('b', 'packager'); self.add('c', None)
        # A stopped non-original is never resumed.
        self.add('d', 'worker'); self.records['d' * 64]['State'].update(Running=False, Status='exited', Pid=0)
        fixture = self
        class Boundary:
            require_idle = staticmethod(QuiescedContainers.require_idle)
            def __new__(cls, data, mode):
                value = QuiescedContainers(data, mode, fixture.capture, fixture.execute)
                original = value.confirm_boundary
                def confirm(): fixture.events.append(('boundary-confirm',)); return original()
                value.confirm_boundary = confirm
                return value
        self.ns['QuiescedContainers'] = Boundary
        self.ns['RecoveryCatalog'] = lambda *_: self.catalog()
        self.ns['output'] = self.output; self.ns['run'] = self.run
        self.maintenance = object.__new__(self.ns['Maintenance'])
        self.maintenance.data = self.data; self.maintenance.root = ROOT
        self.maintenance.cfg = dict(installation_id=INSTALLATION); self.maintenance.images = {}
        self.maintenance.prefix = ['synthetic-compose']; self.maintenance.compose = self.compose
        self.maintenance.copy_offvm = lambda _: 'No external copy in injected control.'
        self.maintenance.prune_backups = lambda: None
        self.reports = []; self.maintenance.report = lambda kind, report: self.reports.append((kind, report))

    def add(self, letter, service):
        identifier = letter * 64; labels = {'io.autosoft.managed': 'true'}
        if service: labels.update({'com.docker.compose.project': 'autosoft', 'com.docker.compose.service': service,
                                   'com.docker.compose.oneoff': 'False', 'com.docker.compose.container-number': '1'})
        else: labels['io.autosoft.app'] = 'documents'
        self.records[identifier] = dict(Id=identifier, Image='sha256:' + 'f' * 64, Name='/synthetic-' + letter,
            Config=dict(Image='company/service@sha256:' + 'e' * 64, Labels=labels, Env=[]),
            HostConfig=dict(RestartPolicy={'Name': 'unless-stopped'}),
            Mounts=[dict(Type='bind', Source=str(self.data / 'mysql'), Destination='/data', RW=True)],
            RestartCount=0, State=dict(Running=True, Paused=False, Restarting=False, Dead=False, OOMKilled=False,
                ExitCode=0, Pid=101, Status='running', StartedAt='2026-10-13T00:00:00Z', FinishedAt='0001-01-01T00:00:00Z'))

    def capture(self, args):
        if args[1] == 'ps': return '\n'.join(name for name, row in self.records.items() if row['State']['Running'])
        assert args[:2] == ['docker', 'inspect']; return json.dumps([self.records[args[2]]])

    def execute(self, args):
        assert args[1] in ('stop', 'start') and args[-1] in self.records
        self.actions.append(args); self.events.append(('original-' + args[1], args[-1]))
        row = self.records[args[-1]]['State']; running = args[1] == 'start'
        row.update(Running=running, Pid=102 if running else 0, Status='running' if running else 'exited',
                   FinishedAt='2026-10-13T00:01:00Z')
        if running: row['StartedAt'] = '2026-10-13T00:02:00Z'

    def output(self, args):
        if args == ['uname', '-m']: return 'x86_64\n'
        assert args[0] == 'synthetic-compose' and args[-1] == 'SHOW BINARY LOGS'
        return 'mysql-bin.000001\t1\nmysql-bin.000002\t1\nmysql-bin.000003\t1\n'

    def compose(self, *args, **kwargs):
        assert args[-1] == 'FLUSH BINARY LOGS'; self.events.append(('synthetic-flush',))

    def run(self, args, **kwargs):
        assert args[0] == 'gpg'; self.events.append(('synthetic-encrypt',))
        kwargs['stdout'].write(b'SYNTHETIC-NOT-ENCRYPTED-NIGHTLY')
        if self.fail_encrypt: raise RuntimeError('synthetic archive outcome unavailable')

    def call(self, mode):
        fixture = self
        class Process:
            def __init__(self, argv, **kwargs):
                assert argv[0] == 'gpg'; self.stdin = io.BytesIO(); self.output = kwargs['stdout']; self.code = None
            def wait(self):
                self.output.write(b'SYNTHETIC-NOT-ENCRYPTED-INCREMENTAL'); self.code = 1 if fixture.fail_encrypt else 0
                return self.code
            def poll(self): return self.code
            def kill(self): self.code = -9
        real_fsync = os.fsync
        def fsync(fd):
            try: real_fsync(fd)
            except OSError as error:
                if os.name != 'nt' or error.errno != 9: raise
                assert stat.S_ISREG(os.fstat(fd).st_mode)
                fixture.events.append(('maintenance-readonly-fsync-policy', fd))
        with patch.object(backup_recovery, 'sync_directory', lambda *_: None), \
             patch.object(shutil, 'disk_usage', return_value=SimpleNamespace(free=1024**4)), \
             patch.object(os, 'fsync', fsync), \
             patch.object(self.ns['subprocess'], 'Popen', Process):
            return getattr(self.maintenance, mode)()


class IntegrationControls(unittest.TestCase):
    def test_actual_nightly_commit_precedes_final_confirmation_and_original_only_resume(self):
        f = MaintenanceFixture(); f.call('backup'); events = f.events
        committed = next(i for i, row in enumerate(events) if row == ('record', 'confirmed.json'))
        final_confirm = max(i for i, row in enumerate(events) if row == ('boundary-confirm',))
        first_resume = next(i for i, row in enumerate(events) if row[0] == 'original-start')
        self.assertLess(committed, final_confirm); self.assertLess(final_confirm, first_resume)
        self.assertEqual({args[-1] for args in f.actions if args[1] == 'start'}, {'a' * 64, 'b' * 64, 'c' * 64})
        self.assertEqual(f.state()['sequence'], 1); self.assertEqual(len(f.reports), 1)

    def test_actual_incremental_commits_before_resume_and_packager_is_selected(self):
        f = MaintenanceFixture(); f.call('backup'); f.events.clear(); f.actions.clear(); f.call('incremental')
        committed = next(i for i, row in enumerate(f.events) if row == ('record', 'confirmed.json'))
        resumed = next(i for i, row in enumerate(f.events) if row[0] == 'original-start')
        self.assertLess(committed, resumed)
        self.assertEqual({args[-1] for args in f.actions if args[1] == 'stop'}, {'b' * 64, 'c' * 64})
        self.assertEqual(f.state()['sequence'], 2); self.assertEqual(f.state()['cursor']['lastFile'], 'mysql-bin.000002')

    def test_actual_archive_failure_resumes_only_originals_and_keeps_catalog_unresolved(self):
        f = MaintenanceFixture(); f.fail_encrypt = True
        with self.assertRaises(RuntimeError): f.call('backup')
        self.assertEqual({args[-1] for args in f.actions if args[1] == 'start'}, {'a' * 64, 'b' * 64, 'c' * 64})
        self.assertEqual(f.reports, [])
        with self.assertRaises(ValueError): f.state()
        old_actions = list(f.actions)
        with self.assertRaises(ValueError): f.call('backup')
        self.assertEqual(f.actions, old_actions)

    def test_actual_catalog_partial_commit_never_reports_success_after_resume(self):
        f = MaintenanceFixture(); f.files.failures['write-confirmed.json'] = 'partial'
        with self.assertRaises(OSError): f.call('backup')
        self.assertEqual(f.reports, [])
        self.assertFalse(any(row == ('boundary-confirm',) for row in f.events[f.events.index(('record', 'confirmed.json')) + 1:]))
        self.assertEqual({args[-1] for args in f.actions if args[1] == 'start'}, {'a' * 64, 'b' * 64, 'c' * 64})
        with self.assertRaises(json.JSONDecodeError): f.state()

    def test_actual_incremental_encryption_failure_preserves_previous_cursor(self):
        f = MaintenanceFixture(); f.call('backup'); pointer = f.files.read_record(f.catalog().base / 'current.json')
        f.fail_encrypt = True; f.reports.clear()
        with self.assertRaises(ValueError): f.call('incremental')
        self.assertEqual(f.files.read_record(f.catalog().base / 'current.json'), pointer)
        self.assertEqual(f.reports, [])
        with self.assertRaises(ValueError): f.state()

    def test_actual_legacy_catalog_preflight_precedes_stop_or_archive_effect(self):
        f = MaintenanceFixture(); (f.data / 'backups/binlog-cursor.json').write_bytes(b'legacy')
        with self.assertRaisesRegex(ValueError, 'migration'): f.call('backup')
        self.assertEqual(f.actions, []); self.assertEqual(f.reports, [])
        self.assertFalse(any(row[0] == 'synthetic-encrypt' for row in f.events))

    def test_actual_capacity_denial_precedes_original_stop_and_encryption(self):
        f = MaintenanceFixture()
        with patch.object(R, 'MAX_GENERATIONS', 0):
            with self.assertRaisesRegex(ValueError, 'generation capacity'): f.call('backup')
        self.assertEqual(f.actions, []); self.assertEqual(f.reports, [])
        self.assertEqual(list((f.catalog().base / 'operations').iterdir()), [])
        self.assertFalse(any(row[0] == 'synthetic-encrypt' for row in f.events))

    def test_actual_missing_catalog_denial_precedes_original_stop(self):
        f = MaintenanceFixture(); f.catalog().base.rename(f.root / 'retained-missing-catalog')
        with self.assertRaises(FileNotFoundError): f.call('backup')
        self.assertEqual(f.actions, []); self.assertEqual(f.reports, [])
        self.assertFalse(any(row[0] == 'synthetic-encrypt' for row in f.events))

    def test_actual_explicit_initializer_route_is_fresh_only(self):
        f = MaintenanceFixture(); f.catalog().base.rename(f.root / 'retained-first-catalog')
        # Only the fresh synthetic archive directories remain; no adoption.
        f.call('initialize_recovery_catalog')
        with self.assertRaisesRegex(ValueError, 'reinitialized'): f.call('initialize_recovery_catalog')
        self.assertEqual(f.actions, [])
        tree = ast.parse((ROOT / 'scripts/maintenance.py').read_bytes())
        main = next(node for node in tree.body if isinstance(node, ast.If)
                    and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                    and node.test.left.id == '__name__')
        source = ast.unparse(main)
        self.assertIn("sys.argv[1].replace('-', '_')", source)
        self.assertIn('getattr(maintenance, action)()', source)


if __name__ == '__main__': unittest.main(verbosity=2)
