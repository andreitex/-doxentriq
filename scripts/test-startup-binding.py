"""Retained local/injected startup controls; no Linux, installer or service actions."""
import copy
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


S = load('startup_binding_controls', ROOT / 'scripts/startup_binding.py')
R = load('startup_layout_fixture', ROOT / 'scripts/test-runtime-layout.py')
B = load('startup_lock_fixture', ROOT / 'test/test_checkpoint_admission.py')
C, A, Q = S.C, S.A, S.Q
INSTALLATION = '64a2a5f8-04b9-43b5-9807-122d866db1f1'
OTHER = '947aaf58-8ba3-4c42-b4ba-e2a1f87b0cf5'
LUKS = '45fb163d-e8ec-452b-aec0-ffdc391be9fa'
APP = 'd9224505-f564-44e5-a697-16e1451fc44a'
KEY = APP + '/documents'
METADATA = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def forbidden(*_, **__):
    raise AssertionError('No native command or mutation is authorized in these controls')


class Files(R.Files):
    def __init__(self):
        super().__init__(); self.file_metadata = {}; self.reads = []

    def protected(self, path, directory=False, private=False):
        info = super().protected(path, directory=directory, private=private)
        if directory or Path(path) not in self.file_metadata: return info
        values = {key: getattr(info, key) for key in METADATA}
        values.update(self.file_metadata[Path(path)]); return SimpleNamespace(**values)

    def read(self, path):
        self.reads.append(Path(path)); return super().read(path)

    def replace(self, path, value):
        self.events.append(('replace-file', path.name)); return C.NativeFiles.replace(self, path, value)


class Transport(R.DirectoryTransport):
    """Linux held-file replacement semantics are injected on Windows too.

    NativeFiles.read still performs actual record file IO and continuity checks.
    Windows os.open denies unlink while held; emulated guard FDs permit real
    rename/replacement controls without adding a Windows native API authority.
    """
    def __init__(self, files):
        super().__init__(files); self.real = {}; self.real_opened = []; self.real_closed = []
        self.fail_record = None

    def open(self, path, flags):
        if flags & self.O_DIRECTORY: return super().open(path, flags)
        path = Path(path)
        assert flags == os.O_RDONLY | self.O_NOFOLLOW | self.O_CLOEXEC | getattr(os, 'O_BINARY', 0)
        if path == self.fail_record: raise OSError('injected-record-open')
        fd = 19000 + len(self.real_opened)
        self.real[fd] = (path, self.files.protected(path, private=True))
        self.real_opened.append(fd); return fd

    def descriptor(self, fd):
        if fd in self.handles: return super().descriptor(fd)
        if fd not in self.real: return os.fstat(fd)
        path, held = self.real[fd]
        current = self.files.protected(path, private=True)
        return current if (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino) else held

    def close(self, fd):
        if fd not in self.real: return super().close(fd)
        self.real_closed.append(fd); del self.real[fd]
        if fd == self.fail_close: raise OSError('injected-record-close')


class Fixture:
    def __init__(self):
        self.placement = R.Fixture(); self.data = self.placement.data
        self.files = Files(); self.files.metadata.update(self.placement.files.metadata)
        self.placement.files = self.files; self.placement.events = self.files.events
        self.placement.call()
        self.host = self.placement.directory / 'host'; self.host.mkdir()
        self.root = self.placement.directory / 'installation'; self.root.mkdir()
        self.backing = self.placement.directory / 'retained.luks'; self.backing.write_bytes(b'synthetic ciphertext')
        self.files.file_metadata[self.backing] = dict(st_size=32 * 1024**3)
        (self.host / 'storage.key').write_bytes(b'synthetic-unlock-material')
        self.clock = B.Clock(); self.locks = B.Locks(self.files)
        self.intent = dict(schemaVersion=1, scope=S.I.SCOPE, installation_id=INSTALLATION,
                           directory=C.directory_binding(self.files.protected(self.host, directory=True)),
                           proposal=dict(data_dir=str(self.data), install_root=str(self.root),
                                         storage_file=str(self.backing), capacity_gib=32))
        self.final = {key: self.intent['proposal'][key] for key in ('data_dir', 'install_root', 'storage_file')}
        self.final['installation_id'] = INSTALLATION
        self.receipt = dict(self.final, creation_stage='new-luks-created', luks_uuid=LUKS)
        self.config = dict(installation_id=INSTALLATION, owner_subject=OTHER, private='synthetic-private-config')
        for path, value in ((self.host / S.I.INTENT, self.intent), (self.host / 'installation.json', self.final),
                            (self.host / 'installation.storage-receipt.json', self.receipt),
                            (self.data / 'config/installation.json', self.config)):
            self.files.write(path, value)
        self.gate().initialize(INSTALLATION)
        self.allocation().initialize(INSTALLATION, read_state=self.read, write_state=self.write)
        self.commands = []; self.mounts = []; self.on_mount = None
        self.files.events.clear(); self.files.reads.clear(); self.locks.events.clear()

    def gate(self, *_):
        return C.Gate(self.data, files=self.files, locks=self.locks, clock=self.clock.time, sleep=self.clock.sleep)

    def allocation(self, *_):
        return A.Allocation(self.data, files=self.files, locks=self.locks, clock=self.clock.time, sleep=self.clock.sleep)

    def read(self, path): return Q.validate_state(self.files.read(path))

    def write(self, path, value):
        Q.validate_state(value)
        if path.exists(): C.NativeFiles.replace(self.files, path, value)
        else: self.files.write(path, value)

    def commit(self, status='active'):
        value = dict(nextProjectId=10001, projects={KEY: dict(projectId=10000, sizeMb=16, status=status)})
        with self.allocation().acquire() as lease:
            lease.commit(value, read_state=self.read, write_state=self.write)
        return value

    def mount(self, data, receipt, command):
        self.assert_inputs = (data, receipt, command)
        self.mounts.append(1)
        if self.on_mount: self.on_mount(len(self.mounts))
        return dict(target=str(data), luksUuid=receipt['luks_uuid'], fixed='injected-encrypted-proof')

    def rewrite(self, path, value): path.write_bytes(C.canonical(value) + b'\n')

    def call(self, **options):
        self.transport = Transport(self.files)
        transport = options.pop('transport', self.transport)
        self.transport = transport
        def fixture_path(value):
            C.require(type(value) is str and Path(value).is_absolute() and str(Path(value)) == value)
            return value
        def layout(data, files):
            return S.L.verify(data, files=files, build_mount=lambda _: dict(self.placement.mount))
        self.files.events.clear(); self.files.reads.clear(); self.locks.events.clear()
        args = dict(host_directory=self.host, files=self.files, command=forbidden, mount=self.mount,
                    layout=layout, gate_factory=self.gate, allocation_factory=self.allocation,
                    read_state=self.read, clock=self.clock.time, timeout=10)
        args.update(options)
        with patch.object(S.I, 'path_value', fixture_path), patch.object(S, 'os', transport), \
             patch.object(S.L, 'os', transport), patch.object(self.files, 'descriptor', transport.descriptor):
            return S.verify(self.data, self.root, **args)

    def assert_readonly(self, case):
        case.assertFalse(any(event[0] in ('write', 'replace-file', 'replace-state', 'mkdir', 'permission') for event in self.files.events))
        case.assertEqual(self.files.handles, {}); case.assertEqual(self.locks.held, {})
        case.assertEqual(self.transport.handles, {}); case.assertEqual(self.transport.real, {})
        case.assertEqual(sorted(self.transport.real_opened), sorted(self.transport.real_closed))


class StartupControls(unittest.TestCase):
    def test_initialized_populated_readonly_closed_result_and_no_secret_bytes(self):
        f = Fixture(); f.commit()
        path = f.data / 'runtime/storage' / APP / 'documents'; path.mkdir(parents=True)
        (path / 'business.txt').write_bytes(b'retained-business-data')
        before = (f.host / 'storage.key').read_bytes(), (path / 'business.txt').read_bytes()
        result = f.call()
        self.assertEqual(set(result), {'scope', 'status', 'installationId', 'hostSha256', 'configurationSha256',
                                     'admissionSha256', 'allocationSha256', 'encryptedMountSha256', 'layoutSha256', 'changed', 'backupReady'})
        self.assertEqual(result['scope'], 'STARTUP_BINDING_ONLY'); self.assertFalse(result['changed']); self.assertFalse(result['backupReady'])
        self.assertNotIn('synthetic-private-config', json.dumps(result)); self.assertNotIn(f.backing, f.files.reads)
        self.assertNotIn(f.host / 'storage.key', f.files.reads)
        self.assertEqual(before, ((f.host / 'storage.key').read_bytes(), (path / 'business.txt').read_bytes()))
        f.assert_readonly(self)

    def test_activity_ex_wait_allows_existing_sh_coordinator_completion(self):
        f = Fixture(); lease = f.gate().admit(C.digest({'fixture': 'in-flight'}))
        def complete(): lease.complete(C.digest({'fixture': 'confirmed'})); lease.release()
        f.locks.on_block = complete
        result = f.call(); self.assertEqual(result['status'], 'verified')
        events = f.locks.events
        denied = events.index(('attempt', 'activity.lock', False, False))
        completed = next(i for i, row in enumerate(events[denied:], denied) if row == ('acquire', 'coordinator.lock', False))
        inspected = next(i for i, row in enumerate(events[completed:], completed) if row == ('acquire', 'activity.lock', False))
        self.assertLess(denied, completed); self.assertLess(completed, inspected)
        self.assertEqual(f.files.handles, {}); self.assertEqual(f.locks.held, {})

    def test_new_admission_cannot_write_under_readonly_gate_context(self):
        f = Fixture()
        with f.gate().inspect_initialized(INSTALLATION, timeout=10) as evidence:
            self.assertFalse(hasattr(evidence, 'complete'))
            with self.assertRaises(ValueError): f.gate().admit(C.digest({'new': 'denied'}), timeout=.03)
            self.assertEqual(f.files.inventory(f.gate().base / 'operations', 0), [])
        self.assertEqual(f.files.handles, {})

    def test_allocation_lock_is_last_and_evidence_has_no_commit_lease(self):
        f = Fixture(); f.call()
        acquired = [row[1] for row in f.locks.events if row[0] == 'acquire']
        self.assertEqual(acquired, ['activity.lock', 'coordinator.lock', 'allocation.lock'])
        with f.allocation().inspect_initialized(INSTALLATION, read_state=f.read) as value:
            self.assertIs(type(value), dict); self.assertNotIn('commit', value)

    def test_shared_deadline_expires_without_releasing_foreign_activity_or_writing(self):
        f = Fixture(); lease = f.gate().admit(C.digest({'ongoing': True}))
        with self.assertRaises(ValueError): f.call(timeout=.03)
        self.assertLessEqual(f.clock.now, .04); self.assertTrue(f.files.handles)
        lease.release(); self.assertEqual(f.files.handles, {})

    def test_timeouts_reject_bool_nan_infinity_and_unbounded_values(self):
        f = Fixture()
        for value in (True, float('nan'), float('inf'), 0, -1, 51):
            with self.subTest(value=value), self.assertRaises(ValueError): f.call(timeout=value)
        for value in (True, float('nan'), float('inf'), 11):
            with self.subTest(allocation=value), self.assertRaises(ValueError):
                with f.allocation().inspect_initialized(INSTALLATION, read_state=f.read, timeout=value): pass

    def test_closed_unresolved_uncertain_and_unknown_gate_records_block(self):
        for kind in ('closed', 'unresolved', 'uncertain', 'unknown'):
            with self.subTest(kind=kind):
                f = Fixture()
                if kind == 'closed': f.gate().close('retained-closed')
                elif kind == 'unknown': (f.gate().base / 'unknown.json').write_text('{}')
                else:
                    lease = f.gate().admit(C.digest({'pending': kind})); lease.release()
                    if kind == 'uncertain':
                        directory = f.gate().base / 'operations' / lease.operation_id
                        intent = f.files.read(directory / 'intent.json')
                        f.files.write(directory / 'uncertain.json', dict(intentSha256=C.digest(intent), stage='completion'))
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.mounts, []); f.assert_readonly(self)

    def test_pending_projects_and_unknown_quota_evidence_block(self):
        for kind in ('pending', 'quota', 'base', 'commit'):
            with self.subTest(kind=kind):
                f = Fixture(); f.commit('pending' if kind == 'pending' else 'active')
                if kind == 'quota': (f.data / 'quota/projects.json.partial').write_text('{}')
                if kind == 'base': (f.allocation().base / 'unknown.json').write_text('{}')
                if kind == 'commit': (f.allocation().base / 'commits/0000000001/unknown.json').write_text('{}')
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.mounts, []); f.assert_readonly(self)

    def test_incomplete_open_fence_and_concurrent_close_never_reopen(self):
        f = Fixture(); gate = f.gate(); fence = gate.close('partial-fixture')
        f.rewrite(gate.base / 'state.json', gate._open(fence['generation'] + 1))
        with self.assertRaisesRegex(ValueError, 'Incomplete close'): f.call()
        f = Fixture(); lease = f.gate().admit(C.digest({'fixture': 'before-close'}))
        def close_after_completion():
            lease.complete(C.digest({'fixture': 'confirmed'})); lease.release(); f.gate().close('concurrent-fixture')
        f.locks.on_block = close_after_completion
        with self.assertRaisesRegex(ValueError, 'Closed admission'): f.call()
        self.assertEqual(f.files.read(f.gate().base / 'state.json')['phase'], 'CLOSED')

    def test_completed_fence_history_is_accepted_without_new_readiness_records(self):
        f = Fixture(); gate = f.gate(); fence = gate.close('completed-fixture')
        lease = gate.readiness(fence); lease.finish_scope_and_reopen(); lease.release()
        before = {path.name: path.read_bytes() for path in (gate.base / 'fences' / fence['fenceId']).iterdir()}
        self.assertEqual(f.call()['status'], 'verified')
        self.assertEqual(before, {path.name: path.read_bytes() for path in (gate.base / 'fences' / fence['fenceId']).iterdir()})
        f.assert_readonly(self)

    def test_rehashed_invalid_project_types_reach_public_allocation_reader(self):
        for field, value in (('projectId', 10000.0), ('sizeMb', 16.0)):
            with self.subTest(field=field):
                f = Fixture(); state = f.commit(); state['projects'][KEY][field] = value
                base = f.allocation().base; pointer = f.files.read(base / 'state.json')
                pointer['projectsSha256'] = C.digest(state)
                path = base / 'commits/0000000001'; intent = f.files.read(path / 'intent.json')
                intent['projectsSha256'] = C.digest(state)
                f.rewrite(f.data / 'quota/projects.json', state); f.rewrite(base / 'state.json', pointer)
                f.rewrite(path / 'intent.json', intent); f.rewrite(path / 'confirmed.json', dict(intentSha256=C.digest(intent)))
                # Bypass Q's validated callback deliberately; lease digests and
                # last-commit hashes are consistent, so the new own type gate
                # must reject the equal-looking float before native queries.
                with self.assertRaises(ValueError): f.call(read_state=f.files.read)
                self.assertEqual(f.mounts, [])

    def test_foreign_install_root_directory_is_denied_before_native_queries(self):
        f = Fixture(); f.files.metadata[f.root] = dict(st_uid=10001, st_gid=10001)
        with self.assertRaises(ValueError): f.call()
        self.assertEqual(f.mounts, [])

    def test_host_configuration_receipt_and_gate_uuid_mismatches_are_blocked(self):
        for kind in ('config', 'receipt', 'gate', 'host'):
            with self.subTest(kind=kind):
                f = Fixture()
                if kind == 'config': f.rewrite(f.data / 'config/installation.json', dict(f.config, installation_id=OTHER))
                if kind == 'receipt': f.rewrite(f.host / 'installation.storage-receipt.json', dict(f.receipt, installation_id=OTHER))
                if kind == 'host': f.rewrite(f.host / 'installation.json', dict(f.final, installation_id=OTHER))
                if kind == 'gate':
                    base = f.gate().base; initial = f.files.read(base / 'initialization.json'); initial['installationId'] = OTHER
                    f.rewrite(base / 'initialization.json', initial); f.rewrite(base / 'initialized.json', dict(initializationSha256=C.digest(initial)))
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.mounts, [])

    def test_allocation_foreign_uuid_with_consistent_initial_and_pointer_hashes_is_blocked(self):
        f = Fixture(); base = f.allocation().base
        initial = f.files.read(base / 'initialization.json'); initial['installationId'] = OTHER
        pointer = f.files.read(base / 'state.json'); pointer['installationId'] = OTHER
        f.rewrite(base / 'initialization.json', initial); f.rewrite(base / 'initialized.json', dict(initializationSha256=C.digest(initial)))
        f.rewrite(base / 'state.json', pointer)
        with self.assertRaisesRegex(ValueError, 'another installation'): f.call()

    def test_missing_legacy_partial_and_pending_host_evidence_are_retained(self):
        for kind in ('intent', 'final', 'receipt', 'legacy', 'pending'):
            with self.subTest(kind=kind):
                f = Fixture()
                if kind in ('intent', 'final', 'receipt'):
                    name = {'intent': S.I.INTENT, 'final': 'installation.json', 'receipt': 'installation.storage-receipt.json'}[kind]
                    (f.host / name).rename(f.host / ('retained-' + name))
                if kind == 'legacy': f.rewrite(f.data / 'config/installation.json', dict(owner_subject=OTHER))
                if kind == 'pending': f.files.write(f.host / 'installation.pending.json', f.receipt)
                before = {path.name: path.read_bytes() for path in f.host.iterdir() if path.is_file()}
                with self.assertRaises((ValueError, FileNotFoundError)): f.call()
                self.assertEqual(before, {path.name: path.read_bytes() for path in f.host.iterdir() if path.is_file()})
                self.assertEqual(f.mounts, [])

    def test_rehashed_type_invalid_history_and_chain_mismatch_reach_historical_stage(self):
        for field, value in (('schemaVersion', True), ('sequence', 1.0), ('nextProjectId', 10001.0),
                             ('previousPointerSha256', 'f' * 64), ('installationId', OTHER)):
            with self.subTest(field=field):
                f = Fixture(); f.commit()
                # A second valid commit makes the first record historical,
                # outside existing Allocation._state's last-commit check.
                with f.allocation().acquire() as lease:
                    lease.commit(lease.read_state(f.read), read_state=f.read, write_state=f.write)
                base = f.allocation().base / 'commits/0000000001'
                intent = f.files.read(base / 'intent.json'); intent[field] = value
                f.rewrite(base / 'intent.json', intent); f.rewrite(base / 'confirmed.json', dict(intentSha256=C.digest(intent)))
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.mounts, [])

    def test_historical_incomplete_commit_is_not_hidden_by_valid_latest_pointer(self):
        f = Fixture(); f.commit()
        with f.allocation().acquire() as lease: lease.commit(lease.read_state(f.read), read_state=f.read, write_state=f.write)
        path = f.allocation().base / 'commits/0000000001/confirmed.json'; path.rename(path.with_name('retained-confirmed.json'))
        with self.assertRaisesRegex(ValueError, 'historical'): f.call()

    def test_pointer_projects_hash_or_typed_project_records_block(self):
        for kind in ('hash', 'projectBool', 'sizeFloat', 'status', 'nextIdFloat'):
            with self.subTest(kind=kind):
                f = Fixture(); value = f.commit()
                if kind == 'hash': value['projects'][KEY]['sizeMb'] = 17
                if kind == 'projectBool': value['projects'][KEY]['projectId'] = True
                if kind == 'sizeFloat': value['projects'][KEY]['sizeMb'] = 16.0
                if kind == 'status': value['projects'][KEY]['status'] = 'unknown'
                if kind == 'nextIdFloat': value['nextProjectId'] = 10001.0
                f.rewrite(f.data / 'quota/projects.json', value)
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.mounts, [])

    def test_actual_control_directory_replacement_fails_with_held_original_fd(self):
        for name in ('checkpoint-admission/operations', 'allocation/commits'):
            with self.subTest(name=name):
                f = Fixture()
                def change(count):
                    if count == 1:
                        path = f.data / 'quota' / name
                        path.rename(path.with_name('retained-' + path.name)); path.mkdir()
                f.on_mount = change
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.files.handles, {}); self.assertEqual(f.locks.held, {})

    def test_midcall_config_receipt_backing_and_key_replacement_or_drift_fail(self):
        for target in ('config', 'receipt', 'backing', 'key'):
            with self.subTest(target=target):
                f = Fixture()
                def change(count):
                    if count != 1: return
                    path = {'config': f.data / 'config/installation.json', 'receipt': f.host / 'installation.storage-receipt.json',
                            'backing': f.backing, 'key': f.host / 'storage.key'}[target]
                    old = path.read_bytes(); path.rename(path.with_name('retained-' + path.name)); path.write_bytes(old)
                f.on_mount = change
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.files.handles, {}); self.assertEqual(f.locks.held, {})

    def test_mount_or_layout_drift_and_insufficient_backing_size_are_blocked(self):
        f = Fixture(); f.files.file_metadata[f.backing]['st_size'] = 31 * 1024**3
        with self.assertRaises(ValueError): f.call()
        f = Fixture(); count = []
        def mount(*_, **__): count.append(1); return {'current': len(count)}
        with self.assertRaisesRegex(ValueError, 'mount changed'): f.call(mount=mount)
        f = Fixture()
        with self.assertRaises(ValueError): f.call(layout=lambda *_, **__: {'changed': True})

    def test_semantic_build_remount_is_accepted_without_saved_receipt_rewrite(self):
        f = Fixture(); path = f.data / 'runtime/builds'; old = (f.data / 'config/runtime-layout/layout.json').read_bytes()
        info = f.files.info(path); f.files.metadata[path].update(st_dev=info.st_dev + 1, st_ino=info.st_ino + 1)
        self.assertEqual(f.call()['status'], 'verified')
        self.assertEqual(old, (f.data / 'config/runtime-layout/layout.json').read_bytes()); f.assert_readonly(self)

    def test_owned_fd_open_close_and_lock_release_failures_do_not_report_success(self):
        f = Fixture(); transport = Transport(f.files); transport.fail_record = f.host / 'storage.key'
        with self.assertRaisesRegex(OSError, 'record-open'): f.call(transport=transport)
        self.assertEqual(transport.real, {}); self.assertEqual(transport.handles, {})
        f = Fixture(); transport = Transport(f.files); transport.fail_close = 9000
        with self.assertRaisesRegex(OSError, 'directory-close'): f.call(transport=transport)
        self.assertEqual(transport.real, {}); self.assertEqual(transport.handles, {})
        f = Fixture(); release = f.locks.release
        def fail_release(fd): release(fd); raise OSError('injected-owned-lock-release')
        with patch.object(f.locks, 'release', fail_release), self.assertRaises(OSError): f.call()
        self.assertEqual(f.files.handles, {}); self.assertEqual(f.locks.held, {})

    def test_held_lock_replacement_and_valid_record_mutation_cannot_escape_exit_readback(self):
        for target in ('gate', 'allocation', 'project'):
            with self.subTest(target=target):
                f = Fixture()
                def change(count):
                    if count != 2: return
                    if target == 'project':
                        path = f.data / 'quota/projects.json'; raw = path.read_bytes()
                        path.rename(path.with_name('retained-projects.json')); path.write_bytes(raw)
                    else:
                        path = f.gate().base / 'activity.lock' if target == 'gate' else f.allocation().base / 'allocation.lock'
                        f.files.displaced_locks.add(path)
                f.on_mount = change
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.files.handles, {}); self.assertEqual(f.locks.held, {})


class EncryptedControls(unittest.TestCase):
    def proof(self, change=None):
        data = PurePosixPath('/srv/autosoft'); storage = PurePosixPath('/var/lib/autosoft-storage.luks')
        mapper = '/dev/mapper/autosoft-data'
        rows = [LUKS + '\n', '/dev/mapper/autosoft-data is active.\n  type: LUKS2\n  device: /dev/loop0\n',
                str(storage) + '\n', str(data) + ' ' + mapper + ' xfs rw,nosuid,nodev,prjquota\n']
        if change: change(rows)
        calls = []
        def command(argv): calls.append(argv); return rows[len(calls) - 1]
        expected = [['/usr/sbin/cryptsetup', 'luksUUID', str(storage)],
                    ['/usr/sbin/cryptsetup', 'status', 'autosoft-data'],
                    ['/usr/sbin/losetup', '--noheadings', '--output', 'BACK-FILE', '--', '/dev/loop0'],
                    ['/usr/bin/findmnt', '-n', '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS', '--target', str(data)]]
        info = SimpleNamespace(**{key: 1 for key in METADATA})
        class FixedPosixPath(PurePosixPath):
            def resolve(self, **_): return self
            def stat(self): return info
            def lstat(self): return info
        with patch.object(S, 'Path', FixedPosixPath), patch.object(Q, 'mount_proof', lambda *_: mapper):
            result = S.encrypted_proof(data, {'storage_file': str(storage), 'luks_uuid': LUKS}, command=command)
        return result, calls, expected

    def test_exact_readonly_commands_bind_luks2_backing_target_and_options(self):
        result, calls, expected = self.proof()
        self.assertEqual(calls, expected); self.assertEqual(result['luksUuid'], LUKS)
        self.assertEqual(result['target'], '/srv/autosoft')

    def test_foreign_uuid_backing_device_duplicate_type_and_wrong_mount_fail(self):
        changes = [(0, OTHER + '\n'), (1, 'type: LUKS1\ndevice: /dev/loop0\n'),
                   (1, 'type: LUKS2\ntype: LUKS2\ndevice: /dev/loop0\n'),
                   (1, 'type: LUKS2\ndevice: --foreign\n'), (2, '/foreign/backing\n'),
                   (3, '/srv /dev/mapper/autosoft-data xfs rw,nosuid,nodev,prjquota\n'),
                   (3, '/srv/autosoft /dev/mapper/autosoft-data ext4 rw,nosuid,nodev,prjquota\n'),
                   (3, '/srv/autosoft /dev/mapper/autosoft-data xfs rw,nodev,prjquota\n'),
                   (3, '/srv/autosoft /dev/mapper/autosoft-data xfs rw,nosuid,nodev,prjquota,rw\n')]
        for index, value in changes:
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                self.proof(lambda rows: rows.__setitem__(index, value))


if __name__ == '__main__': unittest.main(verbosity=2)
