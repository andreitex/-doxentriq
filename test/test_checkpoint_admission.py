"""Injected admission controls; retained local fixtures, not native qualification."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('checkpoint_admission_fixture', ROOT / 'scripts/checkpoint_admission.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
INSTALLATION = '64a2a5f8-04b9-43b5-9807-122d866db1f1'
REQUEST = hashlib.sha256(b'synthetic request').hexdigest()
OUTCOME = hashlib.sha256(b'independently checked synthetic outcome').hexdigest()


class Files(C.NativeFiles):
    """Inject Windows trust and directory fsync; keep real file IO/readback."""
    def __init__(self):
        self.events, self.handles, self.failures = [], {}, {}
        self.untrusted = set()
        self.displaced_locks = set()
        self.descriptor_overrides = {}
        self.on_inventory = None

    def require_root(self):
        self.events.append(('explicit-root-policy',))

    def compare_opened(self, path_info, descriptor_info):
        # Windows path ctime is creation time, whereas descriptor ctime is
        # change time. Only this cross-view comparison omits that field;
        # native read/check_lock retains full continuity within each view.
        C.require(C.identity(path_info)[:-1] == C.identity(descriptor_info)[:-1])

    def check_lock(self, path, fd, expected):
        C.require(path not in self.displaced_locks, 'Checkpoint lock identity changed')
        super().check_lock(path, fd, expected)

    def descriptor(self, fd):
        actual = super().descriptor(fd)
        if fd in self.descriptor_overrides:
            values = {key: getattr(actual, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
            values.update(self.descriptor_overrides[fd])
            return SimpleNamespace(**values)
        return actual

    def inventory(self, path, maximum):
        # Windows cannot scandir a directory FD. Native production holds that
        # descriptor; this injected transport retains exact path continuity.
        before = self.protected(path, directory=True, private=True)
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                names.append(entry.name); C.require(len(names) <= maximum)
        callback, self.on_inventory = self.on_inventory, None
        if callback: callback(path)
        C.require(C.identity(self.protected(path, directory=True, private=True)) == C.identity(before))
        return names

    def protected(self, path, directory=False, private=False):
        path = Path(path); info = path.lstat()
        C.require(path.is_absolute() and path.resolve(strict=True) == path)
        C.require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        C.require(path not in self.untrusted)
        if not directory:
            C.require(info.st_nlink == 1)
        return info

    def sync_directory(self, path):
        self.events.append(('directory-fsync-policy', str(path)))

    def open_lock(self, path):
        fd, binding = super().open_lock(path)
        self.handles[fd] = (str(path), binding)
        return fd, binding

    def close_lock(self, fd):
        super().close_lock(fd); self.handles.pop(fd); self.descriptor_overrides.pop(fd, None)

    def write(self, path, value):
        self.events.append(('write', path.name))
        failure = self.failures.pop(path.name, None)
        if failure == 'before':
            raise OSError('synthetic unconfirmed write before creation')
        super().write(path, value)
        if failure == 'after':
            raise OSError('synthetic unconfirmed write after creation')

    def replace(self, path, value):
        self.events.append(('replace-state', value['phase']))
        failure = self.failures.pop('replace-' + value['phase'], None)
        if failure == 'before':
            raise OSError('synthetic unconfirmed replacement before publication')
        super().replace(path, value)
        if failure == 'after':
            raise OSError('synthetic unconfirmed replacement after publication')


class Clock:
    def __init__(self):
        self.now = 0

    def time(self):
        return self.now

    def sleep(self, amount):
        self.now += amount


class Locks:
    def __init__(self, files):
        self.files, self.held, self.events = files, {}, []
        self.on_block = None
        self.on_acquire = None

    def try_acquire(self, fd, shared):
        path, binding = self.files.handles[fd]
        key = (path, binding[0][0], binding[0][1])
        owners = self.held.get(key, {})
        allowed = not owners or shared and all(owners.values())
        self.events.append(('attempt', Path(path).name, shared, allowed))
        if not allowed:
            callback, self.on_block = self.on_block, None
            if callback:
                callback()
            return False
        self.held.setdefault(key, {})[fd] = shared
        self.events.append(('acquire', Path(path).name, shared))
        callback, self.on_acquire = self.on_acquire, None
        if callback: callback(fd, Path(path).name)
        return True

    def release(self, fd):
        path, binding = self.files.handles[fd]; key = (path, binding[0][0], binding[0][1])
        shared = self.held[key].pop(fd)
        if not self.held[key]:
            del self.held[key]
        self.events.append(('release', Path(path).name, shared))


class Tests(unittest.TestCase):
    def fixture(self, initialize=True):
        # Only the company test runner supplies this override; it is not a
        # platform/application setting. Retain fixtures in the selected root.
        local = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local')))
        self.assertTrue(local.is_absolute())
        self.assertEqual(local.resolve(strict=True), local)
        self.assertTrue(local.is_dir())
        directory = Path(tempfile.mkdtemp(prefix='checkpoint-admission-v1-', dir=local)).resolve()
        self.assertEqual(directory.parent, local.resolve())
        data = directory / 'data'; data.mkdir(); (data / 'quota').mkdir()
        files = Files(); locks = Locks(files); clock = Clock()
        gate = C.Gate(data, files=files, locks=locks, clock=clock.time, sleep=clock.sleep)
        if initialize:
            gate.initialize(INSTALLATION)
        return gate, files, locks, clock

    def rebuild(self, gate, files, locks, clock):
        return C.Gate(gate.data, files=files, locks=locks, clock=clock.time, sleep=clock.sleep)

    def test_missing_state_fails_closed_without_initialization_or_writes(self):
        gate, files, _, _ = self.fixture(False)
        events = list(files.events)
        for action in (gate.status, lambda: gate.admit(REQUEST), lambda: gate.close('checkpoint-1')):
            with self.assertRaises((ValueError, FileNotFoundError)):
                action()
        self.assertFalse(gate.base.exists()); self.assertEqual(files.events, events)

    def test_initialization_is_explicit_root_bound_and_refuses_overwrite(self):
        gate, files, _, _ = self.fixture()
        state = gate.status()
        self.assertEqual((state['phase'], state['scope'], state['backupReady']), ('OPEN', 'PRIMITIVE_ONLY', False))
        before = files.read(gate.base / 'initialization.json')
        with self.assertRaises(C.AdmissionUnavailable):
            gate.initialize(INSTALLATION)
        self.assertEqual(before, files.read(gate.base / 'initialization.json'))

    def test_interrupted_initialization_retains_evidence_and_cannot_auto_open(self):
        for failure in ('before', 'after'):
            with self.subTest(failure=failure):
                gate, files, locks, clock = self.fixture(False); files.failures['initialized.json'] = failure
                with self.assertRaises(OSError): gate.initialize(INSTALLATION)
                self.assertTrue((gate.base / 'initialization.json').exists())
                self.assertTrue((gate.base / 'initialization-unconfirmed.json').exists())
                with self.assertRaises((C.AdmissionUnavailable, FileNotFoundError)): self.rebuild(gate, files, locks, clock).status()
                with self.assertRaises(C.AdmissionUnavailable): gate.initialize(INSTALLATION)

    def test_shared_leases_have_unique_exact_durable_intents_and_stay_held_through_confirmation(self):
        gate, files, locks, _ = self.fixture()
        one = gate.admit(REQUEST); two = gate.admit(REQUEST)
        self.assertNotEqual(one.operation_id, two.operation_id)
        self.assertEqual(len(next(owners for key, owners in locks.held.items() if key[0].endswith('activity.lock'))), 2)
        one.mark_possible_effect(); one.complete(OUTCOME)
        self.assertEqual(files.read(gate.base / 'operations' / one.operation_id / 'completed.json')['status'], 'confirmed')
        self.assertTrue(one.live)
        one.release(); two.abort_before_effect(); two.release()
        self.assertFalse(locks.held)

    def test_close_commits_before_wait_and_releases_coordinator_for_admitted_completion(self):
        gate, files, locks, _ = self.fixture(); lease = gate.admit(REQUEST)
        fence = gate.close('checkpoint-ordered')
        self.assertEqual(files.read(gate.base / 'state.json')['phase'], 'CLOSED')
        def finish():
            self.assertFalse(any(key[0].endswith('coordinator.lock') for key in locks.held))
            lease.mark_possible_effect(); lease.complete(OUTCOME); lease.release()
        locks.on_block = finish
        ready = gate.readiness(fence, timeout=0.1)
        self.assertEqual(ready.evidence['scope'], 'PRIMITIVE_ONLY'); self.assertFalse(ready.evidence['backupReady'])
        ready.finish_scope_and_reopen(); ready.release()
        self.assertEqual(gate.status()['phase'], 'OPEN')

    def test_close_denies_new_admission_without_creating_another_intent(self):
        gate, files, _, _ = self.fixture(); lease = gate.admit(REQUEST); fence = gate.close('checkpoint-race')
        count = len(list((gate.base / 'operations').iterdir()))
        with self.assertRaises(C.AdmissionUnavailable): gate.admit(REQUEST)
        self.assertEqual(len(list((gate.base / 'operations').iterdir())), count)
        lease.abort_before_effect(); lease.release(); gate.abort_and_reopen(fence)
        self.assertEqual(gate.status()['phase'], 'OPEN')

    def test_unresolved_intent_blocks_readiness_after_release_and_reconstruction(self):
        gate, files, locks, clock = self.fixture(); lease = gate.admit(REQUEST); operation = lease.operation_id; lease.release()
        fence = gate.close('checkpoint-crash'); rebuilt = self.rebuild(gate, files, locks, clock)
        for action in (lambda: rebuilt.readiness(fence), lambda: rebuilt.abort_and_reopen(fence)):
            with self.assertRaisesRegex(C.AdmissionUnavailable, 'Unresolved'): action()
        self.assertTrue((gate.base / 'operations' / operation / 'intent.json').exists()); self.assertFalse(locks.held)
        with self.assertRaises(C.AdmissionUnavailable): lease.complete(OUTCOME)

    def test_effect_marker_prevents_abort_and_no_exception_or_expiry_completes_it(self):
        gate, _, _, clock = self.fixture()
        with self.assertRaises(RuntimeError):
            with gate.admit(REQUEST) as lease:
                lease.mark_possible_effect()
                with self.assertRaises(C.AdmissionUnavailable): lease.abort_before_effect()
                raise RuntimeError('synthetic caller interruption')
        clock.now = 10**9
        fence = gate.close('checkpoint-expired')
        with self.assertRaises(C.AdmissionUnavailable): gate.readiness(fence)

    def test_failed_intent_creation_never_returns_permission_and_retains_partial_run(self):
        gate, files, locks, _ = self.fixture(); files.failures['intent.json'] = 'before'
        with self.assertRaises(OSError): gate.admit(REQUEST)
        self.assertFalse(locks.held); self.assertEqual(len(list((gate.base / 'operations').iterdir())), 1)
        with self.assertRaises(FileNotFoundError): gate.close('checkpoint-no-dispatch')

    def test_completion_confirmation_failure_retains_unknown_even_if_terminal_bytes_exist(self):
        gate, files, locks, clock = self.fixture(); lease = gate.admit(REQUEST); lease.mark_possible_effect()
        files.failures['completed.json'] = 'after'
        with self.assertRaises(OSError): lease.complete(OUTCOME)
        lease.release(); fence = gate.close('checkpoint-completion')
        run = gate.base / 'operations' / lease.operation_id
        self.assertTrue((run / 'completed.json').exists()); self.assertTrue((run / 'uncertain.json').exists())
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'Unconfirmed'): self.rebuild(gate, files, locks, clock).readiness(fence)

    def test_valid_explicit_terminal_is_authoritative_when_the_optional_uncertainty_marker_cannot_be_created(self):
        # This qualifies the transport limit, not an inferred provider outcome:
        # complete() already receives the caller's independently checked result.
        gate, files, locks, clock = self.fixture(); lease = gate.admit(REQUEST); lease.mark_possible_effect()
        files.failures['completed.json'] = 'after'; files.failures['uncertain.json'] = 'before'
        with self.assertRaises(OSError): lease.complete(OUTCOME)
        run = gate.base / 'operations' / lease.operation_id
        self.assertEqual(files.read(run / 'completed.json')['outcomeSha256'], OUTCOME)
        self.assertFalse((run / 'uncertain.json').exists()); lease.release()
        rebuilt = self.rebuild(gate, files, locks, clock); fence = rebuilt.close('checkpoint-explicit-terminal')
        ready = rebuilt.readiness(fence)
        self.assertFalse(ready.evidence['backupReady']); ready.release()

    def test_abort_before_effect_is_exact_explicit_and_preserves_all_records(self):
        gate, _, _, _ = self.fixture()
        with gate.admit(REQUEST) as lease:
            lease.abort_before_effect()
            with self.assertRaises(C.AdmissionUnavailable): lease.mark_possible_effect()
        fence = gate.close('checkpoint-abort'); gate.abort_and_reopen(fence)
        self.assertTrue((gate.base / 'operations' / lease.operation_id / 'intent.json').exists())
        self.assertTrue((gate.base / 'fences' / fence['fenceId'] / 'terminal.json').exists())
        with self.assertRaises(C.AdmissionUnavailable): gate.abort_and_reopen(fence)

    def test_wrong_checkpoint_fence_root_or_generation_cannot_reopen(self):
        gate, _, _, _ = self.fixture(); fence = gate.close('checkpoint-exact')
        for field, value in [('checkpointId', 'different'), ('fenceId', 'f' * 32), ('dataRootSha256', 'f' * 64), ('generation', True)]:
            with self.subTest(field=field):
                wrong = dict(fence, **{field: value})
                with self.assertRaises((C.AdmissionUnavailable, FileNotFoundError)): gate.abort_and_reopen(wrong)
        self.assertEqual(gate.status()['phase'], 'CLOSED'); gate.abort_and_reopen(fence)

    def test_released_readiness_does_not_reopen_or_authorize_an_abort(self):
        gate, files, locks, clock = self.fixture(); fence = gate.close('checkpoint-retained')
        ready = gate.readiness(fence); ready.release()
        self.assertEqual(gate.status()['phase'], 'CLOSED')
        with self.assertRaises(C.AdmissionUnavailable): ready.finish_scope_and_reopen()
        with self.assertRaises(C.AdmissionUnavailable): self.rebuild(gate, files, locks, clock).abort_and_reopen(fence)
        with self.assertRaises(FileExistsError): gate.readiness(fence)

    def test_failed_close_and_reopen_publish_keep_gate_closed_after_reconstruction(self):
        gate, files, locks, clock = self.fixture(); files.failures['replace-CLOSED'] = 'before'
        with self.assertRaises(OSError): gate.close('checkpoint-partial-close')
        with self.assertRaises(C.AdmissionUnavailable): self.rebuild(gate, files, locks, clock).admit(REQUEST)
        gate, files, locks, clock = self.fixture(); fence = gate.close('checkpoint-partial-open')
        files.failures['reopened.json'] = 'after'
        with self.assertRaises(OSError): gate.abort_and_reopen(fence)
        self.assertEqual(files.read(gate.base / 'state.json')['phase'], 'OPEN')
        with self.assertRaises(C.AdmissionUnavailable): self.rebuild(gate, files, locks, clock).admit(REQUEST)

    def test_lock_replacement_between_calls_is_rejected_by_initialization_binding(self):
        for name in ('coordinator.lock', 'activity.lock'):
            with self.subTest(name=name):
                gate, _, _, _ = self.fixture(); lock = gate.base / name
                old = gate.base.parent / (name + '.retained'); os.replace(lock, old); lock.write_bytes(b'')
                with self.assertRaisesRegex(C.AdmissionUnavailable, 'Held checkpoint lock|replaced'): gate.status()
                self.assertTrue(old.exists())

    def test_lock_replacement_during_wait_is_detected_without_dispatch(self):
        gate, files, locks, _ = self.fixture(); lease = gate.admit(REQUEST); fence = gate.close('checkpoint-replaced')
        def replace():
            # Windows rejects rename of an open file. Inject the Linux-visible
            # identity replacement at the adapter boundary; between-call
            # replacement above still performs actual filesystem replacement.
            files.displaced_locks.add(gate.base / 'activity.lock')
        locks.on_block = replace
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'identity changed'): gate.readiness(fence, timeout=0.1)
        with self.assertRaises(C.AdmissionUnavailable): lease.release()
        self.assertFalse(locks.held)

    def test_waits_are_bounded_and_timeout_never_resolves_active_or_unknown_work(self):
        gate, _, locks, clock = self.fixture(); lease = gate.admit(REQUEST); fence = gate.close('checkpoint-bounded')
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'expired'): gate.readiness(fence, timeout=0.025)
        self.assertGreaterEqual(clock.now, 0.025); self.assertLessEqual(clock.now, 0.026)
        lease.release()
        with self.assertRaises(C.AdmissionUnavailable): gate.readiness(fence)
        for timeout in (0, -1, True, 51, float('nan'), float('inf')):
            with self.assertRaises(C.AdmissionUnavailable): gate.readiness(fence, timeout=timeout)
        self.assertFalse(locks.held)

    def test_malformed_duplicate_boolean_or_unexplained_evidence_fails_closed(self):
        for variant in ('duplicate', 'boolean', 'unknown'):
            with self.subTest(variant=variant):
                gate, files, _, _ = self.fixture()
                if variant == 'unknown': (gate.base / 'unexplained.pending').write_bytes(b'retained')
                elif variant == 'duplicate': (gate.base / 'state.json').write_bytes(b'{"phase":"OPEN","phase":"OPEN"}')
                else:
                    state = files.read(gate.base / 'state.json'); state['generation'] = True
                    (gate.base / 'state.json').write_bytes(C.canonical(state))
                with self.assertRaises(C.AdmissionUnavailable): gate.admit(REQUEST)

    def test_untrusted_root_or_record_and_hardlinked_record_are_rejected(self):
        gate, files, _, _ = self.fixture(); files.untrusted.add(gate.data)
        with self.assertRaises(C.AdmissionUnavailable): gate.status()
        gate, files, _, _ = self.fixture(); files.untrusted.add(gate.base / 'state.json')
        with self.assertRaises(C.AdmissionUnavailable): gate.status()
        gate, _, _, _ = self.fixture(); os.link(gate.base / 'state.json', gate.base.parent / 'state-retained-hardlink.json')
        with self.assertRaises(C.AdmissionUnavailable): gate.status()

    def test_invalid_identifiers_digests_and_unbounded_inputs_dispatch_nothing(self):
        gate, files, _, _ = self.fixture(); before = list(files.events)
        for value in ('', '../escape', False, 'x' * 129, [], 'with space'):
            with self.assertRaises(C.AdmissionUnavailable): gate.close(value)
        for value in ('', 'g' * 64, 'a' * 63, False, []):
            with self.assertRaises(C.AdmissionUnavailable): gate.admit(value)
        self.assertEqual(files.events, before)

    def test_native_continuity_requires_change_time_and_fixture_cross_views_remain_separately_stable(self):
        base = dict(st_dev=1, st_ino=2, st_mode=0o100600, st_uid=0, st_gid=0, st_nlink=1, st_size=3, st_mtime_ns=4, st_ctime_ns=5)
        one = SimpleNamespace(**base); changed = SimpleNamespace(**dict(base, st_ctime_ns=6))
        with self.assertRaises(C.AdmissionUnavailable): C.NativeFiles().compare_opened(one, changed)
        files = Files(); files.compare_opened(one, changed)
        self.assertNotEqual(C.identity(one), C.identity(changed))

    def test_native_directory_policy_allows_stable_group_but_rejects_writable_or_nonroot_paths(self):
        gate, _, _, _ = self.fixture(False)
        directory = gate.data
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=12345, st_nlink=1)
        with patch.object(Path, 'lstat', return_value=info): C.NativeFiles().protected(directory, directory=True)
        for changed in (dict(st_mode=stat.S_IFDIR | 0o775, st_uid=0, st_gid=12345, st_nlink=1), dict(st_mode=stat.S_IFDIR | 0o755, st_uid=10001, st_gid=0, st_nlink=1)):
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(**changed)):
                with self.assertRaises(C.AdmissionUnavailable): C.NativeFiles().protected(directory, directory=True)

    def test_replacing_operations_directory_cannot_hide_a_released_unknown_intent(self):
        gate, files, locks, clock = self.fixture(); lease = gate.admit(REQUEST); lease.release(); fence = gate.close('checkpoint-directory')
        operations = gate.base / 'operations'; retained = gate.base.parent / 'retained-operations'
        os.replace(operations, retained); operations.mkdir()
        rebuilt = self.rebuild(gate, files, locks, clock)
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'directory was replaced'): rebuilt.readiness(fence)
        self.assertTrue((retained / lease.operation_id / 'intent.json').exists())
        self.assertFalse((gate.base / 'fences' / fence['fenceId'] / 'ready.json').exists())

    def test_inventory_replacement_is_rejected_before_readiness_evidence(self):
        gate, files, _, _ = self.fixture(); fence = gate.close('checkpoint-inventory')
        def swap(path):
            if path == gate.base:
                operations = gate.base / 'operations'
                os.replace(operations, gate.base.parent / 'retained-during-inventory'); operations.mkdir()
        files.on_inventory = swap
        with self.assertRaises(C.AdmissionUnavailable): gate.readiness(fence)
        self.assertFalse((gate.base / 'fences' / fence['fenceId'] / 'ready.json').exists())

    def test_changed_quota_parent_policy_blocks_mutation_before_lock_dispatch(self):
        gate, files, locks, _ = self.fixture(); before = len(locks.events)
        files.untrusted.add(gate.data / 'quota')
        with self.assertRaises(C.AdmissionUnavailable): gate.admit(REQUEST)
        self.assertEqual(len(locks.events), before)

    def test_held_coordinator_ABA_identity_cannot_mutate_even_when_current_path_matches_initialization(self):
        gate, files, locks, _ = self.fixture(); writes = len(files.events)
        def swapped_fd(fd, name):
            self.assertEqual(name, 'coordinator.lock')
            files.descriptor_overrides[fd] = {'st_ino': os.fstat(fd).st_ino + 1000}
        locks.on_acquire = swapped_fd
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'Held checkpoint lock'): gate.admit(REQUEST)
        self.assertFalse(list((gate.base / 'operations').iterdir()))
        self.assertEqual(len([event for event in files.events[writes:] if event[0] == 'write']), 0)
        self.assertFalse(locks.held)

    def test_open_scope_keeps_exclusive_lease_until_release_and_new_admission_never_waits_with_coordinator(self):
        gate, _, locks, clock = self.fixture(); fence = gate.close('checkpoint-exclusive')
        ready = gate.readiness(fence); ready.finish_scope_and_reopen(); before = clock.now
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'immediate admission'): gate.admit(REQUEST)
        self.assertEqual(clock.now, before); ready.release()
        lease = gate.admit(REQUEST); lease.abort_before_effect(); lease.release(); self.assertFalse(locks.held)

    def test_reopen_requires_the_exact_actually_held_exclusive_activity_descriptor(self):
        gate, _, _, _ = self.fixture(); operation = gate.admit(REQUEST); fence = gate.close('checkpoint-own-ex')
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'exact live activity'): gate._reopen(fence, operation.activity_fd)
        operation.abort_before_effect(); operation.release()
        ready = gate.readiness(fence)
        ready.activity.__exit__(None, None, None)
        with self.assertRaisesRegex(C.AdmissionUnavailable, 'exact live activity'): ready.finish_scope_and_reopen()
        self.assertEqual(gate.status()['phase'], 'CLOSED'); ready.release()

    def test_concurrent_release_cannot_drop_the_lease_during_confirmation_or_reopen(self):
        for stage in ('operation', 'readiness'):
            with self.subTest(stage=stage):
                gate, _, locks, _ = self.fixture()
                entered, proceed, releasing, released = (threading.Event() for _ in range(4))
                errors = []
                if stage == 'operation':
                    lease = gate.admit(REQUEST); original = gate._write
                    def delayed(path, value):
                        if path.name == 'completed.json':
                            entered.set(); self.assertTrue(proceed.wait(2))
                        return original(path, value)
                    method, call = '_write', lambda: lease.complete(OUTCOME)
                else:
                    fence = gate.close('checkpoint-racing-release'); lease = gate.readiness(fence); original = gate._reopen
                    def delayed(*args, **kwargs):
                        entered.set(); self.assertTrue(proceed.wait(2))
                        return original(*args, **kwargs)
                    method, call = '_reopen', lease.finish_scope_and_reopen
                def finish():
                    try: call()
                    except BaseException as error: errors.append(error)
                def release():
                    releasing.set()
                    try: lease.release()
                    except BaseException as error: errors.append(error)
                    finally: released.set()
                finisher, releaser = threading.Thread(target=finish, daemon=True), threading.Thread(target=release, daemon=True)
                with patch.object(gate, method, side_effect=delayed):
                    finisher.start()
                    try:
                        self.assertTrue(entered.wait(2)); releaser.start(); self.assertTrue(releasing.wait(2))
                        self.assertFalse(released.wait(0.03))
                        self.assertTrue(lease.live)
                        self.assertIn(lease.activity_fd, gate._held)
                    finally:
                        proceed.set(); finisher.join(3)
                        if releaser.ident is not None: releaser.join(3)
                self.assertFalse(finisher.is_alive()); self.assertFalse(releaser.is_alive()); self.assertEqual(errors, [])
                self.assertFalse(locks.held)
                if stage == 'operation':
                    fence = gate.close('checkpoint-confirmed-release'); gate.abort_and_reopen(fence)
                self.assertEqual(gate.status()['phase'], 'OPEN')

    def test_unrelated_lease_release_cannot_close_a_descriptor_during_registry_validation(self):
        gate, files, locks, _ = self.fixture(); one = gate.admit(REQUEST); two = gate.admit(REQUEST); two.abort_before_effect()
        entered, proceed, releasing, released = (threading.Event() for _ in range(4)); errors = []
        original = files.check_lock; paused = False
        def delayed(path, fd, expected):
            nonlocal paused
            if fd == two.activity_fd and not paused:
                paused = True; entered.set(); self.assertTrue(proceed.wait(2))
            return original(path, fd, expected)
        def finish():
            try: one.complete(OUTCOME)
            except BaseException as error: errors.append(error)
        def release():
            releasing.set()
            try: two.release()
            except BaseException as error: errors.append(error)
            finally: released.set()
        finisher, releaser = threading.Thread(target=finish, daemon=True), threading.Thread(target=release, daemon=True)
        with patch.object(files, 'check_lock', side_effect=delayed):
            finisher.start()
            try:
                self.assertTrue(entered.wait(2)); releaser.start(); self.assertTrue(releasing.wait(2))
                self.assertFalse(released.wait(0.03)); self.assertIn(two.activity_fd, gate._held)
            finally:
                proceed.set(); finisher.join(3)
                if releaser.ident is not None: releaser.join(3)
        self.assertFalse(finisher.is_alive()); self.assertFalse(releaser.is_alive()); self.assertEqual(errors, [])
        one.release(); self.assertFalse(locks.held)
        fence = gate.close('checkpoint-safe-registry'); gate.abort_and_reopen(fence)
        self.assertEqual(gate.status()['phase'], 'OPEN')


if __name__ == '__main__':
    unittest.main(verbosity=2)
