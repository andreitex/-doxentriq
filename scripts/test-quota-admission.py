"""Retained local/injected HOST_QUOTA_ONLY controls; never native XFS/flock."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

Q = load('quota_admission_runtime', ROOT / 'scripts/quota_runtime.py')
B = load('quota_admission_files_policy', ROOT / 'test/test_checkpoint_admission.py')
A, C = Q._allocation, Q._allocation.C
APP = 'd9224505-f564-44e5-a697-16e1451fc44a'
INSTALLATION = '64a2a5f8-04b9-43b5-9807-122d866db1f1'
REQUEST = dict(appId=APP, name='documents', sizeMb=16)
KEY = APP + '/documents'


class Files(B.Files):
    def write(self, path, value):
        self.events.append(('journal', str(path)))
        return super().write(path, value)

    def replace(self, path, value):
        self.events.append(('replace', str(path)))
        failure = self.failures.pop('replace-' + path.parent.name + '-' + path.name, None)
        if failure == 'before': raise OSError('synthetic replacement before publication')
        B.C.NativeFiles.replace(self, path, value)
        if failure == 'after': raise OSError('synthetic replacement after publication')


class Lease:
    def __init__(self, fixture, lease):
        self.fixture, self.lease = fixture, lease
        self.operation_id = lease.operation_id
    def mark_possible_effect(self):
        self.fixture.events.append(('effect-attempt',))
        if self.fixture.marker_failure: raise OSError('synthetic lost marker acknowledgement')
        return self.lease.mark_possible_effect()
    def complete(self, outcome):
        self.fixture.events.append(('completion-attempt',))
        self.lease.complete(outcome)
        if self.fixture.completion_failure: raise OSError('synthetic lost terminal acknowledgement')
    def abort_before_effect(self):
        self.fixture.events.append(('abort-before-effect',))
        return self.lease.abort_before_effect()
    def release(self):
        self.fixture.events.append(('admission-release',))
        return self.lease.release()


class Fixture:
    def __init__(self, initialize=True, initialize_gate=True):
        local = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local')))
        assert local.is_absolute() and local.resolve(strict=True) == local and local.is_dir()
        self.directory = Path(tempfile.mkdtemp(prefix='quota-admission-v1-', dir=local)).resolve()
        self.data = self.directory / 'data'; self.data.mkdir()
        (self.data / 'quota').mkdir(); (self.data / 'runtime').mkdir(); (self.data / 'runtime/storage').mkdir()
        self.files = Files(); self.clock = B.Clock(); self.locks = B.Locks(self.files)
        self.events = self.files.events; self.locks.events = self.events
        self.leases = []; self.owners = {}; self.marker_failure = self.completion_failure = False
        self.write_failure = self.native_failure = self.final_failure = False
        self.on_native = None
        if initialize_gate: self.gate().initialize(INSTALLATION)
        if initialize: self.allocation().initialize(INSTALLATION, read_state=self.read, write_state=self.write)
        self.events.clear()

    def gate(self): return C.Gate(self.data, files=self.files, locks=self.locks, clock=self.clock.time, sleep=self.clock.sleep)
    def allocation(self): return A.Allocation(self.data, files=self.files, locks=self.locks, clock=self.clock.time, sleep=self.clock.sleep)
    def gate_factory(self, _):
        fixture = self
        class Gate:
            def admit(self, request):
                fixture.events.append(('admit',))
                lease = Lease(fixture, fixture.gate().admit(request)); fixture.leases.append(lease)
                return lease
        return Gate()
    def read(self, path):
        self.events.append(('projects-read',))
        return Q.validate_state(self.files.read(path))
    def write(self, path, value):
        Q.validate_state(value)
        self.events.append(('projects-write', next(iter(value['projects'].values()))['status'] if value['projects'] else 'empty'))
        if self.write_failure: raise OSError('synthetic project write failure')
        if path.exists(): self.files.replace(path, value)
        else: self.files.write(path, value)
    def mount(self, *_): self.events.append(('mount',)); return 'synthetic-encrypted-XFS'
    def command(self, args):
        self.events.append(('native', 'limit' if 'limit ' in ' '.join(args) else 'project'))
        if self.on_native: self.on_native()
        if self.native_failure: raise OSError('synthetic native outcome unavailable')
        return ''
    def limits(self, data, path, record, source, command):
        self.events.append(('limits', record['status']))
        if self.final_failure and record['status'] == 'active': raise OSError('synthetic final readback failure')
    def sync(self, _): self.events.append(('directory-sync',))
    def chown(self, path, uid, gid): self.events.append(('chown',)); self.owners[path] = (uid, gid)
    def call(self, value=None):
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path not in self.owners: return info
            fields = {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
            fields['st_uid'], fields['st_gid'] = self.owners[path]
            return types.SimpleNamespace(**fields)
        with patch.object(Q, 'protected_directory'), patch.object(Q.os, 'chown', self.chown, create=True), patch.object(Q.stat, 'S_IMODE', return_value=0o755), patch.object(Path, 'lstat', lstat):
            return Q.provision(self.data, value or REQUEST, command=self.command, read_state=self.read, write_state=self.write,
                               limits=self.limits, mount=self.mount, sync=self.sync,
                               gate_factory=self.gate_factory, allocation_factory=lambda _: self.allocation())
    def operation(self, index=-1):
        path = self.gate().base / 'operations' / self.leases[index].operation_id
        return path, self.files.read(path / 'completed.json') if (path / 'completed.json').exists() else None


class Controls(unittest.TestCase):
    def test_validation_and_mount_failure_precede_admission(self):
        events = []
        def gate(_): events.append('admit'); raise AssertionError('must not admit')
        def mount(*_): events.append('mount'); raise OSError('synthetic mount failure')
        with self.assertRaises(ValueError): Q.provision(Path('/synthetic'), dict(REQUEST, sizeMb=True), mount=mount, gate_factory=gate)
        self.assertEqual(events, [])
        with self.assertRaises(OSError): Q.provision(Path('/synthetic'), REQUEST, mount=mount, gate_factory=gate)
        self.assertEqual(events, ['mount'])

    def test_closed_gate_denies_before_projects_and_allocator(self):
        f = Fixture(); f.gate().close('quota-test-closed'); f.events.clear()
        with self.assertRaises(ValueError): f.call()
        self.assertEqual(f.events[0], ('mount',)); self.assertNotIn(('projects-read',), f.events)
        self.assertFalse(any(row[0] == 'native' for row in f.events))

    def test_missing_gate_is_not_initialized_by_provision(self):
        f = Fixture(initialize_gate=False)
        with self.assertRaises((ValueError, FileNotFoundError)): f.call()
        self.assertFalse((f.data / 'quota/checkpoint-admission').exists())

    def test_missing_allocator_aborts_only_before_any_business_effect(self):
        f = Fixture(initialize=False)
        with self.assertRaises((ValueError, FileNotFoundError)): f.call()
        path, completed = f.operation()
        self.assertEqual(completed['status'], 'aborted_before_effect')
        self.assertFalse((path / 'effect.json').exists()); self.assertFalse((f.data / 'quota/allocation').exists())

    def test_missing_projects_never_defaults_empty_or_reuses_id(self):
        f = Fixture(); projects = f.data / 'quota/projects.json'
        projects.rename(f.data / 'quota/retained-projects.json')
        with self.assertRaises(FileNotFoundError): f.call()
        self.assertNotIn(('effect-attempt',), f.events); self.assertFalse(projects.exists())
        with patch.object(Q, 'protected_directory'):
            with self.assertRaises(ValueError): Q.load_state(projects)

    def test_lifetime_order_marks_before_pending_and_confirms_after_exact_final_readback(self):
        f = Fixture(); result = f.call(); rows = f.events
        def at(row): return rows.index(row)
        self.assertLess(at(('mount',)), at(('admit',)))
        self.assertLess(at(('acquire', 'activity.lock', True)), at(('acquire', 'allocation.lock', False)))
        self.assertLess(at(('acquire', 'allocation.lock', False)), at(('projects-read',)))
        self.assertLess(at(('effect-attempt',)), at(('projects-write', 'pending')))
        self.assertLess(at(('projects-write', 'pending')), at(('native', 'project')))
        self.assertLess(at(('projects-write', 'active')), at(('limits', 'active')))
        self.assertLess(at(('limits', 'active')), at(('completion-attempt',)))
        self.assertLess(at(('completion-attempt',)), at(('release', 'allocation.lock', False)))
        self.assertLess(at(('release', 'allocation.lock', False)), at(('release', 'activity.lock', True)))
        self.assertEqual(result['projectId'], 10000); self.assertTrue(result['quotaEnforced'])
        self.assertEqual(f.operation()[1]['status'], 'confirmed')

    def test_two_separate_allocator_instances_contend_on_same_persistent_inode(self):
        f = Fixture(); first, second = f.allocation(), f.allocation()
        with first.acquire() as held:
            before = f.files.protected(first.base / 'allocation.lock')
            with self.assertRaises(ValueError):
                with second.acquire(timeout=.05): self.fail('concurrent allocation entered')
            self.assertLessEqual(f.clock.now, .06)
            self.assertEqual(C.lock_binding(before), C.lock_binding(f.files.protected(first.base / 'allocation.lock')))
            self.assertEqual(held.read_state(f.read), A.EMPTY_STATE)
        with second.acquire() as held: self.assertEqual(held.read_state(f.read), A.EMPTY_STATE)

    def test_released_lease_cannot_use_a_later_reused_descriptor(self):
        f = Fixture()
        with f.allocation().acquire() as stale:
            self.assertEqual(stale.read_state(f.read), A.EMPTY_STATE)
        self.assertFalse(stale.live)
        with f.allocation().acquire() as current:
            # Align the saved numeric FD as an injected ABA control even on a
            # host whose descriptor allocator chooses another free slot.
            stale.fd = current.fd
            before = f.files.inventory(f.data / 'quota/allocation/commits', 1)
            with self.assertRaises(ValueError): stale.read_state(f.read)
            with self.assertRaises(ValueError): stale.commit(copy.deepcopy(A.EMPTY_STATE), read_state=f.read, write_state=f.write)
            self.assertEqual(f.files.inventory(f.data / 'quota/allocation/commits', 1), before)
            self.assertEqual(current.read_state(f.read), A.EMPTY_STATE)

    def test_lease_rejects_foreign_thread_without_touching_state(self):
        f = Fixture(); failures = []
        with f.allocation().acquire() as held:
            f.events.clear()
            def read():
                try: held.read_state(f.read)
                except ValueError: failures.append(True)
            thread = threading.Thread(target=read); thread.start(); thread.join(2)
            self.assertFalse(thread.is_alive()); self.assertEqual(failures, [True])
            self.assertNotIn(('projects-read',), f.events)
            self.assertEqual(held.read_state(f.read), A.EMPTY_STATE)

    def test_admitted_work_can_complete_while_closed_readiness_waits_for_shared_lease(self):
        f = Fixture(); fences = []
        def checkpoint():
            if fences: return
            fence = f.gate().close('quota-in-flight'); fences.append(fence)
            with self.assertRaises(ValueError): f.gate().readiness(fence, timeout=.05)
        f.on_native = checkpoint; f.call()
        ready = f.gate().readiness(fences[0]); self.assertFalse(ready.evidence['backupReady'])
        ready.finish_scope_and_reopen(); ready.release()

    def test_lost_effect_marker_acknowledgement_never_aborts_or_dispatches(self):
        f = Fixture(); f.marker_failure = True
        with self.assertRaises(OSError): f.call()
        path, completed = f.operation(); self.assertIsNone(completed)
        self.assertNotIn(('abort-before-effect',), f.events)
        self.assertFalse(any(row[0] == 'native' for row in f.events))
        fence = f.gate().close('unknown-marker')
        with self.assertRaises(ValueError): f.gate().readiness(fence)

    def test_failed_pending_commit_retains_intent_and_never_creates_storage(self):
        f = Fixture(); f.write_failure = True
        with self.assertRaises(OSError): f.call()
        path, completed = f.operation(); self.assertIsNone(completed); self.assertTrue((path / 'effect.json').exists())
        self.assertFalse((f.data / 'runtime/storage' / APP).exists())
        self.assertTrue((f.data / 'quota/allocation/commits/0000000001/intent.json').exists())
        f.write_failure = False
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(any(row[0] == 'native' for row in f.events))

    def test_pointer_publication_failure_keeps_unknown_and_blocks_partial_commit(self):
        f = Fixture(); f.files.failures['replace-allocation-state.json'] = 'before'
        with self.assertRaises(OSError): f.call()
        self.assertIsNone(f.operation()[1])
        self.assertFalse((f.data / 'runtime/storage' / APP).exists())
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(any(row[0] == 'native' for row in f.events))

    def test_lost_pointer_ack_does_not_replay_pending_or_complete_old_operation(self):
        f = Fixture(); f.files.failures['replace-allocation-state.json'] = 'after'
        with self.assertRaises(OSError): f.call()
        self.assertIsNone(f.operation()[1])
        self.assertEqual(f.read(f.data / 'quota/projects.json')['projects'][KEY]['status'], 'pending')
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(any(row[0] == 'native' for row in f.events))

    def test_allocation_release_error_still_releases_shared_admission_without_success_ack(self):
        f = Fixture(); original = f.locks.release
        def release(fd):
            name = Path(f.files.handles[fd][0]).name
            original(fd)
            if name == 'allocation.lock': raise OSError('synthetic lost unlock acknowledgement')
        f.locks.release = release
        with self.assertRaises(OSError): f.call()
        self.assertIn(('release', 'activity.lock', True), f.events)
        self.assertEqual(f.operation()[1]['status'], 'confirmed')
        self.assertFalse(f.locks.held)

    def test_missing_or_malformed_initialization_never_creates_or_resets_metadata(self):
        for kind in ('missing', 'malformed'):
            f = Fixture(); path = f.data / 'quota/allocation/initialized.json'
            if kind == 'missing': path.rename(f.data / 'quota/retained-allocation-initialized.json')
            else: f.files.replace(path, {'initializationSha256': '0' * 64})
            with self.assertRaises((ValueError, FileNotFoundError)): f.call()
            self.assertNotIn(('effect-attempt',), f.events)
            self.assertFalse(any(row[0] == 'native' for row in f.events))

    def test_native_unknown_retains_pending_without_replay_and_blocks_readiness(self):
        f = Fixture(); f.native_failure = True
        with self.assertRaises(OSError): f.call()
        self.assertEqual(f.read(f.data / 'quota/projects.json')['projects'][KEY]['status'], 'pending')
        before = sum(row[0] == 'native' for row in f.events)
        f.native_failure = False
        with self.assertRaises(ValueError): f.call()
        self.assertEqual(sum(row[0] == 'native' for row in f.events), before)
        fence = f.gate().close('native-unknown')
        with self.assertRaises(ValueError): f.gate().readiness(fence)

    def test_projects_reset_is_detected_without_reusing_allocated_id(self):
        f = Fixture(); f.call(); f.files.replace(f.data / 'quota/projects.json', copy.deepcopy(A.EMPTY_STATE))
        before = sum(row[0] == 'native' for row in f.events)
        with self.assertRaises(ValueError): f.call(dict(REQUEST, name='other'))
        self.assertEqual(sum(row[0] == 'native' for row in f.events), before)

    def test_partial_active_commit_blocks_instead_of_adopting_active_projects(self):
        f = Fixture(); original = f.write
        def fail(path, value):
            original(path, value)
            if value['projects'][KEY]['status'] == 'active': raise OSError('lost active write acknowledgement')
        f.write = fail
        with self.assertRaises(OSError): f.call()
        self.assertEqual(f.read(f.data / 'quota/projects.json')['projects'][KEY]['status'], 'active')
        f.write = original
        with self.assertRaises(ValueError): f.call()
        self.assertIsNone(f.operation(0)[1])

    def test_final_native_readback_failure_never_asserts_completion(self):
        f = Fixture(); f.final_failure = True
        with self.assertRaises(OSError): f.call()
        self.assertEqual(f.read(f.data / 'quota/projects.json')['projects'][KEY]['status'], 'active')
        self.assertIsNone(f.operation()[1]); self.assertNotIn(('abort-before-effect',), f.events)

    def test_final_wrong_ownership_cannot_assert_completion(self):
        f = Fixture(); f.chown = lambda *_: None
        with self.assertRaises(ValueError): f.call()
        self.assertIsNone(f.operation()[1]); self.assertNotIn(('abort-before-effect',), f.events)

    def test_nested_other_filesystem_is_rejected_before_allocator_initialization_writes(self):
        f = Fixture(initialize=False); original = f.files.protected
        def protected(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == f.data / 'quota':
                values = {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                values['st_dev'] += 1
                return types.SimpleNamespace(**values)
            return info
        f.files.protected = protected
        with self.assertRaises(ValueError): f.allocation().initialize(INSTALLATION, read_state=f.read, write_state=f.write)
        self.assertFalse((f.data / 'quota/allocation').exists()); self.assertFalse((f.data / 'quota/projects.json').exists())

    def test_terminal_ack_failure_preserves_valid_confirmed_outcome_and_business_data(self):
        f = Fixture(); f.completion_failure = True
        with self.assertRaises(OSError): f.call()
        self.assertEqual(f.operation()[1]['status'], 'confirmed')
        self.assertNotIn(('abort-before-effect',), f.events)
        f.completion_failure = False; f.events.clear()
        result = f.call(); self.assertEqual(result['projectId'], 10000)
        self.assertFalse(any(row[0] in ('native', 'projects-write', 'chown') for row in f.events))

    def test_replaced_lock_and_foreign_held_descriptor_are_rejected_before_projects_read(self):
        f = Fixture(); lock = f.data / 'quota/allocation/allocation.lock'
        lock.rename(f.data / 'quota/retained-allocation.lock'); f.files.create_lock(lock)
        with self.assertRaises(ValueError): f.call()
        self.assertNotIn(('projects-read',), f.events)
        other = Fixture()
        def acquired(fd, name):
            if name == 'allocation.lock': other.files.descriptor_overrides[fd] = {'st_ino': other.files.descriptor(fd).st_ino + 1}
            else: other.locks.on_acquire = acquired
        other.locks.on_acquire = acquired
        with self.assertRaises(ValueError): other.call()
        self.assertNotIn(('projects-read',), other.events)

    def test_replaced_commit_directory_cannot_hide_allocation_history(self):
        f = Fixture(); f.call(); commits = f.data / 'quota/allocation/commits'
        commits.rename(f.data / 'quota/retained-allocation-commits'); commits.mkdir()
        with self.assertRaises(ValueError): f.call(dict(REQUEST, name='other'))
        self.assertTrue((f.data / 'quota/retained-allocation-commits/0000000002/confirmed.json').exists())

    def test_older_pointer_cannot_hide_retained_newer_commits(self):
        f = Fixture(); pointer = f.files.read(f.data / 'quota/allocation/state.json'); f.call()
        f.files.replace(f.data / 'quota/allocation/state.json', pointer)
        with self.assertRaises(ValueError): f.call(dict(REQUEST, name='other'))

    def test_explicit_fresh_initialization_requires_mount_and_existing_gate(self):
        f = Fixture(initialize=False)
        Q.initialize_allocation(f.data, INSTALLATION, mount=f.mount, read_state=f.read, write_state=f.write,
                                gate_factory=f.gate_factory, allocation_factory=lambda _: f.allocation())
        self.assertEqual(f.operation()[1]['status'], 'confirmed')
        with self.assertRaises(ValueError):
            Q.initialize_allocation(f.data, INSTALLATION, mount=f.mount, read_state=f.read, write_state=f.write,
                                    gate_factory=f.gate_factory, allocation_factory=lambda _: f.allocation())
        missing = Fixture(initialize=False, initialize_gate=False)
        with self.assertRaises((ValueError, FileNotFoundError)):
            Q.initialize_allocation(missing.data, INSTALLATION, mount=missing.mount, read_state=missing.read, write_state=missing.write,
                                    gate_factory=missing.gate_factory, allocation_factory=lambda _: missing.allocation())
        self.assertFalse((missing.data / 'quota/allocation').exists())

    def test_initialization_refuses_existing_projects_storage_or_partial_metadata(self):
        for kind in ('projects', 'storage', 'partial'):
            f = Fixture(initialize=False)
            if kind == 'projects': f.files.write(f.data / 'quota/projects.json', copy.deepcopy(A.EMPTY_STATE))
            elif kind == 'storage': (f.data / 'runtime/storage/retained').mkdir()
            else: (f.data / 'quota/allocation').mkdir()
            with self.assertRaises(ValueError): f.allocation().initialize(INSTALLATION, read_state=f.read, write_state=f.write)
            self.assertFalse((f.data / 'quota/allocation/initialized.json').exists())


if __name__ == '__main__': unittest.main(verbosity=2)
