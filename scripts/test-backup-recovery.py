#!/usr/bin/env python3
"""Injected interruption and storage-boundary regressions; no Docker dispatch."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import backup_recovery as R
import backup_quiescence as Q


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        previous_mask = os.umask(0o077)
        self.addCleanup(os.umask, previous_mask)
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent.parent / '.local')
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name).resolve()
        if os.name == 'nt':
            sync = patch.object(R, 'sync_directory')
            sync.start(); self.addCleanup(sync.stop)
        self.a, self.b = 'a' * 64, 'b' * 64
        self.initial = {key: dict(profileSha256=key, stateSha256='1'*64, running=True, cleanStopped=False) for key in (self.a, self.b)}
        self.current = copy.deepcopy(self.initial)
        self.calls, self.reads = [], []
        self.journal = R.BackupJournal(self.data)

    def begin(self):
        self.journal.begin('nightly', self.initial)

    def stopped(self, identifier):
        self.journal.record('stop-intent', identifier)
        self.current[identifier].update(stateSha256='2'*64, running=False, cleanStopped=True)
        self.journal.record('stopped', identifier, state='2'*64)

    def observe(self, identifier):
        self.reads.append(identifier)
        return copy.deepcopy(self.current[identifier])

    def start(self, identifier):
        loaded = R.BackupJournal(self.data)
        self.assertTrue(loaded.load())
        self.assertIsNotNone(loaded.read_event(identifier + '-start-intent.json'))
        self.calls.append(identifier)
        self.current[identifier].update(stateSha256='3'*64, running=True, cleanStopped=False)

    def test_missing_status_is_read_only_and_never_initializes_storage(self):
        self.assertEqual(R.reconcile(self.data, self.observe)['status'], 'no_pending_recovery')
        self.assertFalse((self.data / 'backups').exists())
        self.assertEqual(self.reads, [])

    def test_fresh_backup_blocks_before_reading_any_container(self):
        self.begin()
        def denied(*args): self.fail('Pending checkpoint dispatched control')
        with self.assertRaisesRegex(ValueError, 'Pending backup recovery'):
            with Q.QuiescedContainers(self.data, 'nightly', denied, denied): pass

    def test_readonly_reconciliation_preserves_all_journal_bytes(self):
        self.begin(); self.stopped(self.a)
        before = {p.name: p.read_bytes() for p in self.journal.run.iterdir()}
        pointer = self.journal.active.read_bytes()
        result = R.reconcile(self.data, self.observe)
        self.assertEqual(result['originals'][self.a], 'confirmed_stopped')
        self.assertEqual(result['startsDispatched'], 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.journal.run.iterdir()})
        self.assertEqual(pointer, self.journal.active.read_bytes())

    def test_interrupted_checkpoint_resumes_only_recorded_stopped_original(self):
        self.begin(); self.stopped(self.a); self.journal.failure()
        result = R.reconcile(self.data, self.observe, self.start)
        self.assertEqual(self.calls, [self.a])
        self.assertEqual(result['status'], 'originals_resumed_backup_unverified')
        self.assertFalse(result['backupVerified'])
        self.assertFalse(self.journal.active.exists())
        self.assertTrue((self.journal.run / 'checkpoint-failed.json').exists())

    def test_stop_intent_without_confirmation_is_retained_even_if_running(self):
        self.begin(); self.journal.record('stop-intent', self.a)
        result = R.reconcile(self.data, self.observe, self.start)
        self.assertEqual(result['status'], 'pending_company_review')
        self.assertEqual(self.calls, [])
        self.assertTrue(self.journal.active.exists())

    def test_start_intent_without_confirmation_is_not_retried(self):
        self.begin(); self.stopped(self.a)
        self.journal.record('start-intent', self.a)
        self.current[self.a].update(running=True, cleanStopped=False, stateSha256='3'*64)
        for _ in range(2):
            self.assertEqual(R.reconcile(self.data, self.observe, self.start)['status'], 'pending_company_review')
        self.assertEqual(self.calls, [])

    def test_uncertain_start_still_resumes_other_original_and_never_retries(self):
        self.begin(); self.stopped(self.a); self.stopped(self.b)
        def fail(identifier):
            self.start(identifier)
            if identifier == self.a: raise RuntimeError('SECRET provider response')
        result = R.reconcile(self.data, self.observe, fail)
        self.assertEqual(self.calls, [self.a, self.b])
        self.assertEqual(result['status'], 'pending_company_review')
        self.assertEqual(R.reconcile(self.data, self.observe, self.start)['status'], 'pending_company_review')
        self.assertEqual(self.calls, [self.a, self.b])
        self.assertNotIn('SECRET', ''.join(p.read_text() for p in self.journal.run.iterdir()))

    def test_changed_profile_or_stopped_state_is_never_started(self):
        for key, value in [('profileSha256', 'f'*64), ('stateSha256', 'f'*64), ('cleanStopped', False)]:
            with self.subTest(key=key):
                self.begin(); self.stopped(self.a)
                self.current[self.a][key] = value
                self.assertEqual(R.reconcile(self.data, self.observe, self.start)['status'], 'pending_company_review')
                self.assertEqual(self.calls, [])
                # Separate synthetic roots retain each failed case.
                self.setUp()

    def test_original_externally_stopped_without_our_stop_intent_is_not_started(self):
        self.begin()
        self.current[self.a].update(running=False, cleanStopped=True, stateSha256='2'*64)
        self.assertEqual(R.reconcile(self.data, self.observe, self.start)['status'], 'pending_company_review')
        self.assertEqual(self.calls, [])

    def test_final_readers_all_run_after_first_initial_reader_failure(self):
        self.begin(); self.stopped(self.b)
        def faulty(identifier):
            self.reads.append(identifier)
            if identifier == self.a: raise RuntimeError('SECRET inspect error')
            return copy.deepcopy(self.current[identifier])
        result = R.reconcile(self.data, faulty, self.start)
        self.assertEqual(result['status'], 'pending_company_review')
        self.assertEqual(self.calls, [self.b])
        self.assertEqual(self.reads.count(self.a), 2)
        self.assertGreaterEqual(self.reads.count(self.b), 4)

    def test_final_lifecycle_drift_prevents_completion(self):
        self.begin(); self.stopped(self.a)
        counts = {self.a: 0, self.b: 0}
        def changed(identifier):
            counts[identifier] += 1
            result = self.observe(identifier)
            if identifier == self.a and counts[identifier] == 4: result['stateSha256'] = 'f'*64
            return result
        self.assertEqual(R.reconcile(self.data, changed, self.start)['status'], 'pending_company_review')
        self.assertTrue(self.journal.active.exists())
        self.assertFalse((self.journal.run / 'completed.json').exists())

    def test_readonly_final_stopped_state_drift_is_reported_uncertain_without_writes(self):
        self.begin(); self.stopped(self.a)
        counts = {self.a: 0, self.b: 0}
        def changed(identifier):
            counts[identifier] += 1
            result = self.observe(identifier)
            if identifier == self.a and counts[identifier] == 2: result['stateSha256'] = 'f'*64
            return result
        before = {path.name: path.read_bytes() for path in self.journal.run.iterdir()}
        result = R.reconcile(self.data, changed)
        self.assertEqual(result['originals'][self.a], 'uncertain')
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.journal.run.iterdir()})

    def test_directory_sync_failure_before_stop_prevents_all_control_mutations(self):
        with patch.object(R, 'sync_directory', side_effect=OSError('disk fault')):
            with self.assertRaises(OSError): self.begin()
        self.assertEqual(self.calls, [])

    def test_start_intent_directory_sync_failure_prevents_start_and_retains_fence(self):
        self.begin(); self.stopped(self.a)
        with patch.object(R, 'sync_directory', side_effect=OSError('disk fault')):
            result = R.reconcile(self.data, self.observe, self.start)
        self.assertEqual(result['status'], 'pending_company_review')
        self.assertEqual(self.calls, [])
        self.assertTrue((self.journal.run / (self.a + '-start-intent.json')).exists())
        self.assertTrue(self.journal.active.exists())

    def test_start_intent_file_sync_failure_prevents_start_and_retains_uncertainty(self):
        self.begin(); self.stopped(self.a)
        with patch.object(R.os, 'fsync', side_effect=OSError('file sync fault')):
            result = R.reconcile(self.data, self.observe, self.start)
        self.assertEqual(result['status'], 'pending_company_review')
        self.assertEqual(self.calls, [])
        self.assertTrue(self.journal.active.exists())

    def test_record_fdopen_startup_failure_closes_owned_descriptor(self):
        path = self.data / 'partial.json'
        original_close = R.os.close
        with patch.object(R.os, 'fdopen', side_effect=OSError('descriptor setup')), patch.object(R.os, 'close', wraps=original_close) as closed:
            with self.assertRaises(OSError): R.write_record(path, {'schemaVersion': 1})
        closed.assert_called_once()
        self.assertTrue(path.exists())

    def test_pointer_change_blocks_start_before_command(self):
        self.begin(); self.stopped(self.a)
        calls = 0
        def replaced(identifier):
            nonlocal calls
            calls += 1
            if calls == 2:
                pointer = json.loads(self.journal.active.read_text())
                pointer['intentSha256'] = 'f'*64
                self.journal.active.write_bytes(R.canonical(pointer))
            return self.observe(identifier)
        with self.assertRaisesRegex(ValueError, 'pointer changed'):
            R.reconcile(self.data, replaced, self.start)
        self.assertEqual(self.calls, [])

    def test_closed_schema_and_extra_members_block_before_any_start(self):
        for kind in ('bool-version', 'extra-field', 'missing-field', 'wrong-hash', 'extra-member'):
            with self.subTest(kind=kind):
                self.begin(); self.stopped(self.a)
                path = self.journal.active
                pointer = json.loads(path.read_text())
                if kind == 'bool-version': pointer['schemaVersion'] = True
                if kind == 'extra-field': pointer['foreign'] = 1
                if kind == 'missing-field': del pointer['operationId']
                if kind == 'wrong-hash': pointer['intentSha256'] = 'f'*64
                if kind == 'extra-member': (self.journal.run / 'foreign.json').write_text('{}')
                path.write_bytes(R.canonical(pointer))
                with self.assertRaises(ValueError): R.reconcile(self.data, self.observe, self.start)
                self.assertEqual(self.calls, [])
                self.setUp()

    def test_out_of_order_event_blocks_otherwise_valid_start(self):
        self.begin(); self.stopped(self.a)
        self.journal.record('running', self.b, state='3'*64)
        with self.assertRaisesRegex(ValueError, 'order'):
            R.reconcile(self.data, self.observe, self.start)
        self.assertEqual(self.calls, [])

    def test_duplicate_json_invalid_utf8_and_hardlink_records_are_rejected(self):
        path = self.data / 'record.json'
        for raw in (b'{"a":1,"a":2}', b'{"a":"\xff"}', b'{"a":NaN}'):
            path.write_bytes(raw)
            with self.assertRaises((ValueError, UnicodeError)): R.read_record(path)
        path.write_text('{}')
        link = self.data / 'linked.json'
        os.link(path, link)
        with self.assertRaisesRegex(ValueError, 'ambiguous ownership'): R.read_record(path)

    def test_link_and_special_directory_protection_rejects_before_read(self):
        # Actual metadata admits ordinary records; mocked classification
        # exercises symlink rejection without requiring Windows link privilege.
        path = self.data / 'record.json'; path.write_text('{}')
        with patch.object(R.stat, 'S_ISREG', return_value=False):
            with self.assertRaisesRegex(ValueError, 'linked or special'): R.read_record(path)
        self.assertEqual(R.read_record(path), {})

    def test_intent_never_records_environment_paths_or_backup_success(self):
        self.begin(); self.stopped(self.a)
        raw = b''.join(p.read_bytes() for p in self.journal.run.iterdir())
        self.assertNotIn(str(self.data).encode(), raw)
        self.assertNotIn(b'Env', raw)
        self.assertFalse(self.journal.intent['backupVerified'])

    def test_observation_strict_types_and_impossible_running_stopped_pair(self):
        for key, value in [('running', 1), ('cleanStopped', 0), ('cleanStopped', True), ('stateSha256', 1)]:
            invalid = copy.deepcopy(self.initial[self.a]); invalid[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): R.observation(invalid)

    def test_default_control_is_fixed_local_host_with_clean_environment(self):
        with patch.object(Q, '_local_command', return_value=['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'start', self.a]), patch.object(Q.subprocess, 'run') as run:
            Q._execute(['docker', 'start', self.a])
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        self.assertEqual(run.call_args.kwargs['timeout'], 120)
        with self.assertRaisesRegex(ValueError, 'Unknown checkpoint control'):
            Q._local_command(['docker', 'restart', self.a])

    def test_default_control_socket_and_exact_id_denials(self):
        from types import SimpleNamespace
        import stat
        socket = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
        with patch.object(Q.Path, 'resolve', return_value=Path('/run/docker.sock')), patch.object(Q.Path, 'stat', return_value=socket):
            self.assertEqual(Q._local_command(['docker', 'inspect', self.a]), ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'inspect', self.a])
            self.assertEqual(Q._local_command(['docker', 'stop', '--time', '60', self.a])[-4:], ['stop', '--time', '60', self.a])
            with self.assertRaises(ValueError): Q._local_command(['docker', 'start', 'owned-name'])
            socket.st_mode = stat.S_IFSOCK | 0o666
            with self.assertRaisesRegex(ValueError, 'socket'): Q._local_command(['docker', 'start', self.a])
            socket.st_mode = stat.S_IFREG | 0o660
            with self.assertRaisesRegex(ValueError, 'socket'): Q._local_command(['docker', 'start', self.a])

    def test_capture_size_and_deadline_failure_kill_reap_close(self):
        from unittest.mock import Mock
        for kind in ('size', 'deadline'):
            process = Mock(); process.poll.return_value = None
            selector = Mock(); selector.get_map.return_value = True
            selector.select.return_value = [(type('Key', (), {'fd': 3})(), 1)]
            with self.subTest(kind=kind), patch.object(Q, '_local_command', return_value=['fixed']), patch.object(Q.subprocess, 'Popen', return_value=process), patch.object(Q.selectors, 'DefaultSelector', return_value=selector), patch.object(Q.os, 'read', return_value=b'x' * (2 * 1024**2 + 1)), patch.object(Q.time, 'monotonic', side_effect=[0, 31] if kind == 'deadline' else [0, 1]):
                with self.assertRaisesRegex(ValueError, 'timed out' if kind == 'deadline' else 'bound'):
                    Q._capture(['unused'])
            process.kill.assert_called_once(); process.wait.assert_called_once_with(timeout=5)
            process.stdout.close.assert_called_once(); selector.close.assert_called_once()

    def test_capture_setup_failure_reaps_child_and_closes_pipe(self):
        from unittest.mock import Mock
        process = Mock(); process.poll.return_value = None
        selector = Mock(); selector.register.side_effect = OSError('setup fault')
        with patch.object(Q, '_local_command', return_value=['fixed']), patch.object(Q.subprocess, 'Popen', return_value=process), patch.object(Q.selectors, 'DefaultSelector', return_value=selector):
            with self.assertRaises(OSError): Q._capture(['unused'])
        process.kill.assert_called_once(); process.wait.assert_called_once_with(timeout=5)
        process.stdout.close.assert_called_once(); selector.close.assert_called_once()


class MaintenanceIntegrationTests(unittest.TestCase):
    def test_actual_backup_and_incremental_block_before_destination_creation(self):
        source = Path(__file__).with_name('maintenance.py').read_text()
        module = ast.parse(source)
        cls = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == 'Maintenance')
        for name in ('backup', 'incremental'):
            method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
            code = compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), '<maintenance>', 'exec')
            class Denied:
                @staticmethod
                def require_idle(data): raise ValueError('Pending backup recovery')
            scope = {'QuiescedContainers': Denied}
            exec(code, scope)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Pending backup recovery'):
                scope[name](type('Fixture', (), {'data': Path('must-not-be-created')})())

    def test_actual_status_and_resume_delegate_fixed_mode_and_never_claim_backup_pass(self):
        from unittest.mock import Mock
        source = Path(__file__).with_name('maintenance.py').read_text()
        cls = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == 'Maintenance')
        for name, resume in (('backup_recovery_status', False), ('backup_recovery_resume', True)):
            method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
            helper = Mock(); helper.recover.return_value = {'status': 'pending_company_review', 'backupVerified': False}
            scope = {'QuiescedContainers': helper, 'json': json, 'print': Mock()}
            exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), '<maintenance>', 'exec'), scope)
            instance = type('Fixture', (), {'data': Path('encrypted-data')})()
            if resume:
                with self.assertRaisesRegex(ValueError, 'remain uncertain'): scope[name](instance)
                helper.recover.assert_called_once_with(instance.data, resume=True)
            else:
                self.assertFalse(scope[name](instance)['backupVerified'])
                helper.recover.assert_called_once_with(instance.data)


if __name__ == '__main__': unittest.main()
