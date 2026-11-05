#!/usr/bin/env python3
"""Adversarial lifecycle tests for coherent backups and original-only resume."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from backup_quiescence import QuiescedContainers
from backup_recovery import BackupJournal


class BackupBoundaryTests(unittest.TestCase):
    def setUp(self):
        local = Path(__file__).resolve().parent.parent / '.local'
        local.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=local)
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name).resolve()
        if os.name == 'nt':
            # Windows cannot open a directory for fsync. Only this POSIX seam
            # is replaced; real exclusive writes, file fsync/readback remain.
            sync = patch('backup_recovery.sync_directory')
            sync.start(); self.addCleanup(sync.stop)
        self.records, self.actions = {}, []
        self.after_stop, self.failed_start = None, set()
        self.add('a', 'mysql'); self.add('b', 'worker'); self.add('c', app='documents')

    def add(self, letter, service=None, app=None):
        identifier = letter * 64
        (self.data / letter).mkdir(exist_ok=True)
        labels = {'io.autosoft.managed': 'true'}
        if service:
            labels.update({'com.docker.compose.project': 'autosoft', 'com.docker.compose.service': service,
                           'com.docker.compose.oneoff': 'False', 'com.docker.compose.container-number': '1'})
        else: labels['io.autosoft.app'] = app
        self.records[identifier] = dict(Id=identifier, Image='sha256:' + 'f'*64, Name='/owned-' + letter,
            Config=dict(Image='company/service@sha256:' + 'e'*64, Labels=labels, Env=['PASSWORD=never-emitted']),
            HostConfig=dict(RestartPolicy={'Name':'unless-stopped'}),
            Mounts=[dict(Type='bind', Source=str(self.data / letter), Destination='/data', RW=True)],
            RestartCount=0,
            State=dict(Running=True, Paused=False, Restarting=False, Dead=False, OOMKilled=False, ExitCode=0,
                       Pid=101, Status='running', StartedAt='2026-10-12T00:00:00Z', FinishedAt='0001-01-01T00:00:00Z'))
        return identifier

    def capture(self, args):
        if args[1] == 'ps':
            self.assertIn('--no-trunc', args)
            return '\n'.join(key for key, item in self.records.items() if item['State']['Running'])
        self.assertEqual(args[1], 'inspect')
        return json.dumps([self.records[args[2]]])

    def execute(self, args):
        self.actions.append(args)
        identifier = args[-1]
        self.assertEqual(len(identifier), 64)
        self.records[identifier]['State']['Running'] = args[1] == 'start'
        self.records[identifier]['State'].update(Pid=102 if args[1] == 'start' else 0, Status='running' if args[1] == 'start' else 'exited')
        self.records[identifier]['State']['FinishedAt'] = '2026-10-12T00:01:00Z'
        if args[1] == 'start': self.records[identifier]['State']['StartedAt'] = '2026-10-12T00:02:00Z'
        if args[1] == 'stop' and self.after_stop: self.after_stop(identifier)
        if args[1] == 'start' and identifier in self.failed_start: raise RuntimeError('Uncertain start')

    def context(self, mode='nightly'):
        return QuiescedContainers(self.data, mode, self.capture, self.execute)

    def test_nightly_stops_exact_originals_then_resumes_after_capture_error(self):
        self.records['d'*64] = copy.deepcopy(self.records['c'*64])
        self.records['d'*64].update(Id='d'*64,Name='/originally-stopped')
        self.records['d'*64]['State']['Running'] = False
        with self.assertRaisesRegex(RuntimeError, 'Capture interrupted'):
            with self.context() as boundary:
                boundary.confirm_boundary()
                self.assertFalse(any(record['State']['Running'] for record in self.records.values()))
                raise RuntimeError('Capture interrupted')
        self.assertTrue(all(self.records[key*64]['State']['Running'] for key in 'abc'))
        self.assertFalse(self.records['d'*64]['State']['Running'])
        self.assertEqual([action[1] for action in self.actions], ['stop']*3 + ['start']*3)

    def test_incremental_leaves_datastores_running_but_stops_control_worker_apps(self):
        self.add('d','redis'); self.add('e','rabbitmq'); self.add('f','control')
        with self.context('incremental') as boundary:
            boundary.confirm_boundary()
            self.assertTrue(all(self.records[key*64]['State']['Running'] for key in 'ade'))
            self.assertFalse(any(self.records[key*64]['State']['Running'] for key in 'bcf'))
        self.assertTrue(all(item['State']['Running'] for item in self.records.values()))

    def test_incremental_packager_is_selected_and_stopped_by_original_id_before_capture(self):
        self.add('d', 'redis'); self.add('e', 'rabbitmq'); self.add('f', 'registry')
        packager = self.add('0', 'packager')
        broker = self.add('1', 'broker'); control = self.add('2', 'control')
        expected = {'b'*64, 'c'*64, packager, broker, control}
        events = []
        def execute(args):
            events.append((args[1], args[-1]))
            self.execute(args)
        boundary = QuiescedContainers(self.data, 'incremental', self.capture, execute)
        self.assertEqual(set(boundary.selected()), expected)
        self.assertEqual(self.actions, [])
        with boundary:
            boundary.confirm_boundary()
            self.assertEqual(set(boundary.journal.intent['originals']), expected)
            self.assertFalse(any(self.records[key]['State']['Running'] for key in expected))
            self.assertTrue(all(self.records[key*64]['State']['Running'] for key in 'adef'))
            # This injected capture callback cannot run before the packager's
            # exact original ID and all other selected writers are stopped.
            events.append(('capture', None))
            self.assertEqual({key for action, key in events if action == 'stop'}, expected)
            self.assertIn(['docker', 'stop', '--time', '60', packager], self.actions)
        capture_index = events.index(('capture', None))
        self.assertEqual(len(events[:capture_index]), len(expected))
        self.assertTrue(all(action == 'stop' for action, _ in events[:capture_index]))
        self.assertEqual({key for action, key in events[capture_index+1:] if action == 'start'}, expected)
        self.assertTrue(all(action == 'start' for action, _ in events[capture_index+1:]))
        self.assertTrue(all(value['State']['Running'] for value in self.records.values()))
        self.assertFalse(boundary.journal.active.exists())

    def test_ambiguous_image_or_owner_or_paused_state_rejects_before_any_stop(self):
        changes = [lambda v: v['Config'].update(Image='company:latest'),
                   lambda v: v['Config']['Labels'].update({'com.docker.compose.oneoff':'True'}),
                   lambda v: v['Config']['Labels'].update({'com.docker.compose.project':'other'}),
                   lambda v: v['Mounts'][0].update(Source=str(self.data.parent / 'foreign')),
                   lambda v: v['State'].update(Paused=True), lambda v: v.update(Id='0'*64)]
        original = copy.deepcopy(self.records)
        for change in changes:
            self.records = copy.deepcopy(original)
            change(self.records['b'*64])
            with self.subTest(change=change), self.assertRaises(ValueError):
                with self.context(): self.fail('Unsafe boundary admitted')
            self.assertEqual(self.actions, [])

    def test_forced_kill_preserves_pending_evidence_without_uncertain_restart(self):
        self.after_stop = lambda identifier: self.records[identifier]['State'].update(ExitCode=137)
        with self.assertRaisesRegex(ValueError,'safely resumed'):
            with self.context(): self.fail('Forced shutdown admitted')
        self.assertEqual([args[-1] for args in self.actions], ['a'*64])
        self.assertFalse(self.records['a'*64]['State']['Running'])
        self.assertTrue(all(self.records[key*64]['State']['Running'] for key in 'bc'))
        with self.assertRaisesRegex(ValueError, 'Pending backup recovery'):
            with self.context(): self.fail('Pending checkpoint admitted')

    def test_new_writer_invalidates_boundary_without_stopping_new_process(self):
        self.after_stop = lambda _: self.add('d',app='new-application')
        with self.assertRaisesRegex(ValueError, 'new or resumed writer'):
            with self.context(): self.fail('Raced checkpoint admitted')
        self.assertNotIn('d'*64, [args[-1] for args in self.actions])

    def test_replaced_configuration_is_never_restarted_and_others_resume(self):
        with self.assertRaisesRegex(ValueError,'safely resumed'):
            with self.context():
                self.records['b'*64]['Mounts'][0]['Source'] = str(self.data.parent / 'replacement')
        self.assertTrue(self.records['a'*64]['State']['Running'])
        self.assertTrue(self.records['c'*64]['State']['Running'])
        self.assertFalse(self.records['b'*64]['State']['Running'])
        self.assertNotIn(['docker','start','b'*64], self.actions)

    def test_same_path_replaced_bind_inode_is_never_restarted(self):
        original = self.data / 'b'
        with self.assertRaisesRegex(ValueError, 'safely resumed'):
            with self.context():
                original.rename(self.data / 'b-retained-original')
                original.mkdir()
        self.assertFalse(self.records['b'*64]['State']['Running'])
        self.assertTrue(all(self.records[key*64]['State']['Running'] for key in 'ac'))
        self.assertNotIn(['docker', 'start', 'b'*64], self.actions)
        self.assertTrue((self.data / 'b-retained-original').is_dir())
        self.assertTrue((self.data / 'backups/quiescence/active.json').exists())

    def test_resume_failure_still_attempts_unaffected_originals(self):
        self.failed_start.add('b'*64)
        with self.assertRaisesRegex(ValueError,'safely resumed'):
            with self.context(): pass
        self.assertIn(['docker','start','c'*64], self.actions)

    def test_resumed_writer_detected_at_final_boundary(self):
        with self.assertRaisesRegex(ValueError,'safely resumed'):
            with self.context() as boundary:
                self.records['b'*64]['State']['Running'] = True
                boundary.confirm_boundary()
        self.assertNotIn(['docker', 'start', 'b'*64], self.actions)
        self.assertTrue((self.data / 'backups/quiescence/active.json').exists())

    def test_durable_intent_precedes_each_stop_and_completion_cannot_verify_backup(self):
        def before_stop(identifier):
            journal = BackupJournal(self.data)
            self.assertTrue(journal.load())
            self.assertIsNotNone(journal.read_event(identifier + '-stop-intent.json'))
        self.after_stop = before_stop
        with self.context(): pass
        journal = BackupJournal(self.data)
        self.assertFalse(journal.active.exists())
        runs = list((journal.base / 'runs').iterdir())
        self.assertEqual(len(runs), 1)
        self.assertFalse(json.loads((runs[0] / 'completed.json').read_text())['backupVerified'])
        self.assertNotIn('PASSWORD', ''.join(path.read_text() for path in runs[0].iterdir()))

    def test_recovery_of_new_process_uses_exact_stopped_receipts(self):
        boundary = self.context().__enter__()
        result = QuiescedContainers.recover(self.data, True, self.capture, self.execute)
        self.assertEqual(result['status'], 'originals_resumed_backup_unverified')
        self.assertEqual(result['startsDispatched'], 3)
        self.assertFalse(result['backupVerified'])
        self.assertFalse(boundary.journal.active.exists())

    def failing_marker(self, boundary, partial=False):
        def fail():
            if partial:
                with (boundary.journal.run / 'checkpoint-failed.json').open('xb') as handle:
                    handle.write(b'{"schemaVersion":')
            raise OSError('Synthetic failure marker persistence fault')
        return patch.object(boundary.journal, 'failure', side_effect=fail)

    def tracking_boundary(self):
        boundary, observed = self.context(), []
        def capture(args):
            if args[1] == 'inspect': observed.append(args[2])
            return self.capture(args)
        boundary.capture = capture
        return boundary, observed

    def test_exit_marker_failure_before_creation_resumes_and_preserves_capture_error(self):
        boundary, observed = self.tracking_boundary()
        interrupted = RuntimeError('Original capture interrupted')
        with self.failing_marker(boundary), self.assertRaises(RuntimeError) as caught:
            with boundary:
                observed.clear()
                raise interrupted
        self.assertIs(caught.exception, interrupted)
        self.assertEqual([args[1] for args in self.actions], ['stop']*3 + ['start']*3)
        self.assertEqual(observed[-3:], [letter*64 for letter in 'abc'])
        self.assertTrue(all(self.records[letter*64]['State']['Running'] for letter in 'abc'))
        self.assertFalse(boundary.journal.active.exists())
        self.assertFalse((boundary.journal.run / 'checkpoint-failed.json').exists())
        self.assertFalse(json.loads((boundary.journal.run / 'completed.json').read_text())['backupVerified'])

    def test_enter_marker_failure_before_creation_resumes_and_preserves_boundary_error(self):
        boundary, observed = self.tracking_boundary()
        self.after_stop = lambda _: self.add('d', app='new-application')
        with self.failing_marker(boundary), self.assertRaisesRegex(ValueError, 'new or resumed writer'):
            with boundary: self.fail('Raced checkpoint admitted')
        self.assertEqual([args[1] for args in self.actions], ['stop']*3 + ['start']*3)
        self.assertEqual(observed[-3:], [letter*64 for letter in 'abc'])
        self.assertTrue(all(self.records[letter*64]['State']['Running'] for letter in 'abc'))
        self.assertNotIn('d'*64, [args[-1] for args in self.actions])
        self.assertFalse(boundary.journal.active.exists())

    def test_exit_partial_failure_marker_blocks_all_recovery_dispatch(self):
        boundary, observed = self.tracking_boundary()
        with self.failing_marker(boundary, partial=True), self.assertRaises(ValueError):
            with boundary:
                observed.clear()
                raise RuntimeError('Original capture interrupted')
        self.assertEqual([args[1] for args in self.actions], ['stop']*3)
        self.assertEqual(observed, [])  # Closed journal validation precedes observation or start.
        self.assertTrue(boundary.journal.active.exists())
        self.assertEqual((boundary.journal.run / 'checkpoint-failed.json').read_bytes(), b'{"schemaVersion":')
        with self.assertRaisesRegex(ValueError, 'Pending backup recovery'):
            with self.context(): self.fail('Invalid journal admitted a new checkpoint')

    def test_enter_partial_failure_marker_blocks_all_recovery_dispatch(self):
        boundary, observed = self.tracking_boundary()
        self.after_stop = lambda _: self.add('d', app='new-application')
        with self.failing_marker(boundary, partial=True), self.assertRaisesRegex(ValueError, 'safely resumed'):
            with boundary: self.fail('Raced checkpoint admitted')
        self.assertEqual([args[1] for args in self.actions], ['stop']*3)
        self.assertTrue(boundary.journal.active.exists())
        self.assertTrue(all(not self.records[letter*64]['State']['Running'] for letter in 'abc'))
        self.assertNotIn('d'*64, [args[-1] for args in self.actions])
        self.assertEqual((boundary.journal.run / 'checkpoint-failed.json').read_bytes(), b'{"schemaVersion":')

    def test_marker_failure_keeps_uncertain_start_fence_and_checks_unaffected_originals(self):
        boundary, observed = self.tracking_boundary()
        self.failed_start.add('b'*64)
        with self.failing_marker(boundary), self.assertRaisesRegex(ValueError, 'safely resumed'):
            with boundary:
                observed.clear()
                raise RuntimeError('Original capture interrupted')
        self.assertEqual([args[1] for args in self.actions], ['stop']*3 + ['start']*3)
        self.assertEqual(observed[-3:], [letter*64 for letter in 'abc'])
        self.assertIn(['docker', 'start', 'c'*64], self.actions)
        self.assertTrue(boundary.journal.active.exists())
        before = copy.deepcopy(self.actions)
        result = QuiescedContainers.recover(self.data, True, self.capture, self.execute)
        self.assertEqual(result['status'], 'pending_company_review')
        self.assertEqual(result['startsDispatched'], 0)
        self.assertEqual(result['originals']['b'*64], 'uncertain')
        self.assertEqual(self.actions, before)


if __name__ == '__main__': unittest.main()
