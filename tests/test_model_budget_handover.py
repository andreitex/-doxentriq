"""No model requests; durable filesystem controls also run as root on Linux."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch

if sys.platform == 'win32':
    from types import SimpleNamespace
    sys.modules.setdefault('fcntl', SimpleNamespace())


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).resolve().parents[1] / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


M = load('model-test-budget')
H = load('model-budget-handover')


def ledger():
    value = M.new_ledger('30', 'UTC')
    run = M.reserve(value, '2026-10', '2')
    value = M.account_maximum(value, run['id'], 'b' * 64)
    value['runs'].append(dict(id='c' * 32, month='2026-10', reservedMicrousd=1_000_000, spentMicrousd=895128, status='settled', createdAt='2026-10-01T00:00:00Z', reportSha256='d' * 64))
    return value


class HandoverTests(unittest.TestCase):
    def test_exact_shared_allowance_preserves_conservative_unknown_outcome(self):
        original = ledger()
        before = deepcopy(original)
        grant = H.prepare(M, original, 'a' * 64, 'https://admin.example.test', '2026-10')
        self.assertEqual(grant['allocationMicrousd'], 27104872)
        self.assertEqual(grant['confirmedExternalMicrousd'], 895128)
        self.assertEqual(grant['conservativeExternalMicrousd'], 2000000)
        self.assertEqual(original, before)

    def test_no_allocation_when_any_prior_call_is_unknown(self):
        original = M.new_ledger('30', 'UTC')
        M.reserve(original, '2026-09', '2')
        with self.assertRaises(M.UncertainBillingError):
            H.prepare(M, original, 'a' * 64, 'https://admin.example.test', '2026-10')

    def test_old_and_updated_company_runners_fail_closed_after_handover(self):
        original = ledger()
        original['runs'].append(dict(id='e' * 32, month='2026-10', reservedMicrousd=27104872, spentMicrousd=0, status='allocated', createdAt='2026-10-01', reportSha256='f' * 64))
        M.validate(original, '30', 'UTC')
        for month in ('2026-10', '2026-11'):
            with self.assertRaisesRegex(ValueError, 'handed over'):
                M.reserve(original, month, '.01')
        self.assertEqual(M.accounting(original, '2026-10')['allocatedMicrousd'], 27104872)
        with self.assertRaisesRegex(ValueError, 'committed'):
            M.amend_limit(original, '30', '29', 'UTC')

    def test_malformed_target_and_month_refuse_handover(self):
        for origin in ('http://admin.example.test', 'https://user:pass@admin.example.test', 'https://admin.example.test/path', 'https://admin.example.test?x=1', 'https://ADMIN.example.test', 'https://admin.example.test:443', 'https://admin.example.test\n'):
            with self.assertRaises(ValueError):
                H.prepare(M, ledger(), 'a' * 64, origin, '2026-10')
        with self.assertRaises(ValueError):
            H.prepare(M, ledger(), 'a' * 64, 'https://admin.example.test', '2026-13')

    def test_exhausted_allowance_cannot_be_duplicated(self):
        original = ledger()
        original['runs'][1]['spentMicrousd'] = 28_000_000
        with self.assertRaisesRegex(ValueError, 'No remaining'):
            H.prepare(M, original, 'a' * 64, 'https://admin.example.test', '2026-10')


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Root Linux private-file qualification')
class DurableHandoverTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/root'))
        self.directory = os.open(self.folder.name, os.O_RDONLY | os.O_DIRECTORY)
        self.original = M.new_ledger('30', 'UTC')
        self.before_hash = M.durable_json(self.directory, 'monthly.json', self.original)

    def tearDown(self):
        os.close(self.directory)
        self.folder.cleanup()

    def invoke(self):
        return H.handover(M, self.directory, self.before_hash, '30', 'UTC', 'https://admin.example.test')

    def test_commit_before_export_and_identical_recovery_no_second_allocation(self):
        grant = self.invoke()
        committed = json.loads(M.private_read(self.directory, 'monthly.json'))
        self.assertEqual(len(committed['runs']), 1)
        self.assertEqual(committed['runs'][0]['status'], 'allocated')
        self.assertEqual(self.invoke(), grant)
        self.assertEqual(json.loads(M.private_read(self.directory, 'monthly.json')), committed)
        with self.assertRaises(ValueError):
            M.reserve(committed, grant['month'], '.1')

    def test_crash_before_ledger_commit_does_not_export_an_authority(self):
        real = M.durable_json
        def fail_commit(directory, name, value):
            if name == 'monthly.json':
                raise OSError('Simulated interrupted commit')
            return real(directory, name, value)
        with patch.object(M, 'durable_json', fail_commit), self.assertRaises(OSError):
            self.invoke()
        self.assertEqual(hashlib.sha256(M.private_read(self.directory, 'monthly.json')).hexdigest(), self.before_hash)
        grant = self.invoke()
        self.assertEqual(grant['allocationMicrousd'], 30_000_000)
        self.assertEqual(len(json.loads(M.private_read(self.directory, 'monthly.json'))['runs']), 1)

    def test_changed_ledger_and_changed_evidence_refuse_recovery(self):
        with self.assertRaisesRegex(ValueError, 'changed after review'):
            H.handover(M, self.directory, 'f' * 64, '30', 'UTC', 'https://admin.example.test')
        grant = self.invoke()
        M.durable_json(self.directory, 'allocation-' + grant['id'] + '.json', {**grant, 'allocationMicrousd': 1})
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            self.invoke()

    def test_exact_original_ledger_preserved_and_protected(self):
        original = M.private_read(self.directory, 'monthly.json')
        grant = self.invoke()
        self.assertEqual(M.private_read(self.directory, 'allocation-' + grant['id'] + '.before.json'), original)
        for path in Path(self.folder.name).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_cli_cannot_handover_while_company_runner_holds_original_lock(self):
        checked = M.open_private_directory(self.folder.name)
        os.close(checked)
        command = [sys.executable, '-I', '-B', H.__file__, '--state-dir', self.folder.name,
                   '--expected-ledger-sha256', self.before_hash, '--monthly-max-usd', '30',
                   '--timezone', 'UTC', '--admin-origin', 'https://admin.example.test']
        fd = os.open(Path(self.folder.name) / 'monthly.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            M.fcntl.flock(fd, M.fcntl.LOCK_EX | M.fcntl.LOCK_NB)
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)['errorCode'], 'budget_handover_stopped')
            self.assertEqual(hashlib.sha256(M.private_read(self.directory, 'monthly.json')).hexdigest(), self.before_hash)
        finally:
            os.close(fd)
        admitted = subprocess.run(command, capture_output=True, timeout=15)
        self.assertEqual(admitted.returncode, 0)
        self.assertEqual(json.loads(admitted.stdout)['allocationMicrousd'], 30_000_000)
        self.assertEqual(json.loads(M.private_read(self.directory, 'monthly.json'))['runs'][0]['status'], 'allocated')


if __name__ == '__main__':
    unittest.main()
