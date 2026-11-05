"""Actual filesystem fixtures for advisory-only installation diagnostics."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installation_status', ROOT / 'scripts/installation-status.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.session = 's-123456ABCDEF'
        self.base = 'etc/autosoft-install-admission/sessions/' + self.session
        self.request = 'a' * 64
        self.action = 'b' * 64
        self.outcome = 'c' * 64

    def write(self, name, value=''):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding='ascii')

    def session_intent(self):
        self.write('etc/autosoft-install-admission/install.lock')
        self.write('etc/autosoft-install-admission/binding', 'not authenticated by this diagnostic')
        self.write(self.base + '/intent', f'install-session-v1\nsession={self.session}\nrequest={self.request}\nbinding=1:2\ndirectory=3:4\nclosed=true\n')

    def stage(self, confirmed=False):
        self.session_intent()
        self.write(self.base + '/foundation.intent', f'install-stage-v1\nsession={self.session}\nstage=foundation\naction={self.action}\nclosed=true\n')
        if confirmed:
            self.write(self.base + '/foundation.confirmed', f'install-stage-confirmed-v1\nsession={self.session}\nstage=foundation\naction={self.action}\noutcome={self.outcome}\nindependently_confirmed=true\n')

    def complete(self):
        self.stage(True)
        self.write(self.base + '/complete', f'install-complete-v1\nsession={self.session}\nrequest={self.request}\nmanifest={self.action}\nfinal={self.outcome}\nindependently_confirmed=true\n')

    def test_fresh_checkout_reports_missing_bootstrap_without_writes(self):
        before = list(self.root.iterdir())
        result = M.inspect(self.root)
        self.assertEqual(result['state'], 'not_started')
        self.assertFalse(result['trustedBootstrapPresent'])
        self.assertFalse(result['mayResume'])
        self.assertFalse(result['installationVerified'])
        self.assertEqual(list(self.root.iterdir()), before)
        self.assertIn('signed release', ' '.join(result['actions']))

    def test_pending_stage_is_actionable_and_records_stay_identical(self):
        self.stage()
        self.write('etc/autosoft/storage.key', 'SECRET-UNLOCK-KEY-MUST-NEVER-BE-READ')
        self.write('etc/autosoft/installation.pending.json', '{"secret":"PRIVATE"}')
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
        original = M.Files.read
        read_names = []
        def read(files, name):
            read_names.append(name)
            self.assertNotIn(name, ('etc/autosoft/storage.key', 'etc/autosoft/installation.pending.json'))
            return original(files, name)
        with patch.object(M.Files, 'read', read):
            result = M.inspect(self.root)
        self.assertEqual(result['state'], 'incomplete')
        self.assertEqual(result['sessions'][0]['stages'], [{'stage': 'foundation', 'observation': 'intent_without_confirmation'}])
        self.assertIn('Do not rerun fresh setup', ' '.join(result['actions']))
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('SECRET-UNLOCK', json.dumps(result))
        after = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_foundation_confirmation_is_not_platform_installation(self):
        self.complete()
        result = M.inspect(self.root)
        self.assertEqual(result['state'], 'incomplete')
        self.assertTrue(result['sessions'][0]['completeRecordPresent'])
        self.assertFalse(result['installationVerified'])
        self.assertFalse(result['mayResume'])

    def test_recorded_completion_still_requires_current_startup_checks(self):
        self.complete()
        self.write('etc/autosoft/installation.json', '{}')
        self.write('etc/autosoft/installation.complete')
        result = M.inspect(self.root)
        self.assertEqual(result['state'], 'completion_recorded')
        self.assertFalse(result['installationVerified'])
        self.assertIn('autosoft check', ' '.join(result['actions']))
        self.write('etc/autosoft/installation.pending.json', '{}')
        self.assertEqual(M.inspect(self.root)['state'], 'inspection_unavailable')

    def test_conflicting_confirmation_is_unavailable(self):
        self.stage(True)
        path = self.root / self.base / 'foundation.confirmed'
        path.write_text(path.read_text().replace(self.action, 'd' * 64), encoding='ascii')
        self.assertEqual(M.inspect(self.root)['state'], 'inspection_unavailable')

    def test_partial_namespace_and_oversized_record_are_not_clean_setup(self):
        self.write('etc/autosoft-install-admission/binding')
        self.assertEqual(M.inspect(self.root)['state'], 'inspection_unavailable')
        self.stage()
        self.write(self.base + '/foundation.intent', 'x' * (M.MAX_RECORD + 1))
        self.assertEqual(M.inspect(self.root)['state'], 'inspection_unavailable')

    def test_unknown_filename_and_orphan_confirmation_are_bounded_errors(self):
        self.stage()
        self.write(self.base + '/SECRET-CREDENTIAL-TEXT')
        result = M.inspect(self.root)
        self.assertEqual(result['state'], 'inspection_unavailable')
        self.assertNotIn('SECRET-CREDENTIAL-TEXT', json.dumps(result))
        (self.root / self.base / 'SECRET-CREDENTIAL-TEXT').unlink()
        self.write(self.base + '/other.confirmed')
        self.assertEqual(M.inspect(self.root)['state'], 'inspection_unavailable')

    def test_linked_records_are_never_read(self):
        self.stage()
        original = M.Files.path
        def linked(files, name):
            if name.endswith('foundation.intent'):
                raise M.Unavailable('linked_record')
            return original(files, name)
        with patch.object(M.Files, 'path', linked):
            self.assertEqual(M.inspect(self.root)['state'], 'inspection_unavailable')

    def test_entrypoints_dispatch_status_before_install_or_service_actions(self):
        install = (ROOT / 'scripts/install.sh').read_text(encoding='utf-8')
        direct = install[install.index('if [[ "${BASH_SOURCE[0]:-}" = "$0" ]]'):]
        self.assertLess(direct.index('= --status'), direct.index('/opt/autosoft-company/bootstrap/company-install.sh'))
        maintenance = (ROOT / 'scripts/autosoft.sh').read_text(encoding='utf-8')
        self.assertLess(maintenance.index('= installation-status'), maintenance.index('source "$SCRIPT_DIR/lib.sh"'))
        self.assertIn('exec python3 -I -B "$SCRIPT_DIR/installation-status.py" "$@"', maintenance)


if __name__ == '__main__':
    unittest.main()
