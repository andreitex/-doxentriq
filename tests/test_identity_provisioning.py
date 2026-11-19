"""Installer identity failures must not automatically replay external mutations."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bootstrap_identity_provisioning', ROOT/'scripts/bootstrap.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class IdentityProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        self.source = self.data/'source'
        for path in ('config', 'secrets/keycloak', 'secrets/runtime'):
            (self.data/path).mkdir(parents=True)
        (self.data/'config/images.lock.json').write_text(json.dumps({'platform': 'registry.example.invalid/platform@sha256:'+'a'*64}))
        for path in ('keycloak/bootstrap-password', 'runtime/keycloak-client', 'runtime/keycloak-directory-reader'):
            (self.data/'secrets'/path).write_text('synthetic-private-identity-value')

    def test_success_uses_protected_stdin_and_preexisting_image_once(self):
        output = io.StringIO()
        with patch.object(B.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run, redirect_stdout(output):
            B.provision_identity(self.data, self.source)
        run.assert_called_once()
        arguments, options = run.call_args
        self.assertIn('--pull=never', arguments[0])
        self.assertNotIn('synthetic-private-identity-value', ' '.join(arguments[0]))
        self.assertEqual(set(json.loads(options['input'])), {'bootstrapPassword', 'provisionerSecret', 'directoryReaderSecret'})
        self.assertEqual(options['stdout'], subprocess.DEVNULL)
        self.assertEqual(options['stderr'], subprocess.DEVNULL)
        self.assertIn('validated', output.getvalue())
        self.assertNotIn('synthetic-private-identity-value', output.getvalue())

    def test_nonzero_result_never_replays_a_possibly_committed_change(self):
        for status in (1, 125, 137):
            with self.subTest(status=status), patch.object(B.subprocess, 'run', return_value=subprocess.CompletedProcess([], status)) as run:
                with self.assertRaisesRegex(ValueError, 'state may already have changed'):
                    B.provision_identity(self.data, self.source)
                run.assert_called_once()

    def test_launch_failure_never_retries_or_leaks_raw_diagnostic(self):
        with patch.object(B.subprocess, 'run', side_effect=OSError('synthetic-private-identity-value')) as run:
            with self.assertRaisesRegex(ValueError, 'Inspect the identity service') as caught:
                B.provision_identity(self.data, self.source)
            run.assert_called_once()
            self.assertNotIn('synthetic-private-identity-value', str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)


if __name__ == '__main__': unittest.main()
