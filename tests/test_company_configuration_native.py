"""Actual private file fsync/digest/mode checks with synthetic credentials only."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('configuration_native_outputs', ROOT / 'deploy/installer/company_configuration.py')
Q = importlib.util.module_from_spec(spec); spec.loader.exec_module(Q)
NATIVE = sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0


@unittest.skipUnless(NATIVE, 'requires Linux root for exact native UID/mode checks')
class NativeOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='doxentriq-config-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.data = Path(self.temporary.name); self.data.chmod(0o700)
        for name in ('config', 'secrets', *('secrets/' + service for service in
                ('platform', 'mysql', 'keycloak', 'registry', 'runtime', 'packager', 'grafana', 'dns'))):
            (self.data / name).mkdir(mode=0o700)
        for name, raw, mode in (('config/models.json', b'{}\n', 0o644),
                ('secrets/platform/openai-key', b'synthetic-only', 0o600),
                ('secrets/platform/anthropic-key', b'', 0o600), ('secrets/dns.env', b'\n', 0o600)):
            path = self.data / name; path.write_bytes(raw); path.chmod(mode)
        self.cfg = dict(sso='none', certificate_mode='selfsigned', notification_email='', company_registry='')

    def measure(self, durable=False):
        return Q.wizard_outputs(self.data, self.cfg, durable=durable)

    def test_real_files_and_parents_sync_before_stable_readonly_digest(self):
        with patch.object(Q.os, 'fsync', wraps=os.fsync) as sync:
            first = self.measure(durable=True)
            self.assertGreaterEqual(sync.call_count, 8)
        self.assertEqual(first, self.measure())

    def test_deleted_or_changed_provider_key_cannot_match(self):
        first = self.measure()
        path = self.data / 'secrets/platform/openai-key'
        path.write_bytes(b'another-synthetic-value')
        self.assertNotEqual(first, self.measure())
        path.unlink()
        with self.assertRaises(ValueError): self.measure()

    def test_model_catalog_and_optional_credentials_participate(self):
        first = self.measure()
        (self.data / 'config/models.json').write_bytes(b'{"changed":true}')
        second = self.measure(); self.assertNotEqual(first, second)
        directory = self.data / 'secrets/docker-client'; directory.mkdir(mode=0o700)
        path = directory / 'config.json'; path.write_bytes(b'{}'); path.chmod(0o600)
        self.cfg['company_registry'] = 'registry.example.invalid'
        self.assertNotEqual(second, self.measure())

    def test_link_and_unknown_secret_refused(self):
        path = self.data / 'secrets/platform/extra'; path.write_bytes(b'synthetic')
        with self.assertRaises(ValueError): self.measure()
        path.unlink()
        original = self.data / 'secrets/platform/openai-key'; original.unlink()
        original.symlink_to(self.data / 'config/models.json')
        with self.assertRaises(ValueError): self.measure()

    def test_keycloak_uid_is_distinct_and_strict(self):
        self.cfg['sso'] = 'google'
        path = self.data / 'secrets/keycloak/google-client-secret'
        path.write_bytes(b'synthetic-google-value'); path.chmod(0o600)
        with self.assertRaises(ValueError): self.measure()
        os.chown(path, 1000, 1000)
        self.measure(durable=True)
        path.chmod(0o640)
        with self.assertRaises(ValueError): self.measure()


if __name__ == '__main__': unittest.main(verbosity=2)
