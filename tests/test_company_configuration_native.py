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
spec = importlib.util.spec_from_file_location('configuration_native_files', ROOT / 'scripts/checkpoint_admission.py')
C = importlib.util.module_from_spec(spec);sys.modules[spec.name]=C;spec.loader.exec_module(C)
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


@unittest.skipUnless(NATIVE,'requires Linux root for retained-parent checks')
class NativeRetentionParentTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='doxentriq-retention-parents-')
        self.addCleanup(self.temporary.cleanup)
        self.data=Path(self.temporary.name);self.data.chmod(0o700)
        (self.data/'company').mkdir(mode=0o700)
        (self.data/'company/host-releases').mkdir(mode=0o700)
        self.files=C.NativeFiles();self.before=set(os.listdir('/proc/self/fd'))

    def tearDown(self):self.assertEqual(set(os.listdir('/proc/self/fd')),self.before)

    def test_fixed_fresh_parents_sync_and_independent_readonly_digest(self):
        with patch.object(Q.os,'fsync',wraps=os.fsync) as sync:
            initial=Q.prepare_retention_parents(self.data,files=self.files)
            self.assertGreaterEqual(sync.call_count,3)
        with patch.object(Q.os,'mkdir',side_effect=AssertionError('read-only check wrote')):
            self.assertEqual(initial,Q.retention_parents(self.data,files=self.files))
        self.assertEqual(sorted(path.name for path in (self.data/'company').iterdir()),
            ['host-releases','platform-releases','source-releases'])
        for name in ('platform-releases','source-releases'):
            info=(self.data/'company'/name).lstat()
            self.assertEqual((info.st_uid,info.st_gid,info.st_mode&0o777),(0,0,0o700))

    def test_existing_either_parent_preserves_state_without_creating_other(self):
        for name in ('platform-releases','source-releases'):
            with self.subTest(name=name):
                path=self.data/'company'/name;path.mkdir(mode=0o700)
                marker=path/'preserve';marker.write_bytes(b'prior data')
                with self.assertRaises(ValueError):Q.prepare_retention_parents(self.data,files=self.files)
                other='source-releases' if name=='platform-releases' else 'platform-releases'
                self.assertFalse((self.data/'company'/other).exists());self.assertEqual(marker.read_bytes(),b'prior data')
                marker.unlink();path.rmdir()

    def test_replaced_empty_directory_changes_independent_evidence(self):
        before=Q.prepare_retention_parents(self.data,files=self.files)
        path=self.data/'company/platform-releases';path.rename(path.with_name('retained-old-parent'))
        path.mkdir(mode=0o700)
        self.assertNotEqual(before,Q.retention_parents(self.data,files=self.files))

    def test_readonly_prerequisite_refuses_missing_populated_mode_and_symlink(self):
        with self.assertRaises((ValueError,OSError)):Q.retention_parents(self.data,files=self.files)
        Q.prepare_retention_parents(self.data,files=self.files)
        path=self.data/'company/platform-releases';marker=path/'unexpected';marker.write_bytes(b'preserve')
        with self.assertRaises(ValueError):Q.retention_parents(self.data,files=self.files)
        marker.unlink();path.chmod(0o755)
        with self.assertRaises(ValueError):Q.retention_parents(self.data,files=self.files)
        path.chmod(0o700);path.rename(path.with_name('retained-parent'));path.symlink_to(path.with_name('retained-parent'),target_is_directory=True)
        with self.assertRaises(ValueError):Q.retention_parents(self.data,files=self.files)


if __name__ == '__main__': unittest.main(verbosity=2)
