import importlib.util
import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('public_release_check', Path(__file__).with_name('public-release-check.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PublicationChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.add('LICENSE', 'An owner-selected license belongs here in a real release.')

    def tearDown(self):
        self.temp.cleanup()

    def add(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

    def check(self):
        return checker.inspect(self.root, checker.candidates(self.root))

    def test_clean_source_with_example_configuration(self):
        self.add('.env.example', 'PUBLIC_ORIGIN=https://admin.example.com\nAPI_KEY=\n')
        self.add('src/main.ts', 'export const appName = "Example";')
        self.assertTrue(self.check()['ready'])

    def test_license_is_not_inferred(self):
        (self.root / 'LICENSE').unlink()
        self.assertEqual(self.check()['findingCounts'], {'license_missing': 1})

    def test_secret_values_never_appear_in_report(self):
        token = 'sk-' + 'proj-' + 'A' * 45
        self.add('src/settings.ts', 'const secret = "' + token + '";')
        report = self.check()
        self.assertEqual(report['findingCounts']['provider_credential'], 1)
        self.assertNotIn(token, json.dumps(report))

    def test_private_key_body_is_detected_in_source(self):
        private = '-----BEGIN ' + 'PRIVATE KEY-----\n' + 'A' * 80
        self.add('test/key.ts', private)
        self.assertIn('private_key', self.check()['findingCounts'])

    def test_header_alone_is_not_a_private_key(self):
        self.add('test/parser.ts', 'const header = "-----BEGIN ' + 'PRIVATE KEY-----";')
        self.assertTrue(self.check()['ready'])

    def test_deployment_evidence_requires_exclusion(self):
        self.add('deploy/verification/customer.json', '{"host":"redacted"}')
        self.assertEqual(self.check()['findingCounts'], {'installation_evidence_or_release_artifact': 1})

    def test_private_configuration_is_blocked(self):
        self.add('.env', 'password=secret')
        self.add('secrets/customer.txt', 'example')
        report = self.check()
        self.assertEqual(report['findingCounts']['private_or_generated_file'], 1)
        self.assertEqual(report['findingCounts']['private_directory'], 1)

    def test_paths_cannot_escape_root(self):
        report = checker.inspect(self.root, ['LICENSE', '../outside.txt', '/etc/passwd', 'C:/outside.txt'])
        self.assertEqual(report['findingCounts']['unsafe_path'], 3)

    def test_symlink_cannot_import_external_content(self):
        link = self.root / 'linked.txt'
        try:
            link.symlink_to(self.root / 'LICENSE')
        except OSError:
            self.skipTest('Host does not permit symlink creation')
        self.assertEqual(self.check()['findingCounts'], {'unreadable_or_linked_file': 1})

    def test_customer_endpoints_block_docs_but_allow_synthetic_tests(self):
        endpoint = 'auth.' + 'fixture.internal'
        self.add('docs/install.md', endpoint)
        self.add('tests/login.test.ts', endpoint)
        self.assertEqual(self.check()['findingCounts'], {'trial_endpoint': 1})

    def test_ignored_local_work_is_not_recursively_scanned(self):
        self.add('.local/private.txt', 'sk-' + 'proj-' + 'B' * 45)
        self.assertTrue(self.check()['ready'])

    def test_tracked_private_files_are_still_rejected(self):
        self.add('.local/private.txt', 'private')
        report = checker.inspect(self.root, ['LICENSE', '.local/private.txt'])
        self.assertEqual(report['findingCounts'], {'private_directory': 1})

    def test_oversized_source_cannot_silently_pass(self):
        with (self.root / 'large.txt').open('wb') as file:
            file.truncate(checker.MAX_FILE_BYTES + 1)
        self.assertEqual(self.check()['findingCounts'], {'oversized_unreviewed_file': 1})

    def test_fixture_review_is_bound_to_exact_file_bytes(self):
        name='tests/url.ts'
        self.add(name, 'https://user:' + 'synthetic-password@example.test')
        digest=hashlib.sha256((self.root/name).read_bytes()).hexdigest()
        self.add('scripts/public-release-reviewed-fixtures.json', json.dumps([dict(path=name,sha256=digest,code='credential_url',reason='Synthetic URL rejection test')]))
        self.assertTrue(self.check()['ready'])
        self.add(name, 'https://user:' + 'changed-password@example.test')
        self.assertFalse(self.check()['ready'])

    def test_review_cannot_waive_provider_credentials(self):
        name='tests/token.ts'
        self.add(name, 'sk-'+'proj-'+'C'*40)
        digest=hashlib.sha256((self.root/name).read_bytes()).hexdigest()
        self.add('scripts/public-release-reviewed-fixtures.json', json.dumps([dict(path=name,sha256=digest,code='provider_credential',reason='Must not be waived')]))
        self.assertEqual(self.check()['findingCounts'], {'invalid_fixture_review':1,'provider_credential':1})


if __name__ == '__main__':
    unittest.main()
