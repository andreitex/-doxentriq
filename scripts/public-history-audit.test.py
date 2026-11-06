#!/usr/bin/env python3
"""Regression checks for complete-history secret-audit boundaries."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import string
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('history_audit', Path(__file__).with_name('public-history-audit.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class HistoryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='doxentriq-audit-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Audit Test')
        self.git('config', 'user.email', 'audit@example.invalid')
        self.git('config', 'core.autocrlf', 'false')
        self.git('config', 'core.hooksPath', str(self.root / 'no-hooks'))
        self.commit('README.md', 'Synthetic history audit.\n')

    def git(self, *args):
        result = subprocess.run(['git', '-C', str(self.repo), *args], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, 'Synthetic Git fixture command failed')
        return result.stdout.decode().strip()

    def commit(self, name, body):
        target = self.repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body.encode('utf-8'))
        self.git('add', '--', name)
        self.git('commit', '--quiet', '-m', 'Synthetic audit fixture')
        return self.git('rev-parse', 'HEAD')

    def test_removed_file_is_still_in_reachable_objects(self):
        marker = b'synthetic-removed-credential-marker'
        self.commit('removed.txt', marker.decode())
        self.git('rm', '--quiet', '--', 'removed.txt')
        self.git('commit', '--quiet', '-m', 'Remove synthetic fixture')
        snapshot = audit.inventory(self.repo)
        self.assertFalse((self.repo / 'removed.txt').exists())
        self.assertTrue(any(row['data'] == marker for row in snapshot['objects'].values()))
        self.assertEqual(snapshot['counts']['commit'], 3)

    def test_shallow_history_is_refused(self):
        (self.repo / '.git/shallow').write_text(self.git('rev-parse', 'HEAD') + '\n')
        with self.assertRaisesRegex(audit.AuditRefused, 'Shallow'):
            audit.inventory(self.repo)

    def test_replacement_object_cannot_hide_original_bytes(self):
        marker = b'synthetic-original-object-marker'
        self.commit('original.txt', marker.decode())
        original = self.git('rev-parse', 'HEAD:original.txt')
        replacement = self.git('rev-parse', 'HEAD:README.md')
        self.git('replace', original, replacement)
        snapshot = audit.inventory(self.repo)
        self.assertEqual(snapshot['objects'][original]['data'], marker)

    def test_inherited_git_state_cannot_redirect_scope(self):
        head = self.git('rev-parse', 'HEAD')
        with mock.patch.dict(os.environ, {'GIT_DIR': str(self.root / 'foreign'), 'GIT_CONFIG_COUNT': 'not-an-integer'}):
            self.assertEqual(audit.inventory(self.repo)['head'], head)

    def test_grafts_and_alternate_stores_are_refused(self):
        for relative in ('info/grafts', 'objects/info/alternates', 'objects/info/http-alternates'):
            path = self.repo / '.git' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'')
            try:
                with self.assertRaisesRegex(audit.AuditRefused, 'alternate object stores'):
                    audit.inventory(self.repo)
            finally:
                path.unlink()

    def test_lfs_content_is_not_silently_covered(self):
        self.commit('large.bin', 'version https://git-lfs.github.com/spec/v1\r\noid sha256:' + 'a' * 64 + '\r\nsize 50\r\n')
        with self.assertRaisesRegex(audit.AuditRefused, 'LFS'):
            audit.inventory(self.repo)

    def test_gitlink_is_not_silently_covered(self):
        self.git('update-index', '--add', '--cacheinfo', '160000,' + self.git('rev-parse', 'HEAD') + ',external')
        self.git('commit', '--quiet', '-m', 'Synthetic gitlink fixture')
        with self.assertRaisesRegex(audit.AuditRefused, 'Submodule'):
            audit.inventory(self.repo)

    def test_oversized_objects_fail_before_scanning(self):
        with mock.patch.object(audit, 'MAX_OBJECT_BYTES', 10):
            with self.assertRaises(audit.AuditRefused):
                audit.inventory(self.repo)

    def test_changed_refs_invalidate_audit(self):
        calls = 0
        def scanner(*_args):
            nonlocal calls
            calls += 1
            if calls == 1:
                self.commit('new.txt', 'New content after snapshot.\n')
            return []
        with mock.patch.object(audit, 'scanner', scanner):
            with self.assertRaisesRegex(audit.AuditRefused, 'refs changed'):
                audit.audit(self.repo, self.root / 'unused', '0' * 64)

    def test_fixture_review_requires_exact_blob_rule_and_line(self):
        body = 'marker = "synthetic-fixture-marker"\n'
        commit = self.commit('fixture.py', body)
        review_path = self.root / 'reviews.json'
        review_path.write_text(json.dumps([{'path': 'fixture.py', 'blobSha256': hashlib.sha256(body.encode()).hexdigest(),
            'rule': 'generic-api-key', 'line': 1, 'reason': 'Synthetic fixture reviewed only for these exact bytes.'}]))
        def finding(*args):
            return [{'File': 'fixture.py', 'Commit': commit, 'StartLine': 1, 'RuleID': 'generic-api-key'}] if args[3] == 'git' else []
        with mock.patch.object(audit, 'scanner', finding):
            self.assertTrue(audit.audit(self.repo, self.root / 'unused', '0' * 64, review_path)['ready'])
            commit = self.commit('fixture.py', body + '# New unreviewed content.\n')
            report = audit.audit(self.repo, self.root / 'unused', '0' * 64, review_path)
            self.assertFalse(report['ready'])
            self.assertEqual(report['reviewedFixtureCount'], 0)

    def test_broad_fixture_review_is_rejected(self):
        review_path = self.root / 'reviews.json'
        review_path.write_text(json.dumps([{'path': 'tests/*', 'rule': '*', 'reason': 'Ignore tests'}]))
        with self.assertRaises(audit.AuditRefused):
            audit.reviews(review_path)

    def test_scanner_digest_mismatch_is_refused(self):
        tool = self.root / 'tool'
        tool.write_bytes(b'not-an-executable')
        with self.assertRaisesRegex(audit.AuditRefused, 'digest'):
            audit.scanner(tool, '0' * 64, self.repo, 'git', self.root)

    def test_unavailable_scanner_never_passes(self):
        tool = self.root / 'tool'
        tool.write_bytes(b'synthetic-tool')
        with mock.patch.object(audit.subprocess, 'run', return_value=subprocess.CompletedProcess([], 127, b'', b'')):
            with self.assertRaisesRegex(audit.AuditRefused, 'incomplete'):
                audit.scanner(tool, hashlib.sha256(tool.read_bytes()).hexdigest(), self.repo, 'git', self.root)

    def test_unredacted_scanner_output_is_rejected(self):
        tool = self.root / 'tool'
        tool.write_bytes(b'synthetic-tool')
        def invoke(*_args, **_kwargs):
            (self.root / 'git-redacted.json').write_text(json.dumps([{'Secret': 'synthetic-unredacted-marker'}]))
            return subprocess.CompletedProcess([], 1, b'', b'')
        with mock.patch.object(audit.subprocess, 'run', side_effect=invoke):
            with self.assertRaisesRegex(audit.AuditRefused, 'redacted'):
                audit.scanner(tool, hashlib.sha256(tool.read_bytes()).hexdigest(), self.repo, 'git', self.root)

    @unittest.skipUnless(os.environ.get('DOXENTRIQ_GITLEAKS_TEST_BINARY') and os.environ.get('DOXENTRIQ_GITLEAKS_TEST_SHA256'),
                         'Requires an explicitly verified offline scanner binary')
    def test_actual_scanner_catches_removed_secret_without_reporting_value(self):
        marker = 'gh' + 'p_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        self.commit('removed.env', 'ACCESS_TOKEN=' + marker + '\n')
        self.git('rm', '--quiet', '--', 'removed.env')
        self.git('commit', '--quiet', '-m', 'Remove detector canary')
        report = audit.audit(self.repo, Path(os.environ['DOXENTRIQ_GITLEAKS_TEST_BINARY']),
                             os.environ['DOXENTRIQ_GITLEAKS_TEST_SHA256'])
        self.assertFalse(report['ready'])
        self.assertGreater(report['findingCount'], 0)
        self.assertNotIn(marker, json.dumps(report))

    @unittest.skipUnless(os.environ.get('DOXENTRIQ_GITLEAKS_TEST_BINARY') and os.environ.get('DOXENTRIQ_GITLEAKS_TEST_SHA256'),
                         'Requires an explicitly verified offline scanner binary')
    def test_actual_scanner_catches_secret_hidden_by_git_replace(self):
        marker = 'gh' + 'p_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        self.commit('original.env', 'ACCESS_TOKEN=' + marker + '\n')
        original = self.git('rev-parse', 'HEAD:original.env')
        replacement = self.git('rev-parse', 'HEAD:README.md')
        self.git('replace', original, replacement)
        report = audit.audit(self.repo, Path(os.environ['DOXENTRIQ_GITLEAKS_TEST_BINARY']),
                             os.environ['DOXENTRIQ_GITLEAKS_TEST_SHA256'])
        self.assertFalse(report['ready'])
        self.assertTrue(any(row['objectId'] == original for row in report['findings']))
        self.assertNotIn(marker, json.dumps(report))


if __name__ == '__main__':
    unittest.main()
