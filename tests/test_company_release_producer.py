"""Bounded company Git capture transport; no signing, image scans or install."""
import importlib.util
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('producer_transport', ROOT / 'scripts/release-manifest.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
ENV = dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LANG='C', LC_ALL='C',
           GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')


class InputTests(unittest.TestCase):
    def test_bad_tool_or_bounds_are_rejected_before_process_creation(self):
        for argv, maximum, timeout in ((('/bin/sh', '-c', 'true'), 1024, 5),
                (('/usr/bin/git', '--version'), True, 5),
                (('/usr/bin/git', '--version'), 1024, 31)):
            with patch.object(M.subprocess, 'Popen', side_effect=AssertionError('spawn')):
                with self.assertRaises(ValueError):
                    M.bounded_git(argv, env=ENV, limit=maximum, timeout=timeout)

    def test_schema4_entry_rejects_missing_arguments_before_read_or_write(self):
        with patch('pathlib.Path.lstat', side_effect=AssertionError('read')):
            with self.assertRaises(SystemExit):
                M.prepare_platform_cli([])

    def test_schema3_entry_rejects_missing_arguments_before_read_or_write(self):
        with patch('pathlib.Path.lstat', side_effect=AssertionError('read')):
            with self.assertRaises(SystemExit):
                M.prepare_deployment_cli([])

    def test_schema3_entry_refuses_non_native_producer_before_source_read(self):
        with patch.object(M.os, 'name', 'nt'), patch.object(M.Path, 'lstat', side_effect=AssertionError('read')):
            with self.assertRaisesRegex(ValueError, 'Trusted root-owned Linux company producer required'):
                M.protected_producer_directories(ROOT, ROOT)

    def test_old_git_is_refused_before_flag_probe_without_repository_access(self):
        for raw in (b'git version 2.39.5\n', b'git version 2.43.0\n', b'git version 2.45.0\n'):
            with patch.object(M.os, 'name', 'posix'), patch.object(M, 'bounded_git', return_value=raw) as run:
                with self.assertRaisesRegex(M.ProducerPrerequisiteUnavailable, 'requires Git 2.45.1 or newer'):
                    M.producer_git_prerequisite()
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0], ('/usr/bin/git', '--version'))

    def test_supported_git_requires_actual_option_probe_and_exact_version_agreement(self):
        for raw in (b'git version 2.45.1\n', b'git version 2.52.0\n'):
            with patch.object(M.os, 'name', 'posix'), patch.object(M, 'bounded_git', return_value=raw) as run:
                result = M.producer_git_prerequisite()
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args.args[0], ('/usr/bin/git', '--no-lazy-fetch', '--version'))
                self.assertFalse(result['securityQualification']); self.assertFalse(result['sourceCaptured'])
        with patch.object(M.os, 'name', 'posix'), patch.object(M, 'bounded_git', side_effect=[b'git version 2.52.0\n', b'git version 2.51.0\n']):
            with self.assertRaisesRegex(M.ProducerPrerequisiteUnavailable, 'results disagree'):
                M.producer_git_prerequisite()

    def test_missing_malformed_or_unsupported_tool_has_no_fallback(self):
        cases = (([FileNotFoundError()], 1), ([b'unknown tool\n'], 1),
            ([b'git version 2.52.0\n', ValueError('private child diagnostics')], 2))
        for results, count in cases:
            with patch.object(M.os, 'name', 'posix'), patch.object(M, 'bounded_git', side_effect=results) as run:
                with self.assertRaises(M.ProducerPrerequisiteUnavailable) as raised:
                    M.producer_git_prerequisite()
                self.assertNotIn('private child diagnostics', str(raised.exception))
                self.assertIn('company-approved', str(raised.exception)); self.assertEqual(run.call_count, count)

    def test_schema4_prerequisite_refusal_precedes_capture_or_output(self):
        with patch.object(M, 'protected_producer_directories'), patch.object(M, 'producer_git_prerequisite',
                side_effect=M.ProducerPrerequisiteUnavailable('upgrade required')), patch.object(M, '_trusted_sibling',
                side_effect=AssertionError('source capture must not begin')):
            with self.assertRaisesRegex(M.ProducerPrerequisiteUnavailable, 'upgrade required'):
                M.prepare_platform_cli(['/source/bundle', '/source/tree', 'a'*40, 'test'])


@unittest.skipUnless(sys.platform == 'linux' and Path('/usr/bin/git').is_file(), 'requires native Linux Git')
class NativeGitTests(unittest.TestCase):
    def test_real_git_query_returns_bytes_within_bound(self):
        result = M.bounded_git(('/usr/bin/git', '--version'), env=ENV, limit=4096, timeout=5)
        self.assertTrue(result.startswith(b'git version '))

    def test_real_overflow_is_refused_and_owned_child_reaped(self):
        before = tuple(M.subprocess._active)
        with self.assertRaisesRegex(ValueError, 'output limit'):
            M.bounded_git(('/usr/bin/git', '--version'), env=ENV, limit=1, timeout=5)
        self.assertEqual(tuple(M.subprocess._active), before)

    def test_real_nonzero_query_does_not_expose_diagnostics(self):
        with self.assertRaisesRegex(ValueError, '^Company Git query failed; no source artifact emitted$'):
            M.bounded_git(('/usr/bin/git', 'doxentriq-nonexistent-query'), env=ENV, limit=4096, timeout=5)


NATIVE_PRODUCER = sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0 and bool(os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT'))


@unittest.skipUnless(NATIVE_PRODUCER, 'requires root and explicit protected Linux validation directory')
class NativeDeploymentProducerTests(unittest.TestCase):
    def test_schema3_captures_actual_source_and_catalog_bytes_and_preserves_rerun(self):
        base = Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        self.assertTrue(str(base).startswith('/srv/') and base.is_dir() and not base.is_symlink())
        info = base.lstat()
        self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777), (0, 0, 0o700))
        case = Path(tempfile.mkdtemp(prefix='deployment-producer-', dir=base))
        # Deliberately inert catalog bytes: this test qualifies source capture,
        # never a signed release, image/security gate, or fixture installation.
        catalogs = {'images.lock.json': b'{"fixtureOnly":true}\n',
            'runtime-manifest.json': b'{"scope":"synthetic-not-installable"}\n',
            'approved-mirrors.json': b'[]\n'}
        for name, raw in catalogs.items():
            (case / name).write_bytes(raw); (case / name).chmod(0o600)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            M.prepare_deployment_cli([str(case), str(ROOT), 'synthetic-source-test'])
        result = json.loads(output.getvalue())
        self.assertEqual(result['scope'], 'UNSIGNED_DEPLOYMENT_SOURCE_ONLY')
        self.assertEqual(result['schemaVersion'], 3)
        self.assertTrue(all(result[name] is False for name in ('signed', 'imageSecurityQualified', 'installationActivated')))
        payload = json.loads((case / 'release.json').read_bytes())
        for name, raw in catalogs.items():
            self.assertEqual((case / name).read_bytes(), raw)
            self.assertEqual(payload['files'][name], dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        sources = json.loads((case / 'company-sources.json').read_bytes())['files']
        deployment = json.loads((case / 'company-deployment.json').read_bytes())['files']
        self.assertEqual((len(sources), len(deployment)), (44, 10))
        for row in sources + deployment:
            raw = (ROOT / row['path']).read_bytes()
            self.assertEqual((row['bytes'], row['sha256']), (len(raw), hashlib.sha256(raw).hexdigest()))
        before = {path.name: path.read_bytes() for path in case.iterdir()}
        with self.assertRaisesRegex(ValueError, 'preserve partial state'):
            M.prepare_deployment_cli([str(case), str(ROOT), 'synthetic-source-test'])
        self.assertEqual({path.name: path.read_bytes() for path in case.iterdir()}, before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
