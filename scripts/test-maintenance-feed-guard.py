#!/usr/bin/env python3
"""Feed refusal regression checks. No daemon, network, guest or native execution."""
import ast
from contextlib import nullcontext
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('feed_guard_scanner', HERE / 'maintenance_scanner.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def maintenance_method(name, extra=None):
    tree = ast.parse((HERE / 'maintenance.py').read_bytes())
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Maintenance')
    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == name)
    namespace = dict(ScannerUnavailable=M.ScannerUnavailable)
    namespace.update(extra or {})
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                 str(HERE / 'maintenance.py'), 'exec'), namespace)
    return namespace[name]


class FeedRefusal(unittest.TestCase):
    def test_product_feed_refuses_before_scanner_storage_or_chmod(self):
        task = types.SimpleNamespace(scanner=Mock(), data=Mock(), images=Mock())
        with patch('os.chmod') as chmod, self.assertRaisesRegex(M.ScannerUnavailable, 'bounded-vulnerability-feed-refresh-not-ready'):
            maintenance_method('feed')(task)
        task.scanner.assert_not_called()
        self.assertEqual(task.data.mock_calls, [])
        self.assertEqual(task.images.mock_calls, [])
        chmod.assert_not_called()

    def test_os_and_java_refuse_every_mount_network_and_cache_variant(self):
        for arguments in (M.DB, M.JAVA):
            for mounts in ([], [('/secret', '/cache')]):
                for network in ('bridge', 'none', 'host'):
                    for writable in (True, False):
                        with self.subTest(arguments=arguments, mounts=mounts, network=network, writable=writable), \
                             self.assertRaisesRegex(M.ScannerUnavailable, 'bounded-vulnerability-feed-refresh-not-ready'):
                            M.policy(arguments, mounts, network, writable)

    def test_exported_scanner_refuses_before_config_constructor_or_daemon(self):
        for arguments in (M.DB, M.JAVA):
            with self.subTest(arguments=arguments), patch.object(M, 'local_docker_configuration') as config, \
                 patch.object(M, 'MaintenanceScanner') as scanner, patch.object(M, 'docker') as daemon, \
                 self.assertRaisesRegex(M.ScannerUnavailable, 'bounded-vulnerability-feed-refresh-not-ready'):
                M.run_scanner(Path('/protected/data'), 'synthetic@sha256:' + 'a' * 64,
                              arguments, network='bridge', writable_cache=True)
            config.assert_not_called()
            scanner.assert_not_called()
            daemon.assert_not_called()

    def test_direct_scanner_refuses_before_lease_journal_or_cache(self):
        scanner = object.__new__(M.MaintenanceScanner)
        for name in ('serialized', 'reconcile_pending', 'prune_confirmed', 'inputs', 'identity', 'lock_proof'):
            setattr(scanner, name, Mock())
        for arguments in (M.DB, M.JAVA):
            with self.subTest(arguments=arguments), patch.object(M, 'docker') as daemon, \
                 self.assertRaisesRegex(M.ScannerUnavailable, 'bounded-vulnerability-feed-refresh-not-ready'):
                scanner.scan(arguments, network='bridge', writable_cache=True)
            daemon.assert_not_called()
        for name in ('serialized', 'reconcile_pending', 'prune_confirmed', 'inputs', 'identity', 'lock_proof'):
            getattr(scanner, name).assert_not_called()

    def test_offline_image_and_rootfs_still_use_the_same_readonly_contract(self):
        for arguments, destination in ((M.IMAGE, '/input'), (M.ROOTFS, '/inventory')):
            with self.subTest(arguments=arguments):
                policy = M.policy(arguments, [('/fixed/input', destination)], 'none', False)
                self.assertIs(policy['cacheWritable'], False)
                self.assertEqual(policy['memory'], 1024**3)
                self.assertEqual(policy['timeout'], 300)
                fake = Mock()
                fake.scan.return_value = 'synthetic readonly output'
                with patch.object(M, 'local_docker_configuration', return_value=nullcontext()) as config, \
                     patch.object(M, 'MaintenanceScanner', return_value=fake):
                    value = M.run_scanner(Path('/protected/data'), 'synthetic@sha256:' + 'a' * 64,
                                          arguments, [('/fixed/input', destination)])
                self.assertEqual(value, 'synthetic readonly output')
                config.assert_called_once()
                fake.scan.assert_called_once_with(arguments, [('/fixed/input', destination)], 'none', False)

    def test_security_coverage_records_the_fixed_refresh_reason(self):
        # Stop after the real method has handled the refused feed. No remaining
        # host/application scanner, state update or notification is executed.
        captured = []
        class CoverageDone(Exception):
            pass
        def coverage_record(**value):
            captured.append(value)
            raise CoverageDone
        task = types.SimpleNamespace(feed=Mock(side_effect=M.ScannerUnavailable('bounded-vulnerability-feed-refresh-not-ready')))
        function = maintenance_method('security', dict(STAMP=lambda: '2026-10-12T12:00:00Z',
                                                     EPOCH='1970-01-01T00:00:00Z', dict=coverage_record))
        with self.assertRaises(CoverageDone):
            function(task, '--gate')
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]['name'], 'vulnerability-feed')
        self.assertEqual(captured[0]['status'], 'unavailable')
        self.assertIn('Existing database files are preserved', captured[0]['detail'])
        self.assertIn('No clean security claim is possible', captured[0]['detail'])

    def test_arbitrary_exception_text_never_enters_security_coverage(self):
        for error in (ValueError('synthetic-password'), M.ScannerUnavailable('synthetic-token')):
            captured = []
            class CoverageDone(Exception):
                pass
            def record(**value):
                captured.append(value)
                raise CoverageDone
            def detail(error, fallback):
                return fallback
            function = maintenance_method('security', dict(STAMP=lambda: '2026-10-12T12:00:00Z',
                                                         EPOCH='1970-01-01T00:00:00Z', dict=record,
                                                         scanner_coverage_detail=detail))
            with self.subTest(error=type(error)), self.assertRaises(CoverageDone):
                function(types.SimpleNamespace(feed=Mock(side_effect=error)), '--gate')
            self.assertNotIn('synthetic-', captured[0]['detail'])
            self.assertEqual(captured[0]['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
