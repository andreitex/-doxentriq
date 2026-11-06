"""Native retention packaging and actual Linux IO/process boundaries.

Linux tests need a root-owned 0700 DOXENTRIQ_NATIVE_TEST_ROOT on encrypted test
storage. They create only fresh children there; no host services are changed.
This does not qualify encrypted-foundation or complete retention installation.
"""
import ast
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


B = load('test_native_retention_builder', 'deploy/installer/build-native-retention-package.py')
W = load('test_native_retention_worker', 'deploy/installer/company_native_retention.py')


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = B.assemble(ROOT, 'a'*64, reader=lambda p, n: p.read_bytes())
        tree = ast.parse(cls.worker)
        cls.package = next(ast.literal_eval(node.value) for node in tree.body
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PACKAGE' for t in node.targets))

    def test_actual_current_package_has_closed_paths_and_independent_bootstrap(self):
        self.assertLess(len(self.worker), B.MAX_WORKER)
        self.assertEqual(set(self.package['programs']), set(B.PROGRAMS))
        auth = self.package['authentication']
        self.assertEqual(auth['fingerprint'], 'a'*64)
        for path, encoded in auth['bootstrap_records'].items():
            self.assertEqual(base64.b64decode(encoded), (ROOT/path).read_bytes())
        compile(self.worker, '<packaged-native-worker>', 'exec')

    def test_capture_tampering_is_rejected_before_any_program_exec(self):
        before = set(sys.modules)
        value = copy.deepcopy(self.package)
        value['programs']['station']['sha256'] = '0'*64
        with self.assertRaises(ValueError): W.load_package(value)
        self.assertEqual(set(sys.modules), before)

    def test_source_operation_is_stable_and_separate_from_store(self):
        request = dict(operationId='b'*32, releaseSha256='c'*64)
        first = json.loads(W.invocation(request, b'request', W.STAGES[0], 'plan-stage'))
        second = json.loads(W.invocation(request, b'request', W.STAGES[1], 'plan-stage'))
        self.assertEqual(first['operationId'], request['operationId'])
        self.assertNotEqual(first['operationId'], second['operationId'])
        self.assertEqual(first['storeOperationId'], second['storeOperationId'])
        self.assertIsNone(first['parent'])

    def test_repository_companion_pins_exact_package_and_shared_parent(self):
        raw = B.assemble_entry(ROOT, self.worker, reader=lambda p, n: p.read_bytes(), repository=True)
        self.assertIn(B.pin(self.worker)['sha256'].encode(), raw)
        self.assertIn((ROOT/'scripts/install-lock.sh').read_bytes(), raw)
        self.assertNotIn(b'@WORKER_SHA256@', raw)
        self.assertIn(b'--seed-repository', raw)
        self.assertEqual(base64.b64decode(self.package['programs']['repository_io']['base64']),
                         (ROOT/'deploy/installer/company_repository_io.py').read_bytes())
        with self.assertRaises(ValueError):
            B.assemble_entry(ROOT, self.worker, reader=lambda p, n: p.read_bytes(), repository=True, configuration=True)


NATIVE = sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0 and bool(os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT'))


@unittest.skipUnless(NATIVE, 'requires Linux root and an explicit protected native test root')
class NativeBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.S = load('native_retention_station_tests', 'deploy/installer/company_native_station.py')
        cls.C = load('native_retention_crypto_tests', 'deploy/installer/company_release_crypto.py')
        cls.S.baseline()
        cls.base = Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        if not cls.base.is_absolute() or cls.base.is_symlink() or not str(cls.base).startswith('/srv/'):
            raise ValueError('explicit-encrypted-validation-root-required')
        info = cls.base.stat()
        if info.st_uid != info.st_gid or info.st_uid != 0 or info.st_mode & 0o777 != 0o700:
            raise ValueError('private-root-owned-validation-directory-required')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='retention-', dir=self.base)
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_actual_nofollow_hardlink_mode_and_ancestor_replacement_refusals(self):
        source = self.directory/'source'
        source.write_bytes(b'protected bytes')
        source.chmod(0o400)
        self.assertEqual(self.S.read_protected(source), b'protected bytes')
        link = self.directory/'link'
        link.symlink_to(source)
        with self.assertRaises((OSError, ValueError)): self.S.read_protected(link)
        os.link(source, self.directory/'hardlink')
        with self.assertRaises(ValueError): self.S.read_protected(source)
        (self.directory/'hardlink').unlink()
        source.chmod(0o666)
        with self.assertRaises(ValueError): self.S.read_protected(source)
        source.chmod(0o400)
        with self.assertRaises(ValueError):
            with self.S.held_file(source, 1024) as (_, _, check):
                source.rename(self.directory/'original')
                source.write_bytes(b'protected bytes')
                source.chmod(0o400)
                check()

    def test_actual_source_descriptors_close_and_detect_leak(self):
        path = self.directory/'source'
        path.write_bytes(b'x')
        files = self.S.SourceFiles()
        fd = files.open(None, str(path), False)
        self.assertEqual(files.read(fd, 1, 0), b'x')
        self.assertTrue(files.cloexec(fd))
        with self.assertRaises(ValueError): files.require_released()
        files.close(fd)
        files.require_released()

    def test_real_openssl_ed25519_sealed_verification_and_no_child_or_fd_leak(self):
        private, public, message, signature = [self.directory/name for name in ('private.pem','public.pem','message','signature')]
        env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', OPENSSL_CONF='/dev/null')
        def openssl(*args):
            subprocess.run(['/usr/bin/openssl', *map(str, args)], check=True, timeout=15,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        openssl('genpkey', '-algorithm', 'ED25519', '-out', private)
        openssl('pkey', '-in', private, '-pubout', '-out', public)
        message.write_bytes(b'company retention native signature fixture\n')
        openssl('pkeyutl', '-sign', '-rawin', '-inkey', private, '-in', message, '-out', signature)
        before = set(os.listdir('/proc/self/fd'))
        def verifier():
            return self.C.ReleaseCrypto(openssl_pin=self.S.tool_pin('/usr/bin/openssl'),
                budget=dict(calls=2, seconds=60), os_module=os, sys_module=sys,
                subprocess_module=subprocess, select_module=self.S.select, signal_module=self.S.signal,
                fcntl_module=self.S.fcntl, clock=time.monotonic,
                station_contract=self.C.STATION_CONTRACT, protected_fds=())
        crypto = verifier()
        self.assertIs(crypto.verify(message.read_bytes(), signature.read_bytes(), public.read_bytes()), True)
        crypto.require_released()
        bad = verifier()
        with self.assertRaises(ValueError): bad.verify(b'changed release', signature.read_bytes(), public.read_bytes())
        bad.require_released()
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        self.assertFalse(subprocess._active)
        self.assertFalse(self.C.UNRELEASED)


if __name__ == '__main__':
    unittest.main()
