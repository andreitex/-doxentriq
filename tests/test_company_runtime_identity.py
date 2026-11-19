"""Native archive/installed-file verification; no gVisor binary is executed."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_identity_worker', ROOT / 'deploy/installer/company_install.py')
WORKER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WORKER)
NATIVE = sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0 and bool(os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT'))


@unittest.skipUnless(NATIVE, 'requires Linux root and explicit protected test directory')
class NativeRuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        for path in (base, *base.parents):
            info = path.lstat()
            self.assertTrue(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
        self.folder = Path(tempfile.mkdtemp(prefix='runtime-identity-', dir=base))
        self.addCleanup(shutil.rmtree, self.folder)
        self.install = self.folder / 'bin'
        self.install.mkdir(mode=0o755)
        self.namespace = {'__name__': 'runtime_identity_test'}
        exec(compile(WORKER.RUNTIME_IDENTITY, '<captured runtime verifier>', 'exec'), self.namespace)
        self.verify = self.namespace['verify_stream']

    def fixture(self, *, modern=True, current=False):
        companions = WORKER.RUNTIME_CURRENT_SIDECAR_FILES if current else WORKER.RUNTIME_SIDECAR_FILES
        names = WORKER.RUNTIME_PRIMARY_FILES + (companions if modern else ())
        rows = []
        for name in names:
            if '/' in name and not (self.install / 'gvisor-bin').exists():
                (self.install / 'gvisor-bin').mkdir(mode=0o755)
                rows.append(('gvisor-bin', None))
            raw = ('synthetic, never executed: ' + name + '\n').encode()
            path = self.install / name
            path.write_bytes(raw)
            path.chmod(0o755)
            rows.append((name, raw))
        return rows

    def archive(self, rows):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            for name, raw in rows:
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                if raw is None:
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                else:
                    info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))
        data.seek(0)
        return data

    def verify_rows(self, rows):
        return self.verify(self.archive(rows), str(self.install))

    def test_all_seven_previous_layout_files_are_measured(self):
        rows = self.fixture()
        self.assertEqual(self.verify_rows(rows), {name: hashlib.sha256(raw).hexdigest() for name, raw in rows if raw is not None})

    def test_all_eight_current_files_are_measured(self):
        rows = self.fixture(current=True)
        self.assertEqual(len(rows), 9)
        self.assertEqual(self.verify_rows(rows), {name: hashlib.sha256(raw).hexdigest() for name, raw in rows if raw is not None})

    def test_current_archive_missing_previous_companion_rejected(self):
        rows = self.fixture(current=True)
        omitted = WORKER.RUNTIME_SIDECAR_FILES[0]
        with self.assertRaises(AssertionError):
            self.verify_rows([(name, raw) for name, raw in rows if name != omitted])

    def test_previous_archive_rejects_current_installed_extra(self):
        rows = self.fixture(current=True)
        with self.assertRaises(AssertionError):
            self.verify_rows(rows[:-1])

    def test_current_companion_missing_or_changed_rejected(self):
        rows = self.fixture(current=True)
        path = self.install / 'gvisor-bin/gvisor-proc-umounter'
        raw = path.read_bytes()
        path.write_bytes(b'X' + raw[1:])
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify_rows(rows)

    def test_current_companion_symlink_and_privileged_mode_rejected(self):
        rows = self.fixture(current=True)
        path = self.install / 'gvisor-bin/gvisor-proc-umounter'
        path.chmod(0o4755)
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)
        path.chmod(0o755)
        target = self.folder / 'elsewhere'
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)

    def test_current_archive_rejects_additional_member(self):
        rows = self.fixture(current=True)
        with self.assertRaises(AssertionError):
            self.verify_rows([*rows, ('gvisor-bin/unreviewed', b'bad')])

    def test_legacy_layout_requires_no_unmeasured_sidecar_directory(self):
        rows = self.fixture(modern=False)
        self.assertEqual(len(self.verify_rows(rows)), 2)
        (self.install / 'gvisor-bin').mkdir(mode=0o755)
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)

    def test_changed_sidecar_rejected(self):
        rows = self.fixture()
        path = self.install / WORKER.RUNTIME_SIDECAR_FILES[0]
        data = path.read_bytes()
        path.write_bytes(b'X' + data[1:])
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)

    def test_missing_sidecar_rejected(self):
        rows = self.fixture()
        (self.install / WORKER.RUNTIME_SIDECAR_FILES[-1]).unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify_rows(rows)

    def test_unknown_installed_sidecar_rejected(self):
        rows = self.fixture()
        (self.install / 'gvisor-bin/unmeasured').write_bytes(b'extra')
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)

    def test_partial_sidecar_archive_rejected(self):
        rows = self.fixture()
        with self.assertRaises(AssertionError):
            self.verify_rows(rows[:-1])

    def test_archive_traversal_duplicate_and_unknown_member_rejected(self):
        rows = self.fixture()
        for added in (('../outside', b'bad'), rows[0], ('gvisor-bin/unknown', b'bad')):
            with self.subTest(name=added[0]), self.assertRaises(AssertionError):
                self.verify_rows([added, *rows])

    def test_directory_symlink_rejected(self):
        rows = self.fixture()
        directory = self.install / 'gvisor-bin'
        target = self.folder / 'elsewhere'
        directory.rename(target)
        directory.symlink_to(target)
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)

    def test_file_symlink_and_hardlink_rejected(self):
        rows = self.fixture()
        path = self.install / WORKER.RUNTIME_SIDECAR_FILES[0]
        target = self.folder / 'elsewhere'
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)
        path.unlink()
        os.link(target, path)
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)

    def test_privileged_or_writable_file_mode_rejected(self):
        rows = self.fixture()
        path = self.install / WORKER.RUNTIME_SIDECAR_FILES[0]
        for mode in (0o4755, 0o2755, 0o775):
            with self.subTest(mode=mode):
                path.chmod(mode)
                with self.assertRaises(AssertionError):
                    self.verify_rows(rows)

    def test_installed_directory_permissions_change_during_read_rejected(self):
        rows = self.fixture()
        original = self.archive(rows)
        destination = self.install
        class ChangingStream:
            def read(self, size):
                destination.chmod(0o777)
                return original.read(size)
        with self.assertRaises(AssertionError):
            self.verify(ChangingStream(), str(self.install))

    def test_descriptors_close_after_rejection(self):
        rows = self.fixture()
        (self.install / 'runsc').chmod(0o777)
        before = set(os.listdir('/proc/self/fd'))
        with self.assertRaises(AssertionError):
            self.verify_rows(rows)
        self.assertEqual(before, set(os.listdir('/proc/self/fd')))

    def test_already_measured_file_changed_during_final_drain_rejected(self):
        rows = self.fixture()
        original = self.archive(rows)
        path = self.install / 'runsc'
        class ChangingStream:
            def read(self, size):
                raw = original.read(size)
                if not raw:
                    current = path.read_bytes()
                    path.write_bytes(b'X' + current[1:])
                return raw
        with self.assertRaises(AssertionError):
            self.verify(ChangingStream(), str(self.install))

    def test_archive_is_sealed_and_digest_bound(self):
        import fcntl
        path = self.folder / 'archive.zstd'
        raw = b'synthetic compressed bytes, never decoded'
        path.write_bytes(raw)
        expected = hashlib.sha512(raw).hexdigest()
        with self.namespace['pinned_archive'](str(path), expected) as fd:
            self.assertEqual(os.read(fd, len(raw) + 1), raw)
            self.assertTrue(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE)
            with self.assertRaises(OSError):
                os.write(fd, b'bad')
        with self.assertRaises(AssertionError):
            with self.namespace['pinned_archive'](str(path), '0' * 128):
                self.fail('Digest mismatch reached decoding')

    def test_archive_change_cannot_change_decoder_input_and_refuses_confirmation(self):
        path = self.folder / 'archive.zstd'
        raw = b'synthetic compressed bytes, never decoded'
        path.write_bytes(raw)
        with self.assertRaises(AssertionError):
            with self.namespace['pinned_archive'](str(path), hashlib.sha512(raw).hexdigest()) as fd:
                path.write_bytes(b'X' + raw[1:])
                self.assertEqual(os.read(fd, len(raw) + 1), raw)

    def test_archive_symlink_and_replacement_rejected(self):
        path = self.folder / 'archive.zstd'
        original = self.folder / 'original'
        original.write_bytes(b'archive')
        expected = hashlib.sha512(b'archive').hexdigest()
        path.symlink_to(original)
        with self.assertRaises(AssertionError):
            with self.namespace['pinned_archive'](str(path), expected):
                self.fail('Symlink reached decoding')
        path.unlink()
        path.write_bytes(b'archive')
        with self.assertRaises(AssertionError):
            with self.namespace['pinned_archive'](str(path), expected):
                path.unlink()
                path.write_bytes(b'archive')

    def test_decoder_error_never_prints_success(self):
        process = mock.Mock(stdout=io.BytesIO(b''), returncode=1)
        process.wait.return_value = 1
        self.namespace['verify_stream'] = lambda stream: {'runsc': 'a' * 64}
        output = io.StringIO()
        with mock.patch.object(self.namespace['subprocess'], 'Popen', return_value=process), \
                contextlib.redirect_stdout(output), self.assertRaises(AssertionError):
            self.namespace['decode_archive'](-1)
        self.assertEqual(output.getvalue(), '')
        self.assertTrue(process.stdout.closed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
