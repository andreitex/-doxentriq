"""Exercise the installed host command's standalone recovery path without a VM."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/autosoft.sh'
SOURCE = SCRIPT.read_text(encoding='utf-8')
CODE = SOURCE.split("<<'DOXENTRIQ_STORAGE_RECOVERY'\n", 1)[1].split('\nDOXENTRIQ_STORAGE_RECOVERY\n', 1)[0]
RECOVERY = types.ModuleType('installed_recovery')
exec(compile(CODE, str(SCRIPT) + ':recover-mount', 'exec'), RECOVERY.__dict__)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.value = dict(data_dir='/fixture/data', install_root='/fixture/data/company/source',
                          storage_file='/fixture/storage.luks', installation_id='3201cce0-4096-4c65-937a-57ea4991b854')
        self.receipt = dict(self.value, creation_stage='new-luks-created', luks_uuid='a3302634-d995-4159-bbeb-829632e174a7')
        self.snapshot = (self.value, self.receipt, (b'metadata', b'receipt', (1, 2, 3, 0, 0, 1, 4096), ()))
        self.calls = []

    def run_command(self, argv, accepted=(0,)):
        self.calls.append(argv)
        if argv[:2] == ['cryptsetup', 'luksUUID']:
            return 0, self.receipt['luks_uuid'].encode() + b'\n'
        return 0, b''

    @contextlib.contextmanager
    def prepared(self, *, active=False, mounts=(None, {'mounted': True})):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(RECOVERY, 'state', return_value=self.snapshot))
            stack.enter_context(patch.object(RECOVERY, 'mounted', side_effect=mounts))
            stack.enter_context(patch.object(RECOVERY, 'verify_mapper'))
            stack.enter_context(patch.object(RECOVERY, 'protected', return_value=(17,)))
            stack.enter_context(patch.object(RECOVERY.os.path, 'lexists', return_value=active))
            stack.enter_context(patch.object(Path, 'iterdir', return_value=iter(())))
            stack.enter_context(patch.object(Path, 'stat', return_value=types.SimpleNamespace(st_dev=17)))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            yield

    def test_unmounted_storage_opens_then_mounts_without_format_or_service_start(self):
        with self.prepared():
            RECOVERY.recover(self.run_command)
        self.assertEqual(self.calls, [
            ['cryptsetup', 'luksUUID', str(Path('/fixture/storage.luks'))],
            ['cryptsetup', 'open', '--key-file', str(RECOVERY.HOST / 'storage.key'), str(Path('/fixture/storage.luks')), 'autosoft-data'],
            ['mount', '-t', 'xfs', '-o', 'prjquota,nosuid,nodev', '--', str(RECOVERY.MAPPER), str(Path('/fixture/data'))],
        ])

    def test_already_mounted_storage_is_not_reopened_or_remounted(self):
        with self.prepared(active=True, mounts=({'mounted': True}, {'mounted': True})):
            RECOVERY.recover(self.run_command)
        self.assertEqual(self.calls, [['cryptsetup', 'luksUUID', str(Path('/fixture/storage.luks'))]])

    def test_populated_unmounted_directory_is_never_hidden(self):
        with self.prepared(), patch.object(Path, 'iterdir', return_value=iter([Path('/fixture/data/existing')])):
            with self.assertRaisesRegex(ValueError, 'will not hide'):
                RECOVERY.recover(self.run_command)
        self.assertEqual(self.calls, [])

    def test_wrong_backing_uuid_refuses_before_unlock(self):
        def wrong(argv, accepted=(0,)):
            self.calls.append(argv)
            return 0, b'0d773cc3-08a3-4a8c-888b-62b010289554\n'
        with self.prepared(), self.assertRaisesRegex(ValueError, 'identity differs'):
            RECOVERY.recover(wrong)
        self.assertEqual(len(self.calls), 1)

    def test_existing_wrong_mapper_refuses_before_mount(self):
        with self.prepared(active=True), patch.object(RECOVERY, 'verify_mapper', side_effect=ValueError('wrong mapper')):
            with self.assertRaisesRegex(ValueError, 'wrong mapper'):
                RECOVERY.recover(self.run_command)
        self.assertEqual(len(self.calls), 1)

    def test_failed_unlock_is_not_retried_or_followed_by_mount(self):
        def fail(argv, accepted=(0,)):
            if argv[:2] == ['cryptsetup', 'open']:
                self.calls.append(argv)
                raise ValueError('wrong key')
            return self.run_command(argv, accepted)
        with self.prepared(), self.assertRaisesRegex(ValueError, 'wrong key'):
            RECOVERY.recover(fail)
        self.assertEqual(len(self.calls), 2)

    def test_changed_host_records_do_not_report_success(self):
        with self.prepared(), patch.object(RECOVERY, 'state', side_effect=[self.snapshot, (*self.snapshot[:2], ('changed',))]):
            with self.assertRaisesRegex(ValueError, 'Recovery inputs changed'):
                RECOVERY.recover(self.run_command)

    def test_mapper_requires_exact_loop_backing_and_luks2(self):
        def run(argv, accepted=(0,)):
            if argv[0] == 'cryptsetup':
                return 0, b'/dev/mapper/autosoft-data is active.\n  type: LUKS2\n  device: /dev/loop7\n'
            return 0, json.dumps({'loopdevices': [{'name': '/dev/loop7', 'back-file': '/fixture/other.luks'}]}).encode()
        with patch.object(Path, 'stat', return_value=types.SimpleNamespace(st_mode=stat.S_IFBLK)):
            with self.assertRaisesRegex(ValueError, 'another backing file'):
                RECOVERY.verify_mapper(Path('/fixture/storage.luks'), run)

    def test_metadata_paths_and_duplicate_fields_refused(self):
        for path in ('/', '/a/../b', '/a//b', '/a;id', 'relative', '/a\nb'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                RECOVERY.absolute(path)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            json.loads('{"data_dir":"/a","data_dir":"/b"}', object_pairs_hook=RECOVERY.pairs)

    def test_storage_receipt_must_match_before_commands(self):
        changed = dict(self.receipt, storage_file='/fixture/other.luks')
        with patch.object(RECOVERY, 'protected', side_effect=[json.dumps(self.value).encode(), json.dumps(changed).encode()]):
            with self.assertRaisesRegex(ValueError, 'do not agree'):
                RECOVERY.state()

    def test_malformed_mount_observations_fail_closed(self):
        for raw in (b'[]', b'{}', b'{"filesystems":[]}', b'{"filesystems":[{}]}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'ambiguous'):
                RECOVERY.mounted(Path('/fixture/data'), lambda *args: (0, raw))


@unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0 and shutil.which('bash'),
                     'Standalone Bash dispatch requires Linux root; effects remain stubbed')
class StandaloneHostEntryTests(unittest.TestCase):
    def test_protected_file_reader_rejects_links_and_special_files(self):
        with tempfile.TemporaryDirectory(prefix='doxentriq-recovery-files-') as temp:
            base = Path(temp)
            original = base / 'metadata'
            original.write_bytes(b'protected metadata')
            original.chmod(0o600)
            # /tmp intentionally fails the real ancestor policy. Isolate leaf
            # handling here; the separate test below covers that ancestor.
            with patch.object(RECOVERY, 'directory'):
                self.assertEqual(RECOVERY.protected(original, read=True), b'protected metadata')
                (base / 'link').symlink_to(original)
                with self.assertRaises(OSError):
                    RECOVERY.protected(base / 'link', read=True)
                os.link(original, base / 'hardlink')
                with self.assertRaisesRegex(ValueError, 'protected root-owned'):
                    RECOVERY.protected(original, read=True)
                os.mkfifo(base / 'fifo', 0o600)
                with self.assertRaisesRegex(ValueError, 'protected root-owned'):
                    RECOVERY.protected(base / 'fifo', read=True)

    def test_world_writable_ancestor_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='doxentriq-recovery-ancestor-') as temp:
            base = Path(temp)
            unsafe = base / 'unsafe'
            unsafe.mkdir(mode=0o777)
            unsafe.chmod(0o777)
            with self.assertRaisesRegex(ValueError, 'unsafe directory'):
                RECOVERY.directory(unsafe)

    def test_missing_encrypted_library_does_not_block_recovery_entry(self):
        with tempfile.TemporaryDirectory(prefix='doxentriq-recovery-entry-') as temp:
            base = Path(temp)
            script = base / 'autosoft'
            script.write_bytes(SCRIPT.read_bytes())
            python = base / 'python3'
            python.write_text('#!/bin/bash\n[[ "$*" = "-I -B -" ]] || exit 81\n'
                              '/bin/cat > "$RECOVERY_CAPTURE"\nprintf "standalone-recovery-dispatched\\n"\n')
            python.chmod(0o700)
            capture = base / 'captured.py'
            result = subprocess.run([shutil.which('bash'), str(script), 'recover-mount'],
                                    env=dict(os.environ, PATH=str(base) + ':' + os.environ['PATH'], RECOVERY_CAPTURE=str(capture)),
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'standalone-recovery-dispatched\n')
            self.assertEqual(capture.read_text(), CODE + '\n')
            self.assertFalse((base / 'lib.sh').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
