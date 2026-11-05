"""Local source-byte controls; Linux DAC/directory transport is injected on Windows."""
import ast
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATHS = ('scripts/a.py', 'scripts/b.sh')


def literal_host_references(relative, raw):
    """Inert finite syntax coverage, never evaluation of commands or imports."""
    if type(raw) is not bytes or len(raw) > 1024**2:
        raise ValueError('source-control-bound')
    text = raw.decode('utf8', 'strict')
    leaf = r'[A-Za-z0-9][A-Za-z0-9_.-]*\.(?:py|sh|mjs)'
    references = {'scripts/' + name for name in re.findall(r'\bscripts/(' + leaf + r')\b', text)}
    references.update('scripts/' + name for name in re.findall(r'\$(?:SCRIPT_DIR|\{SCRIPT_DIR\})/(' + leaf + r')\b', text))
    if relative.endswith('.py'):
        for node in ast.walk(ast.parse(raw)):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else None
            # Concrete sibling paths used for subprocess scripts and explicit
            # importlib loaders. No variable binding or dynamic code evaluation.
            selected = node.args[:1] if name == 'with_name' else node.args[1:2] if name in ('_sibling', 'spec_from_file_location') else ()
            for argument in selected:
                if isinstance(argument, ast.Constant) and type(argument.value) is str and re.fullmatch(leaf, argument.value):
                    references.add('scripts/' + argument.value)
    return frozenset(references)


def load():
    spec = importlib.util.spec_from_file_location('company_source_test', ROOT / 'scripts/company_source.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Files:
    """Actual retained byte reads, injected Linux root/DAC and held directory FDs."""
    def __init__(self, module):
        self.module = module
        self.next = 1000000
        self.dirs, self.records, self.events, self.changes = {}, {}, [], {}
        self.on_read = None
        self.before_open = None
        self.fail_open = self.fail_fstat = self.fail_close = self.non_cloexec = None
        self.frozen = {}

    def lstat(self, path):
        path = Path(path)
        info = path.lstat()
        value = SimpleNamespace(**{field: getattr(info, field) for field in self.module.FIELDS})
        value.st_uid = value.st_gid = 0
        value.st_mode = (stat.S_IFDIR | 0o755) if stat.S_ISDIR(info.st_mode) else (stat.S_IFREG | 0o644)
        for field, item in self.changes.get(path, {}).items():
            setattr(value, field, item)
        return self.frozen.get(path, value)

    def open(self, parent, name, directory):
        path = Path(name) if parent is None else self.dirs[parent][0] / name
        self.events.append(('open', path, directory))
        if path == self.fail_open:
            raise OSError('injected-open')
        if self.before_open:
            self.before_open(path, directory)
        if directory:
            self.next += 1
            self.dirs[self.next] = path, copy.deepcopy(self.lstat(path))
            return self.next
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        os.set_inheritable(fd, False)
        self.records[fd] = path
        return fd

    def fstat(self, fd):
        path = self.dirs[fd][0] if fd in self.dirs else self.records[fd]
        if path == self.fail_fstat:
            raise OSError('injected-fstat')
        if fd in self.dirs:
            return self.dirs[fd][1]
        info = os.fstat(fd)
        value = self.lstat(path)
        # Keep actual held-file identity; Windows path/FD ctime is normalized only
        # in this injected profile, never by the production native verifier.
        if path not in self.frozen:
            value.st_dev, value.st_ino, value.st_nlink, value.st_size = info.st_dev, info.st_ino, info.st_nlink, info.st_size
        return value

    def cloexec(self, fd):
        path = self.dirs[fd][0] if fd in self.dirs else self.records[fd]
        return path != self.non_cloexec

    def read(self, fd, amount, offset):
        path = self.records[fd]
        self.events.append(('read', path, offset))
        if self.on_read:
            result = self.on_read(fd, amount, offset)
            if result is not None:
                return result
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, amount)

    def close(self, fd):
        path = self.dirs[fd][0] if fd in self.dirs else self.records[fd]
        self.events.append(('close', path, fd))
        if path == self.fail_close:
            raise OSError('injected-close-before-effect')
        if fd in self.dirs:
            del self.dirs[fd]
        else:
            os.close(fd)
            del self.records[fd]


class Controls(unittest.TestCase):
    def setUp(self):
        self.S = load()
        artifact = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local')))
        self.assertTrue(artifact.is_dir())
        self.root = Path(tempfile.mkdtemp(prefix='company-source-v1-', dir=artifact)).resolve()
        (self.root / 'scripts').mkdir()
        (self.root / PATHS[0]).write_bytes(b'print("source-a")\n')
        (self.root / PATHS[1]).write_bytes(b'#!/bin/bash\nexit 0\n')
        self.files = Files(self.S)

    def create(self, paths=PATHS):
        return self.S.create(self.root, paths=paths, files=self.files)

    def verify(self, manifest, paths=PATHS):
        return self.S.verify(self.root, manifest, paths=paths, files=self.files)

    def denied(self, call):
        with self.assertRaisesRegex(self.S.SourceUnavailable, '^company-source-unavailable$'):
            call()
        self.assertFalse(self.files.records)

    def test_exact_actual_bytes_canonical_roundtrip_and_false_authority(self):
        value = self.create(); raw = self.S.encode(value, paths=PATHS)
        self.assertEqual(self.S.decode(raw, paths=PATHS), value)
        for row in value['files']:
            data = (self.root / row['path']).read_bytes()
            self.assertEqual(row['bytes'], len(data)); self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
        result = self.verify(raw)
        self.assertEqual(result['manifestSha256'], hashlib.sha256(raw).hexdigest())
        for key in ('changed', 'companyTrustEstablished', 'signatureVerified', 'nativeAuthorized', 'backupReady'):
            self.assertIs(result[key], False)
        self.assertFalse(self.files.dirs); self.assertFalse(self.files.records)

    def test_default_catalog_hashes_current_sources_without_importing_them(self):
        for relative in self.S.INSTALLER_RUNTIME_SOURCES:
            data = (ROOT / relative).read_bytes()
            (self.root / relative).write_bytes(data)
        manifest = self.create(self.S.INSTALLER_RUNTIME_SOURCES)
        self.assertEqual(len(manifest['files']), len(self.S.INSTALLER_RUNTIME_SOURCES))
        self.assertIn('scripts/company_source.py', [row['path'] for row in manifest['files']])
        self.assertEqual(self.verify(manifest, self.S.INSTALLER_RUNTIME_SOURCES)['fileCount'], len(self.S.INSTALLER_RUNTIME_SOURCES))

    def test_fixed_catalog_covers_current_local_python_sibling_imports(self):
        sources = set(self.S.INSTALLER_RUNTIME_SOURCES)
        for relative in sources:
            if not relative.endswith('.py'):
                continue
            tree = ast.parse((ROOT / relative).read_bytes())
            for node in ast.walk(tree):
                modules = [alias.name.split('.')[0] for alias in node.names] if isinstance(node, ast.Import) else [node.module.split('.')[0]] if isinstance(node, ast.ImportFrom) and node.module else []
                for name in modules:
                    if name not in sys.stdlib_module_names and (ROOT / 'scripts' / (name + '.py')).is_file():
                        self.assertIn('scripts/' + name + '.py', sources)
        for name in ('startup_binding.py', 'runtime_layout.py', 'quota_runtime.py', 'quota_allocation.py', 'checkpoint_admission.py', 'installation_identity.py', 'installer_parent.py', 'registry_manifest.py'):
            self.assertIn('scripts/' + name, sources)

    def test_fixed_catalog_covers_literal_script_and_explicit_sibling_loader_references(self):
        sources = set(self.S.INSTALLER_RUNTIME_SOURCES)
        observed = {}
        total = 0
        for relative in sorted(sources):
            raw = (ROOT / relative).read_bytes()
            total += len(raw)
            self.assertLessEqual(total, self.S.MAX_TOTAL_BYTES)
            observed[relative] = literal_host_references(relative, raw)
            # Schema 4 authenticates this helper through the separate complete
            # platform archive. Keep the legacy 44-file release format stable.
            platform_only = {'scripts/platform_source.py'} if relative == 'scripts/verify-release.py' else set()
            if relative in ('scripts/install.sh', 'scripts/autosoft.sh'):
                platform_only.add('scripts/installation-status.py')
            self.assertLessEqual(observed[relative], sources | platform_only, relative)
        self.assertEqual(len(sources), 44)
        self.assertNotIn('scripts/platform_source.py', sources)
        platform_tree = ast.parse((ROOT / 'scripts/platform_source.py').read_bytes())
        anchors = next(node.value for node in platform_tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'REQUIRED_ANCHORS' for target in node.targets))
        self.assertIn('scripts/platform_source.py', {node.value for node in ast.walk(anchors)
                                                    if isinstance(node, ast.Constant) and isinstance(node.value, str)})
        self.assertIn('scripts/installation-status.py', {node.value for node in ast.walk(anchors)
                                                        if isinstance(node, ast.Constant) and isinstance(node.value, str)})
        self.assertIn('scripts/verify-release.py', observed['scripts/install.sh'])
        self.assertIn('scripts/verify-release.py', observed['scripts/bootstrap.py'])
        self.assertIn('scripts/resolve-images.py', observed['scripts/verify-release.py'])
        self.assertIn('scripts/startup_binding.py', observed['scripts/runtime_pair_init.py'])
        self.assertIn('scripts/runtime_layout.py', observed['scripts/startup_binding.py'])
        self.assertIn('scripts/installation_identity.py', observed['scripts/startup_binding.py'])
        # The exact previously admitted catalog fails this independent coverage
        # control: neither manifest contents nor imports supply its coverage.
        previous = sources - {'scripts/verify-release.py'}
        self.assertEqual(observed['scripts/install.sh'] - previous, {'scripts/verify-release.py'})
        self.assertEqual(observed['scripts/bootstrap.py'] - previous, {'scripts/verify-release.py'})

    def test_literal_reference_control_is_inert_and_bounds_its_supported_forms(self):
        raw = b'''import subprocess
subprocess.run([sys.executable, str(Path(__file__).with_name('verify-release.py'))])
spec = importlib.util.spec_from_file_location('loaded', 'registry_manifest.py')
layout = _sibling('layout', 'runtime_layout.py')
unit = f"ExecStart=/bin/bash {root}/scripts/autosoft.sh"
computed = importlib.util.spec_from_file_location('dynamic', choose_filename())
raise RuntimeError('must never execute')
'''
        self.assertEqual(literal_host_references('scripts/fixture.py', raw), frozenset({
            'scripts/verify-release.py', 'scripts/registry_manifest.py',
            'scripts/runtime_layout.py', 'scripts/autosoft.sh'}))
        shell = b'python3 "$SCRIPT_DIR/verify-release.py"\nsource "${SCRIPT_DIR}/lib.sh"\n/bin/bash "$INSTALL_ROOT/scripts/storage-guard.sh"\n'
        self.assertEqual(literal_host_references('scripts/fixture.sh', shell), frozenset({
            'scripts/verify-release.py', 'scripts/lib.sh', 'scripts/storage-guard.sh'}))
        self.assertEqual(literal_host_references('scripts/fixture.py', b"filename = choose_filename()\n"), frozenset())
        with self.assertRaisesRegex(ValueError, '^source-control-bound$'):
            literal_host_references('scripts/fixture.py', b'x' * (1024**2 + 1))

    def test_missing_extra_reordered_or_duplicate_manifest_coverage_denied_before_io(self):
        value = self.create()
        cases = [dict(value, files=value['files'][:-1]), dict(value, files=value['files'] + [dict(value['files'][0], path='scripts/c.py')]), dict(value, files=list(reversed(value['files']))), dict(value, files=[value['files'][0]] * 2)]
        for case in cases:
            self.files.events.clear(); self.denied(lambda: self.verify(case)); self.assertEqual(self.files.events, [])

    def test_catalog_cannot_derive_its_coverage_from_manifest(self):
        one = self.create(PATHS[:1])
        self.denied(lambda: self.verify(one))
        self.assertEqual(self.verify(one, PATHS[:1])['fileCount'], 1)

    def test_relative_path_traversal_alias_drive_unicode_depth_and_prefix_refusal(self):
        bad = ('../a', '/a', 'a//b', 'a/./b', 'a/../b', 'a\\b', 'C:/a', 'a/', '.git/x', 'a/é', 'a.' , '/'.join(['a'] * 9), 'a' * 129)
        for value in bad:
            self.denied(lambda: self.create((value,)))
        for paths in ((), ('a', 'a'), ('a', 'a-b', 'a/b'), ('a',) * 129):
            self.denied(lambda: self.create(paths))

    def test_closed_typed_schema_size_hash_and_extra_fields(self):
        base = self.create()
        for field, values in [('bytes', (True, 1.0, -1, 0, self.S.MAX_FILE_BYTES + 1, '1')), ('sha256', ('A' * 64, '0' * 63, None, 0))]:
            for bad in values:
                value = copy.deepcopy(base); value['files'][0][field] = bad
                self.denied(lambda: self.verify(value))
        for value in (dict(base, schemaVersion=True), dict(base, schemaVersion=1.0), dict(base, unknown=True)):
            self.denied(lambda: self.verify(value))

    def test_bounded_canonical_parser_duplicate_keys_nonfinite_and_whitespace(self):
        raw = self.S.encode(self.create(), paths=PATHS)
        bad = [raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'), raw.replace(b'"bytes":', b'"bytes":NaN,"ignored":'), raw[:-1], b' ' + raw, raw + b'\n', raw.replace(b'"scope":', b'"scope":Infinity,"ignored":'), b'{"x":"\xff"}', b' ' * (self.S.MAX_MANIFEST_BYTES + 1)]
        for value in bad:
            self.denied(lambda: self.verify(value))

    def test_file_count_directory_and_total_byte_caps_before_further_opens(self):
        with patch.object(self.S, 'MAX_TOTAL_BYTES', sum((self.root / path).stat().st_size for path in PATHS) - 1):
            self.denied(self.create)
        self.assertNotIn(('open', self.root / PATHS[1], False), self.files.events)
        with patch.object(self.S, 'MAX_DIRECTORIES', 1):
            self.denied(self.create)
        value = self.create()
        with patch.object(self.S, 'MAX_MANIFEST_BYTES', 10):
            self.denied(lambda: self.verify(value))

    def test_exact_file_size_boundary_and_oversized_stat_rejected_without_read(self):
        path = self.root / PATHS[0]; path.write_bytes(b'x' * self.S.MAX_FILE_BYTES)
        self.assertEqual(self.create(PATHS[:1])['files'][0]['bytes'], self.S.MAX_FILE_BYTES)
        self.files.events.clear(); self.files.changes[path] = {'st_size': self.S.MAX_FILE_BYTES + 1}
        self.denied(lambda: self.create(PATHS[:1])); self.assertFalse(any(event[0] == 'read' for event in self.files.events))

    def test_file_and_ancestor_symlink_or_special_type_refused(self):
        for path, mode in [(self.root / PATHS[0], stat.S_IFLNK | 0o644), (self.root / PATHS[0], stat.S_IFIFO | 0o644), (self.root / 'scripts', stat.S_IFLNK | 0o755), (self.root, stat.S_IFREG | 0o644)]:
            self.files.changes = {path: {'st_mode': mode}}; self.denied(self.create)

    def test_actual_hardlink_source_preserved_and_refused(self):
        path = self.root / PATHS[0]; before = path.read_bytes()
        os.link(path, self.root / 'linked-source')
        self.denied(self.create); self.assertEqual(path.read_bytes(), before); self.assertTrue((self.root / 'linked-source').is_file())

    def test_foreign_owner_or_group_world_write_denied(self):
        for path in (self.root, self.root / 'scripts', self.root / PATHS[0]):
            for change in ({'st_uid': 7}, {'st_gid': 7}, {'st_mode': (stat.S_IFDIR if path.is_dir() else stat.S_IFREG) | 0o777}):
                self.files.changes = {path: change}; self.denied(self.create)

    def test_explicit_company_build_uid_gid_policy_and_root_default(self):
        for path in (self.root, self.root / 'scripts', *(self.root / item for item in PATHS)):
            self.files.changes[path] = {'st_uid': 123, 'st_gid': 456}
        self.denied(self.create)
        value = self.S.create(self.root, paths=PATHS, files=self.files, owner_uid=123, owner_gid=456)
        self.assertEqual(self.S.verify(self.root, value, paths=PATHS, files=self.files, owner_uid=123, owner_gid=456)['status'], 'verified')
        for uid in (True, -1, 1.0):
            self.denied(lambda: self.S.create(self.root, paths=PATHS, files=self.files, owner_uid=uid))

    def test_midread_root_and_parent_directory_identity_replacement_denied(self):
        for changed in (self.root, self.root / 'scripts'):
            def mutate(fd, amount, offset):
                self.files.changes[changed] = {'st_ino': self.files.lstat(changed).st_ino + 1}
            self.files.on_read = mutate; self.denied(self.create)
            self.files.changes.clear()

    def test_actual_same_name_file_replacement_between_stat_and_open_refused(self):
        path = self.root / PATHS[0]
        def mutate(opened, directory):
            if opened == path and not directory:
                self.files.before_open = None
                raw = path.read_bytes(); path.rename(path.with_suffix('.retained')); path.write_bytes(raw)
        self.files.before_open = mutate; self.denied(self.create)
        self.assertEqual(path.read_bytes(), path.with_suffix('.retained').read_bytes())

    def test_content_drift_with_injected_unchanged_stat_fails_final_hash(self):
        path = self.root / PATHS[0]; original = path.read_bytes(); calls = [0]
        def mutate(fd, amount, offset):
            if self.files.records[fd] == path and offset == 0:
                calls[0] += 1
                if calls[0] == 2:
                    self.files.frozen[path] = copy.deepcopy(self.files.lstat(path))
                    path.write_bytes(b'X' + original[1:])
        self.files.on_read = mutate; self.denied(self.create)
        self.assertEqual(calls[0], 2); self.assertNotEqual(path.read_bytes(), original)

    def test_mutated_caller_manifest_cannot_upgrade_an_invalid_input_snapshot(self):
        value = self.create(); expected = value['files'][0]['sha256']
        value['files'][0]['sha256'] = '0' * 64
        def mutate(fd, amount, offset):
            value['files'][0]['sha256'] = expected
        self.files.on_read = mutate
        self.denied(lambda: self.verify(value))
        self.assertEqual(value['files'][0]['sha256'], expected)

    def test_truncated_growing_wrong_type_or_overread_bytes_denied(self):
        for kind in ('truncate', 'grow', 'type', 'overread'):
            def mutate(fd, amount, offset):
                if offset == 0:
                    if kind == 'type': return 'not-bytes'
                    if kind == 'overread': return b'x' * (amount + 1)
                    self.files.on_read = None
                    path = self.files.records[fd]; path.write_bytes(b'x' if kind == 'truncate' else path.read_bytes() + b'x')
            self.files.on_read = mutate; self.denied(self.create)
            (self.root / PATHS[0]).write_bytes(b'print("source-a")\n')

    def test_open_cloexec_and_first_fstat_failures_close_registered_owned_handles(self):
        for attr in ('fail_open', 'non_cloexec', 'fail_fstat'):
            setattr(self.files, attr, self.root / PATHS[0]); self.denied(self.create)
            self.assertFalse(self.files.dirs); setattr(self.files, attr, None)

    def test_cleanup_failure_attempts_every_close_latches_unknown_and_blocks_success(self):
        self.files.fail_close = self.root / 'scripts'
        self.denied(self.create)
        self.assertEqual(len(self.S.UNRELEASED_HANDLES), 1)
        self.assertEqual(len([event for event in self.files.events if event[0] == 'close']), len([event for event in self.files.events if event[0] == 'open']))
        prior = list(self.files.events); self.denied(self.create); self.assertEqual(self.files.events, prior)
        self.assertIs(self.S.UNRELEASED_HANDLES[0][0], self.files)

    def test_typed_metadata_and_noncanonical_root_fail_closed(self):
        self.files.changes[self.root / PATHS[0]] = {'st_size': True}; self.denied(self.create)
        for path in ('.', str(self.root / '..' / self.root.name), self.root.anchor):
            self.denied(lambda: self.S.create(path, paths=PATHS, files=self.files))

    def test_native_open_flags_are_readonly_nofollow_cloexec_nonblocking(self):
        backend = self.S.NativeFiles.__new__(self.S.NativeFiles)
        constants = dict(O_RDONLY=0, O_NOFOLLOW=0x100, O_CLOEXEC=0x200, O_DIRECTORY=0x400, O_NONBLOCK=0x800)
        with patch.multiple(self.S.os, create=True, **constants), patch.object(self.S.os, 'open', return_value=9) as opened:
            backend.open(7, 'source', False); opened.assert_called_once_with('source', 0xb00, dir_fd=7)
            opened.reset_mock(); backend.open(7, 'child', True); opened.assert_called_once_with('child', 0x700, dir_fd=7)

    def test_exact_manifest_file_count_and_aggregate_bounds(self):
        paths = tuple('scripts/f%03d.py' % value for value in range(self.S.MAX_FILES))
        rows = [dict(path=path, bytes=1, sha256='0' * 64) for path in paths]
        manifest = dict(schemaVersion=1, scope=self.S.SCOPE, files=rows)
        self.assertEqual(len(self.S.decode(self.S.encode(manifest, paths=paths), paths=paths)['files']), 128)
        paths = paths[:17]
        manifest['files'] = [dict(path=path, bytes=self.S.MAX_FILE_BYTES, sha256='0' * 64) for path in paths[:16]]
        self.S.validate(manifest, paths=paths[:16])
        manifest['files'].append(dict(path=paths[16], bytes=1, sha256='0' * 64))
        self.denied(lambda: self.S.validate(manifest, paths=paths))

    def test_native_backend_unsupported_host_denies_without_opening_anything(self):
        with patch.object(self.S.os, 'name', 'nt'), patch.object(self.S.os, 'open') as opened:
            self.denied(self.S.NativeFiles)
            opened.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
