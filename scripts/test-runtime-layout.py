"""Retained injected RUNTIME_PLACEMENT_ONLY controls; no native ownership/mounts."""
import ast
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

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


L = load('runtime_layout_controls', ROOT / 'scripts/runtime_layout.py')
B = load('runtime_layout_file_transport', ROOT / 'test/test_checkpoint_admission.py')
C = L.C


class Files(B.Files):
    """Inject root/DAC, mounts and directory-FD transport on Windows.

    Keep actual canonical paths, inode identities, bounded scans and immutable
    file writes/readback. This adapter proves decisions, not Linux permissions.
    """
    def __init__(self):
        super().__init__(); self.metadata = {}; self.after_names = None

    def info(self, path):
        actual = path.lstat()
        values = {key: getattr(actual, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        if stat.S_ISDIR(actual.st_mode):
            values.update(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o700)
            values.update(self.metadata.get(path, {}))
        return SimpleNamespace(**values)

    def directory(self, path, uid, gid, modes):
        path = Path(path); actual = B.Files.protected(self, path, directory=True)
        info = self.info(path)
        C.require(stat.S_ISDIR(actual.st_mode) and info.st_uid == uid and info.st_gid == gid and stat.S_IMODE(info.st_mode) in modes)
        return info

    def protected(self, path, directory=False, private=False):
        actual = super().protected(path, directory=directory, private=private)
        if not directory: return actual
        info = self.info(Path(path)); C.require(info.st_uid == 0 and not info.st_mode & 0o022)
        if private: C.require(stat.S_IMODE(info.st_mode) == 0o700)
        return info

    def names(self, path, maximum):
        before = self.info(path); B.Files.protected(self, path, directory=True)
        result = []
        with os.scandir(path) as entries:
            for entry in entries:
                result.append(entry.name); C.require(len(result) <= maximum)
        callback, self.after_names = self.after_names, None
        if callback: callback(path)
        C.require(C.identity(self.info(path)) == C.identity(before))
        return result

    def permission(self, path, expected, uid, gid, mode):
        C.require(C.identity(self.info(path)) == C.identity(expected))
        self.events.append(('permission', path.name, uid, gid, mode))
        self.metadata.setdefault(path, {}).update(st_uid=uid, st_gid=gid, st_mode=stat.S_IFDIR | mode)
        return self.directory(path, uid, gid, {mode})

    def mkdir(self, path):
        self.events.append(('mkdir', path.name)); return super().mkdir(path)


class Fixture:
    def __init__(self):
        artifact = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local')))
        assert artifact.is_absolute() and artifact.resolve(strict=True) == artifact and artifact.is_dir()
        self.directory = Path(tempfile.mkdtemp(prefix='runtime-layout-v1-', dir=artifact)).resolve()
        self.data = self.directory / 'data'; self.data.mkdir()
        (self.data / 'config').mkdir(); (self.data / 'quota').mkdir(); (self.data / 'runtime').mkdir()
        self.runtime = self.data / 'runtime'; self.base = self.data / 'config/runtime-layout'
        self.files = Files(); (self.runtime / 'builds').mkdir()
        self.files.metadata[self.runtime / 'builds'] = dict(st_uid=10001, st_gid=10001, st_mode=stat.S_IFDIR | 0o700)
        self.mount = dict(target=str(self.runtime / 'builds'), filesystem='tmpfs', maximumBytes=2147483648, uid=10001, gid=10001, mode=0o700, nosuid=True, nodev=True)
        self.events = self.files.events

    def call(self, mount=None):
        # Only direct path metadata reads used to select an existing owner need
        # the injected DAC view; real file protected/read paths stay unchanged.
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            actual = original(path, *args, **kwargs)
            if path not in self.files.metadata: return actual
            values = {key: getattr(actual, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
            values.update(self.files.metadata[path]); return SimpleNamespace(**values)
        with patch.object(Path, 'lstat', lstat):
            return L.prepare(self.data, files=self.files, build_mount=mount or (lambda _: self.mount))

    def permissions(self): return [event for event in self.events if event[0] == 'permission']

    def rewrite_evidence(self, *, schema=None, field=None, value=None):
        initial = self.files.read(self.base / 'intent.json')
        bound = self.files.read(self.base / 'layout.json')
        if schema is not None: initial['schemaVersion'] = schema
        if field is not None: bound['buildMount'][field] = value
        bound['intentSha256'] = C.digest(initial)
        confirmed = {'layoutSha256': C.digest(bound)}
        for name, record in (('intent.json', initial), ('layout.json', bound), ('confirmed.json', confirmed)):
            (self.base / name).write_bytes(C.canonical(record) + b'\n')
        # Mutations retain all hash correspondences so strict type validation,
        # rather than a stale digest, is the rejection being exercised.
        assert self.files.read(self.base / 'layout.json')['intentSha256'] == C.digest(self.files.read(self.base / 'intent.json'))
        assert self.files.read(self.base / 'confirmed.json')['layoutSha256'] == C.digest(self.files.read(self.base / 'layout.json'))


class Controls(unittest.TestCase):
    def test_schema_bool_or_float_rejected_with_all_evidence_hashes_consistent(self):
        for value in (True, 1.0):
            with self.subTest(value=value):
                f = Fixture(); f.call(); f.rewrite_evidence(schema=value); f.events.clear()
                with self.assertRaisesRegex(ValueError, 'schema version must be an exact integer'): f.call()
                self.assertEqual(f.permissions(), [])
                self.assertFalse(any(event[0] in ('write', 'mkdir') for event in f.events))

    def test_persisted_integer_build_fields_reject_equal_floats_after_rehash(self):
        for field in ('maximumBytes', 'uid', 'gid', 'mode'):
            with self.subTest(field=field):
                f = Fixture(); f.call(); f.rewrite_evidence(field=field, value=float(f.mount[field])); f.events.clear()
                with self.assertRaisesRegex(ValueError, 'Build mount evidence has an invalid field type'): f.call()
                self.assertEqual(f.permissions(), [])

    def test_persisted_boolean_build_fields_reject_equal_numbers_after_rehash(self):
        for field in ('nosuid', 'nodev'):
            for value in (1, 1.0):
                with self.subTest(field=field, value=value):
                    f = Fixture(); f.call(); f.rewrite_evidence(field=field, value=value); f.events.clear()
                    with self.assertRaisesRegex(ValueError, 'Build mount evidence has an invalid field type'): f.call()
                    self.assertEqual(f.permissions(), [])

    def test_live_build_proof_rejects_equal_wrong_types_before_layout_effects(self):
        for field in ('maximumBytes', 'uid', 'gid', 'mode', 'nosuid', 'nodev'):
            with self.subTest(field=field):
                f = Fixture(); value = float(f.mount[field]) if type(f.mount[field]) is int else 1
                with self.assertRaisesRegex(ValueError, 'Build mount evidence has an invalid field type'):
                    f.call(lambda _: dict(f.mount, **{field: value}))
                self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_valid_exact_typed_rehashed_records_verify_readonly(self):
        f = Fixture(); f.call(); f.rewrite_evidence(schema=1, field='uid', value=10001); f.events.clear()
        self.assertFalse(f.call()['changed']); self.assertEqual(f.permissions(), [])
        self.assertFalse(any(event[0] in ('write', 'mkdir') for event in f.events))

    def test_fresh_finite_private_children_and_storage_root(self):
        f = Fixture(); result = f.call()
        self.assertEqual(result, dict(scope=L.SCOPE, status='verified', changed=True, backupReady=False))
        self.assertEqual(set(f.files.names(f.runtime, 30)), set(L.BROKER_DIRECTORIES) | {'storage'})
        f.files.directory(f.runtime, 0, 0, {0o755}); f.files.directory(f.runtime / 'storage', 0, 0, {0o700})
        for name in L.BROKER_DIRECTORIES: f.files.directory(f.runtime / name, 10001, 10001, {0o700})
        self.assertFalse((f.data / 'quota/projects.json').exists())
        self.assertFalse((f.data / 'quota/checkpoint-admission').exists())

    def test_durable_intent_precedes_every_owner_or_mode_change(self):
        f = Fixture(); f.call(); index = f.events.index(('write', 'intent.json'))
        self.assertTrue(f.permissions())
        self.assertTrue(all(f.events.index(event) > index for event in f.permissions()))
        self.assertFalse(any(event[0] == 'permission' and event[1] == 'builds' for event in f.events))

    def test_readonly_rerun_preserves_private_broker_data_and_metadata(self):
        f = Fixture(); f.call(); (f.runtime / 'reports/sample.json').write_text('retained synthetic report')
        initial = f.files.read(f.base / 'layout.json'); f.events.clear()
        self.assertFalse(f.call()['changed']); self.assertEqual(f.permissions(), [])
        self.assertFalse(any(event[0] in ('write', 'mkdir') for event in f.events))
        self.assertEqual(f.files.read(f.base / 'layout.json'), initial)
        self.assertEqual((f.runtime / 'reports/sample.json').read_text(), 'retained synthetic report')

    def test_unknown_runtime_child_rejected_before_intent_or_permission(self):
        f = Fixture(); (f.runtime / 'unexpected').mkdir()
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_declared_child_file_is_not_adopted(self):
        f = Fixture(); (f.runtime / 'reports').write_text('retain file')
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(f.base.exists()); self.assertEqual((f.runtime / 'reports').read_text(), 'retain file')

    def test_populated_declared_child_not_adopted(self):
        f = Fixture(); (f.runtime / 'reports').mkdir(); (f.runtime / 'reports/a').write_text('retain')
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_populated_private_storage_never_adopted(self):
        f = Fixture(); (f.runtime / 'storage').mkdir(); (f.runtime / 'storage/records').write_text('retain')
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_existing_or_partial_quota_state_denies_fresh_and_confirmed_layout(self):
        for confirmed in (False, True):
            for name in ('projects.json', 'allocation', 'checkpoint-admission'):
                with self.subTest(confirmed=confirmed, name=name):
                    f = Fixture()
                    if confirmed: f.call()
                    (f.data / 'quota' / name).write_text('retained ambiguous state'); f.events.clear()
                    with self.assertRaises(ValueError): f.call()
                    self.assertEqual(f.permissions(), [])
                    self.assertFalse(any(event[0] == 'write' for event in f.events))

    def test_foreign_owner_and_writable_parent_denied(self):
        for target, change in (('runtime', dict(st_mode=stat.S_IFDIR | 0o777)), ('runtime/reports', dict(st_uid=999, st_gid=999)), ('config', dict(st_mode=stat.S_IFDIR | 0o777))):
            with self.subTest(target=target):
                f = Fixture(); path = f.data / target
                if not path.exists(): path.mkdir()
                f.files.metadata[path] = change
                with self.assertRaises(ValueError): f.call()
                self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_nested_mount_child_rejected_except_bound_builds_tmpfs(self):
        f = Fixture(); (f.runtime / 'reports').mkdir(); f.files.metadata[f.runtime / 'reports'] = dict(st_dev=f.data.stat().st_dev + 1)
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(f.base.exists())
        f = Fixture(); f.files.metadata[f.runtime / 'builds']['st_dev'] = f.data.stat().st_dev + 1
        self.assertTrue(f.call()['changed'])

    def test_partial_layout_evidence_retained_without_permission_repair(self):
        for record in ('intent.json', 'layout.json', 'confirmed.json'):
            with self.subTest(record=record):
                f = Fixture(); f.files.failures[record] = 'before'
                with self.assertRaises(OSError): f.call()
                before = list(f.events); retained = sorted(p.name for p in f.base.iterdir())
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(sorted(p.name for p in f.base.iterdir()), retained)
                self.assertEqual(f.permissions(), [e for e in before if e[0] == 'permission'])

    def test_lost_confirmed_ack_valid_durable_layout_verifies_without_replay(self):
        f = Fixture(); f.files.failures['confirmed.json'] = 'after'
        with self.assertRaises(OSError): f.call()
        f.events.clear(); self.assertFalse(f.call()['changed']); self.assertEqual(f.permissions(), [])
        self.assertFalse(any(e[0] in ('write', 'mkdir') for e in f.events))

    def test_confirmation_hash_or_missing_record_denies_rerun(self):
        for action in ('hash', 'missing'):
            with self.subTest(action=action):
                f = Fixture(); f.call()
                if action == 'hash': (f.base / 'confirmed.json').write_text('{"layoutSha256":"' + 'a' * 64 + '"}')
                else: (f.base / 'confirmed.json').rename(f.directory / 'retained-confirmed.json')
                f.events.clear()
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.permissions(), [])

    def test_replaced_runtime_child_or_control_directory_denies_rerun(self):
        for target in ('runtime', 'runtime/reports', 'config/runtime-layout'):
            with self.subTest(target=target):
                f = Fixture(); f.call(); path = f.data / target; previous = dict(f.files.metadata.get(path, {}))
                path.rename(f.directory / 'retained-original'); path.mkdir(); f.files.metadata[path] = previous
                if target == 'runtime':
                    for name in L.BROKER_DIRECTORIES + ('storage',): (path / name).mkdir()
                if target == 'config/runtime-layout':
                    for leaf in (f.directory / 'retained-original').iterdir(): (path / leaf.name).write_bytes(leaf.read_bytes())
                f.events.clear()
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.permissions(), [])

    def test_changed_control_mode_and_child_mode_denied_without_repair(self):
        for target in ('config/runtime-layout', 'runtime/reports', 'runtime/storage'):
            with self.subTest(target=target):
                f = Fixture(); f.call(); f.files.metadata.setdefault(f.data / target, {}).update(st_mode=stat.S_IFDIR | 0o755); f.events.clear()
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.permissions(), [])

    def test_changed_data_or_config_identity_denies_confirmed_rerun(self):
        for target in ('', 'config'):
            with self.subTest(target=target):
                f = Fixture(); f.call(); path = f.data / target
                f.files.metadata.setdefault(path, {}).update(st_ino=path.lstat().st_ino + 1); f.events.clear()
                with self.assertRaises(ValueError): f.call()
                self.assertEqual(f.permissions(), [])

    def test_control_directory_on_another_device_denies_fresh_and_rerun(self):
        f = Fixture(); original = f.files.mkdir
        def mkdir(path):
            original(path)
            if path == f.base: f.files.metadata[path] = dict(st_dev=f.data.stat().st_dev + 1)
        with patch.object(f.files, 'mkdir', mkdir), self.assertRaises(ValueError): f.call()
        self.assertEqual(f.permissions(), []); self.assertFalse((f.base / 'intent.json').exists())
        f = Fixture(); f.call(); f.files.metadata[f.base] = dict(st_dev=f.data.stat().st_dev + 1); f.events.clear()
        with self.assertRaises(ValueError): f.call()
        self.assertEqual(f.permissions(), [])

    def test_symlink_resolution_policy_denies_declared_child_before_placement(self):
        f = Fixture(); path = f.runtime / 'reports'; path.mkdir(); original = Path.resolve
        def resolve(current, *args, **kwargs):
            result = original(current, *args, **kwargs)
            return f.directory if current == path else result
        with patch.object(Path, 'resolve', resolve), self.assertRaises(ValueError): f.call()
        self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_unknown_build_mount_and_capacity_limits_deny_before_changes(self):
        for key, value in (('target', '/wrong'), ('filesystem', 'xfs'), ('maximumBytes', 2147483649), ('uid', 0), ('nosuid', False), ('nodev', False)):
            with self.subTest(key=key):
                f = Fixture()
                with self.assertRaises(ValueError): f.call(lambda _: dict(f.mount, **{key: value}))
                self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_build_mount_parser_exact_safe_findmnt_contract(self):
        path = Path('/synthetic/runtime/builds'); calls = []
        def command(args): calls.append(args); return str(path) + ' tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=0700 2147483648\n'
        self.assertEqual(L.builds_proof(path, command)['maximumBytes'], 2147483648)
        self.assertEqual(calls, [['/usr/bin/findmnt', '-n', '-o', 'TARGET,FSTYPE,OPTIONS,SIZE', '--bytes', '--target', str(path)]])
        for row in ('/wrong tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=700 100', str(path) + ' xfs rw,nosuid,nodev,uid=10001,gid=10001,mode=700 100', str(path) + ' tmpfs rw,nodev,uid=10001,gid=10001,mode=700 100', str(path) + ' tmpfs rw,nosuid,nodev,uid=0,gid=10001,mode=700 100', str(path) + ' tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=777 100', str(path) + ' tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=700,mode=700 100', str(path) + ' tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=700 2147483649', str(path) + ' tmpfs rw,nosuid,nodev,uid=10001,gid=10001,mode=700 0'):
            with self.subTest(row=row), self.assertRaises(ValueError): L.builds_proof(path, lambda _: row)

    def test_runtime_inventory_changes_during_scan_fail_closed(self):
        f = Fixture()
        f.files.after_names = lambda path: (path / 'unreviewed').mkdir()
        with self.assertRaises(ValueError): f.call()
        self.assertFalse(f.base.exists()); self.assertEqual(f.permissions(), [])

    def test_placement_dac_model_denies_broker_parent_writes_and_storage_traversal(self):
        f = Fixture(); f.call()
        def rights(path, uid):
            info = f.files.info(path); mode = stat.S_IMODE(info.st_mode)
            return (mode >> 6) & 7 if info.st_uid == uid else mode & 7
        self.assertEqual(rights(f.runtime, 10001), 5)
        self.assertEqual(rights(f.runtime / 'storage', 10001), 0)
        self.assertEqual(rights(f.runtime / 'reports', 10001), 7)
        self.assertEqual(rights(f.runtime / 'storage', 0), 7)

    def test_all_production_runtime_literal_children_are_declared_and_reports_mapped(self):
        names = set(); reports = []
        for path in (ROOT / 'services/runtime').glob('*.go'):
            if path.name.endswith('_test.go'): continue
            source = path.read_text()
            names.update(re.findall(r'filepath\.Join\((?:s|p\.s)\.data, "([^"/]+)"', source))
            reports.extend(re.findall(r'filepath\.Join\(s\.data, "reports", "([^"]+-report\.json)"', source))
        self.assertEqual(names, set(L.BROKER_DIRECTORIES) | {'storage'})
        self.assertEqual(sorted(reports), sorted(['jwks-refresh-report.json'] * 2 + ['tls-renewal-report.json'] * 2 + ['filesystem-revocation-report.json'] * 2))

    def test_broker_storage_paths_are_metadata_only_and_daemon_bound(self):
        source = (ROOT / 'services/runtime/resources.go').read_text(); deploy = (ROOT / 'services/runtime/deploy.go').read_text()
        body = source.split('func (s *server) quotaStorage(', 1)[1].split('func (s *server) applyMigrations(', 1)[0]
        self.assertNotRegex(body, r'os\.(Stat|Lstat|Open|Read|Write|Mkdir)')
        self.assertIn('result.Host != filepath.Join(s.hostRuntime, "storage", appID, name)', body)
        self.assertIn('"type=bind,src="+v.StorageHost+",dst=/data"', deploy)
        self.assertEqual(sum(p.read_text().count('v.StorageHost') for p in (ROOT / 'services/runtime').glob('*.go') if not p.name.endswith('_test.go')), 3)
        compose = (ROOT / 'deploy/compose.yaml').read_text().split('  broker:\n', 1)[1].split('  packager:\n', 1)[0]
        self.assertIn('user: "10001:10001"', compose); self.assertIn('cap_drop: [ALL]', compose)
        self.assertIn('${DATA_DIR:?}/runtime:/data/runtime:z', compose)

    def test_render_layout_precedes_mutable_render_storage_without_recursive_runtime_chown(self):
        tree = ast.parse((ROOT / 'scripts/bootstrap.py').read_text()); render = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'render')
        calls = [n for n in ast.walk(render) if isinstance(n, ast.Call)]
        prepare = [n for n in calls if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == '_layout' and n.func.attr == 'prepare']
        self.assertEqual(len(prepare), 1)
        mutations = [n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr in ('mkdir', 'chown', 'chmod', 'copyfile')]
        self.assertTrue(all(n.lineno > prepare[0].lineno for n in mutations))
        self.assertNotIn("('runtime', 10001)", ast.get_source_segment((ROOT / 'scripts/bootstrap.py').read_text(), render))


class DirectoryTransport:
    """Inject held POSIX directory identities; retain actual path replacements."""
    O_DIRECTORY = 0x10000
    O_NOFOLLOW = 0x20000
    O_CLOEXEC = 0x80000

    def __init__(self, files):
        self.files = files; self.handles = {}; self.opened = []; self.closed = []
        self.fail_open = None; self.fail_close = None

    def __getattr__(self, name): return getattr(os, name)

    def open(self, path, flags):
        path = Path(path)
        assert flags == os.O_RDONLY | self.O_DIRECTORY | self.O_NOFOLLOW | self.O_CLOEXEC
        if path == self.fail_open: raise OSError('injected-directory-open')
        actual = self.files.info(path); assert stat.S_ISDIR(actual.st_mode)
        fd = 9000 + len(self.opened); self.opened.append((fd, path))
        self.handles[fd] = (path, actual)
        return fd

    def descriptor(self, fd):
        path, held = self.handles[fd]
        current = self.files.info(path)
        values = {key: getattr(current, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        # A held directory FD keeps its original inode even when a same-name
        # directory replaces it. Normal entry/time changes remain observable.
        values.update({key: getattr(held, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')})
        return SimpleNamespace(**values)

    def close(self, fd):
        assert fd in self.handles
        self.closed.append(fd); del self.handles[fd]
        if fd == self.fail_close: raise OSError('injected-directory-close')


class InitializedFixture(Fixture):
    def verify(self, mount=None, transport=None):
        transport = transport or DirectoryTransport(self.files)
        self.transport = transport
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            actual = original(path, *args, **kwargs)
            if path not in self.files.metadata: return actual
            values = {key: getattr(actual, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
            values.update(self.files.metadata[path]); return SimpleNamespace(**values)
        with patch.object(Path, 'lstat', lstat), patch.object(L, 'os', transport), patch.object(self.files, 'descriptor', transport.descriptor):
            return L.verify(self.data, files=self.files, build_mount=mount or (lambda _: self.mount))

    def populate(self):
        (self.runtime / 'storage/app/documents').mkdir(parents=True)
        (self.runtime / 'storage/app/documents/current.txt').write_text('retained business document')
        (self.runtime / 'reports/retained.json').write_text('{"retained":true}')
        (self.data / 'quota/projects.json').write_text('{"doNotRead":"private"}')
        for name in ('allocation', 'checkpoint-admission'):
            (self.data / 'quota' / name).mkdir()
            (self.data / 'quota' / name / 'unknown-retained.json').write_text('{"doNotRead":"unknown"}')

    def assert_readonly(self, case):
        case.assertFalse(any(event[0] in ('write', 'mkdir', 'permission') for event in self.events))
        case.assertEqual(self.transport.handles, {})
        case.assertEqual(sorted(fd for fd, _ in self.transport.opened), sorted(self.transport.closed))


class InitializedControls(unittest.TestCase):
    def test_initialized_populated_storage_and_quota_verify_without_admission_reads_or_writes(self):
        f = InitializedFixture(); f.call(); f.populate(); f.events.clear(); reads = []
        original = f.files.read
        def read(path): reads.append(Path(path)); return original(path)
        before = {name: (f.base / name).read_bytes() for name in ('intent.json', 'layout.json', 'confirmed.json')}
        with patch.object(f.files, 'read', read): result = f.verify()
        self.assertEqual(result, {'scope': 'RUNTIME_PLACEMENT_ONLY', 'status': 'verified', 'changed': False, 'backupReady': False})
        self.assertEqual(set(reads), {f.base / name for name in before})
        self.assertEqual(before, {name: (f.base / name).read_bytes() for name in before})
        self.assertEqual((f.runtime / 'storage/app/documents/current.txt').read_text(), 'retained business document')
        f.assert_readonly(self)

    def test_semantic_build_remount_accepts_new_device_inode_without_rewriting_saved_evidence(self):
        f = InitializedFixture(); f.call(); f.populate()
        old = (f.base / 'layout.json').read_bytes(); held = f.files.info(f.runtime / 'builds')
        f.files.metadata[f.runtime / 'builds'].update(st_dev=held.st_dev + 1, st_ino=held.st_ino + 1)
        f.events.clear(); calls = []
        def mount(path): calls.append(path); return dict(f.mount)
        self.assertFalse(f.verify(mount)['changed']); self.assertEqual(calls, [f.runtime / 'builds'] * 2)
        self.assertEqual((f.base / 'layout.json').read_bytes(), old); f.assert_readonly(self)

    def test_actual_midcall_build_directory_replacement_fails_with_original_fd_held(self):
        f = InitializedFixture(); f.call(); f.events.clear(); original = f.files.read; replaced = False
        def read(path):
            nonlocal replaced
            value = original(path)
            if Path(path).name == 'layout.json' and not replaced:
                replaced = True; path = f.runtime / 'builds'
                path.rename(f.directory / 'retained-builds'); path.mkdir()
            return value
        with patch.object(f.files, 'read', read), self.assertRaises(ValueError): f.verify()
        self.assertTrue(replaced); f.assert_readonly(self)

    def test_current_build_identity_change_between_mount_proofs_is_rejected(self):
        f = InitializedFixture(); f.call(); f.events.clear(); calls = 0
        def mount(path):
            nonlocal calls
            calls += 1
            if calls == 2: f.files.metadata[path]['st_ino'] = path.lstat().st_ino + 1
            return f.mount
        with self.assertRaises(ValueError): f.verify(mount)
        self.assertEqual(calls, 2); f.assert_readonly(self)

    def test_permanent_storage_child_replacement_is_rejected_even_with_same_permissions(self):
        for name in ('storage', 'reports'):
            with self.subTest(name=name):
                f = InitializedFixture(); f.call(); path = f.runtime / name
                path.rename(f.directory / 'retained-permanent'); path.mkdir()
                f.events.clear()
                with self.assertRaisesRegex(ValueError, 'Permanent runtime directory binding changed'): f.verify()
                f.assert_readonly(self)

    def test_midcall_permanent_replacement_is_rejected_and_all_directory_handles_close(self):
        f = InitializedFixture(); f.call(); f.events.clear(); original = f.files.read; replaced = False
        def read(path):
            nonlocal replaced
            value = original(path)
            if Path(path).name == 'confirmed.json' and not replaced:
                replaced = True; path = f.runtime / 'reports'
                path.rename(f.directory / 'retained-reports'); path.mkdir()
            return value
        with patch.object(f.files, 'read', read), self.assertRaises(ValueError): f.verify()
        self.assertTrue(replaced); f.assert_readonly(self)

    def test_persisted_build_owner_mode_cannot_use_ephemeral_identity_exception(self):
        for field, value in (('st_uid', '0'), ('st_gid', '0'), ('st_mode', str(stat.S_IFDIR | 0o755))):
            with self.subTest(field=field):
                f = InitializedFixture(); f.call()
                bound = f.files.read(f.base / 'layout.json'); bound['directories']['builds'][field] = value
                (f.base / 'layout.json').write_bytes(C.canonical(bound) + b'\n')
                (f.base / 'confirmed.json').write_bytes(C.canonical({'layoutSha256': C.digest(bound)}) + b'\n')
                f.events.clear()
                with self.assertRaises(ValueError): f.verify()
                f.assert_readonly(self)

    def test_rehashed_wrong_record_types_reject_at_exact_verifier_type_gate(self):
        for action in ('schema', 'integer', 'boolean'):
            with self.subTest(action=action):
                f = InitializedFixture(); f.call()
                if action == 'schema': f.rewrite_evidence(schema=True); reason = 'schema version must be an exact integer'
                elif action == 'integer': f.rewrite_evidence(field='uid', value=10001.0); reason = 'Build mount evidence has an invalid field type'
                else: f.rewrite_evidence(field='nosuid', value=1); reason = 'Build mount evidence has an invalid field type'
                f.events.clear()
                with self.assertRaisesRegex(ValueError, reason): f.verify()
                f.assert_readonly(self)

    def test_rehashed_build_binding_fields_require_closed_canonical_decimal_strings(self):
        for field, value in (('st_dev', True), ('st_ino', '01'), ('st_uid', 10001.0)):
            with self.subTest(field=field):
                f = InitializedFixture(); f.call(); bound = f.files.read(f.base / 'layout.json')
                bound['directories']['builds'][field] = value
                (f.base / 'layout.json').write_bytes(C.canonical(bound) + b'\n')
                (f.base / 'confirmed.json').write_bytes(C.canonical({'layoutSha256': C.digest(bound)}) + b'\n')
                f.events.clear()
                with self.assertRaisesRegex(ValueError, 'canonical decimal strings'): f.verify()
                f.assert_readonly(self)

    def test_unknown_or_foreign_build_mount_proof_and_current_owner_are_rejected(self):
        for field, value in (('target', '/foreign'), ('filesystem', 'xfs'), ('maximumBytes', 2147483649), ('nosuid', False), ('nodev', 1), ('uid', 0), ('unexpected', True)):
            with self.subTest(field=field):
                f = InitializedFixture(); f.call(); f.events.clear()
                with self.assertRaises(ValueError): f.verify(lambda _: dict(f.mount, **{field: value}))
                f.assert_readonly(self)
        f = InitializedFixture(); f.call(); f.files.metadata[f.runtime / 'builds']['st_uid'] = 0; f.events.clear()
        with self.assertRaises(ValueError): f.verify()
        f.assert_readonly(self)

    def test_partial_or_changed_layout_hash_never_creates_or_repairs_records(self):
        for action in ('partial', 'hash'):
            with self.subTest(action=action):
                f = InitializedFixture(); f.call()
                if action == 'partial': (f.base / 'confirmed.json').rename(f.directory / 'retained-confirmed.json')
                else: (f.base / 'confirmed.json').write_bytes(C.canonical({'layoutSha256': '0' * 64}) + b'\n')
                f.events.clear()
                with self.assertRaises(ValueError): f.verify()
                f.assert_readonly(self)

    def test_authorized_child_contents_may_change_while_directory_binding_stays_exact(self):
        f = InitializedFixture(); f.call(); f.events.clear(); original = f.files.read; changed = False
        def read(path):
            nonlocal changed
            value = original(path)
            if not changed:
                changed = True; (f.runtime / 'reports/created-by-owner.json').write_text('{"synthetic":true}')
            return value
        with patch.object(f.files, 'read', read): self.assertFalse(f.verify()['changed'])
        self.assertTrue(changed); f.assert_readonly(self)

    def test_record_drift_between_bounded_reads_blocks_success_with_no_effects(self):
        f = InitializedFixture(); f.call(); f.events.clear(); calls = 0
        def mount(path):
            nonlocal calls
            calls += 1
            if calls == 2: f.rewrite_evidence(schema=True)
            return f.mount
        with self.assertRaisesRegex(ValueError, 'Layout records changed during verification'): f.verify(mount)
        f.assert_readonly(self)

    def test_directory_open_and_close_failures_are_fail_closed_and_release_other_owned_handles(self):
        for action in ('open', 'close'):
            with self.subTest(action=action):
                f = InitializedFixture(); f.call(); f.events.clear(); transport = DirectoryTransport(f.files)
                if action == 'open': transport.fail_open = f.runtime / 'reports'
                else: transport.fail_close = 9000
                with self.assertRaisesRegex(OSError, 'injected-directory-' + action): f.verify(transport=transport)
                f.assert_readonly(self)


if __name__ == '__main__': unittest.main(verbosity=2)
