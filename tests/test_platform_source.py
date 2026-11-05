"""Pure archive controls and injected Git/filesystem protocol; no native release."""
import ast
import copy
import hashlib
import importlib.util
import json
import pathlib
import stat
import struct
import sys
import types
import unittest
from unittest import mock
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('platform_source_tested', ROOT / 'scripts/platform_source.py')
P = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = P
spec.loader.exec_module(P)
REVISION = 'a' * 40
SOURCE_ROOT = pathlib.Path(pathlib.Path.cwd().anchor) / 'clean-company-source-fixture'


def host_catalog():
    tree = ast.parse((ROOT / 'scripts/company_source.py').read_text())
    node = next(node for node in tree.body if isinstance(node, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == 'INSTALLER_RUNTIME_SOURCES' for t in node.targets))
    return tuple(sorted(ast.literal_eval(node.value.args[0].args[0])))


HOST_PATHS = host_catalog()
DEPLOYMENT_PATHS = ('deploy/compose.yaml', 'deploy/config/grafana-datasources.yml',
    'deploy/config/loki.yml', 'deploy/config/mysql.cnf', 'deploy/config/otel.yml',
    'deploy/config/prometheus-web.yml', 'deploy/config/prometheus.yml',
    'deploy/config/rabbitmq.conf', 'deploy/config/redis.conf', 'deploy/config/squid.conf')


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def git_tree(entries):
    nested = {}
    for path, mode, digest in entries:
        node = nested
        parts = path.split('/')
        for part in parts[:-1]: node = node.setdefault(part, {})
        node[parts[-1]] = (mode, digest)
    def tree_digest(node):
        names = sorted(node, key=lambda name: (name + ('/' if isinstance(node[name], dict) else '')).encode())
        output = b''
        for name in names:
            child = node[name]
            mode, digest = ('40000', tree_digest(child)) if isinstance(child, dict) else child
            output += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
        return hashlib.sha1(b'tree ' + str(len(output)).encode() + b'\0' + output).hexdigest()
    return tree_digest(nested)


def fixture():
    paths = set(P.REQUIRED_ANCHORS) | set(HOST_PATHS) | set(DEPLOYMENT_PATHS)
    paths |= {root + '/fixture.txt' for root in P.SOURCE_ROOTS}
    paths |= {'packages/extra/required-nonanchor.ts', 'tools/zero.txt', 'scripts/runner.sh'}
    files = {path: (path + '\n').encode() for path in sorted(paths)}
    files['tools/zero.txt'] = b''
    modes = {path: '100755' if path.endswith('.sh') else '100644' for path in files}
    return files, modes


def manifests(files):
    def one(paths, scope):
        return P.canonical(dict(schemaVersion=1, scope=scope, files=[
            dict(path=path, bytes=len(files[path]), sha256=hashlib.sha256(files[path]).hexdigest())
            for path in sorted(paths)]))
    return one(HOST_PATHS, 'COMPANY_SOURCE_BYTES_ONLY'), one(DEPLOYMENT_PATHS, 'COMPANY_DEPLOYMENT_BYTES_ONLY')


def bundle(files=None, modes=None):
    if files is None: files, modes = fixture()
    entries = [(p, modes[p], git_blob(data)) for p, data in files.items()]
    return P._build(REVISION, git_tree(entries), files, modes)


def verify(value, *, manifest=None, archive=None, host=None, deployment=None, host_paths=HOST_PATHS, deployment_paths=DEPLOYMENT_PATHS):
    h, d = manifests(value.files)
    return P.verify_archive(manifest or value.manifest_bytes, value.archive_bytes if archive is None else archive,
        host_manifest_raw=h if host is None else host, deployment_manifest_raw=d if deployment is None else deployment,
        host_paths=host_paths, deployment_paths=deployment_paths)


def repin(value, archive):
    manifest = json.loads(value.manifest_bytes)
    manifest['archive'] = dict(bytes=len(archive), sha256=hashlib.sha256(archive).hexdigest())
    return P.canonical(manifest)


class FakeGitRunner:
    def __init__(self, files, modes):
        self.entries = [(p, modes[p], git_blob(data)) for p, data in sorted(files.items())]
        self.tree = git_tree(self.entries)
        self.head = REVISION
        self.untracked = b''
        self.ignored = b''
        self.index_entries = None
        self.calls = []
        self.before_call = None
    def __call__(self, argv, *, env, limit, timeout):
        self.calls.append((argv, env, limit, timeout))
        if self.before_call is not None: self.before_call(self, argv)
        if argv[-2:] == ('rev-parse', '--show-toplevel'): return str(SOURCE_ROOT).encode() + b'\n'
        if argv[-3:] == ('rev-parse', '--verify', 'HEAD^{commit}'): return self.head.encode() + b'\n'
        if argv[-3:] == ('rev-parse', '--verify', REVISION + '^{tree}'): return self.tree.encode() + b'\n'
        if 'ls-files' in argv:
            if '--stage' in argv:
                entries = self.entries if self.index_entries is None else self.index_entries
                return b''.join((mode + ' ' + digest + ' 0\t' + path).encode() + b'\0' for path, mode, digest in sorted(entries))
            return self.ignored if '--ignored' in argv else self.untracked
        if 'ls-tree' in argv:
            return b''.join((mode + ' blob ' + digest + '\t' + path).encode() + b'\0' for path, mode, digest in self.entries)
        raise AssertionError('Unexpected command')
    def adapter(self):
        return P.NativeGit(str(SOURCE_ROOT.parent / 'fixed-git'), self)


class FakeFiles:
    def __init__(self, files, modes):
        self.data = {SOURCE_ROOT / p: data for p, data in files.items()}
        self.stats = {}
        directories = {SOURCE_ROOT, *SOURCE_ROOT.parents}
        for path in self.data: directories.update(p for p in path.parents if p == SOURCE_ROOT or SOURCE_ROOT in p.parents)
        for path in sorted(directories, key=str): self.make_stat(path, True, 0, 0o755)
        for path, data in self.data.items(): self.make_stat(path, False, len(data), 0o755 if modes[str(path.relative_to(SOURCE_ROOT)).replace('\\', '/')] == '100755' else 0o644)
        self.handles = {}
        self.closed = []
        self.opened = []
        self.fail_close = set()
        self.close_false = set()
        self.next_fd = 10
        self.inheritable = set()
        self.on_read = None
    def make_stat(self, path, directory, size, mode):
        self.stats[path] = types.SimpleNamespace(st_dev=1, st_ino=100 + len(self.stats),
            st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode, st_uid=0, st_gid=0,
            st_nlink=2 if directory else 1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)
    def lstat(self, path): return copy.copy(self.stats[path])
    def fstat(self, fd): return copy.copy(self.handles[fd][1])
    def cloexec(self, fd): return fd not in self.inheritable
    def open(self, parent, name, directory):
        path = pathlib.Path(name) if parent is None else self.handles[parent][0] / name
        self.opened.append((path, directory))
        fd = self.next_fd; self.next_fd += 1
        self.handles[fd] = (path, copy.copy(self.stats[path]))
        return fd
    def read(self, fd, amount, offset):
        if self.on_read is not None: self.on_read(self, fd, amount, offset)
        return self.data[self.handles[fd][0]][offset:offset + amount]
    def close(self, fd):
        self.closed.append(fd)
        if fd in self.fail_close: raise OSError('Private synthetic error')
        if fd in self.close_false: return False
        del self.handles[fd]


class PlatformSourceTests(unittest.TestCase):
    def setUp(self):
        P.UNRELEASED_HANDLES.clear()
        self.files, self.modes = fixture()
        self.value = bundle(self.files, self.modes)
    def tearDown(self): P.UNRELEASED_HANDLES.clear()
    def denies(self, call):
        with self.assertRaisesRegex(P.SourceUnavailable, '^platform-source-unavailable$'): call()
    def capture(self, backend=None, runner=None):
        backend = backend or FakeFiles(self.files, self.modes)
        runner = runner or FakeGitRunner(self.files, self.modes)
        return P.capture_git_revision(SOURCE_ROOT, REVISION, git=runner.adapter(), backend=backend)

    def test_deterministic_complete_archive_and_zero_byte_file(self):
        again = bundle(dict(reversed(list(self.files.items()))), dict(reversed(list(self.modes.items()))))
        self.assertEqual(self.value.manifest_bytes, again.manifest_bytes)
        self.assertEqual(self.value.archive_bytes, again.archive_bytes)
        result = verify(self.value)
        self.assertEqual(dict(result.files), self.files)
        self.assertEqual(result.files['tools/zero.txt'], b'')
        self.assertEqual(result.git_modes['scripts/runner.sh'], '100755')
        self.assertEqual(result.archive_bytes_count, len(self.value.archive_bytes))
    def test_result_maps_and_attributes_are_immutable(self):
        result = verify(self.value)
        with self.assertRaises(TypeError): result.files['README.md'] = b'changed'
        with self.assertRaises(TypeError): result.git_modes['README.md'] = '100755'
        with self.assertRaises(AttributeError): result.archive_bytes = b'changed'
    def test_public_metadata_and_workflows_preserved_as_optional_source_bytes(self):
        additions = {'LICENSE': b'Apache License\r\nVersion 2.0\r\n',
            'CONTRIBUTING.md': b'Contribution instructions\n',
            'SECURITY.md': b'Private vulnerability reporting\n',
            'RELEASING.md': b'Release instructions\n',
            'PUBLIC-SOURCE.json': b'{"developmentPreview":true}\n',
            '.github/workflows/checks.yml': b'name: checks\n'}
        files = dict(self.files, **additions)
        modes = dict(self.modes, **{path: '100644' for path in additions})
        result = verify(bundle(files, modes))
        for path, data in additions.items():
            self.assertEqual(result.files[path], data)
        # Historical layouts without optional publication metadata stay valid.
        self.assertEqual(dict(verify(self.value).files), self.files)
    def test_git_sha1_reference_vectors(self):
        self.assertEqual(P._blob(b''), 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')
        self.assertEqual(P._tree([]), '4b825dc642cb6eb9a060e54bf8d69288fbee4904')
        self.assertEqual(P._tree([(p, self.modes[p], git_blob(data)) for p, data in self.files.items()]),
                         git_tree([(p, self.modes[p], git_blob(data)) for p, data in self.files.items()]))
    def test_manifest_duplicate_json_keys_and_nonfinite_refused(self):
        self.denies(lambda: P.validate_manifest(self.value.manifest_bytes.replace(b'"fileCount":', b'"fileCount":0,"fileCount":', 1)))
        self.denies(lambda: P.validate_manifest(self.value.manifest_bytes.replace(b'"fileCount":', b'"unused":NaN,"fileCount":', 1)))
    def test_manifest_canonical_version_and_closed_schema(self):
        self.denies(lambda: P.validate_manifest(self.value.manifest_bytes.rstrip(b'\n')))
        for key, value in (('schemaVersion', True), ('policyVersion', 2), ('fileCount', True), ('totalBytes', 1.0), ('sourceRevision', 'b' * 39), ('scope', 'foreign')):
            with self.subTest(key=key):
                manifest = json.loads(self.value.manifest_bytes); manifest[key] = value
                self.denies(lambda: P.validate_manifest(P.canonical(manifest)))
        manifest = json.loads(self.value.manifest_bytes); manifest['extra'] = None
        self.denies(lambda: P.validate_manifest(P.canonical(manifest)))
    def test_member_size_mode_hash_types(self):
        for key, value in (('bytes', True), ('bytes', -1), ('bytes', P.MAX_FILE_BYTES + 1), ('gitMode', '120000'), ('gitMode', 100644), ('sha256', 'A' * 64)):
            with self.subTest(key=key, value=value):
                manifest = json.loads(self.value.manifest_bytes); manifest['files'][0][key] = value
                self.denies(lambda: P.validate_manifest(P.canonical(manifest)))
    def test_manifest_missing_anchor_and_source_root_refused(self):
        for target in ('package-lock.json', 'scripts/installation-status.py', 'tools/fixture.txt'):
            files = dict(self.files)
            if target == 'tools/fixture.txt': files = {p: v for p, v in files.items() if not p.startswith('tools/')}
            else: del files[target]
            modes = {p: self.modes[p] for p in files}
            self.denies(lambda: bundle(files, modes))
    def test_duplicate_case_conflict_and_file_ancestor_refused(self):
        manifest = json.loads(self.value.manifest_bytes)
        manifest['files'].append(dict(manifest['files'][0])); manifest['fileCount'] += 1; manifest['totalBytes'] += manifest['files'][0]['bytes']
        self.denies(lambda: P.validate_manifest(P.canonical(manifest)))
        for path in ('scripts/Runner.sh', 'packages/core/package.json/child.ts'):
            files = dict(self.files, **{path: b'extra'}); modes = dict(self.modes, **{path: '100644'})
            self.denies(lambda: P._paths(tuple(sorted(files))))
    def test_traversal_nonascii_absolute_and_ambiguous_paths_refused(self):
        for path in ('../README.md', '/scripts/runner.sh', 'scripts//a.py', 'scripts/./a.py', 'scripts/a../b.py', 'scripts/a.', 'scripts/é.py', 'scripts/a\\b.py', 'scripts/a\0b.py'):
            with self.subTest(path=path): self.denies(lambda: P.relative_path(path))
    def test_directory_only_case_alias_refused(self):
        files = dict(self.files, **{'packages/Core/a.ts': b'a', 'packages/core/b.ts': b'b'})
        modes = dict(self.modes, **{'packages/Core/a.ts': '100644', 'packages/core/b.ts': '100644'})
        self.denies(lambda: bundle(files, modes))
    def test_tracked_secret_generated_unknown_or_customer_inputs_refused(self):
        for path in ('scripts/.env.example', 'scripts/private.pem', 'scripts/private.ppk', 'deploy/verification/result.json',
                     'scripts/policy-test-fixture/test.py', 'packages/node_modules/x.js', 'apps/customer/src/main.ts', 'unknown.txt', '.local/data.json',
                     '.github/secrets/credentials.json', '.github/workflows/private.key', '.github/.env'):
            with self.subTest(path=path): self.denies(lambda: P.relative_path(path))
    def test_file_count_directory_total_path_and_ustar_bounds(self):
        manifest = json.loads(self.value.manifest_bytes)
        manifest['files'] = manifest['files'] * (P.MAX_FILES // len(manifest['files']) + 1)
        self.denies(lambda: P.validate_manifest(P.canonical(manifest)))
        with mock.patch.object(P, 'MAX_DIRECTORIES', 1): self.denies(lambda: bundle(self.files, self.modes))
        with mock.patch.object(P, 'MAX_TOTAL_BYTES', 1): self.denies(lambda: bundle(self.files, self.modes))
        self.denies(lambda: P.relative_path('scripts/' + 'a' * 249))
        files = dict(self.files, **{'scripts/' + 'a' * 101: b'x'}); modes = dict(self.modes, **{'scripts/' + 'a' * 101: '100644'})
        self.denies(lambda: bundle(files, modes))
    def test_compressed_pin_checked_before_inflation(self):
        with mock.patch.object(P, '_inflate', side_effect=AssertionError('must not inflate')):
            self.denies(lambda: verify(self.value, archive=self.value.archive_bytes[:-1] + b'x'))
    def test_gzip_concatenation_trailing_truncation_and_crc_refused(self):
        for raw in (self.value.archive_bytes * 2, self.value.archive_bytes + b'junk', self.value.archive_bytes[:-1],
                    self.value.archive_bytes[:-8] + b'\0' * 8):
            with self.subTest(size=len(raw)): self.denies(lambda: verify(self.value, archive=raw, manifest=repin(self.value, raw)))
    def test_single_gzip_header_no_name_or_timestamp(self):
        for index in (3, 4, 9):
            raw = bytearray(self.value.archive_bytes); raw[index] ^= 1; raw = bytes(raw)
            self.denies(lambda: verify(self.value, archive=raw, manifest=repin(self.value, raw)))
    def test_expanded_compressed_and_manifest_caps(self):
        with mock.patch.object(P, 'MAX_EXPANDED_BYTES', 100): self.denies(lambda: P._inflate(self.value.archive_bytes))
        with mock.patch.object(P, 'MAX_GZIP_BYTES', len(self.value.archive_bytes) - 1): self.denies(lambda: P._inflate(self.value.archive_bytes))
        with mock.patch.object(P, 'MAX_MANIFEST_BYTES', len(self.value.manifest_bytes) - 1): self.denies(lambda: P.validate_manifest(self.value.manifest_bytes))
    def test_special_tar_types_and_extensions_refused(self):
        original = P._inflate(self.value.archive_bytes)
        for kind in (b'1', b'2', b'3', b'4', b'5', b'6', b'x', b'g', b'L', b'S'):
            changed = bytearray(original); changed[156:157] = kind
            raw = P._gzip(bytes(changed))
            self.denies(lambda: verify(self.value, archive=raw, manifest=repin(self.value, raw)))
    def test_tar_header_metadata_name_mode_and_checksum_refused(self):
        original = P._inflate(self.value.archive_bytes)
        for index in (0, 100, 108, 116, 136, 148, 257, 265, 297, 329, 345):
            changed = bytearray(original); changed[index] ^= 1
            raw = P._gzip(bytes(changed))
            self.denies(lambda: verify(self.value, archive=raw, manifest=repin(self.value, raw)))
    def test_tar_data_padding_and_exact_end_geometry(self):
        original = P._inflate(self.value.archive_bytes)
        first = json.loads(self.value.manifest_bytes)['files'][0]
        for index in (512, 512 + first['bytes'], len(original) - 1):
            changed = bytearray(original); changed[index] ^= 1
            raw = P._gzip(bytes(changed))
            self.denies(lambda: verify(self.value, archive=raw, manifest=repin(self.value, raw)))
        for changed in (original[:-512], original + b'\0' * 10240, original + b'x'):
            raw = P._gzip(changed)
            self.denies(lambda: verify(self.value, archive=raw, manifest=repin(self.value, raw)))
    def test_duplicate_extra_missing_or_reordered_tar_members(self):
        original = P._inflate(self.value.archive_bytes)
        first = json.loads(self.value.manifest_bytes)['files'][0]
        size = 512 + ((first['bytes'] + 511) // 512) * 512
        for changed in (original[:size] + original, original[size:], original[size:2 * size] + original[:size] + original[2 * size:]):
            raw = P._gzip(changed)
            self.denies(lambda: verify(self.value, archive=raw, manifest=repin(self.value, raw)))
    def test_independent_catalog_counts_missing_extra_and_cross_hash_denied(self):
        self.assertEqual(len(HOST_PATHS), 44); self.assertEqual(len(DEPLOYMENT_PATHS), 10)
        for host_paths in (HOST_PATHS[:-1], (*HOST_PATHS, 'scripts/extra.py'), (*HOST_PATHS[:-1], 'scripts/foreign.py')):
            self.denies(lambda: verify(self.value, host_paths=host_paths))
        h, d = manifests(self.files)
        for raw, field in ((h, 'host'), (d, 'deployment')):
            changed = json.loads(raw); changed['files'][0]['sha256'] = 'b' * 64
            self.denies(lambda: verify(self.value, **{field: P.canonical(changed)}))
    def test_source_tree_must_match_actual_archive_blob_bytes(self):
        manifest = json.loads(self.value.manifest_bytes); manifest['sourceTree'] = 'b' * 40
        self.denies(lambda: verify(self.value, manifest=P.canonical(manifest)))
    def test_clean_complete_git_capture_and_expiring_aliases(self):
        backend, runner = FakeFiles(self.files, self.modes), FakeGitRunner(self.files, self.modes)
        with self.capture(backend, runner) as captured:
            aliases = captured.files, captured.git_modes
            self.assertEqual(dict(captured.files), self.files)
            self.assertEqual(captured.manifest_bytes, self.value.manifest_bytes)
            self.assertEqual(captured.archive_bytes, self.value.archive_bytes)
            captured.recheck()
        self.assertFalse(backend.handles)
        self.denies(lambda: captured.manifest_bytes)
        self.denies(lambda: aliases[0]['README.md'])
        self.denies(lambda: len(aliases[1]))
    def test_git_revision_staged_ignored_and_untracked_denied_before_file_open(self):
        for field, value in (('head', 'b' * 40), ('index_entries', []), ('untracked', b'extra\0'), ('ignored', b'node_modules/\0')):
            backend, runner = FakeFiles(self.files, self.modes), FakeGitRunner(self.files, self.modes)
            setattr(runner, field, value)
            self.denies(lambda: self.capture(backend, runner).__enter__())
            self.assertFalse(backend.handles)
            self.assertTrue(all(path not in backend.data for path, _ in backend.opened))
    def test_omitted_tracked_nonanchor_fails_independent_tree_binding(self):
        backend, runner = FakeFiles(self.files, self.modes), FakeGitRunner(self.files, self.modes)
        runner.entries = [row for row in runner.entries if row[0] != 'packages/extra/required-nonanchor.ts']
        self.denies(lambda: self.capture(backend, runner).__enter__())
        self.assertTrue(all(path not in backend.data for path, _ in backend.opened))
    def test_git_symlink_submodule_duplicate_and_unknown_tracked_refused(self):
        for entry in (('scripts/link', '120000', 'b' * 40), ('packages/submodule', '160000', 'b' * 40),
                      ('scripts/private.key', '100644', 'b' * 40), ('unknown.txt', '100644', 'b' * 40)):
            runner = FakeGitRunner(self.files, self.modes); runner.entries.append(entry)
            self.denies(lambda: self.capture(runner=runner).__enter__())
        runner = FakeGitRunner(self.files, self.modes); runner.entries.append(runner.entries[0])
        self.denies(lambda: self.capture(runner=runner).__enter__())
    def test_git_command_protocol_is_fixed_bounded_and_clear_environment(self):
        runner = FakeGitRunner(self.files, self.modes)
        with self.capture(runner=runner): pass
        for argv, env, limit, timeout in runner.calls:
            self.assertEqual(argv[0], str(SOURCE_ROOT.parent / 'fixed-git'))
            self.assertEqual(env, dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LANG='C', LC_ALL='C', TZ='UTC', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1'))
            self.assertEqual(limit, P.MAX_GIT_OUTPUT_BYTES); self.assertEqual(timeout, 30)
            self.assertIn('core.fsmonitor=false', argv); self.assertIn('--no-optional-locks', argv)
            self.assertIn('--no-replace-objects', argv); self.assertIn('--no-lazy-fetch', argv)
            self.assertNotIn('status', argv); self.assertNotIn('diff', argv); self.assertNotIn('hash-object', argv)
        self.assertTrue(any('--stage' in argv for argv, *_ in runner.calls))
        self.assertTrue(any('--ignored' in argv for argv, *_ in runner.calls))
    def test_hostile_attributes_never_select_filter_execution_or_replacement(self):
        files, modes = dict(self.files), dict(self.modes)
        files['.gitattributes'] = b'*.txt filter=hostile diff=hostile\n'
        runner = FakeGitRunner(files, modes); backend = FakeFiles(files, modes)
        def hostile(_, argv):
            if any(command in argv for command in ('status', 'diff', 'diff-files', 'hash-object', 'checkout')):
                raise AssertionError('Configured filter could execute')
            self.assertIn('--no-replace-objects', argv)
            self.assertIn('--no-lazy-fetch', argv)
        runner.before_call = hostile
        with P.capture_git_revision(SOURCE_ROOT, REVISION, git=runner.adapter(), backend=backend) as captured:
            self.assertEqual(captured.files['.gitattributes'], files['.gitattributes'])
        self.assertFalse(backend.handles)
    def test_git_runner_failure_overflow_and_untyped_output_refused(self):
        for outcome in (bytearray(b'a'), b'x' * (P.MAX_GIT_OUTPUT_BYTES + 1), OSError('private')):
            def failed(*args, **kwargs):
                if isinstance(outcome, Exception): raise outcome
                return outcome
            self.denies(lambda: P.capture_git_revision(SOURCE_ROOT, REVISION,
                git=P.NativeGit(str(SOURCE_ROOT.parent / 'fixed-git'), failed), backend=FakeFiles(self.files, self.modes)).__enter__())
    def test_file_blob_mode_symlink_owner_link_and_ancestor_changes_refused(self):
        for field, value in (('st_uid', 1), ('st_nlink', 2), ('st_mode', stat.S_IFLNK | 0o644), ('st_mode', stat.S_IFREG | 0o755)):
            backend = FakeFiles(self.files, self.modes)
            setattr(backend.stats[SOURCE_ROOT / 'README.md'], field, value)
            self.denies(lambda: self.capture(backend).__enter__())
            self.assertFalse(backend.handles)
        backend = FakeFiles(self.files, self.modes); backend.data[SOURCE_ROOT / 'README.md'] = b'x' * len(self.files['README.md'])
        self.denies(lambda: self.capture(backend).__enter__()); self.assertFalse(backend.handles)
        backend = FakeFiles(self.files, self.modes); backend.stats[SOURCE_ROOT].st_mode = stat.S_IFLNK | 0o755
        self.denies(lambda: self.capture(backend).__enter__()); self.assertFalse(backend.handles)
    def test_stable_metadata_content_drift_expires_all_access(self):
        backend = FakeFiles(self.files, self.modes)
        with self.assertRaises(P.SourceUnavailable):
            with self.capture(backend) as captured:
                backend.data[SOURCE_ROOT / 'README.md'] = b'x' * len(self.files['README.md'])
                self.denies(captured.recheck)
                self.denies(lambda: captured.files)
                backend.data[SOURCE_ROOT / 'README.md'] = self.files['README.md']
                self.denies(lambda: captured.archive_bytes)
        # The context exit still denies after an earlier failed recheck.
    def test_mid_read_path_replacement_and_fd_inheritance_closed(self):
        backend = FakeFiles(self.files, self.modes)
        def replace(files, fd, amount, offset):
            path = files.handles[fd][0]
            if path == SOURCE_ROOT / 'README.md': files.stats[path].st_ino += 10000
        backend.on_read = replace
        self.denies(lambda: self.capture(backend).__enter__()); self.assertFalse(backend.handles)
        backend = FakeFiles(self.files, self.modes); backend.inheritable.add(10)
        self.denies(lambda: self.capture(backend).__enter__()); self.assertEqual(backend.closed, [10])
    def test_recheck_head_change_refuses_acknowledgement(self):
        backend, runner = FakeFiles(self.files, self.modes), FakeGitRunner(self.files, self.modes)
        with self.assertRaises(P.SourceUnavailable):
            with self.capture(backend, runner) as captured:
                runner.head = 'b' * 40
                captured.recheck()
        self.assertFalse(backend.handles)
    def test_failed_close_retains_exact_reference_and_blocks_next_capture(self):
        for kind in ('raise', 'false'):
            P.UNRELEASED_HANDLES.clear()
            backend = FakeFiles(self.files, self.modes)
            if kind == 'raise': backend.fail_close.add(10)
            else: backend.close_false.add(10)
            with self.assertRaises(P.SourceUnavailable):
                with self.capture(backend): pass
            self.assertEqual(len(P.UNRELEASED_HANDLES), 1)
            self.assertIs(P.UNRELEASED_HANDLES[0][0], backend)
            self.assertEqual(P.UNRELEASED_HANDLES[0][1], 10)
            self.assertEqual(set(backend.handles), {10})
            self.assertEqual(len(backend.closed), len(backend.opened))
            next_backend = FakeFiles(self.files, self.modes)
            self.denies(lambda: self.capture(next_backend).__enter__())
            self.assertFalse(next_backend.handles)
    def test_native_backend_and_untrusted_git_adapter_not_default_authority(self):
        with mock.patch.object(P.os, 'name', 'nt'): self.denies(P.NativeFiles)
        self.denies(lambda: P.capture_git_revision(SOURCE_ROOT, REVISION, git=types.SimpleNamespace(inspect=lambda *_: None), backend=FakeFiles(self.files, self.modes)).__enter__())


if __name__ == '__main__':
    unittest.main(verbosity=2)
