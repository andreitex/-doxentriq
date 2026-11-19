"""Inert package/source captures and injected Linux-reader controls only."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('company_full_package_controls',
                                            ROOT / 'deploy/installer/build-full-package.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
FINGERPRINT = '5' * 64


class Fixture:
    def __init__(self, actual=False):
        self.root = ROOT if actual else ROOT / '.local/inert-company-publisher'
        paths = set(B.PACKAGE_PATHS) | set(B.OPERATIONAL_PATHS)
        self.files = {path: (ROOT / path).read_bytes() if actual else
                      ('# inert publisher ' + path + '\n').encode() for path in paths}
        self.pins = {path: self.row(self.files[path]) for path in B.PACKAGE_PATHS}
        self.catalog = {path: dict(**self.row(self.files[path]), gitMode='100644')
                        for path in B.OPERATIONAL_PATHS}
        self.events = []

    @staticmethod
    def row(raw):
        return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def reader(self, path, maximum):
        name = path.relative_to(self.root).as_posix()
        self.events.append((name, maximum))
        return self.files[name]

    def build(self, **changes):
        args = dict(package_pins=self.pins, operational_catalog=self.catalog, reader=self.reader)
        args.update(changes)
        return B.assemble(self.root, FINGERPRINT, **args)

    def validate(self, raw, **changes):
        args = dict(package_pins=self.pins, operational_catalog=self.catalog, fingerprint=FINGERPRINT)
        args.update(changes)
        return B.validate_package(raw, **args)


class FakePath:
    def __init__(self, host, name):
        self.host, self.name = host, str(name)

    def __fspath__(self):
        return self.name

    def __eq__(self, other):
        return type(other) is FakePath and self.name == other.name

    @property
    def parents(self):
        return tuple(FakePath(self.host, str(value)) for value in PurePosixPath(self.name).parents)

    def lstat(self):
        return self.host.info[self.name]

    def is_absolute(self):
        return self.name.startswith('/')


class ReadHost:
    def __init__(self):
        self.raw = b'print("never executed")\n'
        self.info = {}
        for index, name in enumerate(('/', '/station', '/station/source', '/station/source/a.py')):
            leaf = name.endswith('.py')
            self.info[name] = SimpleNamespace(st_dev=10, st_ino=index+1,
                st_mode=(stat.S_IFREG | 0o644) if leaf else (stat.S_IFDIR | 0o755),
                st_uid=0, st_gid=0, st_nlink=1 if leaf else 2,
                st_size=len(self.raw) if leaf else 4096, st_mtime_ns=100, st_ctime_ns=200)
        self.fds, self.closed, self.offset = {}, [], 0
        self.fail_close, self.read_hook = None, None
        self.os = SimpleNamespace(name='posix', O_NOFOLLOW=1, O_CLOEXEC=2, O_DIRECTORY=4,
            O_RDONLY=8, geteuid=lambda: 0, getegid=lambda: 0,
            path=SimpleNamespace(normpath=lambda path: str(path.name)),
            open=self.open, fstat=self.fstat, read=self.read, close=self.close)

    def open(self, path, flags):
        fd = 10 + len(self.fds)
        self.fds[fd] = (path.name, copy.copy(self.info[path.name]), flags)
        return fd

    def fstat(self, fd):
        return self.fds[fd][1]

    def read(self, fd, maximum):
        value = self.raw[self.offset:self.offset+maximum]
        self.offset += len(value)
        if self.read_hook:
            hook, self.read_hook = self.read_hook, None
            hook()
        return value

    def close(self, fd):
        self.closed.append(fd)
        if fd == self.fail_close:
            raise OSError('injected unknown close')

    def capture(self, maximum=None):
        with patch.object(B, 'os', self.os), patch.object(B, 'sys', SimpleNamespace(platform='linux')):
            with patch.object(B, 'Path', lambda name: FakePath(self, name)):
                return B.protected_read('/station/source/a.py', maximum or len(self.raw))


class PackageControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(B.UNRELEASED)
        self.f = Fixture()

    def tearDown(self):
        # Injected synthetic references only; product has no reset API.
        B.UNRELEASED.clear()

    def reject(self, function):
        with self.assertRaises(B.FullPackageUnavailable):
            function()

    def test_closed_package_and_operational_catalog_captured_before_inert_output(self):
        with patch('builtins.compile', side_effect=AssertionError('capture code execution')):
            raw = self.f.build()
        value = self.f.validate(raw)
        self.assertEqual([name for name, _ in self.f.events], list(B.PACKAGE_PATHS)+list(B.OPERATIONAL_PATHS))
        self.assertEqual(value['scope'], 'FULL_INSTALLATION_COMPOSITION_ONLY')
        self.assertEqual(len(value['records']), 9)
        self.assertEqual(len(value['operationalCatalog']), 16)
        self.assertEqual(value['records'][B.PACKAGE_PATHS[-1]]['bytes'], len(self.f.files[B.PACKAGE_PATHS[-1]]))

    def test_actual_current_modules_fit_and_original_six_contract_preserved(self):
        f = Fixture(actual=True)
        raw = f.build()
        value = f.validate(raw)
        six = B.PACKAGE_PATHS[:6]
        self.assertEqual(six, ('scripts/company_captured_loader.py','scripts/verify-release.py',
            'scripts/installer_parent.py','scripts/company_source_guard.py',
            'scripts/company_source_guard_backend.py','scripts/installer_materialize.py'))
        self.assertLessEqual(sum(row['bytes'] for row in value['records'].values()), B.MAX_SOURCE_BYTES)
        self.assertLessEqual(len(raw), B.MAX_PACKAGE_BYTES)
        for path in B.OPERATIONAL_PATHS:
            self.assertEqual(value['operationalCatalog'][path]['gitMode'], '100644')

    def test_deterministic_output_independent_of_input_dictionary_order(self):
        original = self.f.build()
        self.f.pins = dict(reversed(list(self.f.pins.items())))
        self.f.catalog = dict(reversed(list(self.f.catalog.items())))
        self.assertEqual(self.f.build(), original)

    def test_missing_extra_catalog_or_capture_refuses_before_reader(self):
        for field, values in (('package_pins', ({}, dict(self.f.pins, extra={}))),
                              ('operational_catalog', ({}, dict(self.f.catalog, extra={})))):
            for value in values:
                self.reject(lambda: self.f.build(**{field: value}))
        self.assertEqual(self.f.events, [])

    def test_external_integer_and_hash_types_refuse_before_reader(self):
        for bad in (True, False, 1.0, '1', 0, -1, B.MAX_CAPTURE_BYTES+1):
            pins = copy.deepcopy(self.f.pins); pins[B.PACKAGE_PATHS[-1]]['bytes'] = bad
            self.reject(lambda: self.f.build(package_pins=pins))
        for bad in (True, b'0'*64, 'A'*64, '0'*63):
            pins = copy.deepcopy(self.f.pins); pins[B.PACKAGE_PATHS[-1]]['sha256'] = bad
            self.reject(lambda: self.f.build(package_pins=pins))
        self.assertEqual(self.f.events, [])

    def test_operational_types_modes_and_total_cap_refuse_before_reader(self):
        for field, bad in (('bytes', True), ('bytes', 1.0), ('gitMode', '100755'),
                           ('gitMode', 100644), ('gitMode', True)):
            rows = copy.deepcopy(self.f.catalog); rows[B.OPERATIONAL_PATHS[0]][field] = bad
            self.reject(lambda: self.f.build(operational_catalog=rows))
        rows = copy.deepcopy(self.f.catalog)
        for path in B.OPERATIONAL_PATHS[:3]: rows[path]['bytes'] = B.MAX_OPERATIONAL_MEMBER
        self.reject(lambda: self.f.build(operational_catalog=rows))
        self.assertEqual(self.f.events, [])

    def test_catalog_and_decoded_source_caps_have_independent_denials(self):
        with patch.object(B, 'MAX_CATALOG_BYTES', 20):
            self.reject(self.f.build)
        with patch.object(B, 'MAX_SOURCE_BYTES', 20):
            self.reject(self.f.build)
        self.assertEqual(self.f.events, [])

    def test_verifier_and_parent_overlap_must_match_external_catalog(self):
        for path in ('scripts/verify-release.py', 'scripts/installer_parent.py'):
            catalog = copy.deepcopy(self.f.catalog); catalog[path]['sha256'] = '0'*64
            self.reject(lambda: self.f.build(operational_catalog=catalog))
        self.assertEqual(self.f.events, [])

    def test_bad_last_capture_refuses_without_executing_any_source(self):
        self.f.files[B.PACKAGE_PATHS[-1]] += b'\n# substituted\n'
        with patch('builtins.compile', side_effect=AssertionError('exec')):
            self.reject(self.f.build)
        self.assertEqual(len(self.f.events), 9)

    def test_changed_last_operational_file_refuses_after_all_captures(self):
        def read(path, maximum):
            name = path.relative_to(self.f.root).as_posix()
            return self.f.reader(path, maximum) + (b'x' if name == B.OPERATIONAL_PATHS[-1]
                and len(self.f.events) > 9 else b'')
        self.reject(lambda: self.f.build(reader=read))
        self.assertEqual(len(self.f.events), 25)

    def test_reader_cannot_return_mutable_or_text_capture(self):
        for raw in (bytearray(b'x'), 'x', None):
            self.reject(lambda: self.f.build(reader=lambda path, maximum: raw))

    def test_captured_inputs_detach_from_caller_mutation_during_read(self):
        def read(path, maximum):
            value = self.f.reader(path, maximum)
            self.f.pins[B.PACKAGE_PATHS[-1]]['sha256'] = '0'*64
            self.f.catalog[B.OPERATIONAL_PATHS[0]]['sha256'] = '0'*64
            return value
        original_pins, original_catalog = copy.deepcopy(self.f.pins), copy.deepcopy(self.f.catalog)
        raw = self.f.build(reader=read)
        self.f.validate(raw, package_pins=original_pins, operational_catalog=original_catalog)

    def test_fingerprint_and_explicit_reader_fail_before_source_read(self):
        for bad in (True, b'0'*64, 'A'*64, '0'*63):
            self.reject(lambda: B.assemble(self.f.root, bad, package_pins=self.f.pins,
                operational_catalog=self.f.catalog, reader=self.f.reader))
        self.reject(lambda: self.f.build(reader=None))
        self.assertEqual(self.f.events, [])

    def test_self_consistent_substitute_cannot_replace_external_pin(self):
        value = self.f.validate(self.f.build()); path = B.PACKAGE_PATHS[-1]
        raw = b'raise RuntimeError("must never run")\n'
        value['records'][path] = dict(**Fixture.row(raw), base64=base64.b64encode(raw).decode())
        self.reject(lambda: self.f.validate(B.canonical(value)))

    def test_closed_schema_and_record_boolean_float_types_deny(self):
        original = self.f.validate(self.f.build())
        for field, bad in (('schemaVersion', True), ('schemaVersion', 1.0),
                           ('scope', 'FULL_INSTALLATION'), ('keyFingerprint', '0'*64)):
            value = copy.deepcopy(original); value[field] = bad
            self.reject(lambda: self.f.validate(B.canonical(value)))
        for bad in (True, 1.0):
            value = copy.deepcopy(original); value['records'][B.PACKAGE_PATHS[0]]['bytes'] = bad
            self.reject(lambda: self.f.validate(B.canonical(value)))
        for value in (dict(original, extra=True), {k:v for k,v in original.items() if k!='records'}):
            self.reject(lambda: self.f.validate(B.canonical(value)))

    def test_noncanonical_base64_and_json_refuse(self):
        original = self.f.validate(self.f.build())
        path = B.PACKAGE_PATHS[-1]
        for encoded in ('!'*len(original['records'][path]['base64']),
                        original['records'][path]['base64']+'\n', True):
            value = copy.deepcopy(original); value['records'][path]['base64'] = encoded
            self.reject(lambda: self.f.validate(B.canonical(value)))
        for raw in (json.dumps(original, indent=2).encode(), B.canonical(original).rstrip(b'\n'),
                    b'{"schemaVersion":1,"schemaVersion":1}\n', b'\xff', b'[]\n'):
            self.reject(lambda: self.f.validate(raw))

    def test_serialized_cap_denies_before_parser_and_no_output_effect(self):
        raw = self.f.build()
        with patch.object(B, 'MAX_PACKAGE_BYTES', len(raw)-1):
            with patch.object(B.json, 'loads', side_effect=AssertionError('overcap parsed')):
                self.reject(lambda: self.f.validate(raw))
        with patch.object(B, 'MAX_PACKAGE_BYTES', len(raw)-1):
            self.reject(self.f.build)

    def test_overdepth_json_has_fixed_denial_without_capture_execution(self):
        raw = b'[' * 2000 + b']' * 2000 + b'\n'
        self.assertLess(len(raw), B.MAX_PACKAGE_BYTES)
        with patch('builtins.compile', side_effect=AssertionError('capture execution')):
            with self.assertRaisesRegex(B.FullPackageUnavailable, '^company-full-package-unavailable$'):
                self.f.validate(raw)

    def test_cli_explicitly_refuses_and_never_reads_or_emits(self):
        with patch.object(B, 'assemble', side_effect=AssertionError('CLI capture')):
            with patch.object(B.sys, 'stderr') as stderr:
                self.assertEqual(B.main(), 2)
                self.assertIn('CLI disabled', stderr.write.call_args_list[0].args[0])

    def test_native_reader_capabilities_and_nonlinux_deny_before_open(self):
        h = ReadHost()
        h.os.name = 'nt'
        self.reject(h.capture)
        self.assertEqual(h.fds, {})
        h.os.name = 'posix'; del h.os.O_NOFOLLOW
        self.reject(h.capture)
        self.assertEqual(h.fds, {})

    def test_native_reader_holds_full_nine_ancestors_and_leaf_through_read(self):
        h = ReadHost()
        self.assertEqual(h.capture(), h.raw)
        self.assertEqual([row[0] for row in h.fds.values()],
                         ['/', '/station', '/station/source', '/station/source/a.py'])
        self.assertEqual(h.closed, list(reversed(list(h.fds))))
        self.assertTrue(all(row[2] & h.os.O_NOFOLLOW for row in h.fds.values()))

    def test_native_reader_ctime_or_ancestor_replacement_denies_and_closes(self):
        for name, field in (('/station/source/a.py', 'st_ctime_ns'), ('/station', 'st_ino')):
            h = ReadHost()
            h.read_hook = lambda: setattr(h.info[name], field, getattr(h.info[name], field)+1)
            self.reject(h.capture)
            self.assertEqual(len(h.closed), 4)

    def test_native_reader_owner_mode_link_and_size_deny(self):
        for name, field, bad in (('/station', 'st_uid', 1), ('/station', 'st_mode', stat.S_IFDIR|0o777),
                ('/station/source/a.py', 'st_mode', stat.S_IFREG|0o755),
                ('/station/source/a.py', 'st_nlink', 2), ('/station/source/a.py', 'st_size', 100000)):
            h = ReadHost(); setattr(h.info[name], field, bad)
            self.reject(h.capture)
            self.assertEqual(len(h.closed), len(h.fds))

    def test_native_reader_close_failure_attempts_all_and_latches_exact_refs(self):
        h = ReadHost(); h.fail_close = 12
        self.reject(h.capture)
        self.assertEqual(h.closed, [13,12,11,10])
        self.assertEqual(B.UNRELEASED[0][0], (10,11,12,13))
        self.assertEqual(B.UNRELEASED[0][1][0][0], 12)
        self.reject(self.f.build)
        self.assertEqual(self.f.events, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
