"""Authenticated package composition; synthetic source and no host effects."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


C = load('full_package_loader_controls', ROOT/'deploy/installer/company_full_package_loader.py')
B = load('full_package_loader_publisher', ROOT/'deploy/installer/build-full-package.py')
T = load('full_package_loader_source_fixtures', ROOT/'tests/test_company_fresh_assembly.py')
FINGERPRINT = T.T.T.FINGERPRINT


class FullPackageLoaderControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(C.UNRELEASED)
        self.assertFalse(C._COMPOSITIONS)
        self.assertFalse(B.UNRELEASED)
        self.f = T.Fixture()
        self.captures = {path: (ROOT/path).read_bytes() for path in B.PACKAGE_PATHS}
        self.pins = {path: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                     for path, raw in self.captures.items()}
        values = dict(self.f.raw, **self.captures)
        self.packet = B.assemble(ROOT, FINGERPRINT, package_pins=self.pins,
            operational_catalog=self.f.catalog,
            reader=lambda path, maximum: values[path.relative_to(ROOT).as_posix()])

    def tearDown(self):
        self.f.clean()
        self.assertFalse(C._COMPOSITIONS)
        C.UNRELEASED.clear()  # Only retained synthetic module objects, no native resources.
        B.UNRELEASED.clear()

    def context(self, **changes):
        args = dict(package_module=B, package_pins=self.pins,
                    operational_catalog=self.f.catalog, key_fingerprint=FINGERPRINT)
        args.update(changes)
        return C.authenticated_full_package(self.packet, **args)

    def shell_source(self, fixture):
        for name in ('scripts/lib.sh', 'scripts/install-runtime-gate.sh', 'scripts/install.sh'):
            fixture.values[name] = (ROOT/name).read_bytes().replace(b'\r\n', b'\n')

    def request(self, release):
        return dict(schemaVersion=1, mode='full-installation', operationId='b'*32,
            releaseSha256=release, bundleRoot='/opt/autosoft-company/incoming/release',
            sourceRoot='/opt/autosoft-company/incoming/source',
            keyPath='/opt/autosoft-company/bootstrap/company.pem', dataDir='/srv/full-package',
            backingFile='/srv/full-package.luks', capacityGiB=128,
            runscVersion='20261005.0', runscSha512='c'*128)

    def test_real_nine_captures_compose_one_original_entry_source_and_fresh_plan(self):
        with patch('subprocess.Popen', side_effect=AssertionError('native child')):
            with self.context() as composition:
                F = composition.modules[C.FULL_ENTRY]
                entry = composition.entry
                self.assertIs(type(entry), F.FullEntry)
                self.assertIs(entry.modules[F.VERIFIER], entry.origin.modules[F.VERIFIER])
                with self.f.fresh_source(entry, self.shell_source) as held:
                    with composition.fresh_foundation(held, self.request(held.metadata['releaseSha256'])) as (assembly, plan):
                        self.assertIs(assembly._entry, entry.origin)
                        self.assertIs(plan._held, held)
                        self.assertIs(plan._assembly, assembly)
                        self.assertEqual(len(plan.files), 63)
                        self.assertIs(assembly.modules[F.PARENT], entry.modules[F.PARENT])
                        self.assertEqual(plan.phase_command('activate')[6], plan.roots['finalRoot'])
                    self.assertIs(entry.modules[F.VERIFIER].require_platform_source(held), held)
                self.assertIs(composition.recheck(), composition)
                names = [module.__name__ for module in composition.modules.values()]
        self.assertTrue(all(name not in sys.modules for name in names))
        with self.assertRaises(C.FullCompositionUnavailable): composition.entry

    def test_bad_last_capture_executes_no_module(self):
        value = json.loads(self.packet)
        value['records'][C.FULL_PLAN]['base64'] = '!'*len(value['records'][C.FULL_PLAN]['base64'])
        self.packet = B.canonical(value)
        with patch.object(C, '_register', side_effect=AssertionError('compile')):
            with self.assertRaises(ValueError):
                with self.context(): self.fail('yield')

    def test_self_consistent_changed_code_cannot_replace_external_pin(self):
        value = json.loads(self.packet); changed = self.captures[C.FULL_PLAN] + b'\nraise RuntimeError("never")\n'
        value['records'][C.FULL_PLAN] = dict(bytes=len(changed), sha256=hashlib.sha256(changed).hexdigest(),
            base64=base64.b64encode(changed).decode())
        self.packet = B.canonical(value)
        with patch.object(C, '_register', side_effect=AssertionError('compile')):
            with self.assertRaises(ValueError):
                with self.context(): self.fail('yield')

    def test_catalog_and_fingerprint_mismatch_before_first_compile(self):
        for changes in (dict(key_fingerprint='0'*64), dict(operational_catalog={}), dict(package_pins={})):
            with patch.object(C, '_register', side_effect=AssertionError('compile')):
                with self.assertRaises(ValueError):
                    with self.context(**changes): self.fail('yield')

    def test_extra_record_and_boolean_schema_refuse_before_compile(self):
        original = self.packet
        for kind in ('extra', 'boolean'):
            value = json.loads(original)
            if kind == 'extra': value['records']['other.py'] = {}
            else: value['schemaVersion'] = True
            self.packet = B.canonical(value)
            with patch.object(C, '_register', side_effect=AssertionError('compile')):
                with self.assertRaises(ValueError):
                    with self.context(): self.fail('yield')

    def test_unknown_publisher_resources_refuse_before_validation_and_compile(self):
        B.UNRELEASED.append(('synthetic pending publisher reference',))
        with patch.object(C, '_register', side_effect=AssertionError('compile')):
            with self.assertRaises(C.FullCompositionUnavailable):
                with self.context(): self.fail('yield')

    def test_unissued_composition_and_subclass_deny_before_source_callbacks(self):
        class Fake(C.FullComposition): pass
        for composition in (C.FullComposition(), Fake()):
            composition._entry = SimpleNamespace(recheck=lambda: self.fail('entry callback'))
            with self.assertRaises(C.FullCompositionUnavailable): composition.recheck()
            with self.assertRaises(C.FullCompositionUnavailable):
                with composition.fresh_foundation(SimpleNamespace(recheck=lambda: self.fail('source callback')), {}):
                    self.fail('yield')

    def test_changed_publisher_function_expires_live_composition(self):
        with self.assertRaises(C.FullCompositionUnavailable):
            with self.context() as composition:
                with patch.object(B, 'validate_package', side_effect=AssertionError('substitution callback')):
                    with self.assertRaises(C.FullCompositionUnavailable): composition.recheck()
                self.assertFalse(composition._active)

    def test_changed_outer_module_registration_is_retained_without_removing_foreign_object(self):
        foreign = ModuleType('foreign_test_substitute'); name = None
        try:
            with self.assertRaises(C.FullCompositionUnavailable):
                with self.context() as composition:
                    owned = composition.modules[C.STORED_STARTUP]; name = owned.__name__
                    sys.modules[name] = foreign
                    with self.assertRaises(C.FullCompositionUnavailable): composition.recheck()
            self.assertIs(sys.modules[name], foreign)
            self.assertTrue(C.UNRELEASED)
            self.assertIs(C.UNRELEASED[0][0], composition)
            self.assertIs(composition._modules[C.STORED_STARTUP], owned)
        finally:
            if name and sys.modules.get(name) is foreign: del sys.modules[name]

    def test_body_failure_closes_known_owned_modules_and_prevents_reuse(self):
        with self.assertRaisesRegex(RuntimeError, 'body'):
            with self.context() as composition:
                names = [module.__name__ for module in composition.modules.values()]
                raise RuntimeError('body')
        self.assertTrue(all(name not in sys.modules for name in names))
        self.assertFalse(C.UNRELEASED)
        with self.assertRaises(C.FullCompositionUnavailable): composition.recheck()

    def test_partial_outer_compilation_closes_known_registered_objects(self):
        original = C._register; names = []
        def fail_second(path, raw, prefix, owned):
            if names: raise RuntimeError('partial compile')
            value = original(path, raw, prefix, owned); names.append(value.__name__); return value
        with patch.object(C, '_register', side_effect=fail_second):
            with self.assertRaisesRegex(RuntimeError, 'partial compile'):
                with self.context(): self.fail('yield')
        self.assertEqual(len(names), 1)
        self.assertTrue(all(name not in sys.modules for name in names))
        self.assertFalse(C.UNRELEASED)

    def test_existing_full_entry_activation_remains_denied(self):
        with self.assertRaises(ValueError):
            with self.context() as composition:
                composition.entry.activate_full()
        self.assertFalse(C.UNRELEASED)


if __name__ == '__main__': unittest.main(verbosity=2)
