"""Original verifier/guard identity composition; injected IO, no native entry."""
import base64
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


F = load('full_entry_controls', ROOT/'deploy/installer/company_full_entry.py')
T = load('full_entry_captured_fixtures', ROOT/'tests/test_company_captured_loader.py')


class Fixture(T.Fixture):
    def __init__(self):
        super().__init__()
        self.package = {path:(ROOT/path).read_bytes() for path in F.PACKAGE_PATHS}
        self.package_pins = {path:dict(bytes=len(raw),sha256=F.sha(raw)) for path,raw in self.package.items()}
        self.records = {path:dict(**self.package_pins[path],base64=base64.b64encode(raw).decode()) for path,raw in self.package.items()}

    def entry(self, **changes):
        args=dict(package_pins=self.package_pins,operational_catalog=self.catalog,key_fingerprint=T.FINGERPRINT)
        args.update(changes)
        return F.authenticated_entry_modules(self.records, **args)


class FullEntryControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(F.UNRELEASED)
        self.f = Fixture()

    def tearDown(self):
        self.f.clean()
        self.assertFalse(F._ISSUED_ENTRIES)
        # Synthetic ownership failures only. No product retry/reset is exposed.
        F.UNRELEASED.clear()

    def reject(self, call):
        with self.assertRaises((F.FullEntryUnavailable,ValueError,TypeError)):
            call()

    def enter(self, **changes):
        with self.f.entry(**changes):
            pass

    def test_exact_package_captures_are_immutable_and_detached(self):
        raw,pins=F.decode_exact_embedded_records(self.f.records,package_pins=self.f.package_pins)
        self.assertIs(type(raw),MappingProxyType)
        self.assertEqual(dict(raw),self.f.package)
        self.f.records[F.MATERIALIZER]['base64']='bad'
        self.f.package_pins[F.BACKEND]['sha256']='0'*64
        self.assertEqual(raw[F.MATERIALIZER],self.f.package[F.MATERIALIZER])
        self.assertNotEqual(pins[F.BACKEND]['sha256'],'0'*64)

    def test_bad_last_capture_executes_zero_modules(self):
        self.f.records[F.MATERIALIZER]['base64']='!'*len(self.f.records[F.MATERIALIZER]['base64'])
        with patch.object(F,'_register',side_effect=AssertionError('package execution')):
            self.reject(self.enter)

    def test_record_self_hash_cannot_replace_independent_package_pin(self):
        raw=self.f.package[F.MATERIALIZER]+b'\n# substituted\n'
        self.f.records[F.MATERIALIZER]=dict(bytes=len(raw),sha256=F.sha(raw),base64=base64.b64encode(raw).decode())
        with patch.object(F,'_register',side_effect=AssertionError('execution')):
            self.reject(self.enter)

    def test_closed_record_inventory_and_types_reject_before_compile(self):
        for records in ({},dict(self.f.records,extra={}),MappingProxyType(dict(self.f.records))):
            with self.assertRaises(F.FullEntryUnavailable):
                F.decode_exact_embedded_records(records,package_pins=self.f.package_pins)
        for field,bad in (('bytes',True),('bytes',1.0),('sha256','A'*64),('base64',b'YQ==')):
            records=copy.deepcopy(self.f.records);records[F.MATERIALIZER][field]=bad
            with self.assertRaises(F.FullEntryUnavailable):
                F.decode_exact_embedded_records(records,package_pins=self.f.package_pins)

    def test_closed_independent_pins_and_capture_caps_reject_before_compile(self):
        for pins in ({},dict(self.f.package_pins,extra={})):
            with patch.object(F,'_register',side_effect=AssertionError('execution')):
                self.reject(lambda:self.enter(package_pins=pins))
        for bad in (True,1.0,F.MAX_CAPTURE_BYTES+1):
            pins=copy.deepcopy(self.f.package_pins);pins[F.MATERIALIZER]['bytes']=bad
            with patch.object(F,'_register',side_effect=AssertionError('execution')):
                self.reject(lambda:self.enter(package_pins=pins))
        pins={path:dict(bytes=F.MAX_CAPTURE_BYTES,sha256='0'*64) for path in F.PACKAGE_PATHS}
        with patch.object(F,'_register',side_effect=AssertionError('execution')):
            self.reject(lambda:self.enter(package_pins=pins))

    def test_noncanonical_base64_padding_whitespace_and_extra_fields_refuse(self):
        pins={path:dict(bytes=1,sha256=F.sha(b'a')) for path in F.PACKAGE_PATHS}
        records={path:dict(**pins[path],base64='YQ==') for path in F.PACKAGE_PATHS}
        for value in ('YR==','YQ==\n','YQ=','éQ=='):
            bad=copy.deepcopy(records);bad[F.MATERIALIZER]['base64']=value
            with self.assertRaises(F.FullEntryUnavailable):
                F.decode_exact_embedded_records(bad,package_pins=pins)
        bad=copy.deepcopy(records);bad[F.MATERIALIZER]['active']=True
        with self.assertRaises(F.FullEntryUnavailable):
            F.decode_exact_embedded_records(bad,package_pins=pins)

    def test_original_issued_verifier_parent_guard_and_defaults_are_shared(self):
        with self.f.entry() as entry:
            modules=entry.modules;origin=entry.origin
            self.assertEqual(set(modules),set(F.PACKAGE_PATHS))
            for path in (F.VERIFIER,F.PARENT,F.GUARD):self.assertIs(modules[path],origin.modules[path])
            self.assertIs(modules[F.PARENT].HeldParent,origin.modules[F.PARENT].HeldParent)
            self.assertIs(type(origin),modules[F.LOADER].TrustedEntry)
            with self.f.source(origin) as (held,guard):
                V=modules[F.VERIFIER]
                self.assertIs(V.require_platform_source(held),held)
                self.assertIn(held,V._ISSUED_PLATFORM_SOURCES)
                with entry.compose(held,source_guard=guard) as assembly:
                    self.assertIs(assembly.modules[F.VERIFIER],V)
                    self.assertIs(assembly.modules[F.PARENT],modules[F.PARENT])
                    R=assembly.modules['scripts/runtime_pair_init.py']
                    self.assertIs(R.initialize.__kwdefaults__['layout'],R.S.L.verify)
                    with self.assertRaises(R.C.AdmissionUnavailable):
                        with R.ParentStageAuthority().hold({}):self.fail('native authority')

    def test_capture_composition_never_imports_siblings_or_constructs_native(self):
        with (patch('importlib.util.spec_from_file_location',side_effect=AssertionError('sibling')),
              patch('subprocess.Popen',side_effect=AssertionError('native')),
              patch('ctypes.CDLL',side_effect=AssertionError('library'))):
            with self.f.entry() as entry:
                self.assertTrue(callable(entry.modules[F.BACKEND].ReadOnlySourceBackend))
                self.assertTrue(callable(entry.modules[F.MATERIALIZER].materialized_deployment))

    def test_materializer_and_backend_remain_separate_original_package_modules(self):
        with self.f.entry() as entry:
            modules=entry.modules
            self.assertNotIn(F.BACKEND,entry.origin.modules)
            self.assertNotIn(F.MATERIALIZER,entry.origin.modules)
            self.assertIs(modules[F.BACKEND].UNRELEASED_HANDLES,modules[F.BACKEND].UNRELEASED_RESOURCES)
            self.assertEqual(modules[F.MATERIALIZER].FILE_COUNT,62)
            self.assertFalse(modules[F.BACKEND].UNRELEASED_RESOURCES)
            self.assertFalse(modules[F.MATERIALIZER].UNRELEASED_HANDLES)

    def test_public_and_subclass_capabilities_refuse_before_callbacks(self):
        calls=[]
        class Fake(F.FullEntry):
            def recheck(self):calls.append('callback');return self
        for fake in (F.FullEntry(),Fake()):
            self.reject(lambda:F.FullEntry.recheck(fake))
            self.reject(lambda:F.FullEntry.modules.fget(fake))
            self.reject(lambda:F.FullEntry.origin.fget(fake))
            with self.assertRaises(F.FullEntryUnavailable):
                with F.FullEntry.compose(fake,None,source_guard=True):self.fail('forged')
        self.assertEqual(calls,[])

    def test_expired_entry_getters_and_compose_refuse_without_source_call(self):
        with self.f.entry() as entry:loader=entry.modules[F.LOADER]
        self.reject(entry.recheck)
        with patch.object(loader,'captured_startup_modules',side_effect=AssertionError('source callback')):
            with self.assertRaises(F.FullEntryUnavailable):
                with entry.compose(None,source_guard=True):self.fail('expired')
        self.reject(lambda:entry.modules)

    def test_fake_original_origin_expires_before_recheck_callback(self):
        calls=[]
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                entry._origin=SimpleNamespace(recheck=lambda:calls.append('callback'))
                self.reject(entry.recheck)
                self.assertNotIn(entry,F._ISSUED_ENTRIES)
        self.assertEqual(calls,[])

    def test_caught_invalid_compose_boundary_expires_genuine_entry(self):
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                origin=entry.origin
                with self.assertRaises(ValueError):
                    with entry.compose(None,source_guard=True):self.fail('invalid input')
                self.assertNotIn(entry,F._ISSUED_ENTRIES)
                self.reject(entry.recheck)
                with self.assertRaises(ValueError):origin.recheck()

    def test_module_global_replacement_expires_caught_live_entry(self):
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                entry.modules[F.MATERIALIZER].held_check=lambda value:True
                self.reject(entry.recheck)
                self.assertNotIn(entry,F._ISSUED_ENTRIES)

    def test_partial_compile_failure_releases_each_exact_owned_module(self):
        before=set(sys.modules);real=F._register
        def compile_package(path,*args):
            module=real(path,*args)
            if path==F.BACKEND:raise ValueError('injected compile failure')
            return module
        with patch.object(F,'_register',side_effect=compile_package):self.reject(self.enter)
        self.assertEqual({name for name in sys.modules if name.startswith('company_full_entry_')},
                         {name for name in before if name.startswith('company_full_entry_')})
        self.assertFalse(F.UNRELEASED)

    def test_foreign_registration_is_preserved_and_retained_unknown(self):
        foreign=ModuleType('foreign')
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                module=entry.modules[F.MATERIALIZER];name=module.__name__
                sys.modules[name]=foreign
                self.reject(entry.recheck)
        self.assertIs(sys.modules[name],foreign)
        self.assertTrue(F.UNRELEASED)
        self.assertIs(F.UNRELEASED[0][0],entry)
        del sys.modules[name]

    def test_unknown_backend_resources_retain_exact_entry_and_prevent_reentry(self):
        token=object()
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                backend=entry.modules[F.BACKEND]
                backend.UNRELEASED_RESOURCES.append(('injected',token))
                self.reject(entry.recheck)
                self.assertNotIn(entry,F._ISSUED_ENTRIES)
        self.assertIs(F.UNRELEASED[0][0],entry)
        self.assertIs(F.UNRELEASED[0][2][F.BACKEND],backend)
        self.assertIs(backend.UNRELEASED_RESOURCES[0][1],token)
        with patch.object(F,'_register',side_effect=AssertionError('reentry')):self.reject(self.enter)

    def test_full_activation_is_denied_and_expires_real_capability(self):
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                self.reject(entry.activate_full)
                self.assertNotIn(entry,F._ISSUED_ENTRIES)
        self.reject(F.FullEntry().activate_full)

    def test_original_unknown_list_replacement_cannot_discard_owned_uncertainty(self):
        token=object()
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                backend=entry.modules[F.BACKEND];original=backend.UNRELEASED_RESOURCES
                original.append(('injected',token));backend.UNRELEASED_RESOURCES=[]
                self.reject(entry.recheck)
        self.assertIs(F.UNRELEASED[0][0],entry)
        self.assertIs(entry._snapshots[F.BACKEND]['UNRELEASED_RESOURCES'],original)
        self.assertIs(original[0][1],token)

    def test_materializer_release_uncertainty_preserves_separate_exact_module(self):
        token=object()
        with self.assertRaises(F.FullEntryUnavailable):
            with self.f.entry() as entry:
                materializer=entry.modules[F.MATERIALIZER]
                materializer.UNRELEASED_HANDLES.append(('injected',token))
                self.reject(entry.recheck)
        self.assertIs(F.UNRELEASED[0][2][F.MATERIALIZER],materializer)
        self.assertIs(materializer.UNRELEASED_HANDLES[0][1],token)


if __name__ == '__main__':
    unittest.main(verbosity=2)
