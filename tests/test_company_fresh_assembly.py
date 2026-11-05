"""Genuine signed-source issuance, injected storage; no native installation."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


T = load('fresh_assembly_existing_entry_fixtures', ROOT/'tests/test_company_full_entry.py')
F = T.F
U = T.T.T


class Fixture(T.Fixture):
    @contextmanager
    def fresh_source(self, entry, changes=None):
        V = entry.modules[F.VERIFIER]
        self.q = U.Q.Fixture(V, U.P)
        self.q.values.update(self.raw)
        self.q.modes.update({path: '100644' for path in self.raw})
        if changes is not None:
            changes(self.q)
        self.q.refresh_platform()
        for path in self.q.root.parents:
            self.q.files.changes.setdefault(path, {}).update(st_mtime_ns=101, st_ctime_ns=202, st_size=0)
        with self.q.held() as held:
            yield held

    @contextmanager
    def physical_guard(self, entry, held):
        self.backend = U.ReadOnlySourceBackend()
        root = '/data/company/source-releases/'+held.metadata['releaseSha256']+'/source'
        self.backend.build(root, dict(held.files))
        G, V = entry.modules[F.GUARD], entry.modules[F.VERIFIER]
        with G.hold_authenticated_company_source(held, verifier_module=V,
                source_root=root, expected_device=7, backend_module=U,
                backend=self.backend, clock=U.Clock()) as guard:
            yield guard


class FreshAssemblyControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(F.UNRELEASED)
        self.f = Fixture()

    def tearDown(self):
        self.f.clean()
        self.assertFalse(F._ISSUED_ENTRIES)
        F.UNRELEASED.clear()  # Injected uncertainty only; no product reset API.

    def reject(self, call):
        with self.assertRaises((ValueError, TypeError)):
            call()

    def enter(self, entry, held):
        with entry.fresh_installation_modules(held):
            pass

    def test_signed_fresh_composition_precedes_any_physical_source_guard(self):
        with self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with (patch('subprocess.Popen', side_effect=AssertionError('native')),
                  patch('ctypes.CDLL', side_effect=AssertionError('physical backend'))):
                with entry.fresh_installation_modules(held) as assembly:
                    self.assertEqual(len(assembly.modules), 15)
                    self.assertIsNone(self.f.backend)

    def test_all15_rows_admitted_before_first_operational_compile(self):
        def changed(q):
            q.values['scripts/company_source_tree.py'] += b'\n# changed signed row\n'
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry, changed) as held:
            with patch('builtins.compile', side_effect=AssertionError('operational compile')):
                self.reject(lambda: self.enter(entry, held))

    def test_missing_last_member_refuses_before_first_operational_compile(self):
        def missing(q):
            q.values.pop('scripts/company_source_tree.py')
            q.modes.pop('scripts/company_source_tree.py')
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry, missing) as held:
            with patch('builtins.compile', side_effect=AssertionError('operational compile')):
                self.reject(lambda: self.enter(entry, held))

    def test_catalog_mode_disagreement_refuses_before_compile(self):
        def changed(q): q.modes['scripts/company_source_tree.py'] = '100755'
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry, changed) as held:
            self.reject(lambda: self.enter(entry, held))

    def test_original_verifier_parent_and_operational_identities_survive_binding(self):
        with self.f.entry() as entry, self.f.fresh_source(entry) as held:
            context = entry.fresh_installation_modules(held)
            assembly = context.__enter__()
            try:
                before = dict(assembly.modules)
                B, M, C = (before[path] for path in ('scripts/bootstrap.py',
                    'scripts/company_platform_store.py', 'scripts/company_source_tree.py'))
                storage_class = B.SeedStorage
                self.assertIs(before[F.VERIFIER], entry.modules[F.VERIFIER])
                self.assertIs(before[F.PARENT], entry.modules[F.PARENT])
                with self.f.physical_guard(entry, held) as guard:
                    assembly.bind_source_guard(guard)
                    after = assembly.modules
                    self.assertTrue(all(after[path] is module for path, module in before.items()))
                    self.assertIs(after['scripts/bootstrap.py'].SeedStorage, storage_class)
                    self.assertIs(after['scripts/company_platform_store.py'], M)
                    self.assertIs(after['scripts/company_source_tree.py'], C)
                    self.assertIs(assembly.recheck(), assembly)
                    context.__exit__(None, None, None)
                    context = None
            finally:
                if context is not None: context.__exit__(None, None, None)

    def test_binding_never_recompiles_operational_modules(self):
        with self.f.entry() as entry, self.f.fresh_source(entry) as held:
            context = entry.fresh_installation_modules(held); assembly = context.__enter__()
            try:
                with self.f.physical_guard(entry, held) as guard:
                    # Do not replace the trusted loader global; compilation is
                    # a builtin and must never be entered during physical bind.
                    with patch('builtins.compile', side_effect=AssertionError('recompile')):
                        assembly.bind_source_guard(guard)
                    context.__exit__(None, None, None); context = None
            finally:
                if context is not None: context.__exit__(None, None, None)

    def test_public_fresh_constructor_and_subclass_refuse_before_callbacks(self):
        with self.f.entry() as entry:
            L = entry.modules[F.LOADER]
            class Fake(L.FreshInstallationAssembly): pass
            for assembly in (L.FreshInstallationAssembly(), Fake()):
                assembly._entry = SimpleNamespace(recheck=lambda: self.fail('fake callback'))
                self.reject(assembly.recheck)
                self.reject(lambda: assembly.call('x', 'x'))
                self.reject(lambda: assembly.bind_source_guard(True))

    def test_public_full_entry_cannot_select_fresh_route(self):
        class Fake(F.FullEntry): pass
        for entry in (F.FullEntry(), Fake()):
            self.reject(lambda: self.enter(entry, SimpleNamespace(recheck=lambda: self.fail('callback'))))

    def test_unissued_same_class_source_refused_without_its_callback(self):
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            V = entry.modules[F.VERIFIER]
            metadata = dict(held.metadata); metadata['release'] = json.loads(held.provenance['release.json'])
            clone = V.HeldPlatformSource(dict(held.files), dict(held.git_modes), dict(held.configs),
                dict(held.provenance), metadata, lambda: self.fail('forged recheck'),
                archive_bytes=held.archive_bytes)
            self.reject(lambda: self.enter(entry, clone))

    def test_fingerprint_mismatch_refuses_before_operational_compile(self):
        self.f.catalog[F.VERIFIER] = dict(self.f.catalog[F.VERIFIER])
        with self.assertRaises(ValueError), self.f.entry(key_fingerprint='b'*64) as entry, self.f.fresh_source(entry) as held:
            self.reject(lambda: self.enter(entry, held))

    def test_stale_guard_rejected_at_binding(self):
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with self.assertRaises(ValueError):
                with entry.fresh_installation_modules(held) as assembly:
                    with self.f.physical_guard(entry, held) as guard: pass
                    assembly.bind_source_guard(guard)

    def test_guard_for_different_held_source_refused(self):
        other = Fixture()
        try:
            with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
                with self.assertRaises(ValueError):
                    with entry.fresh_installation_modules(held) as assembly:
                        with other.fresh_source(entry) as second, other.physical_guard(entry, second) as guard:
                            assembly.bind_source_guard(guard)
        finally: other.clean()

    def test_foreign_original_guard_module_refused(self):
        other = Fixture()
        try:
            with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
                with self.assertRaises(ValueError):
                    with entry.fresh_installation_modules(held) as assembly:
                        with other.entry() as foreign, other.fresh_source(foreign) as second, other.physical_guard(foreign, second) as guard:
                            assembly.bind_source_guard(guard)
        finally: other.clean()

    def test_guard_binding_is_one_way_and_repeated_binding_expires(self):
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with self.assertRaises(ValueError):
                with entry.fresh_installation_modules(held) as assembly:
                    with self.f.physical_guard(entry, held) as guard:
                        assembly.bind_source_guard(guard)
                        self.reject(lambda: assembly.bind_source_guard(guard))
                        self.reject(lambda: assembly.call('scripts/installation_identity.py', 'installation_id', '00000000-0000-0000-0000-000000000001'))

    def test_clearing_bound_guard_cannot_restore_unbound_admission(self):
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with self.assertRaises(ValueError):
                with entry.fresh_installation_modules(held) as assembly:
                    with self.f.physical_guard(entry, held) as guard:
                        assembly.bind_source_guard(guard); assembly._guard = None
                        self.reject(assembly.recheck)

    def test_closed_guard_prevents_next_call_and_expires_assembly(self):
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with self.assertRaises(ValueError):
                with entry.fresh_installation_modules(held) as assembly:
                    with self.f.physical_guard(entry, held) as guard: assembly.bind_source_guard(guard)
                    self.reject(lambda: assembly.call('scripts/installation_identity.py', 'installation_id', '00000000-0000-0000-0000-000000000001'))
                    self.assertNotIn(assembly, entry.modules[F.LOADER]._FRESH_ASSEMBLIES)

    def test_guard_must_outlive_even_unused_assembly_context_closure(self):
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with self.assertRaises(ValueError):
                with entry.fresh_installation_modules(held) as assembly:
                    with self.f.physical_guard(entry, held) as guard: assembly.bind_source_guard(guard)

    def test_expired_assembly_cannot_access_modules_or_call(self):
        with self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with entry.fresh_installation_modules(held) as assembly: pass
            self.reject(lambda: assembly.modules)
            self.reject(lambda: assembly.call('scripts/installation_identity.py', 'installation_id', 'x'))

    def test_code_composition_does_not_authorize_runtime_pair_native_effects(self):
        with self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with entry.fresh_installation_modules(held) as assembly:
                R = assembly.modules['scripts/runtime_pair_init.py']
                with patch('os.mkdir', side_effect=AssertionError('filesystem effect')):
                    with self.assertRaises(ValueError):
                        with R.ParentStageAuthority().hold({}): self.fail('native authority')

    def test_invalid_call_expires_even_when_error_is_caught(self):
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            with self.assertRaises(ValueError):
                with entry.fresh_installation_modules(held) as assembly:
                    self.reject(lambda: assembly.call('scripts/bootstrap.py', '_private'))
                    self.reject(lambda: assembly.modules)

    def test_operational_unknown_retains_exact_assembly_and_module_references(self):
        token = object(); assembly = L = M = None
        with self.assertRaises(ValueError):
            with self.f.entry() as entry, self.f.fresh_source(entry) as held:
                L = entry.modules[F.LOADER]
                with entry.fresh_installation_modules(held) as assembly:
                    M = assembly.modules['scripts/company_platform_store.py']
                    M.UNRELEASED.append(('injected', token))
                    self.reject(assembly.recheck)
        self.assertIs(L.UNRELEASED[0][0], assembly)
        self.assertIs(L.UNRELEASED[0][2]['scripts/company_platform_store.py'], M)
        self.assertIs(M.UNRELEASED[0][1], token)
        self.assertTrue(F.UNRELEASED)

    def test_foreign_module_registration_preserved_and_unknown_owned_refs_retained(self):
        foreign = SimpleNamespace(); name = None; L = None
        with self.assertRaises(ValueError):
            with self.f.entry() as entry, self.f.fresh_source(entry) as held:
                L = entry.modules[F.LOADER]
                with entry.fresh_installation_modules(held) as assembly:
                    name = assembly.modules['scripts/company_source_tree.py'].__name__
                    sys.modules[name] = foreign
        self.assertIs(sys.modules[name], foreign)
        self.assertTrue(L.UNRELEASED)
        del sys.modules[name]

    def test_partial_late_compile_failure_closes_each_exact_owned_registration(self):
        import builtins
        before = set(sys.modules)
        with self.assertRaises(ValueError), self.f.entry() as entry, self.f.fresh_source(entry) as held:
            real = builtins.exec
            def execute(code, values, *args, **kwargs):
                answer = real(code, values, *args, **kwargs)
                if values.get('__file__') == '<captured company scripts/company_source_tree.py>':
                    raise ValueError('injected late compile')
                return answer
            with patch('builtins.exec', side_effect=execute):
                self.reject(lambda: self.enter(entry, held))
            self.assertFalse(any(name.startswith('company_fresh_') for name in sys.modules))
        self.assertFalse(any(name.startswith('company_fresh_') for name in set(sys.modules)-before))

    def test_partial_compile_unknown_retains_failed_module_before_release(self):
        import builtins
        token = object(); failed = []; L = None
        with self.assertRaises(ValueError):
            with self.f.entry() as entry, self.f.fresh_source(entry) as held:
                L = entry.modules[F.LOADER]; real = builtins.exec
                def execute(code, values, *args, **kwargs):
                    answer = real(code, values, *args, **kwargs)
                    if values.get('__file__') == '<captured company scripts/company_source_tree.py>':
                        module = sys.modules[values['__name__']]
                        module.UNRELEASED.append(('injected', token)); failed.append(module)
                        raise ValueError('injected late compile unknown')
                    return answer
                with patch('builtins.exec', side_effect=execute):
                    self.reject(lambda: self.enter(entry, held))
        self.assertTrue(L.UNRELEASED)
        self.assertTrue(any(module is failed[0] for name, module in L.UNRELEASED[0][-1]))
        self.assertIs(failed[0].UNRELEASED[0][1], token)


if __name__ == '__main__':
    unittest.main(verbosity=2)
