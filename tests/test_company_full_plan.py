"""Full-install request and original schema4 composition; no native execution."""
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


K = load('full_plan_product_controls', ROOT/'deploy/installer/company_full_plan.py')
T = load('full_plan_fresh_fixtures', ROOT/'tests/test_company_fresh_assembly.py')
F = T.F


def request(release='a'*64):
    return dict(schemaVersion=1, mode='full-installation', operationId='b'*32,
        releaseSha256=release, bundleRoot='/opt/autosoft-company/incoming/release',
        sourceRoot='/opt/autosoft-company/incoming/source',
        keyPath='/opt/autosoft-company/bootstrap/company.pem', dataDir='/srv/full-test',
        backingFile='/srv/full-test.luks', capacityGiB=128,
        runscVersion='20261005.0', runscSha512='c'*128)


class FullPlanControls(unittest.TestCase):
    def setUp(self):
        self.f = T.Fixture()
        self.assertFalse(K._PLANS)
        self.assertFalse(F.UNRELEASED)

    def tearDown(self):
        self.f.clean()
        self.assertFalse(K._PLANS)
        self.assertFalse(F._ISSUED_ENTRIES)
        self.assertFalse(F.UNRELEASED)

    def shell_source(self, fixture):
        for name in ('scripts/lib.sh', 'scripts/install-runtime-gate.sh', 'scripts/install.sh'):
            fixture.values[name] = (ROOT/name).read_bytes().replace(b'\r\n', b'\n')

    @contextmanager
    def context(self, **changes):
        with self.f.entry() as entry, self.f.fresh_source(entry, self.shell_source) as held:
            with entry.fresh_installation_modules(held) as assembly:
                inputs = request(held.metadata['releaseSha256']); inputs.update(changes)
                with K.planned_foundation(entry, held, inputs, entry_module=F, assembly=assembly) as plan:
                    yield plan, entry, held, assembly, inputs

    def test_closed_request_types_paths_and_capacity(self):
        valid = K.validate_request(request())
        self.assertIs(type(valid), MappingProxyType)
        cases = [('schemaVersion', True), ('schemaVersion', 1.0), ('mode', 'foundation-only'),
            ('operationId', 'A'*32), ('releaseSha256', True), ('runscSha512', 'a'*64),
            ('capacityGiB', True), ('capacityGiB', 31), ('capacityGiB', 4097),
            ('capacityGiB', 128.0), ('dataDir', '/srv'), ('dataDir', '/srv/autosoft-company'),
            ('dataDir', '/srv/x/../full-test'), ('dataDir', '/srv//full-test'),
            ('backingFile', '/srv/full-test'), ('backingFile', '/srv/full-test/disk'),
            ('backingFile', '/srv'), ('keyPath', '/srv/key.pem'),
            ('backingFile', '/opt/autosoft-company'), ('backingFile', '/opt'),
            ('backingFile', '//srv/full-test.luks'), ('keyPath', '//opt/autosoft-company/bootstrap/key.pem'),
            ('backingFile', '/opt/autosoft-company/incoming/source/disk.luks'),
            ('backingFile', '/opt/autosoft-company/staging/disk.luks'),
            ('backingFile', '/opt/autosoft-company/evidence/disk.luks'),
            ('dataDir', '/srv/'+'a'*256), ('dataDir', '/srv/'+'a/'*32+'end'),
            ('dataDir', '/srv/'+('a'*100+'/')*11+'end'),
            ('runscVersion', '20261005.'+'1'*9),
            ('bundleRoot', '/opt/autosoft-company/incoming'),
            ('sourceRoot', '/opt/autosoft-company/incoming/source;evil')]
        for field, bad in cases:
            with self.subTest(field=field, value=bad):
                value = request(); value[field] = bad
                with self.assertRaises(K.FullPlanUnavailable): K.validate_request(value)
        for value in ({}, dict(request(), extra=True), MappingProxyType(request())):
            with self.assertRaises(K.FullPlanUnavailable): K.validate_request(value)

    def test_request_capture_does_not_share_mutable_input(self):
        value = request(); captured = K.validate_request(value)
        value['capacityGiB'] = 1
        self.assertEqual(captured['capacityGiB'], 128)
        with self.assertRaises(TypeError): captured['capacityGiB'] = 256

    def test_exact_schema4_rows_commands_and_shared_identity_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('native child')):
            with self.context() as (plan, entry, held, assembly, inputs):
                self.assertIs(type(plan.files), MappingProxyType)
                self.assertEqual(len(plan.files), 63)
                self.assertNotIn('company-release/platform-sources.tar.gz', plan.files)
                self.assertIs(plan._held, held); self.assertIs(plan._assembly, assembly)
                self.assertIs(plan._verifier, entry.modules[F.VERIFIER])
                self.assertIs(plan._materializer, entry.modules[F.MATERIALIZER])
                expected = {name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                            for name, raw in sorted(plan.files.items())}
                self.assertEqual(plan.inventory_sha256, K.digest(K.canonical(expected)))
                roots = plan.roots
                for phase in K.PHASES:
                    argv = plan.phase_command(phase)
                    self.assertIs(type(argv), tuple)
                    self.assertEqual(argv[:4], ('/bin/bash', '--noprofile', '--norc', '-c'))
                    self.assertEqual(len(argv), 13)
                    self.assertTrue(argv[4].endswith('\ncompany_'+phase+'_phase "$@"\n'))
                    self.assertIn(K.FULL_CAPACITY_CHECK.decode(), argv[4])
                    self.assertLess(argv[4].index('require_host_capacity full'),
                                    argv[4].rindex('company_'+phase+'_phase "$@"'))
                    self.assertLess(len(argv[4].encode()), K.COMMAND_LIMIT)
                    execution = roots['stagingParent'] if phase == 'packages' else roots['finalRoot'] if phase == 'activate' else roots['stagedRoot']
                    self.assertEqual(argv[6:], (execution, roots['finalRoot'], '/srv/full-test',
                        '/srv/full-test.luks', '128', '20261005.0', 'c'*128))
                self.assertFalse(any(getattr(plan, name, False) for name in ('nativeAuthorized', 'installerActivated')))
                inputs['dataDir'] = '/srv/substitution'
                self.assertEqual(plan.request['dataDir'], '/srv/full-test')
                with patch.object(K, 'COMMAND_LIMIT', len(plan._phase_bytes)+1):
                    with self.assertRaises(K.FullPlanUnavailable): plan.phase_command('activate')
        with self.assertRaises(K.FullPlanUnavailable): plan.recheck()

    def test_unissued_entry_and_subclass_refuse_before_source_callbacks(self):
        class Fake(F.FullEntry): pass
        source = SimpleNamespace(recheck=lambda: self.fail('source callback'))
        for entry in (F.FullEntry(), Fake()):
            with self.assertRaises((ValueError, TypeError)):
                with K.planned_foundation(entry, source, request(), entry_module=F,
                        assembly=SimpleNamespace(recheck=lambda: self.fail('assembly callback'))):
                    self.fail('yield')

    def test_unissued_plan_and_subclass_refuse_before_entry_callbacks(self):
        class Fake(K.FoundationPlan): pass
        for plan in (K.FoundationPlan(), Fake()):
            plan._entry = SimpleNamespace(recheck=lambda: self.fail('entry callback'))
            with self.assertRaises(K.FullPlanUnavailable): plan.recheck()
            with self.assertRaises(K.FullPlanUnavailable): plan.phase_command('packages')

    def test_unissued_fresh_assembly_refuses_before_materializer(self):
        with self.f.entry() as entry, self.f.fresh_source(entry, self.shell_source) as held:
            L = entry.modules[F.LOADER]
            with patch('subprocess.Popen', side_effect=AssertionError('native child')):
                with self.assertRaises(ValueError):
                    with K.planned_foundation(entry, held, request(held.metadata['releaseSha256']),
                                              entry_module=F, assembly=L.FreshInstallationAssembly()):
                        self.fail('yield')

    def test_release_mismatch_refuses_before_any_command(self):
        with self.assertRaises(K.FullPlanUnavailable):
            with self.context(releaseSha256='0'*64): self.fail('yield')

    def test_unknown_phase_is_rejected_and_does_not_grant_other_commands(self):
        with self.context() as (plan, *unused):
            for phase in ('full_install_pending', 'publish', '../activate', 'activate;evil', True):
                with self.assertRaises(K.FullPlanUnavailable): plan.phase_command(phase)
            self.assertIs(plan.recheck(), plan)

    def test_source_expiration_expires_plan_and_retains_no_plan_issuer(self):
        with self.assertRaises(ValueError):
            with self.context() as (plan, entry, held, assembly, inputs):
                held._expire()
                with self.assertRaises(ValueError): plan.phase_command('activate')
                self.assertFalse(plan._active)
        self.assertFalse(K._PLANS)

    def test_assembly_expiration_expires_plan_without_new_compilation(self):
        with self.assertRaises(ValueError):
            with self.context() as (plan, entry, held, assembly, inputs):
                assembly._expire()
                with patch('builtins.compile', side_effect=AssertionError('recompile')):
                    with self.assertRaises(ValueError): plan.recheck()
                self.assertFalse(plan._active)

    def test_caller_exception_expires_plan_but_preserves_caller_assembly(self):
        with self.f.entry() as entry, self.f.fresh_source(entry, self.shell_source) as held:
            with entry.fresh_installation_modules(held) as assembly:
                with self.assertRaisesRegex(RuntimeError, 'caller'):
                    with K.planned_foundation(entry, held, request(held.metadata['releaseSha256']),
                                              entry_module=F, assembly=assembly) as plan:
                        raise RuntimeError('caller')
                self.assertIs(assembly.recheck(), assembly)
                self.assertIs(entry.modules[F.VERIFIER].require_platform_source(held), held)
                self.assertFalse(plan._active)

    def test_closed_plan_rejects_reuse_and_borrowed_assembly_remains_live(self):
        with self.f.entry() as entry, self.f.fresh_source(entry, self.shell_source) as held:
            with entry.fresh_installation_modules(held) as assembly:
                with K.planned_foundation(entry, held, request(held.metadata['releaseSha256']),
                                          entry_module=F, assembly=assembly) as plan:
                    pass
                with self.assertRaises(K.FullPlanUnavailable): plan.files
                self.assertIs(assembly.recheck(), assembly)
                self.assertIs(entry.recheck(), entry)


if __name__ == '__main__': unittest.main(verbosity=2)
