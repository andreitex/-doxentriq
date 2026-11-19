"""Genuine RAM source -> signed helpers -> original composition/bootstrap.

Only named frozen fixture definitions are reused. Files and signature checking
are injected RAM collaborators; compiled helpers select no child IO or stages.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys
from types import MappingProxyType, ModuleType
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'deploy/installer'
BASIS = ROOT / 'tests/test_company_authenticated_cli_inputs.py'
BASIS_PIN = 'c6260d9c99c46e70b43eb6687d9595223e61e94d3f73a13f30bb26b8551658a9'
PROFILE_PIN = 'c105c94f4482a727c3c161f87d0b450919a121a0e4383fda6ffd2a4ebbc224e8'


def fixture_basis():
    raw = BASIS.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BASIS_PIN
    names = {'load', 'sha', 'Files', 'Crypto', 'Fixture'}
    tree = ast.parse(raw)
    nodes = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
             or isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    assert {node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.ClassDef))} == names
    module = ModuleType('signed_execute_explicit_frozen_ram_basis')
    module.__file__ = str(BASIS)
    module.ROOT = ROOT
    module.HERE = ROOT / 'deploy/installer'
    exec(compile(ast.Module(body=nodes, type_ignores=[]),
                 '<explicit named frozen RAM fixture definitions>', 'exec'), vars(module))
    return module


T = fixture_basis()


def helper_profile():
    raw = (ROOT / 'tests/fixtures/company_signed_execute_helpers_v5.json').read_bytes()
    assert T.sha(raw) == PROFILE_PIN
    profile = json.loads(raw)
    assert len(profile['helpers']) == 15 and profile['totalBytes'] == 246431
    result = {}
    for row in profile['helpers']:
        path = ROOT / row['path']
        body = path.read_bytes()
        assert T.sha(body) == row['sha256'] and len(body) == row['bytes']
        assert row['gitMode'] == '100644'
        result[row['path']] = (body, row)
    return result


HELPERS = helper_profile()


def contains(value, target, seen=None):
    if value is target:
        return True
    if seen is None:
        seen = set()
    if id(value) in seen:
        return False
    seen.add(id(value))
    if type(value) in (dict, MappingProxyType):
        return any(contains(item, target, seen) for item in value.values())
    if type(value) in (tuple, list):
        return any(contains(item, target, seen) for item in value)
    return False


class Fixture:
    def __init__(self, changes=None):
        def signed_profile(basis):
            for path, (body, row) in HELPERS.items():
                basis.values[path] = body
                basis.modes[path] = row['gitMode']
            if changes:
                changes(basis)
        self.base = T.Fixture(signed_profile)
        self.restores = []
        self.before_names = set(sys.modules)
        self.owned_registrations = {}
        self.Compose = T.load(self.base.prefix + '_compose',
                              ROOT / 'deploy/installer/company_authenticated_cli_compose.py')
        self.M = T.load(self.base.prefix + '_signed_prepare', HERE / 'company_signed_execute_preparation.py')
        self.inputs = self.base.prepare()
        self.prepared = None
        self.root = str(Path(ROOT.anchor) / 'company-signed-execute-virtual-root')

    def registrations(self):
        return {name: module for name, module in tuple(sys.modules.items())
                if name.startswith('_company_execute_bootstrap_') and name not in self.before_names}

    def prepare(self, **changes):
        args = dict(root=self.root, package_module=self.base.PB,
                    delivery_module=self.base.D, cli_module=self.base.C, sys_module=sys)
        args.update(changes)
        try:
            self.prepared = self.M.prepare_signed_execute(self.base.I, self.inputs,
                                                        self.Compose, **args)
            return self.prepared
        finally:
            self.owned_registrations.update(self.registrations())

    def dispose(self):
        for restore in reversed(self.restores):
            restore()
        self.base.dispose()
        # Dedicated-process registrations have no product release API. Remove
        # only exact fixture-owned copies after the control, without a release
        # claim for the preparation or any uncertain reference.
        for name, module in self.owned_registrations.items():
            if sys.modules.get(name) is module:
                del sys.modules[name]


class Controls(unittest.TestCase):
    def fixture(self, changes=None):
        value = Fixture(changes)
        self.addCleanup(value.dispose)
        return value

    def refused(self, f, call):
        with self.assertRaises(f.M.SignedExecuteUnavailable):
            call()

    def no_programs(self, f):
        self.assertFalse(f.registrations())
        self.assertFalse(f.base.C._CLI_OWNERS)

    def test_actual_signed_helpers_construct_original_private_bootstrap(self):
        f = self.fixture()
        p = f.prepare()
        data = p.capture_preparation()
        self.assertIs(type(data), MappingProxyType)
        self.assertEqual((data['signedHelperCount'], data['signedHelperBytes']), (15, 246431))
        self.assertEqual(set(data['helperPins']), set(HELPERS))
        for path, (body, row) in HELPERS.items():
            self.assertEqual(dict(data['helperPins'][path]), {'bytes': len(body), 'sha256': T.sha(body)})
        bootstrap = p.bootstrap
        modules = p.construction_modules
        self.assertIs(type(bootstrap).__dict__['construction_modules'].fget(bootstrap)['io'], modules['io'])
        registrations = f.registrations()
        self.assertEqual(len(registrations), 8)
        self.assertIs(type(bootstrap).__dict__['construction_modules'].fget.__globals__['ExecuteBootstrap'], type(bootstrap))
        self.assertIn(modules['io'], registrations.values())
        self.assertIn(modules['crypto'], registrations.values())
        self.assertTrue(callable(modules['io'].hold_publisher_io))
        self.assertIs(type(modules['crypto'].ReleaseCrypto), type)
        self.assertFalse(f.base.C._CLI_OWNERS)
        self.assertIs(f.base.V.require_platform_source(f.base.source), f.base.source)
        self.assertFalse(data['sourceObjectTransferred'] or data['childPrepared'] or data['stageDispatched']
                         or data['nativeExecuted'] or data['executionEvidenceIssued'] or data['stageAcknowledged'])
        self.assertTrue(data['downstreamOriginalSourceReauthenticationRequired'])
        self.assertFalse(contains(data, f.base.source))

    def test_ten_actual_captures_and_six_authentication_fields_are_immutable(self):
        f = self.fixture()
        p = f.prepare()
        data = p.capture_preparation()
        labels = dict((*f.M.PROGRAMS, *f.M.BOOTSTRAP))
        self.assertEqual(len(labels), 10)
        for label, path in labels.items():
            body = HELPERS[path][0] if path in HELPERS else f.base.values[path]
            self.assertEqual(data['programCaptures'][label], body)
            self.assertEqual(dict(data['programPins'][label]), {'bytes': len(body), 'sha256': T.sha(body)})
        auth = data['authentication']
        self.assertEqual(set(auth), {'delivery_pin', 'launch_pins', 'package_pins',
                                    'operational_catalog', 'fingerprint', 'full_package_pin'})
        self.assertEqual(auth['delivery_pin']['sha256'], T.sha(data['deliveryRaw']))
        self.assertEqual((len(auth['launch_pins']), len(auth['package_pins']),
                          len(auth['operational_catalog'])), (11, 9, 16))
        self.assertEqual(auth['fingerprint'], f.base.fingerprint)
        with self.assertRaises(TypeError):
            auth['delivery_pin']['bytes'] = 1
        with self.assertRaises(TypeError):
            data['programCaptures']['verifier'] = b'forged'
        self.assertEqual(data['programCaptures']['verifier'], f.base.values['scripts/verify-release.py'])

    def test_missing_signed_public_helper_refuses_before_composition_or_compile(self):
        def missing(basis):
            path = 'deploy/installer/company_cli_executed_record_store.py'
            basis.values.pop(path)
            basis.modes.pop(path)
        f = self.fixture(missing)
        self.assertIs(f.base.V.require_platform_source(f.base.source), f.base.source)
        self.refused(f, f.prepare)
        self.no_programs(f)
        self.assertIsNone(f.M.UNRELEASED[-1][0]['composition'])

    def test_changed_signed_helper_body_refuses_before_any_program_compile(self):
        def changed(basis):
            basis.values['deploy/installer/company_cli_record.py'] += b'\n# signed public fixture change\n'
        f = self.fixture(changed)
        self.assertIs(f.base.V.require_platform_source(f.base.source), f.base.source)
        self.refused(f, f.prepare)
        self.no_programs(f)
        self.assertIsNone(f.M.UNRELEASED[-1][0]['helper_module'])

    def test_signed_executable_helper_mode_refuses_before_any_program_compile(self):
        f = self.fixture(lambda b: b.modes.update({'deploy/installer/company_cli_record.py': '100755'}))
        self.assertIs(f.base.V.require_platform_source(f.base.source), f.base.source)
        self.refused(f, f.prepare)
        self.no_programs(f)

    def test_old_private_record_literal_is_not_the_admitted_public_bootstrap(self):
        raw = (ROOT / 'tests/fixtures/company_cli_execute_bootstrap_before_public_path.source.txt').read_bytes()
        self.assertNotEqual(T.sha(raw), HELPERS['deploy/installer/company_cli_execute_bootstrap.py'][1]['sha256'])
        f = self.fixture(lambda b: b.values.update({'deploy/installer/company_cli_execute_bootstrap.py': raw}))
        self.refused(f, f.prepare)
        self.no_programs(f)
        self.assertIsNone(f.M.UNRELEASED[-1][0]['helper_module'])

    def test_unissued_input_clone_cannot_start_composition_or_bootstrap(self):
        f = self.fixture()
        f.inputs = f.base.I.SourceInputs()
        before = f.base.files.reads
        self.refused(f, f.prepare)
        self.assertEqual(f.base.files.reads, before)
        self.no_programs(f)

    def test_borrowed_compose_function_on_public_clone_module_is_not_dispatched(self):
        f = self.fixture()
        clone = ModuleType('public_composition_clone')
        clone.PreparedCliComposition = f.Compose.PreparedCliComposition
        clone.prepare_cli_composition = f.Compose.prepare_cli_composition
        f.Compose = clone
        before = f.base.files.reads
        self.refused(f, f.prepare)
        self.assertEqual(f.base.files.reads, before)
        self.no_programs(f)

    def test_foreign_composition_callback_is_denied_without_invocation(self):
        f = self.fixture()
        calls = []
        original = f.Compose.prepare_cli_composition
        def foreign(*args, **kwargs):
            calls.append(args)
            return object()
        f.Compose.prepare_cli_composition = foreign
        f.restores.append(lambda: setattr(f.Compose, 'prepare_cli_composition', original))
        self.refused(f, f.prepare)
        self.assertFalse(calls)
        self.no_programs(f)

    def test_expired_original_source_refuses_before_composition_or_compile(self):
        f = self.fixture()
        f.base.close_source()
        self.refused(f, f.prepare)
        self.no_programs(f)

    def test_postcapture_archive_drift_retains_actual_bootstrap_without_recompile(self):
        f = self.fixture()
        p = f.prepare()
        bootstrap = p.bootstrap
        registrations = f.registrations()
        path = f.base.bundle / 'platform-sources.tar.gz'
        raw = f.base.files.data[path]
        f.base.files.data[path] = raw[:-1] + bytes([raw[-1] ^ 1])
        self.refused(f, p.capture_preparation)
        self.assertTrue(contains(f.M.UNRELEASED, bootstrap))
        self.assertTrue(contains(f.M.UNRELEASED, f.inputs))
        self.assertEqual(f.registrations(), registrations)
        before = f.base.files.reads
        f.M.UNRELEASED.clear()
        self.refused(f, lambda: p.bootstrap)
        self.assertEqual(f.base.files.reads, before)

    def test_postcapture_validator_drift_invokes_no_foreign_source_callback(self):
        f = self.fixture()
        p = f.prepare()
        calls = []
        original = f.base.V.require_platform_source
        def foreign(value):
            calls.append(value)
            return value
        f.base.V.require_platform_source = foreign
        f.restores.append(lambda: setattr(f.base.V, 'require_platform_source', original))
        self.refused(f, p.capture_preparation)
        self.assertFalse(calls)
        self.assertTrue(contains(f.M.UNRELEASED, f.inputs))

    def test_original_construction_module_drift_refuses_without_foreign_call(self):
        f = self.fixture()
        p = f.prepare()
        bootstrap = p.bootstrap
        io = p.construction_modules['io']
        original = io.hold_publisher_io
        calls = []
        def foreign(*args, **kwargs):
            calls.append(args)
            return True
        io.hold_publisher_io = foreign
        f.restores.append(lambda: setattr(io, 'hold_publisher_io', original))
        self.refused(f, lambda: p.construction_modules)
        self.assertFalse(calls)
        self.assertTrue(contains(f.M.UNRELEASED, bootstrap))

    def test_public_preparation_clone_cannot_observe_bootstrap_or_modules(self):
        f = self.fixture()
        p = f.prepare()
        clone = f.M.SignedExecutePreparation()
        before = f.base.files.reads
        self.refused(f, clone.capture_preparation)
        self.refused(f, lambda: clone.bootstrap)
        self.refused(f, lambda: clone.construction_modules)
        self.assertEqual(f.base.files.reads, before)
        self.assertIs(type(p.bootstrap).__dict__['construction_modules'].fget(p.bootstrap)['io'],
                      p.construction_modules['io'])

    def test_failed_missing_helper_cannot_retry_after_public_ledger_clear(self):
        def missing(basis):
            path = 'deploy/installer/company_cli_record.py'
            basis.values.pop(path)
            basis.modes.pop(path)
        f = self.fixture(missing)
        self.refused(f, f.prepare)
        before = f.base.files.reads
        f.M.UNRELEASED.clear()
        self.refused(f, f.prepare)
        self.assertEqual(f.base.files.reads, before)
        self.no_programs(f)

    def test_second_preparation_cannot_construct_another_private_bootstrap(self):
        f = self.fixture()
        p = f.prepare()
        registrations = f.registrations()
        before = f.base.files.reads
        self.refused(f, f.prepare)
        self.assertEqual(f.base.files.reads, before)
        self.assertEqual(f.registrations(), registrations)
        self.assertIs(type(p.bootstrap).__dict__['construction_modules'].fget(p.bootstrap)['crypto'],
                      p.construction_modules['crypto'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
