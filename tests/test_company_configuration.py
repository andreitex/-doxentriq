"""Protected wizard data path and fail-closed configuration prerequisites.

These tests use synthetic secrets and injected foundation identity. They do not
claim a real encrypted installation, native parent activation or reboot.
"""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


W = load('configuration_wiring_fixture', 'scripts/test-installation-wiring.py')
Q = load('configuration_stage', 'deploy/installer/company_configuration.py')
BUILDER = load('configuration_package_builder', 'deploy/installer/build-native-retention-package.py')


def captured():
    return dict(fingerprint='a' * 64, configs={
        'images.lock.json': b'{ "platform": "registry.invalid/platform@sha256:' + b'b' * 64 + b'" }\n',
        'runtime-manifest.json': b'{ "schemaVersion": 1, "templates": {} }\n',
        'approved-mirrors.json': b'[ ]\n'})


class WizardTests(unittest.TestCase):
    def fixture(self):
        f = W.Fixture()
        f.final(finish=True)
        (f.base / 'models.json').write_text('{}')
        return f

    def call(self, f, release):
        return f.ns['configure'](W.Data(f.data), W.ARGS[1], host_directory=f.host,
            files=f.files, captured_release=release)

    def test_captured_exact_bytes_ignore_environment_and_never_request_runtime_path(self):
        f = self.fixture()
        release = captured()
        with patch.dict(os.environ, COMPANY_RELEASE_DIR='/missing/unsigned/path',
                        COMPANY_RELEASE_FINGERPRINT='untrusted'):
            self.call(f, release)
        for name, raw in release['configs'].items():
            self.assertEqual((f.data / 'config' / name).read_bytes(), raw)
        self.assertEqual(f.files.read(f.data / 'config/installation.json')['company_public_fingerprint'], 'a' * 64)
        self.assertNotIn('Company-approved runtime manifest JSON path', f.prompts)

    def test_bad_captured_input_refuses_before_prompts_or_secret_writes(self):
        mutations = (
            lambda r: r.update(fingerprint='untrusted'),
            lambda r: r.update(extra=True),
            lambda r: r['configs'].pop('images.lock.json'),
            lambda r: r['configs'].update({'runtime-manifest.json': b'{"x":1,"x":2}'}),
            lambda r: r['configs'].update({'runtime-manifest.json': b'{"x":NaN}'}),
            lambda r: r['configs'].update({'approved-mirrors.json': b'{}'}),
            lambda r: r['configs'].update({'images.lock.json': '{}'}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                f = self.fixture(); release = captured(); mutation(release)
                with self.assertRaises(ValueError):
                    self.call(f, release)
                self.assertEqual(f.prompts, [])
                self.assertEqual(f.secret_writes, [])

    def test_partial_signed_catalog_is_preserved_without_prompt_replay(self):
        f = self.fixture()
        path = f.data / 'config/images.lock.json'
        path.write_bytes(b'prior partial catalog')
        with self.assertRaises(ValueError):
            self.call(f, captured())
        self.assertEqual(path.read_bytes(), b'prior partial catalog')
        self.assertEqual(f.prompts, [])
        self.assertEqual(f.secret_writes, [])

    def test_questionnaire_inputs_are_consumed_without_native_stage_prompts(self):
        for mode in ('selfsigned', 'route53', 'gcloud', 'cpanel'):
            with self.subTest(mode=mode):
                f = self.fixture(); account = f.base / 'dns.json'; account.write_text('{}')
                values = {'Certificate mode: selfsigned/route53/gcloud/cpanel': mode,
                    'SSO providers: none/microsoft/google/both': 'both',
                    'Monthly API spending limit USD': '30', 'Microsoft tenant UUID': W.ID,
                    'Google DNS service-account JSON path': str(account),
                    'CPANEL_BASE_URL': 'https://whm.example.invalid',
                    'Optional security notification recipient email (blank disables email)': 'it@example.invalid',
                    'SMTP host (verified STARTTLS required)': 'smtp.example.invalid',
                    'SMTP sender email': 'platform@example.invalid',
                    'Company image registry hostname requiring login (optional)': 'registry.example.invalid'}
                def prompt(text):
                    label = text[:-2]
                    default = ''
                    if label.endswith(']') and ' [' in label:
                        label, default = label.rsplit(' [', 1); default = default[:-1]
                    return values.get(label, f.ask(label, default))
                with patch('builtins.input', side_effect=prompt), patch.object(Q.getpass, 'getpass', side_effect=prompt):
                    answers = Q.collect_answers()
                f.prompts.clear()
                with patch('builtins.input', side_effect=AssertionError('late prompt')):
                    f.ns['configure'](W.Data(f.data), W.ARGS[1], host_directory=f.host, files=f.files,
                        captured_release=captured(), answers=answers)
                self.assertEqual(f.prompts, [])
                self.assertEqual(f.files.read(f.data / 'config/installation.json')['monthly_budget_usd'], '30')

    def test_missing_answer_never_falls_back_to_prompt(self):
        f = self.fixture()
        with self.assertRaisesRegex(ValueError, 'interactive fallback is disabled'):
            f.ns['configure'](W.Data(f.data), W.ARGS[1], host_directory=f.host, files=f.files,
                captured_release=captured(), answers={'Unexpected': 'value'})
        self.assertEqual(f.prompts, []); self.assertEqual(f.secret_writes, [])


class StageTests(unittest.TestCase):
    def state(self, timer=False, **changes):
        value = dict(ActiveState='inactive', SubState='dead', MainPID='0', ControlPID='0', ControlGroup='', LoadState='not-found')
        value.update(changes)
        if timer:
            for key in ('MainPID', 'ControlPID', 'ControlGroup'): value.pop(key)
        return ''.join(key + '=' + value[key] + '\n' for key in value)

    def test_quiet_guard_checks_all_units_and_rejects_even_stopped_containers(self):
        calls = []
        def command(argv):
            calls.append(argv)
            return self.state(timer=argv[-1].endswith('.timer')) if argv[0].endswith('systemctl') else ''
        Q.quiet(command)
        self.assertEqual({row[-1] for row in calls[:-1]}, set(Q.UNITS))
        with self.assertRaises(ValueError):
            Q.quiet(lambda argv: self.state(timer=argv[-1].endswith('.timer')) if argv[0].endswith('systemctl') else 'stopped-original\n')

    def test_active_ambiguous_or_duplicate_unit_state_never_reaches_docker(self):
        for output in (self.state(ActiveState='active'), self.state(MainPID='1'),
                       self.state(ControlGroup='/existing'), self.state() + 'LoadState=loaded\n'):
            calls = []
            with self.assertRaises(ValueError):
                Q.quiet(lambda argv: (calls.append(argv), output)[1])
            self.assertEqual(len(calls), 1)

    def test_no_public_handle_or_boolean_grants_configure_authority(self):
        with patch('pathlib.Path.mkdir', side_effect=AssertionError('mutation')):
            with self.assertRaises(ValueError):
                Q.run(None, full_entry_module=None, held=True, assembly=True, parent=True,
                    request={}, request_raw=b'{}\n', worker_sha256='a' * 64,
                    command=lambda unused: self.fail('native call'), execute=True)

    def test_action_binds_worker_and_exact_request_bytes(self):
        first = Q.action(b'{}\n', 'a' * 64)
        self.assertNotEqual(first, Q.action(b'{ }\n', 'a' * 64))
        self.assertNotEqual(first, Q.action(b'{}\n', 'b' * 64))

    def test_configuration_entry_embeds_same_worker_and_admission_code(self):
        worker = BUILDER.assemble(ROOT, 'a' * 64, reader=lambda path, limit: path.read_bytes())
        entry = BUILDER.assemble_entry(ROOT, worker, reader=lambda path, limit: path.read_bytes(), configuration=True)
        self.assertIn(BUILDER.pin(worker)['sha256'].encode(), entry)
        self.assertNotIn(b'@WORKER_SHA256@', entry)
        self.assertIn(b'install_lock_verify', entry)
        self.assertIn(b'configuration_child_failed_preserve_evidence', entry)


if __name__ == '__main__':
    unittest.main(verbosity=2)
