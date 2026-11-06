"""Narrow renderer/verification seams; no native installation qualification.

Actual temporary configuration bytes exercise the existing data checks. Windows
alone emulates POSIX mode bits; TLS commands are observed rather than executed.
The captured module fixture uses real dependency objects, not source authority.
"""
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import MappingProxyType, ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bootstrap_render_hook_tests', ROOT/'scripts/bootstrap.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


def captured():
    module = ModuleType('captured_bootstrap_render_hook_fixture')
    module.__file__ = '<captured company scripts/bootstrap.py>'
    module.__company_captured_dependencies__ = MappingProxyType({
        'scripts/registry_manifest.py': B._registry,
        'scripts/runtime_layout.py': B._layout,
        'scripts/installation_identity.py': B._identity,
        'scripts/identity.py': B._owner_identity,
    })
    exec(compile((ROOT/'scripts/bootstrap.py').read_bytes(), module.__file__, 'exec'), module.__dict__)
    return module


class StopBeforeEffect(Exception):
    pass


class RenderLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        self.root = self.data/'source'

    def test_legacy_default_keeps_fresh_prepare(self):
        with patch.object(B._layout, 'prepare', side_effect=StopBeforeEffect) as prepare:
            with self.assertRaises(StopBeforeEffect): B.render(self.data, self.root)
        prepare.assert_called_once_with(self.data)
        self.assertEqual(list(self.data.iterdir()), [])

    def test_initialized_pair_uses_explicit_readonly_callback(self):
        # Existing runtime controls must not be sent back to fresh preparation.
        (self.data/'quota').mkdir()
        for name in ('checkpoint-admission', 'allocation'): (self.data/'quota'/name).mkdir()
        (self.data/'quota/projects.json').write_text('{}')
        seen = []
        def layout(data):
            self.assertEqual(data, self.data)
            seen.append('verified')
            return dict(scope='RUNTIME_PLACEMENT_ONLY', status='verified', changed=False, backupReady=False)
        before = sorted(p.relative_to(self.data).as_posix() for p in self.data.rglob('*'))
        with patch.object(B._layout, 'prepare', side_effect=AssertionError('fresh layout must not run')):
            with patch.object(Path, 'mkdir', side_effect=StopBeforeEffect):
                with self.assertRaises(StopBeforeEffect): captured().render(self.data, self.root, verify_layout=layout)
        self.assertEqual(seen, ['verified'])
        self.assertEqual(before, sorted(p.relative_to(self.data).as_posix() for p in self.data.rglob('*')))

    def test_failed_or_unverified_layout_cannot_reach_first_write(self):
        good = dict(scope='RUNTIME_PLACEMENT_ONLY', status='verified', changed=False, backupReady=False)
        for value in (None, True, {}, dict(good, changed=True), dict(good, changed=0),
                      dict(good, backupReady=True), dict(good, extra='unexpected')):
            with self.subTest(value=value), patch.object(Path, 'mkdir', side_effect=AssertionError('unexpected effect')):
                with self.assertRaises(ValueError): B.render(self.data, self.root, verify_layout=lambda _: value)
        def failed(_): raise StopBeforeEffect()
        with self.assertRaises(StopBeforeEffect): B.render(self.data, self.root, verify_layout=failed)
        self.assertEqual(list(self.data.iterdir()), [])

    def test_captured_missing_callback_refuses_before_path_access(self):
        with patch.object(Path, 'exists', side_effect=AssertionError('unexpected path access')):
            for value in (None, False, 'verify'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    captured().render(self.data, self.root, verify_layout=value)


class DataFixture:
    def __init__(self, root):
        self.root = root
        (root/'config').mkdir()
        (root/'secrets/platform').mkdir(parents=True)
        self.key = root/'secrets/platform/secret-key'
        self.key.write_text(base64.b64encode(b'X'*32).decode())
        self.key.chmod(0o600)
        self.mode = 0o600
        digest = 'a'*64
        self.images = {name: 'example.invalid/'+name+'@sha256:'+digest
                       for name in ('mysql','redis','rabbitmq','registry','dependency_proxy')}
        self.manifest = dict(schemaVersion=1,
            templates={'node': dict(toolchainImage='example.invalid/node@sha256:'+digest,
                                    runtimeImage='registry:5000/base/node@sha256:'+digest)},
            scannerImage='example.invalid/scanner@sha256:'+digest,
            serviceImages={name: self.images[key] for name, key in (
                ('mysql','mysql'),('redis','redis'),('rabbitmq','rabbitmq'),
                ('registry','registry'),('dependency-proxy','dependency_proxy'))},
            registry='registry:5000', dependencyProxy='http://dependency-proxy:3128',
            allowedPackageHosts=['registry.npmjs.org'])
        self.models = dict(schemaVersion=1, pricesVerifiedAt=datetime.now(timezone.utc).isoformat(),
                           models=[dict(qualified=True, tier='strong')])
        self.configuration = dict(company_public_fingerprint='b'*64, installation_id='fixture-only')
        self.save()

    def save(self):
        for name, value in (('runtime-manifest.json',self.manifest), ('images.lock.json',self.images),
                            ('models.json',self.models), ('installation.json',self.configuration)):
            (self.root/'config'/name).write_text(json.dumps(value))

    @contextmanager
    def modes(self):
        if os.name != 'nt':
            self.key.chmod(self.mode)
            yield
            return
        original = Path.stat
        def windows_stat(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == self.key:
                values = list(result)
                values[0] = stat.S_IFREG | self.mode
                return os.stat_result(values)
            return result
        with patch.object(Path, 'stat', windows_stat): yield


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        self.f = DataFixture(self.data)
        self.enterContext(self.f.modes())
        self.calls = []

    def command(self, argv): self.calls.append(list(argv))

    def test_data_helper_checks_every_tls_item_without_source_or_success_claim(self):
        (self.data/'config/installation.json').unlink()
        output = io.StringIO()
        with redirect_stdout(output): captured().verify_data(self.data, command=self.command)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(len(self.calls), 26)
        self.assertTrue(all(row[0] == '/usr/bin/openssl' for row in self.calls))
        self.assertEqual(sum(row[1] == 'verify' for row in self.calls), 13)
        self.assertEqual(sum(row[1] == 'x509' for row in self.calls), 13)
        self.assertEqual(self.calls[-1][3], '2592000')

    def test_legacy_data_default_executes_tls_instead_of_skipping(self):
        with patch.object(B.subprocess, 'run') as run:
            B.verify_data(self.data)
        self.assertEqual(run.call_count, 26)
        self.assertTrue(all(call.args[0][0] == 'openssl' and call.kwargs['check'] is True for call in run.call_args_list))
        with patch.object(B.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'openssl')):
            with self.assertRaises(subprocess.CalledProcessError): B.verify_data(self.data)

    def test_data_validation_failures_precede_tls(self):
        original = (copy.deepcopy(self.f.manifest), copy.deepcopy(self.f.models))
        changes = (
            lambda: self.f.manifest.update(scannerImage='scanner:latest'),
            lambda: self.f.manifest['serviceImages'].update(mysql='example.invalid/mysql@sha256:'+'c'*64),
            lambda: self.f.manifest.update(allowedPackageHosts=['unapproved.invalid']),
            lambda: self.f.models.update(pricesVerifiedAt=(datetime.now(timezone.utc)-timedelta(days=32)).isoformat()),
            lambda: self.f.models.update(models=[dict(qualified=False, tier='strong')]),
        )
        for change in changes:
            with self.subTest(change=change):
                self.f.manifest, self.f.models = copy.deepcopy(original)
                change(); self.f.save()
                with self.assertRaises(ValueError): B.verify_data(self.data, command=self.command)
                self.assertFalse(self.calls)

    def test_secret_modes_and_key_length_still_block(self):
        self.f.mode = 0o640
        if os.name != 'nt': self.f.key.chmod(self.f.mode)
        with self.assertRaises(ValueError): B.verify_data(self.data, command=self.command)
        self.f.mode = 0o600
        if os.name != 'nt': self.f.key.chmod(self.f.mode)
        self.f.key.write_text(base64.b64encode(b'short').decode())
        with self.assertRaises(ValueError): B.verify_data(self.data, command=self.command)
        self.assertFalse(self.calls)

    def test_captured_commands_are_explicit_and_checked(self):
        module = captured()
        for value in (None, False, 'openssl'):
            with self.subTest(value=value), self.assertRaises(ValueError): module.verify_data(self.data, command=value)
        for value in (True, False, '', 0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.verify_data(self.data, command=lambda _: value)
        def fail(argv):
            self.command(argv)
            if len(self.calls) == 4: raise StopBeforeEffect()
        with self.assertRaises(StopBeforeEffect): module.verify_data(self.data, command=fail)
        self.assertEqual(len(self.calls), 4)

    def test_live_source_wraps_data_and_avoids_legacy_synthetic_path(self):
        events = []
        def source(data, cfg):
            self.assertEqual(data, self.data)
            self.assertEqual(cfg, self.f.configuration)
            events.append(('source', len(self.calls)))
            cfg.clear()  # A callback receives a detached configuration value.
        module = captured()
        with patch.object(module, '_verify_legacy_source', side_effect=AssertionError('legacy source fallback')):
            with redirect_stdout(io.StringIO()): module.verify(self.data, source_verifier=source, command=self.command)
        self.assertEqual(events, [('source',0),('source',26)])

    def test_captured_missing_seam_refuses_before_any_read_or_command(self):
        module = captured()
        for source, command in ((None, None), (lambda *_: None, None), (None, self.command), (True, self.command)):
            with self.subTest(source=source, command=command):
                with patch.object(Path, 'read_bytes', side_effect=AssertionError('unexpected read')):
                    with self.assertRaises(ValueError): module.verify(self.data, source_verifier=source, command=command)
        self.assertFalse(self.calls)

    def test_source_failure_or_success_flag_cannot_run_tls(self):
        def expired(*_): raise StopBeforeEffect()
        with self.assertRaises(StopBeforeEffect): B.verify(self.data, source_verifier=expired, command=self.command)
        for value in (True, False, {}, 'verified'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                B.verify(self.data, source_verifier=lambda *_: value, command=self.command)
        self.assertFalse(self.calls)

    def test_source_expiry_after_tls_prevents_success_output(self):
        def source(*_):
            if self.calls: raise StopBeforeEffect()
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(StopBeforeEffect):
            captured().verify(self.data, source_verifier=source, command=self.command)
        self.assertEqual(len(self.calls),26)
        self.assertEqual(output.getvalue(),'')

    def test_configuration_drift_during_tls_prevents_confirmation(self):
        sources = []
        def source(*_): sources.append('source')
        def command(argv):
            self.command(argv)
            if len(self.calls) == 1:
                (self.data/'config/installation.json').write_text('{"changed":true}')
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'configuration changed'):
            captured().verify(self.data, source_verifier=source, command=command)
        self.assertEqual(sources, ['source'])

    def test_legacy_wrapper_preserves_signed_source_step(self):
        events = []
        def old_source(data,cfg):
            self.assertEqual(data,self.data);self.assertEqual(cfg,self.f.configuration)
            events.append('legacy-source')
        with patch.object(B,'_verify_legacy_source',side_effect=old_source):
            with redirect_stdout(io.StringIO()): B.verify(self.data,command=self.command)
        self.assertEqual(events,['legacy-source'])
        self.assertEqual(len(self.calls),26)

    def test_legacy_signed_catalog_authentication_and_mismatch_are_preserved(self):
        bundle = self.data/'config/company-release'
        bundle.mkdir()
        content = (self.data/'config/images.lock.json').read_bytes()
        import hashlib
        release = {'files': {'images.lock.json': {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}}}
        (bundle/'release.json').write_text(json.dumps(release))
        with patch.object(B._identity,'verify_host_record',return_value={'install_root':'/signed/company/source'}):
            with patch.object(B.subprocess,'run') as process, redirect_stdout(io.StringIO()):
                B.verify(self.data,command=self.command)
            argv = process.call_args.args[0]
            self.assertEqual(process.call_count,1)
            self.assertIn('--complete-deployment',argv)
            self.assertEqual(argv[-2:],['--source-root','/signed/company/source'])
            self.assertEqual(argv[4:7],[str(bundle),str(bundle/'company-signing-public-key.pem'),'b'*64])
            self.calls.clear()
            (self.data/'config/images.lock.json').write_bytes(content+b' ')
            with patch.object(B.subprocess,'run'), self.assertRaisesRegex(ValueError,'signed company release'):
                B.verify(self.data,command=self.command)
            self.assertFalse(self.calls)

    def test_configuration_drift_in_final_source_recheck_is_rejected(self):
        def source(*_):
            if self.calls: (self.data/'config/installation.json').write_text('{"changed":true}')
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(ValueError,'source recheck'):
            captured().verify(self.data,source_verifier=source,command=self.command)
        self.assertEqual(output.getvalue(),'')


if __name__ == '__main__': unittest.main(verbosity=2)
