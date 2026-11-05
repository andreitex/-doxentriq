"""Local injected storage identity controls. Never invokes installer or host commands."""
import ast
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid
import urllib.parse

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
_proposal = os.environ.get('AUTOSOFT_FOUNDATION_TEST_PROPOSAL')
INSTALL_SOURCE = Path(_proposal).resolve() if _proposal is not None else ROOT / 'scripts/install.sh'
if _proposal is not None and not INSTALL_SOURCE.is_relative_to(ROOT / '.local'):
    raise RuntimeError('Explicit installation test proposal must reside in local evidence.')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


I = load('wiring_identity', ROOT / 'scripts/installation_identity.py')
B = load('wiring_local_files', ROOT / 'test/test_checkpoint_admission.py')
ID = '64a2a5f8-04b9-43b5-9807-122d866db1f1'
OTHER = '947aaf58-8ba3-4c42-b4ba-e2a1f87b0cf5'
LUKS = '45fb163d-e8ec-452b-aec0-ffdc391be9fa'
ARGS = ('/srv/autosoft', '/opt/autosoft', '/var/lib/autosoft-storage.luks', 128)
SELECTED = {'create_storage_identity', 'record_storage_pending', 'storage_final',
            'verify_storage_final', 'commit_storage_final', 'finish_storage_receipt',
            'initialize_storage', 'configure', 'origin', 'storage_record_bytes'}
SOURCE = (ROOT / 'scripts/bootstrap.py').read_text()
TREE = ast.parse(SOURCE)


def forbidden(*args, **kwargs):
    raise AssertionError('No native command is authorized by local controls')


class Data:
    """Only path presentation is injected: writes stay in this owned fixture."""
    def __init__(self, actual, logical=ARGS[0]):
        self.actual, self.logical = actual, logical
    def __str__(self):
        return self.logical
    def __truediv__(self, name):
        return self.actual / name


class Files(B.Files):
    def __init__(self, fixture):
        super().__init__()
        self.fixture = fixture
        self.after_read = None
    def protected(self, path, directory=False, private=False):
        if str(path) == str(Path(ARGS[2])):
            path = self.fixture.backing
        return super().protected(path, directory=directory, private=private)
    def read(self, path):
        value = super().read(path)
        self.events.append(('read', Path(path).name))
        callback = self.after_read
        if callback:
            callback(Path(path), value)
        return value


class Fixture:
    def __init__(self):
        root = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local/installation-identity-wiring-v1/fixtures'))).resolve()
        root.mkdir(parents=True, exist_ok=True)
        self.base = Path(tempfile.mkdtemp(prefix='identity-wiring-', dir=root))
        self.host = self.base / 'etc'; self.host.mkdir(mode=0o700)
        self.data = self.base / 'encrypted'; self.data.mkdir(mode=0o700)
        (self.data / 'config').mkdir(mode=0o700)
        self.backing = self.base / 'synthetic-backing'
        self.files = Files(self)
        self.generated = 0; self.commands = []; self.prompts = []; self.secret_writes = []
        self.blocked = set()
        self.ns = dict(_identity=I, Path=Path, os=os, uuid=uuid, json=json, re=re, urllib=urllib, base64=base64,
                       subprocess=SimpleNamespace(check_output=forbidden, run=forbidden),
                       ask=self.ask, write=self.write)
        nodes = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in SELECTED]
        assert {node.name for node in nodes} == SELECTED
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'selected-bootstrap-controls', 'exec'), self.ns)
    def factory(self):
        self.generated += 1
        return uuid.UUID(ID)
    def exists(self, path):
        return str(path) in self.blocked or (str(path) != ARGS[2] and os.path.lexists(path))
    def create(self, args=ARGS):
        return self.ns['create_storage_identity'](*args, host_directory=self.host, files=self.files,
                                                  exists=self.exists, uuid_factory=self.factory)
    def measure(self, args, **kwargs):
        self.commands.append((args, kwargs))
        return LUKS + '\n'
    def pending(self):
        if not (self.host / I.INTENT).exists(): self.create()
        self.backing.write_text('synthetic encrypted backing')
        (self.host / 'storage.key').write_text('synthetic unlock material')
        return self.ns['record_storage_pending'](*ARGS, host_directory=self.host, files=self.files, command=self.measure)
    def final(self, finish=False):
        value = self.pending()
        self.ns['commit_storage_final'](value, host_directory=self.host, files=self.files)
        if finish: self.ns['finish_storage_receipt'](value, host_directory=self.host, files=self.files)
        return value
    def initialize(self):
        return self.ns['initialize_storage'](self.host, self.host, host_directory=self.host, files=self.files)
    def configure(self, data=None, root=ARGS[1]):
        return self.ns['configure'](data or Data(self.data), root, host_directory=self.host, files=self.files)
    def ask(self, label, default='', sensitive=False):
        self.prompts.append(label)
        values = {'Administrative HTTPS URL': 'https://admin.example.invalid',
                  'Applications HTTPS base URL': 'https://apps.example.invalid',
                  'Identity HTTPS URL': 'https://auth.example.invalid',
                  'OpenAI API key (optional)': 'synthetic-local-value',
                  'Anthropic API key (optional)': '',
                  'Company-approved model catalog JSON path': str(self.base / 'models.json'),
                  'Company-approved runtime manifest JSON path': str(self.base / 'runtime.json')}
        return values.get(label, default)
    def write(self, path, value, mode=0o600, uid=None):
        path = Path(path); self.secret_writes.append(path.relative_to(self.data).as_posix())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
    def existing_config(self, **changes):
        value = dict(installation_id=ID, owner_subject=OTHER, retained='unchanged')
        value.update(changes)
        self.files.write(self.data / 'config/installation.json', value)
        return value


class WiringTests(unittest.TestCase):
    def test_fresh_identity_is_exclusive_synced_and_read_back_before_return(self):
        f = Fixture(); value = f.create()
        self.assertEqual(value['installation_id'], ID); self.assertEqual(f.generated, 1)
        events = f.files.events
        write = events.index(('write', I.INTENT))
        reads = [i for i, event in enumerate(events) if event == ('read', I.INTENT)]
        syncs = [i for i, event in enumerate(events) if event[0] == 'directory-fsync-policy']
        self.assertTrue(write < min(syncs) < min(reads)); self.assertGreaterEqual(len(reads), 3)
        self.assertEqual(f.commands, []); self.assertFalse(f.backing.exists())

    def test_identity_write_failure_prevents_storage_and_pending(self):
        f = Fixture(); f.files.failures[I.INTENT] = 'before'
        with self.assertRaises(OSError): f.create()
        self.assertFalse(f.backing.exists()); self.assertEqual(f.commands, [])
        self.assertFalse((f.host / 'installation.pending.json').exists())

    def test_lost_identity_ack_retains_original_and_refuses_second_identity(self):
        f = Fixture(); f.files.failures[I.INTENT] = 'after'
        with self.assertRaises(OSError): f.create()
        raw = (f.host / I.INTENT).read_bytes()
        with self.assertRaises(ValueError): f.create()
        self.assertEqual(f.generated, 1); self.assertEqual((f.host / I.INTENT).read_bytes(), raw)
        self.assertEqual(f.commands, [])

    def test_retained_receipt_blocks_fresh_before_uuid_generation(self):
        f = Fixture(); (f.host / 'installation.storage-receipt.json').write_text('{}')
        with self.assertRaises(ValueError): f.create()
        self.assertEqual(f.generated, 0); self.assertFalse((f.host / I.INTENT).exists())

    def test_shell_commits_identity_before_each_backing_key_and_format_effect(self):
        source = INSTALL_SOURCE.read_text()
        call = 'python3 -I -B "$SCRIPT_DIR/bootstrap.py" storage-identity "$DATA_DIR" "$INSTALL_ROOT" "$STORAGE_FILE" "$STORAGE_GIB"'
        self.assertEqual(source.count(call), 1)
        for effect in ('(set -o noclobber; : > "$STORAGE_FILE")', 'fallocate -l', 'head -c 64 /dev/urandom', 'cryptsetup luksFormat'):
            self.assertEqual(source.count(effect), 1); self.assertLess(source.index(call), source.index(effect))
        pending = 'python3 -I -B "$SCRIPT_DIR/bootstrap.py" storage-pending "$DATA_DIR" "$INSTALL_ROOT" "$STORAGE_FILE" "$STORAGE_GIB"'
        self.assertEqual(source.count(pending), 1); self.assertLess(source.index('cryptsetup open --key-file'), source.index(pending))

    def test_pending_measurement_and_receipt_preserve_canonical_same_uuid(self):
        f = Fixture(); value = f.pending()
        self.assertEqual(value['installation_id'], ID); self.assertEqual(value['luks_uuid'], LUKS)
        self.assertEqual(f.commands, [(['cryptsetup', 'luksUUID', ARGS[2]], {'text': True})])
        self.assertEqual(I.verify_host_record(f.host, pending=True, files=f.files), value)

    def test_wrong_geometry_denies_pending_before_measurement(self):
        f = Fixture(); f.create()
        with self.assertRaises(ValueError): f.ns['record_storage_pending']('/different', *ARGS[1:], host_directory=f.host, files=f.files, command=f.measure)
        self.assertEqual(f.commands, []); self.assertFalse((f.host / 'installation.pending.json').exists())

    def test_pending_noncanonical_measurement_and_command_failure_preserve_intent(self):
        for result in (LUKS.upper(), 'invalid', LUKS.encode()):
            with self.subTest(result_type=type(result).__name__):
                f = Fixture(); f.create(); f.backing.write_text('x'); (f.host / 'storage.key').write_text('x')
                with self.assertRaises(ValueError):
                    f.ns['record_storage_pending'](*ARGS, host_directory=f.host, files=f.files, command=lambda *a, **k: result)
                self.assertFalse((f.host / 'installation.pending.json').exists()); self.assertEqual(I.read_intent(f.host, files=f.files)['installation_id'], ID)
        f = Fixture(); f.create(); f.backing.write_text('x'); (f.host / 'storage.key').write_text('x')
        def fail(*args, **kwargs): raise OSError('injected local measurement failure')
        with self.assertRaises(OSError): f.ns['record_storage_pending'](*ARGS, host_directory=f.host, files=f.files, command=fail)
        self.assertFalse((f.host / 'installation.pending.json').exists())

    def test_pending_existing_or_unprotected_inputs_deny_before_measurement(self):
        for name in ('installation.pending.json', 'installation.json', 'installation.storage-receipt.json', 'storage.key'):
            with self.subTest(name=name):
                f = Fixture(); f.create(); f.backing.write_text('x'); (f.host / 'storage.key').write_text('x')
                if name == 'storage.key': f.files.untrusted.add(f.host / name)
                else: (f.host / name).write_text('{}')
                with self.assertRaises(ValueError): f.ns['record_storage_pending'](*ARGS, host_directory=f.host, files=f.files, command=f.measure)
                self.assertEqual(f.commands, [])

    def test_lost_pending_ack_retains_receipt_and_refuses_remeasurement(self):
        f = Fixture(); f.files.failures['installation.pending.json'] = 'after'
        with self.assertRaises(OSError): f.pending()
        raw = (f.host / 'installation.pending.json').read_bytes(); count = len(f.commands)
        with self.assertRaises(ValueError): f.ns['record_storage_pending'](*ARGS, host_directory=f.host, files=f.files, command=f.measure)
        self.assertEqual(len(f.commands), count); self.assertEqual((f.host / 'installation.pending.json').read_bytes(), raw)

    def test_intent_change_during_measurement_prevents_pending_publication(self):
        f = Fixture(); f.create(); f.backing.write_text('x'); (f.host / 'storage.key').write_text('x')
        def measure(*args, **kwargs):
            path = f.host / I.INTENT; value = json.loads(path.read_text()); value['installation_id'] = OTHER
            path.write_text(json.dumps(value)); return LUKS
        with self.assertRaises(ValueError): f.ns['record_storage_pending'](*ARGS, host_directory=f.host, files=f.files, command=measure)
        self.assertFalse((f.host / 'installation.pending.json').exists())

    def test_pending_schema_failure_prevents_all_initialize_commands(self):
        for change in ({'installation_id': OTHER}, {'creation_stage': 'unknown'}, {'luks_uuid': 'invalid'}, {'extra': True}):
            with self.subTest(change=change):
                f = Fixture(); value = f.pending(); value.update(change)
                (f.host / 'installation.pending.json').write_text(json.dumps(value))
                with self.assertRaises(ValueError): f.initialize()
                self.assertFalse((f.host / 'installation.json').exists())

    def test_existing_exact_final_is_read_only_and_refuses_native_replay(self):
        f = Fixture(); f.final(); before = {p.name: p.read_bytes() for p in f.host.iterdir()}
        f.files.events.clear()
        with self.assertRaisesRegex(ValueError, 'company continuation'): f.initialize()
        self.assertEqual({p.name: p.read_bytes() for p in f.host.iterdir()}, before)
        self.assertFalse(any(e[0] in ('write', 'directory-fsync-policy') for e in f.files.events))

    def test_final_conflict_and_legacy_fail_before_initialize_effects(self):
        for change in ({'installation_id': OTHER}, {'data_dir': '/different'}, {'installation_id': None}):
            with self.subTest(change=change):
                f = Fixture(); value = f.final(); bad = f.ns['storage_final'](value); bad.update(change)
                (f.host / 'installation.json').write_text(json.dumps(bad)); raw = (f.host / 'installation.json').read_bytes()
                with self.assertRaises(ValueError): f.initialize()
                self.assertEqual((f.host / 'installation.json').read_bytes(), raw)

    def test_final_commit_is_exclusive_durable_and_matching(self):
        f = Fixture(); value = f.pending(); f.files.events.clear()
        final = f.ns['commit_storage_final'](value, host_directory=f.host, files=f.files)
        self.assertEqual(final, f.ns['storage_final'](value)); self.assertEqual(final['installation_id'], ID)
        self.assertIn(('write', 'installation.json'), f.files.events)
        self.assertEqual(I.verify_host_record(f.host, files=f.files), final)
        self.assertFalse((f.host / 'installation.pending-commit').exists())

    def test_final_failure_and_lost_ack_preserve_all_pending_evidence(self):
        for failure in ('before', 'after'):
            with self.subTest(failure=failure):
                f = Fixture(); value = f.pending(); raw = (f.host / 'installation.pending.json').read_bytes()
                f.files.failures['installation.json'] = failure
                with self.assertRaises(OSError): f.ns['commit_storage_final'](value, host_directory=f.host, files=f.files)
                self.assertEqual((f.host / 'installation.pending.json').read_bytes(), raw)
                self.assertEqual((f.host / 'installation.json').exists(), failure == 'after')
                if failure == 'after':
                    with self.assertRaisesRegex(ValueError, 'company continuation'): f.initialize()

    def test_receipt_is_synced_read_back_before_pending_retirement(self):
        f = Fixture(); value = f.final(); raw = (f.host / 'installation.pending.json').read_bytes(); f.files.events.clear()
        f.ns['finish_storage_receipt'](value, host_directory=f.host, files=f.files)
        self.assertFalse((f.host / 'installation.pending.json').exists())
        self.assertEqual((f.host / 'installation.storage-receipt.json').read_bytes(), raw)
        names = [e for e in f.files.events if e[0] in ('write', 'read', 'directory-fsync-policy')]
        self.assertLess(names.index(('write', 'installation.storage-receipt.json')), names.index(('read', 'installation.storage-receipt.json')))
        self.assertGreaterEqual(sum(e[0] == 'directory-fsync-policy' for e in names), 2)

    def test_retained_receipt_conflict_or_lost_ack_never_retires_pending(self):
        for failure in ('conflict', 'before', 'after'):
            with self.subTest(failure=failure):
                f = Fixture(); value = f.final(); raw = (f.host / 'installation.pending.json').read_bytes()
                if failure == 'conflict': f.files.write(f.host / 'installation.storage-receipt.json', {'unrelated': True})
                else: f.files.failures['installation.storage-receipt.json'] = failure
                with self.assertRaises((ValueError, OSError)): f.ns['finish_storage_receipt'](value, host_directory=f.host, files=f.files)
                self.assertEqual((f.host / 'installation.pending.json').read_bytes(), raw)

    def test_retained_exact_receipt_is_verified_without_overwrite(self):
        f = Fixture(); value = f.final(); f.files.write(f.host / 'installation.storage-receipt.json', value)
        raw = (f.host / 'installation.storage-receipt.json').read_bytes(); f.files.events.clear()
        f.ns['finish_storage_receipt'](value, host_directory=f.host, files=f.files)
        self.assertEqual((f.host / 'installation.storage-receipt.json').read_bytes(), raw)
        self.assertFalse(any(e[0] == 'write' for e in f.files.events))

    def test_receipt_or_pending_noncanonical_bytes_are_not_silently_reencoded(self):
        for name in ('installation.pending.json', 'installation.storage-receipt.json'):
            with self.subTest(name=name):
                f = Fixture(); value = f.final()
                path = f.host / name; path.write_text(json.dumps(value, indent=2))
                original = path.read_bytes()
                with self.assertRaises(ValueError): f.ns['finish_storage_receipt'](value, host_directory=f.host, files=f.files)
                self.assertTrue((f.host / 'installation.pending.json').exists())
                self.assertEqual(path.read_bytes(), original)

    def test_pending_change_during_receipt_write_blocks_retirement(self):
        f = Fixture(); value = f.final(); original = f.files.write
        def write(path, record):
            original(path, record)
            if path.name == 'installation.storage-receipt.json':
                pending = f.host / 'installation.pending.json'
                pending.write_bytes(pending.read_bytes() + b' ')
        f.files.write = write
        with self.assertRaises(ValueError): f.ns['finish_storage_receipt'](value, host_directory=f.host, files=f.files)
        self.assertTrue((f.host / 'installation.pending.json').exists())

    def test_configuration_legacy_geometry_and_pending_deny_before_prompts_or_secrets(self):
        for failure in ('missing-id', 'geometry', 'pending'):
            with self.subTest(failure=failure):
                f = Fixture(); f.final(finish=failure != 'pending')
                if failure == 'missing-id':
                    value = json.loads((f.host / 'installation.json').read_text()); value.pop('installation_id')
                    (f.host / 'installation.json').write_text(json.dumps(value))
                with self.assertRaises(ValueError): f.configure(data=Data(f.data, '/different') if failure == 'geometry' else None)
                self.assertEqual(f.prompts, []); self.assertEqual(f.secret_writes, [])

    def test_existing_valid_configuration_preserves_owner_secrets_and_exact_bytes(self):
        f = Fixture(); f.final(finish=True); value = f.existing_config()
        secret = f.data / 'retained-secret'; secret.write_text('synthetic retained material')
        before = (f.data / 'config/installation.json').read_bytes(); f.files.events.clear()
        f.configure()
        self.assertEqual((f.data / 'config/installation.json').read_bytes(), before)
        self.assertEqual(json.loads(before)['owner_subject'], value['owner_subject'])
        self.assertEqual(secret.read_text(), 'synthetic retained material')
        self.assertEqual(f.prompts, []); self.assertEqual(f.secret_writes, [])
        self.assertFalse(any(e[0] == 'write' for e in f.files.events))

    def test_existing_configuration_wrong_missing_or_duplicate_id_is_never_adopted(self):
        for raw in (json.dumps({'installation_id': OTHER}), '{}', '{"installation_id":"' + ID + '","installation_id":"' + ID + '"}'):
            with self.subTest(raw_length=len(raw)):
                f = Fixture(); f.final(finish=True); target = f.data / 'config/installation.json'; target.write_text(raw)
                with self.assertRaises(ValueError): f.configure()
                self.assertEqual(target.read_text(), raw); self.assertEqual(f.prompts, []); self.assertEqual(f.secret_writes, [])

    def test_fresh_configuration_uses_persisted_uuid_and_exclusive_final_write(self):
        f = Fixture(); f.final(finish=True)
        (f.base / 'models.json').write_text('{}'); (f.base / 'runtime.json').write_text('{}')
        prior = os.environ.pop('COMPANY_RELEASE_DIR', None)
        try: f.configure()
        finally:
            if prior is not None: os.environ['COMPANY_RELEASE_DIR'] = prior
        value = f.files.read(f.data / 'config/installation.json')
        self.assertEqual(value['installation_id'], ID); self.assertNotEqual(value['owner_subject'], ID)
        self.assertIn(('write', 'installation.json'), f.files.events)
        self.assertTrue(f.prompts)

    def test_fresh_configuration_lost_final_ack_is_preserved_on_read_only_rerun(self):
        f = Fixture(); f.final(finish=True)
        (f.base / 'models.json').write_text('{}'); (f.base / 'runtime.json').write_text('{}')
        f.files.failures['installation.json'] = 'after'
        prior = os.environ.pop('COMPANY_RELEASE_DIR', None)
        try:
            with self.assertRaises(OSError): f.configure()
            raw = (f.data / 'config/installation.json').read_bytes(); f.prompts.clear(); f.secret_writes.clear()
            f.configure()
            self.assertEqual((f.data / 'config/installation.json').read_bytes(), raw)
            self.assertEqual(f.prompts, []); self.assertEqual(f.secret_writes, [])
        finally:
            if prior is not None: os.environ['COMPANY_RELEASE_DIR'] = prior

    def test_partial_configuration_evidence_refuses_before_new_prompts_or_secrets(self):
        for kind in ('secrets', 'models', 'untrusted-config'):
            with self.subTest(kind=kind):
                f = Fixture(); f.final(finish=True)
                if kind == 'secrets':
                    (f.data / 'secrets').mkdir(); (f.data / 'secrets/retained').write_text('synthetic retained material')
                elif kind == 'models': (f.data / 'config/models.json').write_text('{}')
                else: f.files.untrusted.add(f.data / 'config')
                with self.assertRaises(ValueError): f.configure()
                self.assertEqual(f.prompts, []); self.assertEqual(f.secret_writes, [])

    def test_config_final_write_failure_preserves_partial_secrets_and_refuses_recreation(self):
        f = Fixture(); f.final(finish=True)
        (f.base / 'models.json').write_text('{}'); (f.base / 'runtime.json').write_text('{}')
        f.files.failures['installation.json'] = 'before'
        prior = os.environ.pop('COMPANY_RELEASE_DIR', None)
        try:
            with self.assertRaises(OSError): f.configure()
            secret = f.data / 'secrets/platform/openai-key'; raw = secret.read_bytes()
            f.prompts.clear(); f.secret_writes.clear()
            with self.assertRaises(ValueError): f.configure()
            self.assertEqual(secret.read_bytes(), raw); self.assertEqual(f.prompts, []); self.assertEqual(f.secret_writes, [])
            self.assertFalse((f.data / 'config/installation.json').exists())
        finally:
            if prior is not None: os.environ['COMPANY_RELEASE_DIR'] = prior


if __name__ == '__main__': unittest.main(verbosity=2)
