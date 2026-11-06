"""Fresh-pair local/injected controls; no native installer or service authority."""
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


P = load('runtime_pair_controls', ROOT / 'scripts/runtime_pair_init.py')
F = load('runtime_pair_storage_fixture', ROOT / 'scripts/test-startup-binding.py')
C, Q, A = P.C, P.Q, P.A
INSTALLATION, OTHER, LUKS = F.INSTALLATION, F.OTHER, F.LUKS
SOURCE = 'injected:/dev/mapper/autosoft-data'
PARENT_SESSION_ID = 's-Abc123Def456'


class ByteTransport:
    """Windows file-read flags only; actual bounded IO remains in NativeFiles."""
    O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
    O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
    def __getattr__(self, name): return getattr(os, name)


class Files(F.Files):
    open_record = P.NativeFiles.open_record
    check_record = P.NativeFiles.check_record
    close_record = P.NativeFiles.close_record

    def __init__(self):
        super().__init__(); self.on_write = None; self.on_mkdir = None; self.on_raw = None; self.raw_reads = []

    def write(self, path, value):
        if self.on_write: self.on_write(Path(path), value, 'before')
        result = super().write(path, value)
        if self.on_write: self.on_write(Path(path), value, 'after')
        return result

    def mkdir(self, path):
        if self.on_mkdir: self.on_mkdir(Path(path), 'before')
        result = super().mkdir(path)
        if self.on_mkdir: self.on_mkdir(Path(path), 'after')
        return result

    def read_bytes(self, path, maximum):
        self.raw_reads.append((Path(path), maximum))
        with patch.object(P, 'os', ByteTransport()): result = P.NativeFiles.read_bytes(self, path, maximum)
        if self.on_raw: return self.on_raw(result)
        return result


class Authority(P.ParentStageAuthority):
    """Injected sole original-parent evidence; never native qualification."""
    def __init__(self):
        self.active = False; self.binding = None; self.request = None; self.checks = 0
        self.change = None; self.on_check = None; self.exit_failure = False

    @contextmanager
    def hold(self, request):
        C.require(not self.active); self.active = True; self.request = copy.deepcopy(request)
        self.binding = dict(scope='INSTALLER_PARENT_STAGE_ONLY', stage=P.STAGE, installationId=request['installationId'],
                            requestSha256=C.digest(request), parentSessionId=PARENT_SESSION_ID,
                            parentIntentSha256=C.digest({'synthetic-original-parent': INSTALLATION}), nativeAuthorized=False)
        if self.change: self.binding.update(self.change)
        try: yield copy.deepcopy(self.binding)
        finally:
            self.active = False
            if self.exit_failure: raise OSError('injected-parent-release-unknown')

    def check(self, request, evidence):
        self.checks += 1
        if self.on_check: self.on_check(self.checks)
        C.require(self.active and request == self.request and evidence == self.binding,
                  'Injected parent ownership was lost')


class Fixture:
    def __init__(self):
        self.placement = F.R.Fixture(); self.data = self.placement.data
        self.files = Files(); self.files.metadata.update(self.placement.files.metadata)
        self.placement.files = self.files; self.placement.events = self.files.events; self.placement.call()
        self.host = self.placement.directory / 'host'; self.host.mkdir()
        self.root = self.placement.directory / 'installation'; self.root.mkdir()
        self.backing = self.placement.directory / 'retained.luks'; self.backing.write_bytes(b'synthetic ciphertext')
        self.files.file_metadata[self.backing] = dict(st_size=32 * 1024**3)
        (self.host / 'storage.key').write_bytes(b'synthetic-unlock-material')
        self.clock = F.B.Clock(); self.locks = F.B.Locks(self.files)
        self.intent = dict(schemaVersion=1, scope=P.S.I.SCOPE, installation_id=INSTALLATION,
                           directory=C.directory_binding(self.files.protected(self.host, directory=True)),
                           proposal=dict(data_dir=str(self.data), install_root=str(self.root), storage_file=str(self.backing), capacity_gib=32))
        self.final = {key: self.intent['proposal'][key] for key in ('data_dir', 'install_root', 'storage_file')}
        self.final['installation_id'] = INSTALLATION
        self.receipt = dict(self.final, creation_stage='new-luks-created', luks_uuid=LUKS)
        self.config = dict(installation_id=INSTALLATION, private='synthetic-private-configuration')
        for path, value in ((self.host / P.S.I.INTENT, self.intent), (self.host / 'installation.json', self.final),
                            (self.host / 'installation.storage-receipt.json', self.receipt), (self.data / 'config/installation.json', self.config)):
            self.files.write(path, value)
        self.authority = Authority(); self.stage = self.data / 'config/runtime-pair-initialization'
        self.mounts = []; self.on_mount = None; self.quota_mounts = []; self.on_quota_mount = None
        self.files.events.clear(); self.files.reads.clear()

    def gate(self, *_): return C.Gate(self.data, files=self.files, locks=self.locks, clock=self.clock.time, sleep=self.clock.sleep)
    def allocation(self, *_): return A.Allocation(self.data, files=self.files, locks=self.locks, clock=self.clock.time, sleep=self.clock.sleep)
    def read(self, path): return Q.validate_state(self.files.read(path))
    def write(self, path, value): Q.validate_state(value); self.files.write(path, value)
    def rewrite(self, path, value): path.write_bytes(C.canonical(value) + b'\n')

    def mount(self, data, receipt, command):
        self.mounts.append(1)
        if self.on_mount: self.on_mount(len(self.mounts))
        return dict(target=str(data), luksUuid=receipt['luks_uuid'], source=SOURCE)

    def quota_mount(self, data, command):
        self.quota_mounts.append(1)
        if self.on_quota_mount: return self.on_quota_mount(len(self.quota_mounts))
        return SOURCE

    def call(self, *, only_storage=False, **options):
        transport = options.pop('transport', F.Transport(self.files)); self.transport = transport
        def fixture_path(value):
            C.require(type(value) is str and Path(value).is_absolute() and str(Path(value)) == value); return value
        def layout(data, files): return P.S.L.verify(data, files=files, build_mount=lambda _: dict(self.placement.mount))
        args = dict(host_directory=self.host, files=self.files, command=F.forbidden, mount=self.mount, layout=layout)
        if not only_storage:
            args.update(authority=self.authority, quota_mount=self.quota_mount, gate_factory=self.gate,
                        allocation_factory=self.allocation, read_state=self.read, write_state=self.write,
                        clock=self.clock.time, timeout=10)
        args.update(options)
        with patch.object(P.S.I, 'path_value', fixture_path), patch.object(P, 'os', transport), patch.object(P.S, 'os', transport), \
             patch.object(P.S.L, 'os', transport), patch.object(self.files, 'descriptor', transport.descriptor):
            if only_storage:
                with P.S.fresh_storage_context(self.data, self.root, **args) as proof: return proof
            return P.initialize(self.data, self.root, **args)

    def assert_closed(self, case):
        case.assertEqual(self.files.handles, {}); case.assertEqual(self.locks.held, {})
        case.assertEqual(self.transport.handles, {}); case.assertEqual(self.transport.real, {})
        case.assertEqual(sorted(self.transport.real_opened), sorted(self.transport.real_closed))
        case.assertFalse(self.authority.active)

    def assert_fresh(self, case):
        case.assertFalse(self.stage.exists()); case.assertEqual(list((self.data / 'quota').iterdir()), [])


class Controls(unittest.TestCase):
    def test_default_string_callable_and_borrowed_adapter_cannot_authorize(self):
        for authority in (None, OTHER, lambda _: {}, object()):
            f = Fixture()
            with self.subTest(authority=str(type(authority))), self.assertRaises(ValueError): f.call(authority=authority)
            f.assert_fresh(self)
        f = Fixture()
        with self.assertRaisesRegex(ValueError, 'not implemented'): f.call(authority=P.ParentStageAuthority())
        f.assert_fresh(self); f.assert_closed(self)

    def test_native_claim_and_wrong_parent_stage_request_uuid_or_schema_block(self):
        for change in ({'nativeAuthorized': True}, {'nativeAuthorized': 0}, {'stage': 'borrowed-stage'},
                       {'requestSha256': C.digest({'different': True})}, {'installationId': OTHER}, {'extra': 'unknown'}):
            f = Fixture(); f.authority.change = change
            with self.subTest(change=change), self.assertRaises(ValueError): f.call()
            f.assert_fresh(self); f.assert_closed(self)

    def test_readonly_fresh_storage_context_without_journal_or_secret_bytes(self):
        f = Fixture(); proof = f.call(only_storage=True)
        self.assertEqual(proof['scope'], 'FRESH_STORAGE_BINDING_ONLY'); self.assertFalse(proof['changed']); self.assertFalse(proof['backupReady'])
        self.assertNotIn('synthetic-private', json.dumps(proof)); f.assert_fresh(self)
        self.assertNotIn(f.backing, f.files.reads); self.assertNotIn(f.host / 'storage.key', f.files.reads)
        self.assertFalse(any(event[0] in ('write', 'mkdir', 'permission') for event in f.files.events)); f.assert_closed(self)

    def test_fresh_success_exact_records_hashes_single_admitted_initializer(self):
        f = Fixture(); result = f.call()
        self.assertEqual(set(result), {'scope', 'status', 'installationId', 'intentSha256', 'pairSha256', 'startupSha256', 'authorization', 'nativeAuthorized', 'backupReady'})
        self.assertEqual(result['scope'], P.SCOPE); self.assertEqual(result['status'], 'effects-confirmed')
        self.assertEqual(result['installationId'], INSTALLATION); self.assertFalse(result['nativeAuthorized']); self.assertFalse(result['backupReady'])
        self.assertEqual((f.data / 'quota/projects.json').read_bytes(), P.EMPTY_BYTES)
        self.assertEqual(f.files.read(f.stage / 'confirmed.json'), result)
        self.assertEqual(set(f.files.inventory(f.stage, 4)), {'intent.json', 'gate-confirmed.json', 'allocation-confirmed.json', 'confirmed.json'})
        self.assertEqual(len(f.files.inventory(f.gate().base / 'operations', 1)), 1); self.assertGreaterEqual(len(f.files.raw_reads), 2)
        f.assert_closed(self)

    def test_ciphertext_timestamp_changes_during_pair_writes_do_not_break_storage_guard(self):
        f=Fixture()
        def change(path,value,phase):
            if phase=='after':
                row=f.files.file_metadata[f.backing]
                row['st_mtime_ns']=row.get('st_mtime_ns',100)+1
                row['st_ctime_ns']=row.get('st_ctime_ns',100)+1
        f.files.on_write=change
        result=f.call()
        self.assertEqual(result['status'],'effects-confirmed');self.assertFalse(result['nativeAuthorized'])
        self.assertNotIn(f.backing,f.files.reads);f.assert_closed(self)

    def test_intent_durable_readback_precedes_first_gate_pair_effect(self):
        f = Fixture(); observed = []
        def before(path, phase):
            if path == f.gate().base and phase == 'before':
                intent = f.files.read(f.stage / 'intent.json'); observed.append(intent)
                self.assertEqual(intent['expectedProjectsRawSha256'], P.EMPTY_RAW_SHA256)
                self.assertTrue(f.authority.active); self.assertGreater(f.authority.checks, 1)
        f.files.on_mkdir = before; f.call(); self.assertEqual(len(observed), 1)

    def test_gate_inspection_ex_released_before_allocator_shared_admission(self):
        f = Fixture(); f.call(); rows = f.locks.events
        shared = next(i for i, row in enumerate(rows) if row == ('acquire', 'activity.lock', True))
        self.assertIn(('release', 'activity.lock', False), rows[:shared]); f.assert_closed(self)

    def test_each_existing_pair_projects_stage_and_extra_inventory_is_preserved(self):
        for kind in ('gate', 'allocation', 'projects', 'stage', 'extra', 'storage'):
            f = Fixture()
            target = {'gate': f.gate().base, 'allocation': f.allocation().base, 'projects': f.data / 'quota/projects.json',
                      'stage': f.stage, 'extra': f.data / 'quota/unknown.pending', 'storage': f.data / 'runtime/storage/retained'}[kind]
            if kind in ('gate', 'allocation', 'stage', 'storage'): target.mkdir()
            else: target.write_bytes(P.EMPTY_BYTES)
            before = target.stat().st_ino
            with self.subTest(kind=kind), self.assertRaises(ValueError): f.call()
            self.assertEqual(target.stat().st_ino, before); self.assertFalse((f.stage / 'intent.json').exists())
            f.assert_closed(self)

    def test_completed_pair_and_stage_refuse_fresh_rerun_without_writes(self):
        f = Fixture(); f.call(); before = {p.name: p.read_bytes() for p in f.stage.iterdir()}; f.files.events.clear()
        with self.assertRaises(ValueError): f.call()
        self.assertEqual(before, {p.name: p.read_bytes() for p in f.stage.iterdir()})
        self.assertFalse(any(row[0] in ('write', 'mkdir') for row in f.files.events)); f.assert_closed(self)

    def test_host_config_receipt_pending_and_layout_mismatch_before_pair_effects(self):
        for kind in ('host', 'config', 'receipt', 'pending', 'layout'):
            f = Fixture()
            if kind == 'host': f.rewrite(f.host / 'installation.json', dict(f.final, installation_id=OTHER))
            if kind == 'config': f.rewrite(f.data / 'config/installation.json', dict(f.config, installation_id=OTHER))
            if kind == 'receipt': f.rewrite(f.host / 'installation.storage-receipt.json', dict(f.receipt, creation_stage='unknown'))
            if kind == 'pending': f.rewrite(f.host / 'installation.pending.json', f.receipt)
            if kind == 'layout': f.placement.rewrite_evidence(schema=True)
            with self.subTest(kind=kind), self.assertRaises(ValueError): f.call()
            f.assert_fresh(self); f.assert_closed(self)

    def test_foreign_encrypted_mount_and_backing_capacity_before_pair_effects(self):
        f = Fixture()
        with self.assertRaises(ValueError): f.call(mount=lambda *_args, **_kwargs: {'source': None})
        f.assert_fresh(self); f.assert_closed(self)
        f = Fixture(); f.files.file_metadata[f.backing]['st_size'] = 1024
        with self.assertRaises(ValueError): f.call()
        f.assert_fresh(self); f.assert_closed(self)

    def test_stage_intent_before_and_after_write_failure_never_calls_gate(self):
        for phase in ('before', 'after'):
            f = Fixture()
            def fail(path, value, current):
                if path == f.stage / 'intent.json' and current == phase: raise OSError('injected-stage-intent-unknown')
            f.files.on_write = fail
            with self.subTest(phase=phase), self.assertRaises(OSError): f.call()
            self.assertTrue(f.stage.exists()); self.assertFalse(f.gate().base.exists())
            self.assertEqual((f.stage / 'intent.json').exists(), phase == 'after')
            f.files.on_write = None
            with self.assertRaises(ValueError): f.call()
            self.assertFalse(f.gate().base.exists()); f.assert_closed(self)

    def test_gate_partial_lock_and_state_failure_are_retained_and_never_reinitialized(self):
        for kind in ('lock', 'state'):
            f = Fixture()
            if kind == 'lock':
                create = f.files.create_lock
                def fail(path):
                    create(path)
                    if path.name == 'activity.lock': raise OSError('injected-created-lock-unknown')
                context = patch.object(f.files, 'create_lock', fail)
            else:
                def fail(path, value, phase):
                    if path == f.gate().base / 'state.json' and phase == 'after': raise OSError('injected-Gate-state-unknown')
                f.files.on_write = fail; context = patch.object(f.files, 'on_write', fail)
            with self.subTest(kind=kind), context, self.assertRaises(OSError): f.call()
            self.assertTrue(f.gate().base.exists()); self.assertFalse(f.allocation().base.exists()); f.files.on_write = None
            retained = (f.stage / 'intent.json').read_bytes()
            with self.assertRaises(ValueError): f.call()
            self.assertEqual((f.stage / 'intent.json').read_bytes(), retained); f.assert_closed(self)

    def test_allocator_partial_projects_and_lost_completion_keep_unknown_operation(self):
        for leaf in ('projects.json', 'completed.json'):
            f = Fixture()
            def fail(path, value, phase):
                if path.name == leaf and phase == 'after': raise OSError('injected-allocation-unknown')
            f.files.on_write = fail
            with self.subTest(leaf=leaf), self.assertRaises(OSError): f.call()
            self.assertTrue(f.allocation().base.exists()); self.assertTrue((f.data / 'quota/projects.json').exists())
            self.assertFalse((f.stage / 'allocation-confirmed.json').exists())
            if leaf == 'completed.json':
                run = next((f.gate().base / 'operations').iterdir()); self.assertTrue((run / 'uncertain.json').exists())
            f.files.on_write = None
            with self.assertRaises(ValueError): f.call()
            f.assert_closed(self)

    def test_parent_ownership_loss_before_gate_and_after_allocator_blocks_confirmation(self):
        for at in (2, 5):
            f = Fixture()
            def lose(count):
                if count == at: f.authority.active = False
            f.authority.on_check = lose
            with self.subTest(at=at), self.assertRaises(ValueError): f.call()
            self.assertFalse((f.stage / 'confirmed.json').exists())
            if at == 2: self.assertFalse(f.gate().base.exists())
            else: self.assertTrue(f.allocation().base.exists())
            f.assert_closed(self)

    def test_quota_source_change_blocks_allocator_after_gate_is_retained(self):
        f = Fixture(); f.on_quota_mount = lambda _: 'foreign-source'
        with self.assertRaises(ValueError): f.call()
        self.assertTrue(f.gate().base.exists()); self.assertFalse(f.allocation().base.exists())
        self.assertFalse((f.stage / 'confirmed.json').exists()); f.assert_closed(self)

    def test_consistently_rehashed_float_or_nonempty_state_reaches_independent_reader(self):
        for value in ({'nextProjectId': 10000.0, 'projects': {}}, {'nextProjectId': 10001, 'projects': {}}):
            f = Fixture(); initialize = f.allocation().initialize
            class Changed(A.Allocation):
                def initialize(self, installation_id, **kwargs):
                    initialize(installation_id, **kwargs)
                    f.rewrite(f.data / 'quota/projects.json', value)
                    pointer = f.files.read(f.allocation().base / 'state.json'); pointer.update(projectsSha256=C.digest(value), nextProjectId=value['nextProjectId'])
                    f.rewrite(f.allocation().base / 'state.json', pointer)
            def changed(*_): return Changed(f.data, files=f.files, locks=f.locks, clock=f.clock.time, sleep=f.clock.sleep)
            # Existing Q rejects before final confirmation, even with pointer
            # hashes consistent. Its own strict state checker is preserved.
            with self.subTest(value=value), self.assertRaises(ValueError): f.call(allocation_factory=changed)
            self.assertFalse((f.stage / 'confirmed.json').exists()); f.assert_closed(self)

    def test_raw_empty_state_hash_is_fixed_and_whitespace_or_byte_drift_rejected(self):
        f = Fixture(); f.files.on_raw = lambda raw: b' ' + raw[:-1]
        with self.assertRaisesRegex(ValueError, 'independently fixed'): f.call()
        self.assertFalse((f.stage / 'confirmed.json').exists()); self.assertEqual((f.data / 'quota/projects.json').read_bytes(), P.EMPTY_BYTES)
        f.assert_closed(self)

    def test_independent_projects_type_gate_rejects_lying_validated_callback(self):
        for value in ({'nextProjectId': 10000.0, 'projects': {}}, {'nextProjectId': 10000, 'projects': []}):
            f = Fixture()
            def alter(path, supplied, phase):
                if path == f.data / 'quota/projects.json' and phase == 'after': f.rewrite(path, value)
            f.files.on_write = alter
            # Q/Allocation receive valid typed EMPTY_STATE through an injected
            # callback; the new independent protected read sees actual bad
            # record bytes and must reject at its own exact type gate.
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'strict known empty state'):
                f.call(read_state=lambda _: copy.deepcopy(A.EMPTY_STATE))
            self.assertFalse((f.stage / 'allocation-confirmed.json').exists()); f.assert_closed(self)

    def test_raw_reader_caps_reject_oversize_and_close_actual_owned_file_fd(self):
        f = Fixture(); path = f.data / 'quota/synthetic-oversized'; path.write_bytes(P.EMPTY_BYTES + b'x')
        with self.assertRaises(ValueError): f.files.read_bytes(path, len(P.EMPTY_BYTES))
        path.write_bytes(P.EMPTY_BYTES)
        self.assertEqual(f.files.read_bytes(path, len(P.EMPTY_BYTES)), P.EMPTY_BYTES)
        with self.assertRaises(ValueError): f.files.read_bytes(path, True)

    def test_final_startup_unknown_operation_or_permanent_layout_replacement_blocks(self):
        for kind in ('operation', 'storage'):
            f = Fixture()
            def alter(path, value, phase):
                if path == f.stage / 'allocation-confirmed.json' and phase == 'after':
                    if kind == 'operation':
                        run = next((f.gate().base / 'operations').iterdir()); f.files.write(run / 'uncertain.json', dict(intentSha256=C.digest(f.files.read(run / 'intent.json')), stage='completion'))
                    else:
                        target = f.data / 'runtime/storage'; target.rename(target.with_name('retained-storage')); target.mkdir()
            f.files.on_write = alter
            with self.subTest(kind=kind), self.assertRaises(ValueError): f.call()
            self.assertFalse((f.stage / 'confirmed.json').exists()); f.assert_closed(self)

    def test_midcall_host_record_replacement_and_mount_change_never_confirm(self):
        for kind in ('host', 'mount'):
            f = Fixture()
            def alter(count):
                if count == 2 and kind == 'host':
                    path = f.host / 'installation.json'; path.rename(path.with_name('retained-installation.json')); f.files.write(path, f.final)
            f.on_mount = alter
            if kind == 'mount':
                original = f.mount
                def changing(*args, **kwargs):
                    result = original(*args, **kwargs)
                    if len(f.mounts) >= 3: result['source'] = 'changed'
                    return result
                options = {'mount': changing}
            else: options = {}
            with self.subTest(kind=kind), self.assertRaises(ValueError): f.call(**options)
            self.assertFalse((f.stage / 'confirmed.json').exists()); f.assert_closed(self)

    def test_stage_directory_replacement_or_intent_mutation_blocks_terminal(self):
        for kind in ('directory', 'intent'):
            f = Fixture()
            def alter(path, value, phase):
                if path == f.stage / 'gate-confirmed.json' and phase == 'after':
                    if kind == 'directory':
                        f.stage.rename(f.stage.with_name('retained-stage')); f.stage.mkdir()
                    else: f.rewrite(f.stage / 'intent.json', dict(f.files.read(f.stage / 'intent.json'), schemaVersion=True))
            f.files.on_write = alter
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)): f.call()
            self.assertFalse((f.stage / 'confirmed.json').exists()); f.assert_closed(self)

    def test_unknown_stage_leaf_or_modified_earlier_confirmation_blocks_later_effects(self):
        for kind in ('unknown', 'modified'):
            f = Fixture()
            def alter(path, value, phase):
                if path == f.stage / 'gate-confirmed.json' and phase == 'after':
                    if kind == 'unknown': (f.stage / 'unconfirmed.pending').write_bytes(b'retained-unknown')
                    else: f.rewrite(f.stage / 'intent.json', dict(f.files.read(f.stage / 'intent.json'), schemaVersion=1.0))
            f.files.on_write = alter
            with self.subTest(kind=kind), self.assertRaises(ValueError): f.call()
            self.assertFalse(f.allocation().base.exists()); self.assertFalse((f.stage / 'confirmed.json').exists())
            f.assert_closed(self)

    def test_confirmation_lost_ack_and_parent_exit_failure_never_allow_replay(self):
        for kind in ('confirmation', 'parent-exit'):
            f = Fixture()
            if kind == 'confirmation':
                def fail(path, value, phase):
                    if path == f.stage / 'confirmed.json' and phase == 'after': raise OSError('injected-final-ack-unknown')
                f.files.on_write = fail
            else: f.authority.exit_failure = True
            with self.subTest(kind=kind), self.assertRaises(OSError): f.call()
            self.assertTrue((f.stage / 'confirmed.json').exists())
            f.files.on_write = None; f.authority.exit_failure = False
            with self.assertRaises(ValueError): f.call()
            f.assert_closed(self)

    def test_owned_stage_record_open_or_close_failure_preserves_effects_and_denies_replay(self):
        for kind in ('open', 'close'):
            f = Fixture()
            class FailingTransport(F.Transport):
                def open(self, path, flags):
                    if Path(path) == f.stage / 'intent.json' and kind == 'open': raise OSError('injected-stage-record-open')
                    fd = super().open(path, flags)
                    if Path(path) == f.stage / 'intent.json' and kind == 'close': self.fail_close = fd
                    return fd
            transport = FailingTransport(f.files)
            with self.subTest(kind=kind), self.assertRaises(OSError): f.call(transport=transport)
            self.assertTrue((f.stage / 'intent.json').exists())
            self.assertEqual((f.stage / 'confirmed.json').exists(), kind == 'close')
            f.assert_closed(self)
            with self.assertRaises(ValueError): f.call()

    def test_cleanup_failure_does_not_replace_primary_stage_failure(self):
        f = Fixture()
        class FailingTransport(F.Transport):
            def open(self, path, flags):
                fd = super().open(path, flags)
                if Path(path) == f.stage / 'intent.json': self.fail_close = fd
                return fd
        def fail(path, value, phase):
            if path == f.stage / 'gate-confirmed.json' and phase == 'before': raise RuntimeError('retained-primary-stage-failure')
        f.files.on_write = fail
        with self.assertRaisesRegex(RuntimeError, 'retained-primary-stage-failure'): f.call(transport=FailingTransport(f.files))
        f.assert_closed(self)

    def test_finite_lock_budget_types_and_deadline_failure_preserve_pair(self):
        for timeout in (True, float('nan'), float('inf'), 0, 51):
            f = Fixture()
            with self.subTest(timeout=timeout), self.assertRaises(ValueError): f.call(timeout=timeout)
            f.assert_fresh(self)
        f = Fixture()
        def expire(path, value, phase):
            if path == f.stage / 'gate-confirmed.json' and phase == 'after': f.clock.now = 20
        f.files.on_write = expire
        with self.assertRaises(ValueError): f.call(timeout=10)
        self.assertFalse((f.stage / 'confirmed.json').exists()); f.assert_closed(self)

    def test_bash_session_success_keeps_exact_parent_binding_and_uuid_identity(self):
        f = Fixture(); result = f.call(); intent = f.files.read(f.stage / 'intent.json')
        self.assertEqual(f.authority.binding['parentSessionId'], PARENT_SESSION_ID)
        self.assertEqual(intent['parentSha256'], C.digest(f.authority.binding))
        self.assertEqual(result['installationId'], INSTALLATION)
        legacy = dict(f.authority.binding, parentSessionId=OTHER)
        self.assertNotEqual(intent['parentSha256'], C.digest(legacy))
        self.assertFalse(result['nativeAuthorized']); self.assertFalse(result['backupReady'])
        f.assert_closed(self)

    def test_uuid_and_malformed_parent_session_refuse_before_any_pair_effect(self):
        bad = (INSTALLATION, OTHER, '', 's-Abc123Def45', 's-Abc123Def456X', 'S-Abc123Def456',
               's-Abc123Def45/', 's-Abc123Def45é', 's-Abc123Def45_', 's-Abc123Def456\n',
               ' s-Abc123Def456', 's-Abc123Def456 ', None, True, 12, 12.0)
        for value in bad:
            f = Fixture(); f.authority.change = {'parentSessionId': value}
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'exact Bash installer session'): f.call()
            f.assert_fresh(self); f.assert_closed(self)
            self.assertFalse(any(row[0] in ('write', 'mkdir', 'permission') for row in f.files.events))
            self.assertEqual(f.authority.checks, 0)

    def test_parent_validation_requires_exact_str_before_authority_check(self):
        class Text(str): pass
        for value in (Text(PARENT_SESSION_ID), PARENT_SESSION_ID.encode(), None, False, 1, 1.0):
            authority = Authority(); request = {'stage': P.STAGE, 'installationId': INSTALLATION}
            with authority.hold(request) as evidence:
                evidence['parentSessionId'] = value
                with self.subTest(kind=type(value)), self.assertRaisesRegex(ValueError, 'exact Bash installer session'):
                    P._parent(authority, request, evidence)
                self.assertEqual(authority.checks, 0)
            self.assertFalse(authority.active)

    def test_session_pattern_matches_bash_and_pure_held_parent_argv_contract(self):
        name = 'runtime_pair_exact_parent_contract'
        spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/installer_parent.py')
        core = importlib.util.module_from_spec(spec); sys.modules[name] = core
        self.addCleanup(sys.modules.pop, name, None); spec.loader.exec_module(core)
        self.assertEqual(P.PARENT_SESSION.pattern, core.SESSION.pattern)
        shell = (ROOT / 'scripts/install-lock.sh').read_text(encoding='utf-8')
        self.assertEqual(shell.count('^s-[A-Za-z0-9]{12}$'), 2)
        self.assertIn('"$base/sessions/s-XXXXXXXXXXXX"', shell)
        args = ['42', '11', '12', PARENT_SESSION_ID, 'a' * 64, P.STAGE, 'b' * 64]
        with patch.object(core, 'NativeSystem', side_effect=AssertionError('No native authority constructor')):
            self.assertEqual(core.ParentInput.from_argv(args).session, PARENT_SESSION_ID)
            for value in (OTHER, 's-Abc123Def456X', 's-Abc123Def456\n', 's-Abc123Def45é'):
                self.assertIsNone(P.PARENT_SESSION.fullmatch(value))
                with self.subTest(value=value), self.assertRaises(core.ParentUnavailable):
                    core.ParentInput.from_argv(args[:3] + [value] + args[4:])

    def test_other_valid_session_cannot_replace_the_exact_live_parent_binding(self):
        f = Fixture(); original = []
        def change(count):
            if count == 1: original.append(copy.deepcopy(f.authority.binding))
            if count == 2: f.authority.binding['parentSessionId'] = 's-Zyx987Wvu654'
        f.authority.on_check = change
        with self.assertRaisesRegex(ValueError, 'ownership was lost'): f.call()
        self.assertEqual(f.files.read(f.stage / 'intent.json')['parentSha256'], C.digest(original[0]))
        self.assertFalse(f.gate().base.exists()); self.assertFalse((f.stage / 'confirmed.json').exists())
        retained = (f.stage / 'intent.json').read_bytes(); f.files.events.clear()
        with self.assertRaisesRegex(ValueError, 'Prior pair-stage'): f.call()
        self.assertEqual((f.stage / 'intent.json').read_bytes(), retained)
        self.assertFalse(any(row[0] in ('write', 'mkdir') for row in f.files.events)); f.assert_closed(self)

    def test_uuid_era_stage_hash_and_completion_are_retained_without_conversion(self):
        for completed in (False, True):
            f = Fixture(); proof = f.call(only_storage=True)
            request = dict(stage=P.STAGE, installationId=proof['installationId'], storageProofSha256=C.digest(proof),
                           dataRootSha256=proof['dataRootSha256'])
            legacy = dict(scope='INSTALLER_PARENT_STAGE_ONLY', stage=P.STAGE, installationId=INSTALLATION,
                          requestSha256=C.digest(request), parentSessionId=OTHER,
                          parentIntentSha256=C.digest({'synthetic-original-parent': INSTALLATION}), nativeAuthorized=False)
            f.files.mkdir(f.stage)
            intent = dict(schemaVersion=1, scope=P.SCOPE, installationId=INSTALLATION,
                          dataRootSha256=proof['dataRootSha256'], directory=C.directory_binding(f.files.protected(f.stage, directory=True, private=True)),
                          parentSha256=C.digest(legacy), requestSha256=C.digest(request), storageProofSha256=C.digest(proof),
                          absence=dict(quota=[], storage=[], pairAbsent=True, stageAbsent=True),
                          expectedProjectsSha256=P.EMPTY_STATE_SHA256, expectedProjectsRawSha256=P.EMPTY_RAW_SHA256)
            f.files.write(f.stage / 'intent.json', intent)
            if completed:
                f.files.write(f.stage / 'confirmed.json', dict(scope=P.SCOPE, status='effects-confirmed', installationId=INSTALLATION,
                              intentSha256=C.digest(intent), pairSha256=C.digest({'historical': True}), startupSha256=C.digest({'historical': True}),
                              authorization=P.QUALIFICATION, nativeAuthorized=False, backupReady=False))
            retained = {path.name: (path.stat().st_ino, path.read_bytes()) for path in f.stage.iterdir()}
            f.files.events.clear()
            with self.subTest(completed=completed), self.assertRaisesRegex(ValueError, 'Prior pair-stage'): f.call()
            self.assertEqual(retained, {path.name: (path.stat().st_ino, path.read_bytes()) for path in f.stage.iterdir()})
            self.assertFalse(f.gate().base.exists()); self.assertFalse(f.allocation().base.exists())
            self.assertFalse(any(row[0] in ('write', 'mkdir', 'permission') for row in f.files.events)); f.assert_closed(self)


if __name__ == '__main__': unittest.main(verbosity=2)
