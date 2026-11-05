"""Genuine original-V stage reissuance; injected IO/parent, no native installer."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import inspect
from pathlib import Path, PurePosixPath
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


S = load('company_stage_scope_controls', ROOT/'deploy/installer/company_stage_scope.py')
T = load('company_stage_scope_fresh_fixtures', ROOT/'tests/test_company_fresh_assembly.py')
PT = load('company_stage_scope_parent_fixtures', ROOT/'scripts/test-installer-parent.py')
BT = load('company_stage_scope_backend_fixtures', ROOT/'tests/test_company_source_guard_backend.py')
F, U = T.F, T.U


class Clock:
    def __init__(self): self.now = 10.0
    def __call__(self): return self.now


class StageScopeControls(unittest.TestCase):
    def setUp(self):
        self.assertFalse(S.UNRELEASED)
        self.f, self.clock = T.Fixture(), Clock()
        self.entry = self.coordinator = None

    def tearDown(self):
        # Explicit disposal of synthetic retained uncertainty only. Product has
        # no reset/reconciliation API and these retained raw controls stay intact.
        for row in S.UNRELEASED:
            if row[1] == 'outer-guard-or-assembly-still-live':
                cm, held = row[2], row[3]
                guards = row[5] if type(row[5]) is list else getattr(row[4], '_guards', [])
                for guard in guards if type(guards) is list else []:
                    if not guard._closed: guard._close()
                V = row[0]._V
                V.UNRELEASED_HANDLES.clear()
                if held.active:
                    try: cm.__exit__(None, None, None)
                    except ValueError: pass
        if self.f.q is not None:
            self.f.q.files.fail_close = None
            for fd in list(self.f.q.files.records) + list(self.f.q.files.dirs):
                self.f.q.files.close(fd)
        self.f.clean()
        S.UNRELEASED.clear()
        self.assertFalse(S._COORDINATORS)
        self.assertFalse(S._SCOPES)
        F.UNRELEASED.clear()

    @contextmanager
    def configured(self, **changes):
        # Test-only fixed logical->retained Windows fixture translation. Install
        # it while the original trusted entry captures its initial globals. The
        # saved original V factory still performs real original issuance, crypto
        # ordering, held file bytes/FDs and full-nine rechecks. Shipped coordinator
        # has no translator/callback seam and keeps its strict /opt root schema.
        mappings, self.source_calls, self.native_calls = {}, [], []
        original_F_register = F._register
        def register_F(path, *a, **kw):
            module = original_F_register(path, *a, **kw)
            if path == F.LOADER:
                original_L_register = module._register
                def register_L(member, *args, **kwargs):
                    captured = original_L_register(member, *args, **kwargs)
                    if member == F.VERIFIER:
                        original_source = captured.authenticated_platform_source
                        def source(directory, public_key, fingerprint, **options):
                            logical = (directory, public_key, options['source_root'])
                            assert logical == tuple(mappings)
                            self.source_calls.append(logical)
                            return original_source(mappings[directory], mappings[public_key], fingerprint,
                                **dict(options, source_root=mappings[options['source_root']]))
                        def native(*args, **kwargs):
                            self.native_calls.append((args, kwargs))
                            raise AssertionError('native fallback forbidden')
                        captured.authenticated_platform_source = source
                        captured.NativeFiles = captured.NativeCrypto = native
                    return captured
                module._register = register_L
            return module
        with patch.object(F, '_register', side_effect=register_F), self.f.entry() as entry:
            self.entry = entry
            V = entry.modules[F.VERIFIER]
            q = self.f.q = U.Q.Fixture(V, U.P)
            q.values.update(self.f.raw); q.modes.update({path: '100644' for path in self.f.raw})
            q.refresh_platform()
            # Fixture-only quiet external ancestry; actual source/bundle/key
            # bytes and FDs retain the original V full-nine/readback checks.
            for path in q.root.parents:
                q.files.changes.setdefault(path, {}).update(st_mtime_ns=101, st_ctime_ns=202, st_size=0)
            self.request = dict(schemaVersion=1, mode='full-installation', operationId='b'*32,
                releaseSha256=S.sha((q.bundle/'release.json').read_bytes()),
                bundleRoot='/opt/autosoft-company/incoming/release',
                sourceRoot='/opt/autosoft-company/incoming/source', keyPath='/opt/autosoft-company/bootstrap/company.pem',
                dataDir='/srv/stage-scope', backingFile='/srv/stage-scope.luks', capacityGiB=128,
                runscVersion='20261005.0', runscSha512='c'*128)
            mappings.update({self.request['bundleRoot']: q.bundle, self.request['keyPath']: q.public,
                             self.request['sourceRoot']: q.sources})
            raw = S.canonical(self.request)
            args = dict(full_entry_module=F, request_raw=raw, request_sha256=S.sha(raw),
                operational_catalog=self.f.catalog, key_fingerprint=q.fingerprint,
                expected_architecture='amd64', files=q.files, crypto=q.crypto,
                stages=S.STAGES[:2], clock=self.clock, timeout=100)
            args.update(changes)
            yield entry, args

    def start(self, entry, args):
        return S.stage_coordinator(entry, **args)

    def reject(self, call):
        with self.assertRaises((ValueError, TypeError)):
            call()

    @contextmanager
    def physical_guard(self, entry, held):
        # Original BK class with explicit synthetic Linux OS/libc/getdents refs.
        # No native constructors or ctypes library are opened by this fixture.
        ram = self.f.backend = U.ReadOnlySourceBackend()
        root = '/data/company/source-releases/'+held.metadata['releaseSha256']+'/source'
        ram.build(root, dict(held.files))
        class OS:
            name='posix'; O_RDONLY,O_NOFOLLOW,O_CLOEXEC,O_DIRECTORY,O_NONBLOCK=0,1,2,4,8
            def __init__(self): self.supports_dir_fd={self.open}
            def open(self, path, flags, dir_fd=None): return ram.open(dir_fd, path, bool(flags & self.O_DIRECTORY))
            def lstat(self, path): return SimpleNamespace(**ram.lstat(path))
            def fstat(self, fd): return SimpleNamespace(**ram.fstat(fd))
            def get_inheritable(self, fd): return ram.inheritable(fd)
            def pread(self, fd, count, offset): return ram.pread(fd, count, offset)
            def close(self, fd): return ram.close(fd)
        class Libc(BT.Libc):
            def syscall(self, number, fd, buffer, size):
                self.calls.append((number, fd, size))
                if fd not in self.cursor:
                    self.cursor[fd]=True
                    raw=b''.join(BT.record(name) for name in ('.','..',*ram.names(fd,2049)))
                else: raw=b''
                assert len(raw)<=size
                buffer.raw=raw+b'\0'*(size-len(raw))
                return len(raw)
        BK, G, V = (entry.modules[path] for path in (F.BACKEND,F.GUARD,F.VERIFIER))
        libc=Libc(); ctypes=BT.Ctypes(libc); system=SimpleNamespace(platform='linux',byteorder='little')
        dents=BK.LinuxAMD64Getdents64(ctypes_module=ctypes,libc=libc,sys_module=system,
                                    machine_module=SimpleNamespace(machine=lambda:'x86_64'))
        backend=self.physical_backend=BK.ReadOnlySourceBackend(os_module=OS(),sys_module=system,getdents64=dents)
        with G.hold_authenticated_company_source(held,verifier_module=V,source_root=root,
                expected_device=7,backend_module=BK,backend=backend,clock=U.Clock()) as guard:
            yield guard
        backend.require_released()

    def test_two_real_sources_and_assemblies_reissue_original_v_and_parent(self):
        with self.configured() as (entry, args), self.start(entry, args) as c:
            old_sources, old_assemblies, bootstraps = [], [], []
            V, P = entry.modules[F.VERIFIER], entry.modules[F.PARENT]
            for stage in S.STAGES[:2]:
                with c.source_stage(stage) as scope:
                    self.assertIs(V.require_platform_source(scope.source), scope.source)
                    with scope.assembly() as assembly:
                        self.assertIs(assembly._source, scope.source)
                        self.assertIs(assembly.modules[F.VERIFIER], V)
                        self.assertIs(assembly.modules[F.PARENT], P)
                        bootstraps.append(assembly.modules['scripts/bootstrap.py'])
                        old_sources.append(scope.source); old_assemblies.append(assembly)
                    with self.assertRaises(ValueError): scope.closed_observation
                observation = scope.closed_observation
                self.assertTrue(observation['ownedSourceAssemblyClosed'])
                for name in ('parentStorageBackendReleaseConfirmed', 'effectsConfirmed', 'stageAcknowledged', 'nativeAuthorized'):
                    self.assertIs(observation[name], False)
                self.assertFalse(V._ISSUED_PLATFORM_SOURCES)
                self.assertFalse(self.f.q.files.records); self.assertFalse(self.f.q.files.dirs)
            self.assertIsNot(old_sources[0], old_sources[1])
            self.assertIsNot(old_assemblies[0], old_assemblies[1])
            self.assertIsNot(bootstraps[0].SeedStorage, bootstraps[1].SeedStorage)
            self.assertTrue(all(not held.active for held in old_sources))
            self.assertIs(entry.recheck(), entry)

    def test_original_parent_record_progresses_only_after_source_and_assembly_close(self):
        with self.configured() as (entry, args), self.start(entry, args) as c:
            P = entry.modules[F.PARENT]
            parent_args = P.ParentInput(42, 11, 12, 's-Abc123Def456', args['request_sha256'], S.STAGES[0], 'b'*64)
            with patch.object(PT, 'P', P), patch.object(PT, 'ARGS', parent_args):
                system = PT.FakeSystem(); root = P.BASE+'/sessions/'+parent_args.session
                first = c.source_stage(S.STAGES[0])
                with first as scope:
                    with scope.assembly() as assembly, P.hold_parent(parent_args, system=system) as parent:
                        self.assertIs(type(parent), assembly.modules[F.PARENT].HeldParent)
                        parent.check()
                    self.assertFalse(system.descriptors)
                    with self.assertRaises(ValueError): scope.closed_observation
                observed = scope.closed_observation
                self.assertFalse(self.f.q.files.records); self.assertFalse(self.f.q.files.dirs)
                system.add(root+'/'+S.STAGES[0]+'.confirmed', PT.encoded('install-stage-confirmed-v1',
                    session=parent_args.session, stage=S.STAGES[0], action=parent_args.action,
                    outcome=S.sha(S.canonical(dict(observed))), independently_confirmed='true'))
                system.add(root+'/'+S.STAGES[1]+'.intent', system.stage(S.STAGES[1], 'c'*64))
                next_args = P.ParentInput(42, 11, 12, parent_args.session, parent_args.request, S.STAGES[1], 'c'*64)
                with c.source_stage(S.STAGES[1]) as second, second.assembly() as assembly:
                    with P.hold_parent(next_args, system=system) as parent:
                        self.assertIn(root+'/'+S.STAGES[0]+'.confirmed', parent.files)
                        self.assertIs(assembly.modules[F.PARENT], P)
                self.assertFalse(system.descriptors)
                self.assertIs(second.closed_observation['effectsConfirmed'], False)

    def test_falsey_adapters_refuse_before_native_or_source_io(self):
        class Falsey:
            def __bool__(self): return False
        with self.configured() as (entry, args):
            V = entry.modules[F.VERIFIER]
            for name in ('files', 'crypto'):
                for value in (None, False, 0, Falsey()):
                    changed = dict(args, **{name: value})
                    self.reject(lambda: self.start(entry, changed).__enter__())
            self.assertEqual(self.native_calls, [])
            self.assertFalse(self.f.q.files.events)

    def test_unissued_and_subclass_coordinators_refuse_without_source_callback(self):
        calls = []
        class Fake(S.StageCoordinator):
            def recheck(self): calls.append('callback')
        for c in (S.StageCoordinator(), Fake()):
            self.reject(lambda: S.StageCoordinator.recheck(c))
            with self.assertRaises(ValueError):
                with S.StageCoordinator.source_stage(c, S.STAGES[0]): self.fail('issued')
        self.assertEqual(calls, [])

    def test_exact_request_hash_schema_canonical_and_root_types(self):
        with self.configured() as (entry, args):
            for mutate in (lambda v: v.update(schemaVersion=True), lambda v: v.update(capacityGiB=True),
                           lambda v: v.update(bundleRoot='relative'), lambda v: v.update(keyPath='/'),
                           lambda v: v.update(operationId='A'*32), lambda v: v.update(extra=True)):
                value = dict(self.request); mutate(value); raw = S.canonical(value)
                self.reject(lambda: self.start(entry, dict(args, request_raw=raw, request_sha256=S.sha(raw))).__enter__())
            for raw, expected in ((args['request_raw'], '0'*64), (args['request_raw']+b' ', args['request_sha256']),
                                  (b'['*2000+b']'*2000, '0'*64)):
                self.reject(lambda: self.start(entry, dict(args, request_raw=raw, request_sha256=expected)).__enter__())
            self.assertFalse(self.f.q.files.events)

    def test_catalog_and_fingerprint_are_independent_detached_strict_inputs(self):
        with self.configured() as (entry, args):
            for change in (dict(key_fingerprint='0'*64), dict(operational_catalog={})):
                self.reject(lambda: self.start(entry, dict(args, **change)).__enter__())
            bad = copy.deepcopy(self.f.catalog); bad[next(iter(bad))]['bytes'] = True
            self.reject(lambda: self.start(entry, dict(args, operational_catalog=bad)).__enter__())
            with self.start(entry, args) as c:
                args['operational_catalog'][next(iter(self.f.catalog))]['sha256'] = '0'*64
                self.assertIs(c.recheck(), c)

    def test_ordered_subsequence_only_and_unsupported_architecture_refuse(self):
        with self.configured() as (entry, args):
            for stages in ((S.STAGES[1], S.STAGES[0]), (S.STAGES[0], S.STAGES[0]), (), ['company-platform-store'], ('other',)):
                self.reject(lambda: self.start(entry, dict(args, stages=stages)).__enter__())
            self.reject(lambda: self.start(entry, dict(args, expected_architecture='arm64')).__enter__())
            with self.start(entry, dict(args, stages=(S.STAGES[0], S.STAGES[2]))) as c:
                with c.source_stage(S.STAGES[0]): pass
                with c.source_stage(S.STAGES[2]): pass

    def test_malformed_clock_and_late_falsey_adapter_deny_before_source(self):
        with self.configured() as (entry, args):
            for value in (True, float('inf'), float('nan'), -1):
                self.reject(lambda: self.start(entry, dict(args, clock=lambda: value)).__enter__())
            class Files:
                active = True
                def __bool__(self): return self.active
            files=Files()
            with self.assertRaises(ValueError), self.start(entry, dict(args, files=files)) as c:
                files.active=False
                with self.assertRaises(ValueError):
                    with c.source_stage(S.STAGES[0]): self.fail('native fallback')
            self.assertEqual(self.native_calls, [])
            self.assertEqual(self.source_calls, [])

    def test_overlap_consumes_and_expires_without_second_source_open(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            with c.source_stage(S.STAGES[0]) as scope:
                before = len(self.f.q.crypto.calls)
                with self.assertRaises(ValueError):
                    with c.source_stage(S.STAGES[1]): self.fail('overlap')
                self.assertEqual(len(self.f.q.crypto.calls), before)
                self.assertFalse(c._active)

    def test_replay_or_out_of_order_refusal_does_not_reopen_source(self):
        for replay in (False, True):
            self.f = T.Fixture()
            with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
                if replay:
                    with c.source_stage(S.STAGES[0]): pass
                before = len(self.f.q.crypto.calls)
                with self.assertRaises(ValueError):
                    with c.source_stage(S.STAGES[0] if replay else S.STAGES[1]): self.fail('replay/order')
                self.assertEqual(len(self.f.q.crypto.calls), before)

    def test_changed_release_denied_before_any_operational_compile(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            self.f.q.release['version'] = 'changed'; self.f.q.write_release(self.f.q.release)
            L = entry.modules[F.LOADER]
            with patch.object(L, '_register', side_effect=AssertionError('operational compile')):
                with self.assertRaises(ValueError):
                    with c.source_stage(S.STAGES[0]): self.fail('wrong release')

    def test_deadline_and_stale_source_refuse_then_close(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            with c.source_stage(S.STAGES[0]) as scope:
                held = scope.source; self.clock.now = 111
                with self.assertRaises(ValueError): scope.source
            self.assertFalse(held.active)

    def test_expired_entry_before_stage_opens_no_source(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            entry._expire()
            before = len(self.f.q.files.events)
            with self.assertRaises(ValueError):
                with c.source_stage(S.STAGES[0]): self.fail('expired entry')
            self.assertEqual(len(self.f.q.files.events), before)

    def test_caught_body_failure_has_no_closed_observation(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            with self.assertRaises(RuntimeError):
                with c.source_stage(S.STAGES[0]) as scope:
                    raise RuntimeError('trusted stage failed')
            with self.assertRaises(ValueError): scope.closed_observation
            self.assertFalse(self.f.q.files.records); self.assertFalse(self.f.q.files.dirs)

    def test_only_one_assembly_per_stage_and_caught_failure_expires(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            with c.source_stage(S.STAGES[0]) as scope:
                with scope.assembly(): pass
                with self.assertRaises(ValueError):
                    with scope.assembly(): self.fail('second assembly')
                self.assertFalse(c._active)

    def test_bound_original_guard_outlives_assembly_then_known_closes_before_source(self):
        with self.configured() as (entry, args), self.start(entry, args) as c:
            with c.source_stage(S.STAGES[0]) as scope:
                with self.physical_guard(entry, scope.source) as guard:
                    with scope.assembly() as assembly:
                        assembly.bind_source_guard(guard)
                        self.assertTrue(guard.active)
                    self.assertTrue(guard.active)
                    self.assertFalse(assembly._active)
                self.assertTrue(guard._closed); self.assertFalse(guard._owned)
            self.assertTrue(scope.closed_observation['ownedSourceAssemblyClosed'])

    def test_expired_but_owned_guard_retains_source_instead_of_premature_close(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            source_cm = c.source_stage(S.STAGES[0]); scope = source_cm.__enter__()
            guard_cm = self.physical_guard(entry, scope.source); guard = guard_cm.__enter__()
            with scope.assembly() as assembly: assembly.bind_source_guard(guard)
            guard._expire()
            self.assertFalse(guard.active); self.assertFalse(guard._closed); self.assertTrue(guard._owned)
            with self.assertRaises(ValueError): source_cm.__exit__(None, None, None)
            self.assertTrue(scope._held.active)
            self.assertTrue(self.f.q.files.records)
            self.assertTrue(any(row[1] == 'outer-guard-or-assembly-still-live' and row[3] is scope._held for row in S.UNRELEASED))
            with self.assertRaises(ValueError): scope.closed_observation
            # Complete only synthetic test disposal after the product retained.
            with self.assertRaises(ValueError): guard_cm.__exit__(None, None, None)

    def test_guard_unknown_close_retains_exact_source_context(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            source_cm = c.source_stage(S.STAGES[0]); scope = source_cm.__enter__()
            guard_cm = self.physical_guard(entry, scope.source); guard = guard_cm.__enter__()
            with scope.assembly() as assembly: assembly.bind_source_guard(guard)
            self.f.backend.fail_close = guard._owned[-1]
            with self.assertRaises(ValueError): guard_cm.__exit__(None, None, None)
            self.assertTrue(guard._closed); self.assertFalse(guard._owned)
            with self.assertRaises(ValueError): source_cm.__exit__(None, None, None)
            self.assertTrue(scope._held.active)
            self.assertTrue(S.UNRELEASED)
            self.f.backend.fail_close = None
            # Synthetic guard failure remains latched in original G until this
            # test's disposal; it cannot produce a coordinator observation.
            c._G.UNRELEASED_HANDLES.clear(); c._BK.UNRELEASED_RESOURCES.clear()
            self.f.backend.handles.clear()
            self.physical_backend._owned.clear(); self.physical_backend._close_attempted.clear()

    def test_actual_source_close_failure_latches_exact_original_handles(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            with self.assertRaises(ValueError):
                with c.source_stage(S.STAGES[0]) as scope:
                    self.f.q.files.fail_close = self.f.q.public
            self.assertFalse(scope._held.active)
            self.assertTrue(any(row[1] == 'source-close-unknown' and row[3] is scope._held for row in S.UNRELEASED))
            with self.assertRaises(ValueError): scope.closed_observation

    def test_source_acquisition_close_unknown_latches_manager_before_any_yield(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            self.f.q.crypto.accept=False; self.f.q.files.fail_close=self.f.q.public
            with self.assertRaises(ValueError):
                with c.source_stage(S.STAGES[0]): self.fail('yielded unauthenticated source')
            self.assertTrue(any(row[1]=='source-acquisition-release-unknown' and row[4] is c._V
                                for row in S.UNRELEASED))
            self.assertFalse(S._SCOPES)

    def test_closed_guard_foreign_backend_or_source_refuses_without_foreign_callback(self):
        for changed in ('backend','source'):
            self.f=T.Fixture()
            with self.assertRaises(ValueError), self.configured() as (entry,args), self.start(entry,args) as c:
                source_cm=c.source_stage(S.STAGES[0]);scope=source_cm.__enter__()
                with self.physical_guard(entry,scope.source) as guard:
                    with scope.assembly() as assembly:assembly.bind_source_guard(guard)
                original_backend,original_source=guard._backend,guard._source
                calls=[]
                if changed=='backend':guard._backend=SimpleNamespace(require_released=lambda:calls.append('foreign'))
                else:guard._source=object()
                with self.assertRaises(ValueError):source_cm.__exit__(None,None,None)
                self.assertTrue(scope._held.active);self.assertEqual(calls,[])
                guard._backend,guard._source=original_backend,original_source
            # Dispose this iteration's retained synthetic HPS before a new one.
            for row in S.UNRELEASED:
                if row[1]=='outer-guard-or-assembly-still-live':row[2].__exit__(None,None,None)
            S.UNRELEASED.clear();F.UNRELEASED.clear();self.f.clean()

    def test_module_release_unknown_preserves_exact_assembly_and_denies_observation(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            with self.assertRaises(ValueError):
                with c.source_stage(S.STAGES[0]) as scope:
                    with scope.assembly() as assembly:
                        original = assembly.modules['scripts/bootstrap.py']
                        sys.modules[original.__name__] = SimpleNamespace(foreign='kept')
            self.assertTrue(any(row[1] == 'assembly-close-unknown' and row[3] is assembly for row in S.UNRELEASED))
            self.assertEqual(sys.modules[original.__name__].foreign, 'kept')
            with self.assertRaises(ValueError): scope.closed_observation

    def test_statechanging_adapter_bool_cannot_select_original_v_native_fallback(self):
        class Adapter:
            def __init__(self, target): self.target, self.verifier_bools = target, 0
            def __getattr__(self, name): return getattr(self.target, name)
            def __bool__(self):
                frame = inspect.currentframe().f_back
                try:
                    if frame.f_code.co_name == 'authenticated_platform_source':
                        self.verifier_bools += 1
                        return False
                    return True
                finally: del frame
        with self.configured() as (entry, args):
            files, crypto = Adapter(args['files']), Adapter(args['crypto'])
            with self.start(entry, dict(args, files=files, crypto=crypto)) as c:
                with c.source_stage(S.STAGES[0]) as scope:
                    self.assertIs(c._V.require_platform_source(scope.source), scope.source)
                self.assertTrue(scope.closed_observation['ownedSourceAssemblyClosed'])
            self.assertEqual((files.verifier_bools, crypto.verifier_bools), (0, 0))
            self.assertEqual(self.native_calls, [])
            self.assertTrue(self.f.q.files.events); self.assertTrue(self.f.q.crypto.calls)

    def test_incomplete_explicit_adapter_protocol_denies_before_source_io(self):
        with self.configured() as (entry, args):
            for name in ('files', 'crypto'):
                with self.assertRaises((ValueError, AttributeError)), self.start(entry, dict(args, **{name: object()})) as c:
                    with c.source_stage(S.STAGES[0]): self.fail('incomplete adapter')
            self.assertEqual(self.native_calls, []); self.assertEqual(self.source_calls, [])
            self.assertFalse(self.f.q.files.events)

    def test_missing_original_guard_identity_retains_exact_source_without_callback(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            source_cm=c.source_stage(S.STAGES[0]); scope=source_cm.__enter__()
            with self.physical_guard(entry, scope.source) as guard:
                with scope.assembly() as assembly: assembly.bind_source_guard(guard)
            verifier=guard._verifier; del guard._verifier
            try:
                self.assertIs(S._guard_closed(c, guard, scope._held), False)
                with self.assertRaises(ValueError): source_cm.__exit__(None, None, None)
                self.assertTrue(scope._held.active); self.assertTrue(self.f.q.files.records)
                row=S.UNRELEASED[-1]
                self.assertIs(row[3], scope._held); self.assertIs(row[5][0], guard)
                with self.assertRaises(ValueError): scope.closed_observation
            finally: guard._verifier=verifier

    def test_opaque_guard_inventory_is_retained_without_iteration_or_source_close(self):
        calls=[]
        class Opaque:
            def __iter__(self): calls.append('iteration'); raise RuntimeError('foreign iterator')
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            source_cm=c.source_stage(S.STAGES[0]); scope=source_cm.__enter__()
            inventory=Opaque(); scope._guards=inventory
            with self.assertRaises(ValueError): source_cm.__exit__(None, None, None)
            row=S.UNRELEASED[-1]
            self.assertIs(row[5], inventory); self.assertIs(row[3], scope._held)
            self.assertTrue(scope._held.active); self.assertEqual(calls, [])
            with self.assertRaises(ValueError): scope.closed_observation
            scope._guards=[] # Synthetic disposal only, after exact retention proved.

    def test_missing_assembly_guard_retains_assembly_then_source_until_disposal(self):
        with self.assertRaises(ValueError), self.configured() as (entry, args), self.start(entry, args) as c:
            source_cm=c.source_stage(S.STAGES[0]); scope=source_cm.__enter__()
            assembly_cm=scope.assembly(); assembly=assembly_cm.__enter__()
            saved=assembly._guard; del assembly._guard
            with self.assertRaises((ValueError, AttributeError)): assembly_cm.__exit__(None, None, None)
            row=next(row for row in S.UNRELEASED if row[1]=='assembly-close-unknown')
            self.assertIs(row[3], assembly); self.assertIs(row[4], scope._held)
            with self.assertRaises(ValueError): source_cm.__exit__(None, None, None)
            self.assertTrue(scope._held.active); self.assertTrue(self.f.q.files.records)
            with self.assertRaises(ValueError): scope.closed_observation
            assembly._guard=saved
            # Known closure of the retained synthetic original assembly precedes
            # the tearDown disposal of its original source, never a product reset.
            with self.assertRaises(ValueError): row[2].__exit__(None, None, None)
            scope._assembly_live=None


if __name__ == '__main__':
    unittest.main(verbosity=2)
