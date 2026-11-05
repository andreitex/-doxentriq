"""Injected real-parent/shared-session controls; no native Git or installer.

The genuine verifier issues source capabilities with protected fake crypto/IO.
Actual installer_parent.acquire/check runs against its existing fake System.
Parent confirmation here is a separately verified fixture operation after known
owned and outer context closure, never a consequence of child exit status.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
GLOBAL = hashlib.sha256(b'fixed independently planned complete installation').hexdigest()
OTHER = hashlib.sha256(b'different complete installation').hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


S = load('session_store_fixtures', ROOT / 'tests/test_company_platform_store.py')
Q = load('session_schema4_fixtures', ROOT / 'tests/test_company_release_schema4.py')
PT = load('session_actual_parent_fixtures', ROOT / 'scripts/test-installer-parent.py')
M, T, B, P = S.M, S.T, S.T.B, PT.P


class Session:
    """Actual P context; only original-parent fixture creates stage records."""
    def __init__(self, request=GLOBAL):
        self.system = PT.FakeSystem()
        self.request = request
        self.path = P.BASE + '/sessions/' + PT.ARGS.session
        old = self.path + '/' + PT.ARGS.stage + '.intent'
        self.system.bodies.pop(self.system.metas.pop(old).st_ino)
        self.system.add(self.path + '/intent', PT.encoded('install-session-v1',
            session=PT.ARGS.session, request=request,
            binding=hashlib.sha256(self.system.bodies[self.system.metas[P.BASE + '/binding'].st_ino]).hexdigest(),
            directory=PT.shell(self.system.metas[self.path], True), closed='true'))
    def prepare(self, stage, action):
        if self.system.descriptors:
            raise AssertionError('original parent cannot append during held worker')
        self.system.add(self.path + '/' + stage + '.intent', self.system.stage(stage, action))
        return P.ParentInput(PT.ARGS.parent_pid, PT.ARGS.directory_fd, PT.ARGS.lock_fd,
                             PT.ARGS.session, self.request, stage, action)
    @contextmanager
    def hold(self, arguments):
        with P.hold_parent(arguments, system=self.system) as parent:
            assert type(parent) is P.HeldParent
            yield parent
        assert not self.system.descriptors
    def confirm_store(self, fixture, result):
        # This is a trusted original-parent fixture operation, deliberately
        # separate from the writer. No confirmation during any held context.
        if self.system.descriptors or fixture.t.backend.handles or fixture.t.storage.active:
            raise AssertionError('outer authority not released')
        if fixture.V._ISSUED_PLATFORM_SOURCES or fixture.q.files.records or fixture.q.files.dirs:
            raise AssertionError('source authority not released')
        raw = fixture.t.backend.nodes[result['root'] + '/intent.json']['raw']
        intent = json.loads(raw)
        originals = fixture.records
        names = {p[len(result['root']) + 1:] for p in fixture.t.backend.nodes
                 if p.startswith(result['root'] + '/')}
        assert names == {'intent.json', 'verified.json', *originals}
        assert stat.S_IMODE(fixture.t.backend.nodes[result['root']]['info']['st_mode']) == 0o500
        for name, expected in originals.items():
            node = fixture.t.backend.nodes[result['root'] + '/' + name]
            assert node['raw'] == expected and stat.S_IMODE(node['info']['st_mode']) == 0o400
        verified = json.loads(fixture.t.backend.nodes[result['root'] + '/verified.json']['raw'])
        assert result == dict(verified, root=result['root'], ownedStoreHandlesReleased=True,
                             outerSourceParentStorageContextsRequireClosure=True, executionAuthorized=False)
        assert intent['request']['installationRequestSha256'] == self.request
        assert intent['requestSha256'] == M.digest(M.canonical(intent['request']))
        self.system.add(self.path + '/company-platform-store.confirmed',
            PT.encoded('install-stage-confirmed-v1', session=PT.ARGS.session,
                       stage='company-platform-store', action=intent['actionSha256'],
                       outcome=M.digest(M.canonical(result)), independently_confirmed='true'))


class Fixture:
    def __init__(self):
        self.s = S.Fixture()
        self.t = self.s.f
        self.V = Q.load('session_verifier_' + str(id(self)), ROOT / 'scripts/verify-release.py')
        self.platform = Q.load('session_platform_' + str(id(self)), ROOT / 'scripts/platform_source.py')
        self.q = Q.Fixture(self.V, self.platform)
        self.q.values[M.MODULE_PATH] = (ROOT / M.MODULE_PATH).read_bytes()
        self.q.modes[M.MODULE_PATH] = '100644'
        self.q.refresh_platform()
        self.records = None
        # The Store fixture replaces its SeedFiles after preparation. Rebind
        # SeedGit to those same live files before any seed operation as well.
        self.reopen()
        # Before any authority capture, simulate the required quiet external
        # ancestors in the existing protected fake filesystem. Concurrent host
        # evidence writes must not change this synthetic namespace. The owned
        # fixture root and all source/artifact bytes still use real readback;
        # production full-nine input guards are unchanged and never refreshed.
        for ancestor in self.q.root.parents:
            self.q.files.frozen[ancestor] = self.q.files.lstat(ancestor)
    def reopen(self, *, fresh=True):
        self.t.files.close()
        self.t.storage.active = False
        self.t.files = B.SeedFiles(SimpleNamespace(SeedBackend=T.SeedBackend), self.t.backend)
        self.t.storage = B.SeedStorage(self.t.DATA, self.t.INSTALL, startup_module=self.t.S,
                                     files=self.t.files, commands=self.t.commands, fresh=fresh)
        raw = self.t.backend.nodes['/usr/bin/git']['raw']
        self.t.git = B.SeedGit(self.t.files, self.t.commands,
                              dict(path='/usr/bin/git', bytes=len(raw), sha256=M.digest(raw)))
    def close_storage(self):
        self.t.files.close()
        self.t.storage.active = False
    def close(self):
        self.t.backend.fail_close = None
        self.close_storage()
    def store_request(self, held, shared=GLOBAL):
        return M.authenticated_store_request(held, verifier_module=self.V, bootstrap_module=B,
                    storage=self.t.storage, operation_id=self.t.OP, installation_request_sha256=shared)
    def seed_request(self, held, shared=GLOBAL):
        return B.authenticated_seed_request(self.t.DATA, self.t.INSTALL, held,
                    verifier_module=self.V, storage=self.t.storage, git=self.t.git,
                    operation_id=self.t.OP, installation_request_sha256=shared)
    def store(self, held, parent, shared=GLOBAL):
        return M.store_authenticated_platform(held, verifier_module=self.V, bootstrap_module=B,
            parent_module=P, parent=parent, storage=self.t.storage,
            backend_module=SimpleNamespace(SeedBackend=T.SeedBackend), backend=self.t.backend,
            operation_id=self.t.OP, installation_request_sha256=shared)
    def seed(self, held, parent, shared=GLOBAL, *, confirm=False):
        operation = B.confirm_authenticated_seed if confirm else B.seed_authenticated_repository
        return operation(self.t.DATA, self.t.INSTALL, held, verifier_module=self.V,
            parent_module=P, parent=parent, storage=self.t.storage, files=self.t.files,
            git=self.t.git, operation_id=self.t.OP, installation_request_sha256=shared)


class SharedSessionControls(unittest.TestCase):
    def setUp(self):
        M.UNRELEASED.clear(); B.SEED_UNRELEASED.clear()
        self.fixtures = []
    def tearDown(self):
        for f in self.fixtures:
            f.close()
        M.UNRELEASED.clear(); B.SEED_UNRELEASED.clear()
    def fixture(self):
        f = Fixture(); self.fixtures.append(f); return f
    def test_actual_parent_two_effectful_stages_share_one_session_and_distinct_actions(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            request, request_sha, action, f.records = f.store_request(held)
            args = session.prepare('company-platform-store', action)
            self.assertNotEqual(request_sha, GLOBAL)
            with session.hold(args) as parent:
                result = f.store(held, parent)
                self.assertEqual(parent.arguments.request, GLOBAL)
                with self.assertRaises(AssertionError): session.confirm_store(f, result)
            f.close_storage()
            with self.assertRaises(AssertionError): session.confirm_store(f, result)
        session.confirm_store(f, result)
        f.reopen()
        with f.q.held() as held:
            seed_request, seed_sha, seed_action = f.seed_request(held)
            self.assertNotEqual(seed_sha, request_sha); self.assertNotEqual(seed_action, action)
            self.assertEqual(seed_request['installationRequestSha256'], GLOBAL)
            with session.hold(session.prepare('repository-seed', seed_action)) as parent:
                captured = parent.files[session.path + '/company-platform-store.confirmed'][2]
                confirmed = P.record(captured, 'install-stage-confirmed-v1',
                    ('session','stage','action','outcome','independently_confirmed'))
                self.assertEqual(confirmed['action'], action)
                self.assertEqual(confirmed['outcome'], M.digest(M.canonical(result)))
                parent.check(); seeded = f.seed(held, parent)
                self.assertEqual(parent.arguments.request, GLOBAL)
                self.assertEqual(seeded['requestSha256'], seed_sha)
                self.assertTrue(seeded['ownedSeedHandlesReleased'])
        self.assertFalse(f.t.backend.handles); self.assertFalse(session.system.descriptors)
    def test_effect_free_stage_planning_precedes_current_parent_intent(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            _, _, action, _ = f.store_request(held)
            self.assertNotIn(session.path + '/company-platform-store.intent', session.system.metas)
            self.assertEqual(f.t.backend.effects, [])
            with session.hold(session.prepare('company-platform-store', action)) as parent:
                parent.check()
    def test_injected_quiet_ancestor_still_has_full_nine_drift_refusal(self):
        f = self.fixture(); ancestor = f.q.root.parent
        with self.assertRaises(f.V.ReleaseUnavailable):
            with f.q.held() as held:
                before = f.q.files.frozen[ancestor]
                f.q.files.frozen[ancestor] = SimpleNamespace(**vars(before))
                f.q.files.frozen[ancestor].st_nlink += 1
                f.store_request(held)
        self.assertEqual(f.t.backend.effects, [])
        self.assertFalse(f.q.files.records); self.assertFalse(f.q.files.dirs)
    def test_store_explicit_field_changes_request_and_action_and_retains_intent(self):
        f = self.fixture()
        with f.q.held() as held:
            a, ah, aa, _ = f.store_request(held, GLOBAL)
            b, bh, ba, _ = f.store_request(held, OTHER)
            self.assertNotEqual(ah, bh); self.assertNotEqual(aa, ba)
            self.assertEqual({k:v for k,v in a.items() if k != 'installationRequestSha256'},
                             {k:v for k,v in b.items() if k != 'installationRequestSha256'})
            session = Session()
            with session.hold(session.prepare('company-platform-store', aa)) as parent:
                result = f.store(held, parent)
            intent = json.loads(f.t.backend.nodes[result['root'] + '/intent.json']['raw'])
            self.assertEqual(intent['request'], a); self.assertEqual(intent['actionSha256'], aa)
    def test_store_default_request_matches_historical_shape_and_action(self):
        f = self.fixture()
        with f.q.held() as held:
            request, sha, action, _ = f.store_request(held, None)
            self.assertNotIn('installationRequestSha256', request)
            expected = dict(schemaVersion=1, scope='FRESH_COMPANY_PLATFORM_ARTIFACT_STORE_ONLY',
                installationId=f.t.storage.installation_id, dataDir=f.t.DATA, installRoot=f.t.INSTALL,
                storeParent=f.s.base, operationId=f.t.OP, releaseSha256=held.metadata['releaseSha256'],
                platformManifestSha256=held.metadata['platformManifestSha256'], sourceTree=held.metadata['sourceTree'],
                archiveSha256=held.metadata['archiveSha256'], archiveBytes=held.metadata['archiveBytes'],
                signingKeyFingerprint=held.metadata['signingKeyFingerprint'], storageBindingSha256=f.t.storage.binding_sha256)
            self.assertEqual(request, expected)
            self.assertEqual(sha, M.digest(M.canonical(expected)))
            self.assertEqual(action, M.digest(b'company-platform-store-v1:' + sha.encode() + b':' + M.digest(held.files[M.MODULE_PATH]).encode()))
            session = Session(sha)
            with session.hold(session.prepare('company-platform-store', action)) as parent:
                result = f.store(held, parent, None)
            self.assertEqual(json.loads(f.t.backend.nodes[result['root'] + '/intent.json']['raw'])['request'], expected)
    def test_seed_default_request_matches_historical_shape_and_action(self):
        f = self.fixture()
        with f.q.held() as held:
            request, sha, action = f.seed_request(held, None)
            self.assertEqual(set(request), {'schemaVersion','mode','installationId','dataDir','installRoot',
                'operationId','releaseSha256','platformManifestSha256','sourceTree','gitToolPin','storageBindingSha256'})
            self.assertNotIn('installationRequestSha256', request)
            self.assertEqual(sha, M.digest(B._seed_json(request)))
            self.assertEqual(action, M.digest(b'platform-repository-seed-v1:' + sha.encode() + b':' + M.digest(held.files['scripts/bootstrap.py']).encode()))
            session = Session(sha)
            with session.hold(session.prepare('repository-seed', action)) as parent:
                result = f.seed(held, parent, None)
            intent = json.loads(f.t.backend.nodes[f.t.storage.journal + '/' + f.t.OP + '/intent.json']['raw'])
            self.assertEqual(intent['request'], request); self.assertEqual(result['requestSha256'], sha)
    def test_malformed_explicit_requests_deny_before_queries_or_output(self):
        f = self.fixture()
        with f.q.held() as held:
            for bad in (True, False, 0, b'a'*64, {}, [], '', 'a'*63, 'a'*65, 'A'*64, 'g'*64):
                with self.subTest(value=repr(bad)):
                    calls = len(f.t.runner.calls)
                    with self.assertRaises(ValueError): f.store_request(held, bad)
                    with self.assertRaises(ValueError): f.seed_request(held, bad)
                    self.assertEqual(len(f.t.runner.calls), calls)
                    self.assertEqual(f.t.backend.effects, [])
    def test_actual_session_global_mismatch_denies_parent_acquisition(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            _, _, action, _ = f.store_request(held)
            args = session.prepare('company-platform-store', action)
            wrong = P.ParentInput(args.parent_pid,args.directory_fd,args.lock_fd,args.session,OTHER,args.stage,args.action)
            with self.assertRaises(P.ParentUnavailable):
                with session.hold(wrong): self.fail('foreign session yielded')
            self.assertEqual(f.t.backend.effects, []); self.assertFalse(session.system.descriptors)
    def test_store_different_explicit_global_denies_before_output(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            _, _, action, _ = f.store_request(held)
            with session.hold(session.prepare('company-platform-store', action)) as parent:
                with self.assertRaises(ValueError): f.store(held, parent, OTHER)
                self.assertEqual(f.t.backend.effects, [])
    def test_store_wrong_current_stage_action_denies_before_output(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            with session.hold(session.prepare('company-platform-store', 'f'*64)) as parent:
                with self.assertRaises(ValueError): f.store(held, parent)
                self.assertEqual(f.t.backend.effects, [])
    def test_seed_different_explicit_global_denies_and_closes_before_output(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            _, _, action = f.seed_request(held)
            with session.hold(session.prepare('repository-seed', action)) as parent:
                with self.assertRaises(ValueError): f.seed(held, parent, OTHER)
                self.assertEqual(f.t.backend.effects, [])
                self.assertFalse(f.t.backend.handles)
    def test_seed_wrong_current_stage_action_denies_before_output(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            with session.hold(session.prepare('repository-seed', 'f'*64)) as parent:
                with self.assertRaises(ValueError): f.seed(held, parent)
                self.assertEqual(f.t.backend.effects, [])
    def test_actual_prior_store_without_confirmation_refuses_second_stage(self):
        f = self.fixture(); session = Session()
        with f.q.held() as held:
            _, _, store_action, _ = f.store_request(held)
            session.prepare('company-platform-store', store_action)
            _, _, seed_action = f.seed_request(held)
            with self.assertRaises(P.ParentUnavailable):
                with session.hold(session.prepare('repository-seed', seed_action)): self.fail('unconfirmed prior stage')
            self.assertEqual(f.t.backend.effects, [])
    def test_prior_confirmed_action_mismatch_refuses_real_parent_acquisition(self):
        session = Session(); store_action = 'b'*64
        session.prepare('company-platform-store', store_action)
        session.system.add(session.path + '/company-platform-store.confirmed', PT.encoded('install-stage-confirmed-v1',
            session=PT.ARGS.session, stage='company-platform-store', action='c'*64,
            outcome='d'*64, independently_confirmed='true'))
        with self.assertRaises(P.ParentUnavailable):
            with session.hold(session.prepare('repository-seed', 'e'*64)): self.fail('wrong previous action')
        self.assertFalse(session.system.descriptors)
    def test_completed_foundation_session_cannot_be_extended(self):
        session = Session()
        session.system.add(session.path + '/complete', b'closed original session')
        with self.assertRaises(P.ParentUnavailable):
            with session.hold(session.prepare('company-platform-store', 'b'*64)): self.fail('completed session')
        self.assertFalse(session.system.descriptors)
    def test_seed_explicit_readonly_confirmation_forwards_same_global(self):
        f = self.fixture()
        with f.q.held() as held:
            request, sha, action = f.seed_request(held)
            session = Session()
            with session.hold(session.prepare('repository-seed', action)) as parent:
                f.seed(held, parent)
        f.reopen(fresh=False); before = {p:n['raw'] for p,n in f.t.backend.nodes.items()}; effects = len(f.t.backend.effects)
        with f.q.held() as held:
            again, again_sha, again_action = f.seed_request(held)
            self.assertEqual((again,again_sha,again_action), (request,sha,action))
            confirmation_session = Session()
            with confirmation_session.hold(confirmation_session.prepare('repository-seed', action)) as parent:
                result = f.seed(held, parent, confirm=True)
                self.assertEqual(result['status'], 'SEED_CONFIRMED_READONLY')
                self.assertIs(result['changed'], False)
        self.assertEqual({p:n['raw'] for p,n in f.t.backend.nodes.items()}, before)
        self.assertEqual(len(f.t.backend.effects), effects)
    def test_readonly_confirmation_cannot_adopt_legacy_seed_into_shared_session(self):
        f = self.fixture()
        with f.q.held() as held:
            _, sha, action = f.seed_request(held, None)
            session = Session(sha)
            with session.hold(session.prepare('repository-seed', action)) as parent: f.seed(held, parent, None)
        f.reopen(fresh=False); before = {p:n['raw'] for p,n in f.t.backend.nodes.items()}; effects = len(f.t.backend.effects)
        with f.q.held() as held:
            _, _, action = f.seed_request(held)
            session = Session()
            with session.hold(session.prepare('repository-seed', action)) as parent:
                with self.assertRaises(ValueError): f.seed(held, parent, confirm=True)
        self.assertEqual({p:n['raw'] for p,n in f.t.backend.nodes.items()}, before)
        self.assertEqual(len(f.t.backend.effects), effects)
    def test_readonly_confirmation_rejects_different_global_even_when_parent_matches(self):
        f = self.fixture()
        with f.q.held() as held:
            _, _, action = f.seed_request(held)
            session = Session()
            with session.hold(session.prepare('repository-seed', action)) as parent: f.seed(held, parent)
        f.reopen(fresh=False); before = {p:n['raw'] for p,n in f.t.backend.nodes.items()}
        with f.q.held() as held:
            _, _, action = f.seed_request(held, OTHER)
            session = Session(OTHER)
            with session.hold(session.prepare('repository-seed', action)) as parent:
                with self.assertRaises(ValueError): f.seed(held, parent, OTHER, confirm=True)
        self.assertEqual({p:n['raw'] for p,n in f.t.backend.nodes.items()}, before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
