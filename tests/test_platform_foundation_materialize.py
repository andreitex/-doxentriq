"""Genuine schema4 issuance and retained file bytes; native ownership injected."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module

T = load('platform_foundation_materialize_existing_fixtures', ROOT/'tests/test_installer_materialize.py')
Q = load('platform_foundation_schema4_fixtures', ROOT/'tests/test_company_release_schema4.py')
P = load('platform_foundation_platform_source_fixture', ROOT/'scripts/platform_source.py')
M = T.M


class PlatformFoundationControls(unittest.TestCase):
    def setUp(self):
        self.V = load('platform_foundation_genuine_verifier_' + uuid.uuid4().hex, ROOT/'scripts/verify-release.py')
        self.q = Q.Fixture(self.V, P)
        # Declare quiet external fixture ancestors before genuine capture.
        for path in self.q.root.parents:
            self.q.files.changes.setdefault(path, {}).update(st_mtime_ns=101, st_ctime_ns=202, st_size=0)
        self.parent = T.ARTIFACT/('case-' + uuid.uuid4().hex); self.parent.mkdir()
        self.name = 'install-' + uuid.uuid4().hex
        self.files = T.Files(); self.clock = T.Clock()
        self.assertFalse(M.UNRELEASED_HANDLES)

    def tearDown(self):
        self.files.fixture_release_unknown()  # Injected fixture references only.
        M.UNRELEASED_HANDLES.clear()
        self.assertFalse(M._PLATFORM_FOUNDATION_SOURCES)
        self.assertFalse(self.q.files.records); self.assertFalse(self.q.files.dirs)

    def context(self, held, **kw):
        args = dict(verifier=self.V, files=self.files, clock=self.clock); args.update(kw)
        return M.materialized_platform_foundation(held, self.parent, self.name, **args)

    def test_genuine_schema4_projection_keeps_exact_64_bytes_and_no_archive(self):
        with self.q.held() as held:
            expected = {p: held.files[p] for p in (*M.SOURCES, *M.PLATFORM_FOUNDATION_EXTRA_SOURCES, *M.TEMPLATES)}
            expected.update({'company-release/' + p: b for p,b in {**held.configs, **held.provenance}.items()})
            with patch.object(M, 'NativeFiles', side_effect=AssertionError('native fallback')):
                with self.context(held) as tree:
                    self.assertEqual(len(tree.files), 64)
                    self.assertEqual(set(tree.files), set(expected))
                    self.assertNotIn('company-release/platform-sources.tar.gz', tree.files)
                    for name, raw in expected.items(): self.assertEqual((tree.root/name).read_bytes(), raw)
                    self.assertEqual(tree.release_sha256, held.metadata['releaseSha256'])
                    self.assertIs(tree._held._held, held)
                    self.assertIs(tree._held._verifier, self.V)
                    self.assertIs(self.V.require_platform_source(held), held)
                    adapter = tree._held
            self.assertFalse(adapter.active)
            with self.assertRaises(ValueError): tree.root
        self.assertFalse(self.files.opened)

    def test_signed_code_is_copied_without_candidate_execution(self):
        self.q.values['scripts/bootstrap.py'] = b'raise RuntimeError("candidate must not execute")\n'
        self.q.refresh_platform()
        with self.q.held() as held, patch('subprocess.Popen', side_effect=AssertionError('child')):
            with self.context(held) as tree:
                self.assertEqual((tree.root/'scripts/bootstrap.py').read_bytes(), self.q.values['scripts/bootstrap.py'])

    def test_status_is_signed_schema4_projection_only_and_legacy_catalog_stays_exact(self):
        self.assertEqual(M.SOURCES, self.V.COMPANY_SOURCES)
        self.assertEqual(len(M.SOURCES), 44)
        self.assertNotIn('scripts/installation-status.py', M.SOURCES)
        self.assertEqual(M.PLATFORM_FOUNDATION_EXTRA_SOURCES, ('scripts/installation-status.py',))
        raw = (ROOT/'scripts/installation-status.py').read_bytes()
        self.q.values['scripts/installation-status.py'] = raw
        self.q.refresh_platform()
        with self.q.held() as held:
            rows, release = M.capture_platform_foundation(held, verifier=self.V)
            self.assertEqual(rows['scripts/installation-status.py'], raw)
            self.assertEqual(len(rows), 64)
            self.assertEqual(held.metadata['sourceFileCount'], 44)
        self.assertEqual(self.files.effects, [])

    def test_status_requires_its_exact_signed_platform_row_before_output(self):
        with self.q.held() as held:
            original = json.loads(held.configs['platform-sources.json'])
            for kind in ('missing', 'hash', 'mode', 'boolean'):
                bad = json.loads(json.dumps(original))
                row = next(r for r in bad['files'] if r['path'] == 'scripts/installation-status.py')
                if kind == 'missing': bad['files'].remove(row)
                else: row['sha256' if kind == 'hash' else 'gitMode' if kind == 'mode' else 'bytes'] = '0'*64 if kind == 'hash' else '100755' if kind == 'mode' else True
                with patch.object(self.V, 'decode', return_value=bad):
                    with self.assertRaises(ValueError):
                        with self.context(held): self.fail('yield')
                self.assertEqual(self.files.effects, [])

    def test_unissued_original_class_clone_refuses_without_callback_or_effect(self):
        with self.q.held() as held:
            metadata = dict(held.metadata); metadata['release'] = json.loads(held.provenance['release.json'])
            clone = self.V.HeldPlatformSource(dict(held.files), dict(held.git_modes), dict(held.configs),
                dict(held.provenance), metadata, lambda: self.fail('forged callback'), archive_bytes=held.archive_bytes)
            with self.assertRaises(ValueError):
                with self.context(clone): self.fail('yield')
            self.assertEqual(self.files.effects, [])
            self.assertIs(self.V.require_platform_source(held), held)

    def test_foreign_original_verifier_refuses_before_output_io(self):
        other = load('platform_foundation_foreign_verifier', ROOT/'scripts/verify-release.py')
        with self.q.held() as held:
            with self.assertRaises(ValueError):
                with self.context(held, verifier=other): self.fail('yield')
            self.assertEqual(self.files.effects, [])

    def test_expired_source_refuses_before_effects(self):
        with self.q.held() as held: pass
        with self.assertRaises(ValueError):
            with self.context(held): self.fail('yield')
        self.assertEqual(self.files.effects, [])

    def test_existing_output_is_preserved(self):
        root = self.parent/self.name; root.mkdir(); (root/'sentinel').write_bytes(b'preserve')
        with self.q.held() as held:
            with self.assertRaises(ValueError):
                with self.context(held): self.fail('yield')
            self.assertEqual((root/'sentinel').read_bytes(), b'preserve')
            self.assertEqual(self.files.effects, [])

    def test_explicit_backend_required_no_native_default(self):
        with self.q.held() as held, patch.object(M, 'NativeFiles', side_effect=AssertionError('native')):
            with self.assertRaises(ValueError):
                with self.context(held, files=None): self.fail('yield')
            self.assertEqual(self.files.effects, [])

    def test_signed_selected_hash_mode_and_boolean_disagreement_before_effects(self):
        with self.q.held() as held:
            original = json.loads(held.configs['platform-sources.json'])
            for kind in ('hash', 'mode', 'boolean'):
                bad = json.loads(json.dumps(original))
                row = next(r for r in bad['files'] if r['path'] == M.SOURCES[-1])
                row['sha256' if kind == 'hash' else 'gitMode' if kind == 'mode' else 'bytes'] = '0'*64 if kind == 'hash' else '100755' if kind == 'mode' else True
                with patch.object(self.V, 'decode', return_value=bad):
                    with self.assertRaises(ValueError): M.capture_platform_foundation(held, verifier=self.V)
                self.assertEqual(self.files.effects, [])

    def test_source_drift_during_write_preserves_partial_and_closes_output(self):
        def drift(fd, raw):
            path = self.q.bundle/'platform-sources.tar.gz'
            self.q.files.frozen[path] = self.q.files.lstat(path)
            old = path.read_bytes(); path.write_bytes(bytes([old[0]^1]) + old[1:])
        with self.assertRaises(ValueError), self.q.held() as held:
            self.files.hooks['write'] = drift
            with self.context(held): self.fail('yield')
        self.assertTrue((self.parent/self.name).is_dir())
        self.assertFalse(self.files.opened)

    def test_source_expiry_in_caller_expires_projection_and_closes_all_owned(self):
        with self.assertRaises(ValueError), self.q.held() as held:
            with self.context(held) as tree:
                adapter = tree._held; held._expire()
                with self.assertRaises(ValueError): tree.root
        self.assertFalse(adapter.active); self.assertFalse(self.files.opened)

    def test_legacy_schema3_route_remains_62_and_rejects_schema4(self):
        with self.q.held() as held:
            with self.assertRaises((ValueError, AttributeError)):
                with M.materialized_deployment(held, self.parent, self.name, files=self.files): self.fail('yield')
        self.assertEqual(M.FILE_COUNT, 62)
        self.assertEqual(self.files.effects, [])

    def test_uncertain_close_retains_exact_owned_backend_and_descriptor(self):
        def unknown(fd): raise OSError('injected unknown close')
        self.files.hooks['close'] = unknown
        with self.q.held() as held:
            with self.assertRaises(ValueError):
                with self.context(held): self.fail('yield')
        self.assertTrue(M.UNRELEASED_HANDLES)
        self.assertTrue(all(backend is self.files and fd in self.files.opened for backend,fd in M.UNRELEASED_HANDLES))
        self.assertTrue((self.parent/self.name).is_dir())


if __name__ == '__main__': unittest.main(verbosity=2)
