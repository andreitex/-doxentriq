"""Proposed injected stored authentication controls; no native/stage authority.

Intended destination tests/test_company_stored_platform_source.py after a
separate reviewed product grant. This private proposal has not been run.
"""
import hashlib
import importlib.util
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module


T = load('stored_schema4_fixture',ROOT/'tests/test_company_release_schema4.py')


class StoredControls(unittest.TestCase):
    def setUp(self):
        self.V = load('stored_verifier',ROOT/'scripts/verify-release.py')
        self.P = load('stored_platform_parser',ROOT/'scripts/platform_source.py')
        self.fresh()

    def fresh(self, helper_mode='100644'):
        self.F = T.Fixture(self.V,self.P)
        if helper_mode != '100644':
            self.F.modes['scripts/platform_source.py'] = helper_mode
            self.F.refresh_platform()
        self.release_sha = hashlib.sha256((self.F.bundle/'release.json').read_bytes()).hexdigest()
        company = self.F.root/'company'
        bundle = company/'platform-releases'/self.release_sha
        source = company/'source-releases'/self.release_sha/'source'
        bundle.parent.mkdir(parents=True); source.parent.mkdir(parents=True)
        # Create known fixture bytes exclusively at their final paths. Keeping
        # the original trees avoids Windows directory-rename interference;
        # verifier source, protection predicates and every control are intact.
        bundle.mkdir(); source.mkdir()
        for original in self.F.bundle.iterdir():
            self.assertTrue(original.is_file())
            with (bundle/original.name).open('xb') as stream:
                stream.write(original.read_bytes())
        for relative, raw in self.F.values.items():
            target = source/relative; target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream: stream.write(raw)
        self.F.bundle,self.F.sources = bundle,source
        for path in bundle.iterdir():
            self.F.files.changes[path] = dict(st_mode=stat.S_IFREG|0o400)
        for path in (bundle,source,source.parent,source/'scripts'):
            self.F.files.changes[path] = dict(st_mode=stat.S_IFDIR|0o500)
        self.helper = source/'scripts/platform_source.py'
        self.F.files.changes[self.helper] = dict(st_mode=stat.S_IFREG|0o400)
        self.F.files.changes[self.F.keys] = dict(st_mode=stat.S_IFDIR|0o700)
        # Explicit injected external ancestry: unrelated concurrent test fixture
        # writes are not native continuity evidence. A dedicated control changes
        # this same synthetic observation and proves the full-nine guard denies.
        for path in self.F.root.parents:
            self.F.files.changes.setdefault(path,{}).update(st_mtime_ns=101,st_ctime_ns=202,st_size=0)

    def held(self, **kwargs):
        args = dict(expected_architecture='x86_64',source_root=self.F.sources,
                    files=self.F.files,crypto=self.F.crypto)
        args.update(kwargs)
        return self.V.authenticated_stored_platform_source(self.F.bundle,self.F.public,self.F.fingerprint,**args)

    def clean(self):
        self.assertFalse(self.F.files.records); self.assertFalse(self.F.files.dirs)

    def denied_before_helper(self, **kwargs):
        with patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('helper must not execute')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held(**kwargs): self.fail('unexpected yield')
        self.assertFalse(self.V._ISSUED_PLATFORM_SOURCES); self.clean()

    def drift(self,path):
        self.F.files.frozen[path] = self.F.files.lstat(path)
        raw = path.read_bytes(); path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))

    def test_stored400_preserves_signed644_maps_archive_and_issuer(self):
        with self.held() as value:
            self.assertIs(self.V.require_platform_source(value),value)
            self.assertEqual(dict(value.files),self.F.values)
            self.assertEqual(dict(value.git_modes),self.F.modes)
            self.assertEqual(value.git_modes['scripts/platform_source.py'],'100644')
            self.assertEqual(value.archive_bytes,self.F.captured.archive_bytes)
            self.assertEqual(value.metadata['signingKeyFingerprint'],self.F.fingerprint)
            self.assertEqual(value.metadata['physicalSourcePolicy'],'IMMUTABLE_STORED_PLATFORM_SOURCE_V1')
            for name in ('nativeAuthorized','productionAuthorized','installerActivated','trustContinuesAfterReturn'):
                self.assertIs(value.metadata[name],False)
        self.assertFalse(value.active); self.assertNotIn(value,self.V._ISSUED_PLATFORM_SOURCES); self.clean()

    def test_stored400_preserves_signed755_parser_mode(self):
        self.fresh('100755')
        with self.held() as value:
            self.assertEqual(value.git_modes['scripts/platform_source.py'],'100755')
            self.assertEqual(value.archive_bytes,self.F.captured.archive_bytes)
        self.clean()

    def test_original_producer_factory_still_rejects400_parser(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held(): self.fail('producer accepted sealed parser')
        self.clean()

    def test_stored_factory_refuses644_and755_parser_before_exec(self):
        for mode in (0o644,0o755):
            self.fresh(); self.F.files.changes[self.helper]['st_mode'] = stat.S_IFREG|mode
            self.denied_before_helper()

    def test_external_key700_parent_uses_original_fullnine_policy(self):
        self.assertEqual(stat.S_IMODE(self.F.files.lstat(self.F.keys).st_mode),0o700)
        with self.held() as value:
            self.assertEqual(value.provenance['company-signing-public-key.pem'],self.F.public.read_bytes())
            self.assertEqual(value.metadata['signingKeyFingerprint'],self.F.fingerprint)
        self.clean()

    def test_bundle_source_scripts_and_source_release_require500(self):
        for role in ('bundle','source','scripts','release'):
            self.fresh()
            path = {'bundle':self.F.bundle,'source':self.F.sources,'scripts':self.F.sources/'scripts','release':self.F.sources.parent}[role]
            self.F.files.changes[path]['st_mode'] = stat.S_IFDIR|0o700
            self.denied_before_helper()

    def test_stored_artifact400_owner_link_and_type_are_strict(self):
        for change in ({'st_mode':stat.S_IFREG|0o600},{'st_uid':10001},{'st_nlink':2},{'st_mode':stat.S_IFLNK|0o777}):
            self.fresh(); self.F.files.changes[self.F.bundle/'release.json'].update(change)
            self.denied_before_helper()

    def test_source_relation_and_signed_release_directory_are_exact(self):
        for role in ('release','source'):
            self.fresh()
            if role=='release':
                other=self.F.bundle.with_name('0'*64);self.F.bundle.rename(other);self.F.bundle=other
                self.F.files.changes[other]=dict(st_mode=stat.S_IFDIR|0o500)
                for p in other.iterdir():self.F.files.changes[p]=dict(st_mode=stat.S_IFREG|0o400)
                self.denied_before_helper()
            else:
                self.denied_before_helper(source_root=self.F.sources.parent/'foreign')

    def test_noncanonical_or_untyped_paths_refuse_before_capture(self):
        for value in (True,None,123,str(self.F.bundle/'..'/self.F.bundle.name)):
            with self.assertRaises(self.V.ReleaseUnavailable):self.V._stored_platform_path(value)
        with self.assertRaises(self.V.ReleaseUnavailable):self.V._stored_platform_path('relative/company')
        self.assertEqual(self.F.files.events,[])

    def test_signature_and_fingerprint_refusal_precede_helper(self):
        self.F.crypto.accept=False;self.denied_before_helper()
        self.fresh()
        with patch.object(self.V,'verified_platform_helper',side_effect=AssertionError('helper')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.V.authenticated_stored_platform_source(self.F.bundle,self.F.public,'0'*64,
                    expected_architecture='x86_64',source_root=self.F.sources,files=self.F.files,crypto=self.F.crypto):self.fail('yield')
        self.clean()

    def test_signed_archive_or_parser_tamper_precedes_helper(self):
        for role in ('archive','parser'):
            self.fresh();path=self.F.bundle/'platform-sources.tar.gz' if role=='archive' else self.helper
            path.write_bytes(path.read_bytes()+b'\n');self.denied_before_helper()

    def test_stable_metadata_archive_parser_key_and_release_drift_expire(self):
        for role in ('archive','parser','key','release'):
            self.fresh()
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.held() as value:
                    path={'archive':self.F.bundle/'platform-sources.tar.gz','parser':self.helper,'key':self.F.public,'release':self.F.bundle/'release.json'}[role]
                    self.drift(path)
                    with self.assertRaises(self.V.ReleaseUnavailable):self.V.require_platform_source(value)
                    self.assertFalse(value.active);self.assertNotIn(value,self.V._ISSUED_PLATFORM_SOURCES)
            self.clean()

    def test_fullnine_external_ancestor_drift_is_not_exempted(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.held() as value:
                self.F.files.changes[self.F.root.parent]['st_ctime_ns'] += 1
                value.metadata
        self.assertFalse(value.active);self.clean()

    def test_caught_failed_getter_and_expired_archive_cannot_reissue(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.held() as value:
                raw=self.helper.read_bytes();self.drift(self.helper)
                with self.assertRaises(self.V.ReleaseUnavailable):value.files
                self.helper.write_bytes(raw)
                with self.assertRaises(self.V.ReleaseUnavailable):self.V.require_platform_source(value)
        with self.assertRaises(self.V.ReleaseUnavailable):value.archive_bytes
        self.clean()

    def test_same_class_flags_and_callback_do_not_forge_stored_issuance(self):
        calls=[]
        clone=self.V.HeldPlatformSource({}, {}, {}, {}, {'physicalSourcePolicy':'IMMUTABLE_STORED_PLATFORM_SOURCE_V1'},lambda:calls.append('forged'),archive_bytes=b'inert')
        with self.assertRaises(self.V.ReleaseUnavailable):self.V.require_platform_source(clone)
        self.assertEqual(calls,[]);self.assertNotIn(clone,self.V._ISSUED_PLATFORM_SOURCES)

    def test_unknown_close_expires_and_attempts_all_owned_closes(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.held() as value:self.F.files.fail_close=self.helper
        self.assertFalse(value.active);self.assertNotIn(value,self.V._ISSUED_PLATFORM_SOURCES)
        self.assertTrue(self.V.UNRELEASED_HANDLES)
        self.assertTrue(any(e[0]=='close' and e[1]==str(self.F.public) for e in self.F.files.events))
        with self.assertRaises(self.V.ReleaseUnavailable):self.V.require_platform_source(value)
        # Only explicit injected fixture cleanup, never a production retry policy.
        self.F.files.fail_close=None
        for fd in list(self.F.files.records):self.F.files.close(fd)
        for fd in list(self.F.files.dirs):self.F.files.close(fd)
        self.V.UNRELEASED_HANDLES.clear();self.clean()


if __name__ == '__main__':
    unittest.main(verbosity=2)
