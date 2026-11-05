"""Injected capability issuance controls; no native authentication or activation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from types import MappingProxyType
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


T = load('platform_issuance_schema4_fixture', ROOT / 'tests/test_company_release_schema4.py')


class IssuanceControls(unittest.TestCase):
    setUp = T.Controls.setUp
    clean = T.Controls.clean

    def forged(self, callback, kind=None):
        cls = kind or self.V.HeldPlatformSource
        return cls({'inert.txt': b'inert'}, {'inert.txt': '100644'}, {}, {},
                   {'signatureVerified': True, 'platformSourceAuthenticated': True}, callback)

    def test_public_constructor_flags_never_issue_or_invoke_callback(self):
        calls = []
        value = self.forged(lambda: calls.append('untrusted callback'))
        self.assertTrue(value.active)
        with self.assertRaises(self.V.ReleaseUnavailable):
            self.V.require_platform_source(value)
        self.assertEqual(calls, [])
        self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
        self.clean()

    def test_same_class_clone_of_authenticated_maps_is_not_issued(self):
        calls = []
        with self.F.held() as original:
            metadata = dict(original.metadata)
            metadata['release'] = json.loads(original.provenance['release.json'])
            clone = self.V.HeldPlatformSource(dict(original.files), dict(original.git_modes),
                dict(original.configs), dict(original.provenance), metadata,
                lambda: calls.append('clone callback'))
            with self.assertRaises(self.V.ReleaseUnavailable):
                self.V.require_platform_source(clone)
            self.assertEqual(calls, [])
            self.assertIs(self.V.require_platform_source(original), original)
        self.clean()

    def test_exact_type_rejects_subclass_cross_module_and_dictionary(self):
        calls = []
        class Derived(self.V.HeldPlatformSource):
            pass
        other = T.load('platform_issuance_other_verifier', ROOT / 'scripts/verify-release.py')
        values = [self.forged(lambda: calls.append('subclass'), Derived),
                  other.HeldPlatformSource({}, {}, {}, {}, {}, lambda: calls.append('other')),
                  {'active': True, 'signatureVerified': True}, None]
        for value in values:
            with self.assertRaises(self.V.ReleaseUnavailable):
                self.V.require_platform_source(value)
        self.assertEqual(calls, [])
        self.clean()

    def test_authenticated_context_issues_same_object_without_activation(self):
        self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
        with self.F.held() as value:
            self.assertIn(value, self.V._ISSUED_PLATFORM_SOURCES)
            self.assertIs(self.V.require_platform_source(value), value)
            for name in ('nativeAuthorized', 'productionAuthorized', 'installerActivated'):
                self.assertIs(value.metadata[name], False)
        self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
        self.assertFalse(value.active)
        with self.assertRaises(self.V.ReleaseUnavailable):
            self.V.require_platform_source(value)
        self.clean()

    def test_caller_exception_expires_and_removes_issued_object(self):
        with self.assertRaisesRegex(RuntimeError, 'injected caller'):
            with self.F.held() as value:
                self.V.require_platform_source(value)
                raise RuntimeError('injected caller')
        self.assertFalse(value.active)
        self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
        with self.assertRaises(self.V.ReleaseUnavailable):
            self.V.require_platform_source(value)
        self.clean()

    def test_signature_or_capture_failure_never_registers(self):
        for stage in ('signature', 'helper'):
            self.F = T.Fixture(self.V, self.P)
            self.F.crypto.accept = stage != 'signature'
            if stage == 'helper':
                with patch.object(self.V, 'verified_platform_helper',
                                  side_effect=self.V.ReleaseUnavailable('injected helper')):
                    with self.assertRaises(self.V.ReleaseUnavailable):
                        with self.F.held():
                            self.fail('unexpected yield')
            else:
                with self.assertRaises(self.V.ReleaseUnavailable):
                    with self.F.held():
                        self.fail('unexpected yield')
            self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
            self.clean()

    def test_failed_initial_live_check_precedes_issuance(self):
        with patch.object(self.V.HeldPlatformSource, 'recheck',
                          side_effect=self.V.ReleaseUnavailable('injected initial check')):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held():
                    self.fail('unexpected yield')
        self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
        self.clean()

    def test_caught_failed_recheck_cannot_restore_issuance(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as value:
                source = self.F.sources / 'scripts/platform_source.py'
                original = source.read_bytes()
                self.F.files.frozen[source] = self.F.files.lstat(source)
                source.write_bytes(original + b'\n')
                with self.assertRaises(self.V.ReleaseUnavailable):
                    value.recheck()
                self.assertFalse(value.active)
                self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
                source.write_bytes(original)
                with self.assertRaises(self.V.ReleaseUnavailable):
                    self.V.require_platform_source(value)
        self.clean()

    def test_known_issued_unknown_precheck_expires_even_if_latch_cleared(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as value:
                self.V.UNRELEASED_HANDLES.append(('injected unknown', object()))
                with patch.object(self.V.HeldPlatformSource, 'recheck',
                                  side_effect=AssertionError('must refuse before callback')):
                    with self.assertRaises(self.V.ReleaseUnavailable):
                        self.V.require_platform_source(value)
                self.assertFalse(value.active)
                self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
                # Only injected fixture latch cleanup; production never retries unknown FDs.
                self.V.UNRELEASED_HANDLES.clear()
                with self.assertRaises(self.V.ReleaseUnavailable):
                    self.V.require_platform_source(value)
        self.clean()

    def test_unknown_created_during_recheck_fails_postcheck_and_expires(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as value:
                def on_read(*_):
                    self.V.UNRELEASED_HANDLES.append(('injected during read', object()))
                    self.F.files.on_read = None
                self.F.files.on_read = on_read
                with self.assertRaises(self.V.ReleaseUnavailable):
                    self.V.require_platform_source(value)
                self.assertFalse(value.active)
                self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
                self.V.UNRELEASED_HANDLES.clear()
        self.clean()

    def test_expiration_during_recheck_fails_postcheck(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as value:
                def on_read(*_):
                    value._expire()
                    self.F.files.on_read = None
                self.F.files.on_read = on_read
                with self.assertRaises(self.V.ReleaseUnavailable):
                    self.V.require_platform_source(value)
                self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
        self.clean()

    def test_nested_live_contexts_have_independent_issuance_lifetimes(self):
        other = T.Fixture(self.V, self.P)
        with self.F.held() as outer:
            with other.held() as inner:
                self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, {outer, inner})
                self.assertIs(self.V.require_platform_source(outer), outer)
                self.assertIs(self.V.require_platform_source(inner), inner)
            self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, {outer})
            self.assertIs(self.V.require_platform_source(outer), outer)
            with self.assertRaises(self.V.ReleaseUnavailable):
                self.V.require_platform_source(inner)
        self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
        self.assertFalse(other.files.records)
        self.assertFalse(other.files.dirs)
        self.clean()

    def test_close_uncertainty_denies_and_expires_other_live_context(self):
        other = T.Fixture(self.V, self.P)
        other.files.fail_close = other.keys
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as outer:
                with self.assertRaises(self.V.ReleaseUnavailable):
                    with other.held() as inner:
                        self.V.require_platform_source(inner)
                self.assertFalse(inner.active)
                self.assertNotIn(inner, self.V._ISSUED_PLATFORM_SOURCES)
                self.assertTrue(self.V.UNRELEASED_HANDLES)
                with self.assertRaises(self.V.ReleaseUnavailable):
                    self.V.require_platform_source(outer)
                self.assertFalse(outer.active)
                self.assertNotIn(outer, self.V._ISSUED_PLATFORM_SOURCES)
                # This backend's directory descriptors are synthetic test tokens.
                other.files.dirs.clear()
                self.V.UNRELEASED_HANDLES.clear()
                with self.assertRaises(self.V.ReleaseUnavailable):
                    self.V.require_platform_source(outer)
        self.assertFalse(other.files.records)
        self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
        self.clean()


    def test_archive_getter_returns_original_verified_object_and_exact_readback(self):
        captured = []
        original_helper = self.V.verified_platform_helper
        def helper(raw):
            module = original_helper(raw)
            original_verify = module.verify_archive
            def verify(*args, **kwargs):
                result = original_verify(*args, **kwargs)
                captured.append(result)
                return result
            module.verify_archive = verify
            return module
        expected = (self.F.bundle / 'platform-sources.tar.gz').read_bytes()
        with patch.object(self.V, 'verified_platform_helper', side_effect=helper):
            with self.F.held() as value:
                self.assertEqual(len(captured), 1)
                self.assertIs(value.archive_bytes, captured[0].archive_bytes)
                self.assertIs(value.archive_bytes, value.archive_bytes)
                self.assertEqual(value.archive_bytes, expected)
                self.assertEqual(len(expected), value.metadata['archiveBytes'])
                self.assertEqual(hashlib.sha256(expected).hexdigest(), value.metadata['archiveSha256'])
                self.assertNotIn('platform-sources.tar.gz', value.configs)
                self.assertIs(self.V.require_platform_source(value), value)
        self.clean()

    def test_archive_getter_denies_after_normal_and_exceptional_expiration(self):
        with self.F.held() as normal:
            captured = normal.archive_bytes
        self.assertIs(type(captured), bytes)
        with self.assertRaises(self.V.ReleaseUnavailable):
            normal.archive_bytes
        with self.assertRaisesRegex(RuntimeError, 'injected archive caller'):
            with self.F.held() as exceptional:
                exceptional.archive_bytes
                raise RuntimeError('injected archive caller')
        with self.assertRaises(self.V.ReleaseUnavailable):
            exceptional.archive_bytes
        self.assertFalse(normal.active)
        self.assertFalse(exceptional.active)
        self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
        self.clean()

    def test_archive_getter_rehashes_live_bytes_with_frozen_metadata(self):
        with self.assertRaises(self.V.ReleaseUnavailable):
            with self.F.held() as value:
                path = self.F.bundle / 'platform-sources.tar.gz'
                raw = path.read_bytes()
                self.F.files.frozen[path] = self.F.files.lstat(path)
                path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                with self.assertRaises(self.V.ReleaseUnavailable):
                    value.archive_bytes
                self.assertFalse(value.active)
                self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
                path.write_bytes(raw)
                with self.assertRaises(self.V.ReleaseUnavailable):
                    value.archive_bytes
        self.clean()

    def test_archive_bytes_and_authenticated_metadata_are_immutable(self):
        with self.F.held() as value:
            raw = value.archive_bytes
            with self.assertRaises(TypeError):
                raw[0] = 0
            with self.assertRaises(AttributeError):
                value.archive_bytes = b'caller replacement'
            with self.assertRaises(TypeError):
                value.metadata['archiveBytes'] = 1
            with self.assertRaises(TypeError):
                value.metadata['archiveSha256'] = '0' * 64
            self.assertIs(value.archive_bytes, raw)
        self.clean()

    def test_independent_signing_key_fingerprint_is_retained_exactly(self):
        with self.F.held() as value:
            fingerprint = value.metadata['signingKeyFingerprint']
            self.assertEqual(fingerprint, self.F.fingerprint)
            public = value.provenance['company-signing-public-key.pem']
            self.assertEqual(fingerprint, hashlib.sha256(self.V.public_der(public)).hexdigest())
            with self.assertRaises(TypeError):
                value.metadata['signingKeyFingerprint'] = '0' * 64
            self.assertEqual(value.metadata['signingKeyFingerprint'], fingerprint)
        self.clean()

    def test_factory_cannot_issue_missing_archive(self):
        original_init = self.V.HeldPlatformSource.__init__
        def omit_archive(instance, *args, **kwargs):
            self.assertIs(type(kwargs['archive_bytes']), bytes)
            kwargs['archive_bytes'] = None
            original_init(instance, *args, **kwargs)
        with patch.object(self.V.HeldPlatformSource, '__init__', omit_archive):
            with self.assertRaises(self.V.ReleaseUnavailable):
                with self.F.held():
                    self.fail('archive-less issuance')
        self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
        self.clean()

    def test_factory_archive_pin_type_length_and_hash_refusal_precedes_issuance(self):
        original_init = self.V.HeldPlatformSource.__init__
        for changes in ({'archiveBytes': True}, {'archiveBytes': 1.0}, {'archiveBytes': 0},
                        {'archiveBytes': self.V.PLATFORM_ARCHIVE_LIMIT + 1},
                        {'archiveSha256': '0' * 64}, {'archiveSha256': None}):
            with self.subTest(changes=changes):
                def alter_metadata(instance, files, modes, configs, provenance, metadata, callback, *, archive_bytes=None):
                    original_init(instance, files, modes, configs, provenance,
                                  dict(metadata, **changes), callback, archive_bytes=archive_bytes)
                with patch.object(self.V.HeldPlatformSource, '__init__', alter_metadata):
                    with self.assertRaises(self.V.ReleaseUnavailable):
                        with self.F.held():
                            self.fail('incorrect archive pin issued')
                self.assertEqual(self.V._ISSUED_PLATFORM_SOURCES, set())
                self.clean()

    def test_issued_missing_or_changed_archive_denies_before_callback_and_expires(self):
        for broken in (None, b'altered archive'):
            with self.subTest(broken=broken):
                with self.assertRaises(self.V.ReleaseUnavailable):
                    with self.F.held() as value:
                        # Inject an internal invariant fault, not a caller authorization seam.
                        old_values = value._HeldPlatformSource__values
                        object.__setattr__(value, '_HeldPlatformSource__values',
                                           MappingProxyType(dict(old_values, archive_bytes=broken)))
                        with patch.object(self.V.HeldPlatformSource, 'recheck',
                                          side_effect=AssertionError('must refuse before callback')):
                            with self.assertRaises(self.V.ReleaseUnavailable):
                                self.V.require_platform_source(value)
                        self.assertFalse(value.active)
                        self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
                        object.__setattr__(value, '_HeldPlatformSource__values', old_values)
                        with self.assertRaises(self.V.ReleaseUnavailable):
                            self.V.require_platform_source(value)
                self.clean()

    def test_forged_complete_archive_capability_never_invokes_callback(self):
        calls = []
        with self.F.held() as original:
            metadata = dict(original.metadata)
            metadata['release'] = json.loads(original.provenance['release.json'])
            clone = self.V.HeldPlatformSource(dict(original.files), dict(original.git_modes),
                dict(original.configs), dict(original.provenance), metadata,
                lambda: calls.append('forged archive callback'), archive_bytes=original.archive_bytes)
            with self.assertRaises(self.V.ReleaseUnavailable):
                self.V.require_platform_source(clone)
            with self.assertRaises(self.V.ReleaseUnavailable):
                clone.archive_bytes
            self.assertEqual(calls, [])
            self.assertIs(self.V.require_platform_source(original), original)
        self.clean()

    def test_archive_getter_refuses_unknown_or_expired_postcheck(self):
        for fault in ('unknown', 'expired'):
            with self.subTest(fault=fault):
                with self.assertRaises(self.V.ReleaseUnavailable):
                    with self.F.held() as value:
                        def on_read(*_):
                            self.F.files.on_read = None
                            if fault == 'unknown':
                                self.V.UNRELEASED_HANDLES.append(('injected archive read', object()))
                            else:
                                value._expire()
                        self.F.files.on_read = on_read
                        with self.assertRaises(self.V.ReleaseUnavailable):
                            value.archive_bytes
                        self.assertFalse(value.active)
                        self.assertNotIn(value, self.V._ISSUED_PLATFORM_SOURCES)
                        # Only an injected fixture latch is cleared here.
                        self.V.UNRELEASED_HANDLES.clear()
                        with self.assertRaises(self.V.ReleaseUnavailable):
                            value.archive_bytes
                self.clean()


if __name__ == '__main__':
    unittest.main(verbosity=2)
