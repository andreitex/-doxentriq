"""Native files only; no Docker, Keycloak, host mounts or credentials."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import unittest
import uuid

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, (Path(__file__).resolve().parents[2]/'deploy/installer'/filename.replace('original/','') if not filename.startswith('test_') else HERE/filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E = load('identity_provision_evidence', 'company_identity_evidence.py')
I = load('original_identity_io', 'company_identity_io.py')


@unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0, 'Linux root files required')
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        for path in (parent, *parent.parents):
            info = path.lstat()
            self.assertTrue(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
        self.data = parent/uuid.uuid4().hex
        self.data.mkdir(mode=0o700)
        (self.data/'company').mkdir(mode=0o700)
        self.operation = uuid.uuid4().hex
        self.expected = dict(operationId=self.operation, sourceSha256=E.sha(b'synthetic helper'), caSha256=E.sha(b'synthetic CA'),
            image='registry.example/identity@sha256:'+'a'*64, imageId='sha256:'+'b'*64, networkId='c'*64, keycloakId='d'*64)
        io = I.IdentityIO(self.data, self.operation, b'synthetic helper', b'synthetic CA', check_authority=lambda: None)
        io.record('provision', 'intent', {k:v for k,v in self.expected.items() if k != 'operationId'})
        for event in ('created', 'start-intent', 'completed', 'removed'):
            value = dict(containerId='e'*64)
            if event == 'completed':
                value['outputSha256'] = E.sha(E.MESSAGE)
            io.record('provision', event, value)
        io.close()
        self.path = Path(io.root)

    def read(self, expected=None):
        return E.ProvisionEvidence(self.data, expected or self.expected, check_authority=lambda: None)

    def test_complete_record_observation_has_no_live_or_parent_authority(self):
        before = {p.name: (E.identity(p.lstat()), p.read_bytes()) for p in self.path.iterdir()}
        with self.read() as evidence:
            result = evidence.observation()
            self.assertEqual(result['containerId'], 'e'*64)
            self.assertFalse(result['livePolicyVerified'])
            self.assertFalse(result['parentAuthorityEstablished'])
            self.assertFalse(result['publicStartupAllowed'])
        after = {p.name: (E.identity(p.lstat()), p.read_bytes()) for p in self.path.iterdir()}
        self.assertEqual(before, after)

    def test_partial_attempt_never_counts_as_completed(self):
        (self.path/'005-provision-removed.json').unlink()
        with self.assertRaises(ValueError):
            self.read()

    def test_wrong_expected_image_network_or_source_is_rejected(self):
        for field, value in [('imageId', 'sha256:'+'f'*64), ('networkId', 'f'*64), ('sourceSha256', 'f'*64)]:
            with self.subTest(field=field):
                changed = dict(self.expected); changed[field] = value
                with self.assertRaises(ValueError):
                    self.read(changed)

    def test_inconsistent_container_ids_are_rejected(self):
        path = self.path/'004-provision-completed.json'
        value = json.loads(path.read_bytes()); value['values']['containerId'] = 'f'*64
        path.write_bytes(E.canonical(value))
        with self.assertRaises(ValueError):
            self.read()

    def test_duplicate_json_key_is_rejected(self):
        path = self.path/'003-provision-start-intent.json'
        path.write_bytes(path.read_bytes().replace(b'"phase":"provision"', b'"phase":"verify","phase":"provision"'))
        with self.assertRaises(ValueError):
            self.read()

    def test_added_file_is_not_adopted(self):
        (self.path/'extra').write_bytes(b'unexpected')
        with self.assertRaises(ValueError):
            self.read()

    def test_symlink_hardlink_and_wrong_owner_are_rejected(self):
        path = self.path/'provision.mjs'
        saved = path.read_bytes()
        path.unlink(); path.symlink_to(self.path/'ca.crt')
        with self.assertRaises((ValueError, OSError)):
            self.read()
        path.unlink(); path.write_bytes(saved); path.chmod(0o400); os.chown(path,10001,10001)
        outside = self.data/'linked-source'; os.link(path, outside)
        with self.assertRaises(ValueError):
            self.read()
        outside.unlink(); os.chown(path,0,0)
        with self.assertRaises(ValueError):
            self.read()

    def test_late_change_refused_and_descriptors_close(self):
        baseline = len(os.listdir('/proc/self/fd'))
        evidence = self.read()
        (self.path/'004-provision-completed.json').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            evidence.observation()
        with self.assertRaises(ValueError):
            evidence.close()
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)

    def test_failed_constructor_closes_descriptors(self):
        (self.path/'ca.crt').chmod(0o600)
        baseline = len(os.listdir('/proc/self/fd'))
        for _ in range(3):
            with self.assertRaises(ValueError):
                self.read()
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)

    def test_closed_observation_refuses_reuse(self):
        evidence = self.read(); evidence.close()
        with self.assertRaises(ValueError):
            evidence.observation()


if __name__ == '__main__':
    unittest.main(verbosity=2)
