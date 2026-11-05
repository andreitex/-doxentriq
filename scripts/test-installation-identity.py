"""Local identity record controls; injected root policy, no host installation."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


I = load('installation_identity_test', ROOT / 'scripts/installation_identity.py')
B = load('installation_identity_file_policy', ROOT / 'test/test_checkpoint_admission.py')
ID = '64a2a5f8-04b9-43b5-9807-122d866db1f1'
OTHER = '947aaf58-8ba3-4c42-b4ba-e2a1f87b0cf5'
LUKS = '45fb163d-e8ec-452b-aec0-ffdc391be9fa'
ARGS = ('/srv/autosoft', '/opt/autosoft', '/var/lib/autosoft-storage.luks', 128)


class Fixture:
    def __init__(self):
        root = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', str(ROOT / '.local/installation-identity-v1/fixtures'))).resolve()
        root.mkdir(parents=True, exist_ok=True)
        self.base = Path(tempfile.mkdtemp(prefix='identity-', dir=root))
        self.directory = self.base / 'etc'; self.directory.mkdir(mode=0o700)
        self.files = B.Files(); self.generated = 0; self.blocked = set()
    def factory(self):
        self.generated += 1
        return ID
    def exists(self, path):
        return str(path) in self.blocked or (not isinstance(path, str) and os.path.lexists(path))
    def create(self, args=ARGS):
        return I.create_intent(self.directory, *args, files=self.files, exists=self.exists, uuid_factory=self.factory)
    def read(self):
        return I.read_intent(self.directory, files=self.files)
    def host(self, pending=False, **changes):
        record = dict(zip(('data_dir','install_root','storage_file'), ARGS[:3]), installation_id=ID)
        if pending: record.update(creation_stage='new-luks-created', luks_uuid=LUKS)
        record.update(changes)
        self.files.write(self.directory / ('installation.pending.json' if pending else 'installation.json'), record)
        return record


class IdentityTests(unittest.TestCase):
    def test_fresh_exclusive_commit_retains_canonical_uuid_and_exact_geometry(self):
        f=Fixture(); value=f.create()
        self.assertEqual(value,f.read()); self.assertEqual(f.generated,1)
        self.assertEqual(value['installation_id'],ID)
        self.assertEqual(value['proposal'],I.proposal(*ARGS))
        self.assertTrue(any(event[0]=='directory-fsync-policy' for event in f.files.events))

    def test_existing_intent_refuses_new_identity_and_preserves_exact_bytes(self):
        f=Fixture(); value=f.create(); path=f.directory/I.INTENT; before=path.read_bytes()
        with self.assertRaises(ValueError):f.create()
        self.assertEqual(f.generated,1); self.assertEqual(path.read_bytes(),before)
        self.assertEqual(I.verify_proposal(f.read(),*ARGS),ID)
        self.assertEqual(value,f.read())

    def test_existing_key_pending_and_final_records_block_before_uuid_generation(self):
        for name in ('storage.key','installation.pending.json','installation.json'):
            f=Fixture(); (f.directory/name).write_bytes(b'retained original')
            with self.assertRaises(ValueError):f.create()
            self.assertEqual(f.generated,0); self.assertFalse((f.directory/I.INTENT).exists())
            self.assertEqual((f.directory/name).read_bytes(),b'retained original')

    def test_existing_backing_file_or_link_is_never_adopted(self):
        f=Fixture(); f.blocked.add(ARGS[2])
        with self.assertRaises(ValueError):f.create()
        self.assertEqual(f.generated,0); self.assertFalse((f.directory/I.INTENT).exists())

    def test_lost_commit_ack_preserves_original_identity_without_retry(self):
        f=Fixture(); f.files.failures[I.INTENT]='after'
        with self.assertRaises(OSError):f.create()
        value=f.read()
        with self.assertRaises(ValueError):f.create()
        self.assertEqual(f.generated,1); self.assertEqual(value['installation_id'],ID)

    def test_partial_or_missing_evidence_is_not_repaired(self):
        f=Fixture()
        with self.assertRaises(OSError):f.read()
        (f.directory/I.INTENT).write_bytes(b'{')
        with self.assertRaises(ValueError):f.read()
        with self.assertRaises(ValueError):f.create()
        self.assertEqual(f.generated,0); self.assertEqual((f.directory/I.INTENT).read_bytes(),b'{')

    def test_invalid_paths_and_geometry_fail_before_record_creation(self):
        bad = [('relative',*ARGS[1:]),('/srv/../data',*ARGS[1:]),('//srv/data',*ARGS[1:]),('/srv//data',*ARGS[1:]),('/',*ARGS[1:]),(ARGS[0],ARGS[1],ARGS[0]+'/file',128),(ARGS[0],ARGS[0],ARGS[2],128)]
        bad += [(*ARGS[:3],number) for number in (True,31,128.0,2**31)]
        for args in bad:
            f=Fixture()
            with self.assertRaises(ValueError):f.create(args)
            self.assertEqual(f.generated,0); self.assertFalse((f.directory/I.INTENT).exists())

    def test_noncanonical_uuid_is_rejected(self):
        for value in ('64A2A5F8-04B9-43B5-9807-122D866DB1F1',ID.replace('-',''),None,True,'not-a-uuid'):
            with self.assertRaises((ValueError,TypeError)):I.installation_id(value)

    def test_changed_request_refuses_without_replacing_the_record(self):
        f=Fixture(); value=f.create(); before=(f.directory/I.INTENT).read_bytes()
        for args in (('/srv/other',*ARGS[1:]),(ARGS[0],'/opt/other',*ARGS[2:]),(*ARGS[:2],'/var/lib/other.luks',128),(*ARGS[:3],256)):
            with self.assertRaises(ValueError):I.verify_proposal(value,*args)
        self.assertEqual((f.directory/I.INTENT).read_bytes(),before)

    def test_changed_directory_binding_and_private_policy_are_rejected(self):
        f=Fixture(); value=f.create(); value['directory']['st_ino']='0'
        (f.directory/I.INTENT).write_bytes(I.C.canonical(value))
        with self.assertRaises(ValueError):f.read()
        f.files.untrusted.add(f.directory)
        with self.assertRaises(ValueError):f.read()

    def test_extra_duplicate_and_wrongly_typed_intent_fields_are_rejected(self):
        for change in ({'extra':True},{'schemaVersion':True},{'scope':'foreign'}):
            f=Fixture(); value=f.create(); value.update(change)
            (f.directory/I.INTENT).write_bytes(I.C.canonical(value))
            with self.assertRaises(ValueError):f.read()
        f=Fixture(); f.create(); (f.directory/I.INTENT).write_bytes(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaises(ValueError):f.read()

    def test_exact_final_and_pending_host_records_are_read_only(self):
        for pending in (False,True):
            f=Fixture(); f.create(); value=f.host(pending); files={p.name:p.read_bytes() for p in f.directory.iterdir()}
            self.assertEqual(I.verify_host_record(f.directory,pending=pending,files=f.files),value)
            self.assertEqual({p.name:p.read_bytes() for p in f.directory.iterdir()},files)

    def test_legacy_conflicting_and_wrong_storage_host_binding_are_rejected(self):
        for changes in ({'installation_id':OTHER},{'installation_id':None},{'data_dir':'/srv/other'}):
            f=Fixture(); f.create(); f.host(**changes)
            with self.assertRaises(ValueError):I.verify_host_record(f.directory,files=f.files)
        f=Fixture(); f.create(); value=f.host(); del value['installation_id']
        (f.directory/'installation.json').write_bytes(I.C.canonical(value))
        with self.assertRaises(ValueError):I.verify_host_record(f.directory,files=f.files)

    def test_pending_stage_uuid_extra_fields_and_selector_types_are_rejected(self):
        for changes in ({'creation_stage':'unknown'},{'luks_uuid':'not-a-uuid'},{'extra':True}):
            f=Fixture(); f.create(); f.host(True,**changes)
            with self.assertRaises(ValueError):I.verify_host_record(f.directory,pending=True,files=f.files)
        f=Fixture(); f.create()
        with self.assertRaises(ValueError):I.verify_host_record(f.directory,pending=1,files=f.files)

    def test_config_reference_requires_the_persisted_canonical_id(self):
        f=Fixture(); value=f.create()
        self.assertEqual(I.verify_reference(value,{'installation_id':ID,'admin_origin':'https://admin.example.invalid'}),ID)
        for record in ({},{'installation_id':OTHER},{'installation_id':ID.upper()}):
            with self.assertRaises(ValueError):I.verify_reference(value,record)

    def test_root_policy_failure_prevents_all_writes(self):
        f=Fixture()
        def deny():raise ValueError('injected root refusal')
        f.files.require_root=deny
        with self.assertRaises(ValueError):f.create()
        self.assertEqual(f.generated,0); self.assertEqual(list(f.directory.iterdir()),[])


if __name__=='__main__':unittest.main(verbosity=2)
