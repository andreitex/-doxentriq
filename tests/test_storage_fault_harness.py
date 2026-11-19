"""Synthetic regression only; no real LUKS device or production host paths used."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('storage_fault_candidate', ROOT / 'scripts/test-storage-recovery.py')
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)


class ProtocolTests(unittest.TestCase):
    def test_wrong_passphrase_specific_outcome_and_no_mapper_argument(self):
        seen = []
        def run(argv, timeout):
            seen.append((argv, timeout))
            return subprocess.CompletedProcess(argv, 2, b'', b'No key available with this passphrase.\n')
        result = H.wrong_key_probe({'cryptsetup': '/usr/sbin/cryptsetup'}, PurePosixPath('/synthetic/backing'), PurePosixPath('/synthetic/wrong'), run)
        self.assertTrue(result['testPassphraseOnly'])
        self.assertEqual(seen, [(['/usr/sbin/cryptsetup', 'open', '--test-passphrase', '--key-file', '/synthetic/wrong', '/synthetic/backing'], 90)])

    def test_arbitrary_nonzero_is_not_wrong_passphrase_proof(self):
        for code, out, err in [(0,b'',b''),(1,b'',b'permission denied'),(2,b'',b'No such file'),
                               (2,b'noise',b'No key available with this passphrase.\n'),(127,b'',b'not found')]:
            with self.subTest(code=code, error=err):
                with self.assertRaisesRegex(H.Refused, 'wrong-key-outcome-not-proven'):
                    H.wrong_key_probe({'cryptsetup':'/fake'}, Path('/fake'), Path('/fake'),
                        lambda argv, timeout:subprocess.CompletedProcess(argv, code, out, err))

    def test_missing_script_is_not_guard_proof(self):
        for out, err in [(b'',H.MISMATCH),(b'',b'/missing: No such file or directory\n'),
                         (b'authenticated-guard-bytes-reachable\n',b'ERROR: No installation metadata.\n')]:
            with self.subTest(stderr=err):
                with patch.object(H.os, 'readlink', return_value='mnt:[synthetic-parent]'), self.assertRaisesRegex(H.Refused, 'mount-guard-outcome-not-proven'):
                    H.guard_probe({'unshare':'/fake','bash':'/fake'}, '/data', '/data/root','/source','/out','/empty',
                        {'storage-guard.sh':'a'*64,'lib.sh':'b'*64},
                        lambda argv, timeout:subprocess.CompletedProcess(argv,1,out,err))

    def test_no_repository_or_reboot_claim(self):
        self.assertNotIn('seed_repository', (ROOT/'scripts/test-storage-recovery.py').read_text())
        self.assertTrue(any('reboot recovery was not tested' in x for x in H.LIMITATIONS))
        self.assertTrue(any('resume' in x and 'not tested' in x for x in H.LIMITATIONS))

    def test_path_traversal_and_shell_fragments_refused(self):
        for name in ('/', '/a/../b', '/a//b', '/a;id', '/a\nb', 'relative'):
            with self.subTest(name=name):
                with self.assertRaises(H.Refused):H.safe_path(name)


def fixture(mode, directory):
    directory=Path(directory)
    assert os.geteuid()==0 and os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    etc=directory/'etc'; etc.mkdir(mode=0o700)
    subprocess.run(['/usr/bin/mount','--bind',str(etc),'/etc'],check=True,timeout=10)
    host=Path('/etc/autosoft'); host.mkdir(mode=0o700)
    data=directory/'data'; data.mkdir(mode=0o700)
    install=data/'company/source'; (install/'scripts').mkdir(mode=0o700,parents=True)
    source=directory/'source'; source.mkdir(mode=0o700)
    outside=directory/'outside'; outside.mkdir(mode=0o700)
    empty=directory/'empty'; empty.mkdir(mode=0o700)
    pins={}
    for name in ('storage-guard.sh','lib.sh'):
        raw=(ROOT/'scripts'/name).read_bytes()
        pins[name]=hashlib.sha256(raw).hexdigest()
        H.write_new(install/'scripts'/name,raw)
        H.write_new(source/name,raw)
    H.write_json(host/'installation.json',{'data_dir':str(data),'install_root':str(install)})
    before=subprocess.check_output(['/usr/bin/findmnt','--json','--target',str(data)],text=True)
    if mode=='wrong-hash':pins['lib.sh']='0'*64
    if mode=='missing-library':(source/'lib.sh').unlink()
    if mode=='failed-bind':empty=directory/'absent'
    tool={'unshare':'/usr/bin/unshare','bash':'/usr/bin/bash'}
    if mode=='overlay-only':
        result=H.guard_probe(tool,data,install,source,outside,empty,pins)
        assert result['sourceReachableAfterOverlay'] and result['diagnostic']=='original-guard-mount-mismatch'
    else:
        try:H.guard_probe(tool,data,install,source,outside,empty,pins)
        except H.Refused as error:assert str(error)=='mount-guard-outcome-not-proven'
        else:raise AssertionError('Unexpected fault acceptance')
    assert before==subprocess.check_output(['/usr/bin/findmnt','--json','--target',str(data)],text=True)
    assert (install/'scripts/storage-guard.sh').read_bytes()==(ROOT/'scripts/storage-guard.sh').read_bytes()
    assert not list(outside.iterdir()), 'Namespace mount leaked into parent namespace'
    H.write_json(directory/'result.json',dict(status='passed',mode=mode,
        scope='synthetic namespace fixture; original guard bytes, real bind mounts, no encrypted volume',
        parentMountUnchanged=True,sourceDigests=pins))


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root private namespace required')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        H.protected_parents(cls.base)
        assert cls.base.stat().st_mode&0o777==0o700

    def run_fixture(self,mode):
        case=self.base/('storage-'+uuid.uuid4().hex);case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private',sys.executable,
            '-I','-B',str(Path(__file__).resolve()),'--fixture',mode,str(case)],
            env=dict(H.ENV,DOXENTRIQ_NATIVE_TEST_ROOT=str(self.base)),capture_output=True,timeout=40)
        H.write_new(case/'stdout.log',result.stdout);H.write_new(case/'stderr.log',result.stderr)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertEqual(json.loads((case/'result.json').read_text())['status'],'passed')

    def test_guard_code_remains_reachable_after_install_root_hidden(self):self.run_fixture('overlay-only')
    def test_changed_source_hash_is_not_accepted(self):self.run_fixture('wrong-hash')
    def test_missing_library_is_not_accepted(self):self.run_fixture('missing-library')
    def test_bind_failure_is_not_guard_rejection(self):self.run_fixture('failed-bind')

    def test_evidence_never_overwrites(self):
        case=self.base/('evidence-'+uuid.uuid4().hex);case.mkdir(mode=0o700)
        H.write_json(case/'intent.json',{'original':True})
        with self.assertRaises(FileExistsError):H.write_json(case/'intent.json',{'original':False})
        self.assertEqual(json.loads((case/'intent.json').read_text()),{'original':True})

    def test_protected_read_refuses_symlink_without_following(self):
        case=self.base/('source-'+uuid.uuid4().hex);case.mkdir(mode=0o700)
        H.write_new(case/'regular',b'preserved')
        (case/'link').symlink_to(case/'regular')
        with self.assertRaises(H.Refused):H.read_file(case/'link')
        self.assertEqual((case/'regular').read_bytes(),b'preserved')

    def test_metadata_receipt_must_match(self):
        case=self.base/('records-'+uuid.uuid4().hex);case.mkdir(mode=0o700)
        value=dict(data_dir=str(case/'data'),install_root=str(case/'data/root'),
                   storage_file=str(case/'storage'),installation_id=str(uuid.uuid4()))
        H.write_json(case/'installation.json',value)
        receipt=dict(value,creation_stage='new-luks-created',luks_uuid=str(uuid.uuid4()))
        receipt['installation_id']=str(uuid.uuid4())
        H.write_json(case/'installation.storage-receipt.json',receipt)
        with self.assertRaisesRegex(H.Refused,'invalid-foundation-records'):H.metadata(case)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
