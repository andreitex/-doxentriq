"""Portable injected store controls; no native IO/Git/signing/VM effects."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


M=load('company_platform_store_under_test',ROOT/'scripts/company_platform_store.py')
T=load('authenticated_seed_test_adapter',ROOT/'tests/test_authenticated_seed.py')


def chmod(self,fd,mode):
    self.chmod_calls.append((fd,mode))
    if self.fail_chmod: raise OSError('injected-chmod')
    node=self.handles[fd];node['info']['st_mode']=stat.S_IFMT(node['info']['st_mode'])|mode
    self.tick+=1;node['info']['st_ctime_ns']=self.tick
    if self.after_chmod:self.after_chmod(fd)


# The independently trusted adapter adds the concrete fd-only mode operation;
# the production SeedFiles API and caps remain untouched.
T.SeedBackend.chmod=chmod


class Fixture:
    def __init__(self,archive=b'original-captured-gzip-bytes'):
        f=T.Fixture();self.f=f;self.backend=f.backend
        f.files.close();f.storage.active=False
        # Synthetic prior preparation happens before acquiring the new live
        # storage guard; the actual store API never refreshes outer controls.
        self.base=f.DATA+'/company/platform-releases'
        self.backend.directory(self.base,mode=0o700)
        self.backend.chmod_calls=[];self.backend.fail_chmod=False;self.backend.after_chmod=None
        f.files=T.B.SeedFiles(SimpleNamespace(SeedBackend=T.SeedBackend),self.backend)
        f.storage=T.B.SeedStorage(f.DATA,f.INSTALL,startup_module=f.S,files=f.files,commands=f.commands)
        f.source.files[M.MODULE_PATH]=(ROOT/'scripts/company_platform_store.py').read_bytes()
        f.source.git_modes[M.MODULE_PATH]='100644'
        f.source.metadata['sourceTree']=T.independent_source_tree(f.source.files,f.source.git_modes)
        f.source.configs={name:M.canonical({'fixture':name}) for name in M.CONFIGS}
        f.source.archive_bytes=archive
        records={**f.source.configs,M.ARCHIVE:archive}
        release=dict(schemaVersion=4,version='test-only',createdAt='2026-10-13T00:00:00Z',architecture='x86_64',
            files={name:dict(bytes=len(raw),sha256=M.digest(raw)) for name,raw in records.items()})
        f.source.provenance={'release.json':M.canonical(release),'release.sig':b'captured-test-signature',
            'company-signing-public-key.pem':b'captured-test-public-key'}
        f.source.metadata.update(release=release,releaseSha256=M.digest(f.source.provenance['release.json']),
            platformManifestSha256=M.digest(f.source.configs['platform-sources.json']),
            archiveSha256=M.digest(archive),archiveBytes=len(archive),signingKeyFingerprint='a'*64)
        self.bind()

    def bind(self):
        f=self.f
        _,request,action,_=M.authenticated_store_request(f.source,verifier_module=f.V,
            bootstrap_module=T.B,storage=f.storage,operation_id=f.OP)
        f.parent.arguments.stage='company-platform-store';f.parent.arguments.request=request;f.parent.arguments.action=action
        self.root=self.base+'/'+f.source.metadata['releaseSha256']

    def store(self,clock=None):
        f=self.f
        return M.store_authenticated_platform(f.source,verifier_module=f.V,bootstrap_module=T.B,
            parent_module=f.P,parent=f.parent,storage=f.storage,backend_module=SimpleNamespace(SeedBackend=T.SeedBackend),
            backend=self.backend,operation_id=f.OP,clock=clock)


class CompanyPlatformStoreTests(unittest.TestCase):
    def setUp(self):
        M.UNRELEASED.clear();T.B.SEED_UNRELEASED.clear();self.fixtures=[]
    def tearDown(self):
        for fixture in self.fixtures:
            fixture.backend.fail_close=None
            try:fixture.f.files.close()
            except ValueError:pass
        M.UNRELEASED.clear();T.B.SEED_UNRELEASED.clear()
    def fixture(self,*args,**kwargs):
        f=Fixture(*args,**kwargs);self.fixtures.append(f);return f
    def deny(self,f,code=None):
        with self.assertRaises((ValueError,OSError,KeyError,TypeError)) as raised:f.store()
        if code:self.assertIn(code,str(raised.exception))
        return raised.exception

    def test_exact_original_ten_inputs_and_readonly_final_tree(self):
        f=self.fixture();result=f.store()
        expected={*M.CONFIGS,*M.PROVENANCE,M.ARCHIVE,'intent.json','verified.json'}
        names={path[len(f.root)+1:] for path in f.backend.nodes if path.startswith(f.root+'/')}
        self.assertEqual(names,expected)
        for name in (*M.CONFIGS,*M.PROVENANCE,M.ARCHIVE):
            expected_raw=f.f.source.configs.get(name,f.f.source.provenance.get(name,f.f.source.archive_bytes))
            self.assertEqual(f.backend.nodes[f.root+'/'+name]['raw'],expected_raw)
            self.assertEqual(stat.S_IMODE(f.backend.nodes[f.root+'/'+name]['info']['st_mode']),0o400)
        self.assertEqual(stat.S_IMODE(f.backend.nodes[f.root]['info']['st_mode']),0o500)
        self.assertTrue(result['ownedStoreHandlesReleased']);self.assertFalse(result['executionAuthorized'])
        self.assertTrue(result['outerSourceParentStorageContextsRequireClosure']);self.assertTrue(result['fullInstallDenied'])
        self.assertTrue(f.f.storage.active);self.assertTrue(f.backend.handles)
        self.assertNotIn('/srv/backing.luks',f.backend.reads);self.assertNotIn('/etc/autosoft/storage.key',f.backend.reads)

    def test_intent_durable_before_first_artifact(self):
        f=self.fixture();observed=[];original=f.backend.sync
        def sync(fd):
            observed.append(next(path for path,node in f.backend.nodes.items() if node is f.backend.handles[fd]))
            return original(fd)
        f.backend.sync=sync
        def create(path):
            if path.startswith(f.root+'/') and not path.endswith('/intent.json'):
                self.assertIn(f.root+'/intent.json',observed)
                self.assertIn(f.root,observed)
        f.backend.after_create=create;f.store()

    def test_terminal_written_before_directory_mode_transition(self):
        f=self.fixture()
        def finalized(fd):
            self.assertIn(f.root+'/verified.json',f.backend.nodes)
            self.assertEqual(len([p for p in f.backend.nodes if p.startswith(f.root+'/')]),12)
        f.backend.after_chmod=finalized;f.store();self.assertEqual(len(f.backend.chmod_calls),1)

    def test_archive_above_seed_cap_uses_separate_bound(self):
        f=self.fixture(b'x'*(9*1024**2+1));f.store()
        self.assertEqual(len(f.backend.nodes[f.root+'/'+M.ARCHIVE]['raw']),9*1024**2+1)

    def test_oversize_archive_denies_before_output(self):
        f=self.fixture();f.f.source.archive_bytes=b'x'*(M.ARCHIVE_MAX+1)
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_archive_pin_mismatch_denies_before_output(self):
        f=self.fixture();f.f.source.archive_bytes=b'drift'
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_bool_archive_length_denies(self):
        f=self.fixture();f.f.source.metadata['archiveBytes']=True
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_extra_config_denies_before_output(self):
        f=self.fixture();f.f.source.configs['extra']=b'{}'
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_missing_provenance_denies_before_output(self):
        f=self.fixture();del f.f.source.provenance['release.sig']
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_config_signed_row_mismatch_denies(self):
        f=self.fixture();f.f.source.metadata['release']['files']['images.lock.json']['sha256']='f'*64
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_release_raw_hash_drift_denies(self):
        f=self.fixture();f.f.source.provenance['release.json']+=b' '
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_unissued_same_class_denies_before_properties(self):
        f=self.fixture();forged=T.HeldSource();forged.files=None;f.f.source=forged
        self.deny(f);self.assertEqual(f.backend.effects,[]);self.assertEqual(forged.calls,0)

    def test_missing_live_validator_denies(self):
        f=self.fixture();del f.f.V.require_platform_source
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_wrong_parent_action_denies_before_write(self):
        f=self.fixture();f.f.parent.arguments.action='f'*64
        self.deny(f,'company_store_parent_binding');self.assertEqual(f.backend.effects,[])

    def test_wrong_stage_denies_before_write(self):
        f=self.fixture();f.f.parent.arguments.stage='repository-seed'
        self.deny(f,'company_store_parent_binding');self.assertEqual(f.backend.effects,[])

    def test_nonfresh_storage_denies_before_write(self):
        f=self.fixture();f.f.storage.fresh=False
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_inactive_storage_denies_before_write(self):
        f=self.fixture();f.f.storage.active=False
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_backend_identity_mismatch_denies(self):
        f=self.fixture();f.f.storage.files.backend=object()
        self.deny(f);self.assertEqual(f.backend.effects,[])
        f.f.storage.files.backend=f.backend

    def test_existing_base_child_or_orphan_never_adopted(self):
        f=self.fixture();f.backend.directory(f.base+'/orphan');f.backend.change(f.base)
        self.deny(f);self.assertEqual(f.backend.effects,[]);self.assertIn(f.base+'/orphan',f.backend.nodes)

    def test_wrong_parent_uid_denies(self):
        f=self.fixture();f.backend.nodes[f.base]['info']['st_uid']=10001
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_symlink_parent_denies(self):
        f=self.fixture();f.backend.nodes[f.base]['info']['st_mode']=stat.S_IFLNK|0o700
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_same_encrypted_device_required(self):
        f=self.fixture();f.backend.nodes[f.base]['info']['st_dev']=2
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_source_expiry_after_intent_retains_partial_without_archive(self):
        f=self.fixture();f.backend.after_create=lambda path:setattr(f.f.source,'live',False) if path.endswith('/intent.json') else None
        self.deny(f);self.assertIn(f.root+'/intent.json',f.backend.nodes)
        self.assertNotIn(f.root+'/'+M.ARCHIVE,f.backend.nodes)

    def test_parent_death_after_intent_retains_partial(self):
        f=self.fixture();f.backend.after_create=lambda path:setattr(f.f.parent,'live',False) if path.endswith('/intent.json') else None
        self.deny(f);self.assertIn(f.root+'/intent.json',f.backend.nodes)

    def test_mount_drift_after_intent_denies(self):
        f=self.fixture();f.backend.after_create=lambda path:f.f.mount['mapperIdentity'].__setitem__(1,'123') if path.endswith('/intent.json') else None
        self.deny(f);self.assertIn(f.root+'/intent.json',f.backend.nodes)

    def test_owned_parent_extra_entry_is_not_rebased(self):
        f=self.fixture()
        def extra(path):
            if path.endswith('/intent.json'):f.backend.file(f.root+'/extra',b'unknown');f.backend.change(f.root)
        f.backend.after_create=extra;self.deny(f,'company_store_parent_transition')
        self.assertEqual(f.backend.nodes[f.root+'/extra']['raw'],b'unknown')

    def test_readonly_ancestor_timestamp_drift_denies(self):
        f=self.fixture()
        def drift(path):
            if path.endswith('/intent.json'):f.backend.nodes[f.f.DATA+'/company']['info']['st_ctime_ns']+=1
        f.backend.after_create=drift;self.deny(f,'company_store_held_identity')

    def test_output_inode_replacement_denies(self):
        f=self.fixture()
        original_sync=f.backend.sync
        def sync_unlinked(fd):
            # A real held inode can still fsync after its pathname is replaced.
            if not any(node is f.backend.handles[fd] for node in f.backend.nodes.values()):return None
            return original_sync(fd)
        f.backend.sync=sync_unlinked
        def replace(path):
            if path.endswith('/intent.json'):
                node=f.backend.nodes[path];f.backend.nodes[path]=dict(info=dict(node['info'],st_ino=999999),raw=node['raw'])
        f.backend.after_create=replace;self.deny(f)

    def test_final_readback_after_directory_chmod_denies_byte_drift(self):
        f=self.fixture()
        def drift(fd):
            node=f.backend.nodes[f.root+'/'+M.ARCHIVE];node['raw']=b'!' + node['raw'][1:]
        f.backend.after_chmod=drift;self.deny(f,'company_store_held_bytes')

    def test_final_inventory_after_directory_chmod_denies_extra_leaf(self):
        f=self.fixture();f.backend.after_chmod=lambda fd:f.backend.file(f.root+'/extra',b'unknown',mode=0o400)
        self.deny(f);self.assertIn(f.root+'/extra',f.backend.nodes)

    def test_chmod_false_ack_is_unknown(self):
        f=self.fixture();f.backend.chmod=lambda fd,mode:False
        self.deny(f,'company_store_chmod_unknown')

    def test_nonhex_verified_key_fingerprint_denies_before_write(self):
        f=self.fixture();f.f.source.metadata['signingKeyFingerprint']='g'*64
        self.deny(f);self.assertEqual(f.backend.effects,[])

    def test_written_bytes_corruption_denies(self):
        f=self.fixture()
        def corrupt(fd):
            node=f.backend.handles[fd]
            if node['raw']:node['raw']=b'!' + node['raw'][1:]
        f.backend.after_write=corrupt;self.deny(f,'company_store_held_bytes')

    def test_intent_sync_failure_preserves_no_artifact(self):
        f=self.fixture();f.backend.fail_sync='intent.json'
        self.deny(f);self.assertIn(f.root+'/intent.json',f.backend.nodes)
        self.assertNotIn(f.root+'/'+M.ARCHIVE,f.backend.nodes)

    def test_chmod_failure_preserves_complete_unacknowledged_tree(self):
        f=self.fixture();f.backend.fail_chmod=True
        self.deny(f);self.assertIn(f.root+'/verified.json',f.backend.nodes)
        self.assertEqual(stat.S_IMODE(f.backend.nodes[f.root]['info']['st_mode']),0o700)

    def test_unexpected_chmod_identity_denies(self):
        f=self.fixture();f.backend.after_chmod=lambda fd:f.backend.handles[fd]['info'].__setitem__('st_nlink',123)
        self.deny(f,'company_store_mode_transition')

    def test_owned_close_uncertainty_attempts_all_and_latches(self):
        f=self.fixture();outer=set(f.backend.handles)
        def mark(path):
            if path.endswith('/intent.json'):
                f.backend.fail_close=next(fd for fd,node in f.backend.handles.items() if node is f.backend.nodes[path])
        f.backend.after_create=mark;self.deny(f,'company_store_close_unknown')
        self.assertEqual(len(M.UNRELEASED),1);self.assertIs(M.UNRELEASED[0][0],f.backend)
        self.assertEqual(M.UNRELEASED[0][1],f.backend.fail_close)
        remaining=set(f.backend.handles);self.assertEqual(remaining-outer,{f.backend.fail_close})
        count=len(f.backend.effects);self.deny(f);self.assertEqual(len(f.backend.effects),count)

    def test_logical_timeout_denies_before_output(self):
        f=self.fixture();ticks=iter([0,601]);clock=lambda:next(ticks,601)
        with self.assertRaises(ValueError):f.store(clock=clock)
        self.assertEqual(f.backend.effects,[])

    def test_no_scope_flag_or_native_default_substitutes_authority(self):
        with self.assertRaises(TypeError):M.store_authenticated_platform(object(),nativeAuthorized=True)
        with self.assertRaises(ValueError):M.StoreFiles(SimpleNamespace(SeedBackend=T.SeedBackend),object())


if __name__ == '__main__':unittest.main(verbosity=2)
