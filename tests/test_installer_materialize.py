"""Retained small-byte controls; POSIX directory/ownership/native durability injected."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace, MappingProxyType
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
M=load('installer_materialize_under_test',ROOT/'scripts/installer_materialize.py')
V=load('trusted_verifier_interface_fixture',ROOT/'scripts/verify-release.py')
ARTIFACT=Path(os.environ['AUTOSOFT_TEST_ARTIFACT_ROOT'])
if not ARTIFACT.is_absolute() or not ARTIFACT.is_dir():raise RuntimeError('retained-test-parent-required')

class Files:
    """Real regular-file bytes/FDs, injected root modes, directory FDs and fsync."""
    def __init__(self):
        self.opened={};self.next_directory=100000;self.modes={};self.owners={};self.links={}
        self.effects=[];self.closed=[];self.hooks={};self.counters={};self.time_overrides={};self.directory_metadata={}
    def hook(self,name,*args):
        self.counters[name]=self.counters.get(name,0)+1
        callback=self.hooks.get(name)
        if callback:return callback(*args)
    def info(self,path,raw):
        path=Path(path);mode=raw.st_mode
        if stat.S_ISDIR(mode):mode=stat.S_IFDIR|self.modes.get(path,0o700)
        elif stat.S_ISREG(mode):mode=stat.S_IFREG|self.modes.get(path,0o600)
        uid,gid=self.owners.get(path,(0,0))
        if stat.S_ISDIR(mode):
            if path not in self.directory_metadata:
                self.directory_metadata[path]=[2+sum(child.is_dir() for child in path.iterdir()),raw.st_size,raw.st_mtime_ns,raw.st_ctime_ns]
            link,size,mt,ct=self.directory_metadata[path]
        else:link,size,mt,ct=raw.st_nlink,raw.st_size,raw.st_mtime_ns,raw.st_ctime_ns
        nlink=self.links.get(path,link);mtime,ctime=self.time_overrides.get(path,(mt,ct))
        return SimpleNamespace(st_dev=raw.st_dev,st_ino=raw.st_ino,st_mode=mode,st_uid=uid,st_gid=gid,
            st_nlink=nlink,st_size=size,st_mtime_ns=mtime,st_ctime_ns=ctime)
    def directory_changed(self,path,*,new_directory):
        self.info(path,os.stat(path,follow_symlinks=False));row=self.directory_metadata[path]
        row[0]+=1 if new_directory else 0;row[1]+=1;row[2]+=1;row[3]+=1
    def lstat(self,path):
        self.hook('lstat',Path(path));return self.info(path,os.stat(path,follow_symlinks=False))
    def open(self,parent,name,directory):
        self.hook('open',parent,name,directory)
        path=Path(name) if parent is None else self.opened[parent]['path']/name
        if directory:
            fd=self.next_directory;self.next_directory+=1;raw=os.stat(path,follow_symlinks=False)
            self.opened[fd]=dict(path=path,directory=True,dev=raw.st_dev,ino=raw.st_ino)
        else:
            fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0));os.set_inheritable(fd,False)
            self.opened[fd]=dict(path=path,directory=False)
        return fd
    def mkdir(self,parent,name):
        path=self.opened[parent]['path']/name;self.effects.append(('mkdir',path));self.hook('before_mkdir',path)
        path.mkdir();self.modes[path]=0o700;self.directory_changed(path.parent,new_directory=True);self.hook('mkdir',path)
    def create(self,parent,name):
        path=self.opened[parent]['path']/name;self.effects.append(('create',path));self.hook('before_create',path)
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0),0o600);os.set_inheritable(fd,False)
        self.opened[fd]=dict(path=path,directory=False);self.modes[path]=0o600
        self.directory_changed(path.parent,new_directory=False);self.hook('create',path,fd);return fd
    def fstat(self,fd):
        self.hook('fstat',fd);row=self.opened[fd];path=row['path']
        if row['directory']:
            info=self.info(path,os.stat(path,follow_symlinks=False));info.st_dev=row['dev'];info.st_ino=row['ino'];return info
        info=self.info(path,os.fstat(fd))
        # Windows path ctime differs from CRT ctime; normalize only this injected fixture.
        if path.exists():info.st_ctime_ns=os.stat(path,follow_symlinks=False).st_ctime_ns
        return info
    def cloexec(self,fd):
        result=self.hook('cloexec',fd)
        return result if result is not None else self.opened[fd]['directory'] or not os.get_inheritable(fd)
    def write(self,fd,raw):
        result=self.hook('write',fd,raw)
        return result if result is not None else os.write(fd,raw)
    def read(self,fd,size,offset):
        result=self.hook('read',fd,size,offset)
        if result is not None:return result
        os.lseek(fd,offset,os.SEEK_SET);return os.read(fd,size)
    def chmod(self,fd,mode):
        self.hook('chmod',fd,mode);path=self.opened[fd]['path'];self.modes[path]=mode
    def sync(self,fd):
        self.hook('sync',fd)
        if not self.opened[fd]['directory']:os.fsync(fd)
    def names(self,fd,limit):
        self.hook('names',fd,limit);rows=sorted(child.name for child in self.opened[fd]['path'].iterdir())
        M.require(len(rows)<=limit);return rows
    def close(self,fd):
        self.closed.append(fd);result=self.hook('close',fd)
        if result is not None:return result
        row=self.opened.pop(fd)
        if not row['directory']:os.close(fd)
    def fixture_release_unknown(self):
        # Only retained local fixture references, never a native backend or reused FD.
        self.hooks.pop('close',None)
        for fd in list(self.opened):self.close(fd)

class Clock:
    def __init__(self):self.now=1.0
    def __call__(self):return self.now

class MaterializationControls(unittest.TestCase):
    def setUp(self):
        self.parent=ARTIFACT/('case-'+uuid.uuid4().hex);self.parent.mkdir()
        self.name='install-'+uuid.uuid4().hex;self.files=Files();self.checks=[];self.clock=Clock()
        self.maps=[{name:('inert '+name+'\n').encode() for name in names} for names in (M.SOURCES,M.TEMPLATES,M.CONFIGS)]
        self.provenance={'release.json':b'{"fixture":"signed-record-shape"}\n','release.sig':b's'*64,
            'company-signing-public-key.pem':b'fixture PEM: not cryptographic authority\n'}
        self.meta=dict(status='SCHEMA3_SOURCE_DEPLOYMENT_AND_IMAGE_BYTES_AUTHENTICATED',sourceFileCount=44,
            deploymentFileCount=10,signatureVerified=True,sourceAuthenticated=True,deploymentAuthenticated=True,
            productionAuthorized=False,nativeAuthorized=False,installerActivated=False,trustContinuesAfterReturn=False,
            releaseSha256=hashlib.sha256(self.provenance['release.json']).hexdigest())
        self.fail_check=False;self.held=self.make_held()
        self.assertFalse(M.UNRELEASED_HANDLES)
    def make_held(self):
        def check():
            self.checks.append(len(self.files.effects))
            if self.fail_check:raise ValueError('injected-held-drift')
        return V.HeldDeployment(*self.maps,self.meta,check,provenance=self.provenance)
    def tearDown(self):
        # Fixture-only release after assertions; keep every file/tree and raw outcome.
        self.files.fixture_release_unknown();M.UNRELEASED_HANDLES.clear()
    def context(self,**kw):
        return M.materialized_deployment(self.held,self.parent,self.name,files=self.files,clock=self.clock,**kw)
    def deny(self):
        with self.assertRaises((M.MaterializationUnavailable,V.ReleaseUnavailable,ValueError,OSError)):
            with self.context():self.fail('must not yield')
    def test_exact_catalogs_and_retained_bytes_never_execute(self):
        self.assertEqual(M.SOURCES,V.COMPANY_SOURCES);self.assertEqual(M.TEMPLATES,V.COMPANY_DEPLOYMENT)
        self.assertEqual(M.CONFIGS,V.SIGNED_DEPLOYMENT_FILES);self.maps[0]['scripts/install.sh']=b'raise RuntimeError("must not execute")\n'
        self.held=self.make_held()
        with self.context() as tree:
            root=tree.root;proofs=tree.files
            expected={**self.maps[0],**self.maps[1],**{'company-release/'+k:v for k,v in {**self.maps[2],**self.provenance}.items()}}
            self.assertEqual(set(proofs),set(expected));self.assertEqual(len(proofs),62)
            self.assertEqual(len(list(root.rglob('*'))),66)
            for name,raw in expected.items():self.assertEqual((root/name).read_bytes(),raw)
            self.assertEqual(tree.release_sha256,self.meta['releaseSha256']);tree.recheck()
            self.assertTrue(all(self.files.modes[p]==0o500 for p in tree._dirs))
            self.assertTrue(all(self.files.modes[p]==0o400 for p in tree._records))
        self.assertFalse(self.files.opened);self.assertTrue(self.checks and self.checks[0]==0)
    def test_immutable_hash_map_and_expired_tree(self):
        with self.context() as tree:
            with self.assertRaises(TypeError):tree.files['new']=b'x'
            with self.assertRaises(TypeError):tree.files[M.SOURCES[0]]['bytes']=0
        for field in ('root','files','release_sha256'):
            with self.assertRaises(M.MaterializationUnavailable):getattr(tree,field)
    def test_expired_held_denies_before_effects(self):
        self.held._expire();self.deny();self.assertEqual(self.files.effects,[])
    def test_held_source_drift_mid_write_preserves_partial(self):
        self.files.hooks['write']=lambda fd,raw:setattr(self,'fail_check',True)
        self.deny();self.assertTrue((self.parent/self.name).is_dir());self.assertTrue(self.files.effects)
        self.assertFalse(self.files.opened)
    def test_held_provenance_drift_after_caller_denies(self):
        with self.assertRaises(ValueError):
            with self.context():self.fail_check=True
        self.assertFalse(self.files.opened)
    def test_held_expiration_denies_tree_access(self):
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context() as tree:
                self.held._expire()
                with self.assertRaises(M.MaterializationUnavailable):tree.root
    def test_counterfeit_authority_flags_and_boolean_counts(self):
        for key,value in [('productionAuthorized',True),('signatureVerified',1),('sourceFileCount',True),('deploymentFileCount',True)]:
            with self.subTest(key=key):
                self.meta[key]=value;self.held=self.make_held();self.deny();self.assertEqual(self.files.effects,[])
                self.meta[key]=44 if key=='sourceFileCount' else 10 if key=='deploymentFileCount' else key=='signatureVerified'
    def test_closed_maps_missing_extra_and_nonbytes(self):
        for kind in ('missing','extra','mutable','nonbytes'):
            with self.subTest(kind=kind):
                values=dict(self.maps[0])
                if kind=='missing':values.pop(M.SOURCES[0])
                if kind=='extra':values['scripts/../outside.py']=b'x'
                if kind=='nonbytes':values[M.SOURCES[0]]=bytearray(b'x')
                if kind in ('missing','extra','nonbytes'):
                    fake=SimpleNamespace(active=True,recheck=lambda:None,sources=MappingProxyType(values),templates=MappingProxyType(self.maps[1]),
                        configs=MappingProxyType(self.maps[2]),provenance=MappingProxyType(self.provenance),metadata=MappingProxyType(self.meta))
                else:
                    fake=SimpleNamespace(active=True,recheck=lambda:None,sources=values,templates=MappingProxyType(self.maps[1]),
                        configs=MappingProxyType(self.maps[2]),provenance=MappingProxyType(self.provenance),metadata=MappingProxyType(self.meta))
                with self.assertRaises(M.MaterializationUnavailable):
                    with M.materialized_deployment(fake,self.parent,self.name,files=self.files):self.fail('yield')
                self.assertEqual(self.files.effects,[])
    def test_release_hash_and_signature_length_before_effects(self):
        for kind in ('hash','signature'):
            with self.subTest(kind=kind):
                old=dict(self.meta);prior=dict(self.provenance)
                if kind=='hash':self.meta['releaseSha256']='0'*64
                else:self.provenance['release.sig']=b's'*63
                self.held=self.make_held();self.deny();self.assertEqual(self.files.effects,[])
                self.meta=old;self.provenance=prior
    def test_leaf_and_joint_caps_before_effects(self):
        for kind in ('leaf','joint','templates','config'):
            with self.subTest(kind=kind):
                old=[dict(x) for x in self.maps]
                if kind=='leaf':self.maps[0][M.SOURCES[0]]=b'x'*(M.FILE_LIMIT+1)
                if kind=='joint':
                    for name in M.SOURCES[:17]:self.maps[0][name]=b'x'*M.FILE_LIMIT
                if kind=='templates':
                    for name in M.TEMPLATES[:5]:self.maps[1][name]=b'x'*M.FILE_LIMIT
                if kind=='config':self.maps[2]['company-sources.json']=b'x'*32769
                self.held=self.make_held();self.deny();self.assertEqual(self.files.effects,[]);self.maps=old
    def test_name_traversal_absolute_and_noncanonical_refused(self):
        for name in ('../outside','install-'+('a'*31),'install-'+('A'*32),'install-'+('a'*32)+'/child',str(self.parent/'absolute')):
            with self.subTest(name=name):
                self.name=name;self.deny();self.assertEqual(self.files.effects,[])
    def test_existing_output_never_adopted_or_overwritten(self):
        path=self.parent/self.name;path.mkdir();(path/'sentinel').write_bytes(b'preserve')
        self.deny();self.assertEqual((path/'sentinel').read_bytes(),b'preserve');self.assertEqual(self.files.effects,[])
    def test_parent_mode_and_owner_refused_before_mkdir(self):
        for kind in ('mode','owner'):
            with self.subTest(kind=kind):
                if kind=='mode':self.files.modes[self.parent]=0o755
                else:self.files.owners[self.parent]=(1000,0)
                self.deny();self.assertEqual(self.files.effects,[]);self.files.modes.clear();self.files.owners.clear()
    def test_symlink_type_refused_before_mkdir(self):
        original=self.files.lstat
        def altered(path):
            info=original(path)
            if path==self.parent:info.st_mode=stat.S_IFLNK|0o777
            return info
        self.files.lstat=altered;self.deny();self.assertEqual(self.files.effects,[])
    def test_ancestor_metadata_drift_not_rebased(self):
        ancestor=self.parent.parent
        def change(path):
            if path==self.parent/self.name:
                info=self.files.lstat(ancestor);self.files.time_overrides[ancestor]=(info.st_mtime_ns+1,info.st_ctime_ns)
        self.files.hooks['mkdir']=change;self.deny();self.assertTrue((self.parent/self.name).exists())
    def test_short_writes_complete_exact_bytes(self):
        self.files.hooks['write']=lambda fd,raw:os.write(fd,raw[:3])
        with self.context() as tree:
            self.assertEqual((tree.root/M.SOURCES[0]).read_bytes(),self.maps[0][M.SOURCES[0]])
        self.assertGreater(self.files.counters['write'],62)
    def test_zero_boolean_or_excess_write_retains_partial(self):
        for returned in (0,True,999999):
            with self.subTest(returned=returned):
                self.name='install-'+uuid.uuid4().hex;self.files.hooks['write']=lambda fd,raw,value=returned:value
                self.deny();self.assertTrue((self.parent/self.name).exists());self.assertFalse(self.files.opened)
    def test_write_exception_preserves_file_and_attempts_closes(self):
        def fail(fd,raw):os.write(fd,raw[:1]);raise OSError('injected-write')
        self.files.hooks['write']=fail;self.deny()
        self.assertEqual(len(list((self.parent/self.name).rglob('*'))),5);self.assertFalse(self.files.opened)
    def test_fsync_and_chmod_failures_preserve_partial(self):
        for operation in ('sync','chmod'):
            with self.subTest(operation=operation):
                self.name='install-'+uuid.uuid4().hex
                def fail(*args):raise OSError('injected-effect-ack')
                self.files.hooks[operation]=fail;self.deny();self.assertTrue((self.parent/self.name).exists())
                self.assertFalse(self.files.opened);self.files.hooks.pop(operation)
    def test_readback_corruption_or_extra_bytes_refused(self):
        for raw in (b'corrupt',b'x'*65537):
            with self.subTest(raw_length=len(raw)):
                self.name='install-'+uuid.uuid4().hex;self.files.hooks['read']=lambda *args,value=raw:value
                self.deny();self.assertTrue((self.parent/self.name).exists());self.assertFalse(self.files.opened)
    def test_first_fstat_after_create_releases_registered_fd(self):
        def arm(path,fd):
            def fail(target):
                if target==fd:raise OSError('injected-first-fstat')
            self.files.hooks['fstat']=fail
        self.files.hooks['create']=arm;self.deny();self.assertFalse(self.files.opened)
    def test_cloexec_failure_still_releases_owned_descriptor(self):
        self.files.hooks['cloexec']=lambda fd:False;self.deny();self.assertFalse(self.files.opened)
    def test_hardlink_or_file_type_refused(self):
        def created(path,fd):self.files.links[path]=2
        self.files.hooks['create']=created;self.deny();self.assertFalse(self.files.opened)
    def test_output_content_drift_and_restoration_does_not_revive(self):
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context() as tree:
                path=tree.root/M.SOURCES[0];raw=path.read_bytes();path.write_bytes(raw+b'x')
                with self.assertRaises(M.MaterializationUnavailable):tree.recheck()
                path.write_bytes(raw)
                with self.assertRaises(M.MaterializationUnavailable):tree.root
        self.assertFalse(self.files.opened)
    def test_all_output_getters_refuse_drift_before_return(self):
        for field in ('root','files','release_sha256'):
            with self.subTest(field=field):
                self.name='install-'+uuid.uuid4().hex
                with self.assertRaises(M.MaterializationUnavailable):
                    with self.context() as tree:
                        path=tree.root/M.SOURCES[0];path.write_bytes(path.read_bytes()+b'changed')
                        with self.assertRaises(M.MaterializationUnavailable):getattr(tree,field)
                self.assertFalse(self.files.opened)
    def test_directory_replacement_denied_with_original_fd_held(self):
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context() as tree:
                path=tree.root/'scripts';original=self.files.lstat
                def replaced(target):
                    info=original(target)
                    if target==path:info.st_ino+=1
                    return info
                self.files.lstat=replaced
                tree.recheck()
        self.assertFalse(self.files.opened)
    def test_unknown_extra_output_denies_postcaller(self):
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context() as tree:(tree.root/'unknown').write_bytes(b'preserve unknown')
        self.assertTrue((self.parent/self.name/'unknown').exists());self.assertFalse(self.files.opened)
    def test_unknown_sibling_parent_inventory_denied(self):
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context():(self.parent/'unknown').write_bytes(b'preserve')
    def test_parent_inventory_bound_no_output(self):
        original=self.files.names
        def many(fd,limit):
            if self.files.opened[fd]['path']==self.parent:return ['entry-'+str(i) for i in range(1025)]
            return original(fd,limit)
        self.files.names=many
        # A backend must enforce its supplied limit too; helper independently checks this below.
        self.deny();self.assertEqual(self.files.effects,[])
    def test_close_failure_attempts_all_and_latches_exact_reference(self):
        failed=[]
        def fail_first(fd):
            if not failed:failed.append(fd);raise OSError('injected-close')
        self.files.hooks['close']=fail_first;self.deny()
        self.assertEqual(M.UNRELEASED_HANDLES,[(self.files,failed[0])]);self.assertEqual(set(self.files.opened),set(failed))
        previous=len(self.files.effects)
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context():self.fail('unknown must deny')
        self.assertEqual(len(self.files.effects),previous);self.assertEqual(self.files.closed.count(failed[0]),1)
    def test_false_close_acknowledgment_is_unknown(self):
        self.files.hooks['close']=lambda fd:False;self.deny()
        self.assertTrue(M.UNRELEASED_HANDLES);self.assertTrue(self.files.opened)
    def test_terminal_close_failure_cannot_report_completion(self):
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context() as tree:
                selected=next(iter(tree._records.values()))[0]
                self.files.hooks['close']=lambda fd:False if fd==selected else None
        self.assertEqual(M.UNRELEASED_HANDLES,[(self.files,selected)])
        self.assertEqual(set(self.files.opened),{selected})
    def test_caller_exception_checks_provenance_and_releases(self):
        before=0
        with self.assertRaisesRegex(RuntimeError,'caller-failure'):
            with self.context():before=len(self.checks);raise RuntimeError('caller-failure')
        self.assertGreater(len(self.checks),before);self.assertFalse(self.files.opened)
    def test_preparation_deadline_preserves_created_tree(self):
        self.files.hooks['mkdir']=lambda path:setattr(self.clock,'now',61.0)
        self.deny();self.assertTrue((self.parent/self.name).exists());self.assertFalse(self.files.opened)
    def test_postcaller_recheck_has_own_bounded_window(self):
        with self.assertRaises(M.MaterializationUnavailable):
            with self.context() as tree:
                self.clock.now=600.0;tree.recheck()
                def elapsed(*args):self.clock.now+=61
                self.files.hooks['read']=elapsed
                with self.assertRaises(M.MaterializationUnavailable):tree.recheck()
        self.assertFalse(self.files.opened)
    def test_native_backend_rejects_windows_without_effects(self):
        with mock.patch.object(M,'os',SimpleNamespace(name='nt')):
            with self.assertRaises(M.MaterializationUnavailable):M.NativeFiles()
    def test_fixture_missing_binary_flag_uses_zero_without_native_io(self):
        operations=[]
        opened=SimpleNamespace(O_RDONLY=0,O_RDWR=2,O_CREAT=64,O_EXCL=128,
            open=lambda *args:operations.append(('open',args)) or 999999,
            set_inheritable=lambda *args:operations.append(('inherit',args)))
        fixture=Files();fixture.opened[100000]=dict(path=self.parent,directory=True)
        with mock.patch.dict(globals(),os=opened), mock.patch.object(fixture,'directory_changed') as changed:
            self.assertEqual(fixture.open(100000,'fixture',False),999999)
            self.assertEqual(fixture.create(100000,'created'),999999)
            changed.assert_called_once_with(self.parent,new_directory=False)
        self.assertEqual(operations,[('open',(self.parent/'fixture',0)),('inherit',(999999,False)),
            ('open',(self.parent/'created',194,0o600)),('inherit',(999999,False))])

if __name__=='__main__':unittest.main(verbosity=2)
