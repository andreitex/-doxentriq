"""Genuine original verifier issuance with RAM files/crypto; no native effects."""
import base64
import copy
import hashlib
from pathlib import Path
import stat
import sys
from types import MappingProxyType,ModuleType,SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
HERE=ROOT/'deploy/installer'

def load(name,path):
 value=ModuleType(name);value.__file__=str(path);sys.modules[name]=value
 exec(compile(path.read_bytes(),str(path),'exec'),vars(value));return value

def sha(raw):return hashlib.sha256(raw).hexdigest()

class Files:
    def __init__(self,data,modes):
        self.data=data;self.stats={};self.held={};self.closed=[];self.next_fd=10;self.reads=0
        directories=set()
        for path in data:directories.update(path.parents)
        for path in sorted(directories,key=str):self.metadata(path,True,0,0o755)
        for path,raw in data.items():self.metadata(path,False,len(raw),modes.get(path,0o644))
    def metadata(self,path,directory,size,mode):
        self.stats[path]=SimpleNamespace(st_dev=7,st_ino=100+len(self.stats),
            st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|mode,st_uid=0,st_gid=0,
            st_nlink=2 if directory else 1,st_size=size,st_mtime_ns=1,st_ctime_ns=2)
    def lstat(self,path):return copy.copy(self.stats[Path(path)])
    def fstat(self,fd):return copy.copy(self.held[fd][1])
    def open(self,parent,name,directory):
        path=Path(name) if parent is None else self.held[parent][0]/name
        fd=self.next_fd;self.next_fd+=1;self.held[fd]=(path,copy.copy(self.stats[path]));return fd
    def cloexec(self,fd):return True
    def read(self,fd,amount,offset):self.reads+=1;return self.data[self.held[fd][0]][offset:offset+amount]
    def close(self,fd):self.closed.append(fd);del self.held[fd]

class Crypto:
    def __init__(self):self.calls=[]
    def signature(self,raw,key):return hashlib.sha512(raw+key).digest()
    def verify(self,raw,signature,key):
        self.calls.append((raw,signature,key));return signature==self.signature(raw,key)

class Fixture:
    serial=0
    def __init__(self,changes=None):
        Fixture.serial+=1;self.prefix='authenticated_inputs_fixture_'+str(Fixture.serial);self.restores=[]
        self.V=load(self.prefix+'_V',ROOT/'scripts/verify-release.py')
        self.P=load(self.prefix+'_platform',ROOT/'scripts/platform_source.py')
        self.PB=load(self.prefix+'_package',ROOT/'deploy/installer/build-full-package.py')
        self.D=load(self.prefix+'_delivery',ROOT/'deploy/installer/build-full-cli-package.py')
        self.C=load(self.prefix+'_cli',ROOT/'deploy/installer/company_full_cli.py')
        self.I=load(self.prefix+'_inputs',HERE/'company_authenticated_cli_inputs.py')
        self.required=set(self.D.LAUNCH_PATHS)|set(self.PB.PACKAGE_PATHS)|set(self.PB.OPERATIONAL_PATHS)
        paths=self.required|set(self.V.COMPANY_SOURCES)|set(self.V.COMPANY_DEPLOYMENT)
        self.values={path:(ROOT/path).read_bytes() for path in paths}
        self.values['scripts/platform_source.py']=(ROOT/'scripts/platform_source.py').read_bytes()
        self.values['deploy/installer/build-full-cli-package.py']=(ROOT/'deploy/installer/build-full-cli-package.py').read_bytes()
        for path in self.P.REQUIRED_ANCHORS:self.values.setdefault(path,b'public minimal anchor\n')
        for path in self.P.SOURCE_ROOTS:self.values.setdefault(path+'/fixture.txt',b'public source-root fixture\n')
        self.modes={path:'100755' if path.endswith('.sh') else '100644' for path in self.values}
        if changes:changes(self)
        tree=self.P._tree([(path,self.modes[path],self.P._blob(raw)) for path,raw in sorted(self.values.items())])
        captured=self.P._build('a'*40,tree,self.values,self.modes)
        def manifest(paths,scope):
            return self.V.canonical(dict(schemaVersion=1,scope=scope,files=[dict(path=path,bytes=len(self.values[path]),sha256=sha(self.values[path])) for path in sorted(paths)]))
        names=('mysql','redis','rabbitmq','keycloak','registry','caddy','lego','prometheus','loki','grafana','otel','trivy','node','python','platform','runtime','dependency_proxy')
        configs={'images.lock.json':self.V.canonical({name:'example/'+name+'@sha256:'+'a'*64 for name in names}),
            'runtime-manifest.json':self.V.canonical({}),'approved-mirrors.json':self.V.canonical([]),
            'company-sources.json':manifest(self.V.COMPANY_SOURCES,'COMPANY_SOURCE_BYTES_ONLY'),
            'company-deployment.json':manifest(self.V.COMPANY_DEPLOYMENT,'COMPANY_DEPLOYMENT_BYTES_ONLY'),
            'platform-sources.json':captured.manifest_bytes,'platform-sources.tar.gz':captured.archive_bytes}
        self.release=dict(schemaVersion=4,version='fixture-4',architecture='x86_64',createdAt='2026-10-14T00:00:00Z',
            files={name:dict(bytes=len(raw),sha256=sha(raw)) for name,raw in configs.items()})
        self.release_raw=self.V.canonical(self.release)
        der=bytes.fromhex('302a300506032b6570032100')+b'a'*32
        self.public_raw=b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(der)+b'\n-----END PUBLIC KEY-----\n'
        self.fingerprint=sha(der);self.crypto=Crypto()
        root=Path(ROOT.anchor)/('authenticated-cli-inputs-fixture-'+str(Fixture.serial))
        self.bundle=root/'bundle';self.sources=root/'source';self.public=root/'keys'/'company.pem'
        data={self.sources/path:raw for path,raw in self.values.items()}
        data.update({self.bundle/name:raw for name,raw in configs.items()})
        data[self.bundle/'release.json']=self.release_raw
        data[self.bundle/'release.sig']=self.crypto.signature(self.release_raw,self.public_raw)
        data[self.public]=self.public_raw
        modes={self.sources/path:0o755 if self.modes[path]=='100755' else 0o644 for path in self.values}
        self.files=Files(data,modes)
        self.cm=self.V.authenticated_platform_source(self.bundle,self.public,self.fingerprint,
            expected_architecture='x86_64',source_root=self.sources,files=self.files,crypto=self.crypto)
        self.source=self.cm.__enter__();self.context_closed=False
    def prepare(self,**changes):
        args=dict(package_module=self.PB,delivery_module=self.D,cli_module=self.C);args.update(changes)
        return self.I.prepare_authenticated_cli_inputs(self.V,self.source,**args)
    def close_source(self):
        if not self.context_closed:
            self.context_closed=True
            try:self.cm.__exit__(None,None,None)
            except self.V.ReleaseUnavailable:
                if self.source.active:raise
    def dispose(self):
        for restore in reversed(self.restores):restore()
        self.close_source()
        assert not self.files.held
        for name in tuple(sys.modules):
            if name.startswith(self.prefix):sys.modules.pop(name,None)

class Controls(unittest.TestCase):
    def fixture(self,changes=None):
        value=Fixture(changes);self.addCleanup(value.dispose);return value
    def refused(self,call):
        with self.assertRaises((ValueError,TypeError)):call()

    def test_genuine_original_issuance_captures_exact_catalog_overlap(self):
        f=self.fixture();inputs=f.prepare();result=inputs.capture_inputs()
        self.assertIs(f.V.require_platform_source(f.source),f.source)
        self.assertIs(type(result),MappingProxyType)
        self.assertEqual(set(result['sourceFiles']),f.required)
        self.assertEqual((len(result['launchPins']),len(result['packagePins']),len(result['operationalCatalog'])),(11,9,16))
        for path in f.required:
            self.assertEqual(result['sourceFiles'][path],f.values[path])
            self.assertEqual(result['sourceModes'][path],f.modes[path])
        for path in ('scripts/installer_parent.py','scripts/verify-release.py'):
            self.assertEqual(result['packagePins'][path]['sha256'],result['operationalCatalog'][path]['sha256'])
            self.assertEqual(result['bootstrapRecords'][path],result['sourceFiles'][path])
        with self.assertRaises(TypeError):result['launchPins']['extra']={}
        with self.assertRaises(TypeError):result['sourceFiles']['scripts/installer_parent.py']=b'changed'

    def test_release_identity_and_fingerprint_come_from_original_signed_source(self):
        f=self.fixture();result=f.prepare().capture_inputs()
        self.assertEqual(result['releaseSha256'],sha(f.release_raw));self.assertEqual(result['fingerprint'],f.fingerprint)
        self.assertEqual(f.crypto.calls[0],(f.release_raw,f.crypto.signature(f.release_raw,f.public_raw),f.public_raw))

    def test_public_source_clone_and_foreign_properties_cannot_issue_inputs(self):
        for kind in ('clone','foreign'):
            with self.subTest(kind=kind):
                f=self.fixture();source=f.source;calls=[]
                metadata=dict(source.metadata);metadata['release']=f.release
                if kind=='clone':
                    value=f.V.HeldPlatformSource(dict(source.files),dict(source.git_modes),dict(source.configs),
                        dict(source.provenance),metadata,lambda:calls.append('clone-check'),archive_bytes=source.archive_bytes)
                else:
                    class Foreign:
                        @property
                        def files(self):calls.append('foreign-getter');return {}
                    value=Foreign()
                self.refused(lambda:f.I.prepare_authenticated_cli_inputs(f.V,value,package_module=f.PB,delivery_module=f.D,cli_module=f.C))
                self.assertFalse(calls)

    def test_same_source_is_never_adopted_into_a_new_verifier_registry(self):
        f=self.fixture();other=load(f.prefix+'_otherV',ROOT/'scripts/verify-release.py')
        self.refused(lambda:f.I.prepare_authenticated_cli_inputs(other,f.source,package_module=f.PB,delivery_module=f.D,cli_module=f.C))
        self.assertIs(f.V.require_platform_source(f.source),f.source)

    def test_missing_late_catalog_path_refuses_genuinely_issued_source(self):
        def remove(f):f.values.pop('deploy/installer/company_full_plan.py');f.modes.pop('deploy/installer/company_full_plan.py')
        f=self.fixture(remove);self.assertIs(f.V.require_platform_source(f.source),f.source);self.refused(lambda:f.prepare().capture_inputs())

    def test_python_executable_mode_refuses_before_downstream_compilation(self):
        f=self.fixture(lambda f:f.modes.update({'deploy/installer/company_full_cli.py':'100755'}))
        self.refused(lambda:f.prepare().capture_inputs())

    def test_signed_nonexecutable_lock_mode_is_preserved(self):
        path='scripts/install-lock.sh';f=self.fixture(lambda f:f.modes.update({path:'100644'}))
        result=f.prepare().capture_inputs()
        self.assertEqual(result['sourceModes'][path],'100644')
        self.assertEqual(result['sourceFiles'][path],f.values[path])
        self.assertFalse(result['operationalCodeCompiled'] or result['executionEvidenceIssued'] or result['stageAcknowledged'])

    def test_individual_capture_limit_is_not_overridden_by_signed_archive(self):
        f=self.fixture(lambda f:f.values.update({'deploy/installer/company_full_cli.py':b'#'+b'x'*131072}))
        self.assertIs(f.V.require_platform_source(f.source),f.source);self.refused(lambda:f.prepare().capture_inputs())

    def test_launch_and_package_aggregate_limits_are_separate(self):
        for kind in ('launch','package'):
            with self.subTest(kind=kind):
                def expand(f):
                    path='deploy/installer/company_full_cli.py' if kind=='launch' else 'deploy/installer/company_full_plan.py'
                    catalog=f.D.LAUNCH_PATHS if kind=='launch' else f.PB.PACKAGE_PATHS
                    total=sum(len(f.values[p]) for p in catalog);amount=262145-total
                    f.values[path]+=b'\n#'+b'x'*(amount-2)
                f=self.fixture(expand);self.refused(lambda:f.prepare().capture_inputs())

    def test_source_expiry_and_changed_archive_refuse_reuse(self):
        for kind in ('expired','archive-drift'):
            with self.subTest(kind=kind):
                f=self.fixture();inputs=f.prepare()
                if kind=='expired':f.close_source()
                else:
                    path=f.bundle/'platform-sources.tar.gz';raw=f.files.data[path];f.files.data[path]=raw[:-1]+bytes([raw[-1]^1])
                self.refused(inputs.capture_inputs);self.refused(inputs.recheck)

    def test_validator_replacement_is_not_invoked_before_source_use(self):
        f=self.fixture();inputs=f.prepare();calls=[];original=f.V.require_platform_source
        def foreign(value):calls.append(value);return value
        f.V.require_platform_source=foreign;f.restores.append(lambda:setattr(f.V,'require_platform_source',original))
        self.refused(inputs.capture_inputs);self.assertFalse(calls)

    def test_replaced_source_getter_never_runs_foreign_callback(self):
        f=self.fixture();inputs=f.prepare();calls=[];kind=f.V.HeldPlatformSource;original=kind.files
        def foreign(value):calls.append(value);return {}
        kind.files=property(foreign);f.restores.append(lambda:setattr(kind,'files',original))
        self.refused(inputs.capture_inputs);self.assertFalse(calls)

    def test_public_inputs_clone_has_no_private_issuance_or_source_reads(self):
        f=self.fixture();issued=f.prepare();before=f.files.reads
        clone=f.I.SourceInputs();self.refused(clone.capture_inputs);self.refused(clone.recheck)
        self.assertEqual(f.files.reads,before);self.assertIs(issued.recheck(),issued)

    def test_extra_helpers_are_explicit_immutable_and_not_autoenrolled(self):
        f=self.fixture();inputs=f.prepare();main=inputs.capture_inputs();path='deploy/installer/build-full-cli-package.py'
        self.assertNotIn(path,main['sourceFiles'])
        result=inputs.require_helpers((path,))
        self.assertIs(type(result),MappingProxyType);self.assertEqual(result['captures'][path],f.values[path])
        self.assertEqual(result['pins'][path]['sha256'],sha(f.values[path]))
        self.assertFalse(result['helperCodeCompiled'] or result['sourceObjectTransferred'] or result['executionEvidenceIssued'] or result['stageAcknowledged'])
        with self.assertRaises(TypeError):result['captures'][path]=b'changed'
        self.assertNotIn(path,inputs.capture_inputs()['sourceFiles'])

    def test_missing_or_executable_helper_is_not_admitted(self):
        for kind in ('missing','executable'):
            with self.subTest(kind=kind):
                path='deploy/installer/build-full-cli-package.py'
                f=self.fixture(None if kind=='missing' else lambda f:f.modes.update({path:'100755'}))
                self.refused(lambda:f.prepare().require_helpers(('docs/not-present.py',) if kind=='missing' else (path,)))

    def test_helper_syntax_and_opaque_keys_refuse_without_foreign_callbacks(self):
        for kind in ('absolute','traversal','duplicate','opaque'):
            with self.subTest(kind=kind):
                f=self.fixture();inputs=f.prepare();calls=[]
                class Foreign:
                    def __hash__(self):calls.append('hash');return 1
                    def __eq__(self,value):calls.append('eq');return True
                path='deploy/installer/build-full-cli-package.py'
                rows={'absolute':('/'+path,),'traversal':('../'+path,),'duplicate':(path,path),'opaque':(Foreign(),)}
                self.refused(lambda:inputs.require_helpers(rows[kind]));self.assertFalse(calls)

    def test_catalogue_mismatch_and_opaque_items_refuse_before_source_callback(self):
        for kind in ('mismatch','opaque'):
            with self.subTest(kind=kind):
                f=self.fixture();calls=[];original=f.D.LAUNCH_PATHS
                class Foreign:
                    def __eq__(self,value):calls.append('eq');return True
                f.D.LAUNCH_PATHS=original[:-1]+(('scripts/other.py' if kind=='mismatch' else Foreign()),)
                before=f.files.reads;self.refused(f.prepare)
                self.assertEqual(f.files.reads,before);self.assertFalse(calls)

    def test_helper_failure_remains_private_after_public_ledger_clear(self):
        f=self.fixture();inputs=f.prepare();self.refused(lambda:inputs.require_helpers(('docs/missing.py',)))
        f.I.UNRELEASED.clear();before=f.files.reads
        self.refused(inputs.capture_inputs);self.refused(f.prepare);self.assertEqual(f.files.reads,before)

    def test_extra_helper_must_still_use_original_live_source(self):
        f=self.fixture();inputs=f.prepare();f.close_source()
        self.refused(lambda:inputs.require_helpers(('deploy/installer/build-full-cli-package.py',)))

    def test_helper_member_and_aggregate_caps_do_not_follow_signature_acceptance(self):
        for kind in ('member','aggregate'):
            with self.subTest(kind=kind):
                paths=('docs/large-helper-a.py',) if kind=='member' else tuple('docs/large-helper-'+name+'.py' for name in ('a','b','c'))
                def add(f):
                    for path in paths:f.values[path]=b'#'+b'x'*(131072 if kind=='member' else 89999);f.modes[path]='100644'
                f=self.fixture(add);inputs=f.prepare();self.assertIs(f.V.require_platform_source(f.source),f.source)
                self.refused(lambda:inputs.require_helpers(paths))

    def test_successful_factory_is_one_use_without_source_callbacks(self):
        f=self.fixture();inputs=f.prepare();result=inputs.capture_inputs();before=f.files.reads
        self.refused(f.prepare);self.assertEqual(f.files.reads,before)
        self.assertIs(inputs.capture_inputs(),result)

    def test_helpers_refuse_replaced_original_held_file_map(self):
        f=self.fixture();inputs=f.prepare();path='deploy/installer/build-full-cli-package.py'
        before=object.__getattribute__(f.source,'_HeldPlatformSource__values')
        changed=dict(before);changed['files']=MappingProxyType(dict(before['files'],**{path:b'changed held mapping'}))
        object.__setattr__(f.source,'_HeldPlatformSource__values',MappingProxyType(changed))
        f.restores.append(lambda:object.__setattr__(f.source,'_HeldPlatformSource__values',before))
        self.assertIs(f.V.require_platform_source(f.source),f.source)
        self.refused(lambda:inputs.require_helpers((path,)))

if __name__=='__main__':unittest.main(verbosity=2)
