"""Private company-package controls: real file descriptors, synthetic OS commands."""
import ast,base64,copy,hashlib,importlib.util,json,os,sys,tempfile,unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];D=ROOT/'deploy/installer'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
C=load('engine_catalog_fixture',D/'company_engine_packages.py')
E=load('engine_native_fixture',D/'company_engine_native.py')
ELF=load('engine_elf_fixture',D/'company_engine_elf.py')
EF=load('engine_elf_data_fixture',ROOT/'tests/fixture_company_private_elf.py')
H=load('engine_host_fixture',D/'company_host_package_runtime.py')
S=load('engine_station_fixture',D/'company_native_station.py')
W=load('engine_worker_fixture',D/'company_install.py')
B=load('engine_builder_fixture',D/'build-package.py')
V=load('engine_vendor_fixture',ROOT/'tests/test_company_foundation_packages.py')
def fixture(os_id='rocky',version='10.2'):
    profile=dict(platform=dict(osId=os_id,versionId=version,architecture='x86_64'),origin='doxentriq',releaseId='doxentriq-engine-20261106.1',qualificationReportSha256='a'*64,sourceManifestSha256='b'*64,distributionMetadataSha256='c'*64,packages=[])
    key=b'synthetic company public key\n'*100;profile['packageSigningKey']=dict(filename='doxentriq-engine.asc',bytes=len(key),sha256=E.sha(key),fingerprint='A1'*20)
    archives={'doxentriq-engine.asc':key};manifests={};files={}
    for role in C.ROLES:
        name=C.NAMES[role];filename=name+('.deb' if os_id=='debian' else '.rpm');raw=(name.encode()+b' archive\n')*1000;archives[filename]=raw
        item=dict(role=role,name=name,version='29.9.3-1.doxentriq.1.el10',architecture='amd64' if os_id=='debian' else 'x86_64',filename=filename,bytes=len(raw),sha256=E.sha(raw),executables=[])
        for path in C.EXECUTABLES[role]:
            blob=EF.elf('runc') if path=='/usr/bin/runc' else ('synthetic executable '+path+'\n').encode()*10;files[path]=blob
            item['executables'].append(dict(path=path,bytes=len(blob),sha256=E.sha(blob),mode=0o755))
        for path in E.payload_paths(item,C):files.setdefault(path,('synthetic support '+path+'\n').encode())
        if role=='containerd': files[ELF.LIBRARY]=EF.elf('library')
        rows=[dict(path=p,bytes=len(files[p]),sha256=E.sha(files[p]),mode=0o755 if p in C.EXECUTABLES[role] else 0o644,uid=0,gid=0,type='file') for p in E.payload_paths(item,C)]
        manifest=E.canonical(dict(schemaVersion=2,scope='COMPANY_ENGINE_PACKAGE_PAYLOAD',linkage=EF.linkage() if role=='containerd' else None,package={k:item[k] for k in ('role','name','version','architecture')},files=rows));manifests[name]=manifest
        item.update({k:'e'*64 for k in C.EVIDENCE});item['payloadInventorySha256']=E.sha(manifest);profile['packages'].append(item)
    value=dict(schemaVersion=2,scope='COMPANY_HOST_PACKAGE_CATALOG',profiles=[profile]);raw=E.canonical(value)
    return SimpleNamespace(value=value,raw=raw,archives=archives,manifests=manifests,files=files,platform=profile['platform'])
def bound(f):
    package=E.bind(f.raw,expected_catalog_sha256=E.sha(f.raw),observed_platform=f.platform,catalog=C)
    return package,E.tool_binding(package,C)
def encoded(raw):return dict(bytes=len(raw),sha256=E.sha(raw),base64=base64.b64encode(raw).decode())
def responses(f):
    return {('/usr/bin/rpm','-q'):''.join(p['name']+'\t0:'+p['version']+'\t'+p['architecture']+'\n' for p in f.value['profiles'][0]['packages']).encode(),
        ('/usr/bin/getent','group','docker'):b'docker:x:987:\n',('/usr/bin/getent','passwd'):b'root:x:0:0:root:/root:/bin/bash\n',('/usr/bin/getent','gshadow','docker'):b'docker:!::\n',
        ('/usr/sbin/getenforce',):b'Enforcing\n',('/usr/sbin/semodule','-lfull'):b'400 docker-af-alg-deny cil\n400 docker-af-vsock-deny cil\n',('/usr/sbin/matchpathcon','-V'):b''}
class DataTests(unittest.TestCase):
    def test_four_archives_key_and_two_transport_tools(self):
        p,t=bound(fixture());self.assertEqual(len(p['shellArguments']),10);self.assertEqual(len(p['artifacts']),5);self.assertEqual(t['scope'],E.TOOL_SCOPE);self.assertEqual(set(t['tools']),{'docker','compose'})
    def test_company_debian_is_refused_before_files_or_effects(self):
        f=fixture('debian','13');C.decode(f.raw,expected_catalog_sha256=E.sha(f.raw))
        with self.assertRaisesRegex(ValueError,'DEB execution'):bound(f)
    def test_mixed_or_unbound_catalog_family_refused(self):
        f=fixture();v=V.fixture()
        for catalogs in ({'engine':encoded(f.raw),**v.catalogs},{'engine':encoded(f.raw),'packages':v.catalogs['packages']},{}):
            with self.assertRaises(ValueError):H.bindings(catalogs,profiles=V.P,packages=V.K,engine=C,engine_native=E,observed_platform=f.platform)
    def test_full_payload_manifest_is_bound_and_immutable(self):
        f=fixture();p,_=bound(f);rows=[E.payload(f.manifests[x['name']],x,C) for x in p['source']['packages']]
        self.assertEqual(sum(len(x['files']) for x in rows),27)
        with self.assertRaises(TypeError):rows[0]['files'][0]['mode']=0o777
    def test_loader_dependency_is_bound_in_payload_and_elf_contract(self):
        f=fixture();p,_=bound(f);package=next(x for x in p['source']['packages'] if x['role']=='containerd')
        value=json.loads(f.manifests[package['name']]);needed=['ld-linux-x86-64.so.2','libc.so.6','libgcc_s.so.1','libm.so.6','libresolv.so.2','libseccomp.so.2']
        value['linkage']['runc']['needed']=needed
        raw=E.canonical(value);updated=dict(package,payloadInventorySha256=E.sha(raw))
        readback=E.payload(raw,updated,C);self.assertEqual(E.plain_linkage(readback['linkage']),value['linkage'])
        ELF.contract(E.plain_linkage(readback['linkage']))
        with self.assertRaisesRegex(ValueError,'digest'):E.payload(raw,package,C)
        for wrong in ('/lib64/ld-linux-x86-64.so.2','ld-linux-x86-64.so.3','ld-linux-aarch64.so.1'):
            changed=copy.deepcopy(value);changed['linkage']['runc']['needed']=sorted([wrong,*needed[1:]])
            invalid=E.canonical(changed);claimed=dict(package,payloadInventorySha256=E.sha(invalid))
            with self.subTest(needed=wrong),self.assertRaises(ValueError):E.payload(invalid,claimed,C)
    def test_invalid_payload_support_path_mode_owner_and_binary_digest_refuse(self):
        f=fixture();p,_=bound(f);package=p['source']['packages'][0]
        for mutate in (lambda v:v['files'].pop(),lambda v:v['files'][0].update(path='/etc/evil'),lambda v:v['files'][0].update(mode=0o777),lambda v:v['files'][0].update(uid=1000),lambda v:v['files'][0].update(sha256='f'*64)):
            v=json.loads(f.manifests[package['name']]);mutate(v);raw=E.canonical(v);fake=dict(package);fake['payloadInventorySha256']=E.sha(raw)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):E.payload(raw,fake,C)
    def test_noncanonical_duplicate_and_wrong_inventory_hash_refuse(self):
        f=fixture();p,_=bound(f);package=p['source']['packages'][0];raw=f.manifests[package['name']]
        for bad in (raw+b' ',raw.replace(b'"schemaVersion":2',b'"schemaVersion":2,"schemaVersion":2'),raw.replace(b'synthetic',b'changed')):
            if bad==raw:bad=raw+b'\n'
            fake=dict(package);fake['payloadInventorySha256']=E.sha(bad)
            with self.assertRaises(ValueError):E.payload(bad,fake,C)
        with self.assertRaises(ValueError):E.payload(raw+b' ',package,C)
    def test_phase_exact_ten_arguments_and_shell_constants(self):
        f=fixture();p,_=bound(f);manifests=tuple(E.payload(f.manifests[x['name']],x,C) for x in p['source']['packages'])
        command=['/bin/bash','--noprofile','--norc','-c','set -Eeuo pipefail\ncompany_packages_v2_phase "$@"\n','company-foundation',*['fixed']*7]
        output=E.append_phase_arguments(command,dict(arguments=p['shellArguments'],payloads=manifests),binding=p)
        self.assertEqual(len(output),23);self.assertEqual(output[-10:],list(p['shellArguments']));self.assertIn("DOXENTRIQ_ENGINE_KEY_FINGERPRINT='"+'A1'*20+"'",output[4]);self.assertNotIn('gpg --',output[4])
        with self.assertRaises(ValueError):E.append_phase_arguments(command,dict(arguments=p['shellArguments'][:-2],payloads=manifests),binding=p)
    def test_package_readback_wrong_epoch_duplicate_or_version_refuses(self):
        f=fixture();p,_=bound(f);raw=responses(f)[('/usr/bin/rpm','-q')];self.assertEqual(len(E.package_rows(raw,p)),4)
        for bad in (raw.replace(b'0:',b'1:'),raw.replace(b'29.9.3',b'29.9.4'),raw+raw.splitlines(keepends=True)[0],b''.join(raw.splitlines(keepends=True)[:-1])):
            with self.assertRaises(ValueError):E.package_rows(bad,p)
    def test_foundation_producer_embeds_catalog_and_ten_exact_modules(self):
        f=fixture();rows=B.assemble(ROOT,'a'*64,reader=lambda p,maximum=131072:p.read_bytes(),host_catalogs={'engine':f.raw})
        self.assertLessEqual(len(rows['company_install.py']),524288);self.assertLessEqual(len(rows['company-install.sh']),32768)
        tree=ast.parse(rows['company_install.py']);assign={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('HOST_CATALOGS','TRUSTED_CODE')}
        self.assertEqual(assign['HOST_CATALOGS'],{'engine':encoded(f.raw)});self.assertEqual(len(assign['TRUSTED_CODE']),10);self.assertIn('company_engine_native.py',W.load_trusted(assign['TRUSTED_CODE']))
    def test_producer_rejects_mixed_or_wrong_independent_catalog(self):
        f=fixture()
        with self.assertRaises(ValueError):B.assemble(ROOT,'a'*64,reader=lambda p,maximum=131072:p.read_bytes(),host_catalogs={'engine':f.raw,**V.fixture().raw})
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();path=root/'engine.json';path.write_bytes(f.raw)
            self.assertEqual(B.read_catalogs(source,{'engine':(path,E.sha(f.raw))},reader=lambda p,maximum:p.read_bytes()),{'engine':f.raw})
            with self.assertRaises(ValueError):B.read_catalogs(source,{'engine':(path,'f'*64)},reader=lambda p,maximum:p.read_bytes())
    def test_native_emitted_loader_has_company_catalog_and_exact_transport_binding(self):
        before=set(sys.modules)
        try:
            producer=load('engine_emitted_producer',D/'build-native-retention-package.py');f=fixture();raw=producer.assemble(ROOT,'a'*64,reader=lambda p,maximum:p.read_bytes(),engine_catalog=f.raw)
            self.assertLessEqual(len(raw),producer.MAX_WORKER);m=type(sys)('engine_emitted');exec(compile(raw,'<company-engine-package>','exec'),m.__dict__)
            modules,_,_=m.load_package();self.assertEqual(m.host_catalogs(),{'engine':encoded(f.raw)})
            @contextmanager
            def observed(station):yield f.platform,lambda:None
            with patch.object(modules['host_package_runtime'],'held_platform',observed):t=m.host_tool_binding(modules,f.platform)
            self.assertEqual(t['scope'],E.TOOL_SCOPE);self.assertEqual(t['tools']['docker']['path'],'/usr/bin/docker');self.assertEqual(t['sourceManifestSha256'],'b'*64)
            self.assertEqual(modules['infrastructure_worker'].STAGE,'company-private-infrastructure');self.assertEqual(modules['identity_worker'].STAGE,'company-initial-identity')
        finally:
            for name in set(sys.modules)-before:sys.modules.pop(name,None)
    def test_native_producer_mixed_family_fails(self):
        before=set(sys.modules)
        try:
            producer=load('engine_bad_producer',D/'build-native-retention-package.py');f=fixture();v=V.fixture()
            with self.assertRaises(ValueError):producer.assemble(ROOT,'a'*64,reader=lambda p,maximum:p.read_bytes(),engine_catalog=f.raw,host_tool_catalog=v.raw['tools'],host_package_catalog=v.raw['packages'])
        finally:
            for name in set(sys.modules)-before:sys.modules.pop(name,None)
    def test_foundation_worker_exact_limit_and_overflow_refusal(self):
        f=fixture();rows=B.assemble(ROOT,'a'*64,reader=lambda p,maximum=131072:p.read_bytes(),host_catalogs={'engine':f.raw});size=len(rows['company_install.py'])
        def padded(extra):
            def reader(path,maximum=131072):
                raw=path.read_bytes()
                if path.name=='company_install.py':raw+=b'\n#'+b'x'*(524288-size+extra-2)
                return raw
            return reader
        self.assertEqual(len(B.assemble(ROOT,'a'*64,reader=padded(0),host_catalogs={'engine':f.raw})['company_install.py']),524288)
        with self.assertRaisesRegex(ValueError,'package-limit'):B.assemble(ROOT,'a'*64,reader=padded(1),host_catalogs={'engine':f.raw})

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root protected FD fixtures')
class NativeTests(unittest.TestCase):
    @contextmanager
    def mapped(self):
        f=fixture();p,t=bound(f)
        with tempfile.TemporaryDirectory(prefix='doxentriq-engine-readback-',dir=os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT','/root')) as tmp:
            root=Path(tmp);root.chmod(0o700)
            def write(path,blob,mode):
                target=root/path.lstrip('/');target.parent.mkdir(mode=0o755,parents=True,exist_ok=True);target.write_bytes(blob);target.chmod(mode)
            write('/usr/lib/os-release',b'ID=rocky\nVERSION_ID="10.2"\n',0o644);(root/'etc').mkdir();(root/'etc/os-release').symlink_to('../usr/lib/os-release')
            for item in p['artifacts']:write(item['path'],f.archives[item['filename']],0o400)
            for item in p['source']['packages']:write(p['root']+'/'+item['name']+'.payload.json',f.manifests[item['name']],0o400)
            for path,blob in f.files.items():write(path,blob,0o755 if any(path in C.EXECUTABLES[role] for role in C.ROLES) else 0o644)
            for path in ('/usr/bin/rpm','/usr/bin/getent','/usr/sbin/getenforce','/usr/sbin/semodule','/usr/sbin/matchpathcon'):write(path,b'synthetic command, never executed\n',0o755)
            class Station:
                UNRELEASED=S.UNRELEASED;metadata=staticmethod(S.metadata)
                @staticmethod
                def held_file(path,maximum,**kw):return S.held_file(root/str(path).lstrip('/'),maximum,**kw)
            class NativeOS:
                def __getattr__(self,name):return getattr(os,name)
                def open(self,path,*a,**kw):return os.open(root/'etc' if path=='/etc' else path,*a,**kw)
                def stat(self,path,*a,**kw):return os.stat(root/'etc' if path=='/etc' else path,*a,**kw)
            replies=responses(f);calls=[]
            def run(argv,timeout):
                calls.append(tuple(argv));key=next(key for key in replies if tuple(argv[:len(key)])==key);return replies[key]
            before=set(os.listdir('/proc/self/fd'))
            def readback():return H.readback(p,t,station=Station,runner=SimpleNamespace(run=run),check_authority=lambda:None,engine=C,engine_native=E,engine_elf=ELF)
            with patch.object(H,'os',NativeOS()):yield SimpleNamespace(f=f,p=p,t=t,root=root,station=Station,replies=replies,calls=calls,readback=readback)
            self.assertEqual(set(os.listdir('/proc/self/fd')),before)
    def test_real_descriptor_held_archives_key_and_all_manifests(self):
        with self.mapped() as x:
            with E.held_archives(x.p,x.station,catalog=C,check_authority=lambda:None) as inputs:self.assertEqual(len(inputs['payloads']),4);self.assertEqual(len(inputs['arguments']),10);inputs['recheck']()
    def test_wrong_key_or_archive_digest_refuses_before_command(self):
        for index in (0,4):
            with self.mapped() as x:
                (x.root/x.p['artifacts'][index]['path'].lstrip('/')).write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    with E.held_archives(x.p,x.station,catalog=C,check_authority=lambda:None):pass
                self.assertEqual(x.calls,[])
    def test_unsafe_manifest_mode_and_support_symlink_refuse(self):
        with self.mapped() as x:
            path=x.root/(x.p['root']+'/'+x.p['source']['packages'][0]['name']+'.payload.json').lstrip('/');path.chmod(0o644)
            with self.assertRaises(ValueError):
                with E.held_archives(x.p,x.station,catalog=C,check_authority=lambda:None):pass
        with self.mapped() as x:
            path=x.root/'usr/lib/systemd/system/docker.service';path.unlink();path.symlink_to('/etc/passwd')
            with self.assertRaises((ValueError,OSError)):x.readback()
    def test_actual_all27_all8_readback_and_independent_evidence(self):
        with self.mapped() as x:
            value=x.readback();self.assertEqual(len(value['installedPayloadPins']),27);self.assertEqual(len(value['installedExecutablePins']),8);self.assertEqual(len(x.calls),7)
            H.verify_evidence(value,x.p,x.t,current=x.readback(),engine_native=E)
            label_call=next(call for call in x.calls if call[:2]==('/usr/sbin/matchpathcon','-V'))
            self.assertIn(ELF.LIBRARY,label_call)
    def test_private_library_wrong_mode_owner_hardlink_or_symlink_refuses(self):
        for kind in ('mode','owner','hardlink','symlink'):
            with self.mapped() as x:
                path=x.root/ELF.LIBRARY.lstrip('/')
                if kind=='mode':path.chmod(0o755)
                elif kind=='owner':os.chown(path,1001,0)
                elif kind=='hardlink':os.link(path,x.root/'extra-link')
                else:
                    path.unlink();path.symlink_to('/etc/passwd')
                with self.assertRaises((OSError,ValueError)):x.readback()
    def test_no_authenticated_elf_module_refuses_readback(self):
        with self.mapped() as x:
            with self.assertRaisesRegex(ValueError,'ELF verifier'):
                H.readback(x.p,x.t,station=x.station,runner=SimpleNamespace(run=lambda *_:b''),check_authority=lambda:None,engine=C,engine_native=E)
    def test_matching_file_hashes_do_not_replace_live_elf_contract(self):
        with self.mapped() as x:
            raw=EF.elf('library').replace(b'libseccomp.so.2',b'libseccomp.so.3')
            (x.root/ELF.LIBRARY.lstrip('/')).write_bytes(raw)
            manifests=[]
            for package in x.p['source']['packages']:
                data=json.loads(x.f.manifests[package['name']])
                if package['role']=='containerd':
                    row=next(row for row in data['files'] if row['path']==ELF.LIBRARY)
                    row.update(bytes=len(raw),sha256=E.sha(raw))
                encoded=E.canonical(data);expected=dict(package,payloadInventorySha256=E.sha(encoded))
                manifests.append(E.payload(encoded,expected,C))
            with self.assertRaisesRegex(ValueError,'SONAME'):
                E.installed_payload(x.p,manifests,x.station,check_authority=lambda:None,elf=ELF)
    def test_changed_support_bytes_are_not_hidden_by_eight_binary_checks(self):
        with self.mapped() as x:
            (x.root/'usr/share/doxentriq-engine/selinux/docker-af-alg-deny.cil').write_bytes(b'changed deny rule')
            with self.assertRaises(ValueError):x.readback()
    def test_current_os_mismatch_refuses_before_package_query(self):
        with self.mapped() as x:
            (x.root/'usr/lib/os-release').write_bytes(b'ID=rocky\nVERSION_ID=10.1\n')
            with self.assertRaises(ValueError):x.readback()
            self.assertEqual(x.calls,[])
    def test_group_member_primary_group_and_shadow_admin_refuse(self):
        cases=[(('/usr/bin/getent','group','docker'),b'docker:x:987:alice\n'),(('/usr/bin/getent','passwd'),b'alice:x:1000:987::/home/alice:/bin/bash\n'),(('/usr/bin/getent','gshadow','docker'),b'docker:!:alice:\n'),(('/usr/bin/getent','gshadow','docker'),b'docker::: \n')]
        for key,raw in cases:
            with self.mapped() as x:
                x.replies[key]=raw
                with self.assertRaises(ValueError):x.readback()
    def test_missing_shadowed_or_disabled_selinux_policy_refuses(self):
        for raw in (b'400 docker-af-alg-deny cil\n',b'400 docker-af-alg-deny cil disabled\n400 docker-af-vsock-deny cil\n',b'100 docker-af-alg-deny cil\n400 docker-af-vsock-deny cil\n'):
            with self.mapped() as x:
                x.replies[('/usr/sbin/semodule','-lfull')]=raw
                with self.assertRaises(ValueError):x.readback()
    def test_selinux_disabled_is_explicit_not_false_label_proof(self):
        with self.mapped() as x:
            x.replies[('/usr/sbin/getenforce',)]=b'Disabled\n';value=x.readback();self.assertFalse(value['hostPolicy']['executableLabelsVerified']);self.assertEqual(value['hostPolicy']['enabledDenyPolicies'],[])
    def test_consumer_own_catalog_and_current_support_drift_refuse(self):
        with self.mapped() as x:
            value=x.readback()
            for key in ('packageCatalogSha256','packageProfileSha256','sourceManifestSha256','distributionMetadataSha256'):
                changed=copy.deepcopy(value);changed[key]='f'*64
                with self.assertRaises(ValueError):H.verify_evidence(changed,x.p,x.t,current=changed,engine_native=E)
            changed=copy.deepcopy(value);changed['installedPayloadPins']['/usr/lib/systemd/system/docker.service']['sha256']='f'*64
            with self.assertRaises(ValueError):H.verify_evidence(value,x.p,x.t,current=changed,engine_native=E)
    def test_live_authority_failure_closes_owned_descriptors(self):
        with self.mapped() as x:
            count=[0]
            def authority():
                count[0]+=1
                if count[0]==8:raise ValueError('original parent no longer live')
            with self.assertRaisesRegex(ValueError,'original parent'):
                with E.held_archives(x.p,x.station,catalog=C,check_authority=authority):pass

if __name__=='__main__':unittest.main(verbosity=2)
