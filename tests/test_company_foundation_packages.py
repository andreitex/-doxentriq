"""Private pinned-package integration controls; no package manager installation."""
import ast,base64,copy,hashlib,importlib.util,io,json,os,subprocess,sys,tempfile,unittest
from contextlib import contextmanager,redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
D=ROOT/'deploy/installer'
H=load('packages_runtime_test',D/'company_host_package_runtime.py')
P=load('packages_tools_test',D/'company_host_tool_profiles.py')
K=load('packages_catalog_test',D/'company_host_packages.py')
S=load('packages_station_test',D/'company_native_station.py')
W=load('packages_foundation_test',D/'company_install.py')
B=load('packages_builder_test',D/'build-package.py')
C=load('packages_configuration_test',D/'company_configuration_worker.py')
Q=load('packages_configuration_core_test',D/'company_configuration.py')
F=load('packages_old_foundation_fixture',ROOT/'tests/test_company_foundation.py')
def encoded(raw):return dict(bytes=len(raw),sha256=H.sha(raw),base64=base64.b64encode(raw).decode())
def fixture(os_id='rocky',version='10.2'):
    platform=dict(osId=os_id,versionId=version,architecture='x86_64');arch='amd64' if os_id=='debian' else 'x86_64'
    archive={name:(name.encode()+b'\n')*2000 for name in K.NAMES};archive={name:(value*2)[:16384] for name,value in archive.items()}
    archive['docker.asc']=b'only a synthetic vendor public key\n'*40
    bins={name:(b'synthetic '+name.encode()+b'\n')*100 for name in P.PACKAGES}
    packages=[dict(name=name,version='5.7.0-1.synthetic',architecture=arch,filename=name+('.deb' if os_id=='debian' else '.rpm'),bytes=len(archive[name]),sha256=H.sha(archive[name]),repositoryMetadataSha256=H.sha(b'synthetic metadata')) for name in K.NAMES]
    rows={row['name']:row for row in packages}
    tools={name:dict(path=P.PATHS[name][0],bytes=len(bins[name]),sha256=H.sha(bins[name]),package=dict(name=package,version=rows[package]['version'],architecture=arch,archiveSha256=rows[package]['sha256'],repositoryMetadataSha256=rows[package]['repositoryMetadataSha256'])) for name,package in P.PACKAGES.items()}
    tool_catalog=dict(schemaVersion=1,scope='COMPANY_HOST_TOOL_PROFILES',profiles=[dict(platform=platform,tools=tools,qualificationReportSha256=H.sha(b'synthetic qualification'))])
    tool_raw=H.canonical(tool_catalog);tool=P.bind(tool_raw,expected_catalog_sha256=H.sha(tool_raw),observed_platform=platform)
    pack=dict(schemaVersion=1,scope='COMPANY_HOST_PACKAGE_CATALOG',profiles=[dict(platform=platform,toolProfileSha256=tool['profileSha256'],qualificationReportSha256=tool['qualificationReportSha256'],vendorKey=dict(filename='docker.asc',bytes=len(archive['docker.asc']),sha256=H.sha(archive['docker.asc']),fingerprint=K.KEYS[os_id]),packages=packages)])
    raw={'tools':tool_raw,'packages':H.canonical(pack)};catalogs={name:encoded(value) for name,value in raw.items()}
    package,tool=H.bindings(catalogs,profiles=P,packages=K,observed_platform=platform)
    rows=sorted(({key:row[key] for key in ('name','version','architecture')} for row in packages),key=lambda x:x['name'])
    current=dict(schemaVersion=1,scope=H.EVIDENCE_SCOPE,packageCatalogSha256=package['catalogSha256'],packageProfileSha256=package['profileSha256'],toolCatalogSha256=tool['catalogSha256'],toolProfileSha256=tool['profileSha256'],qualificationReportSha256=tool['qualificationReportSha256'],platform=platform,installedPackages=rows,installedToolPins={name:{key:row[key] for key in ('path','bytes','sha256')} for name,row in tools.items()})
    return SimpleNamespace(raw=raw,catalogs=catalogs,package=package,tools=tool,current=current,archive=archive,bins=bins)
def query_raw(f):
    rocky=f.package['platform']['osId']=='rocky'
    return ''.join(x['name']+'\t'+('0:' if rocky else '')+x['version']+'\t'+x['architecture']+('' if rocky else '\tinstalled')+'\n' for x in f.current['installedPackages']).encode()

class DataTests(unittest.TestCase):
    def test_os_observation_is_inert_and_duplicate_fields_refuse(self):
        self.assertEqual(H.platform_value(b'ID="rocky"\nVERSION_ID="10.2"\n'),dict(osId='rocky',versionId='10.2',architecture='x86_64'))
        for raw in (b'ID=rocky\nID=debian\nVERSION_ID=13\n',b'ID=$(id)\nVERSION_ID=10\n',b'ID=rocky\n',b'ID=rocky\nVERSION_ID=10\x00\n'):
            with self.assertRaises(ValueError):H.platform_value(raw)
    def test_exact_rpm_and_debian_package_readback(self):
        for os_id,version in [('rocky','10.2'),('debian','13')]:
            f=fixture(os_id,version);self.assertEqual(H.package_rows(query_raw(f),f.package),f.current['installedPackages'])
            self.assertEqual(H.query_command(f.package)[-5:],list(K.NAMES))
    def test_changed_missing_duplicate_uninstalled_and_other_epoch_refuse(self):
        for os_id,version in [('rocky','10.2'),('debian','13')]:
            f=fixture(os_id,version);raw=query_raw(f);lines=raw.splitlines(keepends=True)
            for bad in (b''.join(lines[:-1]),b''.join(lines[:-1]+[lines[0]]),raw.replace(b'5.7.0',b'5.7.1'),raw.replace(b'0:',b'1:') if os_id=='rocky' else raw.replace(b'installed',b'config-files')):
                with self.subTest(os_id=os_id),self.assertRaises(ValueError):H.package_rows(bad,f.package)
    def test_zero_epoch_catalog_refuses_before_producer_effects(self):
        f=fixture();value=json.loads(f.raw['packages']);value['profiles'][0]['packages'][0]['version']='0:1'
        raw=H.canonical(value)
        with self.assertRaisesRegex(ValueError,'zero epoch'):K.decode(raw,H.sha(raw),P)
    def test_evidence_requires_own_catalog_not_nonzero_foreign_digest(self):
        f=fixture();H.verify_evidence(f.current,f.package,f.tools,current=f.current)
        for key in ('packageCatalogSha256','packageProfileSha256','toolCatalogSha256','toolProfileSha256','qualificationReportSha256'):
            changed=copy.deepcopy(f.current);changed[key]=H.sha(b'foreign catalog')
            with self.subTest(key=key),self.assertRaises(ValueError):H.verify_evidence(changed,f.package,f.tools,current=changed)
        changed=copy.deepcopy(f.current);changed['installedToolPins']['docker']['sha256']=H.sha(b'drift')
        with self.assertRaises(ValueError):H.verify_evidence(f.current,f.package,f.tools,current=changed)
    def test_producer_embeds_both_catalogs_under_bounded_worker(self):
        f=fixture();rows=B.assemble(ROOT,'a'*64,reader=lambda p,maximum=131072:p.read_bytes(),host_catalogs=f.raw)
        self.assertLessEqual(len(rows['company_install.py']),524288);self.assertLessEqual(len(rows['company-install.sh']),32768)
        tree=ast.parse(rows['company_install.py']);assign={n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)}
        self.assertEqual(ast.literal_eval(assign['HOST_CATALOGS']),f.catalogs)
        records=ast.literal_eval(assign['TRUSTED_CODE']);self.assertEqual(set(records),set(B.TRUSTED))
        self.assertEqual(len(records),10);self.assertIn('company_engine_elf.py',records);self.assertIn(b'[[ true = true ]]',rows['company-install.sh'])
        self.assertEqual(W.load_trusted(records)['company_host_package_runtime.py'].EVIDENCE_SCOPE,H.EVIDENCE_SCOPE)
    def test_missing_or_mismatched_catalog_cannot_silently_select_latest(self):
        rows=B.assemble(ROOT,'a'*64,reader=lambda p,maximum=131072:p.read_bytes())
        entry=rows['company-install.sh'];self.assertIn(b'[[ false = true ]]',entry)
        self.assertLess(entry.index(b'[[ false = true ]]'),entry.index(b'install_lock_initialize /etc'))
        f=fixture();bad=copy.deepcopy(f.raw);v=json.loads(bad['packages']);v['profiles'][0]['toolProfileSha256']=H.sha(b'other');bad['packages']=H.canonical(v)
        with self.assertRaises(ValueError):B.assemble(ROOT,'a'*64,reader=lambda p,maximum=131072:p.read_bytes(),host_catalogs=bad)
    def test_independent_producer_inputs_digest_and_source_separation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir();f=fixture();paths={}
            for name,raw in f.raw.items():
                p=root/(name+'.json');p.write_bytes(raw);paths[name]=(p,H.sha(raw))
            self.assertEqual(B.read_catalogs(source,paths,reader=lambda p,maximum:p.read_bytes()),f.raw)
            bad=dict(paths);bad['tools']=(paths['tools'][0],H.sha(b'changed'))
            with self.assertRaises(ValueError):B.read_catalogs(source,bad,reader=lambda p,maximum:p.read_bytes())
            p=source/'tools.json';p.write_bytes(f.raw['tools']);bad=dict(paths);bad['tools']=(p,H.sha(f.raw['tools']))
            with self.assertRaises(ValueError):B.read_catalogs(source,bad,reader=lambda p,maximum:p.read_bytes())
    def test_legacy_classification_does_not_claim_verified(self):
        self.assertEqual(C.foundation_record_version({'scope':'FOUNDATION_ONLY'}),'legacy-unpinned')
        for value in ({'schemaVersion':True},{'schemaVersion':1},{'hostPackages':{}},None):self.assertEqual(C.foundation_record_version(value),'unsupported')

class WorkerTests(unittest.TestCase):
    def setUp(self):W.UNKNOWN.clear()
    def tearDown(self):W.UNKNOWN.clear()
    @contextmanager
    def harness(self):
        f=fixture();h=F.Harness();calls=[]
        @contextmanager
        def archives(binding,station,check_authority):
            check_authority();h.events.append('archives-enter');yield f.package['shellArguments'],check_authority;h.events.append('archives-close')
        def readback(*args,**kw):
            kw['check_authority']();h.events.append('package-readback');calls.append(True)
            if getattr(h,'bad_packages',False):raise ValueError('installed package mismatch')
            return copy.deepcopy(f.current)
        h.modules.update({'company_host_package_runtime.py':SimpleNamespace(readback=readback,verify_evidence=H.verify_evidence),'company_native_station.py':SimpleNamespace(UNRELEASED=[]),'company_host_packages.py':SimpleNamespace(held_archives=archives,append_phase_arguments=K.append_phase_arguments)})
        with patch.object(W,'COMPANY_FINGERPRINT',F.FP),patch.object(W,'measure',h.measure),patch.object(W,'host_bindings',return_value=(f.package,f.tools)):
            def execute(verify=False):return W.Worker(h.modules,h.state,h.runner,output_guard=h.output_guard,host_catalogs=f.catalogs).run(F.request(),object(),verify=verify)
            yield f,h,execute,calls
    def test_archive_scope_and_readback_precede_storage_and_final_proof(self):
        with self.harness() as (f,h,execute,calls):
            result=execute();self.assertEqual(result['schemaVersion'],2);self.assertEqual(result['hostPackages'],f.current);self.assertEqual(len(calls),2)
            phases=[x for x in h.events if isinstance(x,tuple) and x[0]=='phase'];self.assertEqual([x[1] for x in phases],['packages','storage','prepare','activate'])
            self.assertEqual(len(phases[0][2]),25);self.assertTrue(all(len(x[2])==13 for x in phases[1:]))
            self.assertLess(h.events.index('archives-enter'),h.events.index(phases[0]));self.assertLess(h.events.index(phases[0]),h.events.index('archives-close'))
            self.assertLess(h.events.index('package-readback'),h.events.index(phases[1]))
    def test_failed_installed_readback_preserves_intent_without_storage(self):
        with self.harness() as (_,h,execute,_):
            h.bad_packages=True
            with self.assertRaises(ValueError):execute()
            self.assertEqual([x[1] for x in h.events if isinstance(x,tuple) and x[0]=='phase'],['packages'])
            self.assertTrue(any(p.endswith('/intent.json') for p in h.state.records));self.assertFalse(any(p.endswith('/result.json') for p in h.state.records))
    def test_unknown_package_phase_never_retries_or_writes_success(self):
        with self.harness() as (_,h,execute,calls):
            h.phase_fail='packages'
            with self.assertRaises(ValueError):execute()
            self.assertEqual(calls,[]);self.assertEqual(len([x for x in h.events if isinstance(x,tuple) and x[0]=='phase']),1)
    def test_separate_verification_queries_again_then_confirms(self):
        with self.harness() as (_,h,execute,calls):
            execute();execute(True);self.assertEqual(len(calls),3);self.assertTrue(any(p.endswith('/verified') for p in h.state.records))
    def test_legacy_or_altered_retained_evidence_never_confirms(self):
        for mode in ('legacy','changed'):
            with self.harness() as (_,h,execute,_):
                execute();path=next(p for p in h.state.records if p.endswith('/result.json'));value=json.loads(h.state.records[path])
                if mode=='legacy':value.pop('schemaVersion');value.pop('hostPackages')
                else:value['hostPackages']['packageCatalogSha256']=H.sha(b'changed')
                h.state.records[path]=H.canonical(value)
                with self.assertRaises(ValueError):execute(True)
                self.assertFalse(any(p.endswith('/verified') for p in h.state.records))

class ConsumerTests(unittest.TestCase):
    def fixture(self):
        f=fixture();r=F.request();initial=dict(r);request=dict(r);request['mode']='full';root=r['dataDir']+'/company/host-releases/install-'+r['operationId'];events=[]
        previous=SimpleNamespace(sources={'scripts/install.sh':b'captured phase'},templates={},configs={'catalog.json':b'{}'},provenance={},metadata={'releaseSha256':r['releaseSha256']},recheck=lambda:events.append('source-check'))
        held=SimpleNamespace(files=dict(previous.sources),configs=dict(previous.configs))
        rows=dict(previous.sources);rows.update({'company-release/'+name:raw for name,raw in previous.configs.items()})
        tree=H.sha(H.canonical({name:dict(bytes=len(raw),sha256=H.sha(raw)) for name,raw in sorted(rows.items())}))
        host={'installation.intent.json':{},'installation.json':{'installation_id':'synthetic'},'installation.storage-receipt.json':{}}
        result=dict(schemaVersion=2,hostPackages=f.current,scope='FOUNDATION_ONLY',status='effects-independently-confirmed',operationId=r['operationId'],installationId='synthetic',releaseSha256=r['releaseSha256'],treeSha256=tree,hostSha256=H.sha(H.canonical(host)),runscVersionSha256='a'*64,runtimeBinaryPins={},fullPlatformActivated=False,backupReady=False,runtimePairInitialized=False)
        evidence='/opt/autosoft-company/evidence/'+r['operationId'];store={evidence+'/intent.json':H.canonical(initial),evidence+'/result.json':H.canonical(result)}
        def marker():store[evidence+'/verified']=('foundation-verified-v1\noperation='+r['operationId']+'\noutcome='+H.sha(store[evidence+'/result.json'])+'\n').encode()
        marker();store.update({'/etc/autosoft/'+name:H.canonical(value) for name,value in host.items()})
        @contextmanager
        def authenticate(*args,**kw):events.append('source-enter');yield previous;events.append('source-close')
        v=SimpleNamespace(authenticated_deployment=authenticate,require_platform_source=lambda _:None)
        def run(current=None,package=None,tools=None):
            with patch.object(C,'host_observation',return_value=(H,package or f.package,tools or f.tools,current or f.current)):
                return C.foundation(Q,SimpleNamespace(read_protected=lambda p,n:store[p]),v,request,held,{'files':None,'crypto':None},'a'*64,modules={},host_catalogs=f.catalogs,check_authority=lambda:None)
        return SimpleNamespace(f=f,result=result,store=store,evidence=evidence,marker=marker,run=run,events=events)
    def test_versioned_source_bound_evidence_accepts_own_current_catalog(self):
        x=self.fixture();self.assertEqual(len(x.run()),64);self.assertIn('source-close',x.events)
    def test_legacy_receipt_is_retained_but_not_adopted(self):
        x=self.fixture();x.result.pop('schemaVersion');x.result.pop('hostPackages');x.store[x.evidence+'/result.json']=H.canonical(x.result);x.marker()
        before=dict(x.store)
        with self.assertRaisesRegex(ValueError,'legacy records'):x.run()
        self.assertEqual(x.store,before)
    def test_consumer_own_catalog_and_installed_drift_refuse(self):
        x=self.fixture();changed=copy.deepcopy(x.f.current);changed['toolCatalogSha256']=H.sha(b'other authenticated consumer catalog')
        with self.assertRaises(ValueError):x.run(current=changed)
        changed=copy.deepcopy(x.f.current);changed['installedPackages'][0]['version']='other'
        with self.assertRaises(ValueError):x.run(current=changed)

class PackageHandoffTests(unittest.TestCase):
    @contextmanager
    def emitted(self,catalogs=True):
        before=set(sys.modules)
        try:
            producer=load('host_handoff_native_producer',D/'build-native-retention-package.py');f=fixture()
            raw=producer.assemble(ROOT,'a'*64,reader=lambda path,limit:path.read_bytes(),
                host_tool_catalog=f.raw['tools'] if catalogs else None,
                host_package_catalog=f.raw['packages'] if catalogs else None)
            worker=type(sys)('host_handoff_emitted');exec(compile(raw,'<authenticated-package-test>','exec'),worker.__dict__)
            modules,_,_=worker.load_package()
            yield f,producer,raw,worker,modules
        finally:
            for name in set(sys.modules)-before:sys.modules.pop(name,None)
    def test_complete_captured_package_loads_matching_both_catalogs(self):
        with self.emitted() as (f,producer,raw,worker,modules):
            self.assertLessEqual(len(raw),producer.MAX_WORKER)
            self.assertEqual(worker.HOST_TOOL_CATALOG,f.catalogs['tools']);self.assertEqual(worker.HOST_PACKAGE_CATALOG,f.catalogs['packages'])
            self.assertEqual(set(modules),set(producer.PROGRAMS));self.assertIn('foundation_worker',modules)
            self.assertEqual(modules['host_package_runtime'].bindings({'tools':worker.HOST_TOOL_CATALOG,'packages':worker.HOST_PACKAGE_CATALOG},profiles=modules['host_tool_profiles'],packages=modules['host_packages'],observed_platform=dict(f.package['platform']))[0]['catalogSha256'],f.package['catalogSha256'])
    def test_configuration_action_uses_captured_catalogs_and_no_effects(self):
        with self.emitted() as (f,producer,raw,worker,modules):
            @contextmanager
            def observed(station):yield dict(f.package['platform']),lambda:None
            output=io.StringIO()
            with patch.object(modules['host_package_runtime'],'held_platform',observed),redirect_stdout(output):
                modules['configuration_worker'].run('configuration-action',modules,None,None,{},b'{}\n',H.sha(raw),None,
                    host_catalogs={'tools':worker.HOST_TOOL_CATALOG,'packages':worker.HOST_PACKAGE_CATALOG})
            self.assertEqual(output.getvalue().strip(),modules['configuration'].action(b'{}\n',H.sha(raw)))
            with patch.object(modules['host_package_runtime'],'held_platform',observed),self.assertRaises(ValueError):
                modules['configuration_worker'].run('configuration-action',modules,None,None,{},b'{}\n',H.sha(raw),None,host_catalogs=None)
    def test_native_producer_rejects_package_catalog_without_matching_tools(self):
        before=set(sys.modules)
        try:
            producer=load('host_handoff_bad_producer',D/'build-native-retention-package.py')
            with self.assertRaisesRegex(ValueError,'matching-company-tool'):
                producer.assemble(ROOT,'a'*64,reader=lambda path,limit:path.read_bytes(),host_package_catalog=fixture().raw['packages'])
        finally:
            for name in set(sys.modules)-before:sys.modules.pop(name,None)

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root protected-file fixtures')
class NativeTests(unittest.TestCase):
    @contextmanager
    def mapped(self):
        f=fixture()
        with tempfile.TemporaryDirectory(prefix='doxentriq-host-readback-',dir='/root') as directory:
            root=Path(directory);root.chmod(0o700)
            for name in ('etc','usr','usr/lib','usr/bin','usr/libexec','usr/libexec/docker','usr/libexec/docker/cli-plugins'):(root/name).mkdir(mode=0o755)
            (root/'usr/lib/os-release').write_bytes(b'ID="rocky"\nVERSION_ID="10.2"\n');(root/'etc/os-release').symlink_to('../usr/lib/os-release')
            for path,raw in [('/usr/bin/rpm',b'not executed package query fixture'),*[(f.tools['tools'][name]['path'],raw) for name,raw in f.bins.items()]]:
                p=root/path.lstrip('/');p.write_bytes(raw);p.chmod(0o755)
            class Station:
                UNRELEASED=S.UNRELEASED;metadata=staticmethod(S.metadata)
                @staticmethod
                def held_file(path,maximum,**kw):return S.held_file(root/str(path).lstrip('/'),maximum,**kw)
            class NativeOS:
                def __getattr__(self,name):return getattr(os,name)
                def open(self,path,*a,**kw):return os.open(root/'etc' if path=='/etc' else path,*a,**kw)
                def stat(self,path,*a,**kw):return os.stat(root/'etc' if path=='/etc' else path,*a,**kw)
            before=set(os.listdir('/proc/self/fd'))
            with patch.object(H,'os',NativeOS()):yield f,root,Station
            self.assertEqual(set(os.listdir('/proc/self/fd')),before)
    def test_actual_held_os_and_installed_binary_hashes(self):
        with self.mapped() as (f,root,station):
            calls=[]
            runner=SimpleNamespace(run=lambda argv,timeout:(calls.append((argv,timeout)) or query_raw(f)))
            result=H.readback(f.package,f.tools,station=station,runner=runner,check_authority=lambda:None)
            self.assertEqual(result,f.current);self.assertEqual(calls,[(H.query_command(f.package),30)])
    def test_actual_binary_drift_and_unsafe_os_link_refuse(self):
        with self.mapped() as (f,root,station):
            runner=SimpleNamespace(run=lambda *args:query_raw(f));(root/'usr/bin/docker').write_bytes(b'changed binary')
            with self.assertRaises(ValueError):H.readback(f.package,f.tools,station=station,runner=runner,check_authority=lambda:None)
            (root/'etc/os-release').unlink();(root/'etc/os-release').symlink_to('/untrusted/os-release')
            with self.assertRaises(ValueError):
                with H.held_platform(station):pass
    def test_platform_mutation_during_query_refuses_and_closes(self):
        with self.mapped() as (f,root,station):
            def run(*args):(root/'usr/lib/os-release').write_bytes(b'ID=rocky\nVERSION_ID=10.1\n');return query_raw(f)
            with self.assertRaises(ValueError):H.readback(f.package,f.tools,station=station,runner=SimpleNamespace(run=run),check_authority=lambda:None)
    def test_original_bash_entry_missing_catalog_refuses_before_any_paths(self):
        rows=B.assemble(ROOT,'a'*64,reader=lambda p,maximum=131072:p.read_bytes())
        with tempfile.TemporaryDirectory(prefix='doxentriq-no-catalog-',dir='/root') as directory:
            entry=Path(directory)/'company-install.sh';entry.write_bytes(rows['company-install.sh'])
            result=subprocess.run(['/bin/bash','--noprofile','--norc',str(entry),'--foundation-only','/path/that/does/not/exist'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/','LC_ALL':'C'},timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertIn(b'authenticated_host_package_catalog_required',result.stderr)
            self.assertEqual(sorted(x.name for x in Path(directory).iterdir()),['company-install.sh'])

if __name__=='__main__':unittest.main(verbosity=2)
