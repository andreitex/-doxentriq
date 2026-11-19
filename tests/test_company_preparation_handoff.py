"""Original journal and runtime-pair parsers; synthetic acquisition, no activation."""
import copy
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import sys
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',str(ROOT)))
def source(relative):return ROOT/relative if (ROOT/relative).is_file() else BASE/relative
def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,source(relative));m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m
H=load('prep_handoff','deploy/installer/company_preparation_handoff.py')
F=load('prep_foundation','deploy/installer/company_install.py')
P=load('prep_parent','scripts/installer_parent.py')
Q=load('prep_configuration','deploy/installer/company_configuration.py')
W=load('prep_pair_worker','deploy/installer/company_runtime_pair_worker.py')
OLD='s-ABCDEFGHIJKL';LIVE='s-MNOPQRSTUVWX';WORKER='a'*64;PACKAGE='b'*64


class Records:
    def __init__(self):
        self.raw={};self.meta={};self.directories={}
        self.request=dict(operationId='c'*32,dataDir='/srv/platform',releaseSha256='d'*64)
        self.body=F.canonical(self.request);self.sha=F.sha(self.body)
        self.session=P.BASE+'/sessions/'+OLD;self.operation='/opt/autosoft-company/evidence/'+self.request['operationId']
        self.directory(self.session,80);self.directory(self.operation,81)
        self.put(P.BASE+'/binding',b'original admission namespace\n')
        self.put(self.session+'/intent',('install-session-v1\nsession='+OLD+'\nrequest='+self.sha
            +'\nbinding='+F.sha(self.raw[P.BASE+'/binding'])+'\ndirectory=1:80:41c0:0:0:700\nclosed=true\n').encode())
        for name in ('intent.json','result.json','verified'):self.put(self.operation+'/'+name,b'unchanged foundation\n')
        confirmations={};outcomes=[]
        for index,(stage,magic) in enumerate(zip(H.STAGES,H.MAGICS)):
            action=str(index+1)*64
            self.put(self.session+'/'+stage+'.intent',f'install-stage-v1\nsession={OLD}\nstage={stage}\naction={action}\nclosed=true\n'.encode())
            result=F.canonical(dict(fixtureStage=stage,requestSha256=self.sha,actionSha256=action,session=OLD,workerSha256=WORKER));outcome=F.sha(result);outcomes.append(outcome)
            confirmations[stage]=f'install-stage-confirmed-v1\nsession={OLD}\nstage={stage}\naction={action}\noutcome={outcome}\nindependently_confirmed=true\n'.encode()
            self.put(self.session+'/'+stage+'.confirmed',confirmations[stage]);self.directory(self.operation+'/'+stage,100+index)
            self.put(self.operation+'/'+stage+'/intent.json',F.canonical(dict(requestSha256=self.sha,actionSha256=action,session=OLD,workerSha256=WORKER)),0o400)
            self.put(self.operation+'/'+stage+'/executed.json',result,0o400);self.put(self.operation+'/'+stage+'/verified.json',result,0o400)
            self.put(self.operation+'/'+stage+'/confirmation',f'{magic}\nrequest={self.sha}\nsession={OLD}\nstage={stage}\naction={action}\noutcome={outcome}\n'.encode())
        self.final=F.sha(('preparation-only-v1:'+self.sha+':'+':'.join(outcomes)).encode())
        manifest=F.sha(b''.join(confirmations[n] for n in sorted(confirmations)))
        self.put(self.session+'/complete',f'install-complete-v1\nsession={OLD}\nrequest={self.sha}\nmanifest={manifest}\nfinal={self.final}\nindependently_confirmed=true\n'.encode())
    def directory(self,p,ino):
        self.directories[str(p)]=SimpleNamespace(st_dev=1,st_ino=ino,st_mode=0o40700,st_uid=0,st_gid=0,st_nlink=2,st_size=128,st_mtime_ns=1,st_ctime_ns=1)
    def put(self,p,raw,mode=0o600):
        p=str(p);self.raw[p]=raw
        if p not in self.meta:self.meta[p]=SimpleNamespace(st_dev=1,st_ino=200+len(self.meta),st_mode=0o100000|mode,st_uid=0,st_gid=0,st_nlink=1,st_size=len(raw),st_mtime_ns=1,st_ctime_ns=1)
        self.meta[p].st_size=len(raw)
    def read(self,p,maximum):
        raw=self.raw[str(p)];F.require(len(raw)<=maximum);return raw
    def protected(self,p):return self.meta[str(p)]
    def observe_directory(self,p):return self.directories[str(p)]
    def names(self,p):
        prefix=str(p)+'/'
        return sorted({n[len(prefix):].split('/')[0] for n in (*self.raw,*self.directories) if n.startswith(prefix)})
    def inspect(self,**kwargs):
        values=dict(F=F,P=P,state=self,request=self.request,request_raw=self.body,worker_sha=WORKER,predecessor=OLD)
        values.update(kwargs)
        with patch.object(H,'Path',PurePosixPath):return H.completed(**values)


class Journal(unittest.TestCase):
    def test_original_sorted_manifest_and_three_stage_result_bindings(self):
        f=Records();before=copy.deepcopy(f.raw);observed=f.inspect()
        self.assertEqual(observed['final'],f.final);self.assertEqual(set(observed['results']),set(H.STAGES));self.assertEqual(f.raw,before)
    def test_changed_worker_session_request_and_package_are_not_adopted(self):
        f=Records();saved=f.inspect();first=H.action(F,f.body,WORKER,OLD,PACKAGE,saved)
        for change in (dict(worker_sha='e'*64),dict(predecessor=LIVE),dict(request_raw=b'changed')):
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):f.inspect(**change)
        self.assertNotEqual(first,H.action(F,f.body,WORKER,OLD,'e'*64,saved))
    def test_missing_confirmation_or_completion_refuses_without_writing(self):
        for name in ('complete',*[stage+'.confirmed' for stage in H.STAGES]):
            f=Records();del f.raw[f.session+'/'+name];before=copy.deepcopy(f.raw)
            with self.subTest(name=name),self.assertRaises(ValueError):f.inspect()
            self.assertEqual(f.raw,before)
    def test_partial_or_completed_private_work_and_extra_inventory_refuse(self):
        for name in ('private-session','company-platform-store/intent.json','unexpected'):
            f=Records();f.put(f.operation+'/'+name,b'preserve')
            with self.subTest(name=name),self.assertRaises(ValueError):f.inspect()
    def test_changed_result_or_confirmation_is_not_an_execution_receipt(self):
        for name in ('executed.json','verified.json','confirmation','intent.json'):
            f=Records();target=f.operation+'/'+H.STAGES[1]+'/'+name
            f.put(target,f.raw[target]+b' ')
            with self.subTest(name=name),self.assertRaises(ValueError):f.inspect()
    def test_world_writable_or_replaced_old_record_changes_binding(self):
        f=Records();before=f.inspect();target=f.operation+'/'+H.STAGES[0]+'/verified.json'
        f.meta[target].st_ino+=1;self.assertNotEqual(before,f.inspect())
        f.meta[target].st_mode=0o100666
        with self.assertRaises(ValueError):f.inspect()
    def test_new_parent_is_allowed_but_previous_handoff_is_never_replayed(self):
        f=Records();path=P.BASE+'/sessions/'+LIVE+'/intent'
        f.put(path,f'install-session-v1\nsession={LIVE}\nrequest={f.sha}\nbinding=x\ndirectory=x\nclosed=true\n'.encode())
        with self.assertRaises(ValueError):f.inspect()
        self.assertEqual(f.inspect(current_session=LIVE)['final'],f.final)
    def test_foreign_foundation_session_does_not_grant_or_block_full_request(self):
        f=Records();f.put(P.BASE+'/sessions/'+LIVE+'/intent',f'install-session-v1\nsession={LIVE}\nrequest={"9"*64}\nbinding=x\ndirectory=x\nclosed=true\n'.encode())
        self.assertEqual(f.inspect()['final'],f.final)
    def test_original_final_and_sorted_manifest_must_both_match(self):
        for field in ('final','manifest'):
            f=Records();path=f.session+'/complete';text=f.raw[path].decode();prefix=field+'='
            text='\n'.join(prefix+'0'*64 if line.startswith(prefix) else line for line in text.split('\n'));f.put(path,text.encode())
            with self.subTest(field=field),self.assertRaises(ValueError):f.inspect()
    def test_resealed_result_still_must_match_original_action_request_session_and_worker(self):
        for field,changed in (('actionSha256','f'*64),('requestSha256','f'*64),('session',LIVE),('workerSha256','f'*64)):
            f=Records();stage=H.STAGES[1];directory=f.operation+'/'+stage
            value=__import__('json').loads(f.raw[directory+'/executed.json']);value[field]=changed;raw=F.canonical(value);outcome=F.sha(raw)
            for name in ('executed.json','verified.json'):f.put(directory+'/'+name,raw,0o400)
            for name in (directory+'/confirmation',f.session+'/'+stage+'.confirmed'):
                f.put(name,re.sub(rb'outcome=[a-f0-9]{64}',b'outcome='+outcome.encode(),f.raw[name]))
            outcomes=[P.record(f.raw[f.session+'/'+name+'.confirmed'],'install-stage-confirmed-v1',('session','stage','action','outcome','independently_confirmed'))['outcome']for name in H.STAGES]
            final=F.sha(('preparation-only-v1:'+f.sha+':'+':'.join(outcomes)).encode())
            manifest=F.sha(b''.join(f.raw[f.session+'/'+name+'.confirmed']for name in sorted(H.STAGES)))
            complete=re.sub(rb'final=[a-f0-9]{64}',b'final='+final.encode(),f.raw[f.session+'/complete'])
            f.put(f.session+'/complete',re.sub(rb'manifest=[a-f0-9]{64}',b'manifest='+manifest.encode(),complete))
            with self.subTest(field=field),self.assertRaises(ValueError):f.inspect()


class Pair(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.T=load('prep_original_pair_fixture','scripts/test-runtime-pair-init.py')
    def fixture(self):
        T=self.T;f=T.Fixture();f.root=f.data/'company/host-releases'/('install-'+'c'*32);f.root.mkdir(parents=True)
        f.intent['proposal']['install_root']=str(f.root);f.final['install_root']=str(f.root);f.receipt['install_root']=str(f.root)
        for name,value in ((T.P.S.I.INTENT,f.intent),('installation.json',f.final),('installation.storage-receipt.json',f.receipt)):
            f.rewrite(f.host/name,value)
        f.call();f.files.events.clear();f.authority.hold=lambda *_:self.fail('old parent must never reopen')
        return f
    def inspect(self,f):
        T=self.T;R=T.P;transport=T.F.Transport(f.files);observations=[]
        def path(value):R.C.require(type(value) is str and Path(value).is_absolute() and str(Path(value))==value);return value
        def layout(data,files):return R.S.L.verify(data,files=files,build_mount=lambda _:dict(f.placement.mount))
        inputs=dict(host_directory=f.host,files=f.files,command=T.F.forbidden,mount=f.mount,layout=layout,
            gate_factory=f.gate,allocation_factory=f.allocation,read_state=f.read,clock=f.clock.time,timeout=10)
        request=dict(dataDir=str(f.data),operationId='c'*32,releaseSha256='d'*64)
        with patch.object(W,'native_inputs',lambda *_:inputs),patch.object(R.S.I,'path_value',path),patch.object(R,'os',transport),\
             patch.object(R.S,'os',transport),patch.object(R.S.L,'os',transport),patch.object(f.files,'descriptor',transport.descriptor):
            result=H.pair(dict(runtime_pair_worker=W,configuration=Q),SimpleNamespace(modules={W.PAIR:R}),request,
                F.canonical(request),WORKER,T.PARENT_SESSION_ID,R.C.digest({'synthetic-original-parent':T.INSTALLATION}),None,
                lambda:observations.append('fresh-parent-source-check'))
        self.assertFalse(transport.handles);self.assertFalse(transport.real);self.assertFalse(f.locks.held)
        self.assertGreaterEqual(len(observations),3);return result
    def test_original_pair_and_startup_readers_preserve_effects_and_parent_records(self):
        f=self.fixture();before={p.name:p.read_bytes()for p in f.stage.iterdir()};result=self.inspect(f)
        self.assertEqual(result['pairResult'],self.T.P._record(f.files,f.stage/'confirmed.json'))
        self.assertEqual(before,{p.name:p.read_bytes()for p in f.stage.iterdir()})
        self.assertFalse(any(row[0]in('write','mkdir','permission','replace-file')for row in f.files.events))
    def test_historical_parent_change_fails_at_original_intent_comparison(self):
        f=self.fixture();path=f.stage/'intent.json';value=f.files.read(path);value['parentSha256']='0'*64;f.rewrite(path,value)
        with self.assertRaises(ValueError):self.inspect(f)
        self.assertFalse(any(row[0]in('write','mkdir')for row in f.files.events))
    def test_partial_pair_is_preserved_and_never_reinitialized(self):
        f=self.fixture();(f.stage/'allocation-confirmed.json').unlink();before={p.name:p.read_bytes()for p in f.stage.iterdir()}
        with self.assertRaises(ValueError):self.inspect(f)
        self.assertEqual(before,{p.name:p.read_bytes()for p in f.stage.iterdir()})
    def test_uncertain_gate_operation_refuses_current_pair(self):
        f=self.fixture();base=next((f.gate().base/'operations').iterdir())
        f.files.write(base/'uncertain.json',dict(intentSha256=self.T.P.C.digest(f.files.read(base/'intent.json')),stage='completion'))
        with self.assertRaises(ValueError):self.inspect(f)
    def test_gate_record_replacement_changes_saved_aggregate(self):
        f=self.fixture();before=self.inspect(f);path=f.stage/'gate-confirmed.json';value=f.files.read(path);value['gateSha256']='0'*64;f.rewrite(path,value)
        self.assertNotEqual(before['stageRecordsSha256'],self.inspect(f)['stageRecordsSha256'])


class Repository(unittest.TestCase):
    """Actual captured seed readers with the existing finite memory transport."""
    @classmethod
    def setUpClass(cls):cls.T=load('prep_original_seed_fixture','tests/test_authenticated_seed.py')
    def fixture(self):
        T=self.T;T.B.SEED_UNRELEASED.clear()
        class Fixture(T.Fixture):INSTALL=T.Fixture.DATA+'/company/host-releases/install-'+T.Fixture.OP
        f=Fixture();request=dict(dataDir=f.DATA,operationId=f.OP,backingFile='/srv/backing.luks',releaseSha256='a'*64)
        body=Q.canonical(request)
        _,_,action=T.B.authenticated_seed_request(f.DATA,f.INSTALL,f.source,verifier_module=f.V,
            storage=f.storage,git=f.git,operation_id=f.OP,installation_request_sha256=Q.sha(body))
        f.parent.arguments.request=Q.sha(body);f.parent.arguments.action=action
        T.B.seed_authenticated_repository(f.DATA,f.INSTALL,f.source,verifier_module=f.V,parent_module=f.P,
            parent=f.parent,storage=f.storage,files=f.files,git=f.git,operation_id=f.OP,installation_request_sha256=Q.sha(body))
        f.parent.check=lambda:self.fail('historical parent must never reopen')
        f.backend.effects.clear();return f,request,body
    def inspect(self,f,request,body):
        T=self.T;backends=[];runners=[];checks=[];test=self
        class Backend(T.SeedBackend):
            def __init__(self,**kwargs):
                test.assertIs(kwargs['writable'],False)
                test.assertEqual(kwargs['data'],f.DATA);test.assertEqual(kwargs['install_root'],f.INSTALL)
                self.__dict__.update(f.backend.__dict__);self.closed=False;backends.append(self)
            def finish(self):
                test.assertFalse(self.handles);self.closed=True
            def require_released(self):test.assertTrue(self.closed);test.assertFalse(self.handles)
        class Runner(T.SeedRunner):
            def __init__(self,**kwargs):
                super().__init__(kwargs['backend']);runners.append(self)
            def preflight(self,tool):test.assertIs(self.backend.handles[tool],f.backend.nodes['/usr/bin/git'])
            def require_released(self):test.assertFalse(self.unknown)
        N=SimpleNamespace(SeedBackend=Backend,SeedRunner=Runner)
        tool=f.backend.nodes['/usr/bin/git']['raw'];station=SimpleNamespace(tool_pin=lambda path:dict(bytes=len(tool),sha256=Q.sha(tool)))
        modules=dict(repository_io=N,station=station,configuration=Q)
        assembly=SimpleNamespace(modules={'scripts/bootstrap.py':T.B,'scripts/startup_binding.py':f.S})
        result=H.repository(modules,assembly,f.source,f.V,request,body,WORKER,OLD,dict(runner=None),lambda:checks.append(1))
        self.assertGreaterEqual(len(checks),3);self.assertTrue(backends[0].closed)
        self.assertTrue(any('cat-file' in row[0] for row in runners[0].calls));return result
    def test_original_storage_git_and_output_checks_preserve_seed(self):
        f,request,body=self.fixture();before=copy.deepcopy(f.backend.nodes);result=self.inspect(f,request,body)
        self.assertEqual(result['seedCommit'],self.T.B._seed_plan(f.source)['commit'])
        self.assertEqual(f.backend.nodes,before);self.assertFalse(f.backend.effects);self.assertFalse(f.backend.handles)
    def test_modified_seed_bytes_are_rejected_by_original_output_reader(self):
        f,request,body=self.fixture();f.backend.nodes[f.DATA+'/runtime/repository/platform/package.json']['raw']=b'bad'
        with self.assertRaisesRegex(ValueError,'seed_output_bytes'):self.inspect(f,request,body)
        self.assertFalse(f.backend.effects);self.assertFalse(f.backend.handles)
    def test_changed_git_tool_is_rejected_by_original_seed_intent(self):
        f,request,body=self.fixture();f.backend.nodes['/usr/bin/git']['raw']=b'changed-exact-git'
        f.backend.nodes['/usr/bin/git']['info']['st_size']=len(b'changed-exact-git')
        with self.assertRaises(ValueError):self.inspect(f,request,body)
        self.assertFalse(f.backend.effects);self.assertFalse(f.backend.handles)
    def test_modified_seed_evidence_is_not_adopted(self):
        f,request,body=self.fixture();path=f.DATA+'/config/repository-seed/'+f.OP+'/objects-verified.json'
        value=self.T.B._seed_decode(f.backend.nodes[path]['raw']);value['nativeQualified']=True
        f.backend.nodes[path]['raw']=self.T.B._seed_json(value);f.backend.nodes[path]['info']['st_size']=len(f.backend.nodes[path]['raw'])
        with self.assertRaises(ValueError):self.inspect(f,request,body)
        self.assertFalse(f.backend.effects);self.assertFalse(f.backend.handles)


class Package(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.T=load('prep_guided_producer_fixture','tests/test_company_guided_package.py')
        cls.T.ROOT=ROOT;cls.T.BASE=BASE
        with cls.T.clean_modules():
            cls.records=cls.T.B.assemble(ROOT,'a'*64,reader=cls.T.reader,host_catalogs={'engine':cls.T.catalog()})
    def test_real_guided_producer_keeps_original_bound_and_captures_handoff(self):
        raw=self.records['company-guided-private.sh']
        self.assertLessEqual(len(raw),self.T.B.MAX_GUIDED_ENTRY)
        self.assertIn(b'--continue-after-preparation',raw)
        self.assertIn(b'verify-completed-preparation',raw)
        self.assertIn(b'if [[ $1 != --continue-after-preparation ]]',raw)
        self.assertIn(b'full_install_pending_signed_source_and_native_pair',self.records['company-install.sh'])
        worker=ModuleType('prep_captured_worker');worker.__file__='/opt/autosoft-company/company-native-retention.py'
        exec(compile(self.records['company-native-retention.py'],worker.__file__,'exec'),worker.__dict__)
        captured=worker.PACKAGE['programs']['preparation_handoff']
        self.assertEqual(__import__('base64').b64decode(captured['base64']),source('deploy/installer/company_preparation_handoff.py').read_bytes())
    def test_guided_emitted_limit_is_exact_and_input_bounds_are_unchanged(self):
        records={name:raw for name,raw in self.records.items() if name!='company-guided-private.sh'}
        actual=len(self.records['company-guided-private.sh']);limits=[]
        def reader(extra):
            def read(path,maximum):
                limits.append((Path(path).name,maximum));raw=self.T.reader(path,maximum)
                if Path(path).name=='company-guided-private.sh':raw+=b'\n'*extra
                self.assertLessEqual(len(raw),maximum);return raw
            return read
        self.assertEqual(len(self.T.B.entry(ROOT,records,reader=reader(40*1024-actual))),40*1024)
        with self.assertRaisesRegex(ValueError,'guided-entry-size'):
            self.T.B.entry(ROOT,records,reader=reader(40*1024+1-actual))
        self.assertTrue(all(limit==32768 for _,limit in limits));self.assertEqual(self.T.B.MAX_PACKAGE,4*1024**2)
    @unittest.skipUnless(os.name=='posix','Original native package requires Linux resource/process APIs')
    def test_real_worker_dispatch_binds_predecessor_package_and_original_catalog(self):
        worker=ModuleType('prep_captured_dispatch');worker.__file__='/opt/autosoft-company/company-native-retention.py'
        raw=self.records['company-native-retention.py'];exec(compile(raw,worker.__file__,'exec'),worker.__dict__)
        with self.T.clean_modules():
            modules,delivery,auth=worker.load_package();request=dict(schemaVersion=1,mode='full-installation',operationId='c'*32,
                releaseSha256='d'*64,bundleRoot='/opt/autosoft-company/incoming/release',sourceRoot='/opt/autosoft-company/incoming/source',
                keyPath='/opt/autosoft-company/bootstrap/company.pem',dataDir='/srv/platform',backingFile='/srv/platform.luks',
                capacityGiB=32,runscVersion='20261106.1',runscSha512='e'*128)
            body=worker.canonical(request);calls=[]
            def read(path,maximum):
                value=body if str(path).endswith('c'*32+'.json')else raw
                self.assertLessEqual(len(value),maximum);return value
            with patch.object(worker,'load_package',lambda:(modules,delivery,auth)),patch.object(modules['station'],'baseline',lambda:None),\
                 patch.object(modules['station'],'read_protected',read),patch.object(modules['preparation_handoff'],'run',lambda *a,**kw:calls.append((a,kw))):
                worker.main(['preparation-handoff-action','--request','/opt/autosoft-company/requests/'+'c'*32+'.json',
                    '--predecessor',OLD,'--guided-package-sha',PACKAGE])
                self.assertEqual(len(calls),1);args,kwargs=calls[0]
                self.assertEqual(args[5],body);self.assertEqual(args[6],worker.sha(raw));self.assertEqual(args[7:10],(None,OLD,PACKAGE))
                self.assertEqual(set(kwargs['host_catalogs']),{'engine'})
                with self.assertRaises(ValueError):
                    worker.main(['configuration-action','--request','/opt/autosoft-company/requests/'+'c'*32+'.json','--predecessor',OLD])
                self.assertEqual(len(calls),1)


if __name__=='__main__':unittest.main(verbosity=2)
