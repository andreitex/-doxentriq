"""Actual worker component composition and files; synthetic Docker/readiness."""
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value);return value
F=load('worker_composition_fixture','tests/infrastructure_component_fixture.py')
W=load('worker_composition','deploy/installer/company_infrastructure_worker.py')
P=F.P

@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root protected-file fixture required')
class Composition(unittest.TestCase):
    def setUp(self):
        self.base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])/uuid.uuid4().hex;self.base.mkdir(mode=0o700)
        self.data=self.base/'data';self.data.mkdir(mode=0o700);self.records=self.base/'effects';self.records.mkdir(mode=0o700)
        self.modules={n:load('composition_'+n,'deploy/installer/company_'+n+'.py') for n in
            ('infrastructure_io','infrastructure_commands','infrastructure_evidence','infrastructure_verify')}
        self.I=self.modules['infrastructure_io'];self.authorized=True;self.transports=[];self.verifying=False;self.extra=False
        directories={''};files={}
        for rows in P.BINDS.values():
            for source,_,_,_ in rows:
                directory=source in ('mysql','mysql-keyring','redis','rabbitmq','registry','config/redis') or source.startswith(('tls/','secrets/'))
                if directory:
                    directories.add(source)
                    if source=='redis':files['redis/users.acl']=b'synthetic-acl'
                    if source.startswith(('tls/','secrets/')):files[source+'/fixture']=b'synthetic-input'
                else:files[source]=b'synthetic-config'
                name=source
                while '/' in name:name=name.rsplit('/',1)[0];directories.add(name)
        files['tls/ca.crt']=b'synthetic-ca'
        for name in sorted(directories-{''},key=lambda n:(n.count('/'),n)):(self.data/name).mkdir(mode=0o700)
        for name,raw in files.items():(self.data/name).write_bytes(raw);(self.data/name).chmod(0o600)
        manifest=dict(files={n:dict(identity=list(self.I.identity((self.data/n).lstat())),sha256=self.I.sha(raw)) for n,raw in files.items()},
            directories={n:dict(identity=list(self.I.identity((self.data/n).lstat())),children=sorted(p.name for p in (self.data/n).iterdir())) for n in directories-{'registry'}},labels={})
        self.old_data=F.DATA;F.DATA=str(self.data)
        self.modules.update(infrastructure_policy=P,infrastructure_transport=SimpleNamespace(NativeTransport=self.transport),
            infrastructure_probe=SimpleNamespace(Readiness=lambda *args:SimpleNamespace(ready=lambda *a,**kw:True)),
            records=SimpleNamespace(directory=self.record_directory))
        self.args=dict(data=str(self.data),source=F.SOURCE,cfg=F.CFG,images=F.IMAGES,compose_source=F.SOURCE_BYTES,
            manifest=manifest,binding=F.TOOLS,authority=self.authority,records_path=str(self.records),host=SimpleNamespace(verify=lambda transport:None))

    def tearDown(self):F.DATA=self.old_data

    def authority(self):
        if not self.authorized:raise ValueError('Synthetic predecessor changed')

    @contextmanager
    def record_directory(self,path):
        assert path==str(self.records)
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);before=self.I.identity(os.fstat(fd))[:5]
        def check():assert self.I.identity(os.fstat(fd))[:5]==before==self.I.identity(self.records.lstat())[:5]
        try:yield fd,check;check()
        finally:os.close(fd)

    def transport(self,io,pins):
        value=F.FakeTransport(io);self.assertEqual(pins,value.pins)
        value.closed=False
        if self.verifying:value.created=True;value.running=set(P.SERVICES)
        original=value.run
        def run(tool,args,**kwargs):
            result=original(tool,args,**kwargs)
            if self.extra and tool=='docker' and args[2:4]==['container','ls']:
                result.stdout+=b'\n'+b'f'*64+b'\n'
            return result
        value.run=run
        value.close=lambda:setattr(value,'closed',True)
        self.transports.append(value);return value

    def execute(self):
        result=W.execute_component(self.modules,**self.args)
        self.assertTrue(all(t.closed for t in self.transports));self.verifying=True
        return result

    def test_successful_execute_and_fresh_verifier_accept_exact_five_live_services(self):
        component=self.execute();before={p.name:p.read_bytes() for p in self.records.iterdir()}
        (self.data/'mysql/synthetic-business-data').write_bytes(b'preserved')
        observation=W.observe_component(self.modules,component=component,**self.args)
        self.assertTrue(observation['privateInfrastructureObserved']);self.assertTrue(self.transports[-1].closed)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.records.iterdir()})
        self.assertFalse(any(set(args)&{'create','start','stop','rm','up','pull'} for _,args in self.transports[-1].calls))

    def test_unexpected_sixth_live_container_refuses_independent_completion(self):
        component=self.execute();self.extra=True
        with self.assertRaises(ValueError):W.observe_component(self.modules,component=component,**self.args)
        self.assertTrue(self.transports[-1].closed)

    def test_changed_predecessor_refuses_before_reopening_live_transport(self):
        component=self.execute();before=len(self.transports);self.authorized=False
        with self.assertRaises(ValueError):W.observe_component(self.modules,component=component,**self.args)
        self.assertEqual(len(self.transports),before)

if __name__=='__main__':unittest.main(verbosity=2)
