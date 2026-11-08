"""Worker binding/closure tests; synthetic effects grant no host authority."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value
W=load('infrastructure_worker_test','deploy/installer/company_infrastructure_worker.py')
P=load('infrastructure_policy_test','deploy/installer/company_infrastructure_policy.py')
Q=SimpleNamespace(require=P.require,canonical=P.canonical,sha=lambda raw:hashlib.sha256(raw).hexdigest())


class WorkerBindings(unittest.TestCase):
    def test_host_identity_is_inert_and_exact(self):
        self.assertEqual(W.platform_value(Q,b'NAME="Rocky Linux"\nID="rocky"\nVERSION_ID="10.2"\n'),
            dict(osId='rocky',versionId='10.2',architecture='x86_64'))
        for raw in (b'ID=rocky\nID=debian\nVERSION_ID=10\n',b'ID=ubuntu\nVERSION_ID=24.04\n',
                    b'ID=rocky\nVERSION_ID="$(id)"\n',b'ID=rocky\nVERSION_ID=10\x00',b'ID=rocky\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):W.platform_value(Q,raw)

    def test_action_binds_request_and_whole_worker(self):
        values={W.action(Q,r,w) for r,w in [(b'first','a'*64),(b'second','a'*64),(b'first','b'*64)]}
        self.assertEqual(len(values),3)
        with self.assertRaises(ValueError):W.action(Q,b'first','bad')

    def test_outcome_binds_render_and_preserves_scope(self):
        a=W.outcome(Q,{'releaseSha256':'a'*64},b'{}','b'*64,'s-abcdefghijkl',b'render',{'toolContext':'fixture'},{'scope':'synthetic-host'})
        b=W.outcome(Q,{'releaseSha256':'a'*64},b'{}','b'*64,'s-abcdefghijkl',b'other',{'toolContext':'fixture'},{'scope':'synthetic-host'})
        self.assertNotEqual(a,b)
        for name in ('identityProvisioned','publicStartupAllowed','backupReady','wholeInstallationQualified'):
            self.assertIs(a[name],False)

    def test_json_cannot_hide_duplicate_or_noncanonical_bindings(self):
        for raw in (b'{"x":1,"x":2}\n',b'{ "x":1 }',b'[]\n'):
            with self.assertRaises(ValueError):W.decode(Q,raw)

    def test_original_indented_wizard_configuration_is_accepted(self):
        bootstrap=load('infrastructure_configuration_bootstrap_test','scripts/bootstrap.py')
        value={'auth_origin':'https://auth.example.invalid','company_public_fingerprint':'a'*64}
        self.assertEqual(W.configuration(bootstrap,Q,(json.dumps(value,indent=2)+'\n').encode()),value)
        with self.assertRaises(ValueError):W.configuration(bootstrap,Q,b'{"auth_origin":"one","auth_origin":"two"}')

    def test_render_predecessor_reconstructs_instead_of_trusting_flags(self):
        RW=load('infrastructure_previous_test','deploy/installer/company_render_worker.py')
        request={'operationId':'a'*32,'releaseSha256':'b'*64};request_raw=P.canonical(request)
        session='s-abcdefghijkl';worker='c'*64;previous={'scope':'fixture'}
        manifest={'files':{'synthetic':{}},'directories':{},'labels':{}}
        manifest_raw=P.canonical(manifest);a=RW.action(Q,request_raw,worker)
        intent=P.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=a,session=session,workerSha256=worker))
        record=P.canonical(dict(scope='NATIVE_RENDER_STAGE_ONLY',requestSha256=Q.sha(request_raw),actionSha256=a,
            session=session,workerSha256=worker,releaseSha256=request['releaseSha256'],predecessorSha256=P.digest(previous),
            outputsSha256=Q.sha(manifest_raw),outputFiles=1,servicesActivated=False,identityProvisioned=False,backupReady=False))
        saved={'outputs.json':manifest_raw,'intent.json':intent,'executed.json':record,'verified.json':record}
        modules={'configuration':Q,'station':SimpleNamespace(read_protected=lambda path,limit:saved[Path(path).name]),'render_worker':RW}
        parent=SimpleNamespace(arguments=SimpleNamespace(session=session))
        actual=W.render_predecessor(modules,parent,request,request_raw,worker,previous)
        self.assertEqual(actual[:2],(manifest,record))
        wrong=json.loads(record);wrong['session']='s-XXXXXXXXXXXX';saved['verified.json']=P.canonical(wrong)
        with self.assertRaises(ValueError):W.render_predecessor(modules,parent,request,request_raw,worker,previous)


class ComponentClosure(unittest.TestCase):
    def scenario(self,*,fail=None):
        events=[]
        def authority():
            events.append('authority')
            if fail=='late-authority' and 'io-close' in events:raise ValueError('fixture late authority')
        class IO:
            def __init__(self,*args,**kwargs):events.append('io-open')
            def check(self):events.append('io-check')
            def close(self):
                events.append('io-close')
                if fail=='close':raise ValueError('fixture close')
        class Transport:
            def __init__(self,*args):events.append('transport-open')
            def close(self):events.append('transport-close')
        class Commands:
            def __init__(self,*args,**kwargs):events.append('commands-open')
            def preflight(self):events.append('preflight')
            def create(self):events.append('create')
            def start(self):
                events.append('start')
                if fail=='start':raise ValueError('fixture uncertain start')
                return {'synthetic':True}
            def close(self):events.append('commands-close')
        policy=SimpleNamespace(BINDS={},MUTABLE={},tool_pins=lambda b:{})
        modules=dict(infrastructure_policy=policy,infrastructure_io=SimpleNamespace(InfrastructureIO=IO),
            infrastructure_transport=SimpleNamespace(NativeTransport=Transport),
            infrastructure_probe=SimpleNamespace(Readiness=lambda *args:None),
            infrastructure_commands=SimpleNamespace(infrastructure_commands=lambda p:Commands),
            records=SimpleNamespace(directory=lambda path:None))
        def host_check(transport):
            events.append('host-check')
            if fail=='host-before' or fail=='host-after' and 'start' in events:raise ValueError('fixture host drift')
        def run():return W.execute_component(modules,data='fixture',source='fixture',cfg={},images={},compose_source=b'',
            manifest={},binding={},authority=authority,records_path='fixture',host=SimpleNamespace(verify=host_check))
        return events,run

    def test_success_is_returned_only_after_all_scopes_close(self):
        events,run=self.scenario();self.assertEqual(run(),{'synthetic':True})
        selected=[e for e in events if e!='authority' and e!='io-check']
        self.assertEqual(selected,['io-open','transport-open','commands-open','preflight','host-check','create','start','host-check',
            'commands-close','transport-close','io-close'])
        self.assertEqual(events[-1],'authority')

    def test_uncertain_start_never_retries_and_closes_owned_scopes(self):
        events,run=self.scenario(fail='start')
        with self.assertRaises(ValueError):run()
        self.assertEqual(events.count('create'),1);self.assertEqual(events.count('start'),1)
        self.assertEqual(events[-3:],['commands-close','transport-close','io-close'])

    def test_late_close_or_authority_failure_cannot_return_success(self):
        for failure in ('close','late-authority'):
            with self.subTest(failure=failure):
                events,run=self.scenario(fail=failure)
                with self.assertRaises(ValueError):run()
                self.assertIn('io-close',events)

    def test_host_recheck_is_required_before_create_and_after_start(self):
        for failure,count in [('host-before',0),('host-after',1)]:
            with self.subTest(failure=failure):
                events,run=self.scenario(fail=failure)
                with self.assertRaises(ValueError):run()
                self.assertEqual(events.count('create'),count);self.assertEqual(events.count('start'),count)
                self.assertIn('io-close',events)

    def test_independent_dispatch_has_no_executor_phase_or_start_path(self):
        calls=[];component={'immutableInputsSha256':'d'*64}
        def verify(**kwargs):
            calls.append(kwargs)
            return dict(executedOutcomeSha256=P.digest(component),immutableInputsSha256='d'*64,
                toolContext={'synthetic':True},privateInfrastructureObserved=True)
        policy=SimpleNamespace(canonical=P.canonical,digest=P.digest,require=P.require,tool_context=lambda b:{'synthetic':True})
        modules=dict(infrastructure_policy=policy,infrastructure_io=object(),infrastructure_transport=object(),
            infrastructure_probe=object(),infrastructure_evidence=SimpleNamespace(infrastructure_evidence=lambda *args:'reader'),
            infrastructure_verify=SimpleNamespace(verify_recorded_infrastructure=verify,infrastructure_verifier=lambda p:'verifier'))
        W.observe_component(modules,data='fixture',source='fixture',cfg={},images={},compose_source=b'',manifest={},binding={},
            authority=lambda:None,records_path='fixture',component=component,host=SimpleNamespace(verify=lambda transport:None))
        self.assertEqual(len(calls),1);self.assertEqual(calls[0]['executed_sha256'],P.digest(component))
        self.assertEqual(calls[0]['evidence_class'],'reader');self.assertTrue(callable(calls[0]['verifier_class']))


class ActiveStorageControls(unittest.TestCase):
    def scenario(self,active=None,nonempty=None):
        configuration=load('active_configuration_test','deploy/installer/company_configuration.py');calls=[]
        def command(argv):
            calls.append(argv)
            if argv[0]=='/usr/bin/docker':raise AssertionError('No empty-engine query is permitted after startup')
            unit=argv[-1];names=[s.removeprefix('--property=') for s in argv if s.startswith('--property=')]
            values=dict(ActiveState='active' if unit==active else 'inactive',SubState='running' if unit==active else 'dead',
                MainPID='0',ControlPID='0',ControlGroup='',LoadState='loaded')
            return ''.join(name+'='+values[name]+'\n' for name in names)
        storage=SimpleNamespace(fresh=False,host='/etc/autosoft',data='/srv/synthetic',
            startup=SimpleNamespace(L=SimpleNamespace(BROKER_DIRECTORIES=('repository','builds','apps','releases'))),
            files=SimpleNamespace(names=lambda path,limit:['unexpected'] if path.endswith('/'+str(nonempty)) else []),
            check=lambda:calls.append('storage-check'))
        return configuration,storage,SimpleNamespace(text=command),calls

    def test_legitimate_private_services_do_not_trigger_empty_engine_requirement(self):
        q,storage,commands,calls=self.scenario()
        with patch.object(W.os.path,'lexists',return_value=False):W.active_storage_check(q,storage,commands)
        self.assertEqual([r[-1] for r in calls if type(r) is list],list(q.UNITS))
        self.assertEqual(calls[-1],'storage-check')

    def test_any_active_public_writer_is_refused(self):
        q,storage,commands,calls=self.scenario(active='autosoft-backup.timer')
        with patch.object(W.os.path,'lexists',return_value=False),self.assertRaises(ValueError):W.active_storage_check(q,storage,commands)

    def test_completed_installation_is_not_adopted(self):
        q,storage,commands,calls=self.scenario()
        with patch.object(W.os.path,'lexists',return_value=True),self.assertRaises(ValueError):W.active_storage_check(q,storage,commands)
        self.assertEqual(calls,[])

    def test_runtime_app_or_release_contents_are_not_adopted(self):
        for name in ('apps','releases'):
            q,storage,commands,calls=self.scenario(nonempty=name)
            with patch.object(W.os.path,'lexists',return_value=False),self.assertRaises(ValueError):W.active_storage_check(q,storage,commands)


if __name__=='__main__':unittest.main(verbosity=2)
