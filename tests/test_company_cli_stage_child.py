"""Fixed child source composition: injected syscalls, no native/main/stage process.

Cheap controls use a declared synthetic CLI protocol. The separate genuine lane
reuses original C/F/V/P/Worker with before-admission test-only path translation
and a RAM native_stage_inputs replacement; native construction is not qualified.
"""
import base64
import contextlib
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value
def module(name,raw):
    value=ModuleType(name);exec(compile(raw,'<explicit stage-child fixture>','exec'),vars(value));return value
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')

CLI_ADDITIONS='''
from contextlib import contextmanager
_CLI_OWNERS={};_CLOSED_OWNERS={};_native_calls=[];_fault_exit=False;_fault_enter=False;_exit_hook=lambda:None
_original_init=FullCli.__init__
def fixture_init(self):
 _original_init(self)
 state=dict(_closed=False,_failed=False,_retained=False)
 _CLI_OWNERS[id(self)]=(self,state,type(self),{}, {},None)
FullCli.__init__=fixture_init
def _owned_state(self):
 row=_CLI_OWNERS[id(self)]
 if row[0] is not self:raise ValueError('foreign')
 return row[1]
def native_stage_inputs(self,request_raw,**station):
 self.recheck();_native_calls.append((self,request_raw,station))
 return dict(files=station['files'],crypto=station['crypto'],backend_module=_adapters,backend=object(),runner_module=_adapters,runner=object(),parent_system_module=_adapters,parent_system=object(),clock=station['clock'])
FullCli.native_stage_inputs=native_stage_inputs
@contextmanager
def authenticated_cli(delivery_raw,*,delivery_module,delivery_pin,launch_pins,package_pins,operational_catalog,fingerprint,full_package_pin,bootstrap_records,bootstrap_pins,running_cli_raw):
 if _fault_enter:raise OSError(5,'fixture enter unavailable')
 cli=FullCli()
 try:yield cli
 finally:
  close_original(cli)
  state=_owned_state(cli)
  if _fault_exit:state['_failed']=True;raise OSError(5,'fixture CLI release')
  state['_closed']=True;_CLOSED_OWNERS[id(cli)]=(_CLI_OWNERS[id(cli)],cli._identity)
  _exit_hook()
'''

class Fixture:
    def __init__(self):
        suffix=uuid.uuid4().hex
        self.S=load('stage_child_'+suffix,ROOT/'deploy/installer/company_cli_stage_child.py')
        self.I=load('stage_child_io_'+suffix,ROOT/'deploy/installer/company_cli_record_io.py')
        self.P=load('stage_child_publisher_'+suffix,ROOT/'deploy/installer/company_cli_record_publish.py')
        self.K=load('stage_child_captured_'+suffix,ROOT/'deploy/installer/company_cli_captured_publish.py')
        self.R=load('stage_child_reader_'+suffix,ROOT/'deploy/installer/company_cli_record.py')
        self.IT=load('stage_child_io_fixture_'+suffix,ROOT/'tests/test_company_cli_record_io.py')
        self.PT=load('stage_child_pub_fixture_'+suffix,ROOT/'tests/test_company_cli_record_publish.py')
        self.CT=load('stage_child_crypto_fixture_'+suffix,ROOT/'tests/test_company_release_crypto.py')
        self.X=self.CT.C;self.h=self.CT.Harness()
        self.C=module('stage_child_cli_fixture_'+suffix,self.PT.CLI_SOURCE+CLI_ADDITIONS)
        self.A=ModuleType('stage_child_adapters_'+suffix);self.C._adapters=self.A
        self.r=self.IT.RAM(self.I)
        self.request=canonical(dict(schemaVersion=1));self.plan=canonical(dict(actionSha256='c'*64))
        sha=lambda raw:self.P.hashlib.sha256(raw).hexdigest()
        self.invocation=canonical(dict(command='execute-stage',stage='company-platform-store',requestSha256=sha(self.request),releaseSha256='a'*64,
            operationId='b'*32,storeOperationId='b'*32,planSha256=sha(self.plan),parent=['42','11','12','s-Abc123Def456',sha(self.request),'company-platform-store','c'*64]))
        self.bodies(self.request,self.invocation,self.plan)
        self.auth=dict(delivery_module=self.A,delivery_pin=dict(bytes=1,sha256='a'*64),launch_pins={},package_pins={},operational_catalog={},
            fingerprint='a'*64,full_package_pin=dict(bytes=1,sha256='a'*64),bootstrap_records={},bootstrap_pins={},running_cli_raw=b'C')
        self.station={name:self.A for name in self.S.STATION_FIELDS if name.endswith('_module')}
        self.station.update(libc=object(),tool_catalog={},backend_budget={},runner_budget={},clock=lambda:1,files=object())
        self.crypto=None
    def bodies(self,request,invocation,plan):
        self.r.bodies=dict(zip(('request.json','invocation.json','plan.json'),(request,invocation,plan)))
        for name,raw in self.r.bodies.items():self.r.metas[self.IT.PATH+'/'+name]['st_size']=len(raw)
    def io(self):return self.I.hold_publisher_io(self.IT.PATH,**self.r.arguments())
    def prepare(self,io,**changes):
        if self.crypto is None:self.crypto=self.h.crypto()
        args=dict(io_module=self.I,io=io,crypto_module=self.X,crypto=self.crypto,delivery_raw=b'D',authentication=self.auth,station=self.station)
        args.update(changes)
        return self.S.prepare_execute_child(self.C,self.R,self.P,self.K,**args)
    def dispose_io(self,io):
        io.release_inputs();io.close_outputs()

class StageChildControls(unittest.TestCase):
    def setUp(self):self.f=Fixture()
    def reject(self,call):
        with self.assertRaises(self.f.S.StageChildUnavailable):call()
    def test_fixed_original_callbacks_close_cli_and_crypto_before_actual_publication(self):
        f=self.f;observed=[]
        with f.io() as io:
            child=f.prepare(io)
            def write(*args):
                cli=f.C.calls[0][0]
                self.assertIs(f.C._CLOSED_OWNERS[id(cli)][0],f.C._CLI_OWNERS[id(cli)])
                self.assertIs(f.crypto.require_released(),f.crypto);observed.append('after-closure')
            f.r.hooks['write']=write
            result=child.run();raw=f.r.writes[0][1]
            self.assertEqual(result['recordSha256'],f.P.hashlib.sha256(raw).hexdigest())
            self.assertEqual(observed,['after-closure']);self.assertEqual(f.C._native_calls[0][1],f.request)
            self.assertFalse(result['crossProcessEvidenceIssued']);self.assertFalse(result['stageAcknowledged'])
            self.assertIs(f.I.require_released(io),io)
    def test_failed_original_cli_exit_prevents_publication_and_retains_actual_context(self):
        f=self.f;f.C._fault_exit=True
        with f.io() as io:
            child=f.prepare(io);self.reject(child.run)
            row=f.S.UNRELEASED[-1][0]
            self.assertIsNotNone(row['publisher']);self.assertIsNotNone(row['cli']);self.assertTrue(row['exit_attempted'])
            self.assertFalse(row['cli_known_closed']);self.assertEqual(f.r.writes,[])
            f.dispose_io(io)
    def test_crypto_release_failure_after_cli_close_prevents_record_output(self):
        f=self.f
        exec("_original_release=ReleaseCrypto.require_released\n_release_calls=[]\ndef release(self):\n _release_calls.append(self)\n value=_original_release(self)\n if len(_release_calls)==2:raise OSError(5,'fixture final crypto release')\n return value\nReleaseCrypto.require_released=release\n",vars(f.X))
        with f.io() as io:
            child=f.prepare(io);self.reject(child.run)
            row=f.S.UNRELEASED[-1][0]
            self.assertTrue(row['cli_known_closed']);self.assertEqual(f.r.writes,[])
            self.assertIs(row['crypto'],f.crypto);f.dispose_io(io)
    def test_unknown_output_close_retains_actual_write_and_never_retries(self):
        f=self.f
        with self.assertRaises(f.I.RecordIOUnavailable):
            with f.io() as io:
                child=f.prepare(io);f.r.fail_close.add(40);self.reject(child.run)
                self.assertEqual(len(f.r.writes),1);self.assertEqual(f.r.close_calls.count(40),1)
                row=f.S.UNRELEASED[-1][0];self.assertTrue(row['cli_known_closed']);self.assertIsNotNone(row['publisher'])
                f.S.UNRELEASED.clear();self.reject(child.run)
                self.assertEqual(len(f.r.writes),1);self.assertEqual(f.r.close_calls.count(40),1)
        # Failed/unknown closure is deliberately retained by the original IO;
        # its context cannot report known release merely because test catches.
    def test_alternate_auth_context_or_dispatch_arguments_denied_before_callbacks(self):
        f=self.f
        with f.io() as io:
            bad=dict(f.auth,context_manager=object());before=len(f.r.reads)
            self.reject(lambda:f.prepare(io,authentication=bad))
            self.assertEqual(len(f.r.reads),before);self.assertEqual(f.C.calls,[])
            child=f.prepare(io)
            with self.assertRaises(TypeError):child.run(dict(request_raw=b'caller-selected'))
            f.dispose_io(io)
    def test_successful_use_cannot_reacquire_or_resume_after_public_clear(self):
        f=self.f
        with f.io() as io:
            child=f.prepare(io);child.run();f.S.UNRELEASED.clear()
            before=len(f.r.reads);self.reject(child.run);self.reject(lambda:f.prepare(io))
            self.assertEqual(len(f.r.reads),before);self.assertEqual(len(f.C.calls),1)
    def test_changed_saved_factory_boundary_denies_before_cli_acquisition(self):
        f=self.f;changed=[]
        with f.io() as io:
            child=f.prepare(io);original=f.C.authenticated_cli
            f.C.authenticated_cli=lambda *args,**kw:changed.append(args)
            self.reject(child.run);f.C.authenticated_cli=original;f.S.UNRELEASED.clear();self.reject(child.run)
            self.assertEqual(changed,[]);self.assertEqual(f.C.calls,[]);f.dispose_io(io)
    def test_auth_wrapper_closure_target_drift_denies_before_input_or_context(self):
        f=self.f;changed=[]
        with f.io() as io:
            child=f.prepare(io);cell=f.C.authenticated_cli.__closure__[0];original=cell.cell_contents
            cell.cell_contents=lambda *args,**kw:changed.append(args)
            before=len(f.r.reads);self.reject(child.run)
            cell.cell_contents=original;f.S.UNRELEASED.clear();self.reject(child.run)
            self.assertEqual(changed,[]);self.assertEqual(len(f.r.reads),before);f.dispose_io(io)
    def test_original_context_enter_failure_retains_owned_generator_without_publication(self):
        f=self.f;f.C._fault_enter=True
        with f.io() as io:
            child=f.prepare(io);self.reject(child.run)
            row=f.S.UNRELEASED[-1][0]
            self.assertTrue(row['cm_owned']);self.assertTrue(row['enter_attempted']);self.assertFalse(row['entered'])
            self.assertIs(row['cm'].gen,row['generator']);self.assertFalse(row['cli_known_closed'])
            self.assertEqual(f.r.writes,[]);f.dispose_io(io)
    def test_inherited_cm_constructor_drift_never_invokes_replacement_factory_callback(self):
        f=self.f;changed=[]
        with f.io() as io:
            child=f.prepare(io);base=contextlib._GeneratorContextManager.__mro__[1];original=vars(base)['__init__']
            base.__init__=lambda *args,**kw:changed.append(args)
            try:self.reject(child.run)
            finally:base.__init__=original
            self.assertEqual(changed,[]);self.assertEqual(f.C.calls,[]);f.dispose_io(io)
    def test_successful_original_exit_cm_state_drift_blocks_known_close_and_publication(self):
        f=self.f;owners=[]
        f.C._exit_hook=lambda:setattr(owners[0]['cm'],'gen',object())
        with f.io() as io:
            child=f.prepare(io)
            # Test-only mutation targets the exact privately owned CM. It
            # never substitutes an observation or supplies closure authority.
            issued=dict(zip(child.run.__func__.__code__.co_freevars,(cell.cell_contents for cell in child.run.__func__.__closure__)))['issued']
            registry=dict(zip(issued.__code__.co_freevars,(cell.cell_contents for cell in issued.__closure__)))['registry']
            owners.append(registry[id(child)])
            self.reject(child.run);row=f.S.UNRELEASED[-1][0]
            self.assertTrue(row['exit_attempted']);self.assertFalse(row['cli_known_closed']);self.assertEqual(f.r.writes,[])
            self.assertEqual(row['returns'][-1][0],'cli-exit');f.dispose_io(io)
    def test_unconfigured_main_never_selects_native_or_io(self):
        f=self.f;self.reject(lambda:f.S.main([]));self.assertEqual(f.r.opens,[]);self.assertEqual(f.h.starts,[])

class GenuineStageChildControls(unittest.TestCase):
    def test_genuine_original_store_closed_owner_registry_precedes_publication(self):
        f=Fixture();T=load('stage_child_genuine_'+uuid.uuid4().hex,ROOT/'tests/test_company_full_cli.py');g=T.Fixture();C=T.C
        original_factory=C.authenticated_cli;original_register=C._register;original_native=C.FullCli.native_stage_inputs
        try:
            with patch('subprocess.Popen',side_effect=AssertionError('no native process')):
                with g.context(genuine=True) as cli:planned=g.dispatch(cli,'plan-stage')
                plan=base64.b64decode(json.loads(planned.completed_record())['planBase64'],validate=True)
                files=g.w.f.q.files
                g.system.add(g.session+'/'+T.WT.W.STAGES[0]+'.intent',g.system.stage(T.WT.W.STAGES[0],json.loads(plan)['actionSha256']))
                invocation=g.invocation('execute-stage',plan);f.bodies(g.request_raw,invocation,plan)
                # Before trusted admission only: use the original genuine
                # factory through the existing RAM path translator. Restore
                # every original C binding before this outer generator yields.
                def enter_fixture():
                    C.authenticated_cli=original_factory
                    cm=g.context(genuine=True)
                    try:cli=cm.__enter__()
                    finally:C.authenticated_cli=test_factory;C._register=original_register
                    return cm,cli
                def exit_fixture(cm,problem):
                    C.authenticated_cli=original_factory
                    try:return cm.__exit__(None if problem is None else type(problem),problem,None if problem is None else problem.__traceback__)
                    finally:C.authenticated_cli=test_factory;C._register=original_register
                C._fixture_enter=enter_fixture;C._fixture_exit=exit_fixture
                C._fixture_backend,C._fixture_runner,C._fixture_system,C._fixture_module=g.w.backend,g.w.runner,g.system,T.WT.ADAPTERS
                exec("@contextmanager\ndef authenticated_cli(delivery_raw,*,delivery_module,delivery_pin,launch_pins,package_pins,operational_catalog,fingerprint,full_package_pin,bootstrap_records,bootstrap_pins,running_cli_raw):\n cm,cli=_fixture_enter()\n problem=None\n try:yield cli\n except BaseException as error:problem=error;raise\n finally:_fixture_exit(cm,problem)\ndef native_stage_inputs(self,request_raw,**station):\n self.recheck()\n return dict(files=station['files'],crypto=station['crypto'],backend_module=_fixture_module,backend=_fixture_backend,runner_module=_fixture_module,runner=_fixture_runner,parent_system_module=_fixture_module,parent_system=_fixture_system,clock=station['clock'])\nFullCli.native_stage_inputs=native_stage_inputs\n",vars(C))
                test_factory=C.authenticated_cli
                f.C=C;f.auth=g.args;f.station.update(files=files,clock=g.w.clock)
                f.crypto=f.h.crypto(budget=dict(calls=16,seconds=240))
                observed=[]
                with f.io() as io:
                    child=f.prepare(io,delivery_raw=g.delivery)
                    def check(*args):
                        row=C._CLOSED_OWNERS[id(g.contexts[-1])]
                        self.assertIs(row[0],C._CLI_OWNERS[id(g.contexts[-1])])
                        self.assertFalse(g.w.backend.handles);self.assertFalse(g.system.descriptors)
                        self.assertFalse(files.records);self.assertFalse(files.dirs)
                        self.assertFalse(g.contexts[-1]._V._ISSUED_PLATFORM_SOURCES)
                        self.assertIs(f.crypto.require_released(),f.crypto);observed.append('known-before-output')
                    f.r.hooks['write']=check
                    result=child.run();raw=f.r.writes[0][1];actual=g.contexts[-1]._observations[-1].completed_record()
                    self.assertEqual(raw,actual);self.assertEqual(result['recordSha256'],C.sha(actual))
                    self.assertEqual(observed,['known-before-output']);self.assertFalse(result['crossProcessEvidenceIssued'])
        finally:
            C.authenticated_cli=original_factory;C._register=original_register;C.FullCli.native_stage_inputs=original_native
            g.clean()

if __name__=='__main__':unittest.main(verbosity=2)
