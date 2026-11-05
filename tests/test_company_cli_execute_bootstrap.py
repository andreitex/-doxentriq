"""New bounded source/bootstrap controls; no native constructor or CLI stage.

Synthetic captures explicitly exercise delegation boundaries only. One control
prepares the actual frozen eight-module StageChild with original IO/Crypto
private issuance backed solely by RAM syscalls; it never runs the CLI stage.
"""
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, MappingProxyType
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT/'deploy/installer'


def load(path):
    name = 'execute_bootstrap_control_' + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec);sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


STAGE = b'''from types import MappingProxyType
calls=[]
class ExecuteChild:
 def run(self):
  calls.append(('run',self))
  return MappingProxyType(dict(dataOnly=True))
def prepare_execute_child(C,R,P,K,**kwargs):
 calls.append(('prepare',C,R,P,K,kwargs))
 return ExecuteChild()
'''


class Fixture:
    def __init__(self, actual=False):
        self.B = load(HERE/'company_cli_execute_bootstrap.py')
        self.captures = {label:(ROOT/path).read_bytes() if actual else b'marker=1\n'
                         for label, path in (*self.B.PROGRAM_PATHS, *self.B.BOOTSTRAP_PATHS)}
        if not actual:
            self.captures['stage'] = STAGE
            # Raw bootstrap bytes are admitted but never executed here.
            self.captures['verifier'] = b'not Python: original verifier byte fixture\n'
            self.captures['parent'] = b'not Python: original parent byte fixture\n'
        self.pins = {label:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                     for label, raw in self.captures.items()}
        self.before = set(sys.modules)
        self.value = None

    def capture(self):
        self.value = self.B.capture_execute_bootstrap(self.captures,self.pins,sys_module=sys)
        self.modules = {name.rsplit('_',1)[1]:sys.modules[name] for name in set(sys.modules)-self.before
                        if name.startswith('_company_execute_bootstrap_')}
        return self.value

    def arguments(self):
        return dict(io=object(),crypto=object(),delivery_raw=b'fixed-data',
                    authentication={name:{} for name in self.B.AUTHENTICATION_FIELDS},station={})

    def dispose(self):
        # Test process only: remove our registered synthetic/controlled modules.
        # Product exposes no release/adoption API; production lifetime is process.
        for name in tuple(set(sys.modules)-self.before):
            if name.startswith('_company_execute_bootstrap_'):del sys.modules[name]


class ExecuteBootstrapControls(unittest.TestCase):
    def fixture(self, actual=False):
        f=Fixture(actual);self.addCleanup(f.dispose);return f

    def deny(self, f, call):
        with self.assertRaises(f.B.ExecuteBootstrapUnavailable):call()

    def test_bad_last_independent_pin_precedes_all_compile_and_registration(self):
        f=self.fixture();f.captures['cli']=b'raise AssertionError("candidate must not execute")\n'
        f.pins['cli']=dict(bytes=len(f.captures['cli']),sha256=hashlib.sha256(f.captures['cli']).hexdigest())
        f.pins['parent']['sha256']='0'*64
        self.deny(f,f.capture)
        self.assertFalse(f.B.UNRELEASED)
        self.assertFalse(any(name.startswith('_company_execute_bootstrap_') for name in set(sys.modules)-f.before))

    def test_closed_input_shapes_reject_foreign_keys_without_callbacks(self):
        f=self.fixture();observed=[]
        class Foreign:
            def __hash__(self):return hash('parent')
            def __eq__(self,other):observed.append(other);raise AssertionError('foreign equality')
        foreign=Foreign();f.captures.pop('parent');f.captures[foreign]=b'opaque'
        self.deny(f,f.capture);self.assertEqual(observed,[]);self.assertFalse(f.B.UNRELEASED)

    def test_boolean_size_and_total_cap_refuse_before_compile(self):
        f=self.fixture();f.pins['parent']['bytes']=True;self.deny(f,f.capture)
        f=self.fixture()
        for label in ('cli','delivery','record'):
            raw=b'x'*100000;f.captures[label]=raw;f.pins[label]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        self.deny(f,f.capture);self.assertFalse(f.B.UNRELEASED)

    def test_exact_authentication_injects_original_delivery_cli_and_pair(self):
        f=self.fixture();b=f.capture();args=f.arguments();self.assertIs(b.prepare_child(**args),b)
        call=f.modules['stage'].calls[0];self.assertEqual(call[0],'prepare')
        self.assertIs(call[1],f.modules['cli']);self.assertIs(call[2],f.modules['record'])
        auth=call[5]['authentication']
        self.assertIs(auth['delivery_module'],f.modules['delivery'])
        self.assertIs(auth['running_cli_raw'],f.captures['cli'])
        for label,path in f.B.BOOTSTRAP_PATHS:
            self.assertIs(auth['bootstrap_records'][path],f.captures[label])
            self.assertEqual(auth['bootstrap_pins'][path],f.pins[label])
        result=b.run_child();self.assertIs(type(result),MappingProxyType)
        self.assertEqual(len(f.modules['stage'].calls),2)

    def test_caller_cannot_override_internal_bootstrap_authentication(self):
        f=self.fixture();b=f.capture();args=f.arguments()
        args['authentication']['running_cli_raw']=b'caller'
        self.deny(f,lambda:b.prepare_child(**args));self.assertEqual(f.modules['stage'].calls,[])
        f.B.UNRELEASED.clear();self.deny(f,lambda:b.prepare_child(**f.arguments()))

    def test_authentication_aggregate_cap_refuses_before_original_prepare(self):
        f=self.fixture();b=f.capture();args=f.arguments();fields=f.B.AUTHENTICATION_FIELDS
        args['authentication'][fields[0]]=b'a'*1048576
        args['authentication'][fields[1]]=b'b'*1048576
        args['authentication'][fields[2]]=b'c'
        self.deny(f,lambda:b.prepare_child(**args));self.assertEqual(f.modules['stage'].calls,[])

    def test_source_registration_drift_is_sticky_before_setup_callbacks(self):
        f=self.fixture();b=f.capture();io=f.modules['io'];saved=io.marker;io.marker=object()
        self.deny(f,lambda:b.construction_modules);io.marker=saved;f.B.UNRELEASED.clear()
        self.deny(f,lambda:b.prepare_child(**f.arguments()));self.assertEqual(f.modules['stage'].calls,[])
        self.assertFalse(any(row[0]=='prepare' for row in f.modules['stage'].calls))

    def test_in_place_original_run_code_drift_is_denied_without_new_callback(self):
        f=self.fixture();b=f.capture();b.prepare_child(**f.arguments())
        original=f.modules['stage'].ExecuteChild.run;code=original.__code__
        def replacement(self):raise AssertionError('changed run must not execute')
        original.__code__=replacement.__code__
        self.deny(f,b.run_child);original.__code__=code;f.B.UNRELEASED.clear();self.deny(f,b.run_child)
        self.assertEqual(len(f.modules['stage'].calls),1)

    def test_returned_child_is_retained_before_post_boundary_drift(self):
        f=self.fixture()
        f.captures['stage']=STAGE+b'''original_prepare=prepare_execute_child
def prepare_execute_child(C,R,P,K,**kwargs):
 value=original_prepare(C,R,P,K,**kwargs)
 C.marker=2
 return value
'''
        raw=f.captures['stage'];f.pins['stage']=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        b=f.capture();self.deny(f,lambda:b.prepare_child(**f.arguments()))
        record=f.B.UNRELEASED[-1][0]
        self.assertIs(type(record['child']),f.modules['stage'].ExecuteChild)
        self.assertIs(record['returns'][-1][1],record['child'])

    def test_partial_compile_failure_keeps_exact_modules_and_blocks_reacquire(self):
        f=self.fixture();raw=b'not valid Python !!\n';f.captures['stage']=raw
        f.pins['stage']=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        self.deny(f,f.capture);record=f.B.UNRELEASED[-1][0]
        self.assertEqual(len(record['registrations']),8)
        self.assertTrue(all(sys.modules[name] is module for name,module in record['registrations']))
        f.B.UNRELEASED.clear();self.deny(f,f.capture)

    def test_actual_eight_programs_prepare_original_stage_with_issued_ram_io_crypto(self):
        f=self.fixture(actual=True);b=f.capture();construction=b.construction_modules
        self.assertEqual(set(construction),{'io','crypto'})
        IT=load(ROOT/'tests/test_company_cli_record_io.py');XT=load(ROOT/'tests/test_company_release_crypto.py')
        I=construction['io'];X=construction['crypto'];ram=IT.RAM(I);h=XT.Harness()
        station_module=ModuleType('explicit_bootstrap_ram_station')
        station={name:station_module for name in f.modules['stage'].STATION_FIELDS if name.endswith('_module')}
        station.update(libc=object(),tool_catalog={},backend_budget={},runner_budget={},clock=ram.clock,files=object())
        auth={name:{} for name in f.B.AUTHENTICATION_FIELDS}
        with patch('subprocess.Popen',side_effect=AssertionError('no native child')):
            crypto=X.ReleaseCrypto(openssl_pin=h.pin(),budget=dict(calls=2,seconds=30),
                os_module=h.os,sys_module=h.sys,subprocess_module=h.subprocess,select_module=h.select,
                signal_module=h.signal,fcntl_module=h.fcntl,clock=h.clock,
                station_contract=X.STATION_CONTRACT,protected_fds=(0,1,2))
            with I.hold_publisher_io(IT.PATH,**ram.arguments()) as io:
                self.assertIs(b.prepare_child(io=io,crypto=crypto,delivery_raw=b'deferred delivery',authentication=auth,station=station),b)
                self.assertIs(crypto.require_released(),crypto)
                io.release_inputs();io.close_outputs();self.assertIs(I.require_released(io),io)
            self.assertEqual(h.starts,[]);self.assertEqual(ram.writes,[])

    def test_one_bootstrap_success_cannot_reacquire_and_unconfigured_main_denies(self):
        f=self.fixture();b=f.capture();f.B.UNRELEASED.clear();self.deny(f,f.capture)
        self.deny(f,lambda:f.B.main([]))
        clone=f.B.ExecuteBootstrap();self.deny(f,lambda:clone.construction_modules)


if __name__=='__main__':unittest.main(verbosity=2)
