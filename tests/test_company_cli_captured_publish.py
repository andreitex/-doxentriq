"""Actual frozen IO/publisher preparation, RAM syscalls only; no stage calls."""
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value
def module(name,raw):
    value=ModuleType(name);exec(compile(raw,'<explicit injected source fixture>','exec'),vars(value));return value
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')

class CapturedPublishControls(unittest.TestCase):
    def setUp(self):
        suffix=uuid.uuid4().hex
        self.Q=load('coupling_'+suffix,ROOT/'deploy/installer/company_cli_captured_publish.py')
        self.I=load('coupling_io_'+suffix,ROOT/'deploy/installer/company_cli_record_io.py')
        self.P=load('coupling_publisher_'+suffix,ROOT/'deploy/installer/company_cli_record_publish.py')
        self.R=load('coupling_reader_'+suffix,ROOT/'deploy/installer/company_cli_record.py')
        self.IT=load('coupling_io_fixtures_'+suffix,ROOT/'tests/test_company_cli_record_io.py')
        self.PT=load('coupling_publish_fixtures_'+suffix,ROOT/'tests/test_company_cli_record_publish.py')
        self.C=module('coupling_cli_'+suffix,self.PT.CLI_SOURCE)
        self.r=self.IT.RAM(self.I);self.A=ModuleType('coupling_adapters_'+suffix)
        self.collaborators=dict(files=object(),crypto=object(),backend_module=self.A,backend=object(),
            runner_module=self.A,runner=object(),parent_system_module=self.A,parent_system=object(),clock=lambda:1)
        request=canonical(dict(schemaVersion=1));plan=canonical(dict(actionSha256='c'*64))
        sha=lambda raw:self.Q.hashlib.sha256(raw).hexdigest()
        invocation=canonical(dict(command='execute-stage',stage='company-platform-store',requestSha256=sha(request),releaseSha256='a'*64,
            operationId='b'*32,storeOperationId='b'*32,planSha256=sha(plan),
            parent=['42','11','12','s-Abc123Def456',sha(request),'company-platform-store','c'*64]))
        self.r.bodies=dict(zip(('request.json','invocation.json','plan.json'),(request,invocation,plan)))
        for name,raw in self.r.bodies.items():self.r.metas[self.IT.PATH+'/'+name]['st_size']=len(raw)
        # Instrument only this separately test-loaded clone before admission.
        # The original saved preparation still creates the real private publisher.
        exec("_original_prepare=prepare_publish\n_prepared=[]\ndef prepare_publish(*args,**kwargs):\n _prepared.append(kwargs['dispatch_arguments'])\n return _original_prepare(*args,**kwargs)\n",vars(self.P))

    def context(self):return self.I.hold_publisher_io(self.IT.PATH,**self.r.arguments())
    def prepare(self,io,**changes):
        return self.Q.prepare_captured_publish(self.C,self.R,self.P,io_module=self.I,io=io,
            collaborators=dict(self.collaborators,**changes))
    def reject(self,action,*args,**kwargs):
        with self.assertRaises(self.Q.CapturedPublishUnavailable):action(*args,**kwargs)
    def close(self,io):
        io.release_inputs();io.close_outputs();self.assertIs(self.I.require_released(io),io)

    def test_actual_io_captures_only_form_original_fourteen_arguments_and_prepared_publisher(self):
        with self.context() as io:
            publisher=self.prepare(io);self.assertIs(type(publisher),self.P.RecordPublisher)
            args=self.P._prepared[0]
            self.assertEqual(len(args),14)
            for name,key in (('request.json','request_raw'),('invocation.json','invocation_raw'),('plan.json','plan_raw')):
                self.assertIs(args[key],io.captured_inputs[key])
                self.assertEqual(args[key],self.r.bodies[name])
            self.assertEqual(args['request_sha256'],self.Q.hashlib.sha256(args['request_raw']).hexdigest())
            self.assertEqual(args['invocation_sha256'],self.Q.hashlib.sha256(args['invocation_raw']).hexdigest())
            self.assertTrue(all(args[key] is value for key,value in self.collaborators.items()))
            self.assertEqual(self.C.calls,[]);self.assertEqual(self.r.writes,[])
            self.close(io)

    def test_caller_byte_substitution_refuses_before_io_getter_and_cannot_override_hashes(self):
        with self.context() as io:
            before=len(self.r.reads)
            self.reject(self.prepare,io,request_raw=b'caller-selected')
            self.reject(self.prepare,io,invocation_sha256='0'*64)
            self.assertEqual(len(self.r.reads),before);self.assertEqual(self.P._prepared,[])
            self.close(io)

    def test_closed_or_unissued_original_io_cannot_prepare_publisher(self):
        self.reject(self.prepare,self.I.PublisherIO())
        self.assertEqual(self.P._prepared,[]);self.assertEqual(self.r.opens,[])

    def test_getter_drift_preserves_actual_return_never_invokes_changed_prepare(self):
        changed=[]
        with self.context() as io:
            original=self.P.prepare_publish
            self.r.hooks['pread']=lambda *args:setattr(self.P,'prepare_publish',lambda *args,**kwargs:changed.append(args))
            self.reject(self.prepare,io)
            row=self.Q.UNRELEASED[-1]
            self.assertEqual(dict(row[6]),dict(request_raw=self.r.bodies['request.json'],invocation_raw=self.r.bodies['invocation.json'],plan_raw=self.r.bodies['plan.json']))
            self.assertEqual(changed,[]);self.assertEqual(self.P._prepared,[])
            self.r.hooks.clear();self.P.prepare_publish=original;self.Q.UNRELEASED.clear()
            before=len(self.r.reads);self.reject(self.prepare,io);self.assertEqual(len(self.r.reads),before)
            self.close(io)

    def test_successful_prepare_return_retained_before_post_class_drift(self):
        exec("def prepare_publish(*args,**kwargs):\n value=_original_prepare(*args,**kwargs)\n RecordPublisher.execute=lambda *args:None\n return value\n",vars(self.P))
        with self.context() as io:
            self.reject(self.prepare,io)
            row=self.Q.UNRELEASED[-1]
            self.assertIs(type(row[8]),self.P.RecordPublisher)
            self.assertIs(row[2],io);self.assertEqual(self.r.writes,[]);self.assertEqual(self.C.calls,[])
            self.close(io)

    def test_one_use_second_prepare_denied_before_new_reader_or_capture_io(self):
        with self.context() as io:
            self.prepare(io);before=len(self.r.reads);self.Q.UNRELEASED.clear()
            self.reject(self.prepare,io)
            self.assertEqual(len(self.r.reads),before);self.assertEqual(len(self.P._prepared),1)
            self.close(io)

    def test_foreign_collaborator_keys_never_run_hash_or_equality_during_admission(self):
        callbacks=[]
        class Key:
            def __hash__(self):callbacks.append('hash');return 1
            def __eq__(self,other):callbacks.append('eq');return False
        value=dict(self.collaborators);value[Key()]=b'bytes';callbacks.clear()
        self.reject(self.Q.prepare_captured_publish,self.C,self.R,self.P,io_module=self.I,io=self.I.PublisherIO(),collaborators=value)
        self.assertEqual(callbacks,[]);self.assertEqual(self.r.opens,[])

    def test_main_refuses_with_no_io_selection_or_stage_execution(self):
        self.reject(self.Q.main,[]);self.assertEqual(self.r.opens,[]);self.assertEqual(self.C.calls,[])


if __name__=='__main__':unittest.main(verbosity=2)
