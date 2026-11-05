"""Injected publisher IO plus one actual original CLI Store fixture.

Synthetic IO is privately issued RAM ownership, not native terminal evidence.
The genuine fixture translates protected paths before trusted source admission;
no installed stage, native process, signing or ACK is invoked.
"""
import base64
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
READER = ROOT/'deploy/installer/company_cli_record.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def module(name, raw):
    value = ModuleType(name)
    exec(compile(raw, '<injected trusted protocol fixture>', 'exec'), vars(value))
    return value


CLI_SOURCE = '''
import hashlib,json
_owners={};_observations={};calls=[]
class CliObservation:
 def completed_record(self):
  row=_observations.get(id(self))
  if row is None or row[0] is not self or _owners[id(row[1])][1] is not False:raise ValueError('open/unissued')
  return row[2]
class FullCli:
 def __init__(self):
  self._identity='d'*64;_owners[id(self)]=[self,True]
 def recheck(self):
  row=_owners.get(id(self))
  if row is None or row[0] is not self or row[1] is not True:raise ValueError('inactive')
  return self
 def dispatch(self,command,**args):
  self.recheck();calls.append((self,command,args))
  inv=json.loads(args['invocation_raw'])
  binding={key:inv[key] for key in ('stage','requestSha256','releaseSha256','operationId','storeOperationId','planSha256')}
  binding.update(session=inv['parent'][3],actionSha256=inv['parent'][6])
  value=dict(schemaVersion=1,scope='FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY',command=command,deliveryIdentitySha256=self._identity,binding=binding,planBase64=None,result={},outcomeSha256='e'*64,stageAcknowledged=False,fullInstallationCompleted=False,nativeQualified=False)
  raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\\n').encode('ascii')
  observation=CliObservation();_observations[id(observation)]=(observation,self,raw)
  return observation
def close_original(cli):
 if _owners[id(cli)][0] is not cli:raise ValueError('foreign')
 _owners[id(cli)][1]=False
'''

IO_SOURCE = '''
UNRELEASED=[];_owners={};events=[]
class PublisherIO:
 def __init__(self,mode='ok',inputs=()):
  self.decorative=False
  _owners[id(self)]=dict(instance=self,mode=mode,inputs=tuple(inputs),inputToken=object(),outputToken=object(),failed=False,writes=[],closes=0)
 def release_inputs(self):
  row=_row(self);events.append('inputs')
  if row['mode']=='inputs-fail':row['failed']=True;UNRELEASED.append((self,row));raise OSError(5,'synthetic')
  for value in row['inputs']:
   if type(value) not in (dict,list,set) or len(value)!=0:raise ValueError('actual input still owned')
  row['inputToken']=None
  return self
 def write_stdout(self,raw):
  row=_row(self);events.append('write')
  if row['inputToken'] is not None:raise ValueError('inputs live')
  if row['mode']=='partial':row['writes'].append(raw[:-1]);return len(raw)-1
  row['writes'].append(raw)
  if row['mode']=='class-drift':PublisherIO.close_outputs=lambda value:events.append('foreign-close')
  if row['mode']=='publisher-drift':_publisher.RecordPublisher.publish=lambda value:events.append('foreign-publish')
  return len(raw)
 def close_outputs(self):
  row=_row(self);events.append('outputs');row['closes']+=1
  if row['mode']=='close-fail':row['failed']=True;UNRELEASED.append((self,row));raise OSError(5,'synthetic')
  row['outputToken']=None
  return self
def _row(value):
 if type(value) is not PublisherIO:raise ValueError('type')
 row=_owners.get(id(value))
 if row is None or row['instance'] is not value or row['failed']:raise ValueError('unknown/unissued')
 return row
def require_publisher_io(value):_row(value);return value
def require_inputs_released(value):
 if _row(value)['inputToken'] is not None:raise ValueError('inputs held')
 return value
def require_released(value):
 row=_row(value)
 if row['inputToken'] is not None or row['outputToken'] is not None:raise ValueError('held')
 return value
_publisher=None
'''


class PublisherControls(unittest.TestCase):
    def setUp(self):
        suffix = uuid.uuid4().hex
        self.P = load('publish_'+suffix, ROOT/'deploy/installer/company_cli_record_publish.py')
        self.R = load('publish_reader_'+suffix, READER)
        self.C = module('publish_cli_'+suffix, CLI_SOURCE)
        self.I = module('publish_io_'+suffix, IO_SOURCE)
        self.I._publisher = self.P
        self.A = ModuleType('publish_adapter_'+suffix)
        canon = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode('ascii')
        sha = lambda raw: self.P.hashlib.sha256(raw).hexdigest()
        self.plan = canon(dict(actionSha256='c'*64))
        self.request = canon(dict(schemaVersion=1))
        self.invocation = canon(dict(command='execute-stage', stage='company-platform-store',
            requestSha256=sha(self.request), releaseSha256='a'*64, operationId='b'*32,
            storeOperationId='b'*32, planSha256=sha(self.plan),
            parent=['42','11','12','s-Abc123Def456',sha(self.request),'company-platform-store','c'*64]))
        self.args = dict(request_raw=self.request, request_sha256=sha(self.request),
            invocation_raw=self.invocation, invocation_sha256=sha(self.invocation), plan_raw=self.plan,
            files=object(), crypto=object(), backend_module=self.A, backend=object(),
            runner_module=self.A, runner=object(), parent_system_module=self.A,
            parent_system=object(), clock=lambda: 1)
        self.cli = self.C.FullCli()

    def prepare(self, mode='ok', **changes):
        self.io = self.I.PublisherIO(mode)
        return self.P.prepare_publish(self.C, self.R, dispatch_arguments=dict(self.args, **changes),
                                      io_module=self.I, io=self.io)

    def executed(self, mode='ok'):
        publisher = self.prepare(mode)
        self.assertIs(publisher.execute(self.cli), publisher)
        self.C.close_original(self.cli)
        return publisher

    def reject(self, action, *args, **kwargs):
        with self.assertRaises(self.P.RecordPublishUnavailable):action(*args, **kwargs)

    def test_fixed_dispatch_captured_arguments_and_actual_reader_bytes_once(self):
        publisher = self.prepare()
        self.args['request_raw'] = b'caller replaced after preparation'
        publisher.execute(self.cli)
        self.C.close_original(self.cli)
        result = publisher.publish()
        raw = self.I._owners[id(self.io)]['writes'][0]
        original = self.C._observations[next(iter(self.C._observations))][2]
        self.assertEqual(raw, original)
        self.assertEqual(result['recordSha256'], self.P.hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.C.calls[0][1], 'execute-stage')
        self.assertEqual(self.C.calls[0][2]['request_raw'], self.request)
        self.assertEqual(self.I.events, ['inputs','write','outputs'])
        self.assertFalse(result['crossProcessEvidenceIssued']);self.assertFalse(result['stageAcknowledged'])
        self.reject(publisher.publish)
        self.assertEqual(len(self.I._owners[id(self.io)]['writes']), 1)

    def test_open_original_scope_public_flags_never_publish(self):
        publisher = self.prepare();publisher.execute(self.cli)
        self.cli._closed = True
        self.reject(publisher.publish)
        self.assertEqual(self.I._owners[id(self.io)]['writes'], [])
        self.C.close_original(self.cli)
        self.reject(publisher.publish)

    def test_outer_input_unknown_prevents_record_getter_and_output(self):
        publisher = self.executed('inputs-fail')
        self.reject(publisher.publish)
        self.assertFalse(self.R.UNRELEASED)  # Saved reader was never invoked.
        self.assertEqual(self.I._owners[id(self.io)]['writes'], [])
        self.assertTrue(self.P.UNRELEASED)

    def test_partial_write_retains_original_record_and_no_retry(self):
        publisher = self.executed('partial');self.reject(publisher.publish)
        row = self.P.UNRELEASED[-1][0]
        self.assertIs(row['observation'], next(iter(self.C._observations.values()))[0])
        self.assertEqual(row['written'], len(row['raw'])-1)
        self.assertEqual(self.I._owners[id(self.io)]['closes'], 1)
        self.reject(publisher.publish)
        self.assertEqual(len(self.I._owners[id(self.io)]['writes']), 1)

    def test_unknown_output_close_retained_once_despite_public_clear(self):
        publisher = self.executed('close-fail');self.reject(publisher.publish)
        original = self.P.UNRELEASED[-1]
        original_io = self.io
        self.P.UNRELEASED.clear()
        self.reject(publisher.publish);self.reject(self.prepare)
        self.assertIs(original[0]['io'], original_io)
        self.assertEqual(self.I._owners[id(original_io)]['closes'], 1)

    def test_write_mutates_publisher_class_retains_successful_return(self):
        publisher = self.executed('publisher-drift');method = type(publisher).publish
        self.reject(method, publisher)
        row = self.P.UNRELEASED[-1][0]
        self.assertEqual(row['io_returns'][-1][0], 'write_stdout')
        self.assertEqual(row['io_returns'][-1][2], len(row['raw']))
        self.assertNotIn('foreign-publish', self.I.events)
        self.assertEqual(self.I._owners[id(self.io)]['closes'], 0)

    def test_io_class_drift_never_calls_replacement_cleanup(self):
        publisher = self.executed('class-drift');self.reject(publisher.publish)
        self.assertNotIn('foreign-close', self.I.events)
        self.assertEqual(self.I._owners[id(self.io)]['closes'], 0)
        self.assertTrue(self.P.UNRELEASED)

    def test_builtins_binding_drift_denied_before_dispatch(self):
        publisher = self.prepare();self.C.__builtins__ = {}
        self.reject(publisher.execute, self.cli)
        self.assertEqual(self.C.calls, [])

    def test_foreign_class_module_equality_never_observed(self):
        calls = []
        class Foreign:
            def __eq__(self, other):calls.append(other);raise AssertionError('foreign equality')
        self.C.FullCli.__module__ = Foreign()
        self.reject(self.prepare)
        self.assertEqual(calls, [])

    def test_unissued_clones_io_and_extra_arguments_refuse(self):
        self.reject(self.P.RecordPublisher().execute, self.cli)
        self.io = object.__new__(self.I.PublisherIO)
        self.reject(self.P.prepare_publish, self.C, self.R, dispatch_arguments=self.args, io_module=self.I, io=self.io)
        self.assertEqual(self.C.calls, [])

    def test_pins_mode_and_fresh_arguments_denied_before_original_call(self):
        self.reject(self.prepare, invocation_sha256='0'*64)
        self.reject(self.prepare, execution_evidence={})
        publisher = self.prepare()
        with self.assertRaises(TypeError):publisher.execute(self.cli, self.args)
        self.assertEqual(self.C.calls, [])

    def test_main_refuses_without_io_or_dispatch(self):
        self.reject(self.P.main, ['--execute-stage'])
        self.assertEqual(self.C.calls, [])


class GenuinePublisherControls(unittest.TestCase):
    def test_actual_original_store_closes_all_scopes_before_actual_byte_publication(self):
        suffix = uuid.uuid4().hex
        T = load('publish_genuine_fixture_'+suffix, ROOT/'tests/test_company_full_cli.py')
        C = T.C
        P = load('publish_genuine_'+suffix, ROOT/'deploy/installer/company_cli_record_publish.py')
        R = load('publish_genuine_reader_'+suffix, READER)
        I = module('publish_genuine_io_'+suffix, IO_SOURCE)
        f = T.Fixture()
        original_register = C._register
        try:
            with patch('subprocess.Popen', side_effect=AssertionError('native child')):
                with f.context(genuine=True) as cli:planned = f.dispatch(cli, 'plan-stage')
                plan = base64.b64decode(json.loads(planned.completed_record())['planBase64'], validate=True)
                with f.context(genuine=True) as cli:
                    # Test-only translator has already been captured in the
                    # original nested V. Restore C's original register before
                    # publisher/reader origin snapshots and keep it stable.
                    C._register = original_register
                    action = json.loads(plan)['actionSha256']
                    f.system.add(f.session+'/'+T.WT.W.STAGES[0]+'.intent', f.system.stage(T.WT.W.STAGES[0], action))
                    invocation = f.invocation('execute-stage', plan)
                    q = f.w.f.q
                    args = dict(request_raw=f.request_raw, request_sha256=C.sha(f.request_raw),
                        invocation_raw=invocation, invocation_sha256=C.sha(invocation), plan_raw=plan,
                        files=q.files, crypto=q.crypto, backend_module=T.WT.ADAPTERS, backend=f.w.backend,
                        runner_module=T.WT.ADAPTERS, runner=f.w.runner,
                        parent_system_module=T.WT.ADAPTERS, parent_system=f.system, clock=f.w.clock)
                    io = I.PublisherIO(inputs=(f.w.backend.handles, f.system.descriptors, q.files.records, q.files.dirs))
                    publisher = P.prepare_publish(C, R, dispatch_arguments=args, io_module=I, io=io)
                    publisher.execute(cli)
                    self.assertFalse(f.w.backend.handles);self.assertFalse(f.system.descriptors)
                    self.assertFalse(q.files.records);self.assertFalse(q.files.dirs)
                    self.assertFalse(cli._V._ISSUED_PLATFORM_SOURCES)
                self.assertIn(id(cli), C._CLOSED_OWNERS)
                result = publisher.publish()
                raw = I._owners[id(io)]['writes'][0]
                record = json.loads(raw)
                self.assertEqual(raw, cli._observations[-1].completed_record())
                self.assertEqual(result['recordSha256'], C.sha(raw))
                self.assertEqual(record['command'], 'execute-stage')
                self.assertEqual(record['outcomeSha256'], C.sha(C.canonical(record['result']['operationResult'])))
                self.assertIs(I.require_released(io), io)
                self.assertFalse(P.UNRELEASED);self.assertFalse(R.UNRELEASED)
                self.assertFalse(record['stageAcknowledged']);self.assertFalse(result['crossProcessEvidenceIssued'])
        finally:
            C._register = original_register
            f.clean()


if __name__ == '__main__':
    unittest.main(verbosity=2)
