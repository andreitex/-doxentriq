"""Original CLI fixture controls, separated cheap and genuine execution lanes."""
import base64,importlib.util,json,sys,unittest,uuid
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];HERE=ROOT/'deploy/installer'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
T=load('original_cli_record_fixtures',ROOT/'tests/test_company_full_cli.py');C=T.C
class RecordControls(unittest.TestCase):
 def setUp(self):
  self.R=load('record_reader_'+uuid.uuid4().hex,HERE/'company_cli_record.py');self.f=T.Fixture()
 def tearDown(self):self.f.clean()
 def reader(self,command='describe'):return self.R.prepare_record_reader(C,expected_command=command)
 def describe(self):
  with self.f.context() as cli:return cli.dispatch('describe',request_raw=C.canonical(self.f.request),request_sha256=C.sha(C.canonical(self.f.request)))
 def reject(self,reader,value):
  with self.assertRaises(self.R.RecordUnavailable):reader(value)
 def test_actual_closed_describe_exact_bytes_and_one_use_data(self):
  reader=self.reader();observation=self.describe();result=reader(observation);raw=observation.completed_record()
  self.assertEqual(result['record'],raw);self.assertEqual((result['sha256'],result['bytes']),(C.sha(raw),len(raw)))
  self.assertFalse(result['crossProcessEvidenceIssued']);self.assertFalse(result['parentTerminalQualified']);self.assertFalse(result['stageAcknowledged'])
  with self.assertRaises(TypeError):result['record']=b'changed'
  self.reject(reader,observation)
 def test_open_original_scope_refuses_then_cannot_retry_after_known_close(self):
  with self.f.context() as cli:
   reader=self.reader();observation=cli.dispatch('describe',request_raw=C.canonical(self.f.request),request_sha256=C.sha(C.canonical(self.f.request)))
   self.reject(reader,observation)
  self.assertTrue(observation.completed_record());self.reject(reader,observation);self.assertTrue(self.R.UNRELEASED)
 def test_public_closed_flags_cannot_create_original_closure(self):
  with self.f.context() as cli:
   reader=self.reader();observation=cli.dispatch('describe',request_raw=C.canonical(self.f.request),request_sha256=C.sha(C.canonical(self.f.request)))
   cli._closed=True
   try:self.reject(reader,observation)
   finally:cli._closed=False
 def test_clone_subclass_and_foreign_metaclass_refuse_before_callbacks(self):
  calls=[]
  class Meta(type):
   def __getattribute__(self,key):calls.append(key);raise AssertionError('foreign meta')
  class Foreign(metaclass=Meta):pass
  class Subclass(C.CliObservation):pass
  for value in (C.CliObservation(),Subclass(),Foreign(),{'stageAcknowledged':False}):
   self.R=load('record_reader_'+uuid.uuid4().hex,HERE/'company_cli_record.py');self.reject(self.reader(),value)
  self.assertEqual(calls,[])
 def test_module_method_and_helper_drift_rejects_without_changed_callbacks(self):
  observation=self.describe();calls=[]
  for target,name in ((C,'_closed_owner'),(C.CliObservation,'completed_record')):
   self.R=load('record_reader_'+uuid.uuid4().hex,HERE/'company_cli_record.py');reader=self.reader()
   with patch.object(target,name,lambda *args:calls.append('changed')):self.reject(reader,observation)
   self.reject(reader,observation)
  self.assertFalse(calls)
 def test_wrong_expected_command_retains_exact_original_bytes_and_observation(self):
  reader=self.reader('execute-stage');observation=self.describe();self.reject(reader,observation)
  row=self.R.UNRELEASED[-1];self.assertIs(row[5],observation);self.assertEqual(row[7],observation.completed_record());self.assertEqual(row[8],row[7])
 def test_public_unknown_ledger_replacement_cannot_resume_admission(self):
  reader=self.reader();self.reject(reader,C.CliObservation());original=self.R.UNRELEASED;self.R.UNRELEASED=[]
  with self.assertRaises(self.R.RecordUnavailable):self.reader()
  self.assertTrue(original);self.assertEqual(self.R.UNRELEASED,[])
 def test_error_constructor_replacement_does_not_invoke_foreign_code(self):
  reader=self.reader();original=self.R.RecordUnavailable;calls=[]
  self.R.RecordUnavailable=lambda *args:calls.append(args)
  with self.assertRaises(original):reader(C.CliObservation())
  self.assertFalse(calls)
 def test_reader_admission_finite_even_without_consumption(self):
  readers=[self.reader() for _ in range(64)]
  with self.assertRaises(self.R.RecordUnavailable):self.reader()
  self.assertEqual(len(set(readers)),64)
 def test_original_observation_record_drift_never_accepts_changed_bytes(self):
  reader=self.reader();observation=self.describe();observation._record=b'{}\n';self.reject(reader,observation)
  self.assertIs(self.R.UNRELEASED[-1][5],observation)
 def test_public_limits_and_command_references_cannot_change_original_admission(self):
  self.R.MAX_RECORD=1;self.R.MAX_READERS=1;self.R.COMMANDS=('arbitrary',)
  first=self.reader();second=self.reader();observation=self.describe()
  self.assertGreater(first(observation)['bytes'],1);self.assertEqual(second(observation)['record'],observation.completed_record())
  with self.assertRaises(self.R.RecordUnavailable):self.R.prepare_record_reader(C,expected_command='arbitrary')
class GenuineRecordControls(unittest.TestCase):
 def test_original_store_execution_fully_closes_before_record_data_read(self):
  R=load('record_reader_genuine_'+uuid.uuid4().hex,HERE/'company_cli_record.py');f=T.Fixture()
  try:
   with patch('subprocess.Popen',side_effect=AssertionError('native child')):
    with f.context(genuine=True) as cli:planned=f.dispatch(cli,'plan-stage')
    plan=base64.b64decode(json.loads(planned.completed_record())['planBase64'],validate=True)
    reader=R.prepare_record_reader(C,expected_command='execute-stage')
    with f.context(genuine=True) as cli:
     action=json.loads(plan)['actionSha256'];f.system.add(f.session+'/'+T.WT.W.STAGES[0]+'.intent',f.system.stage(T.WT.W.STAGES[0],action))
     observation=f.dispatch(cli,'execute-stage',plan)
     self.assertFalse(f.w.backend.handles);self.assertFalse(f.system.descriptors);self.assertFalse(f.w.f.q.files.records);self.assertFalse(f.w.f.q.files.dirs)
    result=reader(observation);raw=observation.completed_record();record=json.loads(raw)
    self.assertEqual(result['record'],raw);self.assertEqual(result['sha256'],C.sha(raw));self.assertEqual(record['command'],'execute-stage')
    self.assertEqual(record['outcomeSha256'],C.sha(C.canonical(record['result']['operationResult'])))
    self.assertIn(id(cli),C._CLOSED_OWNERS);self.assertFalse(R.UNRELEASED);self.assertFalse(result['crossProcessEvidenceIssued'])
  finally:f.clean()
if __name__=='__main__':unittest.main(verbosity=2)
