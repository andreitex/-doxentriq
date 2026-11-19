"""Actual delivered intake/IO inside private mount namespaces; no VM effects."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
ENV=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',TZ='UTC')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


def snapshot(root):
    result={}
    for path in sorted(root.rglob('*')):
        info=path.lstat()
        row=dict(inode=info.st_ino,mode=stat.S_IMODE(info.st_mode),mtime=info.st_mtime_ns,ctime=info.st_ctime_ns)
        if path.is_file():row['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        result[str(path.relative_to(root))]=row
    return result


def fault_program(mode,case):
    # Only the fixture process injects a failure into original helper functions.
    # The delivered helper bytes and both original validators stay unchanged.
    return ('MODE='+repr(mode)+'\nCASE='+repr(str(case))+'\n'+r'''
import importlib.util,os,signal,sys,time
from pathlib import Path
p=Path('/opt/autosoft-company/bootstrap/company-request-intake.py')
s=importlib.util.spec_from_file_location('actual_intake_fault_fixture',p)
I=importlib.util.module_from_spec(s);sys.modules[s.name]=I;s.loader.exec_module(I)
original_write=I.write_exclusive
def write(inputs,path,raw):
 if MODE=='partial-intent' and path.name=='intent.json':
  real_write=I.os.write
  def partial(fd,data):
   real_write(fd,data[:17])
   raise OSError('synthetic-partial-request-write')
  I.os.write=partial
  try:return original_write(inputs,path,raw)
  finally:I.os.write=real_write
 original_write(inputs,path,raw)
 stop=(MODE.startswith('kill-') and path.name==MODE[5:])
 stop=stop or (MODE=='kill-foundation' and path.parent==I.REQUESTS and path.name.endswith('.foundation.json'))
 stop=stop or (MODE=='kill-full' and path.parent==I.REQUESTS and path.name.endswith('.json') and not path.name.endswith('.foundation.json'))
 if stop:os.kill(os.getpid(),signal.SIGKILL)
 if MODE=='replace-directory' and path.name=='intent.json':
  os.rename(I.REQUESTS,I.BASE/'requests-retained');os.mkdir(I.REQUESTS,0o700)
I.write_exclusive=write
original_prepare=I.prepare
def prepare(inputs,answers=None):
 if MODE=='kill-empty-intake':
  mkdir=inputs.state.mkdir
  def created(path,mode=0o700):
   result=mkdir(path,mode)
   if path==I.INTAKE:os.kill(os.getpid(),signal.SIGKILL)
   return result
  inputs.state.mkdir=created
 if MODE=='changed-readback':
  read=inputs.state.read
  def changing(path,maximum=131072):
   raw=read(path,maximum)
   if str(path).endswith('.foundation.json'):
    Path(path).write_bytes(raw.replace(b'foundation-only',b'foundation-evil'))
   return raw
  inputs.state.read=changing
 if MODE=='concurrent':
  mkdir=os.mkdir
  def pause(path,mode=0o700):
   if path==I.INTAKE:
    Path(CASE,'ready').write_text('ready')
    stop=time.monotonic()+10
    while not Path(CASE,'resume').exists():
     assert time.monotonic()<stop
     time.sleep(.01)
   return mkdir(path,mode)
  # Pause the original syscall after its real preflight, so the losing process
  # actually reaches mkdir's exclusive creation against the concurrent winner.
  os.mkdir=pause
 return original_prepare(inputs,answers)
I.prepare=prepare
try:I.main(['collect','--delivery-sha256',sys.argv[1]])
except BaseException as error:
 print(type(error).__name__+': '+str(error),file=sys.stderr)
 raise SystemExit(74)
''')


def fixture(mode,case):
    case=Path(case)
    assert sys.platform=='linux' and os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']) and case.resolve()==case
    for name in ('etc','opt'):
        child=case/name;child.mkdir(mode=0o700)
        subprocess.run(['/usr/bin/mount','--bind',str(child),'/'+name],check=True,timeout=10)
    T=load('actual_intake_producer_fixture',ROOT/'tests/test_company_request_intake.py')
    base=Path('/opt/autosoft-company');base.mkdir(mode=0o700)
    for name in ('bootstrap','incoming','staging','evidence','requests'):(base/name).mkdir(mode=0o700)
    defaults=json.loads(T.DEFAULTS)
    for name in ('foundation','platform'):
        source=Path(defaults[name]['sourceRoot']);source.mkdir(mode=0o700)
        bundle=Path(defaults[name]['bundleRoot']);bundle.mkdir(mode=0o700)
        raw=T.I.canonical(dict(fixture=name));path=bundle/'release.json';path.write_bytes(raw);path.chmod(0o400)
        defaults[name]['releaseSha256']=T.I.sha(raw)
    with T.G.clean_modules():
        records=T.B.assemble(ROOT,T.FINGERPRINT,reader=T.reader,host_catalogs={'engine':T.G.catalog()},
                             intake_defaults=T.I.canonical(defaults),public_key=T.PUBLIC)
    package=base/'bootstrap'
    for name,raw in records.items():
        path=package/name;path.write_bytes(raw);path.chmod(0o400)
    delivery=T.I.sha(records['guided-delivery.txt'])
    entry=package/'company-guided-private.sh'
    command=['/bin/bash','--noprofile','--norc',str(entry)]
    answers='/srv/doxentriq-intake-fixture\n/var/lib/doxentriq-intake-fixture.luks\n32\n'
    assert not Path('/srv/doxentriq-intake-fixture').exists()
    assert not Path('/var/lib/doxentriq-intake-fixture.luks').exists()
    if mode=='bad-receipt':delivery='f'*64
    if mode in ('changed-helper','changed-entry','changed-defaults'):
        name={'changed-helper':'company-request-intake.py','changed-entry':'company-guided-private.sh',
              'changed-defaults':'guided-request-defaults.json'}[mode]
        path=package/name;path.write_bytes(path.read_bytes()+b'\n')
    if mode=='receipt-writable':(package/'guided-delivery.txt').chmod(0o600)
    if mode=='missing-python':
        empty=case/'no-python';empty.write_bytes(b'');empty.chmod(0o400)
        subprocess.run(['/usr/bin/mount','--bind',str(empty),'/usr/bin/python3'],check=True,timeout=10)
    before=snapshot(base)
    if mode.startswith('kill-') or mode in ('replace-directory','changed-readback','partial-intent'):
        result=subprocess.run(['/usr/bin/python3','-I','-B','-c',fault_program(mode,case),delivery],
                              input=answers,text=True,capture_output=True,env=ENV,timeout=30)
    elif mode=='concurrent':
        child=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',fault_program(mode,case),delivery],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=ENV)
        try:
            child.stdin.write(answers);child.stdin.close();child.stdin=None
            stop=time.monotonic()+10
            while not (case/'ready').exists():
                assert child.poll() is None and time.monotonic()<stop
                time.sleep(.01)
            result=subprocess.run(command+['--prepare-requests',delivery],input=answers,text=True,capture_output=True,env=ENV,timeout=30)
            (case/'resume').write_text('continue')
            stdout,stderr=child.communicate(timeout=30)
            competing=dict(code=child.returncode,stdout=stdout,stderr=stderr)
        finally:
            if child.poll() is None:child.kill()
            child.wait(timeout=5)
    else:
        result=subprocess.run(command+['--prepare-requests',delivery],input=answers,text=True,capture_output=True,env=ENV,timeout=30)
    after=snapshot(base)
    status=subprocess.run(command+['--request-status',delivery],input='',text=True,capture_output=True,env=ENV,timeout=30)
    retry=None
    if mode not in ('missing-python','replace-directory','changed-readback'):
        retry=subprocess.run(command+['--prepare-requests',delivery],input='',text=True,capture_output=True,env=ENV,timeout=30)
    complete=base/'requests/intake/complete.json'
    request_files=sorted(path.name for path in (base/'requests').glob('*.json'))
    pair_accepted=None
    if complete.exists() and mode!='changed-readback':
        paths=[str(base/'requests'/name) for name in request_files]
        first=next(path for path in paths if path.endswith('.foundation.json'));full=next(path for path in paths if not path.endswith('.foundation.json'))
        accepted=subprocess.run(command+['--private-status',first,full],input='',text=True,capture_output=True,env=ENV,timeout=30)
        pair_accepted=accepted.returncode==0
    final=snapshot(base)
    report=dict(mode=mode,code=result.returncode,stdout=result.stdout,stderr=result.stderr,
        statusCode=status.returncode,statusOutput=status.stdout+status.stderr,
        retryCode=None if retry is None else retry.returncode,retryOutput='' if retry is None else retry.stdout+retry.stderr,
        afterReadOnlyUnchanged=after==final,allInputUnchanged=all(after.get(name)==row for name,row in before.items() if name.startswith(('bootstrap/','incoming/'))),
        deliveredReceiptMode=stat.S_IMODE((package/'guided-delivery.txt').stat().st_mode),
        requestModes={name:stat.S_IMODE((base/'requests'/name).stat().st_mode) for name in request_files},
        evidenceModes={path.name:stat.S_IMODE(path.stat().st_mode) for path in (base/'requests/intake').glob('*')},
        requestFiles=request_files,intakeFiles=sorted(path.name for path in (base/'requests/intake').glob('*')) if (base/'requests/intake').exists() else [],
        intakeNamespaceExists=(base/'requests/intake').exists(),
        intakeIntentBytes=(base/'requests/intake/intent.json').stat().st_size if (base/'requests/intake/intent.json').exists() else None,
        complete=complete.exists(),originalGuidedPairAccepted=pair_accepted,backingFileCreated=Path('/var/lib/doxentriq-intake-fixture.luks').exists(),
        dataDirectoryCreated=Path('/srv/doxentriq-intake-fixture').exists())
    if mode=='concurrent':report['competing']=competing
    if mode=='replace-directory':
        report['retainedFiles']=sorted(str(path.relative_to(base/'requests-retained')) for path in (base/'requests-retained').rglob('*'))
    (case/'report.json').write_text(json.dumps(report,sort_keys=True))


class NativeRequestIntake(unittest.TestCase):
    def run_case(self,mode):
        if sys.platform!='linux' or os.geteuid()!=0:self.skipTest('Requires actual Linux root mount namespace fixtures')
        root=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        case=root/uuid.uuid4().hex;case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',
                               str(Path(__file__).resolve()),'--fixture',mode,str(case)],env={**ENV,'DOXENTRIQ_NATIVE_TEST_ROOT':str(root)},
                              text=True,capture_output=True,timeout=100)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        report=json.loads((case/'report.json').read_text())
        self.assertFalse(report['backingFileCreated']);self.assertFalse(report['dataDirectoryCreated'])
        self.assertTrue(report['afterReadOnlyUnchanged'],report)
        return report

    def test_actual_package_creates_valid_pair_and_complete_rerun_has_no_prompts(self):
        row=self.run_case('success')
        self.assertEqual(row['code'],0,row);self.assertTrue(row['complete']);self.assertTrue(row['allInputUnchanged'])
        self.assertEqual(row['statusCode'],0);self.assertEqual(row['retryCode'],0)
        self.assertIn('already exist and were verified',row['retryOutput'])
        self.assertNotIn('Folder where',row['retryOutput']);self.assertEqual(len(row['requestFiles']),2)
        self.assertTrue(row['originalGuidedPairAccepted'])
        self.assertEqual(row['deliveredReceiptMode'],0o400)
        self.assertEqual(set(row['requestModes'].values()),{0o600})
        self.assertEqual(row['evidenceModes'],{'intent.json':0o400,'complete.json':0o400})

    def test_receipt_helper_entry_and_defaults_tamper_refuse_before_request_writes(self):
        for mode in ('bad-receipt','changed-helper','changed-entry','changed-defaults','receipt-writable'):
            with self.subTest(mode=mode):
                row=self.run_case(mode);self.assertNotEqual(row['code'],0,row)
                self.assertEqual(row['requestFiles'],[]);self.assertEqual(row['intakeFiles'],[])

    def test_missing_python_has_actionable_refusal_before_prompts_or_writes(self):
        row=self.run_case('missing-python');self.assertNotEqual(row['code'],0,row)
        self.assertIn('needs Python 3',row['stderr']);self.assertEqual(row['requestFiles'],[])
        self.assertNotIn('Folder where',row['stdout'])

    def test_interrupt_after_intent_preserves_missing_pair_and_refuses_replay(self):
        row=self.run_case('kill-intent.json');self.assertEqual(row['code'],-signal.SIGKILL)
        self.assertEqual(row['intakeFiles'],['intent.json']);self.assertEqual(row['requestFiles'],[])
        self.assertIn('Missing:',row['statusOutput']);self.assertNotEqual(row['retryCode'],0)

    def test_interrupt_before_intent_preserves_empty_namespace_and_refuses_replay(self):
        row=self.run_case('kill-empty-intake');self.assertEqual(row['code'],-signal.SIGKILL,row)
        self.assertTrue(row['intakeNamespaceExists']);self.assertEqual(row['intakeFiles'],[])
        self.assertEqual(row['requestFiles'],[]);self.assertFalse(row['complete'])
        self.assertIn('stopped before its intent was durable',row['statusOutput'])
        self.assertNotEqual(row['retryCode'],0)

    def test_partial_intent_write_is_preserved_without_requests_or_completion(self):
        row=self.run_case('partial-intent');self.assertNotEqual(row['code'],0,row)
        self.assertIn('synthetic-partial-request-write',row['stderr'])
        self.assertEqual(row['intakeFiles'],['intent.json']);self.assertEqual(row['intakeIntentBytes'],17)
        self.assertEqual(row['requestFiles'],[]);self.assertFalse(row['complete'])
        self.assertNotEqual(row['statusCode'],0);self.assertNotEqual(row['retryCode'],0)

    def test_interrupt_after_first_request_preserves_it_without_creating_second(self):
        row=self.run_case('kill-foundation')
        self.assertEqual(row['code'],-signal.SIGKILL,row)
        self.assertEqual(len(row['requestFiles']),1);self.assertFalse(row['complete'])
        self.assertIn('Missing:',row['statusOutput']);self.assertNotEqual(row['retryCode'],0)

    def test_interrupt_after_both_requests_does_not_invent_completion(self):
        row=self.run_case('kill-full');self.assertEqual(row['code'],-signal.SIGKILL,row)
        self.assertEqual(len(row['requestFiles']),2);self.assertFalse(row['complete'])
        self.assertIn('completion was not confirmed',row['statusOutput']);self.assertNotEqual(row['retryCode'],0)

    def test_interrupt_after_durable_completion_redisplays_exact_original_pair(self):
        row=self.run_case('kill-complete.json');self.assertEqual(row['code'],-signal.SIGKILL,row)
        self.assertTrue(row['complete']);self.assertEqual(row['statusCode'],0);self.assertEqual(row['retryCode'],0)
        self.assertIn('already exist and were verified',row['retryOutput']);self.assertTrue(row['originalGuidedPairAccepted'])

    def test_changed_output_during_readback_is_not_confirmed(self):
        row=self.run_case('changed-readback');self.assertNotEqual(row['code'],0,row)
        self.assertIn('changed while reading',row['stderr']);self.assertFalse(row['complete'])
        self.assertEqual(len(row['requestFiles']),1)

    def test_directory_replacement_between_writes_stops_and_preserves_old_intent(self):
        row=self.run_case('replace-directory');self.assertNotEqual(row['code'],0,row)
        self.assertIn('request directory was replaced',row['stderr'])
        self.assertEqual(row['requestFiles'],[]);self.assertEqual(row['retainedFiles'],['intake','intake/intent.json'])

    def test_concurrent_intake_has_one_exclusive_winner_and_no_duplicate_pair(self):
        row=self.run_case('concurrent');self.assertEqual(row['code'],0,row)
        self.assertNotEqual(row['competing']['code'],0);self.assertIn('FileExistsError',row['competing']['stderr'])
        self.assertTrue(row['complete']);self.assertEqual(len(row['requestFiles']),2)
        self.assertEqual(row['retryCode'],0);self.assertTrue(row['originalGuidedPairAccepted'])


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
