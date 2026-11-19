"""Actual emitted placement, interruption and races in private mount namespaces.

Only /opt inside a fresh private mount namespace is changed. No network,
packages, production directories or service calls are involved.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
ENV=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',TZ='UTC')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


def snapshot(root):
    result={}
    for path in sorted(root.rglob('*')):
        info=path.lstat();row=[info.st_ino,info.st_mode,info.st_mtime_ns,info.st_ctime_ns]
        if path.is_file():row.append(hashlib.sha256(path.read_bytes()).hexdigest())
        result[str(path.relative_to(root))]=row
    return result


def fixture(mode,case):
    case=Path(case);assert sys.platform=='linux'and os.geteuid()==os.getegid()==0
    assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])and case.resolve()==case
    assert str(os.stat('/proc/self/ns/mnt').st_ino)!=os.environ['DOXENTRIQ_PARENT_MOUNT_NAMESPACE']
    replacement=case/'opt';replacement.mkdir(mode=0o700)
    subprocess.run(['/usr/bin/mount','--bind',str(replacement),'/opt'],check=True,timeout=10)
    T=load('placement_actual_intake_fixture',ROOT/'tests/test_company_request_intake.py')
    with T.G.clean_modules():
        records=T.B.assemble(ROOT,T.FINGERPRINT,reader=T.reader,host_catalogs={'engine':T.G.catalog()},intake_defaults=T.DEFAULTS,public_key=T.PUBLIC)
    delivery=case/'delivery';delivery.mkdir(mode=0o700)
    for name,raw in records.items():
        path=delivery/name;path.write_bytes(raw);path.chmod(0o400)
    def reader(path,maximum=131072):
        if mode=='predecessor-replace-at-completion'and Path(path)==ROOT/'deploy/installer/company-place-guided.sh':
            raw=(ROOT/'tests/fixtures/company_guided_placement_before_completion_recheck.source.txt').read_bytes()
            assert hashlib.sha256(raw).hexdigest()=='4291041f5f7242b7a5ccc246a578a3bbcc97e5ced75eeb07cd4121fe4f9c4b9f'
            assert 0<len(raw)<=maximum
            return raw
        return T.reader(path,maximum)
    launcher=T.B.placement(ROOT,records,reader=reader)['doxentriq-place-guided.sh']
    entry=case/'doxentriq-place-guided.sh';entry.write_bytes(launcher);entry.chmod(0o400)
    digest=hashlib.sha256(records['guided-delivery.txt']).hexdigest()
    before=snapshot(delivery);entry_before=entry.read_bytes()
    command=['/bin/bash','--noprofile','--norc',str(entry)]
    extra={}
    if mode=='wrong-receipt':
        digest='0'*64
    if mode=='tampered-delivery':
        path=delivery/'company-guided-private.sh';path.chmod(0o600)
        path.write_bytes(path.read_bytes()+b'not-executed\n');path.chmod(0o400)
        before=snapshot(delivery)
    if mode=='replace-package-directory':
        # Inject only a filesystem race immediately before the original target
        # guard. The delivered source bytes and every guard remain unchanged.
        injected=r'''
set -Eeuo pipefail
source "$1" --help >/dev/null
definition=$(declare -f _bp_target_file)
[[ "$definition" = '_bp_target_file ()'* ]]
eval "_fixture_original_target${definition#_bp_target_file}"
_fixture_injected=false
_bp_target_file() {
  if [[ $_fixture_injected = false ]]; then
    _fixture_injected=true
    /usr/bin/mv -- /opt/autosoft-company/bootstrap /opt/autosoft-company/bootstrap-retained
    /usr/bin/mkdir -m 0700 -- /opt/autosoft-company/bootstrap
  fi
  _fixture_original_target "$@"
}
company_place_guided_entry --place "$2" "$3"
'''
    elif mode in('replace-at-completion','predecessor-replace-at-completion'):
        # The last inventory has succeeded, but completion has not been written.
        # The old candidate wrote its completion marker into this invalid state.
        injected=r'''
set -Eeuo pipefail
source "$1" --help >/dev/null
definition=$(declare -f _bp_inventory)
[[ "$definition" = '_bp_inventory ()'* ]]
eval "_fixture_original_inventory${definition#_bp_inventory}"
_fixture_injected=false
_bp_inventory() {
  _fixture_original_inventory "$@"
  if [[ $_fixture_injected = false && "$1" = /opt/autosoft-company/bootstrap && "$BP_PHASE" = copy ]]; then
    _fixture_injected=true
    /usr/bin/mv -- /opt/autosoft-company/bootstrap /opt/autosoft-company/bootstrap-retained
    /usr/bin/mkdir -m 0700 -- /opt/autosoft-company/bootstrap
  fi
}
company_place_guided_entry --place "$2" "$3"
'''
    elif mode=='interrupt-after-first-copy':
        injected=r'''
set -Eeuo pipefail
source "$1" --help >/dev/null
definition=$(declare -f _bp_copy_file)
[[ "$definition" = '_bp_copy_file ()'* ]]
eval "_fixture_original_copy${definition#_bp_copy_file}"
_bp_copy_file() {
  _fixture_original_copy "$@"
  kill -TERM "$BASHPID"
}
company_place_guided_entry --place "$2" "$3"
'''
    elif mode=='concurrent-placement':
        # The contender runs while the winning process is alive and owns a
        # durable intent. The winner proceeds only after refusal is captured.
        injected=r'''
set -Eeuo pipefail
source "$1" --help >/dev/null
_fixture_entry=$1 _fixture_delivery=$2 _fixture_digest=$3 _fixture_case=$4
definition=$(declare -f _il_write)
[[ "$definition" = '_il_write ()'* ]]
eval "_fixture_original_write${definition#_il_write}"
_il_write() {
  _fixture_original_write "$@"
  if [[ "$1" = /opt/autosoft-company/bootstrap-placement.intent ]]; then
    set +e
    /bin/bash --noprofile --norc "$_fixture_entry" --place "$_fixture_delivery" "$_fixture_digest" >"$_fixture_case/contender.log" 2>&1
    _fixture_status=$?
    set -e
    printf '%s\n' "$_fixture_status" >"$_fixture_case/contender.code"
    [[ $_fixture_status = 74 ]]
  fi
}
company_place_guided_entry --place "$2" "$3"
'''
    else:injected=None
    if injected is not None:
        done=subprocess.run(['/bin/bash','--noprofile','--norc','-c',injected,'fixture',str(entry),str(delivery),digest,str(case)],
                            env=ENV,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=120)
    else:
        action='--status'if mode=='status-before-placement'else'--place'
        done=subprocess.run(command+[action,str(delivery),digest],env=ENV,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=120)
    base=Path('/opt/autosoft-company')
    if mode=='completed-tamper':
        assert done.returncode==0
        path=base/'bootstrap/company-guided-private.sh';path.chmod(0o600)
        path.write_bytes(path.read_bytes()+b'not-executed\n');path.chmod(0o400)
    if mode=='concurrent-placement':
        extra=dict(contenderCode=int((case/'contender.code').read_text()),contenderOutput=(case/'contender.log').read_text())
    after=snapshot(base)
    status=subprocess.run(command+['--status',str(delivery),digest],env=ENV,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=120)
    retry_action='--status'if mode=='status-before-placement'else'--place'
    retry=subprocess.run(command+[retry_action,str(delivery),digest],env=ENV,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=120)
    members=list((base/'bootstrap').iterdir())if(base/'bootstrap').is_dir()else[]
    result=dict(mode=mode,code=done.returncode,stdout=done.stdout,stderr=done.stderr,**extra,
        statusCode=status.returncode,statusOutput=status.stdout+status.stderr,retryCode=retry.returncode,retryOutput=retry.stdout+retry.stderr,
        afterReadOnlyUnchanged=after==snapshot(base),deliveryUnchanged=before==snapshot(delivery),entryUnchanged=entry_before==entry.read_bytes(),
        baseExists=base.exists(),complete=(base/'bootstrap-placement.complete').exists(),intent=(base/'bootstrap-placement.intent').exists(),
        files=sorted(path.name for path in members),
        modes={path.name:stat.S_IMODE(path.stat().st_mode)for path in members},
        retainedFiles=sorted(path.name for path in (base/'bootstrap-retained').iterdir())if(base/'bootstrap-retained').exists()else[])
    (case/'result.json').write_text(json.dumps(result,sort_keys=True))


class NativePlacement(unittest.TestCase):
    def case(self,mode):
        if sys.platform!='linux'or os.geteuid()!=0:self.skipTest('Actual Linux root mount namespace required')
        root=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);case=root/uuid.uuid4().hex;case.mkdir(mode=0o700)
        done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',
            str(Path(__file__).resolve()),'--fixture',mode,str(case)],env={**ENV,'DOXENTRIQ_NATIVE_TEST_ROOT':str(root),
                'DOXENTRIQ_PARENT_MOUNT_NAMESPACE':str(os.stat('/proc/self/ns/mnt').st_ino)},
            stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=400)
        self.assertEqual(done.returncode,0,done.stdout+done.stderr)
        result=json.loads((case/'result.json').read_bytes())
        self.assertTrue(result['deliveryUnchanged']);self.assertTrue(result['entryUnchanged'])
        self.assertTrue(result['afterReadOnlyUnchanged']);return result

    def test_actual_placement_and_completed_rerun_preserve_fixed_package(self):
        row=self.case('success');self.assertEqual(row['code'],0,row)
        self.assertEqual(row['statusCode'],0,row);self.assertEqual(row['retryCode'],0,row)
        self.assertTrue(row['complete']);self.assertTrue(row['intent']);self.assertEqual(len(row['files']),11)
        self.assertEqual(set(row['modes'].values()),{0o400});self.assertEqual(row['retainedFiles'],[])
        self.assertIn('no files were copied or replaced',row['retryOutput'])

    def test_child_directory_replacement_refuses_and_preserves_partial_file(self):
        row=self.case('replace-package-directory');self.assertEqual(row['code'],74,row)
        self.assertIn('bootstrap_package_directory_replaced',row['stderr'])
        self.assertFalse(row['complete']);self.assertTrue(row['intent']);self.assertEqual(row['files'],[])
        self.assertEqual(row['retainedFiles'],['company-guided-private.sh'])
        self.assertNotEqual(row['statusCode'],0);self.assertNotEqual(row['retryCode'],0)
        self.assertIn('placement is incomplete',row['statusOutput'])

    def test_final_boundary_replacement_refuses_before_completion_record(self):
        row=self.case('replace-at-completion');self.assertEqual(row['code'],74,row)
        self.assertIn('bootstrap_package_directory_replaced',row['stderr'])
        self.assertFalse(row['complete']);self.assertTrue(row['intent']);self.assertEqual(row['files'],[])
        self.assertEqual(len(row['retainedFiles']),11)
        self.assertEqual(row['statusCode'],74);self.assertEqual(row['retryCode'],74)
        self.assertIn('placement is incomplete',row['retryOutput'])

    def test_predecessor_reproduces_invalid_completion_at_same_race_boundary(self):
        row=self.case('predecessor-replace-at-completion');self.assertEqual(row['code'],74,row)
        self.assertIn('bootstrap_package_directory_replaced',row['stderr'])
        self.assertTrue(row['complete']);self.assertTrue(row['intent']);self.assertEqual(row['files'],[])
        self.assertEqual(len(row['retainedFiles']),11)
        self.assertEqual(row['statusCode'],74);self.assertEqual(row['retryCode'],74)

    def test_interrupted_copy_preserves_partial_package_and_refuses_replay(self):
        row=self.case('interrupt-after-first-copy');self.assertEqual(row['code'],-15,row)
        self.assertFalse(row['complete']);self.assertTrue(row['intent'])
        self.assertEqual(row['files'],['company-guided-private.sh'])
        self.assertEqual(row['statusCode'],74);self.assertEqual(row['retryCode'],74)
        self.assertIn('placement is incomplete',row['retryOutput'])

    def test_concurrent_contender_refuses_without_changing_winning_placement(self):
        row=self.case('concurrent-placement');self.assertEqual(row['code'],0,row)
        self.assertEqual(row['contenderCode'],74);self.assertIn('placement is incomplete',row['contenderOutput'])
        self.assertTrue(row['complete']);self.assertTrue(row['intent']);self.assertEqual(len(row['files']),11)
        self.assertEqual(row['statusCode'],0);self.assertEqual(row['retryCode'],0)

    def test_wrong_independent_receipt_refuses_without_destination(self):
        row=self.case('wrong-receipt');self.assertEqual(row['code'],74,row)
        self.assertIn('bootstrap_independent_receipt_mismatch',row['stderr'])
        self.assertFalse(row['baseExists']);self.assertEqual(row['statusCode'],74);self.assertEqual(row['retryCode'],74)

    def test_tampered_delivery_refuses_without_destination(self):
        row=self.case('tampered-delivery');self.assertEqual(row['code'],74,row)
        self.assertIn('bootstrap_file_profile',row['stderr'])
        self.assertFalse(row['baseExists']);self.assertEqual(row['statusCode'],74);self.assertEqual(row['retryCode'],74)

    def test_readonly_status_does_not_create_destination(self):
        row=self.case('status-before-placement');self.assertEqual(row['code'],0,row)
        self.assertIn('has not been placed',row['stdout']);self.assertFalse(row['baseExists'])
        self.assertEqual(row['statusCode'],0);self.assertEqual(row['retryCode'],0)

    def test_completed_package_tamper_refuses_and_is_preserved(self):
        row=self.case('completed-tamper');self.assertEqual(row['code'],0,row)
        self.assertTrue(row['complete']);self.assertTrue(row['intent']);self.assertEqual(len(row['files']),11)
        self.assertEqual(row['statusCode'],74);self.assertEqual(row['retryCode'],74)
        self.assertIn('bootstrap_file_profile',row['statusOutput'])


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
