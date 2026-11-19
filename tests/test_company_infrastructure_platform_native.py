"""Protected host-identity reader in private mount namespaces, no host edits."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value

def fixture(mode,case):
    case=Path(case);assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
    assert case.resolve()==case and os.geteuid()==os.getegid()==0
    assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    etc=case/'etc';etc.mkdir(mode=0o700);vendor=case/'vendor-release'
    raw=b'NAME="Synthetic fixture only"\nID=rocky\nVERSION_ID="10.2"\n'
    vendor.write_bytes(raw);vendor.chmod(0o644)
    if mode=='override':(etc/'os-release').write_bytes(raw.replace(b'10.2',b'10.1'))
    else:(etc/'os-release').symlink_to('/tmp/not-vendor' if mode=='wrong-link' else '../usr/lib/os-release')
    subprocess.run(['/usr/bin/mount','--bind',str(etc),'/etc'],check=True,timeout=10)
    subprocess.run(['/usr/bin/mount','--bind',str(vendor),'/usr/lib/os-release'],check=True,timeout=10)
    W=load('native_platform_worker','deploy/installer/company_infrastructure_worker.py')
    Q=load('native_platform_configuration','deploy/installer/company_configuration.py')
    S=load('native_platform_station','deploy/installer/company_native_station.py')
    before=set(os.listdir('/proc/self/fd'));refused=False;value=None
    try:
        with W.held_platform(Q,S) as (value,check):
            if mode=='drift':vendor.write_bytes(raw.replace(b'10.2',b'10.1'))
            check()
    except ValueError:refused=True
    after=set(os.listdir('/proc/self/fd'))
    assert before==after
    (case/'report.json').write_text(json.dumps(dict(mode=mode,refused=refused,value=value,descriptorsUnchanged=True))+'\n')

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root namespace fixture required')
class PlatformNative(unittest.TestCase):
    def run_case(self,mode):
        base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']);case=base/uuid.uuid4().hex;case.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],
            capture_output=True,stdin=subprocess.DEVNULL,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr.decode());return json.loads((case/'report.json').read_text())

    def test_exact_vendor_link_is_held_and_read_inertly(self):
        r=self.run_case('success');self.assertFalse(r['refused']);self.assertEqual(r['value'],dict(osId='rocky',versionId='10.2',architecture='x86_64'))

    def test_arbitrary_vendor_link_is_refused_without_fd_leak(self):self.assertTrue(self.run_case('wrong-link')['refused'])
    def test_disagreeing_host_override_is_refused_without_fd_leak(self):self.assertTrue(self.run_case('override')['refused'])
    def test_changed_vendor_bytes_are_refused_without_fd_leak(self):self.assertTrue(self.run_case('drift')['refused'])

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
