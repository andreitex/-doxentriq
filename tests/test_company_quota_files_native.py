"""Real exclusive unit files; only fixture paths are writable, never host units."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value
U=load('quota_units_native','deploy/installer/company_quota_units.py')
B=load('quota_units_bootstrap','scripts/bootstrap.py')

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class Units(unittest.TestCase):
    def setUp(self):
        self.base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])/uuid.uuid4().hex;self.base.mkdir(mode=0o700)
        self.directory=self.base/'system';self.directory.mkdir(mode=0o755)
        self.dropdir=self.directory/'docker.service.d';self.dropdir.mkdir(mode=0o755)
        self.unit=str(self.directory/'autosoft-quota.service');self.dropin=str(self.dropdir/'autosoft-quota.conf')
        self.build=str(self.dropdir/'autosoft-builds.conf');self.raw=b'[Unit]\nRequires=srv-data-runtime-builds.mount\nAfter=srv-data-runtime-builds.mount\n'
        Path(self.build).write_bytes(self.raw);Path(self.build).chmod(0o644)
        self.patches=patch.multiple(U,UNIT=self.unit,DROPIN=self.dropin,BUILDS=self.build);self.patches.start();self.addCleanup(self.patches.stop)
        self.expected=U.plan(B,'/srv/data','/srv/data/company/host-releases/install-'+'a'*32,self.raw)
        self.fds=set(os.listdir('/proc/self/fd'))
    def tearDown(self):self.assertEqual(set(os.listdir('/proc/self/fd')),self.fds)
    def opened(self,**kwargs):return U.QuotaUnits(self.expected,authority=lambda:None,builds_raw=self.raw,**kwargs)
    def test_exclusive_write_then_independent_reopen_has_exact_bytes(self):
        with self.opened() as units:units.install();first=units.observation()
        with self.opened(installed=True) as units:self.assertEqual(units.observation(),first)
        for path,raw in self.expected.items():self.assertEqual(Path(path).read_bytes(),raw)
    def test_existing_partial_unit_is_never_adopted_or_overwritten(self):
        Path(self.unit).write_bytes(b'partial');Path(self.unit).chmod(0o644)
        with self.assertRaises(ValueError):self.opened()
        self.assertEqual(Path(self.unit).read_bytes(),b'partial');self.assertFalse(Path(self.dropin).exists())
    def test_symlink_and_hardlink_cannot_become_verified_units(self):
        with self.opened() as units:units.install()
        Path(self.unit).unlink();Path(self.unit).symlink_to(self.build)
        with self.assertRaises((ValueError,OSError)):self.opened(installed=True)
        Path(self.unit).unlink();Path(self.unit).write_bytes(self.expected[self.unit]);Path(self.unit).chmod(0o644)
        os.link(self.unit,self.base/'extra-link')
        with self.assertRaises(ValueError):self.opened(installed=True)
    def test_build_dependency_drift_is_detected(self):
        with self.assertRaises(ValueError):
            with self.opened() as units:
                Path(self.build).write_bytes(self.raw+b'# changed\n');units.install()
        self.assertFalse(Path(self.unit).exists())
    def test_other_system_unit_addition_is_not_concealed(self):
        with self.assertRaises(ValueError):
            with self.opened() as units:
                (self.directory/'unexpected.service').write_bytes(b'other');units.install()
        self.assertFalse(Path(self.unit).exists())
    def test_close_or_authority_failure_cannot_report_ready(self):
        calls=[]
        def authority():
            calls.append(1)
            if Path(self.unit).exists():raise ValueError('synthetic revoked authority')
        with self.assertRaises(ValueError):
            with U.QuotaUnits(self.expected,authority=authority,builds_raw=self.raw) as units:units.install()
        self.assertTrue(Path(self.unit).exists());self.assertFalse(Path(self.dropin).exists())

if __name__=='__main__':unittest.main(verbosity=2)
