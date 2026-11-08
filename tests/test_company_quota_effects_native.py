"""Original bounded supervisor with harmless children and actual changed inputs.

The held systemctl executable is real; Popen substitutes a fixed Python fixture
before any systemd call. No host unit or service is installed or started.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class Effects(unittest.TestCase):
    def scenario(self,kind):
        S=load('quota_effect_station','deploy/installer/company_native_station.py')
        H=load('quota_effect_host','deploy/installer/company_infrastructure_host.py')
        K=load('quota_effect_service','deploy/installer/company_quota_service.py')
        T=load('quota_effect_fixture','tests/test_company_identity_closed_native.py')
        fixture=T.ClosedIdentity();fixture.setUp()
        base=fixture.data/'unit-fixture';base.mkdir(mode=0o700)
        unit=base/'autosoft-quota.service';unit.write_bytes(b'fixed synthetic unit');unit.chmod(0o644)
        target=unit if kind=='unit' else fixture.path/'004-verify-completed.json'
        original=subprocess.Popen;children=[];checks=[]
        def launch(argv,**kwargs):
            kwargs.pop('executable')
            if argv==['/usr/bin/systemctl','daemon-reload']:code='pass'
            else:
                self.assertEqual(argv,['/usr/bin/systemctl','start','--','autosoft-quota.service'])
                code='import pathlib,time;time.sleep(.05);pathlib.Path('+repr(str(target))+').write_bytes(b"changed");time.sleep(30)'
            child=original(['/usr/bin/python3','-I','-B','-c',code],**kwargs);children.append(child);return child
        baseline=set(os.listdir('/proc/self/fd'));started=time.monotonic()
        with self.assertRaises(ValueError):
            with fixture.read() as identity,S.held_file(unit,4096) as (_,_,check_unit):
                def check_effect():checks.append(1);identity.check();check_unit()
                source_check=lambda:None
                with K.systemctl_class(H)(S,source_check) as ctl,patch.object(H.subprocess,'Popen',side_effect=launch):
                    ctl.reload(check_effect=check_effect)
                    with self.assertRaises(ValueError):ctl.start(check_effect=check_effect)
                    self.assertIs(ctl.authority,source_check);self.assertTrue(ctl.failed)
                    with self.assertRaises(ValueError):ctl.start(check_effect=check_effect)
        self.assertLess(time.monotonic()-started,5);self.assertGreater(len(checks),2)
        self.assertEqual(len(children),2);self.assertTrue(all(p.returncode is not None for p in children))
        self.assertFalse(H.UNKNOWN);self.assertEqual(set(os.listdir('/proc/self/fd')),baseline)
    def test_changed_unit_aborts_actual_supervised_start_without_retry(self):
        # Exact readers must also fail their close check after the deliberate
        # mutation; that is part of refusing successful stage completion.
        self.scenario('unit')
    def test_changed_identity_aborts_actual_supervised_start_without_retry(self):
        self.scenario('identity')
    def test_malformed_readonly_result_cannot_reuse_supervisor(self):
        S=load('quota_parse_station','deploy/installer/company_native_station.py')
        H=load('quota_parse_host','deploy/installer/company_infrastructure_host.py');original=subprocess.Popen;calls=[]
        def launch(argv,**kwargs):
            kwargs.pop('executable');calls.append(argv)
            return original(['/usr/bin/python3','-I','-B','-c','print("unexpected")'],**kwargs)
        with H.Systemctl(S,lambda:None) as ctl,patch.object(H.subprocess,'Popen',side_effect=launch):
            for _ in range(2):
                with self.assertRaises(ValueError):ctl.query('docker.service')
            self.assertTrue(ctl.failed)
        self.assertEqual(len(calls),1)

if __name__=='__main__':unittest.main(verbosity=2)
