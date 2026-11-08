"""Actual bounded child/pipe supervision with explicit synthetic executables.

The production adapter still holds the real root-owned systemctl file. Tests
replace only Popen with a fixed harmless Python child; no systemd/Docker call.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import ctypes
import threading
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value);return value
H=load('host_process_test','deploy/installer/company_infrastructure_host.py')
S=load('host_process_station','deploy/installer/company_native_station.py')

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root held-tool fixture required')
class ProcessNative(unittest.TestCase):
    def setUp(self):
        global H
        # Each fixture gets a fresh module; retained unknown-resource ledgers
        # are never cleared or reused by the production adapter.
        H=load('host_process_case_'+uuid.uuid4().hex,'deploy/installer/company_infrastructure_host.py')
    def scenario(self,code):
        original=subprocess.Popen;children=[]
        def launch(argv,**kwargs):
            self.assertEqual(argv[:2],['/usr/bin/systemctl','show']);self.assertEqual(argv[-2:],['--','docker.service'])
            kwargs.pop('executable');child=original(['/usr/bin/python3','-I','-B','-c',code],**kwargs)
            children.append(child);return child
        return launch,children

    def test_successful_child_output_is_bounded_parsed_and_closed(self):
        raw=''.join(name+'=synthetic\n' for name in H.UNITS['docker.service'])
        launch,children=self.scenario('import sys;sys.stdout.write('+repr(raw)+')')
        before=len(os.listdir('/proc/self/fd'))
        with H.Systemctl(S,lambda:None) as query,patch.object(H.subprocess,'Popen',side_effect=launch):
            result=query.query('docker.service');self.assertEqual(set(result),set(H.UNITS['docker.service']))
        self.assertEqual(len(children),1);self.assertEqual(children[0].returncode,0)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_slow_child_is_killed_within_deadline_and_never_retried(self):
        launch,children=self.scenario('import time;time.sleep(30)');before=len(os.listdir('/proc/self/fd'));start=time.monotonic()
        with H.Systemctl(S,lambda:None) as query,patch.object(H.subprocess,'Popen',side_effect=launch),self.assertRaises(ValueError):
            query.query('docker.service')
        self.assertLess(time.monotonic()-start,12);self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].returncode);self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_excessive_output_refuses_and_reaps_owned_child(self):
        launch,children=self.scenario('import sys;sys.stdout.write("x"*70000);sys.stdout.flush()');before=len(os.listdir('/proc/self/fd'))
        with H.Systemctl(S,lambda:None) as query,patch.object(H.subprocess,'Popen',side_effect=launch),self.assertRaises(ValueError):
            query.query('docker.service')
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_unknown_group_release_is_retained_and_cannot_return_success(self):
        raw=''.join(name+'=synthetic\n' for name in H.UNITS['docker.service'])
        launch,children=self.scenario('import sys;sys.stdout.write('+repr(raw)+')')
        original=H.os.killpg;before=len(os.listdir('/proc/self/fd'))
        def lingering(group,sig):
            if sig==0:return None  # Explicit synthetic unknown group observation.
            return original(group,sig)
        with H.Systemctl(S,lambda:None) as query,patch.object(H.subprocess,'Popen',side_effect=launch),patch.object(H.os,'killpg',side_effect=lingering):
            with self.assertRaisesRegex(ValueError,'resource release is unknown'):query.query('docker.service')
            self.assertTrue(H.UNKNOWN)
            with self.assertRaises(ValueError):query.query('docker.service')
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_close_failure_is_retained_even_when_child_exited_successfully(self):
        raw=''.join(name+'=synthetic\n' for name in H.UNITS['docker.service'])
        launch,children=self.scenario('import sys;sys.stdout.write('+repr(raw)+')')
        original=H.selectors.DefaultSelector;before=len(os.listdir('/proc/self/fd'))
        def selector():
            value=original();close=value.close
            def fail():close();raise OSError('synthetic reported close failure after actual FD release')
            value.close=fail;return value
        with H.Systemctl(S,lambda:None) as query,patch.object(H.subprocess,'Popen',side_effect=launch),patch.object(H.selectors,'DefaultSelector',side_effect=selector),self.assertRaisesRegex(ValueError,'resource release is unknown'):
            query.query('docker.service')
        self.assertTrue(H.UNKNOWN);self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_pipe_holding_descendant_is_terminated_and_reaped(self):
        base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])/uuid.uuid4().hex;base.mkdir(mode=0o700);pidfile=base/'child.pid'
        code='import os,time,pathlib\npid=os.fork()\nif pid==0:\n time.sleep(30);os._exit(0)\npathlib.Path('+repr(str(pidfile))+').write_text(str(pid))\nos._exit(0)\n'
        launch,children=self.scenario(code);libc=ctypes.CDLL(None,use_errno=True);old=ctypes.c_int()
        self.assertEqual(libc.prctl(37,ctypes.byref(old),0,0,0),0)
        self.assertEqual(libc.prctl(36,1,0,0,0),0)
        reaped=[];failures=[]
        def reap():
            try:
                end=time.monotonic()+16
                while not pidfile.exists() and time.monotonic()<end:time.sleep(0.01)
                pid=int(pidfile.read_text())
                while time.monotonic()<end:
                    try:
                        found,status=os.waitpid(pid,os.WNOHANG)
                        if found:reaped.append((found,status));return
                    except ChildProcessError:pass
                    time.sleep(0.01)
                failures.append('synthetic descendant not reaped within fixture bound')
            except BaseException as error:failures.append(type(error).__name__)
        thread=threading.Thread(target=reap,daemon=True);thread.start();before=len(os.listdir('/proc/self/fd'))
        try:
            with H.Systemctl(S,lambda:None) as query,patch.object(H.subprocess,'Popen',side_effect=launch),self.assertRaises(ValueError):query.query('docker.service')
            thread.join(timeout=18);self.assertFalse(thread.is_alive());self.assertEqual(failures,[])
            self.assertEqual(len(reaped),1);self.assertFalse(H.UNKNOWN)
            self.assertEqual(len(children),1);self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        finally:self.assertEqual(libc.prctl(36,old.value,0,0,0),0)

if __name__=='__main__':unittest.main(verbosity=2)
