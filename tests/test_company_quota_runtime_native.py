"""Actual locks/process/socket fixtures; no real service, signing or encryption."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value

def locks(case,mode):
    F=load('quota_pair_fixture','tests/test_company_runtime_pair_native.py');F.pair_fixture(case)
    R=F.R;W=load('quota_window','deploy/installer/company_quota_worker.py')
    Q=load('quota_configuration','deploy/installer/company_configuration.py')
    data=case/'data';host=case/'host';install=case/'company-source';builds=data/'runtime/builds'
    def findmnt(args):return subprocess.check_output(args,text=True,timeout=5)
    def layout(data,files):return R.S.L.verify(data,files=files,build_mount=lambda path:R.S.L.builds_proof(path,command=findmnt))
    def mount(data,receipt,command):return dict(source='synthetic-not-encrypted-storage',fixtureOnly=True)
    inputs=dict(host_directory=host,files=R.NativeFiles(),command=lambda *args:None,mount=mount,layout=layout,
        gate_factory=R.C.Gate,allocation_factory=R.A.Allocation,read_state=R.Q.load_state)
    assembly=SimpleNamespace(call=lambda name,method,*args,**kw:getattr(R.S,method)(*args,**kw))
    program=r'''
import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('quota_real_helper',Path(sys.argv[1])/'scripts/quota-helper.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
q.mount_proof=lambda data:None
q.verify_startup(Path(sys.argv[2]),'64a2a5f8-04b9-43b5-9807-122d866db1f1')
'''
    try:
        with W.storage_window(Q,assembly,R.S,inputs,str(data),str(install)):
            # The actual helper function takes the initialized journals in a
            # separate process. Holding the old outer inspection locks fails.
            done=subprocess.run(['/usr/bin/python3','-I','-B','-c',program,str(ROOT),str(data)],capture_output=True,timeout=25)
            assert done.returncode==0,done.stderr.decode()
            if mode=='journal-drift':(data/'quota/projects.json').write_bytes(b'changed')
    except ValueError:
        assert mode=='journal-drift'
    else:assert mode=='locks'

def process(case,mode):
    run=case/'run';run.mkdir(mode=0o700)
    subprocess.run(['/usr/bin/mount','--bind',str(run),'/run'],check=True,timeout=10)
    root=case/'runtime-source';root.mkdir(mode=0o700);(root/'scripts').mkdir(mode=0o700)
    source=b'''import os,socket,time
from pathlib import Path
p=Path('/run/autosoft');p.mkdir(mode=0o750);os.chmod(p,0o750);os.chown(p,0,10001)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(str(p/'quota.sock'));os.chmod(p/'quota.sock',0o660);os.chown(p/'quota.sock',0,10001);s.listen(2)
while True:
 c,_=s.accept();c.close()
'''
    file=root/'scripts/quota-helper.py';file.write_bytes(source);file.chmod(0o444)
    S=load('quota_native_station','deploy/installer/company_native_station.py')
    H=load('quota_native_host','deploy/installer/company_infrastructure_host.py')
    K=load('quota_native_service','deploy/installer/company_quota_service.py')
    child=subprocess.Popen(['/usr/bin/python3','-I','-B',str(file)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+5
        while not Path('/run/autosoft/quota.sock').exists():
            assert child.poll() is None and time.monotonic()<deadline;time.sleep(.02)
        # File existence can precede the fixture's chmod/listen by a few ticks.
        time.sleep(.05)
        state={name:'' for name in K.FIELDS};state.update(ActiveState='active',SubState='running',LoadState='loaded',MainPID=str(child.pid),
            ControlPID='0',ControlGroup='/system.slice/autosoft-quota.service',NeedDaemonReload='no',
            FragmentPath='/etc/systemd/system/autosoft-quota.service',Type='notify',NotifyAccess='main')
        before=set(os.listdir('/proc/self/fd'))
        try:
            with K.QuotaProcess(S,H,SimpleNamespace(state=lambda:state),root=str(root),source_files={'scripts/quota-helper.py':source},check_authority=lambda:None) as held:
                assert held.observation()['pid']==child.pid
                if mode=='dead-process':child.terminate();child.wait(timeout=3);held.check()
        except ValueError:assert mode=='dead-process'
        else:assert mode=='process'
        assert set(os.listdir('/proc/self/fd'))==before
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=3)
        child.stderr.close()

def fixture(case,mode):
    case=Path(case);assert case.parent==Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
    assert os.geteuid()==0 and os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
    if mode in ('locks','journal-drift'):locks(case,mode)
    else:process(case,mode)

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class Runtime(unittest.TestCase):
    def run_case(self,mode):
        case=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])/uuid.uuid4().hex;case.mkdir(mode=0o700)
        done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',str(case),mode],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
        self.assertEqual(done.returncode,0,done.stderr.decode())
    def test_real_helper_acquires_journals_during_startup_window(self):self.run_case('locks')
    def test_journal_change_during_unlocked_window_is_refused(self):self.run_case('journal-drift')
    def test_observer_binds_actual_ready_unix_peer_and_python_process(self):self.run_case('process')
    def test_exited_service_cannot_remain_ready(self):self.run_case('dead-process')

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':fixture(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
