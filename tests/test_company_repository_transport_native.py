"""Synthetic executable transport tests inside private Linux mount namespaces.

These exercise real process/pipe/timeout cleanup with a controlled executable
bound over /usr/bin/git only inside each child namespace. They do not qualify
the installed Git or a signed installer stage. No host services are touched.
"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


def child(case, root):
    import hashlib
    root = Path(root)
    assert str(root).startswith('/srv/') and root.resolve() == root
    assert (root.stat().st_uid, root.stat().st_gid, stat.S_IMODE(root.stat().st_mode)) == (0, 0, 0o700)
    script = root/'git-fixture'
    cases = {'old-version': "print('git version 2.45.0')",
        'output-limit': "print('x'*257)",
        'deadline': 'import time;time.sleep(30)',
        'compatible': "print('git version 2.45.1')"}
    script.write_bytes(('#!/usr/bin/python3\n'+cases[case]+'\n').encode())
    script.chmod(0o755)
    subprocess.run(['/usr/bin/mount', '--bind', str(script), '/usr/bin/git'], check=True)
    spec = importlib.util.spec_from_file_location('native_repository_transport', ROOT/'deploy/installer/company_repository_io.py')
    native = importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    data=root/'data';data.mkdir(mode=0o700);(data/'runtime').mkdir(mode=0o755)
    repo=data/'runtime/repository';repo.mkdir(mode=0o700);os.chown(repo,10001,10001)
    plan={'output':{'platform/file':b'fixed'},'directories':{'platform'},'modes':{'platform/file':'100644'},
          'leaves':{'platform/file':b'fixed'},'objects':{},'commit':'a'*40}
    backend=native.SeedBackend(data=str(data),install_root=str(data/'company/source'),storage_file=str(root/'backing.luks'),
        operation_id='1'*32,plan=plan,broker_directories=('repository',),writable=True)
    raw=script.read_bytes();pin={'path':'/usr/bin/git','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    runner=native.SeedRunner(host_runner=None,backend=backend,repository=str(repo),plan=plan,git_pin=pin,
        clock=(lambda: time.monotonic()*100) if case=='deadline' else time.monotonic)
    fd=backend.open('/usr/bin/git','file');before=set(os.listdir('/proc/self/fd'));started=time.monotonic()
    error=None
    try: result=runner.preflight(fd)
    except ValueError as raised:error=str(raised)
    if case=='compatible':assert error is None and result=='git version 2.45.1'
    else:assert error=={'old-version':'compatible-installed-git-required','output-limit':'repository-git-output-limit','deadline':'repository-git-deadline'}[case],error
    assert time.monotonic()-started<5
    runner.require_released();assert before==set(os.listdir('/proc/self/fd')) and not list(repo.iterdir())
    backend.finish();backend.require_released()
    print(json.dumps({'case':case,'status':'passed','syntheticExecutable':True,'hostEffects':False}))


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class NativeGitTransportTests(unittest.TestCase):
    def run_case(self,case):
        parent=Path(os.environ['DOXENTRIQ_REPOSITORY_TEST_ROOT']);assert parent.resolve()==parent and str(parent).startswith('/srv/')
        root=parent/uuid.uuid4().hex;root.mkdir(mode=0o700)
        result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',case,str(root)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)['status'],'passed')
    def test_version_2_45_0_refused(self):self.run_case('old-version')
    def test_success_closes_real_pipes_and_process(self):self.run_case('compatible')
    def test_oversize_output_kills_and_reaps(self):self.run_case('output-limit')
    def test_deadline_kills_and_reaps(self):self.run_case('deadline')


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':child(sys.argv[2],sys.argv[3])
    else:unittest.main(verbosity=2)
