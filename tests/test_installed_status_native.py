"""Actual installed shell dispatch in a private mount namespace, no services.

The schema4 source capability is genuine with explicitly synthetic signing and
filesystem metadata. The projected script bytes and Bash/Python execution are
real. Only a fixture /etc is mounted in a child namespace; parent mounts stay put.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]


def status_child(case):
    before=os.readlink('/proc/self/ns/mnt')
    assert before!=(case/'parent-mount-namespace').read_text()
    subprocess.run(['/usr/bin/mount','--bind',str(case/'etc'),'/etc'],check=True,timeout=10)
    # PATH supplies only the existing external commands used by early dispatch.
    # Docker, systemctl, mount and ordinary maintenance actions cannot resolve.
    done=subprocess.run(['/bin/bash',str(case/'installed/autosoft'),'installation-status','--json'],
        stdin=subprocess.DEVNULL,capture_output=True,timeout=15,
        env=dict(PATH=str(case/'bin'),HOME=str(case),LANG='C',LC_ALL='C',TZ='UTC'))
    assert not done.stderr,done.stderr.decode()
    result=json.loads(done.stdout)
    assert result['mayResume'] is False and result['installationVerified'] is False
    print(json.dumps(dict(exitCode=done.returncode,report=result)))


if len(sys.argv)==3 and sys.argv[1]=='--status-child':
    status_child(Path(sys.argv[2]));raise SystemExit(0)

spec=importlib.util.spec_from_file_location('installed_status_projection_fixture',ROOT/'tests/test_platform_foundation_materialize.py')
T=importlib.util.module_from_spec(spec);sys.modules[spec.name]=T;spec.loader.exec_module(T)


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,
                     'actual Linux root and private mount namespace required')
class InstalledStatus(unittest.TestCase):
    def scenario(self,conflict):
        fixture=T.PlatformFoundationControls('test_genuine_schema4_projection_keeps_exact_64_bytes_and_no_archive')
        fixture.setUp();self.addCleanup(fixture.tearDown)
        for name in ('scripts/autosoft.sh','scripts/lib.sh','scripts/installation-status.py'):
            fixture.q.values[name]=(ROOT/name).read_bytes()
        fixture.q.refresh_platform()
        case=fixture.parent/('status-'+uuid.uuid4().hex);case.mkdir(mode=0o700)
        (case/'installed').mkdir(mode=0o700);(case/'bin').mkdir(mode=0o700)
        for name in ('python3','dirname'):(case/'bin'/name).symlink_to('/usr/bin/'+name)
        (case/'installed/autosoft').write_bytes(fixture.q.values['scripts/autosoft.sh'])
        host=case/'etc/autosoft';host.mkdir(mode=0o700,parents=True)
        projected=fixture.parent/fixture.name
        (host/'installation.json').write_text(json.dumps(dict(install_root=str(projected))))
        (host/'storage.key').write_text('SECRET-MUST-NOT-APPEAR')
        session='s-ABCDEF123456';base=case/'etc/autosoft-install-admission';base.mkdir(mode=0o700)
        (base/'install.lock').touch();(base/'binding').write_text('presence-only diagnostic')
        records=base/'sessions'/session;records.mkdir(mode=0o700,parents=True)
        request='a'*64;action='b'*64;other='c'*64;stage='company-private-quota'
        (records/'intent').write_text(f'install-session-v1\nsession={session}\nrequest={request}\nbinding=1:2\ndirectory=3:4\nclosed=true\n')
        (records/(stage+'.intent')).write_text(f'install-stage-v1\nsession={session}\nstage={stage}\naction={action}\nclosed=true\n')
        if conflict:
            (records/(stage+'.confirmed')).write_text(f'install-stage-confirmed-v1\nsession={session}\nstage={stage}\naction={other}\noutcome={other}\nindependently_confirmed=true\n')
        (case/'parent-mount-namespace').write_text(os.readlink('/proc/self/ns/mnt'))
        before=Path('/proc/self/mountinfo').read_bytes()
        originals={path:path.read_bytes() for path in (case/'etc').rglob('*') if path.is_file()}
        with fixture.q.held() as held,fixture.context(held) as tree:
            self.assertEqual(tree.root,projected)
            self.assertEqual((tree.root/'scripts/installation-status.py').read_bytes(),fixture.q.values['scripts/installation-status.py'])
            done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',
                str(Path(__file__).resolve()),'--status-child',str(case)],stdin=subprocess.DEVNULL,
                capture_output=True,timeout=30,env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/root',LANG='C',LC_ALL='C',TZ='UTC'))
            self.assertEqual(done.returncode,0,done.stderr.decode())
            result=json.loads(done.stdout)
            self.assertEqual(result['exitCode'],2 if conflict else 0)
            self.assertEqual(result['report']['state'],'inspection_unavailable' if conflict else 'incomplete')
            if not conflict:self.assertEqual(result['report']['sessions'][0]['stages'],[dict(stage=stage,observation='intent_without_confirmation')])
            self.assertNotIn('SECRET-MUST-NOT-APPEAR',done.stdout.decode())
            tree.recheck()
        self.assertEqual(Path('/proc/self/mountinfo').read_bytes(),before)
        self.assertEqual({path:path.read_bytes() for path in originals},originals)
        self.assertFalse(fixture.files.opened)

    def test_copied_maintenance_entry_finds_projected_status_and_reports_pending_quota(self):self.scenario(False)
    def test_copied_maintenance_entry_refuses_conflicting_confirmation_without_writes(self):self.scenario(True)


if __name__=='__main__':unittest.main(verbosity=2)
