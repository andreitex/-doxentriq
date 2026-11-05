#!/usr/bin/env python3
"""Non-destructive recovery fault checks on an unaccepted encrypted foundation."""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile


def output(args):
    return subprocess.check_output(args,text=True).strip()


if __name__ == '__main__':
    if os.geteuid()!=0 or Path('/etc/autosoft/installation.complete').exists():
        raise SystemExit('Use root on an unaccepted company test foundation')
    metadata=json.loads(Path('/etc/autosoft/installation.json').read_text())
    data, storage, root=map(Path,(metadata['data_dir'],metadata['storage_file'],metadata['install_root']))
    uuid_before=output(['cryptsetup','luksUUID',str(storage)])
    expected=Path('/dev/mapper/autosoft-data').resolve()
    assert Path(output(['findmnt','-n','-o','SOURCE','--target',str(data)])).resolve()==expected
    with tempfile.TemporaryDirectory(prefix='recovery-',dir=data/'validation') as temporary:
        folder=Path(temporary)
        wrong_key=folder/'wrong-test-key'
        wrong_key.write_bytes(secrets.token_bytes(64))
        os.chmod(wrong_key,0o600)
        denied=subprocess.run(['cryptsetup','open','--test-passphrase','--key-file',str(wrong_key),str(storage)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        assert denied.returncode!=0,'Wrong key unexpectedly accepted'
        wrong_key.unlink()
        empty=folder/'empty-mount'
        empty.mkdir()
        guard=subprocess.run(['unshare','--mount','--propagation','private','/bin/bash','-c','mount --bind "$1" "$2"; exec /bin/bash "$3/scripts/storage-guard.sh"','isolated-mount-test',str(empty),str(data),str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert guard.returncode!=0 and 'Data directory is not the expected encrypted mapping' in guard.stderr,guard.stderr
        assert Path(output(['findmnt','-n','-o','SOURCE','--target',str(data)])).resolve()==expected
        assert output(['cryptsetup','luksUUID',str(storage)])==uuid_before
        # Resume an unborn shared repository in a new isolated fixture, then
        # confirm a later company-source change cannot replace committed work.
        fixture, source=folder/'seed-data',folder/'company-source'
        source.mkdir()
        (source/'package.json').write_text('{"name":"reviewed-seed-fixture","private":true}\n')
        provenance=fixture/'config/company-release'
        provenance.mkdir(parents=True)
        (provenance/'release.json').write_text('{"schemaVersion":1,"version":"synthetic-test-only"}\n')
        repository=fixture/'runtime/repository'
        repository.mkdir(parents=True)
        subprocess.run(['git','init',str(repository)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        spec=importlib.util.spec_from_file_location('reviewed_bootstrap',root/'scripts/bootstrap.py')
        bootstrap=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        bootstrap.seed_repository(fixture,source)
        git=['git','-c','safe.directory='+str(repository),'-C',str(repository)]
        head=output(git+['rev-parse','HEAD'])
        assert output(git+['show','HEAD:platform/package.json']).startswith('{"name":"reviewed-seed-fixture"')
        assert 'synthetic-test-only' in output(git+['show','HEAD:company-release/release.json'])
        assert all(path.stat().st_uid==10001 for path in [repository/'.git']+list((repository/'.git').rglob('*')) if not path.is_symlink())
        (source/'package.json').write_text('{"name":"changed-company-source"}\n')
        bootstrap.seed_repository(fixture,source)
        assert output(git+['rev-parse','HEAD'])==head
        assert 'reviewed-seed-fixture' in (repository/'platform/package.json').read_text()
    report=dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='passed',scope='Non-destructive isolated recovery fault checks',checks=['Wrong LUKS passphrase rejected using --test-passphrase; active mapping and UUID preserved','Startup guard rejects an unexpected data mount in a private mount namespace; host mount unchanged','Interrupted unborn shared repository resumes with committed company source and provenance','Committed repository and worker ownership remain preserved on rerun'],limitations=['Wrong-key rejection was tested without changing the real boot key or unmounting the host; a failed-unlock reboot was not injected','The boot-metadata interruption transaction still requires a dedicated disposable installer fixture'],modelApiCalls=0)
    (data/'validation/storage-recovery-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
