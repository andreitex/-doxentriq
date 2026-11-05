#!/usr/bin/env python3
"""Isolated Linux VM checks. This never starts or accepts the platform."""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def output(args):
    return subprocess.check_output([str(value) for value in args], text=True).strip()


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),Path(__file__).with_name(name+'.py'))
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


if __name__ == '__main__':
    if os.geteuid()!=0: raise SystemExit('Run foundation checks as root')
    metadata=json.loads(Path('/etc/autosoft/installation.json').read_text())
    data=Path(metadata['data_dir'])
    assert Path(output(['findmnt','-n','-o','SOURCE','--target',data])).resolve()==Path('/dev/mapper/autosoft-data').resolve()
    assert output(['getenforce'])=='Enforcing', 'This Rocky test requires SELinux Enforcing'
    assert len(Path('/proc/swaps').read_text().splitlines())==1
    assert output(['docker','info','--format','{{.DockerRootDir}}'])==str(data/'docker')
    assert output(['docker','info','--format','{{.LoggingDriver}}'])=='journald'
    assert output(['findmnt','-n','-o','FSTYPE','--target',data/'runtime/builds'])=='tmpfs'
    assert int(output(['findmnt','-n','-o','SIZE','--bytes','--target',data/'runtime/builds']))<=2147483648
    validation=data/'validation'
    validation.mkdir(mode=0o700,exist_ok=True)
    (data/'quota').mkdir(mode=0o700,exist_ok=True)
    (data/'runtime/storage').mkdir(mode=0o755,exist_ok=True)
    quotas=load('quota-helper')
    quotas.DATA=data
    request=dict(appId=str(uuid.uuid4()),name='foundation-test',sizeMb=16)
    resource=quotas.provision(request)
    node=json.loads((Path(metadata['install_root'])/'deploy/images.sources.json').read_text())['node']
    subprocess.run(['docker','pull',node],check=True,stdout=subprocess.DEVNULL)
    image=json.loads(output(['docker','image','inspect',node,'--format','{{json .RepoDigests}}']))[0]
    name='autosoft-foundation-'+uuid.uuid4().hex[:12]
    source="""const fs=require('node:fs'),net=require('node:net');
(async()=>{let written=0,quota=false,readonly=false;
if(process.getuid()!==10001||fs.existsSync('/var/run/docker.sock')||fs.existsSync('/run/secrets'))throw Error('Unexpected host capability');
try{fs.writeFileSync('/etc/autosoft-test','x')}catch(e){readonly=['EROFS','EACCES'].includes(e.code)}
const fd=fs.openSync('/storage/quota-probe','w');try{const chunk=Buffer.alloc(65536);while(written<33554432){written+=fs.writeSync(fd,chunk)}}catch(e){quota=e.code==='ENOSPC'||e.code==='EDQUOT'}finally{fs.closeSync(fd)}
if(!quota||written>16777216||!readonly)throw Error('Containment check failed');
const denied=await new Promise(resolve=>{const socket=net.connect({host:'1.1.1.1',port:443});socket.setTimeout(2000);socket.on('connect',()=>{socket.destroy();resolve(false)});socket.on('error',()=>resolve(true));socket.on('timeout',()=>{socket.destroy();resolve(false)})});
if(!denied)throw Error('Network must be unavailable');
process.stdout.write(JSON.stringify({uid:process.getuid(),readonlyRoot:readonly,networkDenied:denied,quotaEnforced:quota,writtenBytes:written})+'\\n')})().catch(e=>{console.error(e.message);process.exitCode=1})"""
    args=['docker','create','--name',name,'--runtime=runsc','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--pids-limit=64','--user=10001:10001','--tmpfs','/tmp:size=32m,mode=1777','--volume',resource['hostPath']+':/storage:z',image,'node','-e',source]
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
    try:
        inspect=json.loads(output(['docker','inspect',name]))[0]
        assert inspect['HostConfig']['ReadonlyRootfs'] and inspect['HostConfig']['Memory']==268435456 and inspect['HostConfig']['PidsLimit']==64
        assert inspect['HostConfig']['Runtime']=='runsc' and inspect['HostConfig']['NetworkMode']=='none'
        sandbox=json.loads(output(['docker','start','--attach',name]))
        assert int(output(['docker','inspect',name,'--format','{{.State.ExitCode}}']))==0
    finally:
        subprocess.run(['docker','rm','-f',name],check=True,stdout=subprocess.DEVNULL)
    # Only this test's exact file is removed. The quota allocation remains auditable.
    probe=Path(resource['hostPath'])/'quota-probe'
    assert probe.parent.resolve().is_relative_to((data/'runtime/storage').resolve())
    probe.unlink(missing_ok=True)
    pki=validation/('pki-'+uuid.uuid4().hex[:8])
    (pki/'tls').mkdir(parents=True)
    (pki/'public-tls').mkdir()
    bootstrap=load('bootstrap')
    bootstrap.certificates(pki,dict(certificate_mode='selfsigned',admin_origin='https://admin.autosoft.internal',apps_base_url='https://apps.autosoft.internal',auth_origin='https://auth.autosoft.internal'))
    certs=list((pki/'tls').glob('*/*.crt'))+[pki/'secrets/runtime/app-issuer.crt',pki/'public-tls/server.crt']
    for certificate in certs:
        subprocess.run(['openssl','verify','-CAfile',str(pki/'tls/ca.crt'),str(certificate)],check=True,stdout=subprocess.DEVNULL)
    for private in pki.rglob('*.key'):
        assert private.stat().st_mode & 0o077==0
    report=dict(schemaVersion=1,checkedAt=datetime.now(timezone.utc).isoformat(),host=output(['hostname']),os=output(['cat','/etc/os-release']),architecture=output(['uname','-m']),kernel=output(['uname','-r']),dockerVersion=output(['docker','version','--format','{{.Server.Version}}']),gvisor=output(['/usr/local/bin/runsc','--version']),nodeImage=image,checks=dict(encryptedStorage=True,encryptedJournals=True,buildTmpfsBounded=True,swapDisabled=True,selinuxEnforcing=True,resourceLimits=True,sandbox=sandbox,pkiLeafChains=len(certs),pkiPrivateKeys0600=True),acceptance=dict(platform='unavailable',reason='Foundation checks alone do not qualify complete platform installation',modelApiCalls=0))
    file=validation/'foundation-report.json'
    file.write_text(json.dumps(report,indent=2)+'\n')
    os.chmod(file,0o644)
    print(json.dumps(report,indent=2))
