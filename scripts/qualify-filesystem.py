#!/usr/bin/env python3
"""Actual isolated TLS/read-only/openat2/runsc qualification on synthetic files.

This proves connector protocol containment only. Image security qualification is
an independent mandatory company release gate, never granted by this rehearsal.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile


def command(*args):
    return subprocess.check_output(list(args), text=True, stderr=subprocess.PIPE).strip()


def docker(*args):
    return command('docker', *args)


def secret_file(path, value):
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    os.chmod(path, 0o400)
    os.chown(path, 10001, 10001)


def main():
    if os.name != 'posix' or os.geteuid() != 0:
        raise SystemExit('A root-owned isolated Linux company build machine is required')
    image, report = sys.argv[1], Path(sys.argv[2]).resolve()
    source = Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else Path(__file__).resolve().parents[1] / 'deploy/connectors/filesystem.py'
    if report.exists() or not re.fullmatch(r'[A-Za-z0-9._:/-]+(?::[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})', image) or image.endswith(':latest'):
        raise SystemExit('A new report and explicit company image reference are required')
    foundation = Path(json.loads(Path('/etc/autosoft/installation.json').read_text())['data_dir']).resolve()
    if not report.parent.is_relative_to(foundation) or Path(command('findmnt', '-n', '-o', 'SOURCE', '--target', str(foundation))).resolve() != Path('/dev/mapper/autosoft-data').resolve():
        raise SystemExit('Qualification evidence must remain on the expected encrypted data mapping')
    scope = 'filesystem-check-' + secrets.token_hex(6)
    network, container = scope + '-internal', scope + '-adapter'
    network_id, container_id = None, None
    result = None
    with tempfile.TemporaryDirectory(prefix=scope + '-', dir=report.parent) as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        source_root, cross_root, secret_root = directory/'source', directory/'cross', directory/'scope'
        for path in (source_root, cross_root, secret_root): path.mkdir(mode=0o755)
        (source_root/'good').mkdir()
        (source_root/'denied').mkdir()
        (source_root/'cross').mkdir()
        (source_root/'good/report.txt').write_bytes(b'Synthetic filesystem document\n')
        (source_root/'good/folder').mkdir()
        (source_root/'good/folder/nested.txt').write_bytes(b'Nested synthetic document\n')
        (cross_root/'outside.txt').write_bytes(b'Cross mount must never be exposed\n')
        (source_root/'denied/ordinary').write_bytes(b'Synthetic hardlink must be denied')
        os.link(source_root/'denied/ordinary', source_root/'denied/hardlink')
        os.symlink('/etc/passwd', source_root/'denied/symlink')
        os.mkfifo(source_root/'denied/pipe')
        with (source_root/'denied/large').open('wb') as stream: stream.truncate(4*1024*1024+1)
        for path in source_root.rglob('*'):
            if path.is_dir(): path.chmod(0o755)
            elif path.is_file() and not path.is_symlink(): path.chmod(0o644)
        (cross_root/'outside.txt').chmod(0o644)
        alias='filesystem-fixture.internal'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','2','-subj','/CN=Filesystem Synthetic Qualification CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(directory/'ca.key'),'-out',str(directory/'ca.crt')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (directory/'ca.crt').chmod(0o444)
        (secret_root/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+alias+'\n')
        subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+alias,'-keyout',str(secret_root/'app.key'),'-out',str(secret_root/'leaf.csr')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['openssl','x509','-req','-in',str(secret_root/'leaf.csr'),'-CA',str(directory/'ca.crt'),'-CAkey',str(directory/'ca.key'),'-CAcreateserial','-days','1','-sha256','-extfile',str(secret_root/'extensions'),'-out',str(secret_root/'app.crt')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        token = secrets.token_urlsafe(32)
        configuration = dict(schemaVersion=1,appId='fixture-app',connectionId='fixture-files',sourceRootId='fixture-import',root='documents',expiresAt=(datetime.now(timezone.utc)+timedelta(seconds=20)).isoformat(),sourceEvidenceHash=hashlib.sha256(b'Synthetic company-owned imported directory').hexdigest(),templateSourceHash=hashlib.sha256(source.read_bytes()).hexdigest(),capabilities=['files.list','files.read'])
        secret_file(secret_root/'config.json',configuration)
        secret_file(secret_root/'token',token)
        for path in (secret_root/'app.key',secret_root/'app.crt'): os.chmod(path,0o400);os.chown(path,10001,10001)
        try:
            network_id = docker('network','create','--internal','--label','io.autosoft.fixture=filesystem-qualification',network)
            container_id = docker('run','-d','--name',container,'--label','io.autosoft.fixture=filesystem-qualification','--runtime=runsc','--network',network,'--read-only','--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--pids-limit=64','--tmpfs','/tmp:size=16m,mode=1777','--volume',str(source_root)+':/run/source:ro,z','--volume',str(cross_root)+':/run/source/cross:ro,z','--volume',str(secret_root)+':/run/connector:ro,z','--volume',str(directory/'ca.crt')+':/run/ca.crt:ro,z','--env','CONNECTOR_CONFIG_FILE=/run/connector/config.json','--env','CONNECTOR_TOKEN_FILE=/run/connector/token','--env','CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt','--env','CONNECTOR_TLS_KEY_FILE=/run/connector/app.key',image)
            probe=r'''import base64,datetime,errno,hashlib,http.client,json,os,socket,ssl,time
ctx=ssl.create_default_context(cafile='/run/ca.crt')
token=open('/run/connector/token').read().strip()
config=json.load(open('/run/connector/config.json'))
def request(operation,path='',app='fixture-app',root='documents',authorization=token,connection='fixture-files'):
 c=http.client.HTTPSConnection('filesystem-fixture.internal',8443,context=ctx,timeout=2)
 c.connect=lambda:setattr(c,'sock',ctx.wrap_socket(socket.create_connection(('127.0.0.1',8443),timeout=2),server_hostname='filesystem-fixture.internal'))
 c.request('POST','/v1/connections/'+connection+'/'+operation,json.dumps(dict(appId=app,root=root,path=path)),{'Content-Type':'application/json','Authorization':'Bearer '+authorization})
 response=c.getresponse();value=json.loads(response.read());c.close();return response.status,value
for attempt in range(20):
 try:
  status,value=request('list','good')
  if status==200:break
 except OSError:pass
 time.sleep(.2)
else:raise AssertionError('Actual read-only/openat2 runsc adapter never became ready')
assert any(item['name']=='report.txt' for item in value['entries'])
assert request('read','good/report.txt')[0]==200
assert base64.b64decode(request('read','good/folder/nested.txt')[1]['contentBase64'])==b'Nested synthetic document\n'
for path in ('denied/symlink','denied/ordinary','denied/hardlink','denied/pipe','denied/large','../etc/passwd','%2e%2e/etc/passwd','cross/outside.txt'):
 assert request('read',path)[0]==403,path
assert request('list','denied')[0]==403
for changes in (dict(app='other'),dict(root='other'),dict(authorization='x'*43),dict(connection='other')):
 assert request('read','good/report.txt',**changes)[0]==403
assert request('write','good/report.txt')[0]==403
try:open('/run/source/good/report.txt','wb')
except OSError as error:assert error.errno in (errno.EROFS,errno.EACCES)
else:raise AssertionError('Source mount is writable')
try:socket.create_connection(('1.1.1.1',443),timeout=1)
except OSError:pass
else:raise AssertionError('Connector has an external route')
expiry=datetime.datetime.fromisoformat(config['expiresAt'])
remaining=(expiry-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
if remaining>0:time.sleep(min(remaining+.2,21))
assert request('read','good/report.txt')[0]==403
print(json.dumps(dict(status='passed',sourceSha256=hashlib.sha256(open('/opt/connector/filesystem.py','rb').read()).hexdigest(),checks=['Actual TLS identity verification','Actual read-only Linux openat2 under UID10001/runsc','Bounded list/read and nested content','Symlink/hardlink/FIFO/oversized/traversal/cross-mount rejection','Cross-app/root/connection/token/write rejection','Actual read-only source write rejection','No external network route','Actual scope expiration rejection'])))
'''
            result=json.loads(docker('exec','--user=10001:10001',container_id,'python','-I','-c',probe))
            if result.get('sourceSha256')!=configuration['templateSourceHash']: raise ValueError('The image does not contain the exact company source')
            result.update(fixtureOnly=True,productionImageQualified=False,scope='synthetic-readonly-filesystem-runsc',checkedAt=datetime.now(timezone.utc).isoformat(),connectorImage=image,connectorImageID=docker('image','inspect','--format','{{.Id}}',image))
        finally:
            if container_id:
                actual=json.loads(docker('inspect',container_id))[0]
                if actual['Id']!=container_id or actual['Name']!='/'+container or actual['Config']['Labels'].get('io.autosoft.fixture')!='filesystem-qualification':raise ValueError('Fixture cleanup ownership mismatch')
                docker('rm','-f',container_id)
            if network_id:docker('network','rm',network_id)
    if result is None:raise ValueError('Qualification did not produce real execution evidence')
    report.write_text(json.dumps(result,indent=2)+'\n')
    os.chmod(report,0o600)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
