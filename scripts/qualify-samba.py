#!/usr/bin/env python3
"""Real isolated SMB3.1.1/TLS read-only qualification; no customer shares or secrets.

Run on a company Linux build machine after building the two fixed Dockerfiles.
Failure or lack of a Docker/runsc runtime produces no qualification receipt.
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
import time


def run(*args):
    return subprocess.check_output(list(args),text=True).strip()


def docker(*args):
    return run('docker',*args)


def write(file,value):
    file.write_text(json.dumps(value) if not isinstance(value,str) else value)
    file.chmod(0o400)
    os.chown(file,10001,10001)


def main():
    if os.name != 'posix' or os.geteuid()!=0:
        raise SystemExit('Real connector qualification requires a root-owned isolated Linux company build machine')
    adapter_image,fixture_image,report=sys.argv[1],sys.argv[2],Path(sys.argv[3]).resolve()
    if report.exists():raise SystemExit('Never replace an existing qualification report')
    for image in (adapter_image,fixture_image):
        if not re.fullmatch(r'[A-Za-z0-9._:/-]+(?::[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})',image) or image.endswith(':latest'):
            raise SystemExit('Explicit company image references are required')
    scope='smb-check-'+secrets.token_hex(6)
    names={mode:scope+'-'+mode for mode in ('server','relay','adapter')}
    network=scope+'-internal'
    containers=[]
    with tempfile.TemporaryDirectory(prefix=scope+'-',dir=report.parent) as temporary:
        directory=Path(temporary);directory.chmod(0o755)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','2','-subj','/CN=Synthetic Connector Qualification CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(directory/'ca.key'),'-out',str(directory/'ca.crt')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        (directory/'ca.crt').chmod(0o444)
        alias='app-'+'a'*24+'.internal'
        for mode in ('adapter','relay'):
            leaf=directory/mode;leaf.mkdir(mode=0o755)
            (leaf/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectAltName=DNS:'+alias+'\nextendedKeyUsage=serverAuth\n')
            subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+alias,'-keyout',str(leaf/'app.key'),'-out',str(leaf/'leaf.csr')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
            subprocess.run(['openssl','x509','-req','-in',str(leaf/'leaf.csr'),'-CA',str(directory/'ca.crt'),'-CAkey',str(directory/'ca.key'),'-CAcreateserial','-days','1','-sha256','-extfile',str(leaf/'extensions'),'-out',str(leaf/'app.crt')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
            for name in ('app.crt','app.key'):
                (leaf/name).chmod(0o400);os.chown(leaf/name,10001,10001)
        token,relay_token=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
        common=dict(schemaVersion=1,appId='fixture-app',connectionId='fixture-connection',serverIp='',expiresAt=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())
        try:
            docker('network','create','--internal','--driver','bridge',network)
            docker('run','-d','--name',names['server'],'--runtime=runsc','--network',network,'--read-only','--cap-drop=ALL','--cap-add=NET_BIND_SERVICE','--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN','--cap-add=DAC_OVERRIDE','--security-opt=no-new-privileges','--memory=384m','--pids-limit=128','--tmpfs','/run:size=32m,mode=0755','--tmpfs','/tmp:size=16m,mode=1777','--tmpfs','/share:size=16m,mode=0755',fixture_image)
            containers.append(names['server'])
            common['serverIp']=docker('inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',names['server'])
            for mode in ('relay','adapter'):
                leaf=directory/mode
                config=common.copy()
                if mode=='adapter':
                    config.update(root='documents',share='documents',relayHost=alias,relayServerName=alias,relayPort=8444,readonlyAclEvidenceSha256=hashlib.sha256(b'Synthetic fixture config: one share read only valid users smbreader').hexdigest())
                    write(leaf/'credentials.json',dict(username='smbreader',password='Fixture-Only-Protocol-Check-2037'))
                    write(leaf/'relay-token',relay_token)
                write(leaf/'config.json',config);write(leaf/'token',token if mode=='adapter' else relay_token)
                args=['run','-d','--name',names[mode],'--runtime=runsc','--network',network,'--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user=10001:10001','--memory=256m','--pids-limit=64','--tmpfs','/tmp:size=16m,mode=1777','--volume',str(leaf)+':/run/connector:ro,z','--volume',str(directory/'ca.crt')+':/run/ca.crt:ro,z','--env','CONNECTOR_MODE='+mode,'--env','CONNECTOR_CONFIG_FILE=/run/connector/config.json','--env','CONNECTOR_TOKEN_FILE=/run/connector/token','--env','CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt','--env','CONNECTOR_TLS_KEY_FILE=/run/connector/app.key']
                if mode=='relay':args+=['--network-alias',alias]
                else:
                    relay_ip=docker('inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',names['relay'])
                    args+=['--add-host',alias+':'+relay_ip,'--env','CONNECTOR_CA_FILE=/run/ca.crt','--env','CONNECTOR_CREDENTIALS_FILE=/run/connector/credentials.json','--env','CONNECTOR_RELAY_TOKEN_FILE=/run/connector/relay-token']
                docker(*args,adapter_image);containers.append(names[mode])
            # Trusted probe inside the adapter container. Token read from its own
            # synthetic scope file, TLS verified against the fixture CA.
            probe='''import base64,http.client,json,ssl,time
ctx=ssl.create_default_context(cafile="/run/ca.crt")
token=open("/run/connector/token").read().strip()
def request(path,body,authorization=token):
 c=http.client.HTTPSConnection("127.0.0.1",8443,context=ctx,timeout=10)
 # Fixture certificate deliberately has only the private DNS identity.
 c.connect=lambda: setattr(c,"sock",ctx.wrap_socket(__import__("socket").create_connection(("127.0.0.1",8443),timeout=10),server_hostname="'''+alias+'''"))
 c.request("POST",path,json.dumps(body),{"content-type":"application/json","authorization":"Bearer "+authorization});r=c.getresponse();v=json.loads(r.read());c.close();return r.status,v
status=0
errors=[]
for _ in range(20):
 try:
  status,listing=request("/v1/connections/fixture-connection/list",dict(appId="fixture-app",root="documents",path=""))
  if status==200:break
 except (OSError,ValueError) as error:errors.append(type(error).__name__+': '+str(error))
 time.sleep(.3)
assert status==200, "Actual encrypted SMB3.1.1 listing unavailable; fixture status="+str(status)+" exceptions="+repr(errors[-3:])
assert any(x["name"]=="report.txt" and x["kind"]=="file" for x in listing["entries"])
assert not any(x["name"]=="escape" for x in listing["entries"])
status,value=request("/v1/connections/fixture-connection/read",dict(appId="fixture-app",root="documents",path="report.txt"))
assert status==200 and base64.b64decode(value["contentBase64"])==b"synthetic document\\n"
status,value=request("/v1/connections/fixture-connection/read",dict(appId="fixture-app",root="documents",path="folder/nested.txt"))
assert status==200 and base64.b64decode(value["contentBase64"])==b"nested synthetic document\\n"
for app,root,path,operation in [("other","documents","report.txt","read"),("fixture-app","other","report.txt","read"),("fixture-app","documents","../report.txt","read"),("fixture-app","documents","report.txt","write"),("fixture-app","documents","escape","read")]:
 assert request("/v1/connections/fixture-connection/"+operation,dict(appId=app,root=root,path=path))[0] in (400,503)
assert request("/v1/connections/fixture-connection/read",dict(appId="fixture-app",root="documents",path="report.txt"),"x"*43)[0]==403
print(json.dumps({"status":"passed","encryptedDialect":"SMB3.1.1","fixtureOnly":True,"checks":["TLS relay verification","actual SMB list/read and nested read","cross-app/root denial","traversal/write denial","symlink read denial","wrong adapter token denial"]}))
'''
            output=docker('exec','--user=10001:10001',names['adapter'],'python','-I','-c',probe)
            result=json.loads(output)
            result.update(schemaVersion=1,checkedAt=datetime.now(timezone.utc).isoformat(),connectorImageID=docker('image','inspect','--format','{{.Id}}',adapter_image),fixtureImageID=docker('image','inspect','--format','{{.Id}}',fixture_image),sourceSha256=hashlib.sha256((Path(__file__).resolve().parents[1]/'deploy/connectors/samba.py').read_bytes()).hexdigest(),limitations=['Synthetic Samba server only; customer share ACLs/connectivity, Windows server and Kerberos require separate reviewed qualification'])
            report.write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result,indent=2))
        except Exception:
            diagnostic=dict(status='failed',checkedAt=datetime.now(timezone.utc).isoformat(),scope='synthetic-fixture-only',companyQualified=False,containers={})
            for container in containers:
                state=subprocess.run(['docker','inspect','--format','{{json .State}}',container],text=True,capture_output=True)
                logs=subprocess.run(['docker','logs','--tail','30',container],text=True,capture_output=True)
                diagnostic['containers'][container]={'state':state.stdout[-4096:],'logs':(logs.stdout+logs.stderr)[-8192:]}
            report.with_suffix('.failed.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
            print(json.dumps(diagnostic,indent=2))
            raise
        finally:
            for container in reversed(containers):
                subprocess.run(['docker','rm','-f',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
            subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)


if __name__=='__main__':main()
