#!/usr/bin/env python3
"""Exercise the narrow quota service under its production systemd restrictions."""
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import uuid


if __name__=='__main__':
    if os.geteuid()!=0: raise SystemExit('Root is required for this isolated host-helper test')
    metadata=json.loads(Path('/etc/autosoft/installation.json').read_text())
    data=Path(metadata['data_dir'])
    assert not Path('/etc/autosoft/installation.complete').exists()
    fixture=data/'validation'/('quota-service-'+uuid.uuid4().hex[:12])
    fixture.mkdir(mode=0o700)
    token=secrets.token_urlsafe(40)
    tokenfile=fixture/'token'
    tokenfile.write_text(token)
    os.chmod(tokenfile,0o600)
    unit='autosoft-quota-test-'+uuid.uuid4().hex[:12]
    args=['systemd-run','--unit',unit,'--property','RuntimeDirectory=autosoft','--property','RuntimeDirectoryMode=0750','--property','NoNewPrivileges=true','--property','ProtectSystem=strict','--property','ProtectHome=true','--property','PrivateTmp=true','--property',f'ReadWritePaths={data}/runtime/storage {data}/quota /run/autosoft','--property','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE','--setenv','QUOTA_TOKEN_FILE='+str(tokenfile),'/usr/bin/python3',str(Path(metadata['install_root'])/'scripts/quota-helper.py')]
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
    def call(path,value,authorized=True):
        connection=http.client.HTTPConnection('localhost',timeout=10)
        def connect(_address,timeout,source_address):
            client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            client.settimeout(timeout)
            client.connect('/run/autosoft/quota.sock')
            return client
        connection.connect=lambda:setattr(connection,'sock',connect(None,connection.timeout,None))
        connection.request('POST',path,json.dumps(value),{'Content-Type':'application/json',**({'Authorization':'Bearer '+token} if authorized else {})})
        response=connection.getresponse()
        body=response.read()
        return response.status,json.loads(body) if response.status==200 else None
    try:
        for attempt in range(30):
            if Path('/run/autosoft/quota.sock').is_socket(): break
            time.sleep(0.2)
        else: raise ValueError('Quota helper socket did not become ready')
        assert call('/v1/telemetry',{},False)[0]==403
        status,telemetry=call('/v1/telemetry',{})
        assert status==200 and telemetry['host']['encryptedDataMounted'] is True
        request=dict(appId=str(uuid.uuid4()),name='helper-test',sizeMb=16)
        status,resource=call('/v1/storage',request)
        assert status==200 and resource['quotaEnforced'] is True and resource['sizeMb']==16
        assert call('/v1/storage',{**request,'name':'../../escape'})[0]==503
        report=dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='passed',scope='isolated host quota helper under production systemd restrictions',checks=['Unauthorized telemetry rejected','Authenticated actual host telemetry and encrypted mount verified','XFS project quota created and kernel hard limit verified under restricted systemd service','Path traversal rejected'],host=telemetry['host'],modelApiCalls=0)
        (data/'validation/quota-service-report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    finally:
        subprocess.run(['systemctl','stop',unit],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['systemctl','reset-failed',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
