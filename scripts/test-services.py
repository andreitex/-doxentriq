#!/usr/bin/env python3
"""Synthetic, isolated MySQL and Keycloak verification; never accepts the platform."""
from datetime import datetime, timezone
import base64
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse
import uuid


def execute(args, **kw):
    return subprocess.run([str(v) for v in args], check=True, **kw)


def output(args):
    return subprocess.check_output([str(v) for v in args], text=True,stderr=subprocess.DEVNULL).strip()


def write(path, value, uid=0):
    path.write_text(json.dumps(value) if isinstance(value, (dict, list)) else value)
    os.chmod(path, 0o600)
    os.chown(path, uid, uid)


def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def pin(source):
    execute(['docker','pull',source],stdout=subprocess.DEVNULL)
    return json.loads(output(['docker','image','inspect',source,'--format','{{json .RepoDigests}}']))[0]


if __name__ == '__main__':
    if os.geteuid()!=0: raise SystemExit('Root is required for this isolated fixture')
    metadata=json.loads(Path('/etc/autosoft/installation.json').read_text())
    data=Path(metadata['data_dir'])
    assert Path(output(['findmnt','-n','-o','SOURCE','--target',data])).resolve()==Path('/dev/mapper/autosoft-data').resolve()
    assert not Path('/etc/autosoft/installation.complete').exists(), 'Run this only on an unaccepted test foundation'
    source_root=Path(metadata['install_root'])
    sources=json.loads((source_root/'deploy/images.sources.json').read_text())
    images={name:pin(sources[name]) for name in ('mysql','keycloak','node')}
    test_id=uuid.uuid4().hex[:12]
    work=data/'validation'/('services-'+test_id)
    work.mkdir(mode=0o700)
    for folder in ('config','tls','public-tls','mysql','mysql-keyring','secrets/runtime','secrets/keycloak','secrets/mysql'):
        (work/folder).mkdir(parents=True,exist_ok=True)
    for folder in ('mysql','mysql-keyring'):
        os.chown(work/folder,999,999)
        os.chmod(work/folder,0o700)
    bootstrap=module('bootstrap')
    cfg=dict(certificate_mode='selfsigned',admin_origin='https://admin.test.internal',apps_base_url='https://apps.test.internal',auth_origin='https://identity.test.internal',sso='none',owner_subject=str(uuid.uuid4()))
    bootstrap.certificates(work,cfg)
    mysql_password,db_password,owner_password,platform_secret,master_password,master_secret=[secrets.token_urlsafe(40) for _ in range(6)]
    bootstrap.realm(work,cfg,secrets.token_urlsafe(40),owner_password,platform_secret)
    imported=json.loads((work/'config/realm.json').read_text())
    imported['users'][0]['credentials'].append(dict(type='otp',userLabel='synthetic-recovery-fixture',secretData=json.dumps({'value':base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')}),credentialData=json.dumps(dict(subType='totp',digits=6,counter=0,algorithm='HmacSHA1',period=30))))
    write(work/'config/realm.json',imported,1000)
    shutil.copyfile(source_root/'deploy/config/mysql.cnf',work/'config/mysql.cnf')
    write(work/'config/mysqld.my',{'components':'file://component_keyring_file'})
    write(work/'config/component_keyring_file.cnf',{'path':'/var/lib/mysql-keyring/keyring','read_only':False})
    write(work/'config/init.sql',f"CREATE DATABASE keycloak DEFAULT ENCRYPTION='Y'; CREATE USER 'keycloak'@'%' IDENTIFIED BY '{db_password}' REQUIRE SSL; GRANT ALL ON keycloak.* TO 'keycloak'@'%'; CREATE DATABASE fixture DEFAULT ENCRYPTION='Y'; USE fixture; CREATE TABLE proof (id INT PRIMARY KEY,value VARCHAR(32)); INSERT INTO proof VALUES (1,'synthetic');")
    for name in ('mysql.cnf','mysqld.my','component_keyring_file.cnf','init.sql'): os.chmod(work/'config'/name,0o644)
    write(work/'secrets/mysql/mysql-root',mysql_password)
    write(work/'secrets/mysql/client.cnf',f'[client]\nuser=root\npassword={mysql_password}\nprotocol=socket\nssl-mode=DISABLED\n')
    write(work/'secrets/mysql/tls-test.cnf',f'[client]\nuser=keycloak\npassword={db_password}\nhost=mysql\nprotocol=TCP\nssl-mode=VERIFY_IDENTITY\nssl-ca=/etc/autosoft/tls/ca.crt\n')
    os.chown(work/'secrets/mysql',999,999)
    os.chmod(work/'secrets/mysql',0o700)
    for path in (work/'secrets/mysql').iterdir(): os.chown(path,999,999)
    write(work/'secrets/keycloak/mysql-password',db_password,1000)
    write(work/'secrets/keycloak/bootstrap-password',master_password,1000)
    os.chown(work/'secrets/keycloak',1000,1000)
    os.chmod(work/'secrets/keycloak',0o700)
    shutil.copyfile(source_root/'scripts/keycloak-start.sh',work/'config/keycloak-start.sh')
    network='autosoft-services-'+test_id
    mysql_name='autosoft-test-mysql-'+test_id
    identity_name='autosoft-test-keycloak-'+test_id
    containers=[]
    checks=[]
    def mount(source,target): return ['--mount',f'type=bind,source={work/source},target={target},readonly']
    def mysql(sql):
        return output(['docker','exec',mysql_name,'mysql','--defaults-extra-file=/run/secrets/client.cnf','--batch','--skip-column-names','-e',sql])
    try:
        execute(['docker','network','create','--internal',network],stdout=subprocess.DEVNULL)
        args=['docker','run','-d','--name',mysql_name,'--user','999:999','--network',network,'--network-alias','mysql','--memory','2g','--pids-limit','256','--security-opt','no-new-privileges:true','--env','MYSQL_ROOT_HOST=localhost','--env','MYSQL_ROOT_PASSWORD_FILE=/run/secrets/mysql-root','--mount',f'type=bind,source={work}/mysql,target=/var/lib/mysql','--mount',f'type=bind,source={work}/mysql-keyring,target=/var/lib/mysql-keyring']
        for source,target in [('config/mysql.cnf','/etc/mysql/conf.d/autosoft.cnf'),('config/mysqld.my','/usr/sbin/mysqld.my'),('config/component_keyring_file.cnf','/usr/lib64/mysql/plugin/component_keyring_file.cnf'),('config/init.sql','/docker-entrypoint-initdb.d/init.sql'),('tls/mysql','/etc/autosoft/tls'),('secrets/mysql','/run/secrets')]: args+=mount(source,target)
        # Apply SELinux labels to our newly created fixture only.
        execute(['chcon','-R','-t','container_file_t',work],stdout=subprocess.DEVNULL)
        execute(args+[images['mysql']],stdout=subprocess.DEVNULL)
        containers.append(mysql_name)
        for attempt in range(90):
            if output(['docker','inspect',mysql_name,'--format','{{.State.Status}}']) not in ('running','created'): raise ValueError('MySQL fixture exited during initialization')
            try:
                if mysql('SELECT value FROM fixture.proof WHERE id=1')=='synthetic': break
            except subprocess.CalledProcessError: pass
            time.sleep(2)
        else: raise ValueError('MySQL fixture did not become ready')
        values=mysql("SELECT @@require_secure_transport,@@default_table_encryption,@@innodb_redo_log_encrypt,@@innodb_undo_log_encrypt,@@binlog_encryption").split('\t')
        assert values==['1']*5, values
        assert 'ENCRYPTION=\'Y\'' in mysql('SHOW CREATE TABLE fixture.proof')
        assert (work/'mysql-keyring/keyring').stat().st_size>0
        checks.append('MySQL required TLS and native tablespace/redo/undo/binlog encryption enabled with persistent keyring')
        cipher=output(['docker','exec',mysql_name,'mysql','--defaults-extra-file=/run/secrets/tls-test.cnf','--batch','--skip-column-names','-e',"SHOW STATUS LIKE 'Ssl_cipher'"])
        assert len(cipher.split('\t'))==2 and cipher.split('\t')[1]
        denied=subprocess.run(['docker','exec',mysql_name,'mysql','--defaults-extra-file=/run/secrets/tls-test.cnf','--ssl-mode','DISABLED','-e','SELECT 1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        assert denied.returncode!=0
        checks.append('MySQL plaintext TCP connection rejected')
        args=['docker','run','-d','--name',identity_name,'--network',network,'--network-alias','keycloak','--memory','1536m','--pids-limit','256','--security-opt','no-new-privileges:true','--entrypoint','/bin/bash']
        env=dict(KC_DB='mysql',KC_DB_URL='jdbc:mysql://mysql:3306/keycloak?sslMode=VERIFY_IDENTITY&fallbackToSystemTrustStore=true',KC_TRUSTSTORE_PATHS='/etc/autosoft/tls/ca.crt',KC_DB_USERNAME='keycloak',KC_HOSTNAME=cfg['auth_origin'],KC_HOSTNAME_STRICT='true',KC_HTTP_ENABLED='false',KC_HTTPS_CERTIFICATE_FILE='/etc/autosoft/tls/keycloak.crt',KC_HTTPS_CERTIFICATE_KEY_FILE='/etc/autosoft/tls/keycloak.key',KC_HEALTH_ENABLED='true',KC_METRICS_ENABLED='true',KC_PROXY_HEADERS='xforwarded')
        for name,value in env.items(): args+=['--env',name+'='+value]
        for source,target in [('config/keycloak-start.sh','/etc/autosoft/keycloak-start.sh'),('config/realm.json','/opt/keycloak/data/import/platform-realm.json'),('tls/keycloak','/etc/autosoft/tls'),('secrets/keycloak','/run/secrets')]: args+=mount(source,target)
        execute(args+[images['keycloak'],'/etc/autosoft/keycloak-start.sh'],stdout=subprocess.DEVNULL)
        containers.append(identity_name)
        address=json.loads(output(['docker','inspect',identity_name]))[0]['NetworkSettings']['Networks'][network]['IPAddress']
        tls=ssl.create_default_context(cafile=str(work/'tls/ca.crt'))
        def request(path,method='GET',value=None,token=None,form=False,expected=200):
            connection=http.client.HTTPSConnection('keycloak',8443,context=tls,timeout=30)
            connection._create_connection=lambda _address,timeout,source_address:socket.create_connection((address,8443),timeout,source_address)
            headers={'Content-Type':'application/x-www-form-urlencoded' if form else 'application/json'}
            if token: headers['Authorization']='Bearer '+token
            body=urllib.parse.urlencode(value) if form else json.dumps(value) if value is not None else None
            connection.request(method,path,body,headers)
            result=connection.getresponse()
            raw=result.read()
            if result.status!=expected: raise ValueError(f'Identity fixture HTTP {result.status}, expected {expected}: {path}')
            return json.loads(raw) if raw else None
        for attempt in range(120):
            if output(['docker','inspect',identity_name,'--format','{{.State.Status}}']) not in ('running','created'): raise ValueError('Keycloak fixture exited during initialization')
            try:
                request('/realms/platform/.well-known/openid-configuration')
                break
            except Exception: time.sleep(2)
        else: raise ValueError('Keycloak fixture did not become ready')
        admin=request('/realms/master/protocol/openid-connect/token','POST',dict(grant_type='password',client_id='admin-cli',username='bootstrap-admin',password=master_password),form=True)['access_token']
        def api(path,method='GET',value=None,token=admin,expected=200): return request('/admin/realms/'+path,method,value,token,expected=expected)
        owner=api('platform/users/'+cfg['owner_subject'])
        assert owner['username']=='owner' and set(owner['requiredActions'])=={'UPDATE_PASSWORD','CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES'}
        checks.append('Protected exact owner UUID imported with password change, TOTP and recovery-code enrollment required; enrollment alone does not attest MFA')
        api('master/clients','POST',dict(clientId='autosoft-provisioner',enabled=True,protocol='openid-connect',publicClient=False,secret=master_secret,standardFlowEnabled=False,directAccessGrantsEnabled=False,serviceAccountsEnabled=True,fullScopeAllowed=True),expected=201)
        client=api('master/clients?clientId=autosoft-provisioner')[0]
        account=api('master/clients/'+client['id']+'/service-account-user')
        role=api('master/roles/create-realm')
        api('master/users/'+account['id']+'/role-mappings/realm','POST',[role],expected=204)
        provision=request('/realms/master/protocol/openid-connect/token','POST',dict(grant_type='client_credentials',client_id='autosoft-provisioner',client_secret=master_secret),form=True)['access_token']
        apprealm='fixture-'+test_id
        api('', 'POST',dict(realm=apprealm,enabled=True,sslRequired='all',roles={'realm':[{'name':'reader'}]},clients=[dict(clientId='fixture-app',publicClient=False,secret=secrets.token_urlsafe(40),standardFlowEnabled=True,redirectUris=['https://apps.test.internal/auth/callback'],protocol='openid-connect')]),token=provision,expected=201)
        api(apprealm,token=provision)
        api(apprealm+'/clients?clientId=fixture-app',token=provision)
        checks.append('Master create-realm provisioner can create and manage its own app realm')
        platform_token=request('/realms/platform/protocol/openid-connect/token','POST',dict(grant_type='client_credentials',client_id='platform-provisioner',client_secret=platform_secret),form=True)['access_token']
        api('platform/clients','POST',dict(clientId='fixture-broker-'+test_id,publicClient=False,secret=secrets.token_urlsafe(40),protocol='openid-connect',standardFlowEnabled=True),token=platform_token,expected=201)
        central=api('platform/clients?clientId=fixture-broker-'+test_id,token=platform_token)[0]
        api('platform/clients/'+central['id']+'/client-secret',token=platform_token)
        claims=json.loads(base64.urlsafe_b64decode(platform_token.split('.')[1]+'=='))
        assert 'manage-clients' in claims.get('resource_access',{}).get('realm-management',{}).get('roles',[])
        checks.append('Platform manage-clients service account creates clients and reads their secrets with signed role claims')
        before=api('platform/users/'+cfg['owner_subject']+'/credentials')
        assert len([credential for credential in before if credential['type']=='otp'])==1, 'Synthetic owner OTP was not imported'
        recovery_args=['docker','run','--rm','--network',network,'--read-only','--cap-drop=ALL','--security-opt','no-new-privileges','--env','NODE_EXTRA_CA_CERTS=/etc/autosoft/ca.crt','--volume',f'{work}/tls/ca.crt:/etc/autosoft/ca.crt:ro,z','--volume',f'{source_root}/scripts/keycloak-provision.mjs:/opt/provision.mjs:ro,z','-i',images['node'],'node','/opt/provision.mjs']
        recovery=execute(recovery_args,input=json.dumps(dict(action='recover-owner',resetTotp=True,bootstrapPassword=master_password,ownerSubject=cfg['owner_subject'],ownerPassword='Aa1!'+secrets.token_urlsafe(40))).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        recovered=json.loads(recovery.stdout)
        assert recovered['removedTotpCredentials']==1 and recovered['removedRecoveryCredentials']==0 and recovered['recoveryEnrollmentRequired'] is True and recovered['sessionsInvalidated'] is True
        after=api('platform/users/'+cfg['owner_subject'])
        credentials=api('platform/users/'+cfg['owner_subject']+'/credentials')
        assert not any(credential['type'] in ('otp','recovery-authn-codes') for credential in credentials)
        assert {'UPDATE_PASSWORD','CONFIGURE_TOTP','CONFIGURE_RECOVERY_AUTHN_CODES'}<=set(after['requiredActions'])
        checks.append('Trusted owner MFA recovery removed exactly one synthetic owner OTP credential, invalidated sessions and required password/TOTP/recovery-code re-enrollment')
        quota=module('quota-helper')
        quota.DATA=data
        report=dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='passed',scope='isolated synthetic MySQL/Keycloak fixture only',images=images,checks=checks,host=quota.host_telemetry(),selinux=output(['getenforce']),modelApiCalls=0,limitations=['Interactive owner password/TOTP enrollment and Google/Microsoft SSO not exercised','Full platform remains unaccepted; resource and model qualification guards unchanged'])
        write(data/'validation/services-report.json',report)
        print(json.dumps(report,indent=2))
    except Exception as exc:
        report=dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='failed',scope='isolated synthetic MySQL/Keycloak fixture only',images=images,checks=checks,error=str(exc),fixture=str(work),modelApiCalls=0)
        write(data/'validation/services-report.json',report)
        for name in containers:
            logs=subprocess.run(['docker','logs',name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True).stdout
            write(work/(name+'.log'),logs)
        print(json.dumps(report,indent=2))
        raise SystemExit(1)
    finally:
        for name in reversed(containers): subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
