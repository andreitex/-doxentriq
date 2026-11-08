"""Read-only relationships and PKI checks after exact render output readback."""
import base64
import hashlib
import json
import re
import urllib.parse


def require(ok):
    if not ok:raise ValueError('Rendered configuration verification failed; preserve outputs for company review')


def verify(B,io,*,source_verifier):
    data=io.data;cfg=io.cfg
    read=lambda name:(data/name).read_text()
    value=lambda name:json.loads(read(name))
    B.verify(data,source_verifier=source_verifier,command=io.process.verify_command)
    for original,copies in (
        ('secrets/platform/broker-token',('secrets/runtime/broker-token','secrets/packager/broker-token')),
        ('secrets/platform/publication-proof-key',('secrets/runtime/publication-proof-key',)),
        ('secrets/control/metrics-token',('secrets/metrics/metrics-token',)),
        ('secrets/runtime/registry.json',('secrets/packager/registry.json',)),
        ('config/redis/users.acl',('redis/users.acl',))):
        require(all(read(original)==read(copy) for copy in copies))
    for name in ('secrets/platform/secret-key','secrets/platform/publication-proof-key','secrets/runtime/vault-key'):
        require(len(base64.b64decode(read(name),validate=True))==32)
    password=read('secrets/runtime/registry-password')
    require(value('secrets/runtime/registry.json')==dict(username='platform',password=password))
    require(value('secrets/runtime/config.json')=={'auths':{'registry:5000':{'auth':base64.b64encode(('platform:'+password).encode()).decode()}}})
    require(re.fullmatch(r'platform:\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}\n',read('secrets/registry/htpasswd')) is not None)
    io.process.verify_bcrypt()
    redis,admin=read('secrets/platform/redis-password'),read('secrets/runtime/redis-admin')
    require(read('config/redis/users.acl')==f'user default off\nuser platform on >{redis} ~platform:* &platform:* +@all -config -acl -module -debug -shutdown -flushall -flushdb\nuser provisioner on >{admin} ~* &* +@all\n')
    require(read('secrets/platform/redis-url')==f'rediss://platform:{redis}@redis:6379')
    rmq,rmqadmin=read('secrets/platform/rabbitmq-password'),read('secrets/runtime/rabbitmq-admin')
    require(read('secrets/platform/rabbitmq-url')==f'amqps://platform:{rmq}@rabbitmq:5671/platform')
    definitions=value('config/rabbitmq-definitions.json');users=definitions['users']
    require(len(users)==2)
    for user,name,secret,tags in zip(users,('platform','provisioner'),(rmq,rmqadmin),('','administrator')):
        raw=base64.b64decode(user['password_hash'],validate=True)
        require(set(user)=={'name','password_hash','hashing_algorithm','tags'} and user['name']==name and user['tags']==tags
            and user['hashing_algorithm']=='rabbit_password_hashing_sha256' and len(raw)==36
            and raw[4:]==hashlib.sha256(raw[:4]+secret.encode()).digest())
    require(definitions['vhosts']==[{'name':'platform'}] and definitions['permissions']==[
        dict(user=name,vhost='platform',configure='.*',write='.*',read='.*') for name in ('platform','provisioner')])
    captured=[]
    B.realm(data,cfg,read('secrets/platform/oidc-client'),read('secrets/owner-password'),
        read('secrets/runtime/keycloak-platform-client'),writer=lambda path,result,**kw:captured.append((str(path),result,kw)))
    require(len(captured)==1 and captured[0]==(str(data/'config/realm.json'),value('config/realm.json'),{'uid':1000}))
    require(value('config/filesystem-sources.json')==dict(schemaVersion=1,sources=[]))
    require(value('config/mysqld.my')=={'components':'file://component_keyring_file'})
    require(value('config/component_keyring_file.cnf')=={'path':'/var/lib/mysql-keyring/keyring','read_only':False})
    # Exact SQL bytes are already bound by the closed execute manifest. Check the
    # independently meaningful encryption/TLS/grant invariants, not broad grants.
    sql=read('config/mysql-init.sql')
    require("ALTER TABLESPACE mysql ENCRYPTION='Y';" in sql and sql.count("DEFAULT ENCRYPTION='Y'")==2
        and sql.count('REQUIRE SSL;')==4 and 'GRANT ALL ON *.*' not in sql)
    adapted=value('config/caddy.json');servers=adapted['apps']['http']['servers']
    require(set(servers)=={'apps'} and type(servers['apps']['routes']) is list and bool(servers['apps']['routes']))
    require(all(route.get('@id')=='autosoft-protected-'+str(i) for i,route in enumerate(servers['apps']['routes'])))
    environment={}
    for line in read('config/compose.env').splitlines():
        k,v=line.split('=',1);require(k not in environment);environment[k]=v
    require(environment['DATA_DIR']==io.root and environment['ADMIN_ORIGIN']==cfg['admin_origin']
        and environment['APPS_BASE_URL']==cfg['apps_base_url'] and environment['AUTH_ORIGIN']==cfg['auth_origin']
        and environment['OWNER_SUBJECT']==cfg['owner_subject'] and environment['MONTHLY_BUDGET_USD']==cfg['monthly_budget_usd']
        and environment['JOB_BUDGET_USD']==cfg['job_budget_usd'])
    require(all(environment[name.upper()+'_IMAGE']==image for name,image in value('config/images.lock.json').items()))
    ca=str(data/'tls/ca.crt')
    run=lambda args:io.process.run(['openssl',*args],check=True,capture_output=True,text=True).stdout
    run(['verify','-x509_strict','-CAfile',ca,ca])
    extensions=run(['x509','-in',ca,'-noout','-ext','basicConstraints,keyUsage'])
    require('CA:TRUE' in extensions and 'Certificate Sign' in extensions)
    pairs=[('tls/ca.key','tls/ca.crt',None),('secrets/runtime/app-issuer.key','secrets/runtime/app-issuer.crt',None)]
    for directory in io.spec['freshDirectories']:
        if directory.startswith('tls/'):
            name=directory.split('/')[1];pairs.append((directory+'/'+name+'.key',directory+'/'+name+'.crt',name))
    if cfg['certificate_mode']=='selfsigned':pairs.append(('public-tls/server.key','public-tls/server.crt',urllib.parse.urlsplit(cfg['admin_origin']).hostname))
    for private,certificate,hostname in pairs:
        public=run(['pkey','-in',str(data/private),'-pubout'])
        require(public.startswith('-----BEGIN PUBLIC KEY-----\n') and len(public)>64
            and public==run(['x509','-in',str(data/certificate),'-pubkey','-noout']))
        args=['verify','-x509_strict','-CAfile',ca]
        if hostname:args+=['-purpose','sslserver','-verify_hostname',hostname]
        run(args+[str(data/certificate)])
    if cfg['certificate_mode']=='selfsigned':
        hosts=[urllib.parse.urlsplit(cfg[name]).hostname for name in ('admin_origin','apps_base_url','auth_origin')]
        for host in [*hosts,'probe.'+hosts[1]]:
            run(['verify','-x509_strict','-CAfile',ca,'-purpose','sslserver','-verify_hostname',host,str(data/'public-tls/server.crt')])
    io.check()
    return dict(scope='RENDER_OUTPUTS_ONLY',status='independently-verified',files=len(io.files),
        servicesActivated=False,identityProvisioned=False,backupReady=False)
