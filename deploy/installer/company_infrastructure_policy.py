"""Finite policy for the reviewed company Compose source, never generated apps."""
import hashlib
import ipaddress
import json
import re

COMPOSE_SHA256='2b021c035ab1a426612ed19f3b35e65ee567c6673469f246986b943c2dd5c03f'
SERVICES=('mysql','redis','rabbitmq','registry','keycloak')
NETWORKS={'database':True,'cache':True,'queue':True,'observability':True,
          'identity':True,'outbound':False,'artifact':True,'ingress':False}
NETWORK_MEMBERS={'mysql':('database',),'redis':('cache',),'rabbitmq':('queue','observability'),
                 'registry':('artifact','ingress'),'keycloak':('database','identity','outbound')}
MEMORY={'mysql':2147483648,'redis':805306368,'rabbitmq':1073741824,'registry':536870912,'keycloak':1610612736}
MUTABLE={'mysql':('mysql','mysql-keyring'),'redis':('redis',),'rabbitmq':('rabbitmq',),'registry':('registry',),'keycloak':()}
# (relative source, container destination, read-only, SELinux transition)
BINDS={
 'mysql':(('mysql','/var/lib/mysql',False,'Z'),('mysql-keyring','/var/lib/mysql-keyring',False,'Z'),
  ('config/mysql.cnf','/etc/mysql/conf.d/autosoft.cnf',True,'Z'),('config/mysqld.my','/usr/sbin/mysqld.my',True,'Z'),
  ('config/component_keyring_file.cnf','/usr/lib64/mysql/plugin/component_keyring_file.cnf',True,'Z'),
  ('config/mysql-init.sql','/docker-entrypoint-initdb.d/01-autosoft.sql',True,'Z'),
  ('tls/mysql','/etc/autosoft/tls',True,'z'),('secrets/mysql','/run/secrets',True,'Z')),
 'redis':(('redis','/data',False,'Z'),('config/redis','/etc/autosoft/redis',True,'Z'),('tls/redis','/etc/autosoft/tls',True,'z')),
 'rabbitmq':(('rabbitmq','/var/lib/rabbitmq',False,'Z'),('config/rabbitmq.conf','/etc/rabbitmq/rabbitmq.conf',True,'Z'),
  ('config/rabbitmq-definitions.json','/etc/rabbitmq/definitions.json',True,'Z'),('tls/rabbitmq','/etc/autosoft/tls',True,'z')),
 'registry':(('registry','/var/lib/registry',False,'Z'),('tls/registry','/etc/autosoft/tls',True,'z'),('secrets/registry','/run/secrets',True,'Z')),
 'keycloak':(('config/keycloak-start.sh','/etc/autosoft/keycloak-start.sh',True,'Z'),
  ('config/realm.json','/opt/keycloak/data/import/platform-realm.json',True,'Z'),('tls/keycloak','/etc/autosoft/tls',True,'z'),
  ('secrets/keycloak','/run/secrets',True,'Z')),
}
HEALTH={
 'mysql':dict(test=['CMD-SHELL','mysqladmin --defaults-extra-file=/run/secrets/client.cnf ping --silent'],interval='10s',timeout='5s',retries=30),
 'rabbitmq':dict(test=['CMD','rabbitmq-diagnostics','-q','ping'],interval='15s',timeout='10s',retries=20),
}

def require(value,reason='Infrastructure profile differs; preserve evidence for IT review'):
    if not value:raise ValueError(reason)

def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def tool_context(binding):
    """Project authenticated outer-worker DATA; this does not grant authority."""
    require(binding['scope'] in ('COMPANY_HOST_TOOL_PROFILE_BINDING_ONLY','COMPANY_ENGINE_TOOL_BINDING_V2_ONLY'))
    result={name:binding[name] for name in ('catalogSha256','profileSha256','qualificationReportSha256')}
    require(all(type(value) is str and re.fullmatch('[a-f0-9]{64}',value) for value in result.values()))
    result['platform']=dict(binding['platform'])
    require(set(result['platform'])=={'osId','versionId','architecture'} and result['platform']['architecture']=='x86_64')
    if binding['scope']=='COMPANY_ENGINE_TOOL_BINDING_V2_ONLY':
        require(result['platform']['osId']=='rocky'
            and all(binding[name] is False for name in ('installedToolsVerified','qualificationEvidenceVerified','parentAuthorityEstablished')))
        result['scope']=binding['scope']
        for name in ('sourceManifestSha256','distributionMetadataSha256'):
            value=binding[name];require(type(value) is str and re.fullmatch('[a-f0-9]{64}',value));result[name]=value
    return result

def tool_pins(binding):
    require(set(binding['tools'])=={'docker','compose'})
    return {name:{key:binding['tools'][name][key] for key in ('path','bytes','sha256')} for name in ('docker','compose')}

def reference(value):
    require(type(value) is str and re.fullmatch('[a-z0-9._:/-]+@sha256:[a-f0-9]{64}',value))
    repository,sha=value.split('@');parts=repository.split('/')
    require(all(p and p not in ('.','..') for p in parts))
    if len(parts)>1 and ('.' in parts[0] or ':' in parts[0] or parts[0]=='localhost'):registry,parts=parts[0],parts[1:]
    else:registry='docker.io'
    require(not any(':' in p for p in parts))
    if registry=='docker.io' and len(parts)==1:parts=['library',*parts]
    return registry+'/'+('/'.join(parts))+'@'+sha

def environment(service,cfg):
    if service=='mysql':return dict(MYSQL_ROOT_PASSWORD_FILE='/run/secrets/mysql-root',MYSQL_ROOT_HOST='localhost')
    if service=='registry':return dict(REGISTRY_HTTP_ADDR='0.0.0.0:5000',REGISTRY_HTTP_TLS_CERTIFICATE='/etc/autosoft/tls/registry.crt',
        REGISTRY_HTTP_TLS_KEY='/etc/autosoft/tls/registry.key',REGISTRY_AUTH='htpasswd',REGISTRY_AUTH_HTPASSWD_REALM='Autosoft',
        REGISTRY_AUTH_HTPASSWD_PATH='/run/secrets/htpasswd',REGISTRY_STORAGE_DELETE_ENABLED='false')
    if service=='keycloak':return dict(KC_DB='mysql',KC_DB_URL='jdbc:mysql://mysql:3306/keycloak?sslMode=VERIFY_IDENTITY&fallbackToSystemTrustStore=true',
        KC_TRUSTSTORE_PATHS='/etc/autosoft/tls/ca.crt',KC_DB_USERNAME='keycloak',KC_HOSTNAME=cfg['auth_origin'],KC_HOSTNAME_STRICT='true',
        KC_HTTP_ENABLED='false',KC_HTTPS_CERTIFICATE_FILE='/etc/autosoft/tls/keycloak.crt',KC_HTTPS_CERTIFICATE_KEY_FILE='/etc/autosoft/tls/keycloak.key',
        KC_HEALTH_ENABLED='true',KC_METRICS_ENABLED='true',KC_PROXY_HEADERS='xforwarded')
    return {}

def validate_model(model,*,data,cfg,images,compose_source):
    """Validate Compose's selected normalized model before any create call.

    The signed source hash is versioned policy, not authentication. The caller
    must supply original live source and parent authority separately.
    """
    require(type(compose_source) is bytes and hashlib.sha256(compose_source).hexdigest()==COMPOSE_SHA256)
    require(type(data) is str and data.startswith('/') and not data.endswith('/') and '..' not in data.split('/') and '\\' not in data)
    require(type(model) is dict and model.get('name')=='autosoft' and set(model['services'])==set(SERVICES))
    require(set(model)<={'name','services','networks','x-platform-env','x-platform-volumes','x-service'})
    require(set(model.get('networks',{}))==set(NETWORKS) and not model.get('volumes') and not model.get('secrets') and not model.get('configs'))
    for name,internal in NETWORKS.items():
        row=model['networks'][name]
        require(set(row)<={'name','internal','driver','ipam'} and row['name']=='autosoft_'+name
            and row.get('internal',False) is internal and row.get('driver','bridge')=='bridge' and row.get('ipam')=={})
    result={}
    for service in SERVICES:
        row=model['services'][service]
        base={'image','environment','networks','volumes','labels','restart','security_opt','logging','mem_limit','command','entrypoint'}
        optional={'mysql':{'user','healthcheck'},'redis':{'command'},'rabbitmq':{'hostname','healthcheck'},'registry':{'ports'},'keycloak':{'entrypoint','depends_on'}}[service]
        require(set(row)<=base|optional and reference(row['image'])==reference(images[service]))
        require(row.get('environment',{})==environment(service,cfg) and set(row['networks'])==set(NETWORK_MEMBERS[service]))
        require(all(v in (None,{}) for v in row['networks'].values()))
        require(row['labels']=={'io.autosoft.managed':'true'} and row['restart']=='unless-stopped'
            and row['security_opt']==['no-new-privileges:true'] and row['mem_limit']==str(MEMORY[service]))
        require(row['logging']==dict(driver='journald',options={'tag':'autosoft/{{.Name}}'}))
        expected={target:(data+'/'+source,readonly,label) for source,target,readonly,label in BINDS[service]}
        require(type(row['volumes']) is list and len(row['volumes'])==len(expected));seen=set()
        for mount in row['volumes']:
            require(set(mount)<={'type','source','target','read_only','bind'} and mount['type']=='bind'
                and mount['target'] in expected and mount['target'] not in seen)
            seen.add(mount['target']);source,readonly,label=expected[mount['target']]
            require(mount['source']==source and mount.get('read_only',False) is readonly
                and mount['bind']==dict(selinux=label))
        if service=='mysql':require(row['user']=='999:999')
        if service=='redis':require(row['command']==['redis-server','/etc/autosoft/redis/redis.conf'])
        else:require(row.get('command') is None)
        if service!='keycloak':require(row.get('entrypoint') is None)
        if service=='rabbitmq':require(row['hostname']=='rabbitmq')
        if service in HEALTH:require(row['healthcheck']==HEALTH[service])
        if service=='keycloak':
            require(row['entrypoint']==['/bin/bash','/etc/autosoft/keycloak-start.sh']
                and row['depends_on']=={'mysql':{'condition':'service_healthy','required':True}})
        if service=='registry':
            require(row['ports']==[dict(mode='ingress',host_ip='127.0.0.1',target=5000,published='5000',protocol='tcp')])
        result[service]=row
    return dict(schema=1,project='autosoft',data=data,services=result,networks=model['networks'],modelSha256=digest(model))

def image_profile(service,row,wanted):
    require(row['Os']=='linux' and row['Architecture']=='amd64' and re.fullmatch('sha256:[a-f0-9]{64}',row['Id']))
    require(any(reference(item)==reference(wanted) for item in row.get('RepoDigests',[])))
    config=row['Config'];require(type(config) is dict)
    require(set(config.get('Volumes') or {}) <= {target for _,target,_,_ in BINDS[service]})
    require(service!='keycloak' or config.get('User') in ('1000','1000:0','1000:1000'))
    require(service!='registry' or config.get('User') in ('',None,'0','0:0','root'))
    for name in ('Env','Entrypoint','Cmd'):
        value=config.get(name);require(value is None or type(value) is list and all(type(item) is str and '\0' not in item for item in value))
    # Secrets must come only from protected bind files, never image environment.
    require(all('=' in value for value in config.get('Env') or []))
    require(len({value.split('=',1)[0] for value in config.get('Env') or []})==len(config.get('Env') or []))
    return dict(id=row['Id'],config=config)

def _environment(values):
    require(type(values) is list and all(type(v) is str and '=' in v for v in values))
    pairs=[v.split('=',1) for v in values];require(len({k for k,_ in pairs})==len(pairs));return dict(pairs)

def inspect_container(service,row,*,plan,image,network_ids,config_hash,created=True):
    spec=plan['services'][service];c,h,s=row['Config'],row['HostConfig'],row['State']
    require(re.fullmatch('[a-f0-9]{64}',row['Id']) and row['Name']=='/autosoft-'+service+'-1' and row['Image']==image['id'])
    labels=c.get('Labels') or {}
    require(labels.get('com.docker.compose.project')=='autosoft' and labels.get('com.docker.compose.service')==service
        and labels.get('com.docker.compose.container-number')=='1' and labels.get('com.docker.compose.oneoff')=='False'
        and labels.get('com.docker.compose.config-hash')==config_hash and labels.get('io.autosoft.managed')=='true')
    require(reference(c['Image'])==reference(spec['image']))
    expected_env=_environment(image['config'].get('Env') or []);expected_env.update(spec.get('environment',{}))
    require(_environment(c.get('Env') or [])==expected_env)
    require(c.get('User','')==spec.get('user',image['config'].get('User','')) and not c['Tty'] and not c['OpenStdin'])
    # Compose explicitly emits JSON null for unspecified entrypoint/command.
    entrypoint=spec.get('entrypoint');command=spec.get('command')
    require(c.get('Entrypoint')==(entrypoint if entrypoint is not None else image['config'].get('Entrypoint')))
    require(c.get('Cmd')==(command if command is not None or entrypoint is not None else image['config'].get('Cmd')))
    require(c.get('WorkingDir','')==image['config'].get('WorkingDir',''))
    if service=='rabbitmq':require(c['Hostname']=='rabbitmq')
    health=spec.get('healthcheck')
    if health:
        expected_health=dict(Test=health['test'],Interval=int(health['interval'][:-1])*10**9,
            Timeout=int(health['timeout'][:-1])*10**9,Retries=health['retries'])
        measured=c.get('Healthcheck') or {}
        require(all(measured.get(key)==value for key,value in expected_health.items())
            and set(measured)<={'Test','Interval','Timeout','Retries','StartPeriod','StartInterval'}
            and measured.get('StartPeriod',0)==0 and measured.get('StartInterval',0)==0)
    else:require(c.get('Healthcheck')==image['config'].get('Healthcheck'))
    require(not h['Privileged'] and not h['ReadonlyRootfs'] and h['Memory']==MEMORY[service] and not h.get('CapAdd') and not h.get('CapDrop'))
    require(h['SecurityOpt']==['no-new-privileges:true'] and h['RestartPolicy']==dict(Name='unless-stopped',MaximumRetryCount=0))
    require(h['LogConfig']==dict(Type='journald',Config={'tag':'autosoft/{{.Name}}'}))
    require(not h.get('Devices') and not h.get('DeviceRequests') and not h.get('GroupAdd') and not h.get('ExtraHosts')
        and not h.get('VolumesFrom') and not h.get('Tmpfs') and h.get('PidMode','')=='' and h.get('UTSMode','')=='')
    ports={'5000/tcp':[dict(HostIp='127.0.0.1',HostPort='5000')]} if service=='registry' else {}
    require((h.get('PortBindings') or {})==ports and not h.get('PublishAllPorts'))
    expected={target:(plan['data']+'/'+source,not readonly) for source,target,readonly,_ in BINDS[service]}
    mounts=row['Mounts'];require(len(mounts)==len(expected))
    require(all(m.get('Type')=='bind' and m.get('Destination') in expected for m in mounts))
    require({m['Destination']:(m['Source'],m['RW']) for m in mounts}==expected)
    require(len({m['Destination'] for m in mounts})==len(expected))
    names={'autosoft_'+name for name in NETWORK_MEMBERS[service]}
    require(h['NetworkMode'] in names|{network_ids[n] for n in NETWORK_MEMBERS[service]})
    endpoints=row['NetworkSettings']['Networks'];require(set(endpoints)==names)
    for name in NETWORK_MEMBERS[service]:
        endpoint=endpoints['autosoft_'+name];require(endpoint['NetworkID'] in (network_ids[name],'') if created else endpoint['NetworkID']==network_ids[name])
        require(service in (endpoint.get('Aliases') or []) and not endpoint.get('IPAMConfig') and not endpoint.get('Links'))
        if not created:require(ipaddress.ip_address(endpoint['IPAddress']).version==4)
    require(not s.get('Error') and not s.get('OOMKilled') and not s.get('Restarting'))
    if created:require(s['Status']=='created' and s['Pid']==0 and not s['Running'])
    else:require(s['Status']=='running' and s['Running'] and s['Pid']>0)
    return row['Id']
