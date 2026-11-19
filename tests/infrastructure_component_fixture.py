"""Synthetic Compose/daemon controls; no Docker, VM, real TLS or service calls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/'deploy/installer'
def load(name):
    spec=importlib.util.spec_from_file_location(name,BASE/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
P=load('company_infrastructure_policy');C=load('company_infrastructure_commands').infrastructure_commands(P)
def identifier(name):return hashlib.sha256(name.encode()).hexdigest()
CFG={'auth_origin':'https://auth.example.invalid'};DATA='/srv/doxentriq-data';SOURCE='/opt/company/source'
SOURCE_BYTES=(ROOT/'deploy/compose.yaml').read_bytes()
IMAGES={service:'registry.example.invalid/infra/'+service+'@sha256:'+identifier('image'+service) for service in P.SERVICES}
TOOLS=dict(scope='COMPANY_HOST_TOOL_PROFILE_BINDING_ONLY',catalogSha256=identifier('catalog'),profileSha256=identifier('profile'),
    qualificationReportSha256=identifier('qualification'),platform=dict(osId='debian',versionId='13',architecture='x86_64'),
    tools={name:dict(path=path,bytes=64,sha256=identifier(name)) for name,path in (
        ('docker','/usr/bin/docker'),('compose','/usr/libexec/docker/cli-plugins/docker-compose'))})

def model():
    rows={}
    for service in P.SERVICES:
        row=dict(image=IMAGES[service],environment=P.environment(service,CFG),networks={n:None for n in P.NETWORK_MEMBERS[service]},
            labels={'io.autosoft.managed':'true'},restart='unless-stopped',security_opt=['no-new-privileges:true'],mem_limit=str(P.MEMORY[service]),command=None,entrypoint=None,
            logging=dict(driver='journald',options={'tag':'autosoft/{{.Name}}'}),volumes=[dict(type='bind',source=DATA+'/'+s,target=t,
                read_only=ro,bind=dict(selinux=label)) for s,t,ro,label in P.BINDS[service]])
        if service=='mysql':row['user']='999:999'
        if service=='rabbitmq':row['hostname']='rabbitmq'
        if service in P.HEALTH:row['healthcheck']=copy.deepcopy(P.HEALTH[service])
        if service=='redis':row['command']=['redis-server','/etc/autosoft/redis/redis.conf']
        if service=='keycloak':row.update(entrypoint=['/bin/bash','/etc/autosoft/keycloak-start.sh'],depends_on={'mysql':{'condition':'service_healthy','required':True}})
        if service=='registry':row['ports']=[dict(mode='ingress',host_ip='127.0.0.1',target=5000,published='5000',protocol='tcp')]
        rows[service]=row
    return dict(name='autosoft',services=rows,networks={n:dict(name='autosoft_'+n,internal=i,ipam={}) for n,i in P.NETWORKS.items()})

class IO:
    deadline=1000
    def __init__(self):self.events=[];self.started=set();self.checks=0;self.refuse=False
    def check(self):self.checks+=1;P.require(not self.refuse,'synthetic authority withdrawn')
    def record(self,event,values):self.events.append((event,values))
    def begin_labels(self,enabled):self.record('create-intent',{});self.transition=True
    def finish_labels(self,rows):self.transition=False;self.sealed_inputs={'sha256':identifier('synthetic-inputs')};self.record('labels-verified',{})
    def start_intent(self,service,identifier):self.record('start-intent',dict(service=service,containerId=identifier));self.started.add(service)

class FakeTransport:
    selinux=False
    def __init__(self,io):
        self.io=io;self.calls=[];self.created=False;self.running=set();self.failure=None;self.candidate=model();self.elapsed=0
        self.pins=P.tool_pins(TOOLS)
    def preflight(self):pass
    def check(self):self.io.check()
    def close(self):pass
    def image(self,service):
        return dict(Id='sha256:'+identifier('local'+service),Os='linux',Architecture='amd64',RepoDigests=[IMAGES[service]],
            Config=dict(User='1000' if service=='keycloak' else '',Env=['PATH=/usr/bin'],Entrypoint=['entrypoint'],Cmd=['serve'],WorkingDir='',Volumes={}))
    def container(self,service):
        spec=self.candidate['services'][service];image=self.image(service)['Config'];cid=identifier('container'+service)
        env={'PATH':'/usr/bin',**spec.get('environment',{})}
        entrypoint=spec.get('entrypoint');command=spec.get('command')
        c=dict(Image=IMAGES[service],User=spec.get('user',image['User']),Entrypoint=entrypoint if entrypoint is not None else image['Entrypoint'],
            Cmd=command if command is not None or entrypoint is not None else image['Cmd'],WorkingDir='',Hostname='rabbitmq' if service=='rabbitmq' else cid[:12],
            Env=[k+'='+v for k,v in env.items()],Tty=False,OpenStdin=False,Labels={'com.docker.compose.project':'autosoft',
            'com.docker.compose.service':service,'com.docker.compose.container-number':'1','com.docker.compose.oneoff':'False',
            'com.docker.compose.config-hash':identifier('config'+service),'io.autosoft.managed':'true'})
        if service in P.HEALTH:
            health=P.HEALTH[service];c['Healthcheck']=dict(Test=health['test'],Interval=int(health['interval'][:-1])*10**9,Timeout=int(health['timeout'][:-1])*10**9,Retries=health['retries'])
        live=service in self.running
        return dict(Id=cid,Name='/autosoft-'+service+'-1',Image=self.image(service)['Id'],Config=c,
            HostConfig=dict(Privileged=False,ReadonlyRootfs=False,Memory=P.MEMORY[service],CapAdd=None,CapDrop=None,SecurityOpt=['no-new-privileges:true'],
                RestartPolicy=dict(Name='unless-stopped',MaximumRetryCount=0),LogConfig=dict(Type='journald',Config={'tag':'autosoft/{{.Name}}'}),
                PortBindings={'5000/tcp':[dict(HostIp='127.0.0.1',HostPort='5000')]} if service=='registry' else {},PublishAllPorts=False,
                NetworkMode='autosoft_'+P.NETWORK_MEMBERS[service][0]),
            Mounts=[dict(Type='bind',Source=DATA+'/'+s,Destination=t,RW=not ro) for s,t,ro,_ in P.BINDS[service]],
            NetworkSettings=dict(Networks={'autosoft_'+n:dict(NetworkID=identifier('net'+n) if live else '',Aliases=[service],IPAddress='172.31.0.2' if live else '') for n in P.NETWORK_MEMBERS[service]}),
            State=dict(Status='running' if live else 'created',Running=live,Pid=123 if live else 0,Health={'Status':'healthy'} if service in P.HEALTH else {}),MountLabel='')
    def run(self,tool,args,*,timeout=30):
        self.calls.append((tool,list(args)));value=None
        if tool=='compose':
            command=args[args.index('--progress')+2:]
            if command[:3]==['config','--format','json']:value=self.candidate
            elif command[:2]==['config','--hash']:
                service=command[2];assert service in P.SERVICES
                output=service+' '+identifier('config'+service)+'\n'
                if self.failure=='hash-extra':output+='foreign '+identifier('foreign')+'\n'
                return SimpleNamespace(returncode=0,stdout=output.encode())
            elif command[0]=='create':
                self.created=True
                if self.failure=='create-unknown':raise TimeoutError('synthetic ambiguous create')
                return SimpleNamespace(returncode=0,stdout=b'')
            else:raise AssertionError(command)
        else:
            self.assert_host(args);command=args[2:]
            if command[0]=='info':value=dict(ID='synthetic-daemon',DockerRootDir=DATA+'/docker',LoggingDriver='journald',Plugins={'Log':['journald']})
            elif command[:2]==['container','ls']:
                ids=[identifier('container'+s) for s in P.SERVICES] if self.created else []
                if self.failure=='foreign-before':ids.append(identifier('foreign'))
                return SimpleNamespace(returncode=0,stdout=('\n'.join(ids)+('\n' if ids else '')).encode())
            elif command[:2]==['network','ls']:
                names=['bridge','host','none']+(['autosoft_'+n for n in P.NETWORKS] if self.created else [])
                rows=[dict(Name=n,ID=identifier('net'+n.removeprefix('autosoft_'))) for n in names]
                return SimpleNamespace(returncode=0,stdout=b'\n'.join(json.dumps(row).encode() for row in rows))
            elif command[:2]==['network','inspect']:
                name=next(n for n in ['bridge','host','none',*P.NETWORKS] if identifier('net'+n)==command[2]);builtin=name not in P.NETWORKS
                value=[dict(Id=command[2],Name=name if builtin else 'autosoft_'+name,Driver={'none':'null','host':'host'}.get(name,'bridge'),
                    Internal=P.NETWORKS.get(name,False),Scope='local',Ingress=False,
                    Containers={identifier('container'+s):{} for s in self.running if name in P.NETWORK_MEMBERS[s]},
                    Labels={} if builtin else {'com.docker.compose.project':'autosoft','com.docker.compose.network':name})]
            elif command[:2]==['image','inspect']:value=[self.image(next(s for s in P.SERVICES if IMAGES[s]==command[2]))]
            elif command[:2]==['container','inspect']:
                service=next(s for s in P.SERVICES if identifier('container'+s)==command[2]);row=self.container(service)
                if self.failure=='unexpected-port' and service=='mysql':row['HostConfig']['PortBindings']={'3306/tcp':[dict(HostIp='0.0.0.0',HostPort='3306')]}
                if self.failure=='wrong-hash':row['Config']['Labels']['com.docker.compose.config-hash']='0'*64
                value=[row]
            elif command[:2]==['container','start']:
                service=next(s for s in P.SERVICES if identifier('container'+s)==command[2]);self.running.add(service)
                if self.failure=='start-unknown':raise TimeoutError('synthetic ambiguous start')
                return SimpleNamespace(returncode=0,stdout=(command[2]+'\n').encode())
            else:raise AssertionError(command)
        return SimpleNamespace(returncode=0,stdout=json.dumps(value).encode())
    @staticmethod
    def assert_host(args):assert args[:2]==['--host','unix:///run/docker.sock']
