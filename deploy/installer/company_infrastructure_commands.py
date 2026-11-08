"""Finite Compose create and exact-ID starts, with no retry or deletion API.

The caller is the authenticated native worker. The injected transport and probe
are trusted test seams; neither grants source/parent authority.
"""
import json
import re
import time

def infrastructure_commands(policy):
    P=policy
    class InfrastructureCommands:
        def __init__(self,io,transport,probe,*,data,source,cfg,images,compose_source,tool_binding,clock=time.monotonic,sleep=time.sleep):
            self.io=io;self.transport=transport;self.probe=probe;self.data=data;self.source=source
            self.cfg=cfg;self.images=images;self.compose_source=compose_source;self.clock=clock;self.sleep=sleep
            self.tool_context=P.tool_context(tool_binding)
            P.require(self.transport.pins==P.tool_pins(tool_binding))
            self.phase='new';self.failed=False;self.ids={};self.network_ids={};self.image_profiles={};self.hashes={}
            self.compose_prefix=['--project-name','autosoft','--project-directory',source,'--env-file',data+'/config/compose.env',
                '--file',source+'/deploy/compose.yaml','--ansi','never','--progress','plain']

        def _check(self):P.require(not self.failed);self.io.check();self.transport.check()

        def _call(self,tool,args,*,timeout=30):
            self._check()
            result=self.transport.run(tool,args,timeout=timeout)
            P.require(result.returncode==0,'Infrastructure command outcome is unconfirmed; preserve evidence and do not retry')
            P.require(type(result.stdout) is bytes and len(result.stdout)<=2*1024**2)
            self._check();return result.stdout

        def _docker(self,args,**kw):return self._call('docker',['--host','unix:///run/docker.sock',*args],**kw)
        def _compose(self,args,**kw):return self._call('compose',self.compose_prefix+args,**kw)
        def _json(self,args):return json.loads(self._docker(args))

        def _daemon(self):
            info=self._json(['info','--format','{{json .}}'])
            P.require(type(info['ID']) is str and 1<=len(info['ID'])<=256
                and info['DockerRootDir']==self.data+'/docker' and info['LoggingDriver']=='journald'
                and 'journald' in info['Plugins']['Log'])
            if hasattr(self,'daemon_id'):P.require(info['ID']==self.daemon_id)
            else:self.daemon_id=info['ID']
            return info

        def _network_inventory(self,*,fresh):
            raw=self._docker(['network','ls','--no-trunc','--format','{{json .}}'])
            rows=[json.loads(line) for line in raw.splitlines() if line]
            P.require(len(rows)==(3 if fresh else 3+len(P.NETWORKS)) and len({r['Name'] for r in rows})==len(rows))
            names={row['Name']:row['ID'] for row in rows};wanted={'bridge','host','none'}
            if not fresh:wanted|={'autosoft_'+name for name in P.NETWORKS}
            P.require(set(names)==wanted and all(re.fullmatch('[a-f0-9]{64}',value) for value in names.values()))
            if fresh:
                self.builtin_networks=dict(names)
                for name,identifier in names.items():
                    values=self._json(['network','inspect',identifier]);P.require(len(values)==1)
                    value=values[0];P.require(value['Id']==identifier and value['Name']==name and not value.get('Containers'))
                    P.require(value['Driver']=={'bridge':'bridge','host':'host','none':'null'}[name])
                return
            P.require({n:names[n] for n in ('bridge','host','none')}==self.builtin_networks)
            for name,internal in P.NETWORKS.items():
                identifier=names['autosoft_'+name]
                if name in self.network_ids:P.require(self.network_ids[name]==identifier)
                values=self._json(['network','inspect',identifier]);P.require(len(values)==1)
                value=values[0];labels=value.get('Labels') or {}
                P.require(value['Id']==identifier and value['Name']=='autosoft_'+name and value['Driver']=='bridge'
                    and value['Internal'] is internal and value['Scope']=='local' and not value.get('Ingress'))
                P.require(labels.get('com.docker.compose.project')=='autosoft' and labels.get('com.docker.compose.network')==name)
                P.require(set(value.get('Containers') or {})<={self.ids[s] for s in self.ids if name in P.NETWORK_MEMBERS[s]})
                self.network_ids[name]=identifier

        def _containers(self,*,fresh=False):
            values=self._docker(['container','ls','--all','--no-trunc','--quiet']).decode().splitlines()
            P.require(len(set(values))==len(values) and all(re.fullmatch('[a-f0-9]{64}',v) for v in values))
            if fresh:P.require(values==[]);return {}
            P.require(len(values)==len(P.SERVICES));result={}
            for identifier in values:
                rows=self._json(['container','inspect',identifier]);P.require(len(rows)==1)
                row=rows[0];service=(row['Config'].get('Labels') or {}).get('com.docker.compose.service')
                P.require(service in P.SERVICES and service not in result and row['Id']==identifier)
                if service in self.ids:P.require(self.ids[service]==identifier)
                result[service]=row
            P.require(set(result)==set(P.SERVICES));return result

        def preflight(self):
            try:
                P.require(self.phase=='new');self.transport.preflight();self._daemon()
                self._containers(fresh=True);self._network_inventory(fresh=True)
                raw=self._compose(['config','--format','json',*P.SERVICES])
                self.plan=P.validate_model(json.loads(raw),data=self.data,cfg=self.cfg,images=self.images,compose_source=self.compose_source)
                # Compose 5.7.0 emits all non-profile services for --hash '*'
                # despite the selected positional list. Request each exact
                # service independently and refuse any additional output row.
                for service in P.SERVICES:
                    hashes=self._compose(['config','--hash',service,*P.SERVICES]).decode().splitlines()
                    P.require(len(hashes)==1)
                    name,value=hashes[0].split()
                    P.require(name==service and re.fullmatch('[a-f0-9]{64}',value));self.hashes[name]=value
                P.require(set(self.hashes)==set(P.SERVICES))
                for service in P.SERVICES:
                    rows=self._json(['image','inspect',self.images[service]]);P.require(len(rows)==1)
                    self.image_profiles[service]=P.image_profile(service,rows[0],self.images[service])
                self._check();self.phase='preflight'
                return dict(scope='PRIVATE_INFRASTRUCTURE_PREFLIGHT',modelSha256=self.plan['modelSha256'],
                    configHashes=dict(self.hashes),services=list(P.SERVICES),mutated=False)
            except BaseException:self.failed=True;raise

        def create(self):
            try:
                P.require(self.phase=='preflight');self._daemon();self._containers(fresh=True);self._network_inventory(fresh=True)
                self.io.begin_labels(self.transport.selinux)
                self.phase='create-attempted'
                self._compose(['create','--no-build','--pull','never','--no-recreate',*P.SERVICES],timeout=180)
                rows=self._containers()
                self.ids={service:row['Id'] for service,row in rows.items()}
                self._network_inventory(fresh=False)
                for service in P.SERVICES:
                    P.inspect_container(service,rows[service],plan=self.plan,image=self.image_profiles[service],
                        network_ids=self.network_ids,config_hash=self.hashes[service],created=True)
                    self.io.record('created',dict(service=service,containerId=self.ids[service]))
                self.io.finish_labels(rows);self._check();self.phase='created'
                return dict(scope='PRIVATE_INFRASTRUCTURE_CREATED',containerIds=dict(self.ids),networkIds=dict(self.network_ids),started=False)
            except BaseException:self.failed=True;raise

        def _running(self,service):
            rows=self._json(['container','inspect',self.ids[service]]);P.require(len(rows)==1 and rows[0]['Id']==self.ids[service])
            P.inspect_container(service,rows[0],plan=self.plan,image=self.image_profiles[service],
                network_ids=self.network_ids,config_hash=self.hashes[service],created=False)
            return rows[0]

        def start(self):
            try:
                P.require(self.phase=='created');self._daemon();rows=self._containers();self._network_inventory(fresh=False)
                for service in P.SERVICES:P.inspect_container(service,rows[service],plan=self.plan,image=self.image_profiles[service],
                    network_ids=self.network_ids,config_hash=self.hashes[service],created=True)
                self.phase='start-attempted'
                for service in P.SERVICES:
                    self.io.start_intent(service,self.ids[service])
                    raw=self._docker(['container','start',self.ids[service]],timeout=60)
                    P.require(raw.decode().strip()==self.ids[service])
                    deadline=min(self.io.deadline,self.clock()+180)
                    while True:
                        self._check();P.require(self.clock()<deadline,'Private service readiness deadline exceeded; preserve partial startup')
                        row=self._running(service)
                        health=row['State'].get('Health') or {}
                        ready=(health.get('Status')=='healthy') if service in P.HEALTH else True
                        P.require(health.get('Status')!='unhealthy','Private service declared itself unhealthy; no automatic restart')
                        if ready and self.probe.ready(service,row,deadline=deadline):break
                        self.sleep(min(1,max(0,deadline-self.clock())))
                    self.io.record('started',dict(service=service,containerId=self.ids[service]))
                self.phase='running';return self.verify()
            except BaseException:self.failed=True;raise

        def verify(self):
            try:
                P.require(self.phase=='running');self._daemon();self._containers();self._network_inventory(fresh=False)
                for service in P.SERVICES:
                    row=self._running(service)
                    P.require(service not in P.HEALTH or row['State'].get('Health',{}).get('Status')=='healthy')
                    P.require(self.probe.ready(service,row,deadline=min(self.io.deadline,self.clock()+10)))
                self._check()
                value=dict(scope='PRIVATE_INFRASTRUCTURE_COMPONENT',containerIds=dict(self.ids),networkIds=dict(self.network_ids),
                    daemonId=self.daemon_id,toolContext=self.tool_context,
                    imageIds={name:row['id'] for name,row in self.image_profiles.items()},modelSha256=self.plan['modelSha256'],
                    immutableInputsSha256=self.io.sealed_inputs['sha256'],
                    configHashes=dict(self.hashes),privateInfrastructureReady=True,identityProvisioned=False,publicStartupAllowed=False,
                    backupReady=False,wholeSignedStageQualified=False)
                self.io.record('verified',dict(outcomeSha256=P.digest(value)))
                self.phase='verified';return value
            except BaseException:self.failed=True;raise

        def close(self):
            self.transport.close()
            P.require(not self.failed and self.phase in ('new','preflight','verified'),
                'Infrastructure outcome remains unconfirmed; preserve containers and durable intents')
    return InfrastructureCommands
