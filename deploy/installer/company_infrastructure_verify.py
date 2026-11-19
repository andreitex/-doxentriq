"""Independent read-only live observation; no create/start/retry or stage ACK.

The outer worker must supply genuine source/parent authority and the protected
executed outcome. This verifier never mutates the executor's in-memory phase.
"""
import json
import re
from contextlib import ExitStack

def verify_recorded_infrastructure(*,data,records_path,render_manifest,executed_raw,executed_sha256,
        source,cfg,images,compose_source,tool_binding,check_authority,evidence_class,verifier_class,
        transport_factory,probe_factory):
    """Close every evidence/transport scope before returning the observation.

    Factories are fixed company worker wiring and synthetic test seams, never
    administrator input. This is still not the genuine parent-stage worker.
    """
    check_authority()
    with ExitStack() as stack:
        held=stack.enter_context(evidence_class(data,records_path,render_manifest,executed_raw,executed_sha256,
            tool_binding=tool_binding,check_authority=check_authority))
        transport=transport_factory(held);stack.callback(transport.close)
        probe=probe_factory(held,transport)
        verifier=verifier_class(held,transport,probe,data=data,source=source,cfg=cfg,images=images,
            compose_source=compose_source,tool_binding=tool_binding)
        result=verifier.verify();held.check();check_authority()
    check_authority()
    return result

def infrastructure_verifier(P):
    class InfrastructureVerifier:
        def __init__(self,evidence,transport,probe,*,data,source,cfg,images,compose_source,tool_binding):
            self.evidence=evidence;self.transport=transport;self.probe=probe;self.data=data;self.source=source
            self.cfg=cfg;self.images=images;self.compose_source=compose_source;self.failed=False;self.used=False
            self.expected=evidence.execution
            P.require(P.tool_context(tool_binding)==self.expected['toolContext'])
            P.require(self.transport.pins==P.tool_pins(tool_binding))
            self.prefix=['--project-name','autosoft','--project-directory',source,'--env-file',data+'/config/compose.env',
                '--file',source+'/deploy/compose.yaml','--ansi','never','--progress','plain']

        def _check(self):P.require(not self.failed);self.evidence.check();self.transport.check()
        def _call(self,tool,args):
            self._check();result=self.transport.run(tool,args,timeout=30)
            P.require(result.returncode==0 and type(result.stdout) is bytes and len(result.stdout)<=2*1024**2)
            self._check();return result.stdout
        def _docker(self,args):return self._call('docker',['--host','unix:///run/docker.sock',*args])
        def _json(self,args):return json.loads(self._docker(args))
        def _compose(self,args):return self._call('compose',self.prefix+args)

        def verify(self):
            try:
                P.require(not self.used and not self.failed);self.used=True
                self.evidence.check();self.transport.preflight()
                e=self.expected;info=self._json(['info','--format','{{json .}}'])
                P.require(info['ID']==e['daemonId'] and info['DockerRootDir']==self.data+'/docker'
                    and info['LoggingDriver']=='journald' and 'journald' in info['Plugins']['Log'])
                raw=self._compose(['config','--format','json',*P.SERVICES])
                plan=P.validate_model(json.loads(raw),data=self.data,cfg=self.cfg,images=self.images,compose_source=self.compose_source)
                P.require(plan['modelSha256']==e['modelSha256'])
                for service in P.SERVICES:
                    hashes=self._compose(['config','--hash',service,*P.SERVICES]).decode().splitlines()
                    P.require(len(hashes)==1 and hashes[0].split()==[service,e['configHashes'][service]])
                listed=self._docker(['container','ls','--all','--no-trunc','--quiet']).decode().splitlines()
                P.require(len(listed)==len(set(listed))==len(P.SERVICES) and set(listed)==set(e['containerIds'].values()))
                networks=[json.loads(line) for line in self._docker(['network','ls','--no-trunc','--format','{{json .}}']).splitlines() if line]
                names={row['Name']:row['ID'] for row in networks}
                P.require(len(networks)==len(names)==len(P.NETWORKS)+3 and set(names)=={'bridge','host','none'}|{'autosoft_'+n for n in P.NETWORKS})
                for name,identifier in names.items():
                    if name.startswith('autosoft_'):P.require(identifier==e['networkIds'][name.removeprefix('autosoft_')])
                    P.require(re.fullmatch('[a-f0-9]{64}',identifier));rows=self._json(['network','inspect',identifier]);P.require(len(rows)==1)
                    row=rows[0];P.require(row['Id']==identifier and row['Name']==name)
                    if name in ('bridge','host','none'):
                        P.require(row['Driver']=={'bridge':'bridge','host':'host','none':'null'}[name] and not row.get('Containers'));continue
                    logical=name.removeprefix('autosoft_');labels=row.get('Labels') or {}
                    P.require(identifier==e['networkIds'][logical] and row['Driver']=='bridge' and row['Internal'] is P.NETWORKS[logical]
                        and row['Scope']=='local' and not row.get('Ingress') and labels.get('com.docker.compose.project')=='autosoft'
                        and labels.get('com.docker.compose.network')==logical)
                    P.require(set(row.get('Containers') or {})=={e['containerIds'][s] for s in P.SERVICES if logical in P.NETWORK_MEMBERS[s]})
                for service in P.SERVICES:
                    rows=self._json(['image','inspect',self.images[service]]);P.require(len(rows)==1)
                    image=P.image_profile(service,rows[0],self.images[service]);P.require(image['id']==e['imageIds'][service])
                    rows=self._json(['container','inspect',e['containerIds'][service]]);P.require(len(rows)==1)
                    row=rows[0];P.require(row['Id']==e['containerIds'][service])
                    P.inspect_container(service,row,plan=plan,image=image,network_ids=e['networkIds'],config_hash=e['configHashes'][service],created=False)
                    self._labels(service,row)
                    P.require(service not in P.HEALTH or row['State'].get('Health',{}).get('Status')=='healthy')
                    P.require(self.probe.ready(service,row,deadline=self.evidence.deadline))
                self._check()
                return dict(scope='INDEPENDENT_PRIVATE_INFRASTRUCTURE_COMPONENT_OBSERVATION',
                    executedOutcomeSha256=self.evidence.execution_sha256,immutableInputsSha256=e['immutableInputsSha256'],
                    toolContext=e['toolContext'],privateInfrastructureObserved=True,
                    parentAuthorityEstablished=False,identityProvisioned=False,publicStartupAllowed=False,wholeSignedStageQualified=False)
            except BaseException:self.failed=True;raise

        def _labels(self,service,row):
            snapshot=self.evidence.snapshot
            P.require(self.transport.selinux is snapshot['selinuxEnabled'])
            if not snapshot['selinuxEnabled']:return
            mount=row['MountLabel'];P.require(type(mount) is str and re.fullmatch(r'system_u:object_r:container_file_t:s0:c[0-9]+,c[0-9]+',mount))
            for root,_,_,kind in P.BINDS[service]:
                wanted=mount if kind=='Z' else 'system_u:object_r:container_file_t:s0'
                for name in snapshot['labelTransitions']:
                    if name==root or name.startswith(root+'/'):P.require(snapshot['labelTransitions'][name]['afterLabel']==wanted)

        def close(self):self.transport.close()
    return InfrastructureVerifier
