"""Fixed identity helper lifecycle. No public service activation API exists.

The trusted package supplies the original reviewed renderer transport module.
Neither this adapter nor an injectable Python callback is an authority sandbox.
"""
import json,os,re,stat

def canonical_digest_reference(value):
    """Only Docker Hub's implicit registry/library spellings are equivalent."""
    if type(value) is not str or not re.fullmatch(r'[a-z0-9._:/-]+@sha256:[a-f0-9]{64}',value):raise ValueError('Invalid pinned image reference')
    repository,digest=value.split('@');parts=repository.split('/')
    if any(not part or part in ('.','..') for part in parts):raise ValueError('Invalid pinned image repository')
    if len(parts)>1 and ('.' in parts[0] or ':' in parts[0] or parts[0]=='localhost'):
        registry,parts=parts[0],parts[1:]
    else:registry='docker.io'
    if any(':' in part for part in parts):raise ValueError('Tagged pinned aliases are unsupported')
    if registry=='docker.io' and len(parts)==1:parts=['library',*parts]
    return registry+'/'+('/'.join(parts))+'@'+digest

def pinned_reference_present(wanted,references):
    if type(references) is not list:return False
    expected=canonical_digest_reference(wanted)
    return any(canonical_digest_reference(value)==expected for value in references)

def identity_commands(render,evidence_module=None):
    require=render.require
    class IdentityCommands(render.NativeCommands):
        def __init__(self,io,operation,image,network_id,keycloak_id,keycloak_image_id,*,provision_evidence=None):
            require(re.fullmatch('[a-f0-9]{32}',operation) and re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',image))
            require(all(re.fullmatch('[a-f0-9]{64}',v) for v in (network_id,keycloak_id)))
            require(re.fullmatch('sha256:[a-f0-9]{64}',keycloak_image_id))
            self.io=io;self.operation=operation;self.image=image;self.network_id=network_id
            self.keycloak_id=keycloak_id;self.keycloak_image_id=keycloak_image_id
            self.tools={};self.failed=False;self.container=None;self.used=set();self.phase=None
            self.prior=provision_evidence;self.prior_observation=None
            if self.prior is not None:
                require(evidence_module is not None and type(self.prior) is evidence_module.ProvisionEvidence)
                self.prior_observation=self.prior.observation()
                self._prior()

        def _prior(self):
            if self.prior is None:return
            observation=self.prior.observation();require(observation==self.prior_observation)
            expected=observation['expected']
            require(expected['operationId']!=self.operation and expected['image']==self.image
                and expected['networkId']==self.network_id and expected['keycloakId']==self.keycloak_id
                and expected['sourceSha256']==self.io.copy_hashes['provision.mjs']
                and expected['caSha256']==self.io.copy_hashes['ca.crt'])
            if hasattr(self,'image_id'):require(expected['imageId']==self.image_id)

        def _check(self):
            self._prior();super()._check();self._prior()

        def _docker(self,args,*,stdin=b'',timeout=30):
            result=self._execute('docker',['--host','unix:///run/docker.sock',*args],stdin=stdin,timeout=timeout)
            require(result.returncode==0,'Identity Docker outcome is unconfirmed; preserve evidence and do not retry')
            return result.stdout

        def _infrastructure(self):
            rows=json.loads(self._docker(['network','inspect',self.network_id]));require(type(rows) is list and len(rows)==1)
            network=rows[0]
            require(network['Id']==self.network_id and network['Name']=='autosoft_identity' and network['Driver']=='bridge' and network['Internal'] is True)
            require(set(network.get('Containers') or {}) <= {self.keycloak_id,self.container}
                and self.keycloak_id in network['Containers'])
            rows=json.loads(self._docker(['container','inspect',self.keycloak_id]));require(type(rows) is list and len(rows)==1)
            keycloak=rows[0];require(keycloak['Id']==self.keycloak_id and keycloak['Image']==self.keycloak_image_id)
            # Compose currently declares no Docker HEALTHCHECK. The helper probes
            # actual HTTPS :9000/health/ready before any provisioning mutation.
            require(keycloak['State']['Running'] is True)
            require(keycloak['HostConfig']['Privileged'] is False and not keycloak['HostConfig'].get('PortBindings'))
            require(keycloak['Config']['Labels'].get('com.docker.compose.service')=='keycloak'
                and keycloak['Config']['Labels'].get('com.docker.compose.project')=='autosoft')
            endpoint=keycloak['NetworkSettings']['Networks']['autosoft_identity']
            require(endpoint['NetworkID']==self.network_id and 'keycloak' in endpoint['Aliases'])

        def preflight(self):
            require(not self.tools);self._tool('docker')
            sock=os.stat('/run/docker.sock',follow_symlinks=False)
            require(stat.S_ISSOCK(sock.st_mode) and sock.st_uid==0 and stat.S_IMODE(sock.st_mode)==0o660)
            self.socket=render.ident(sock)
            rows=json.loads(self._docker(['image','inspect',self.image]));require(type(rows) is list and len(rows)==1)
            image=rows[0];require(image['Os']=='linux' and image['Architecture']=='amd64' and pinned_reference_present(self.image,image['RepoDigests']))
            require(re.fullmatch('sha256:[a-f0-9]{64}',image['Id']) and not image['Config'].get('Volumes'))
            self.image_id=image['Id'];self.io.labels(os.path.exists('/sys/fs/selinux/enforce'))
            self._infrastructure();self._check()

        def _container(self,identifier,*,exited=False):
            rows=json.loads(self._docker(['container','inspect',identifier]));require(type(rows) is list and len(rows)==1)
            v=rows[0];c,h,s=v['Config'],v['HostConfig'],v['State']
            require(v['Id']==identifier and v['Name']=='/'+self.name and v['Image']==self.image_id)
            require(c['Image']==self.image and c['User']=='10001:10001' and c['Entrypoint']==['node'] and c['Cmd']==['/opt/doxentriq/provision.mjs'])
            require(c['Labels'].get('com.doxentriq.identity')==self.name and c['OpenStdin'] is True and c['Tty'] is False)
            require(h['NetworkMode']==self.network_id and not h['Privileged'] and h['ReadonlyRootfs']
                and h['Memory']==134217728 and h['PidsLimit']==64 and h['NanoCpus']==1000000000)
            require(set(h['CapDrop'])=={'ALL'} and not h.get('CapAdd') and h['SecurityOpt']==['no-new-privileges'])
            require(not h.get('PortBindings') and not h.get('Tmpfs') and h['LogConfig']['Type']=='none' and h['RestartPolicy']['Name']=='no')
            binds=[self.io.root+'/provision.mjs:/opt/doxentriq/provision.mjs:ro',self.io.root+'/ca.crt:/etc/doxentriq/ca.crt:ro']
            require(h['Binds']==binds and len(v['Mounts'])==2)
            for row,name,target in zip(v['Mounts'],('provision.mjs','ca.crt'),('/opt/doxentriq/provision.mjs','/etc/doxentriq/ca.crt')):
                # Docker inspect does not promise mount-array order.
                matches=[m for m in v['Mounts'] if m['Destination']==target]
                require(len(matches)==1 and matches[0]['Type']=='bind' and matches[0]['Source']==self.io.root+'/'+name and matches[0]['RW'] is False)
            env=c['Env'];require(type(env) is list and 'NODE_EXTRA_CA_CERTS=/etc/doxentriq/ca.crt' in env)
            require(not any(v.startswith(('NODE_OPTIONS=','NODE_TLS_REJECT_UNAUTHORIZED=','HTTP_PROXY=','HTTPS_PROXY=','ALL_PROXY=')) and v.split('=',1)[1] for v in env))
            require(s['Pid']==0 and not s.get('Error') and not s.get('OOMKilled'))
            if exited:require(s['Status']=='exited' and s['ExitCode']==0)
            else:require(s['Status']=='created')

        def run_phase(self,phase,payload):
            try:return self._run_phase(phase,payload)
            except BaseException:
                self.failed=True
                raise

        def _run_phase(self,phase,payload):
            require(phase in ('provision','verify') and phase not in self.used and self.container is None)
            if self.prior is not None:
                require(phase=='verify' and not self.used)
            else:
                require(phase=='provision' and not self.used or phase=='verify' and self.used=={'provision'})
            require(type(payload) is bytes and len(payload)<=65536)
            supplied=json.loads(payload);require(type(supplied) is dict)
            require(supplied.get('action')==('verify-initial' if phase=='verify' else None))
            self._check();self._infrastructure();self.used.add(phase);self.phase=phase
            self.name='doxentriq-identity-'+self.operation+'-'+phase
            self.io.record(phase,'intent',dict(image=self.image,imageId=self.image_id,networkId=self.network_id,
                keycloakId=self.keycloak_id,sourceSha256=self.io.copy_hashes['provision.mjs'],caSha256=self.io.copy_hashes['ca.crt']))
            args=['container','create','--pull=never','--name',self.name,'--label','com.doxentriq.identity='+self.name,
                '--log-driver=none','--restart=no','--network',self.network_id,'--read-only','--user=10001:10001',
                '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--cpus=1','--pids-limit=64',
                '--entrypoint=node','--env','NODE_EXTRA_CA_CERTS=/etc/doxentriq/ca.crt','--env','NODE_OPTIONS=',
                '--env','NODE_TLS_REJECT_UNAUTHORIZED=','--env','HTTP_PROXY=','--env','HTTPS_PROXY=','--env','ALL_PROXY=',
                '--volume',self.io.root+'/provision.mjs:/opt/doxentriq/provision.mjs:ro',
                '--volume',self.io.root+'/ca.crt:/etc/doxentriq/ca.crt:ro','--interactive',self.image,'/opt/doxentriq/provision.mjs']
            raw=self._docker(args);identifier=raw.decode().strip();require(re.fullmatch('[a-f0-9]{64}',identifier))
            self.container=identifier;self.io.record(phase,'created',dict(containerId=identifier));self._container(identifier)
            self._infrastructure();self.io.record(phase,'start-intent',dict(containerId=identifier))
            out=self._docker(['container','start','--attach','--interactive',identifier],stdin=payload,timeout=150)
            self._container(identifier,exited=True);self._infrastructure()
            if phase=='provision':require(out==b'Scoped app realm provisioner configured.\n')
            else:
                result=json.loads(out)
                require(result==dict(scope='INITIAL_IDENTITY_POLICY_READBACK',ownerSubject=supplied['ownerSubject'],
                    configuredPolicyVerified=True,browserMfaQualified=False,publicStartupAllowed=False))
            self.io.record(phase,'completed',dict(containerId=identifier,outputSha256=__import__('hashlib').sha256(out).hexdigest()))
            require(self._docker(['container','rm',identifier]).decode().strip()==identifier)
            require(self._docker(['container','ls','--all','--no-trunc','--quiet','--filter','id='+identifier])==b'')
            self.container=None;self.io.record(phase,'removed',dict(containerId=identifier));self._check()
            return dict(phase=phase,containerId=identifier,configuredPolicyVerified=phase=='verify',publicStartupAllowed=False)
    return IdentityCommands
