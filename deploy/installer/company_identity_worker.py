"""Same-parent identity successor after independently confirmed infrastructure.

Original source/storage/parent and pinned host tools remain live. Provisioning
and a separate policy readback use the reviewed isolated components. No public
startup, retry, overwrite, credential logging or browser-MFA claim is exposed.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse

STAGE='company-initial-identity'
COMMANDS=('identity-action','provision-initial-identity','verify-initial-identity')
BOOTSTRAP='scripts/bootstrap.py'
STARTUP='scripts/startup_binding.py'
PROVISION='scripts/keycloak-provision.mjs'


def action(Q,request_raw,worker_sha256):
    Q.require(type(worker_sha256) is str and re.fullmatch('[a-f0-9]{64}',worker_sha256) is not None)
    return Q.sha(b'company-initial-identity-v1:'+Q.sha(request_raw).encode()+b':'+worker_sha256.encode())


def operation_ids(Q,request):
    value=request['operationId'];Q.require(type(value) is str and re.fullmatch('[a-f0-9]{32}',value) is not None)
    return tuple(Q.sha((prefix+value).encode())[:32] for prefix in ('identity-provision:','identity-verify:'))


def bound_commands(modules,binding):
    """Use the reviewed stdin-capable transport, with the approved Docker pin."""
    D,M,E,P=(modules[name] for name in ('render_commands','identity_commands','identity_evidence','infrastructure_policy'))
    pins=P.tool_pins(binding);pin=pins['docker']
    D.require(pin['path']==D.TOOLS['docker'])
    Original=M.identity_commands(D,E)
    class Commands(Original):
        def _tool(self,name):
            D.require(name=='docker');super()._tool(name)
            fd,before=self.tools[name]
            D.require(before[6]==pin['bytes'] and 0<before[6]<=256*1024**2)
            hashed=hashlib.sha256();offset=0
            while offset<before[6]:
                raw=os.pread(fd,min(1024**2,before[6]-offset),offset);D.require(raw)
                hashed.update(raw);offset+=len(raw)
            D.require(hashed.hexdigest()==pin['sha256'] and D.ident(os.fstat(fd))==before)
    return Commands


def infrastructure_record(modules,parent,request,request_raw,worker_sha256,render_raw):
    Q,S,I,RW=(modules[n] for n in ('configuration','station','infrastructure_worker','render_worker'))
    directory='/opt/autosoft-company/evidence/'+request['operationId']+'/'+I.STAGE
    raw=S.read_protected(directory+'/executed.json',32768);record=I.decode(Q,raw)
    expected=I.outcome(Q,request,request_raw,worker_sha256,parent.arguments.session,render_raw,record['component'],record['hostContainment'])
    Q.require(record==expected)
    values={directory+'/intent.json':I.intended_record(Q,request_raw,worker_sha256,parent.arguments.session),
        directory+'/executed.json':raw,directory+'/verified.json':raw}
    Q.require(all(S.read_protected(path,32768)==value for path,value in values.items()))
    return directory,record,raw,values


def payloads(Q,held_inputs,cfg):
    # Read only the exact infrastructure-bound render files, never a host path
    # supplied by chat. Credentials remain in memory and go only to helper stdin.
    owner=cfg['owner_subject']
    Q.require(type(owner) is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',owner) is not None)
    admin=cfg['admin_origin'];sso=cfg['sso']
    Q.require(type(admin) is str and 0<len(admin)<=2048 and type(sso) is str and sso in ('none','google','microsoft','both'))
    parsed=urllib.parse.urlsplit(admin)
    Q.require(parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password
        and not parsed.path and not parsed.query and not parsed.fragment and admin=='https://'+parsed.netloc)
    aliases=[name for name in ('google','microsoft') if sso in (name,'both')]
    values={}
    for key,path in (('bootstrapPassword','secrets/keycloak/bootstrap-password'),
        ('provisionerSecret','secrets/runtime/keycloak-client'),
        ('directoryReaderSecret','secrets/runtime/keycloak-directory-reader')):
        raw=held_inputs.read(path)
        Q.require(type(raw) is bytes and re.fullmatch(rb'[A-Za-z0-9_-]{32,128}',raw) is not None)
        values[key]=raw.decode('ascii')
    provision=Q.canonical(values)
    verification=Q.canonical(dict(values,action='verify-initial',ownerSubject=owner,adminOrigin=admin,ssoAliases=aliases))
    return provision,verification


def provision_component(modules,*,data,request,source,ca,image,component,binding,authority,payload,workspace_context):
    Q,I,E=(modules[n] for n in ('configuration','identity_io','identity_evidence'))
    operation,_=operation_ids(Q,request);Commands=bound_commands(modules,binding)
    authority()
    with ExitStack() as stack:
        io=I.IdentityIO(data,operation,source,ca,check_authority=authority);stack.callback(io.close)
        stack.enter_context(workspace_context())
        commands=Commands(io,operation,image,component['networkIds']['identity'],component['containerIds']['keycloak'],component['imageIds']['keycloak'])
        stack.callback(commands.close);commands.preflight()
        result=commands.run_phase('provision',payload)
        Q.require(result['phase']=='provision' and result['configuredPolicyVerified'] is False
            and result['publicStartupAllowed'] is False and commands.container is None)
        expected=dict(operationId=operation,sourceSha256=Q.sha(source),caSha256=Q.sha(ca),image=image,
            imageId=commands.image_id,networkId=component['networkIds']['identity'],keycloakId=component['containerIds']['keycloak'])
        authority();io.check()
    with E.ProvisionEvidence(data,expected,check_authority=authority) as held:
        observation=held.observation()
    authority();return dict(expected=expected,recordsSha256=Q.sha(Q.canonical(observation)))


def validate_provision(Q,value,*,request,source,ca,image,component):
    Q.require(type(value) is dict and set(value)=={'expected','recordsSha256'}
        and type(value['expected']) is dict and type(value['recordsSha256']) is str
        and re.fullmatch('[a-f0-9]{64}',value['recordsSha256']) is not None)
    expected=value['expected'];image_id=expected.get('imageId')
    Q.require(type(image_id) is str and re.fullmatch('sha256:[a-f0-9]{64}',image_id) is not None)
    Q.require(expected==dict(operationId=operation_ids(Q,request)[0],sourceSha256=Q.sha(source),caSha256=Q.sha(ca),
        image=image,imageId=image_id,networkId=component['networkIds']['identity'],keycloakId=component['containerIds']['keycloak']))
    return expected


def verify_component(modules,*,data,request,source,ca,image,component,binding,authority,payload,provision,workspace_context):
    Q,E,I,S=(modules[n] for n in ('configuration','identity_evidence','identity_io','identity_split'))
    expected=validate_provision(Q,provision,request=request,source=source,ca=ca,image=image,component=component)
    with E.ProvisionEvidence(data,expected,check_authority=authority) as held:
        Q.require(Q.sha(Q.canonical(held.observation()))==provision['recordsSha256'])
    result=S.verify_provisioned(data,expected,operation_ids(Q,request)[1],source,ca,payload,
        check_authority=authority,io_module=I,evidence_module=E,commands_class=bound_commands(modules,binding),
        keycloak_image_id=component['imageIds']['keycloak'],workspace_context=workspace_context)
    Q.require(result['provisionRecordsSha256']==provision['recordsSha256']
        and result['configuredPolicyVerified'] is True and result['publicStartupAllowed'] is False)
    return result


def execution_record(Q,request,request_raw,worker_sha256,session,infrastructure_raw,provision):
    return dict(scope='NATIVE_INITIAL_IDENTITY_PROVISION_ONLY',requestSha256=Q.sha(request_raw),
        actionSha256=action(Q,request_raw,worker_sha256),session=session,workerSha256=worker_sha256,
        releaseSha256=request['releaseSha256'],infrastructureOutcomeSha256=Q.sha(infrastructure_raw),
        provision=provision,configuredPolicyVerified=False,browserMfaQualified=False,publicStartupAllowed=False,backupReady=False)


def run(command,modules,delivery,auth,request,request_raw,worker_sha256,parent_args,*,host_tool_binding):
    Q,S,C,W,R,I,RW=(modules[n] for n in ('configuration','station','cli','configuration_worker','records','infrastructure_worker','render_worker'))
    Q.require(command in COMMANDS)
    expected_action=action(Q,request_raw,worker_sha256)
    if command=='identity-action':Q.require(parent_args is None);print(expected_action);return
    Q.require(parent_args is not None);execute=command=='provision-initial-identity'
    data=request['dataDir'];root=data+'/company/host-releases/install-'+request['operationId']
    operation='/opt/autosoft-company/evidence/'+request['operationId'];directory=operation+'/'+STAGE
    collaborators=None;result=None
    with C.authenticated_cli(delivery,**auth) as controller:
        F,V,P,entry=(controller.original_modules[n] for n in ('full_entry','verifier','parent','entry'))
        collaborators=S.stage_inputs(controller,request_raw,modules['crypto'])
        with ExitStack() as outer:
            observed,check_platform=outer.enter_context(I.held_platform(Q,S));binding=host_tool_binding(modules,observed)
            arguments=P.ParentInput.from_argv(parent_args)
            Q.require(arguments.stage==STAGE and arguments.request==Q.sha(request_raw) and arguments.action==expected_action)
            parent=outer.enter_context(P.hold_parent(arguments,system=collaborators['parent_system']))
            previous=modules['infrastructure_predecessor'].reconstruct(modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent)
            manifest,render_raw,records=I.render_predecessor(modules,parent,request,request_raw,worker_sha256,previous)
            RW.confirmed(P,parent,RW.STAGE,RW.action(Q,request_raw,worker_sha256),Q.sha(render_raw))
            infra_directory,infrastructure,infra_raw,infra_records=infrastructure_record(modules,parent,request,request_raw,worker_sha256,render_raw)
            RW.confirmed(P,parent,I.STAGE,I.action(Q,request_raw,worker_sha256),Q.sha(infra_raw));records.update(infra_records)
            with V.authenticated_platform_source(request['bundleRoot'],request['keyPath'],auth['fingerprint'],expected_architecture='x86_64',
                    source_root=request['sourceRoot'],files=collaborators['files'],crypto=collaborators['crypto'],owner_uid=0,owner_gid=0) as held:
                Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
                with entry.fresh_installation_modules(held) as assembly:
                    B,startup=(assembly.modules[n] for n in (BOOTSTRAP,STARTUP))
                    commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner']);I.quiet_units(Q,commands.text)
                    inputs=modules['startup_worker'].inputs_for(modules,assembly,commands)
                    initial=assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)
                    cfg=I.configuration(B,Q,S.read_protected(Path(data)/'config/installation.json',32768))
                    Q.require(cfg['company_public_fingerprint']==held.metadata['signingKeyFingerprint'])
                    for name in ('approved-mirrors.json','images.lock.json','runtime-manifest.json'):
                        Q.require(S.read_protected(Path(data)/'config'/name,1024**2)==held.configs[name])
                    all_images=json.loads(held.configs['images.lock.json']);policy=modules['infrastructure_policy']
                    image=all_images['platform'];source=held.files[PROVISION]
                    Q.require(type(source) is bytes and 0<len(source)<=131072);policy.reference(image)
                    with ExitStack() as active:
                        proof,check_invariants=active.enter_context(RW.invariant_records(startup,inputs,data,root))
                        def authority():
                            parent.check();V.require_platform_source(held);F.FullEntry.recheck(entry);check_invariants();check_platform()
                        args=dict(data=data,source=request['sourceRoot'],cfg=cfg,images={s:all_images[s] for s in policy.SERVICES},
                            compose_source=held.files['deploy/compose.yaml'],manifest=manifest,binding=binding,authority=authority,
                            records_path=infra_directory+'/effects',component=infrastructure['component'])
                        @contextmanager
                        def observed_host():
                            # Workspace creation changes data/company metadata.
                            # Close the first exact reader before that declared
                            # mutation, reopen afterward and compare observations;
                            # never refresh an already-held ancestor identity.
                            with modules['infrastructure_host'].HostContainment(S,data=data,root=root,
                                    mount_source=proof['mountSource'],guard_raw=held.files['scripts/storage-guard.sh'],check_authority=authority) as host:
                                I.observe_component(modules,**args,host=host);Q.require(host.result==infrastructure['hostContainment'])
                                yield
                                I.observe_component(modules,**args,host=host);Q.require(host.result==infrastructure['hostContainment'])
                        with observed_host():pass
                        intended=Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=expected_action,session=arguments.session,workerSha256=worker_sha256))
                        if execute:
                            with R.directory(operation) as (fd,check):os.mkdir(STAGE,0o700,dir_fd=fd);os.fsync(fd);check()
                            W.write(R,directory,'intent.json',intended)
                        else:
                            Q.require(S.read_protected(directory+'/intent.json',4096)==intended)
                            executed_raw=S.read_protected(directory+'/executed.json',32768);executed=I.decode(Q,executed_raw)
                            Q.require(executed==execution_record(Q,request,request_raw,worker_sha256,arguments.session,infra_raw,executed['provision']))
                            records[directory+'/executed.json']=executed_raw
                        records[directory+'/intent.json']=intended
                        with I.held_records(Q,S,records) as check_records:
                            def bound_authority():authority();check_records()
                            E=modules['infrastructure_evidence'].infrastructure_evidence(modules['infrastructure_io'],policy)
                            component=infrastructure['component'];component_raw=policy.canonical(component)
                            with E(data,infra_directory+'/effects',manifest,component_raw,policy.digest(component),tool_binding=binding,check_authority=bound_authority) as retained:
                                provision_payload,verification_payload=payloads(Q,retained,cfg);ca=retained.read('tls/ca.crt')
                                def identity_authority():bound_authority();retained.check()
                                common=dict(data=data,request=request,source=source,ca=ca,image=image,component=component,binding=binding,
                                    authority=identity_authority,workspace_context=observed_host)
                                if execute:
                                    provision=provision_component(modules,**common,payload=provision_payload)
                                    result=execution_record(Q,request,request_raw,worker_sha256,arguments.session,infra_raw,provision)
                                else:
                                    observation=verify_component(modules,**common,payload=verification_payload,provision=executed['provision'])
                                    result=dict(scope='NATIVE_INITIAL_IDENTITY_POLICY_VERIFIED',executionSha256=Q.sha(executed_raw),
                                        infrastructureOutcomeSha256=Q.sha(infra_raw),verification=observation,configuredPolicyVerified=True,
                                        browserMfaQualified=False,publicStartupAllowed=False,backupReady=False)
                                identity_authority()
                    Q.require(assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)==initial)
                    I.quiet_units(Q,commands.text);V.require_platform_source(held)
            Q.require(modules['infrastructure_predecessor'].reconstruct(modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent)==previous)
            Q.require(infrastructure_record(modules,parent,request,request_raw,worker_sha256,render_raw)[2]==infra_raw);parent.check()
        S.require_released(collaborators)
    S.require_released(collaborators);raw=Q.canonical(result)
    if execute:
        W.write(R,directory,'executed.json',raw);print('Initial identity provisioning recorded; independent policy verification is required.')
    else:
        W.write(R,directory,'verified.json',raw)
        marker=('initial-identity-verified-v1\nrequest='+Q.sha(request_raw)+'\nsession='+parent_args[3]+'\nstage='+STAGE
            +'\naction='+expected_action+'\noutcome='+Q.sha(raw)+'\n').encode()
        W.write(R,directory,'confirmation',marker,mode=0o600)
        print('Initial identity policy independently verified. Public startup and browser MFA acceptance remain pending.')
