"""Five private services after the genuine same-session Render confirmation.

This trusted worker uses original source/storage/parent capabilities. Serialized
records bind observations; none grants authority. No retry, adoption, identity
provisioning or public startup is exposed by this stage.
"""
from contextlib import ExitStack,contextmanager
import json
import os
from pathlib import Path
import platform
import re
import stat

STAGE='company-private-infrastructure'
BOOTSTRAP='scripts/bootstrap.py'
STARTUP='scripts/startup_binding.py'
COMMANDS=('infrastructure-action','infrastructure-ready',
          'initialize-private-infrastructure','verify-private-infrastructure')


def action(Q,request_raw,worker_sha256):
    Q.require(type(worker_sha256) is str and re.fullmatch('[a-f0-9]{64}',worker_sha256) is not None)
    return Q.sha(b'company-private-infrastructure-v1:'+Q.sha(request_raw).encode()+b':'+worker_sha256.encode())


def decode(Q,raw):
    value=json.loads(raw)
    Q.require(type(value) is dict and Q.canonical(value)==raw)
    return value


def configuration(B,Q,raw):
    # Original wizard files are indented JSON, unlike stage evidence. Reuse
    # its duplicate-rejecting bounded decoder without inventing canonical form.
    value=B._seed_decode(raw);Q.require(type(value) is dict)
    return value


def quiet_units(Q,command,*,quota_check=None):
    """Original complete public-writer policy, without the old empty engine.

    The separate component must verify exactly the five authorized live IDs.
    This function neither stops units nor substitutes a fabricated Docker result.
    """
    fields=('ActiveState','SubState','MainPID','ControlPID','ControlGroup','LoadState')
    for unit in Q.UNITS:
        if unit=='autosoft-quota.service' and quota_check is not None:
            # Only the dedicated successor supplies a live exact process/unit
            # verifier. No boolean, serialized evidence or other unit exception.
            Q.require(callable(quota_check));quota_check();continue
        selected=('ActiveState','SubState','LoadState') if unit.endswith('.timer') else fields
        raw=command(['/usr/bin/systemctl','show',*['--property='+name for name in selected],'--',unit])
        Q.require(type(raw) is str and len(raw)<=65536)
        pairs=[line.split('=',1) for line in raw.splitlines()]
        Q.require(len(pairs)==len(selected) and all(len(row)==2 for row in pairs) and len({row[0] for row in pairs})==len(selected))
        state=dict(pairs)
        Q.require(set(state)==set(selected) and state['ActiveState'] in ('inactive','failed')
            and state['SubState'] in ('dead','failed') and state['LoadState'] in ('loaded','not-found'))
        if unit.endswith('.service'):Q.require(state['MainPID']==state['ControlPID']=='0' and state['ControlGroup']=='')


def active_storage_check(Q,storage,commands,*,quota_check=None):
    """Preserve all original fresh controls except the now-authorized engine."""
    Q.require(storage.fresh is False and not os.path.lexists(storage.host+'/installation.complete'))
    for name in storage.startup.L.BROKER_DIRECTORIES:
        if name not in ('repository','builds'):
            Q.require(storage.files.names(storage.data+'/runtime/'+name,0)==[])
    quiet_units(Q,commands.text,quota_check=quota_check)
    storage.check()


def platform_value(Q,raw):
    """Parse only bounded inert os-release assignments, never source a shell."""
    Q.require(type(raw) is bytes and 0<len(raw)<=16384 and b'\0' not in raw)
    text=raw.decode('utf-8');selected={}
    for line in text.splitlines():
        if not line or line.startswith('#'):continue
        Q.require('=' in line)
        name,value=line.split('=',1)
        Q.require(re.fullmatch('[A-Z_][A-Z0-9_]*',name) is not None)
        if name not in ('ID','VERSION_ID'):continue
        Q.require(name not in selected)
        if len(value)>=2 and value[0]==value[-1] and value[0] in ('"',"'"):value=value[1:-1]
        Q.require(re.fullmatch('[a-z0-9.]+',value) is not None)
        selected[name]=value
    Q.require(set(selected)=={'ID','VERSION_ID'} and selected['ID'] in ('debian','rocky')
              and re.fullmatch(r'[1-9][0-9]*(?:\.[0-9]+)?',selected['VERSION_ID']) is not None)
    return dict(osId=selected['ID'],versionId=selected['VERSION_ID'],architecture='x86_64')


@contextmanager
def held_platform(Q,S):
    """Fixed host-owned vendor identity; no request-selected OS or profile."""
    Q.require(platform.system()=='Linux' and platform.machine()=='x86_64')
    with ExitStack() as stack:
        fd,info,check=stack.enter_context(S.held_file('/usr/lib/os-release',16384))
        raw=os.pread(fd,16385,0);Q.require(len(raw)==info['st_size'])
        # /etc/os-release may be the conventional vendor link or an identical
        # protected regular file. Arbitrary symlink targets/overrides refuse.
        etc=os.open('/etc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        stack.callback(os.close,etc)
        before=S.metadata(os.fstat(etc));Q.require(before['st_uid']==before['st_gid']==0 and not before['st_mode']&0o022)
        leaf=os.stat('os-release',dir_fd=etc,follow_symlinks=False);link_before=S.metadata(leaf)
        if stat.S_ISLNK(leaf.st_mode):
            Q.require(leaf.st_uid==leaf.st_gid==0 and leaf.st_nlink==1)
            target=os.readlink('os-release',dir_fd=etc)
            Q.require(target in ('../usr/lib/os-release','/usr/lib/os-release'))
            other=None
        else:
            efd,einfo,other=stack.enter_context(S.held_file('/etc/os-release',16384))
            Q.require(os.pread(efd,16385,0)==raw and einfo['st_size']==len(raw))
            target=None
        value=platform_value(Q,raw)
        def recheck():
            check()
            Q.require(S.metadata(os.fstat(etc))==before==S.metadata(os.stat('/etc',follow_symlinks=False)))
            Q.require(S.metadata(os.stat('os-release',dir_fd=etc,follow_symlinks=False))==link_before)
            if target is not None:Q.require(os.readlink('os-release',dir_fd=etc)==target)
            if other:other()
        recheck();yield value,recheck;recheck()


def render_predecessor(modules,parent,request,request_raw,worker_sha256,previous):
    Q,S,RW=(modules[n] for n in ('configuration','station','render_worker'))
    directory='/opt/autosoft-company/evidence/'+request['operationId']+'/'+RW.STAGE
    manifest_raw=S.read_protected(directory+'/outputs.json',131072)
    manifest=decode(Q,manifest_raw)
    expected_action=RW.action(Q,request_raw,worker_sha256)
    intended=Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=expected_action,
        session=parent.arguments.session,workerSha256=worker_sha256))
    raw=Q.canonical(dict(scope='NATIVE_RENDER_STAGE_ONLY',requestSha256=Q.sha(request_raw),actionSha256=expected_action,
        session=parent.arguments.session,workerSha256=worker_sha256,releaseSha256=request['releaseSha256'],
        predecessorSha256=Q.sha(Q.canonical(previous)),outputsSha256=Q.sha(manifest_raw),outputFiles=len(manifest['files']),
        servicesActivated=False,identityProvisioned=False,backupReady=False))
    values={'intent.json':intended,'outputs.json':manifest_raw,'executed.json':raw,'verified.json':raw}
    Q.require(all(S.read_protected(directory+'/'+name,131072)==value for name,value in values.items()))
    return manifest,raw,{directory+'/'+name:value for name,value in values.items()}


@contextmanager
def held_records(Q,S,values):
    """Hold exact predecessor records after the declared new stage creation."""
    with ExitStack() as stack:
        rows=[]
        for name,raw in sorted(values.items()):
            fd,info,check=stack.enter_context(S.held_file(name,131072))
            Q.require(info['st_size']==len(raw) and os.pread(fd,len(raw)+1,0)==raw)
            rows.append(check)
        def check():
            for recheck in rows:recheck()
        check();yield check;check()


def intended_record(Q,request_raw,worker_sha256,session):
    return Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=action(Q,request_raw,worker_sha256),
        session=session,workerSha256=worker_sha256))


def outcome(Q,request,request_raw,worker_sha256,session,render_raw,component,host_observation):
    return dict(scope='NATIVE_PRIVATE_INFRASTRUCTURE_STAGE_ONLY',requestSha256=Q.sha(request_raw),
        actionSha256=action(Q,request_raw,worker_sha256),session=session,workerSha256=worker_sha256,
        releaseSha256=request['releaseSha256'],renderOutcomeSha256=Q.sha(render_raw),
        component=component,hostContainment=host_observation,privateInfrastructureReady=True,identityProvisioned=False,
        publicStartupAllowed=False,backupReady=False,wholeInstallationQualified=False)


def execute_component(modules,*,data,source,cfg,images,compose_source,manifest,binding,authority,records_path,host):
    """Fixed native component wiring. Every owned scope closes before return."""
    P,I,T,H,C=(modules[n] for n in ('infrastructure_policy','infrastructure_io','infrastructure_transport',
                                 'infrastructure_probe','infrastructure_commands'))
    R=modules['records'];authority()
    with ExitStack() as stack:
        io=I.InfrastructureIO(data,manifest,P.BINDS,P.MUTABLE,check_authority=authority,
            record_directory=lambda:R.directory(records_path))
        stack.callback(io.close)
        transport=T.NativeTransport(io,P.tool_pins(binding));stack.callback(transport.close)
        commands=C.infrastructure_commands(P)(io,transport,H.Readiness(io,transport),data=data,source=source,
            cfg=cfg,images=images,compose_source=compose_source,tool_binding=binding)
        stack.callback(commands.close)
        commands.preflight();host.verify(transport)
        commands.create();result=commands.start();host.verify(transport);authority();io.check()
    authority();return result


def observe_component(modules,*,data,source,cfg,images,compose_source,manifest,binding,authority,records_path,component,host):
    P,I,T,H,E,V=(modules[n] for n in ('infrastructure_policy','infrastructure_io','infrastructure_transport',
                                   'infrastructure_probe','infrastructure_evidence','infrastructure_verify'))
    raw=P.canonical(component)
    Original=V.infrastructure_verifier(P)
    class Observed:
        def __init__(self,evidence,transport,probe,**kwargs):
            self.transport=transport;self.original=Original(evidence,transport,probe,**kwargs)
        def verify(self):
            value=self.original.verify();host.verify(self.transport);return value
    result=V.verify_recorded_infrastructure(data=data,records_path=records_path,render_manifest=manifest,
        executed_raw=raw,executed_sha256=P.digest(component),source=source,cfg=cfg,images=images,
        compose_source=compose_source,tool_binding=binding,check_authority=authority,
        evidence_class=E.infrastructure_evidence(I,P),verifier_class=Observed,
        transport_factory=lambda held:T.NativeTransport(held,P.tool_pins(binding)),
        probe_factory=lambda held,transport:H.Readiness(held,transport))
    P.require(result['executedOutcomeSha256']==P.digest(component)
        and result['immutableInputsSha256']==component['immutableInputsSha256']
        and result['toolContext']==P.tool_context(binding) and result['privateInfrastructureObserved'] is True)
    return result


def run(command,modules,delivery,auth,request,request_raw,worker_sha256,parent_args,*,host_tool_binding):
    Q,S,C,W,R,RW=(modules[n] for n in ('configuration','station','cli','configuration_worker','records','render_worker'))
    Q.require(command in COMMANDS and callable(host_tool_binding))
    expected_action=action(Q,request_raw,worker_sha256)
    if command=='infrastructure-action':Q.require(parent_args is None);print(expected_action);return
    modules['infrastructure_host'].require_decoder()
    planning=command=='infrastructure-ready';execute=command=='initialize-private-infrastructure'
    Q.require((parent_args is None) is planning)
    data=request['dataDir'];root=data+'/company/host-releases/install-'+request['operationId']
    operation='/opt/autosoft-company/evidence/'+request['operationId'];directory=operation+'/'+STAGE
    records_path=directory+'/effects';collaborators=None;result=None
    with C.authenticated_cli(delivery,**auth) as controller:
        F,V,P,entry=(controller.original_modules[n] for n in ('full_entry','verifier','parent','entry'))
        collaborators=S.stage_inputs(controller,request_raw,modules['crypto'])
        with ExitStack() as outer:
            observed,check_platform=outer.enter_context(held_platform(Q,S))
            binding=host_tool_binding(modules,observed)
            parent=None
            if not planning:
                arguments=P.ParentInput.from_argv(parent_args)
                Q.require(arguments.stage==STAGE and arguments.request==Q.sha(request_raw) and arguments.action==expected_action)
                parent=outer.enter_context(P.hold_parent(arguments,system=collaborators['parent_system']))
                previous=(RW.predecessor if execute else modules['infrastructure_predecessor'].reconstruct)(
                    modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent)
                manifest,render_raw,render_records=render_predecessor(modules,parent,request,request_raw,worker_sha256,previous)
                RW.confirmed(P,parent,RW.STAGE,RW.action(Q,request_raw,worker_sha256),Q.sha(render_raw))
            with V.authenticated_platform_source(request['bundleRoot'],request['keyPath'],auth['fingerprint'],
                    expected_architecture='x86_64',source_root=request['sourceRoot'],files=collaborators['files'],
                    crypto=collaborators['crypto'],owner_uid=0,owner_gid=0) as held:
                Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
                with entry.fresh_installation_modules(held) as assembly:
                    B,startup=(assembly.modules[n] for n in (BOOTSTRAP,STARTUP))
                    commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner'])
                    if planning or execute:Q.quiet(commands.text)
                    else:quiet_units(Q,commands.text)
                    inputs=modules['startup_worker'].inputs_for(modules,assembly,commands)
                    initial=assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)
                    cfg=configuration(B,Q,S.read_protected(Path(data)/'config/installation.json',32768))
                    Q.require(cfg['company_public_fingerprint']==held.metadata['signingKeyFingerprint'])
                    for name in ('approved-mirrors.json','images.lock.json','runtime-manifest.json'):
                        Q.require(S.read_protected(Path(data)/'config'/name,1024**2)==held.configs[name])
                    all_images=json.loads(held.configs['images.lock.json'])
                    images={s:all_images[s] for s in modules['infrastructure_policy'].SERVICES}
                    compose_source=held.files['deploy/compose.yaml']
                    Q.require(type(compose_source) is bytes)
                    with ExitStack() as active:
                        proof,check_invariants=active.enter_context(RW.invariant_records(startup,inputs,data,root))
                        def authority():
                            if parent:parent.check()
                            V.require_platform_source(held);F.FullEntry.recheck(entry);check_invariants();check_platform()
                        authority()
                        if not planning:
                            host=active.enter_context(modules['infrastructure_host'].HostContainment(S,data=data,root=root,
                                mount_source=proof['mountSource'],guard_raw=held.files['scripts/storage-guard.sh'],check_authority=authority))
                            intended=intended_record(Q,request_raw,worker_sha256,parent.arguments.session)
                            if execute:
                                # Reopen the ORIGINAL read-only render verifier before
                                # any SELinux/data effects, then close it permanently.
                                io=modules['render_io'].RenderIO(data,request['sourceRoot'],held.files,cfg,
                                    check_authority=authority,process_factory=lambda value:modules['render_commands'].NativeCommands(value,request['operationId']),
                                    readonly=True,expected=manifest)
                                try:
                                    def source_verifier(_data,_cfg):Q.require(_cfg==cfg);authority()
                                    modules['render_verify'].verify(B,io,source_verifier=source_verifier)
                                    Q.require(io.manifest()==manifest)
                                finally:io.close()
                                with R.directory(operation) as (fd,check):os.mkdir(STAGE,0o700,dir_fd=fd);os.fsync(fd);check()
                                W.write(R,directory,'intent.json',intended)
                                with R.directory(directory) as (fd,check):os.mkdir('effects',0o700,dir_fd=fd);os.fsync(fd);check()
                            else:
                                Q.require(S.read_protected(directory+'/intent.json',4096)==intended)
                                executed_raw=S.read_protected(directory+'/executed.json',32768)
                                executed=decode(Q,executed_raw);component=executed['component']
                                Q.require(executed==outcome(Q,request,request_raw,worker_sha256,parent.arguments.session,render_raw,component,executed['hostContainment']))
                            held_values=dict(render_records)
                            held_values[directory+'/intent.json']=intended
                            if not execute:held_values[directory+'/executed.json']=executed_raw
                            with held_records(Q,S,held_values) as check_records:
                                def bound_authority():authority();check_records();host.check()
                                args=dict(data=data,source=request['sourceRoot'],cfg=cfg,images=images,compose_source=compose_source,
                                    manifest=manifest,binding=binding,authority=bound_authority,records_path=records_path,host=host)
                                if execute:component=execute_component(modules,**args)
                                else:observe_component(modules,component=component,**args)
                                bound_authority()
                            result=outcome(Q,request,request_raw,worker_sha256,parent.arguments.session,render_raw,component,host.result)
                            if not execute:Q.require(result==executed)
                    Q.require(assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)==initial)
                    quiet_units(Q,commands.text);V.require_platform_source(held)
            if not planning:
                Q.require(modules['infrastructure_predecessor'].reconstruct(
                    modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent)==previous)
                now_manifest,now_raw,_=render_predecessor(modules,parent,request,request_raw,worker_sha256,previous)
                Q.require(now_manifest==manifest and now_raw==render_raw)
                RW.confirmed(P,parent,RW.STAGE,RW.action(Q,request_raw,worker_sha256),Q.sha(render_raw));parent.check()
        S.require_released(collaborators)
    S.require_released(collaborators)
    if planning:print('private-infrastructure-prerequisites-verified');return
    raw=Q.canonical(result)
    if execute:
        W.write(R,directory,'executed.json',raw)
        print('Private services started; independent read-only verification is required.')
    else:
        Q.require(S.read_protected(directory+'/executed.json',32768)==raw)
        W.write(R,directory,'verified.json',raw)
        marker=('private-infrastructure-verified-v1\nrequest='+Q.sha(request_raw)+'\nsession='+parent_args[3]+'\nstage='+STAGE
            +'\naction='+expected_action+'\noutcome='+Q.sha(raw)+'\n').encode()
        W.write(R,directory,'confirmation',marker,mode=0o600)
