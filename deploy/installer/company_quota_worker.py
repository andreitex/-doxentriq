"""Same-parent private quota support after genuine initial identity confirmation.

Only the quota unit and its Docker dependency are installed and only quota is
started. Public units and timers stay quiet. Interrupted effects are preserved;
this stage grants no full-installation, browser-MFA, backup or resume capability.
"""
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re

STAGE='company-private-quota'
COMMANDS=('quota-action','activate-private-quota','verify-private-quota')
BOOTSTRAP='scripts/bootstrap.py'
STARTUP='scripts/startup_binding.py'


def action(Q,request_raw,worker_sha256):
    Q.require(type(worker_sha256) is str and re.fullmatch('[a-f0-9]{64}',worker_sha256) is not None)
    return Q.sha(b'company-private-quota-v1:'+Q.sha(request_raw).encode()+b':'+worker_sha256.encode())


def outcome(Q,request,request_raw,worker_sha256,session,identity,units,service,before_host,before_units,after_host):
    return dict(scope='NATIVE_PRIVATE_QUOTA_SUPPORT_ONLY',requestSha256=Q.sha(request_raw),
        actionSha256=action(Q,request_raw,worker_sha256),workerSha256=worker_sha256,session=session,
        releaseSha256=request['releaseSha256'],identity=identity,installedUnits=units,service=service,
        priorHost=before_host,priorUnits=before_units,currentHost=after_host,
        quotaServiceReady=True,publicStartupAllowed=False,browserMfaQualified=False,backupReady=False)


@contextmanager
def storage_window(Q,assembly,startup,inputs,data,root):
    """Exact host controls stay held while the child inspects the same locks."""
    initial=assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)
    selected={key:inputs[key] for key in ('host_directory','files','command','mount','layout')}
    # Both journal inspection scopes have closed before yielding. Quota-helper
    # must independently acquire them, inspect initialized state and release.
    with startup.fresh_storage_context(Path(data),Path(root),**selected) as proof:
        yield proof
    # Reacquire the original inspections after that one declared start. The
    # observation must match; no initializer, replay or adoption is invoked.
    Q.require(assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)==initial)


def run(command,modules,delivery,auth,request,request_raw,worker_sha256,parent_args,*,host_tool_binding):
    Q,S,C,W,R,I,RW,Y,H,U,K=(modules[n] for n in ('configuration','station','cli','configuration_worker',
        'records','infrastructure_worker','render_worker','identity_worker','infrastructure_host','quota_units','quota_service'))
    Q.require(command in COMMANDS);expected_action=action(Q,request_raw,worker_sha256)
    if command=='quota-action':Q.require(parent_args is None);print(expected_action);return
    Q.require(parent_args is not None);execute=command=='activate-private-quota'
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
            with V.authenticated_platform_source(request['bundleRoot'],request['keyPath'],auth['fingerprint'],expected_architecture='x86_64',
                    source_root=request['sourceRoot'],files=collaborators['files'],crypto=collaborators['crypto'],owner_uid=0,owner_gid=0) as held:
                Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
                with entry.fresh_installation_modules(held) as assembly:
                    B,startup=(assembly.modules[n] for n in (BOOTSTRAP,STARTUP))
                    commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner'])
                    inputs=modules['startup_worker'].inputs_for(modules,assembly,commands)
                    cfg=I.configuration(B,Q,S.read_protected(Path(data)/'config/installation.json',32768))
                    Q.require(cfg['company_public_fingerprint']==held.metadata['signingKeyFingerprint'])
                    for name in ('approved-mirrors.json','images.lock.json','runtime-manifest.json'):
                        Q.require(S.read_protected(Path(data)/'config'/name,1024**2)==held.configs[name])
                    all_images=json.loads(held.configs['images.lock.json']);policy=modules['infrastructure_policy']
                    # The authenticated manifest, not a recursive filesystem
                    # discovery, supplies every installed operational script.
                    source_manifest=json.loads(held.configs['company-sources.json'])
                    runtime_sources={row['path']:held.files[row['path']] for row in source_manifest['files']}
                    def authority():parent.check();V.require_platform_source(held);F.FullEntry.recheck(entry);check_platform()
                    with ExitStack() as runtime:
                        check_source=runtime.enter_context(K.installed_sources(S,root,runtime_sources))
                        def bound_authority():authority();check_source()
                        ctl=runtime.enter_context(K.systemctl_class(H)(S,bound_authority))
                        live=None
                        if not execute:
                            live=runtime.enter_context(K.QuotaProcess(S,H,ctl,root=root,source_files=runtime_sources,check_authority=bound_authority))
                        quota_check=live.check if live is not None else None
                        I.quiet_units(Q,commands.text,quota_check=quota_check)
                        previous=modules['infrastructure_predecessor'].reconstruct(modules,controller,collaborators,auth,
                            request,request_raw,worker_sha256,parent,quota_check=quota_check)
                        manifest,render_raw,records=I.render_predecessor(modules,parent,request,request_raw,worker_sha256,previous)
                        RW.confirmed(P,parent,RW.STAGE,RW.action(Q,request_raw,worker_sha256),Q.sha(render_raw))
                        infra_directory,infrastructure,infra_raw,infra_records=Y.infrastructure_record(modules,parent,request,request_raw,worker_sha256,render_raw)
                        RW.confirmed(P,parent,I.STAGE,I.action(Q,request_raw,worker_sha256),Q.sha(infra_raw));records.update(infra_records)
                        # Keep exact host/key/storage controls across startup,
                        # without holding the initialized journal locks needed
                        # by quota-helper's own read-only startup inspection.
                        with storage_window(Q,assembly,startup,inputs,data,root) as proof:
                            intended=Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=expected_action,
                                session=arguments.session,workerSha256=worker_sha256))
                            if execute:
                                with R.directory(operation) as (fd,check):os.mkdir(STAGE,0o700,dir_fd=fd);os.fsync(fd);check()
                                W.write(R,directory,'intent.json',intended)
                            else:
                                Q.require(S.read_protected(directory+'/intent.json',4096)==intended)
                                executed_raw=S.read_protected(directory+'/executed.json',65536);executed=I.decode(Q,executed_raw)
                                records[directory+'/executed.json']=executed_raw
                            records[directory+'/intent.json']=intended
                            with I.held_records(Q,S,records) as check_records:
                                def current_authority():bound_authority();check_records()
                                E=modules['infrastructure_evidence'].infrastructure_evidence(modules['infrastructure_io'],policy)
                                component=infrastructure['component'];component_raw=policy.canonical(component)
                                with E(data,infra_directory+'/effects',manifest,component_raw,policy.digest(component),tool_binding=binding,check_authority=current_authority) as retained:
                                    def identity_authority():current_authority();retained.check()
                                    with modules['identity_predecessor'].confirmed_identity(modules,parent,request,request_raw,worker_sha256,infra_raw,
                                            data=data,source=held.files[Y.PROVISION],ca=retained.read('tls/ca.crt'),image=all_images['platform'],
                                            component=component,owner_subject=cfg['owner_subject'],authority=identity_authority,parent_module=P) as (identity,check_identity):
                                        def final_authority():identity_authority();check_identity()
                                        builds_raw=S.read_protected(U.BUILDS,4096);unit_plan=U.plan(B,data,root,builds_raw)
                                        builds_unit=builds_raw.decode().splitlines()[1].split('=',1)[1]
                                        args=dict(data=data,source=request['sourceRoot'],cfg=cfg,images={s:all_images[s] for s in policy.SERVICES},
                                            compose_source=held.files['deploy/compose.yaml'],manifest=manifest,binding=binding,authority=final_authority,
                                            records_path=infra_directory+'/effects',component=component)
                                        host_args=dict(data=data,root=root,mount_source=proof['mountSource'],
                                            guard_raw=held.files['scripts/storage-guard.sh'],check_authority=final_authority)
                                        if execute:
                                            with H.HostContainment(S,**host_args) as host:
                                                I.observe_component(modules,**args,host=host);Q.require(host.result==infrastructure['hostContainment'])
                                                before_host=host.result;before_units=host.units
                                        else:
                                            before_host=executed['priorHost'];before_units=executed['priorUnits']
                                            Q.require(before_host==infrastructure['hostContainment'])
                                        with U.QuotaUnits(unit_plan,authority=final_authority,builds_raw=builds_raw,installed=not execute) as units:
                                            if execute:
                                                # Close the original exact host-unit reader
                                                # before these two declared exclusive writes.
                                                units.install()
                                                # Effect-only checks include exact units and
                                                # both closed identity readers on every poll.
                                                # Restore the ordinary source/parent callback
                                                # before read-only state/process observations.
                                                ctl.reload(check_effect=units.check);ctl.start(check_effect=units.check)
                                                live=runtime.enter_context(K.QuotaProcess(S,H,ctl,root=root,source_files=runtime_sources,check_authority=bound_authority))
                                            Q.require(live is not None);live.check();units.check()
                                            with H.HostContainment(S,**host_args) as host:
                                                I.observe_component(modules,**args,host=host)
                                                K.host_transition(H,before_host,host.result,before_units,host.units,builds_unit)
                                                result=outcome(Q,request,request_raw,worker_sha256,arguments.session,identity,
                                                    units.observation(),live.observation(),before_host,before_units,host.result)
                                                if not execute:Q.require(Q.canonical(result)==executed_raw)
                                                I.quiet_units(Q,commands.text,quota_check=live.check);units.check();final_authority()
                        Q.require(modules['infrastructure_predecessor'].reconstruct(modules,controller,collaborators,auth,
                            request,request_raw,worker_sha256,parent,quota_check=live.check)==previous)
                        bound_authority()
                V.require_platform_source(held)
            parent.check()
        S.require_released(collaborators)
    S.require_released(collaborators);raw=Q.canonical(result)
    if execute:W.write(R,directory,'executed.json',raw);print('Private quota support started; independent verification is required.')
    else:
        W.write(R,directory,'verified.json',raw)
        marker=('private-quota-verified-v1\nrequest='+Q.sha(request_raw)+'\nsession='+parent_args[3]+'\nstage='+STAGE
            +'\naction='+expected_action+'\noutcome='+Q.sha(raw)+'\n').encode()
        W.write(R,directory,'confirmation',marker,mode=0o600)
        print('Private quota support independently verified. Public services and operational timers remain disabled.')
