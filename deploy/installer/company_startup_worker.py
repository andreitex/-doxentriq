"""Native same-session retained-source startup inspection; no activation.

Original signed source, physical source guard, storage and live Bash parent
remain held through the original StoredStartup API. No serialized completion
record substitutes for prior confirmations in that same parent session.
"""
from contextlib import contextmanager
import ctypes
import os
from pathlib import Path
import platform
import sys
import time

STAGE='company-stored-startup'
BOOTSTRAP='scripts/bootstrap.py'
PAIR='scripts/runtime_pair_init.py'
STARTUP='scripts/startup_binding.py'


def stage_request(K,request,request_raw,storage,device):
    return K.request_value(dict(schemaVersion=1,scope=K.SCOPE,operationId=request['operationId'],
        installationId=storage.installation_id,installationRequestSha256=K.sha(request_raw),
        dataDir=request['dataDir'],installRoot=storage.root,releaseSha256=request['releaseSha256'],
        storeOperationId=request['operationId'],
        sourceOperationId=K.sha(('source:'+request['operationId']).encode())[:32],
        storageBindingSha256=storage.binding_sha256,expectedDevice=device))


def stage_action(K,request,worker_sha256):
    K.request_value(request)
    K.require(type(worker_sha256) is str and K.re.fullmatch('[a-f0-9]{64}',worker_sha256) is not None)
    return K.sha(b'company-stored-startup-v1:'+K.sha(K.canonical(request)).encode()+b':'+worker_sha256.encode())


@contextmanager
def held_startup(K,entry,*,full_entry_module,held,source_guard,parent,request,worker_sha256,backend,assembly,clock):
    """Use the issued original capability and its exact physically bound assembly."""
    with K.hold_confirmed_stored_startup(entry,full_entry_module=full_entry_module,
            held=held,source_guard=source_guard,parent=parent,request=request,
            worker_sha256=worker_sha256,backend=backend,clock=clock) as capability:
        with capability.assembly(fresh_assembly=assembly) as original:
            K.require(original is assembly)
            yield capability
        capability.recheck()


def inputs_for(modules,assembly,commands):
    value=modules['runtime_pair_worker'].native_inputs(assembly.modules[PAIR],commands)
    return {key:value[key] for key in ('host_directory','files','command','mount','layout',
        'gate_factory','allocation_factory','read_state','clock','timeout')}


def configuration_binding(Q,S,B,held,request,files):
    intent=B._seed_decode(files.records['/etc/autosoft/installation.intent.json']['raw'])
    proposal=intent['proposal']
    root=request['dataDir']+'/company/host-releases/install-'+request['operationId']
    Q.require(proposal['data_dir']==request['dataDir'] and proposal['storage_file']==request['backingFile']
        and type(proposal['capacity_gib']) is int and proposal['capacity_gib']==request['capacityGiB']
        and proposal['install_root']==root)
    configuration=B._seed_decode(files.records[request['dataDir']+'/config/installation.json']['raw'])
    Q.require(configuration['company_public_fingerprint']==held.metadata['signingKeyFingerprint'])
    for name in ('approved-mirrors.json','images.lock.json','runtime-manifest.json'):
        Q.require(S.read_protected(Path(request['dataDir'])/'config'/name,1024**2)==held.configs[name])


def preflight(modules,delivery,auth,request,request_raw):
    """Read-only incoming-source/runtime check before any continuation session."""
    S,C,Q=(modules[name] for name in ('station','cli','configuration'))
    collaborators=files=None
    with C.authenticated_cli(delivery,**auth) as controller:
        V,entry=(controller.original_modules[name] for name in ('verifier','entry'))
        collaborators=S.stage_inputs(controller,request_raw,modules['crypto'])
        with V.authenticated_platform_source(request['bundleRoot'],request['keyPath'],auth['fingerprint'],
                expected_architecture='x86_64',source_root=request['sourceRoot'],files=collaborators['files'],
                crypto=collaborators['crypto'],owner_uid=0,owner_gid=0) as held:
            Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
            with entry.fresh_installation_modules(held) as assembly:
                B,startup=(assembly.modules[name] for name in (BOOTSTRAP,STARTUP))
                commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner'])
                files=B.SeedFiles(collaborators['backend_module'],collaborators['backend'])
                try:
                    root=request['dataDir']+'/company/host-releases/install-'+request['operationId']
                    storage=B.SeedStorage(request['dataDir'],root,startup_module=startup,files=files,commands=commands,fresh=True)
                    configuration_binding(Q,S,B,held,request,files)
                    Q.retention_parents(Path(request['dataDir']),files=assembly.modules[PAIR].NativeFiles())
                    assembly.call(STARTUP,'verify',Path(request['dataDir']),Path(root),**inputs_for(modules,assembly,commands))
                    storage.check();V.require_platform_source(held)
                finally:
                    if files.owned:files.close()
                    collaborators['backend'].require_released()
        S.require_released(collaborators)
    S.require_released(collaborators)
    print('stored-startup-prerequisites-verified')


def run(command,modules,delivery,auth,request,request_raw,worker_sha256,parent_args):
    S,C,Q,W,K=(modules[name] for name in ('station','cli','configuration','configuration_worker','stored_startup'))
    Q.require(command in ('continuation-ready','startup-action','inspect-stored-startup','verify-stored-startup'))
    if command=='continuation-ready':
        Q.require(parent_args is None)
        return preflight(modules,delivery,auth,request,request_raw)
    planning,execute=command=='startup-action',command=='inspect-stored-startup'
    Q.require((parent_args is None) is planning and not K.UNRELEASED)
    data=request['dataDir'];root=data+'/company/host-releases/install-'+request['operationId']
    bundle=data+'/company/platform-releases/'+request['releaseSha256']
    source=data+'/company/source-releases/'+request['releaseSha256']+'/source'
    operation='/opt/autosoft-company/evidence/'+request['operationId'];directory=operation+'/'+STAGE
    collaborators=readonly=files=None
    with C.authenticated_cli(delivery,**auth) as controller:
        F,V,P,entry=(controller.original_modules[name] for name in ('full_entry','verifier','parent','entry'))
        BK,G=(entry.modules[name] for name in (F.BACKEND,F.GUARD))
        collaborators=S.stage_inputs(controller,request_raw,modules['crypto'])
        dents=BK.LinuxAMD64Getdents64(ctypes_module=ctypes,libc=ctypes.CDLL(None,use_errno=True),
            sys_module=sys,machine_module=platform)
        readonly=BK.ReadOnlySourceBackend(os_module=os,sys_module=sys,getdents64=dents)
        with V.authenticated_stored_platform_source(bundle,request['keyPath'],auth['fingerprint'],
                expected_architecture='x86_64',source_root=source,files=collaborators['files'],crypto=collaborators['crypto']) as held:
            Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
            with entry.fresh_installation_modules(held) as assembly:
                B,startup=(assembly.modules[name] for name in (BOOTSTRAP,STARTUP))
                commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner'])
                files=B.SeedFiles(collaborators['backend_module'],collaborators['backend'])
                try:
                    storage=B.SeedStorage(data,root,startup_module=startup,files=files,commands=commands,fresh=True)
                    configuration_binding(Q,S,B,held,request,files)
                    device=files.records[data]['before']['st_dev']
                    proposed=stage_request(K,request,request_raw,storage,device)
                    action=stage_action(K,proposed,worker_sha256)
                    with G.hold_authenticated_company_source(held,verifier_module=V,source_root=source,
                            expected_device=device,backend_module=BK,backend=readonly,clock=time.monotonic) as guard:
                        assembly.bind_source_guard(guard)
                        if not planning:
                            arguments=P.ParentInput.from_argv(parent_args)
                            Q.require(arguments.stage==STAGE and arguments.request==Q.sha(request_raw) and arguments.action==action)
                            with P.hold_parent(arguments,system=collaborators['parent_system']) as parent:
                                intended=Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=action,
                                    session=arguments.session,workerSha256=worker_sha256))
                                if execute:
                                    with modules['records'].directory(operation) as (fd,check):
                                        os.mkdir(STAGE,0o700,dir_fd=fd);os.fsync(fd);check()
                                    W.write(modules['records'],directory,'intent.json',intended)
                                else:
                                    Q.require(S.read_protected(directory+'/intent.json',4096)==intended)
                                    S.read_protected(directory+'/executed.json',32768)
                                with held_startup(K,entry,full_entry_module=F,held=held,source_guard=guard,
                                        parent=parent,request=proposed,worker_sha256=worker_sha256,
                                        backend=readonly,assembly=assembly,clock=time.monotonic) as capability:
                                    inspection=capability.inspection()
                                    runtime=capability.inspect_initialized(inputs=inputs_for(modules,assembly,commands),fresh_assembly=assembly)
                                    Q.require(capability.inspection()==inspection)
                                    storage.check();parent.check()
                                Q.require(not K.UNRELEASED and not K._ISSUED and not K._OWNERS)
                                result=dict(scope='NATIVE_STORED_STARTUP_INSPECTION_ONLY',requestSha256=Q.sha(request_raw),
                                    actionSha256=action,session=arguments.session,workerSha256=worker_sha256,
                                    releaseSha256=held.metadata['releaseSha256'],storedInspection=inspection,
                                    runtimeInspection=runtime,fullInstallationActivated=False,backupReady=False)
                                parent.check()
                        storage.check();V.require_platform_source(held)
                    readonly.require_released()
                finally:
                    if files.owned:files.close()
                    collaborators['backend'].require_released()
                readonly.require_released()
        S.require_released(collaborators)
    readonly.require_released();S.require_released(collaborators)
    if planning:
        print(action)
        return
    raw=Q.canonical(result)
    if execute:
        W.write(modules['records'],directory,'executed.json',raw)
        print('Retained signed source and initialized runtime inspected; separate confirmation is required.')
    else:
        Q.require(S.read_protected(directory+'/executed.json',32768)==raw)
        W.write(modules['records'],directory,'verified.json',raw)
        marker=('stored-startup-verified-v1\nrequest='+Q.sha(request_raw)+'\nsession='+parent_args[3]
            +'\nstage='+STAGE+'\naction='+action+'\noutcome='+Q.sha(raw)+'\n').encode()
        W.write(modules['records'],directory,'confirmation',marker,mode=0o600)
