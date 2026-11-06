"""Fresh render successor, authenticated incoming bytes and genuine live parent.

Retained physical source is inspected in separate closed scopes before/after
the known directory mutations. No guard identity is refreshed or disabled.
"""
from contextlib import ExitStack,contextmanager
import ctypes
import json
import os
from pathlib import Path
import platform
import stat
import sys
import time

STAGE='company-render'
BOOTSTRAP='scripts/bootstrap.py'
STARTUP='scripts/startup_binding.py'


def action(Q,request_raw,worker_sha256):
    return Q.sha(b'company-render-v1:'+Q.sha(request_raw).encode()+b':'+worker_sha256.encode())


def confirmed(P,parent,stage,action,outcome):
    """Read the original HeldParent's authenticated SAME-session records."""
    parent.check();args=parent.arguments;base=parent.session_path+'/'+stage
    P.require(base+'.intent' in parent.files and base+'.confirmed' in parent.files)
    initial=P.record(parent.files[base+'.intent'][2],'install-stage-v1',('session','stage','action','closed'))
    saved=P.record(parent.files[base+'.confirmed'][2],'install-stage-confirmed-v1',('session','stage','action','outcome','independently_confirmed'))
    P.require(initial==dict(session=args.session,stage=stage,action=action,closed='true'))
    P.require(saved==dict(session=args.session,stage=stage,action=action,outcome=outcome,independently_confirmed='true'))
    parent.check()


def predecessor(modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent):
    """Remeasure original Store/Source journals and current startup, then close.

    This successor does not impersonate a StoredStartup parent or issue that
    stage's capability. Original reconstruction + physical source verifier and
    original current runtime verifier bind the three predecessor confirmations.
    """
    Q,S,K,T=(modules[n] for n in ('configuration','station','stored_startup','startup_worker'))
    F,V,P,entry=(controller.original_modules[n] for n in ('full_entry','verifier','parent','entry'))
    BK,G=(entry.modules[n] for n in (F.BACKEND,F.GUARD))
    data=request['dataDir'];root=data+'/company/host-releases/install-'+request['operationId']
    source=data+'/company/source-releases/'+request['releaseSha256']+'/source'
    bundle=data+'/company/platform-releases/'+request['releaseSha256']
    dents=BK.LinuxAMD64Getdents64(ctypes_module=ctypes,libc=ctypes.CDLL(None,use_errno=True),sys_module=sys,machine_module=platform)
    backend=BK.ReadOnlySourceBackend(os_module=os,sys_module=sys,getdents64=dents);files=None
    try:
        with V.authenticated_stored_platform_source(bundle,request['keyPath'],auth['fingerprint'],expected_architecture='x86_64',
                source_root=source,files=collaborators['files'],crypto=collaborators['crypto']) as held:
            Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
            with entry.fresh_installation_modules(held) as assembly:
                B,startup=(assembly.modules[n] for n in (BOOTSTRAP,STARTUP))
                commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner'])
                files=B.SeedFiles(collaborators['backend_module'],collaborators['backend'])
                try:
                    storage=B.SeedStorage(data,root,startup_module=startup,files=files,commands=commands,fresh=True)
                    T.configuration_binding(Q,S,B,held,request,files)
                    proposed=T.stage_request(K,request,request_raw,storage,files.records[data]['before']['st_dev'])
                    journals,stages,actual_source=K._expected(V,G,held,proposed)
                    Q.require(actual_source==source)
                    with G.hold_authenticated_company_source(held,verifier_module=V,source_root=source,
                            expected_device=files.records[data]['before']['st_dev'],backend_module=BK,backend=backend,clock=time.monotonic) as guard:
                        assembly.bind_source_guard(guard)
                        Q.require(all(S.read_protected(name,K.MAX_RECORD)==raw for name,raw in journals.items()))
                        for name,(a,o) in stages.items():confirmed(P,parent,name,a,o)
                        startup_action=T.stage_action(K,proposed,worker_sha256)
                        runtime=assembly.call(STARTUP,'verify',Path(data),Path(root),**T.inputs_for(modules,assembly,commands))
                        inspection=dict(scope=K.SCOPE,status='held',releaseSha256=proposed['releaseSha256'],
                            installationId=proposed['installationId'],sourceRoot=source,requestSha256=K.sha(K.canonical(proposed)),
                            actionSha256=startup_action,storedJournalsSha256=K.sha(K.canonical({p:K.sha(raw) for p,raw in journals.items()})),
                            priorStageOutcomesSha256=K.sha(K.canonical(stages)),changed=False,fullInstallDenied=True,
                            runtimePairInitialized=False,backupReady=False,nativeQualified=False,outerContextsRequireClosure=True)
                        result=dict(scope='NATIVE_STORED_STARTUP_INSPECTION_ONLY',requestSha256=Q.sha(request_raw),
                            actionSha256=startup_action,session=parent.arguments.session,workerSha256=worker_sha256,
                            releaseSha256=held.metadata['releaseSha256'],storedInspection=inspection,runtimeInspection=runtime,
                            fullInstallationActivated=False,backupReady=False)
                        raw=Q.canonical(result);directory='/opt/autosoft-company/evidence/'+request['operationId']+'/'+K.STAGE
                        Q.require(all(S.read_protected(directory+'/'+name,32768)==raw for name in ('executed.json','verified.json')))
                        confirmed(P,parent,K.STAGE,startup_action,Q.sha(raw))
                        Q.require(all(S.read_protected(name,K.MAX_RECORD)==value for name,value in journals.items()))
                        storage.check();parent.check();V.require_platform_source(held)
                finally:
                    if files.owned:files.close()
                    collaborators['backend'].require_released()
        backend.require_released()
        return dict(startupOutcomeSha256=Q.sha(raw),runtime=runtime,proposal=proposed)
    finally:backend.require_released()


@contextmanager
def invariant_records(startup,inputs,data,root):
    """Keep original host/key/layout controls and both initialized journals held.

    The original storage context permits only first-seven backing-file identity
    while key/config files remain strict. This supplements, not replaces, the
    render IO's exact directory transition accounting.
    """
    with ExitStack() as stack:
        selected={key:inputs[key] for key in ('host_directory','files','command','mount','layout')}
        proof=stack.enter_context(startup.fresh_storage_context(Path(data),Path(root),**selected))
        gate=inputs['gate_factory'](Path(data));allocation=inputs['allocation_factory'](Path(data))
        admission=stack.enter_context(gate.inspect_initialized(proof['installationId'],timeout=10))
        quota=stack.enter_context(allocation.inspect_initialized(proof['installationId'],read_state=inputs['read_state'],timeout=10))
        host=Path('/etc/autosoft');final=inputs['files'].read(host/'installation.json')
        paths=[host/'installation.intent.json',host/'installation.json',host/'installation.storage-receipt.json',
            host/'storage.key',Path(data)/'config/installation.json',Path(final['storage_file'])]
        handles=[]
        try:
            for path in paths:
                before=inputs['files'].protected(path,private=True)
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);handles.append((path,fd,startup.C.identity(before),7 if str(path)==final['storage_file'] else 9))
            def check():
                for path,fd,before,length in handles:
                    startup.C.require(startup.C.identity(os.fstat(fd))[:length]==before[:length]
                        ==startup.C.identity(inputs['files'].protected(path,private=True))[:length])
            check();yield proof,check;check()
        finally:
            failures=[]
            for _,fd,_,_ in reversed(handles):
                try:os.close(fd)
                except BaseException as error:failures.append(error)
            if failures:raise failures[0]


def write_record(R,directory,name,raw):
    R.require(name in ('outputs.json','executed.json','verified.json') and type(raw) is bytes and 0<len(raw)<=131072)
    with R.directory(directory) as (parent,check):
        fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            offset=0
            while offset<len(raw):
                n=os.write(fd,raw[offset:]);R.require(n>0);offset+=n
            os.fchmod(fd,0o400);os.fsync(fd)
            info=os.fstat(fd);R.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400 and os.pread(fd,len(raw)+1,0)==raw)
            now=os.stat(name,dir_fd=parent,follow_symlinks=False);R.require((now.st_dev,now.st_ino)==(info.st_dev,info.st_ino))
            os.fsync(parent);check()
        finally:
            try:os.close(fd)
            except BaseException:R.UNKNOWN.append(fd);raise


def run(command,modules,delivery,auth,request,request_raw,worker_sha256,parent_args):
    Q,S,C,W,R,N,D=(modules[n] for n in ('configuration','station','cli','configuration_worker','records','render_io','render_commands'))
    Q.require(command in ('render-action','render-ready','render-configuration','verify-render'))
    expected_action=action(Q,request_raw,worker_sha256)
    if command=='render-action':Q.require(parent_args is None);print(expected_action);return
    planning=command=='render-ready';execute=command=='render-configuration'
    Q.require((parent_args is None) is planning)
    operation='/opt/autosoft-company/evidence/'+request['operationId'];directory=operation+'/'+STAGE
    data=request['dataDir'];root=data+'/company/host-releases/install-'+request['operationId']
    collaborators=None;result=None
    with C.authenticated_cli(delivery,**auth) as controller:
        F,V,P,entry=(controller.original_modules[n] for n in ('full_entry','verifier','parent','entry'))
        collaborators=S.stage_inputs(controller,request_raw,modules['crypto'])
        with ExitStack() as outer:
            parent=None
            if not planning:
                arguments=P.ParentInput.from_argv(parent_args)
                Q.require(arguments.stage==STAGE and arguments.request==Q.sha(request_raw) and arguments.action==expected_action)
                parent=outer.enter_context(P.hold_parent(arguments,system=collaborators['parent_system']))
                previous=predecessor(modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent)
            with V.authenticated_platform_source(request['bundleRoot'],request['keyPath'],auth['fingerprint'],expected_architecture='x86_64',
                    source_root=request['sourceRoot'],files=collaborators['files'],crypto=collaborators['crypto'],owner_uid=0,owner_gid=0) as held:
                Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
                with entry.fresh_installation_modules(held) as assembly:
                    B,startup=(assembly.modules[n] for n in (BOOTSTRAP,STARTUP))
                    commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner']);Q.quiet(commands.text)
                    inputs=modules['startup_worker'].inputs_for(modules,assembly,commands)
                    initial=assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)
                    cfg=json.loads(S.read_protected(Path(data)/'config/installation.json',32768))
                    Q.require(cfg['company_public_fingerprint']==held.metadata['signingKeyFingerprint'])
                    for name in ('approved-mirrors.json','images.lock.json','runtime-manifest.json'):
                        Q.require(S.read_protected(Path(data)/'config'/name,1024**2)==held.configs[name])
                    expected=None
                    intended=Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=expected_action,
                        session=parent.arguments.session if parent else None,workerSha256=worker_sha256))
                    if not planning and not execute:
                        Q.require(S.read_protected(directory+'/intent.json',4096)==intended)
                        expected=json.loads(S.read_protected(directory+'/outputs.json',131072))
                        S.read_protected(directory+'/executed.json',32768)
                    with invariant_records(startup,inputs,data,root) as (proof,check_invariants):
                        def authority():
                            if parent:parent.check()
                            V.require_platform_source(held);F.FullEntry.recheck(entry);check_invariants()
                        io=N.RenderIO(data,request['sourceRoot'],held.files,cfg,check_authority=authority,
                            process_factory=lambda value:D.NativeCommands(value,request['operationId']),
                            readonly=not planning and not execute,expected=expected)
                        try:
                            if not planning:
                                if execute:
                                    with R.directory(operation) as (fd,check):os.mkdir(STAGE,0o700,dir_fd=fd);os.fsync(fd);check()
                                    W.write(R,directory,'intent.json',intended)
                                    assembly.call(BOOTSTRAP,'render',Path(data),Path(root),render_io=io,
                                        verify_layout=lambda _:inputs['layout'](Path(data),files=inputs['files']))
                                    manifest=io.manifest()
                                else:
                                    def source_verifier(_data,_cfg):
                                        Q.require(_cfg==cfg);authority()
                                    modules['render_verify'].verify(B,io,source_verifier=source_verifier)
                                    manifest=io.manifest()
                                authority()
                        finally:io.close()
                    Q.require(assembly.call(STARTUP,'verify',Path(data),Path(root),**inputs)==initial)
                    Q.quiet(commands.text);V.require_platform_source(held)
            if not planning:
                Q.require(predecessor(modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent)==previous)
                parent.check()
                result=dict(scope='NATIVE_RENDER_STAGE_ONLY',requestSha256=Q.sha(request_raw),actionSha256=expected_action,
                    session=parent.arguments.session,workerSha256=worker_sha256,releaseSha256=request['releaseSha256'],
                    predecessorSha256=Q.sha(Q.canonical(previous)),outputsSha256=Q.sha(Q.canonical(manifest)),
                    outputFiles=len(manifest['files']),servicesActivated=False,identityProvisioned=False,backupReady=False)
        S.require_released(collaborators)
    S.require_released(collaborators)
    if planning:print('render-prerequisites-verified');return
    raw=Q.canonical(result)
    if execute:
        write_record(R,directory,'outputs.json',Q.canonical(manifest));W.write(R,directory,'executed.json',raw)
        print('Configuration rendered; separate read-only verification is required.')
    else:
        Q.require(S.read_protected(directory+'/executed.json',32768)==raw)
        W.write(R,directory,'verified.json',raw)
        marker=('render-verified-v1\nrequest='+Q.sha(request_raw)+'\nsession='+parent_args[3]+'\nstage='+STAGE
            +'\naction='+expected_action+'\noutcome='+Q.sha(raw)+'\n').encode()
        W.write(R,directory,'confirmation',marker,mode=0o600)
