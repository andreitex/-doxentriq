"""Private service successor's read-only predecessor reconstruction.

Derived narrowly from company_render_worker.predecessor. Original signed source,
physical guard, expected journals and same-parent confirmations remain intact.
The earlier fresh-empty-engine check cannot be reapplied after authorized start.
"""
import ctypes
import os
from pathlib import Path
import platform
import sys
import time
BOOTSTRAP='scripts/bootstrap.py'
STARTUP='scripts/startup_binding.py'

def reconstruct(modules,controller,collaborators,auth,request,request_raw,worker_sha256,parent,*,quota_check=None):
    """Remeasure original journals/storage after private services have started.

    Original SeedStorage(fresh=False) checks retained storage rather than the
    never-activated Docker-empty precondition. Explicit public-writer and empty
    runtime checks remain, and the separate exact live-container verifier is
    mandatory before stage confirmation. This issues no StoredStartup capability. Original reconstruction + physical source verifier and
    original current runtime verifier bind the three predecessor confirmations.
    """
    quiet_units=modules['infrastructure_worker'].quiet_units
    active_storage_check=modules['infrastructure_worker'].active_storage_check
    RW=modules['render_worker']
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
                    storage=B.SeedStorage(data,root,startup_module=startup,files=files,commands=commands,fresh=False)
                    active_storage_check(Q,storage,commands,quota_check=quota_check)
                    T.configuration_binding(Q,S,B,held,request,files)
                    proposed=T.stage_request(K,request,request_raw,storage,files.records[data]['before']['st_dev'])
                    journals,stages,actual_source=K._expected(V,G,held,proposed)
                    Q.require(actual_source==source)
                    with G.hold_authenticated_company_source(held,verifier_module=V,source_root=source,
                            expected_device=files.records[data]['before']['st_dev'],backend_module=BK,backend=backend,clock=time.monotonic) as guard:
                        assembly.bind_source_guard(guard)
                        Q.require(all(S.read_protected(name,K.MAX_RECORD)==raw for name,raw in journals.items()))
                        for name,(a,o) in stages.items():RW.confirmed(P,parent,name,a,o)
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
                        RW.confirmed(P,parent,K.STAGE,startup_action,Q.sha(raw))
                        Q.require(all(S.read_protected(name,K.MAX_RECORD)==value for name,value in journals.items()))
                        active_storage_check(Q,storage,commands,quota_check=quota_check);storage.check();parent.check();V.require_platform_source(held)
                finally:
                    if files.owned:files.close()
                    collaborators['backend'].require_released()
        backend.require_released()
        return dict(startupOutcomeSha256=Q.sha(raw),runtime=runtime,proposal=proposed)
    finally:backend.require_released()

