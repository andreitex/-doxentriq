"""Read-only completed-preparation handoff under a fresh installer parent.

The previous session is data, never revived authority. Original signed source
readers remeasure configuration, seed Git objects and the initialized pair.
No prior stage is executed, no observation is overwritten and no service starts.
"""
import json
from pathlib import Path
import stat

STAGE='preparation-handoff'
STAGES=('company-configuration','repository-seed','fresh-runtime-pair')
MAGICS=('configuration-verified-v1','repository-verified-v1','runtime-pair-verified-v1')
COMMANDS=('preparation-handoff-action','verify-completed-preparation')


def completed(F,P,state,request,request_raw,worker_sha,predecessor,*,current_session=None):
    """Close the original three-stage journal and its exact immutable evidence."""
    F.require(type(predecessor) is str and P.SESSION.fullmatch(predecessor) is not None)
    F.require(type(worker_sha) is str and P.DIGEST.fullmatch(worker_sha) is not None)
    F.require(current_session is None or (type(current_session) is str
        and P.SESSION.fullmatch(current_session) is not None and current_session!=predecessor))
    request_sha=F.sha(request_raw);admission=Path(P.BASE);session=admission/'sessions'/predecessor
    snapshot={}
    def record(path,maximum=P.RECORD_MAX,mode=0o600):
        before=state.protected(path)
        F.require(stat.S_IMODE(before.st_mode)==mode)
        if mode==0o600:P.protected(P.Metadata.of(before))
        raw=state.read(path,maximum)
        F.require(F.identity(state.protected(path))==F.identity(before))
        snapshot[str(path)]=dict(identity=F.identity(before),sha256=F.sha(raw))
        return raw
    def directory(path,expected):
        before=state.observe_directory(path);P.protected(P.Metadata.of(before),directory=True)
        F.require(state.names(path)==sorted(expected))
        snapshot[str(path)]=dict(identity=F.identity(before),names=sorted(expected))
        return before
    names=['intent','complete']+[stage+suffix for stage in STAGES for suffix in('.intent','.confirmed')]
    before=directory(session,names)
    binding=record(admission/'binding')
    saved=P.record(record(session/'intent'),'install-session-v1',('session','request','binding','directory','closed'))
    F.require(saved['session']==predecessor and saved['request']==request_sha
        and saved['binding']==F.sha(binding) and saved['closed']=='true')
    P.shell_metadata(saved['directory'],P.Metadata.of(before),directory=True)
    evidence=Path('/opt/autosoft-company/evidence')/request['operationId']
    directory(evidence,['intent.json','result.json','verified',*STAGES])
    confirmations={};outcomes=[];results={};intents={};stage_hashes={}
    for stage,magic in zip(STAGES,MAGICS):
        raw=record(session/(stage+'.intent'))
        value=P.record(raw,'install-stage-v1',('session','stage','action','closed'))
        action=value['action'];stage_hashes[stage]=F.sha(raw)
        F.require(value['session']==predecessor and value['stage']==stage and value['closed']=='true'
            and P.DIGEST.fullmatch(action) is not None)
        confirmed=record(session/(stage+'.confirmed'))
        value=P.record(confirmed,'install-stage-confirmed-v1',('session','stage','action','outcome','independently_confirmed'))
        outcome=value['outcome']
        F.require(value['session']==predecessor and value['stage']==stage and value['action']==action
            and P.DIGEST.fullmatch(outcome) is not None and value['independently_confirmed']=='true')
        confirmations[stage]=confirmed;outcomes.append(outcome)
        stage_path=evidence/stage
        directory(stage_path,['intent.json','executed.json','verified.json','confirmation'])
        intended=dict(requestSha256=request_sha,actionSha256=action,session=predecessor,workerSha256=worker_sha)
        F.require(record(stage_path/'intent.json',4096,0o400)==F.canonical(intended))
        raw=record(stage_path/'executed.json',32768,0o400)
        F.require(record(stage_path/'verified.json',32768,0o400)==raw and F.sha(raw)==outcome)
        result=json.loads(raw);F.require(type(result) is dict and F.canonical(result)==raw)
        F.require(result.get('requestSha256')==request_sha and result.get('actionSha256')==action)
        if stage!='company-configuration':
            F.require(result.get('session')==predecessor and result.get('workerSha256')==worker_sha)
        F.require(record(stage_path/'confirmation',4096)==(magic+'\nrequest='+request_sha+'\nsession='+predecessor
            +'\nstage='+stage+'\naction='+action+'\noutcome='+outcome+'\n').encode())
        intents[stage]=intended;results[stage]=result
    final=F.sha(('preparation-only-v1:'+request_sha+':'+':'.join(outcomes)).encode())
    F.require(record(session/'complete')==('install-complete-v1\nsession='+predecessor+'\nrequest='+request_sha
        +'\nmanifest='+F.sha(b''.join(confirmations[name] for name in sorted(confirmations)))+'\nfinal='+final+'\nindependently_confirmed=true\n').encode())
    # Old foundation/handoff sessions use the distinct foundation request.
    # Any competing preparation, private work or earlier handoff is refused.
    sessions=state.names(admission/'sessions');F.require(len(sessions)<=P.SESSION_MAX)
    for name in sessions:
        F.require(P.SESSION.fullmatch(name) is not None)
        if name in (predecessor,current_session):continue
        value=P.record(state.read(admission/'sessions'/name/'intent',P.RECORD_MAX),
            'install-session-v1',('session','request','binding','directory','closed'))
        F.require(value['request']!=request_sha)
    for name,row in tuple(snapshot.items()):
        if 'names' in row:
            F.require(F.identity(state.observe_directory(name))==row['identity'] and state.names(name)==row['names'])
    return dict(snapshot=snapshot,results=results,intents=intents,stageHashes=stage_hashes,final=final)


def action(F,request_raw,worker_sha,predecessor,package_sha,saved):
    F.require(type(package_sha) is str and F.re.fullmatch('[a-f0-9]{64}',package_sha) is not None)
    return F.sha(b'completed-preparation-handoff-v1:'+F.sha(request_raw).encode()+b':'+worker_sha.encode()
        +b':'+predecessor.encode()+b':'+package_sha.encode()+b':'+F.sha(F.canonical(saved)).encode())


def configuration(modules,assembly,held,request,request_raw,worker_sha,command,foundation_sha,check):
    """Remeasure original configuration outputs without its now-false empty-repo test."""
    Q=modules['configuration'];B,L,S=(assembly.modules[path] for path in (Q.BOOTSTRAP,Q.LAYOUT,Q.STARTUP))
    data=Path(request['dataDir']);root=data/'company/host-releases'/('install-'+request['operationId'])
    files=L.NativeFiles();files.require_root();host_directory=Path('/etc/autosoft')
    check();host=S.I.verify_host_record(host_directory,files=files)
    intent=S.I.read_intent(host_directory,files=files);receipt=files.read(host_directory/'installation.storage-receipt.json')
    Q.require(host=={key:receipt[key] for key in host} and host['data_dir']==str(data)
        and host['install_root']==str(root) and host['storage_file']==request['backingFile']
        and intent['proposal']['capacity_gib']==request['capacityGiB'] and receipt['creation_stage']=='new-luks-created'
        and not modules['foundation_worker'].os.path.lexists(host_directory/'installation.pending.json')
        and not modules['foundation_worker'].os.path.lexists(host_directory/'installation.complete'))
    mount=S.encrypted_proof(data,receipt,command=command);Q.quiet(command)
    value=files.read(data/'config/installation.json');identifier=S.I.verify_reference(intent,value)
    Q.require(value['company_public_fingerprint']==held.metadata['signingKeyFingerprint'])
    for name in Q.CONFIGS:
        path=data/'config'/name;before=files.protected(path,private=name=='approved-mirrors.json')
        Q.require(path.read_bytes()==held.configs[name]);files.compare_opened(before,path.lstat())
    placement=assembly.call(Q.LAYOUT,'verify',data,files=files,build_mount=lambda path:L.builds_proof(path,command=command))
    Q.require(placement['changed'] is False and placement['backupReady'] is False)
    outputs=Q.wizard_outputs(data,value,durable=False);parents=Q.retention_parents(data,files=files,durable=False)
    check();Q.require(S.encrypted_proof(data,receipt,command=command)==mount);Q.quiet(command)
    return dict(schemaVersion=1,scope='COMPANY_CONFIGURATION_AND_PLACEMENT_ONLY',requestSha256=Q.sha(request_raw),
        actionSha256=Q.action(request_raw,worker_sha),releaseSha256=request['releaseSha256'],installationId=identifier,
        configurationSha256=Q.sha(Q.canonical(value)),encryptedMountSha256=Q.sha(Q.canonical(mount)),
        layoutSha256=Q.sha(Q.canonical(files.read(data/'config/runtime-layout/layout.json'))),
        signedConfigurationSha256=Q.sha(Q.canonical({name:Q.sha(held.configs[name]) for name in Q.CONFIGS})),
        wizardOutputsSha256=outputs,retentionParentsSha256=parents,modelCatalogSource='operator-supplied',
        servicesStarted=False,runtimePairInitialized=False,fullInstallationCompleted=False,
        outerContextsRequireClosure=True,foundationEvidenceSha256=foundation_sha)


def repository(modules,assembly,held,V,request,request_raw,worker_sha,predecessor,collaborators,check):
    """Use actual captured SeedFiles/SeedGit; require the unchanged initial tree."""
    N,S,Q=(modules[name] for name in ('repository_io','station','configuration'))
    B,startup=(assembly.modules[path] for path in ('scripts/bootstrap.py','scripts/startup_binding.py'))
    data=request['dataDir'];root=data+'/company/host-releases/install-'+request['operationId']
    backend=files=runner=None
    try:
        check();plan=B._seed_plan(held)
        backend=N.SeedBackend(data=data,install_root=root,storage_file=request['backingFile'],
            operation_id=request['operationId'],plan=plan,broker_directories=startup.L.BROKER_DIRECTORIES,writable=False)
        files=B.SeedFiles(N,backend);installed=S.tool_pin('/usr/bin/git')
        git_pin=dict(path='/usr/bin/git',bytes=installed['bytes'],sha256=installed['sha256'])
        runner=N.SeedRunner(host_runner=collaborators['runner'],backend=backend,repository=data+'/runtime/repository',plan=plan,git_pin=git_pin)
        commands=B.SeedCommands(N,runner);git=B.SeedGit(files,commands,git_pin);runner.preflight(git.tool)
        storage=B.SeedStorage(data,root,startup_module=startup,files=files,commands=commands,fresh=True)
        proposed,proposed_sha,stage_action=B.authenticated_seed_request(data,root,held,verifier_module=V,
            storage=storage,git=git,operation_id=request['operationId'],installation_request_sha256=Q.sha(request_raw))
        operation=storage.journal+'/'+request['operationId']
        Q.require(files.names(storage.journal,1)==[request['operationId']])
        files.hold(operation,kind='directory',mode=0o700)
        Q.require(files.names(operation,2)==['intent.json','objects-verified.json'])
        for name in ('intent.json','objects-verified.json'):files.hold(operation+'/'+name,mode=0o600)
        intended=dict(scope='AUTHENTICATED_REPOSITORY_SEED_ONLY',request=proposed,requestSha256=proposed_sha,
            actionSha256=stage_action,commit=plan['commit'],tree=plan['root'],leafCount=len(plan['leaves']))
        outcome=dict(scope='AUTHENTICATED_REPOSITORY_SEED_ONLY',requestSha256=proposed_sha,actionSha256=stage_action,
            commit=plan['commit'],tree=plan['root'],head=plan['commit'],leafCount=len(plan['leaves']),objectCount=len(plan['objects']),
            objectBytesVerified=True,installationActivated=False,nativeQualified=False,companyStoreImplemented=False,
            fullInstallDenied=True,nativeFdCapacityQualified=False)
        Q.require(files.records[operation+'/intent.json']['raw']==B._seed_json(intended)
            and files.records[operation+'/objects-verified.json']['raw']==B._seed_json(outcome))
        check();B._seed_hold_output(files,storage.repository,plan,fresh=True)
        Q.require(git.verify(storage.repository,plan,fresh=True)==plan['commit'])
        storage.check(force_host=True);files.check(readback=True);check()
        result=dict(scope='NATIVE_REPOSITORY_SEED_ONLY',requestSha256=Q.sha(request_raw),actionSha256=stage_action,
            session=predecessor,workerSha256=worker_sha,releaseSha256=held.metadata['releaseSha256'],
            sourceTree=held.metadata['sourceTree'],seedCommit=plan['commit'],tree=plan['root'],leafCount=len(plan['leaves']),
            objectCount=len(plan['objects']),gitToolPin=git_pin,fullInstallationActivated=False,runtimePairInitialized=False)
        if files.owned:files.close()
        runner.require_released();backend.finish();backend.require_released()
        return result
    finally:
        if files is not None and files.owned:files.close()
        if backend is not None and not backend.closed:backend.finish()


def pair(modules,assembly,request,request_raw,worker_sha,predecessor,stage_hash,commands,check):
    """Compare historical parent data, then independently read current pair/startup."""
    W,Q=(modules[name] for name in ('runtime_pair_worker','configuration'))
    R=assembly.modules[W.PAIR];S,C=R.S,R.C
    inputs=W.native_inputs(R,commands);files=inputs['files'];clock=inputs['clock'];deadline=clock()+inputs['timeout']
    data=Path(request['dataDir']);root=data/'company/host-releases'/('install-'+request['operationId'])
    stage=data/'config/runtime-pair-initialization'
    check()
    with S.fresh_storage_context(data,root,**W.storage_inputs(inputs)) as proof:
        proposed=W.proposal(R,proof);stage_action=W.action(R,request_raw,worker_sha,proposed)
        records,digest=W.stage_records(R,files,stage)
        historical=dict(scope='INSTALLER_PARENT_STAGE_ONLY',stage=R.STAGE,installationId=proof['installationId'],
            requestSha256=C.digest(proposed),parentSessionId=predecessor,parentIntentSha256=stage_hash,nativeAuthorized=False)
        intent=dict(schemaVersion=1,scope=R.SCOPE,installationId=proof['installationId'],dataRootSha256=proof['dataRootSha256'],
            directory=C.directory_binding(files.protected(stage,directory=True,private=True)),parentSha256=C.digest(historical),
            requestSha256=C.digest(proposed),storageProofSha256=C.digest(proof),
            absence=dict(quota=[],storage=[],pairAbsent=True,stageAbsent=True),
            expectedProjectsSha256=R.EMPTY_STATE_SHA256,expectedProjectsRawSha256=R.EMPTY_RAW_SHA256)
        C.require(records['intent.json']==intent)
        gate=C.fields(records['gate-confirmed.json'],{'intentSha256','gateSha256'})
        C.require(gate['intentSha256']==C.digest(intent));C.hash_value(gate['gateSha256'])
        current=R._pair(files,data,inputs['gate_factory'](data),inputs['allocation_factory'](data),
            proof['installationId'],proof['mountSource'],inputs['read_state'],deadline-clock())
        C.require(records['allocation-confirmed.json']==dict(intentSha256=C.digest(intent),pairSha256=C.digest(current)))
        check();selected={key:inputs[key] for key in ('host_directory','files','command','mount','layout',
            'gate_factory','allocation_factory','read_state','clock')}
        startup=S.verify(data,root,**selected,timeout=deadline-clock())
        expected=dict(scope=R.SCOPE,status='effects-confirmed',installationId=proof['installationId'],intentSha256=C.digest(intent),
            pairSha256=C.digest(current),startupSha256=C.digest(startup),authorization=R.QUALIFICATION,nativeAuthorized=False,backupReady=False)
        C.require(records['confirmed.json']==expected)
        C.require(R._pair(files,data,inputs['gate_factory'](data),inputs['allocation_factory'](data),proof['installationId'],
            proof['mountSource'],inputs['read_state'],deadline-clock())==current)
        C.require(W.stage_records(R,files,stage)==(records,digest));check()
    return dict(scope='NATIVE_RUNTIME_PAIR_STAGE_ONLY',requestSha256=Q.sha(request_raw),actionSha256=stage_action,
        session=predecessor,workerSha256=worker_sha,releaseSha256=request['releaseSha256'],pairResult=expected,
        stageRecordsSha256=digest,fullInstallationActivated=False,backupReady=False)


def run(command,modules,delivery,auth,request,request_raw,worker_sha,parent_args,predecessor,package_sha,*,host_catalogs):
    F,S,C,Q,W=(modules[name] for name in ('foundation_worker','station','cli','configuration','configuration_worker'))
    Q.require(command in COMMANDS and (parent_args is None) is (command==COMMANDS[0]))
    state=F.NativeState();collaborators=None
    with C.authenticated_cli(delivery,**auth) as controller:
        V,P,entry=(controller.original_modules[name] for name in ('verifier','parent','entry'))
        arguments=P.ParentInput.from_argv(parent_args) if parent_args is not None else None
        saved=completed(F,P,state,request,request_raw,worker_sha,predecessor,current_session=arguments.session if arguments else None)
        proposed=action(F,request_raw,worker_sha,predecessor,package_sha,saved)
        if command==COMMANDS[0]:
            print(proposed);return
        Q.require(arguments.stage==STAGE and arguments.request==Q.sha(request_raw) and arguments.action==proposed)
        collaborators=S.stage_inputs(controller,request_raw,modules['crypto'],repository_seed=True)
        with P.hold_parent(arguments,system=collaborators['parent_system']) as parent:
            with V.authenticated_platform_source(request['bundleRoot'],request['keyPath'],auth['fingerprint'],
                    expected_architecture='x86_64',source_root=request['sourceRoot'],files=collaborators['files'],
                    crypto=collaborators['crypto'],owner_uid=0,owner_gid=0) as held:
                Q.require(held.metadata['releaseSha256']==request['releaseSha256'])
                with entry.fresh_installation_modules(held) as assembly:
                    def check():
                        parent.check();V.require_platform_source(held)
                        Q.require(completed(F,P,state,request,request_raw,worker_sha,predecessor,current_session=arguments.session)==saved)
                    B=assembly.modules[Q.BOOTSTRAP];commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner'])
                    check()
                    foundation_sha=W.foundation(Q,S,V,request,held,collaborators,auth['fingerprint'],modules=modules,
                        host_catalogs=host_catalogs,check_authority=check)
                    observed=configuration(modules,assembly,held,request,request_raw,worker_sha,commands.text,foundation_sha,check)
                    Q.require(observed==saved['results'][STAGES[0]])
                    observed=repository(modules,assembly,held,V,request,request_raw,worker_sha,predecessor,collaborators,check)
                    Q.require(observed==saved['results'][STAGES[1]])
                    observed=pair(modules,assembly,request,request_raw,worker_sha,predecessor,saved['stageHashes'][STAGES[2]],commands,check)
                    Q.require(observed==saved['results'][STAGES[2]])
                    Q.require(W.foundation(Q,S,V,request,held,collaborators,auth['fingerprint'],modules=modules,
                        host_catalogs=host_catalogs,check_authority=check)==foundation_sha)
                    check()
        S.require_released(collaborators)
    S.require_released(collaborators)
    Q.require(completed(F,P,state,request,request_raw,worker_sha,predecessor,current_session=arguments.session)==saved)
    print('Completed preparation rechecked; original configuration, repository and runtime records preserved.')
