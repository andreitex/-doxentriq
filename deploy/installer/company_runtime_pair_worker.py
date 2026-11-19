"""Native fresh runtime-pair dispatch through the original captured APIs.

No arbitrary adapter, path, success record or authorization boolean is accepted
from an administrator. The company package selects the actual native collaborators.
The original parent adapter remains one-use; nativeAuthorized stays false.
"""
from pathlib import Path
import os
import time

STAGE = 'fresh-runtime-pair'
PAIR = 'scripts/runtime_pair_init.py'


def native_inputs(R, commands):
    """Wire every native observation to the fixed company command supervisor."""
    S, Q, C, A = R.S, R.Q, R.C, R.A
    files = R.NativeFiles()
    files.require_root()
    def layout(data, *, files):
        return S.L.verify(data, files=files,
            build_mount=lambda path: S.L.builds_proof(path, command=commands.text))
    return dict(host_directory=Path('/etc/autosoft'), files=files, command=commands.text,
        mount=S.encrypted_proof, layout=layout, quota_mount=Q.mount_proof,
        gate_factory=C.Gate, allocation_factory=A.Allocation,
        read_state=Q.load_state, write_state=Q.save_state, clock=time.monotonic, timeout=50)


def storage_inputs(inputs):
    return {key: inputs[key] for key in ('host_directory','files','command','mount','layout')}


def proposal(R, proof):
    return dict(stage=R.STAGE, installationId=proof['installationId'],
        storageProofSha256=R.C.digest(proof), dataRootSha256=proof['dataRootSha256'])


def action(R, request_raw, worker_sha256, pair_request):
    import hashlib
    R.C.hash_value(worker_sha256)
    return hashlib.sha256(b'full-runtime-pair-v1:' + hashlib.sha256(request_raw).hexdigest().encode()
        + b':' + worker_sha256.encode() + b':' + R.C.digest(pair_request).encode()).hexdigest()


def stage_records(R, files, stage):
    """Measure exact immutable native records, including their actual inodes."""
    C = R.C
    expected = {'intent.json','gate-confirmed.json','allocation-confirmed.json','confirmed.json'}
    directory = C.directory_binding(files.protected(stage,directory=True,private=True))
    C.require(set(files.inventory(stage,4)) == expected)
    values, bindings = {}, {}
    for name in sorted(expected):
        path = stage/name
        before = files.protected(path,private=True)
        value = R._record(files,path)
        raw = files.read_bytes(path,C.MAX_RECORD)
        C.require(raw == C.canonical(value)+b'\n' and C.identity(files.protected(path,private=True)) == C.identity(before))
        values[name] = value
        bindings[name] = dict(identity=list(C.identity(before)),rawSha256=__import__('hashlib').sha256(raw).hexdigest())
    C.require(directory == C.directory_binding(files.protected(stage,directory=True,private=True))
        and set(files.inventory(stage,4)) == expected)
    return values,C.digest(dict(directory=directory,records=bindings))


def inspect_completed(R, data, root, *, authority, inputs):
    """Remeasure the existing pair, never replay initialization or adopt partials.

    The historical gate-only digest is bound by the closed execute child's
    immutable record aggregate. Its pre-allocation empty history cannot be
    reproduced by pretending the now-completed allocation operation is absent.
    Current pair/startup state is independently inspected by the original APIs.
    """
    S,C = R.S,R.C
    data,root = Path(data),Path(root)
    files,clock = inputs['files'],inputs['clock']
    deadline = clock()+inputs['timeout']
    stage = data/'config/runtime-pair-initialization'
    with S.fresh_storage_context(data,root,**storage_inputs(inputs)) as proof:
        request = proposal(R,proof)
        with authority.hold(S.json_copy(request)) as parent:
            R._parent(authority,request,parent)
            records,digest = stage_records(R,files,stage)
            intent = dict(schemaVersion=1,scope=R.SCOPE,installationId=proof['installationId'],
                dataRootSha256=proof['dataRootSha256'],
                directory=C.directory_binding(files.protected(stage,directory=True,private=True)),
                parentSha256=C.digest(parent),requestSha256=C.digest(request),storageProofSha256=C.digest(proof),
                absence=dict(quota=[],storage=[],pairAbsent=True,stageAbsent=True),
                expectedProjectsSha256=R.EMPTY_STATE_SHA256,expectedProjectsRawSha256=R.EMPTY_RAW_SHA256)
            C.require(records['intent.json']==intent)
            gate_record = C.fields(records['gate-confirmed.json'],{'intentSha256','gateSha256'})
            C.require(gate_record['intentSha256']==C.digest(intent));C.hash_value(gate_record['gateSha256'])
            pair = R._pair(files,data,inputs['gate_factory'](data),inputs['allocation_factory'](data),
                proof['installationId'],proof['mountSource'],inputs['read_state'],deadline-clock())
            R._parent(authority,request,parent)
            C.require(records['allocation-confirmed.json']==dict(intentSha256=C.digest(intent),pairSha256=C.digest(pair)))
            selected={key:inputs[key] for key in ('host_directory','files','command','mount','layout',
                'gate_factory','allocation_factory','read_state','clock')}
            final=S.verify(data,root,**selected,timeout=deadline-clock())
            expected=dict(scope=R.SCOPE,status='effects-confirmed',installationId=proof['installationId'],
                intentSha256=C.digest(intent),pairSha256=C.digest(pair),startupSha256=C.digest(final),
                authorization=R.QUALIFICATION,nativeAuthorized=False,backupReady=False)
            C.require(records['confirmed.json']==expected)
            C.require(R._pair(files,data,inputs['gate_factory'](data),inputs['allocation_factory'](data),
                proof['installationId'],proof['mountSource'],inputs['read_state'],deadline-clock())==pair)
            C.require(stage_records(R,files,stage)==(records,digest))
            R._parent(authority,request,parent)
    return expected,digest


def run(command, modules, delivery, auth, request, request_raw, worker_sha256, parent_args):
    S,C,Q,W,A = (modules[name] for name in ('station','cli','configuration','configuration_worker','runtime_pair_parent'))
    Q.require(command in ('runtime-pair-action','initialize-runtime-pair','verify-runtime-pair'))
    planning,execute = command=='runtime-pair-action',command=='initialize-runtime-pair'
    Q.require((parent_args is None) is planning and not A.UNCONFIRMED)
    data=Path(request['dataDir'])
    root=data/'company/host-releases'/('install-'+request['operationId'])
    operation='/opt/autosoft-company/evidence/'+request['operationId']
    directory=operation+'/'+STAGE
    collaborators=result=None
    expected_action=None
    with C.authenticated_cli(delivery,**auth) as controller:
        originals=controller.original_modules
        F,V,P,entry=(originals[name] for name in ('full_entry','verifier','parent','entry'))
        collaborators=S.stage_inputs(controller,request_raw,modules['crypto'])
        with V.authenticated_platform_source(request['bundleRoot'],request['keyPath'],auth['fingerprint'],
                expected_architecture='x86_64',source_root=request['sourceRoot'],files=collaborators['files'],
                crypto=collaborators['crypto'],owner_uid=0,owner_gid=0) as held:
            with entry.fresh_installation_modules(held) as assembly:
                R=assembly.modules[PAIR]
                B=assembly.modules['scripts/bootstrap.py']
                commands=B.SeedCommands(collaborators['runner_module'],collaborators['runner'])
                inputs=native_inputs(R,commands)
                Q.quiet(commands.text)
                with R.S.fresh_storage_context(data,root,**storage_inputs(inputs)) as proof:
                    pair_request=proposal(R,proof)
                    expected_action=action(R,request_raw,worker_sha256,pair_request)
                    if planning or execute:
                        R._fresh(inputs['files'],data,data/'config/runtime-pair-initialization')
                if not planning:
                    arguments=P.ParentInput.from_argv(parent_args)
                    Q.require(arguments.stage==STAGE and arguments.request==Q.sha(request_raw)
                        and arguments.action==expected_action)
                    with P.hold_parent(arguments,system=collaborators['parent_system']) as parent:
                        intended=Q.canonical(dict(requestSha256=Q.sha(request_raw),actionSha256=expected_action,
                            session=arguments.session,workerSha256=worker_sha256))
                        if execute:
                            with modules['records'].directory(operation) as (fd,check):
                                os.mkdir(STAGE,0o700,dir_fd=fd);os.fsync(fd);check()
                            W.write(modules['records'],directory,'intent.json',intended)
                        else:
                            Q.require(S.read_protected(directory+'/intent.json',4096)==intended)
                            S.read_protected(directory+'/executed.json',32768)
                        with A.hold_runtime_pair_parent(entry,full_entry_module=F,assembly=assembly,parent=parent,
                                installation_request_sha256=Q.sha(request_raw),full_worker_sha256=worker_sha256) as authority:
                            if execute:
                                pair_result=assembly.call(PAIR,'initialize',data,root,authority=authority,**inputs)
                                measured,records_sha=stage_records(R,inputs['files'],data/'config/runtime-pair-initialization')
                                Q.require(measured['confirmed.json']==pair_result)
                            else:
                                pair_result,records_sha=inspect_completed(R,data,root,authority=authority,inputs=inputs)
                        Q.require(not A.UNCONFIRMED and not A._ISSUED and not A._TYPES)
                        parent.check();V.require_platform_source(held)
                        Q.quiet(commands.text)
                        result=dict(scope='NATIVE_RUNTIME_PAIR_STAGE_ONLY',requestSha256=Q.sha(request_raw),
                            actionSha256=expected_action,session=arguments.session,workerSha256=worker_sha256,
                            releaseSha256=held.metadata['releaseSha256'],pairResult=pair_result,
                            stageRecordsSha256=records_sha,fullInstallationActivated=False,backupReady=False)
                V.require_platform_source(held)
        S.require_released(collaborators)
    S.require_released(collaborators)
    if planning:
        print(expected_action)
        return
    raw=Q.canonical(result)
    if execute:
        W.write(modules['records'],directory,'executed.json',raw)
        print('Runtime admission and quota pair initialized; separate read-only verification is required.')
    else:
        Q.require(S.read_protected(directory+'/executed.json',32768)==raw)
        W.write_observation(modules['records'],S,directory,'verified.json',raw)
        marker=('runtime-pair-verified-v1\nrequest='+Q.sha(request_raw)+'\nsession='+parent_args[3]
            +'\nstage='+STAGE+'\naction='+expected_action+'\noutcome='+Q.sha(raw)+'\n').encode()
        W.write_observation(modules['records'],S,directory,'confirmation',marker,mode=0o600)
