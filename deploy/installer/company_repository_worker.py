"""Company packaged repository seed stage, retaining original source authority.

This is not stored-source startup or platform activation. The fixed parent
waits for execute exit, requests a distinct read-only verification child and
confirms only the exact closed observation. Partial output is never replayed.
"""
from contextlib import ExitStack
import os

STAGE = 'repository-seed'
BOOTSTRAP = 'scripts/bootstrap.py'
STARTUP = 'scripts/startup_binding.py'


def run(command, modules, delivery, auth, request, request_raw, worker_sha256, parent_args):
    N, S, C, R, Q, W = (modules[name] for name in
        ('repository_io', 'station', 'cli', 'records', 'configuration', 'configuration_worker'))
    N.require(command in ('repository-action', 'seed-repository', 'verify-repository'))
    planning, execute = command == 'repository-action', command == 'seed-repository'
    N.require((parent_args is None) is planning)
    operation = '/opt/autosoft-company/evidence/' + request['operationId']
    directory = operation + '/' + STAGE
    data = request['dataDir']
    install_root = data + '/company/host-releases/install-' + request['operationId']
    collaborators = backend = files = runner = None
    result = action = None
    try:
        with C.authenticated_cli(delivery, **auth) as controller:
            originals = controller.original_modules
            V, P, entry = (originals[name] for name in ('verifier', 'parent', 'entry'))
            collaborators = S.stage_inputs(controller, request_raw, modules['crypto'], repository_seed=True)
            with ExitStack() as contexts:
                parent = None
                if not planning:
                    arguments = P.ParentInput.from_argv(parent_args)
                    N.require(arguments.stage == STAGE and arguments.request == Q.sha(request_raw))
                    parent = contexts.enter_context(P.hold_parent(arguments, system=collaborators['parent_system']))
                held = contexts.enter_context(V.authenticated_platform_source(request['bundleRoot'],
                    request['keyPath'], auth['fingerprint'], expected_architecture='x86_64',
                    source_root=request['sourceRoot'], files=collaborators['files'],
                    crypto=collaborators['crypto'], owner_uid=0, owner_gid=0))
                assembly = contexts.enter_context(entry.fresh_installation_modules(held))
                B, startup = (assembly.modules[name] for name in (BOOTSTRAP, STARTUP))
                V.require_platform_source(held)
                plan = B._seed_plan(held)
                backend = N.SeedBackend(data=data, install_root=install_root, storage_file=request['backingFile'],
                    operation_id=request['operationId'], plan=plan, broker_directories=startup.L.BROKER_DIRECTORIES,
                    writable=execute)
                if planning: backend.admit_write_capacity()
                files = B.SeedFiles(N, backend)
                installed = S.tool_pin('/usr/bin/git')
                git_pin = dict(path='/usr/bin/git', bytes=installed['bytes'], sha256=installed['sha256'])
                runner = N.SeedRunner(host_runner=collaborators['runner'], backend=backend,
                    repository=data+'/runtime/repository', plan=plan, git_pin=git_pin)
                commands = B.SeedCommands(N, runner)
                git = B.SeedGit(files, commands, git_pin)
                runner.preflight(git.tool)  # No repository/evidence write before capability admission.
                storage = B.SeedStorage(data, install_root, startup_module=startup,
                    files=files, commands=commands, fresh=command != 'verify-repository')
                _, _, action = B.authenticated_seed_request(data, install_root, held,
                    verifier_module=V, storage=storage, git=git, operation_id=request['operationId'],
                    installation_request_sha256=Q.sha(request_raw))
                if planning:
                    N.require(files.names(storage.repository, 0) == [] and files.names(storage.journal, 0) == [])
                else:
                    N.require(arguments.action == action)
                    parent.check()
                    intended = Q.canonical(dict(requestSha256=Q.sha(request_raw), actionSha256=action,
                        session=arguments.session, workerSha256=worker_sha256))
                    if execute:
                        with R.directory(operation) as (fd, check):
                            os.mkdir(STAGE, 0o700, dir_fd=fd); os.fsync(fd); check()
                        W.write(R, directory, 'intent.json', intended)
                    else:
                        N.require(S.read_protected(directory+'/intent.json',4096) == intended)
                        S.read_protected(directory+'/executed.json',32768)
                    outcome = assembly.call(BOOTSTRAP,
                        'seed_authenticated_repository' if execute else 'confirm_authenticated_seed',
                        data, install_root, held, verifier_module=V, parent_module=P, parent=parent,
                        storage=storage, files=files, git=git, operation_id=request['operationId'],
                        installation_request_sha256=Q.sha(request_raw))
                    N.require(outcome['ownedSeedHandlesReleased'] is True)
                    if not execute:
                        N.require(outcome['status'] == 'SEED_CONFIRMED_READONLY'
                            and outcome['preservedHead'] == outcome['seedCommit'] == plan['commit'])
                    result = dict(scope='NATIVE_REPOSITORY_SEED_ONLY', requestSha256=Q.sha(request_raw),
                        actionSha256=action, session=arguments.session, workerSha256=worker_sha256,
                        releaseSha256=held.metadata['releaseSha256'], sourceTree=held.metadata['sourceTree'],
                        seedCommit=plan['commit'], tree=plan['root'], leafCount=len(plan['leaves']),
                        objectCount=len(plan['objects']), gitToolPin=git_pin,
                        fullInstallationActivated=False, runtimePairInitialized=False)
                    parent.check(); V.require_platform_source(held)
                if files.owned: files.close()
                runner.require_released(); backend.finish(); backend.require_released()
            S.require_released(collaborators)
        S.require_released(collaborators)
    finally:
        # Never turn cleanup failure into success or retry a close of unknown state.
        if files is not None and files.owned: files.close()
        if backend is not None and not backend.closed: backend.finish()
    if planning:
        print(action)
        return
    raw = Q.canonical(result)
    if execute:
        W.write(R, directory, 'executed.json', raw)
        print('Repository objects written and verified; separate read-only confirmation is required.')
    else:
        N.require(S.read_protected(directory+'/executed.json',32768) == raw)
        W.write(R, directory, 'verified.json', raw)
        marker = ('repository-verified-v1\nrequest='+Q.sha(request_raw)+'\nsession='+parent_args[3]
            +'\nstage='+STAGE+'\naction='+action+'\noutcome='+Q.sha(raw)+'\n').encode()
        W.write(R, directory, 'confirmation', marker, mode=0o600)
