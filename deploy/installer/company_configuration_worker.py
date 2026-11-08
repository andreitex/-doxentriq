"""Native configuration dispatch for the separately authenticated company worker.

The fixed Bash parent observes child exit and confirms only a separate native
remeasurement. No caller-supplied success JSON authorizes writing or replay.
"""
import os
import json
from pathlib import Path
import stat


def host_observation(modules, catalogs, check_authority):
    """Own authenticated catalogs and current host readback; no inherited JSON authority."""
    H, P, K, S, F = (modules[name] for name in ('host_package_runtime', 'host_tool_profiles',
        'host_packages', 'station', 'foundation_worker'))
    def check():
        H.require(not F.UNKNOWN and not S.UNRELEASED)
        check_authority()
    check()
    with H.held_platform(S) as (observed, recheck):
        package, tools = H.bindings(catalogs, profiles=P, packages=K, observed_platform=observed,
            engine=modules.get('engine_packages'),engine_native=modules.get('engine_native'))
        recheck(); check()
    current = H.readback(package, tools, station=S, runner=F.NativeRunner(), check_authority=check,
        engine=modules.get('engine_packages'),engine_native=modules.get('engine_native'),engine_elf=modules.get('engine_elf'))
    check()
    return H, package, tools, current


def foundation_record_version(value):
    """Read-only classification; legacy proof never enters the new execution path."""
    if type(value) is dict and 'schemaVersion' not in value and 'hostPackages' not in value:
        return 'legacy-unpinned'
    if type(value) is dict and type(value.get('schemaVersion')) is int and value['schemaVersion'] == 2:
        return 'pinned-v2'
    return 'unsupported'


def foundation(Q, S, V, request, held, collaborators, fingerprint, *, modules, host_catalogs, check_authority):
    """Bind the real confirmed schema3 foundation to this schema4 source.

    The installed foundation's signed 54 host/template files and five catalogs
    must exactly equal the corresponding complete-source release bytes. A
    result or marker without that original signed source is insufficient.
    """
    H, package, tools, current = host_observation(modules, host_catalogs, check_authority)
    root = request['dataDir'] + '/company/host-releases/install-' + request['operationId']
    evidence = '/opt/autosoft-company/evidence/' + request['operationId']
    raw = {name: S.read_protected(evidence + '/' + name, 32768)
           for name in ('intent.json', 'result.json', 'verified')}
    initial, result = (json.loads(raw[name]) for name in ('intent.json', 'result.json'))
    Q.require(Q.canonical(initial) == raw['intent.json'] and Q.canonical(result) == raw['result.json']
        and set(initial) == set(request) and initial['schemaVersion'] == 1 and initial['mode'] == 'foundation-only')
    for name in ('operationId', 'dataDir', 'backingFile', 'capacityGiB', 'runscVersion', 'runscSha512', 'keyPath'):
        Q.require(initial[name] == request[name])
    with V.authenticated_deployment(root + '/company-release', request['keyPath'], fingerprint,
            expected_architecture='x86_64', source_root=root, files=collaborators['files'],
            crypto=collaborators['crypto'], owner_uid=0, owner_gid=0) as previous:
        V.require_platform_source(held)
        previous.recheck()
        Q.require(initial['releaseSha256'] == previous.metadata['releaseSha256'])
        for group in (previous.sources, previous.templates):
            Q.require(all(held.files[name] == value for name, value in group.items()))
        Q.require(all(held.configs[name] == value for name, value in previous.configs.items()))
        rows = {name: value for group in (previous.sources, previous.templates) for name, value in group.items()}
        rows.update({'company-release/' + name: value for group in (previous.configs, previous.provenance)
                     for name, value in group.items()})
        expected_tree = Q.sha(Q.canonical({name: dict(bytes=len(value), sha256=Q.sha(value))
            for name, value in sorted(rows.items())}))
        host = {name: json.loads(S.read_protected('/etc/autosoft/' + name, 32768))
                for name in ('installation.intent.json', 'installation.json', 'installation.storage-receipt.json')}
        H.require(foundation_record_version(result) == 'pinned-v2', 'Pinned foundation package evidence is required; legacy records are retained for IT inspection')
        Q.require(set(result) == {'schemaVersion', 'hostPackages', 'scope', 'status', 'operationId', 'installationId', 'releaseSha256',
            'treeSha256', 'hostSha256', 'runscVersionSha256', 'runtimeBinaryPins',
            'fullPlatformActivated', 'backupReady', 'runtimePairInitialized'})
        H.verify_evidence(result['hostPackages'], package, tools, current=current,engine_native=modules.get('engine_native'))
        Q.require(result['scope'] == 'FOUNDATION_ONLY' and result['status'] == 'effects-independently-confirmed'
            and result['operationId'] == request['operationId']
            and result['installationId'] == host['installation.json']['installation_id']
            and result['releaseSha256'] == initial['releaseSha256'] and result['treeSha256'] == expected_tree
            and result['hostSha256'] == Q.sha(Q.canonical(host))
            and all(result[name] is False for name in ('fullPlatformActivated', 'backupReady', 'runtimePairInitialized')))
        Q.require(raw['verified'] == ('foundation-verified-v1\noperation=' + request['operationId']
            + '\noutcome=' + Q.sha(raw['result.json']) + '\n').encode())
        previous.recheck(); V.require_platform_source(held)
        Q.require(all(S.read_protected(evidence + '/' + name, 32768) == value for name, value in raw.items()))
        value = Q.sha(Q.canonical({name: Q.sha(value) for name, value in raw.items()}))
    # Close the original legacy source before creating siblings of its encrypted
    # data ancestry. A new independent invocation reauthenticates it afterward;
    # no held-directory timestamp is refreshed or quietly adopted.
    return value


def run(command, modules, delivery, auth, request, request_raw, worker_sha256, parent_args, *, host_catalogs=None):
    Q, S, C, R = (modules[name] for name in ('configuration', 'station', 'cli', 'records'))
    expected_action = Q.action(request_raw, worker_sha256)
    if command == 'configuration-action':
        Q.require(parent_args is None)
        # Before stage effects and questionnaire: validate the own captured catalogs.
        H = modules['host_package_runtime']
        with H.held_platform(S) as (observed, recheck):
            H.bindings(host_catalogs, profiles=modules['host_tool_profiles'], packages=modules['host_packages'], observed_platform=observed,
                engine=modules.get('engine_packages'),engine_native=modules.get('engine_native'))
            recheck()
        print(expected_action)
        return
    Q.require(command in ('configure-foundation', 'verify-configuration') and parent_args is not None)
    operation = '/opt/autosoft-company/evidence/' + request['operationId']
    directory = operation + '/' + Q.STAGE
    execute = command == 'configure-foundation'
    # Human interaction owns no source/native deadlines and has no host effects.
    # The mutation path consumes exactly this bounded data after authentication.
    answers = Q.collect_answers() if execute else None
    result = collaborators = None
    # No mutation occurs before live parent/source admission in the contexts below.
    with C.authenticated_cli(delivery, **auth) as controller:
        originals = controller.original_modules
        F, V, P, entry = (originals[name] for name in ('full_entry', 'verifier', 'parent', 'entry'))
        collaborators = S.stage_inputs(controller, request_raw, modules['crypto'])
        parent_input = P.ParentInput.from_argv(parent_args)
        Q.require(parent_input.stage == Q.STAGE and parent_input.request == Q.sha(request_raw)
                  and parent_input.action == expected_action)
        with P.hold_parent(parent_input, system=collaborators['parent_system']) as parent:
            with V.authenticated_platform_source(request['bundleRoot'], request['keyPath'], auth['fingerprint'],
                    expected_architecture='x86_64', source_root=request['sourceRoot'],
                    files=collaborators['files'], crypto=collaborators['crypto'], owner_uid=0, owner_gid=0) as held:
                with entry.fresh_installation_modules(held) as assembly:
                    B = assembly.modules[Q.BOOTSTRAP]
                    commands = B.SeedCommands(collaborators['runner_module'], collaborators['runner'])
                    def check_host_authority():
                        parent.check(); held.recheck()
                    foundation_sha = foundation(Q, S, V, request, held, collaborators, auth['fingerprint'],
                        modules=modules, host_catalogs=host_catalogs, check_authority=check_host_authority)
                    if execute:
                        # Existing operation evidence belongs to the verified foundation.
                        with R.directory(operation) as (fd, check):
                            os.mkdir(Q.STAGE, 0o700, dir_fd=fd)
                            os.fsync(fd); check()
                        write(R, directory, 'intent.json', Q.canonical(dict(
                            requestSha256=Q.sha(request_raw), actionSha256=expected_action,
                            session=parent_input.session, workerSha256=worker_sha256)))
                    else:
                        intended = S.read_protected(directory + '/intent.json', 4096)
                        Q.require(intended == Q.canonical(dict(requestSha256=Q.sha(request_raw),
                            actionSha256=expected_action, session=parent_input.session, workerSha256=worker_sha256)))
                        # A failed execute child cannot be made successful by verification.
                        S.read_protected(directory + '/executed.json', 32768)
                    result = Q.run(entry, full_entry_module=F, held=held, assembly=assembly, parent=parent,
                        request=request, request_raw=request_raw, worker_sha256=worker_sha256,
                        command=commands.text, execute=execute, answers=answers)
                    Q.require(foundation(Q, S, V, request, held, collaborators, auth['fingerprint'],
                        modules=modules, host_catalogs=host_catalogs, check_authority=check_host_authority) == foundation_sha)
                    result['foundationEvidenceSha256'] = foundation_sha
                    parent.check()
        S.require_released(collaborators)
    S.require_released(collaborators)
    raw = Q.canonical(result)
    if execute:
        write(R, directory, 'executed.json', raw)
        print('Configuration and runtime placement written; independent verification is required.')
    else:
        Q.require(S.read_protected(directory + '/executed.json', 32768) == raw)
        write_observation(R, S, directory, 'verified.json', raw)
        marker = ('configuration-verified-v1\nrequest=' + Q.sha(request_raw) + '\nsession=' + parent_args[3]
            + '\nstage=' + Q.STAGE + '\naction=' + expected_action + '\noutcome=' + Q.sha(raw) + '\n').encode()
        write_observation(R, S, directory, 'confirmation', marker, mode=0o600)


def write_observation(R, S, directory, name, raw, *, mode=0o400):
    """Persist a newly remeasured verification without replacing prior bytes.

    Call only after original source/parent/current-effect verification. Existing
    exact records may finish an interrupted verification; mismatches remain for
    IT inspection. This cannot replay an execute operation or mint its evidence.
    """
    R.require(name in ('verified.json', 'confirmation') and type(raw) is bytes
        and 0 < len(raw) <= 32768 and mode == (0o600 if name == 'confirmation' else 0o400))
    target = Path(directory) / name
    if not os.path.lexists(target):
        return write(R, directory, name, raw, mode=mode)
    with R.directory(directory) as (parent, check):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        R.require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode)
        R.require(S.read_protected(target, 32768) == raw)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        R.require(all(getattr(before, key) == getattr(after, key) for key in fields))
        check()


def write(R, directory, name, raw, *, mode=0o400):
    """Exclusive protected record write; never replace interrupted evidence."""
    R.require(name in ('intent.json', 'executed.json', 'verified.json', 'confirmation')
              and type(raw) is bytes and 0 < len(raw) <= 32768
              and mode == (0o600 if name == 'confirmation' else 0o400))
    with R.directory(directory) as (parent, check):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                R.require(type(count) is int and count > 0)
                offset += count
            os.fchmod(fd, mode); os.fsync(fd)
            info = os.fstat(fd)
            R.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
                and info.st_size == len(raw) and os.pread(fd, len(raw) + 1, 0) == raw)
            now = os.stat(name, dir_fd=parent, follow_symlinks=False)
            R.require((now.st_dev, now.st_ino) == (info.st_dev, info.st_ino))
            os.fsync(parent); check()
        finally:
            try:
                os.close(fd)
            except BaseException:
                R.UNKNOWN.append(fd)
                raise
