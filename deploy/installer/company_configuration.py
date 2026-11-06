"""Execute configuration and runtime placement before signed source retention.

The independently delivered company worker owns this module, its original
FullEntry/source/assembly and the live Bash parent. The administrator supplies
business configuration through the existing protected wizard, never a callback
or execution grant. This stage starts no containers and initializes no quota
journals. Failed or interrupted outputs stay in place for reconciliation.
"""
import hashlib
import json
import os
import getpass
from pathlib import Path
import re
from types import ModuleType
import urllib.parse
import warnings
import stat

STAGE = 'company-configuration'
CONFIGS = ('images.lock.json', 'runtime-manifest.json', 'approved-mirrors.json')
BOOTSTRAP = 'scripts/bootstrap.py'
LAYOUT = 'scripts/runtime_layout.py'
STARTUP = 'scripts/startup_binding.py'
UNITS = ('autosoft.service', 'autosoft-quota.service', 'autosoft-security.service',
    'autosoft-log-retention.service', 'autosoft-certificates.service', 'autosoft-logs.service',
    'autosoft-backup.service', 'autosoft-incremental.service', 'autosoft-restore-verify.service',
    'autosoft-security.timer', 'autosoft-certificates.timer', 'autosoft-log-retention.timer',
    'autosoft-logs.timer', 'autosoft-backup.timer', 'autosoft-incremental.timer',
    'autosoft-restore-verify.timer')


def require(value):
    if value is not True:
        raise ValueError('company-configuration-unavailable; preserve partial configuration')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def action(request_raw, worker_sha256):
    require(type(request_raw) is bytes and 0 < len(request_raw) <= 4096
            and type(worker_sha256) is str
            and re.fullmatch('[a-f0-9]{64}', worker_sha256) is not None)
    return sha(b'company-configuration-v1:' + sha(request_raw).encode() + b':' + worker_sha256.encode())


def collect_answers():
    """Company-owned IT questionnaire, before any bounded native context opens.

    Values stay in memory and are consumed once by the original signed wizard.
    This function performs no filesystem writes and accepts no callback/code.
    """
    answers = {}
    def ask(label, default='', sensitive=False):
        prompt = label + (' [' + default + ']' if default else '') + ': '
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = (getpass.getpass(prompt) if sensitive else input(prompt)).strip()
        value = value if value else default
        require(len(value) <= 16384 and '\0' not in value)
        answers[label] = value
        return value
    ask('Administrative HTTPS URL')
    apps = ask('Applications HTTPS base URL')
    hostname = urllib.parse.urlsplit(apps).hostname
    require(type(hostname) is str)
    ask('Identity HTTPS URL', 'https://auth.' + hostname)
    mode = ask('Certificate mode: selfsigned/route53/gcloud/cpanel', 'selfsigned')
    require(mode in ('selfsigned', 'route53', 'gcloud', 'cpanel'))
    sso = ask('SSO providers: none/microsoft/google/both', 'none')
    require(sso in ('none', 'microsoft', 'google', 'both'))
    ask('Per-job API spending limit USD', '10')
    ask('Monthly API spending limit USD', '200')
    if mode != 'selfsigned': ask('ACME certificate contact email')
    ask('Optional off-VM mounted backup directory (local backups always retained 30 days)')
    ask('Unused private IPv4 pool for application networks (CIDR /16 through /24; confirm with your network administrator)')
    ask('Schedule timezone (IANA name)', 'UTC')
    if ask('Optional security notification recipient email (blank disables email)'):
        ask('SMTP host (verified STARTTLS required)'); ask('SMTP STARTTLS port', '587')
        ask('SMTP sender email'); ask('SMTP username (blank for relay)')
        ask('SMTP password (optional for relay)', sensitive=True)
    if sso in ('microsoft', 'both'): ask('Microsoft tenant UUID')
    if sso in ('google', 'both'): ask('Allowed Google Workspace domain')
    ask('OpenAI API key (optional)', sensitive=True)
    ask('Anthropic API key (optional)', sensitive=True)
    ask('Company-approved model catalog JSON path')
    if ask('Company image registry hostname requiring login (optional)'):
        ask('Company registry username'); ask('Company registry password/token', sensitive=True)
    for provider in ('microsoft', 'google'):
        if sso in (provider, 'both'):
            ask(provider.title() + ' OAuth client ID')
            ask(provider.title() + ' OAuth client secret', sensitive=True)
    if mode == 'route53':
        for key in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'AWS_HOSTED_ZONE_ID'):
            ask(key, sensitive='SECRET' in key)
    elif mode == 'gcloud':
        ask('Google Cloud project ID'); ask('Google DNS service-account JSON path')
    elif mode == 'cpanel':
        for key in ('CPANEL_BASE_URL', 'CPANEL_USERNAME', 'CPANEL_TOKEN'):
            ask(key, sensitive=key.endswith('TOKEN'))
    return answers


def _bound(entry, F, held, assembly, parent, request, request_raw, worker_sha256):
    # An exact original object is mandatory before invoking its methods.
    require(type(F) is ModuleType and type(entry) is F.FullEntry)
    F.FullEntry.recheck(entry)
    V, P, L = (entry.modules[path] for path in (F.VERIFIER, F.PARENT, F.LOADER))
    require(V.require_platform_source(held) is held
            and type(assembly) is L.FreshInstallationAssembly
            and assembly._entry is entry.origin and assembly._source is held
            and type(parent) is P.HeldParent and parent.live)
    L.FreshInstallationAssembly.recheck(assembly)
    require(canonical(request) == request_raw and request['mode'] == 'full-installation'
            and request['releaseSha256'] == held.metadata['releaseSha256'])
    require(parent.arguments.request == sha(request_raw)
            and parent.arguments.stage == STAGE
            and parent.arguments.action == action(request_raw, worker_sha256))
    P.HeldParent.check(parent)
    return assembly.modules


def quiet(command):
    """Require all application writers absent; never stop or repair them."""
    fields = ('ActiveState', 'SubState', 'MainPID', 'ControlPID', 'ControlGroup', 'LoadState')
    for unit in UNITS:
        selected = ('ActiveState', 'SubState', 'LoadState') if unit.endswith('.timer') else fields
        raw = command(['/usr/bin/systemctl', 'show', *['--property=' + name for name in selected], '--', unit])
        require(type(raw) is str and len(raw) <= 65536)
        pairs = [line.split('=', 1) for line in raw.splitlines()]
        require(len(pairs) == len(selected) and all(len(row) == 2 for row in pairs)
                and len({row[0] for row in pairs}) == len(selected))
        state = dict(pairs)
        require(set(state) == set(selected) and state['ActiveState'] in ('inactive', 'failed')
                and state['SubState'] in ('dead', 'failed') and state['LoadState'] in ('loaded', 'not-found'))
        if unit.endswith('.service'):
            require(state['MainPID'] == state['ControlPID'] == '0' and state['ControlGroup'] == '')
    require(command(['/usr/bin/docker', 'ps', '-aq', '--no-trunc']) == '')


def wizard_outputs(data, configuration, *, durable):
    """Remeasure every wizard file without returning any credential content.

    Exact signed catalogs are checked separately. The model catalog is an
    operator-supplied input here, not a company qualification receipt. Optional
    output presence participates in this digest, so deletion cannot disappear
    from a later verification. Native file/parent fsync precedes execution proof.
    """
    require(type(durable) is bool)
    data = Path(data)
    device = data.lstat().st_dev
    required = {'config/models.json', 'secrets/platform/openai-key',
                'secrets/platform/anthropic-key', 'secrets/dns.env'}
    expected_directories = {'secrets', *('secrets/' + name for name in
        ('platform', 'mysql', 'keycloak', 'registry', 'runtime', 'packager', 'grafana', 'dns'))}
    if configuration.get('company_registry'):
        required.add('secrets/docker-client/config.json')
        expected_directories.add('secrets/docker-client')
    for provider in ('microsoft', 'google'):
        if configuration['sso'] in (provider, 'both'):
            required.add('secrets/keycloak/' + provider + '-client-secret')
    if configuration['certificate_mode'] == 'gcloud': required.add('secrets/dns/gcloud.json')
    if configuration.get('notification_email'):
        required.add('secrets/notifications/smtp-password')
        expected_directories.add('secrets/notifications')
    observed, directories = set(), []
    for parent, children, leaves in os.walk(data / 'secrets', followlinks=False):
        current = Path(parent)
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o700 and info.st_dev == device)
        require(current.relative_to(data).as_posix() in expected_directories)
        directories.append(current)
        require(len(directories) <= 24 and len(children) <= 16 and len(leaves) <= 16)
        for child in children:
            child_info = (current / child).lstat()
            require(stat.S_ISDIR(child_info.st_mode) and not stat.S_ISLNK(child_info.st_mode))
        observed.update((current / name).relative_to(data).as_posix() for name in leaves)
    observed.add('config/models.json')
    require(observed == required
            and {path.relative_to(data).as_posix() for path in directories} == expected_directories)
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    identity = lambda info: tuple(getattr(info, key) for key in keys)
    rows, populated_model_key, total = {}, False, 0
    for name in sorted(observed):
        path = data / name
        before = path.lstat()
        uid = 1000 if name.startswith('secrets/keycloak/') else 0
        mode = 0o644 if name == 'config/models.json' else 0o600
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == uid
                and before.st_dev == device and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == mode and 0 <= before.st_size <= 1024 ** 2)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            require(identity(os.fstat(fd)) == identity(before))
            raw = bytearray()
            while len(raw) < before.st_size:
                chunk = os.read(fd, min(65536, before.st_size - len(raw)))
                require(bool(chunk)); raw.extend(chunk)
            require(os.read(fd, 1) == b'')
            total += len(raw); require(total <= 4 * 1024 ** 2)
            if name in ('secrets/platform/openai-key', 'secrets/platform/anthropic-key'):
                populated_model_key |= bool(raw)
            if name == 'config/models.json': require(type(json.loads(raw)) is dict)
            if durable: os.fsync(fd)
            require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()))
            rows[name] = dict(identity=identity(before), sha256=sha(raw))
        finally:
            os.close(fd)
    require(populated_model_key)
    for path in sorted(set(directories + [data / 'config', data]), key=lambda p: -len(p.parts)):
        before = path.lstat()
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
                and not stat.S_IMODE(before.st_mode) & 0o022 and before.st_dev == device)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require(identity(os.fstat(fd)) == identity(before))
            if durable: os.fsync(fd)
            require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()))
            if path in directories:
                rows[path.relative_to(data).as_posix()] = dict(directoryIdentity=identity(before)[:5])
        finally:
            os.close(fd)
    return sha(canonical(rows))


def run(entry, *, full_entry_module, held, assembly, parent, request, request_raw,
        worker_sha256, command, execute, host_directory=Path('/etc/autosoft'), answers=None):
    """Perform the actual original configure/placement calls, or remeasure them.

    command is the fixed company's bounded read-only command supervisor. The
    caller owns all source/parent/native lifetimes and observes successful child
    exit before separate verification and admission confirmation. Returned JSON
    is an observation, not an effect issuer or a full-install completion flag.
    """
    require(type(execute) is bool and callable(command) and Path(host_directory) == Path('/etc/autosoft'))
    require(not execute or type(answers) is dict)
    check = lambda: _bound(entry, full_entry_module, held, assembly, parent, request,
                          request_raw, worker_sha256)
    modules = check()
    B, R, S = (modules[path] for path in (BOOTSTRAP, LAYOUT, STARTUP))
    data = Path(request['dataDir'])
    root = data / 'company/host-releases' / ('install-' + request['operationId'])
    files = R.NativeFiles()
    files.require_root()
    host = S.I.verify_host_record(host_directory, files=files)
    intent = S.I.read_intent(host_directory, files=files)
    receipt = files.read(host_directory / 'installation.storage-receipt.json')
    require(host == {key: receipt[key] for key in host}
            and host['data_dir'] == str(data) and host['install_root'] == str(root)
            and host['storage_file'] == request['backingFile']
            and intent['proposal']['capacity_gib'] == request['capacityGiB']
            and receipt['creation_stage'] == 'new-luks-created'
            and not os.path.lexists(host_directory / 'installation.pending.json')
            and not os.path.lexists(host_directory / 'installation.complete'))
    mount = S.encrypted_proof(data, receipt, command=command)
    quiet(command)
    check()
    if execute:
        # One admission attempt only. A final config alone cannot justify
        # replaying prompts or changing partial secrets/layout from a prior try.
        for path in (data / 'config', data / 'secrets', data / 'quota'):
            require(not os.path.lexists(path))
        files.mkdir(data / 'config')
        captured = dict(fingerprint=held.metadata['signingKeyFingerprint'],
                        configs={name: held.configs[name] for name in CONFIGS})
        assembly.call(BOOTSTRAP, 'configure', data, root, files=files,
                      host_directory=host_directory, captured_release=captured, answers=answers)
        check()
        require(S.encrypted_proof(data, receipt, command=command) == mount)
        quiet(command)
        assembly.call(LAYOUT, 'prepare', data, files=files,
                      build_mount=lambda path: R.builds_proof(path, command=command))
        files.mkdir(data / 'config/repository-seed')
    check()
    quiet(command)
    require(S.encrypted_proof(data, receipt, command=command) == mount)
    configuration = files.read(data / 'config/installation.json')
    identifier = S.I.verify_reference(intent, configuration)
    require(configuration['company_public_fingerprint'] == held.metadata['signingKeyFingerprint'])
    for name in CONFIGS:
        # All three are newly issued exact signed bytes, with no env/path fallback.
        path = data / 'config' / name
        before = files.protected(path, private=name == 'approved-mirrors.json')
        require(path.read_bytes() == held.configs[name])
        files.compare_opened(before, path.lstat())
    placement = assembly.call(LAYOUT, 'verify', data, files=files,
                    build_mount=lambda path: R.builds_proof(path, command=command))
    require(placement['changed'] is False and placement['backupReady'] is False)
    files.protected(data / 'config/repository-seed', directory=True, private=True)
    require(files.inventory(data / 'config/repository-seed', 0) == [])
    for name in R.BROKER_DIRECTORIES:
        require(files.names(data / 'runtime' / name, 0) == [])
    outputs_sha = wizard_outputs(data, configuration, durable=execute)
    check()
    return dict(schemaVersion=1, scope='COMPANY_CONFIGURATION_AND_PLACEMENT_ONLY',
        requestSha256=sha(request_raw), actionSha256=action(request_raw, worker_sha256),
        releaseSha256=request['releaseSha256'], installationId=identifier,
        configurationSha256=sha(canonical(configuration)), encryptedMountSha256=sha(canonical(mount)),
        layoutSha256=sha(canonical(files.read(data / 'config/runtime-layout/layout.json'))),
        signedConfigurationSha256=sha(canonical({name: sha(held.configs[name]) for name in CONFIGS})),
        wizardOutputsSha256=outputs_sha, modelCatalogSource='operator-supplied',
        servicesStarted=False, runtimePairInitialized=False, fullInstallationCompleted=False,
        outerContextsRequireClosure=True)
