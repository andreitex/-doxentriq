#!/usr/bin/env python3
"""Fixed MySQL replay clients for an independently extracted recovery candidate.

This helper never starts a database, replaces live data, pulls an image, installs
packages, changes accounts, or emits SQL/passwords. The company must supply the
already scanned, signed and digest-pinned mysql_recovery image.
"""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PIN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$')
CONTAINER_ID = re.compile(r'^[a-f0-9]{64}$')
CANDIDATE_NAME = re.compile(r'^/autosoft-chain-[a-f0-9]{12}$')
BINLOG = re.compile(r'^mysql-bin\.(\d{6,})$')
HOSTS = '127.0.0.1 localhost mysql\n::1 localhost\n'
CLIENT_OPTIONS = ('--defaults-file=/run/recovery/client.cnf --no-login-paths '
                  '--protocol=TCP --host=mysql --port=3306 '
                  '--ssl-mode=VERIFY_IDENTITY --ssl-ca=/run/recovery/ca.crt')
REPLAY_COMMAND = ('set -Eeuo pipefail; '
                  'mysqlbinlog ' + CLIENT_OPTIONS + ' --read-from-remote-server '
                  '--verify-binlog-checksum --disable-log-bin "$@" | '
                  'mysql ' + CLIENT_OPTIONS + ' --binary-mode --local-infile=0')
CHECK_COMMAND = 'set -Eeuo pipefail; mysqlcheck ' + CLIENT_OPTIONS + ' --all-databases --check --skip-auto-repair'


class RecoveryCleanupUncertain(ValueError):
    pass


def cleanup_candidate(container_id, server_image, candidate, name, capture=None, execute=None):
    """Remove only the originally returned full ID; never a replacement name."""
    def read(args):
        return subprocess.check_output(args, text=True, timeout=30, stderr=subprocess.DEVNULL)
    def act(args):
        subprocess.run(args, check=True, timeout=45, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    capture, execute = capture or read, execute or act
    try:
        candidate = candidate_path(candidate)
        if not isinstance(container_id, str) or not CONTAINER_ID.fullmatch(container_id) or not PIN.fullmatch(server_image) or not CANDIDATE_NAME.fullmatch('/' + name):
            raise ValueError('Original recovery container provenance is unavailable')
        text = capture(['docker', 'inspect', container_id])
        if len(text) > 2 * 1024**2:
            raise ValueError('Recovery cleanup inspection exceeds its bound')
        rows = json.loads(text)
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError('Recovery cleanup exact inspection unavailable')
        value = rows[0]
        image_id = value.get('Image', '')
        if value.get('Id') != container_id or value.get('Name') != '/' + name or not isinstance(image_id, str) or not CONTAINER_ID.fullmatch(image_id.removeprefix('sha256:')) or value.get('Config', {}).get('Image') != server_image:
            raise ValueError('Recovery cleanup identity changed')
        mounts = value.get('Mounts', [])
        matches = [item for item in mounts if item.get('Destination') == '/var/lib/mysql']
        if len(matches) != 1 or matches[0].get('Type') != 'bind' or matches[0].get('Source') != str(candidate / 'mysql'):
            raise ValueError('Recovery cleanup original isolated storage changed')
        execute(['docker', 'rm', '-f', container_id])
        # A successful daemon query confirms removal; an inspect error alone
        # cannot distinguish removal from a lost connection to the daemon.
        if capture(['docker', 'ps', '-a', '--no-trunc', '--filter', 'id=' + container_id, '--format', '{{.ID}}']).strip():
            raise ValueError('Recovery cleanup remains pending')
    except Exception as error:
        raise RecoveryCleanupUncertain('Retain the encrypted isolated copy until exact recovery container cleanup is confirmed') from error


def canonical_binlogs(names):
    if not isinstance(names, list) or not names or len(names) > 100_000:
        raise ValueError('An exact bounded nonempty binary log range is required')
    previous = None
    for name in names:
        match = BINLOG.fullmatch(name) if isinstance(name, str) and len(name) <= 64 else None
        if not match or previous is not None and int(match.group(1)) != previous + 1:
            raise ValueError('Binary logs must be canonical, contiguous and unique')
        previous = int(match.group(1))
    return list(names)


def regular_file(path, maximum):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Scoped recovery credential or certificate is unavailable')
    return path


def candidate_path(candidate):
    candidate = Path(candidate)
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError('Recovery candidate must be a separately extracted directory')
    resolved = candidate.resolve(strict=True)
    invalid = ',\r\n\x00' + (':' if os.name != 'nt' else '')
    if str(resolved) != str(candidate) or any(character in str(resolved) for character in invalid):
        raise ValueError('Recovery candidate requires an exact canonical bind path')
    return resolved


def validate_candidate_container(value, container_id, server_image, candidate, image_id):
    if not CONTAINER_ID.fullmatch(container_id) or not PIN.fullmatch(server_image):
        raise ValueError('Exact candidate container and immutable server image required')
    candidate = candidate_path(candidate)
    if not isinstance(value, dict) or value.get('Id') != container_id or value.get('Image') != image_id or not CONTAINER_ID.fullmatch(image_id.removeprefix('sha256:')):
        raise ValueError('Recovery server image or container identity differs')
    config, host, state = value.get('Config', {}), value.get('HostConfig', {}), value.get('State', {})
    if config.get('Image') != server_image or not CANDIDATE_NAME.fullmatch(value.get('Name', '')) or state.get('Running') is not True or host.get('NetworkMode') != 'none' or host.get('PortBindings') or value.get('NetworkSettings', {}).get('Ports') and any(value.get('NetworkSettings', {}).get('Ports', {}).values()):
        raise ValueError('Only the exact running network-isolated recovery server is eligible')
    if config.get('User') != '999:999' or host.get('Privileged') or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host' or host.get('Devices') or 'ALL' not in (host.get('CapDrop') or []) or not any(item in {'no-new-privileges', 'no-new-privileges:true'} for item in host.get('SecurityOpt') or []):
        raise ValueError('Recovery server privilege boundaries differ from the fixed clone policy')
    networks = value.get('NetworkSettings', {}).get('Networks', {})
    if not isinstance(networks, dict) or set(networks) - {'none'} or any(item.get('IPAddress') or item.get('GlobalIPv6Address') for item in networks.values()):
        raise ValueError('Recovery namespace must have no external network address')
    mounts = value.get('Mounts')
    if not isinstance(mounts, list):
        raise ValueError('Recovery server bind provenance is unavailable')
    required = {'/var/lib/mysql': 'mysql', '/var/lib/mysql-keyring': 'mysql-keyring', '/etc/autosoft/tls': 'tls/mysql', '/run/secrets': 'secrets/mysql'}
    for target, relative in required.items():
        matches = [item for item in mounts if item.get('Destination') == target]
        if len(matches) != 1 or matches[0].get('Type') != 'bind' or matches[0].get('Source') != str(candidate / relative):
            raise ValueError('Recovery server is not mounted from the exact candidate')
    allowed = {**required, '/etc/mysql/conf.d/autosoft.cnf': 'config/mysql.cnf',
               '/usr/sbin/mysqld.my': 'config/mysqld.my',
               '/usr/lib64/mysql/plugin/component_keyring_file.cnf': 'config/component_keyring_file.cnf'}
    seen = set()
    for item in mounts:
        source = item.get('Source')
        target = item.get('Destination')
        if item.get('Type') != 'bind' or not isinstance(source, str) or target not in allowed or target in seen or source != str(candidate / allowed[target]) or Path(source).resolve() != Path(source) or Path(source).is_symlink():
            raise ValueError('Recovery server includes an unrelated or linked host mount')
        seen.add(target)
    return candidate


def _tooling_base_command(tools_image, container_id, inputs):
    if not isinstance(tools_image, str) or not PIN.fullmatch(tools_image) or not CONTAINER_ID.fullmatch(container_id):
        raise ValueError('Signed immutable recovery tooling and exact container ID required')
    inputs = Path(inputs)
    command = ['docker', 'run', '--rm', '--pull=never', '--read-only', '--user=999:999',
               '--network=container:' + container_id, '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--memory=512m', '--cpus=1', '--pids-limit=64', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m,mode=1777',
               '--env', 'TMPDIR=/tmp', '--env', 'HOME=/tmp', '--env', 'MYSQL_HISTFILE=/dev/null',
               '--entrypoint', '/bin/bash']
    for source, target in [('client.cnf', '/run/recovery/client.cnf'), ('ca.crt', '/run/recovery/ca.crt'), ('hosts', '/etc/hosts')]:
        command += ['--volume', f'{inputs / source}:{target}:ro,Z']
    return command + [tools_image, '-c']


def tooling_command(tools_image, container_id, inputs, logs):
    return _tooling_base_command(tools_image, container_id, inputs) + [REPLAY_COMMAND, 'recovery'] + canonical_binlogs(logs)


def table_check_command(tools_image, container_id, inputs):
    return _tooling_base_command(tools_image, container_id, inputs) + [CHECK_COMMAND, 'recovery-check']


def _verified_candidate(container_id, server_image, tools_image, candidate):
    if os.geteuid() != 0:
        raise ValueError('Trusted root-only recovery is required')
    if not isinstance(tools_image, str) or not PIN.fullmatch(tools_image) or not CONTAINER_ID.fullmatch(container_id) or not PIN.fullmatch(server_image):
        raise ValueError('Recovery tooling is unavailable; no binary log replay attempted')
    image_id = subprocess.check_output(['docker', 'image', 'inspect', server_image, '--format', '{{.Id}}'], text=True, timeout=15, stderr=subprocess.DEVNULL).strip()
    inspected = subprocess.check_output(['docker', 'inspect', container_id], text=True, timeout=15, stderr=subprocess.DEVNULL)
    if len(inspected) > 2 * 1024**2:
        raise ValueError('Recovery container inspection is excessive')
    records = json.loads(inspected)
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError('Exact recovery container inspection required')
    candidate = validate_candidate_container(records[0], container_id, server_image, candidate, image_id)
    return candidate


@contextmanager
def _scoped_inputs(candidate):
    client_file = regular_file(candidate / 'secrets/mysql/client.cnf', 65536)
    ca_file = regular_file(candidate / 'tls/mysql/ca.crt', 65536)
    with tempfile.TemporaryDirectory(dir=candidate.parent, prefix='replay-input-') as directory:
        inputs = Path(directory)
        for source, name in [(client_file, 'client.cnf'), (ca_file, 'ca.crt')]:
            shutil.copyfile(source, inputs / name)
            os.chmod(inputs / name, 0o400)
            os.chown(inputs / name, 999, 999)
        (inputs / 'hosts').write_text(HOSTS)
        os.chmod(inputs / 'hosts', 0o444)
        yield inputs


def replay_native_binlogs(container_id, server_image, tools_image, candidate, logs):
    """Replay only into this exact clone; return tooling provenance, never SQL."""
    logs = canonical_binlogs(logs)
    candidate = _verified_candidate(container_id, server_image, tools_image, candidate)
    with _scoped_inputs(candidate) as inputs:
        # SQL is streamed between two clients in one bounded container. Nothing
        # is written to the host, and either side's failure fails the operation.
        subprocess.run(tooling_command(tools_image, container_id, inputs, logs), check=True, timeout=3600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {'toolsImage': tools_image, 'serverImage': server_image, 'containerId': container_id,
            'transport': 'isolated shared namespace TCP with TLS VERIFY_IDENTITY', 'binlogs': logs}


def check_native_tables(container_id, server_image, tools_image, candidate):
    """Check all cloned tables with a fixed verified-TLS operation only."""
    candidate = _verified_candidate(container_id, server_image, tools_image, candidate)
    with _scoped_inputs(candidate) as inputs:
        subprocess.run(table_check_command(tools_image, container_id, inputs), check=True, timeout=3600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {'toolsImage': tools_image, 'serverImage': server_image, 'containerId': container_id,
            'transport': 'isolated shared namespace TCP with TLS VERIFY_IDENTITY', 'operation': 'all-table-check'}
