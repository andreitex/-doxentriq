#!/usr/bin/env python3
"""Load cold Redis/RabbitMQ copies without consumers or external networking.

These checks establish native store readability only. They never start platform
workers, apps, connectors or identity, consume queues, restore production data,
or grant destructive checkpoint eligibility. Archived images must still match
the root-managed company image lock; old/unknown images are unavailable.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid
from recovery_tools import candidate_path, regular_file

PIN = re.compile(r'^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$')
ID = re.compile(r'^[a-f0-9]{64}$')
NAME = re.compile(r'^/autosoft-store-[a-f0-9]{12}-(redis|rabbitmq)$')
REDIS_CONFIG = '''bind 127.0.0.1
port 6379
protected-mode yes
aclfile /data/users.acl
dir /data
appendonly yes
appendfsync everysec
aof-load-truncated no
maxmemory 512mb
maxmemory-policy noeviction
'''
RABBIT_CONFIG = '''listeners.tcp = none
management.tcp.ip = 127.0.0.1
management.tcp.port = 15672
prometheus.tcp.listener = none
log.console = true
log.console.level = warning
'''


class StoreNotReady(ValueError):
    pass


class ColdStoreCleanupUncertain(ValueError):
    def __init__(self, identifier, name=None, inputs=None):
        super().__init__('Cold-store cleanup could not be confirmed; preserve its isolated copy')
        self.container_id = identifier
        self.container_name = name
        self.inputs = inputs


def _output(args, maximum=2 * 1024**2, stdin=None, scratch=None):
    # Store bounded output on encrypted scratch, never emit provider records,
    # Redis keys/values, cookies, passwords or RabbitMQ exported password hashes.
    import resource
    def limit_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    with tempfile.TemporaryFile(dir=scratch) as handle:
        subprocess.run(args, input=stdin, check=True, timeout=45, stdout=handle,
                       stderr=subprocess.DEVNULL, preexec_fn=limit_output)
        handle.seek(0)
        value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError('Recovery native inspection exceeds its bound')
    return value.decode('utf-8')


def clone_command(service, image, candidate, inputs, name):
    if service not in {'redis', 'rabbitmq'} or not PIN.fullmatch(image) or not NAME.fullmatch('/' + name) or not name.endswith('-' + service):
        raise ValueError('Exact fixed recovery service/image/name required')
    candidate, inputs = candidate_path(candidate), candidate_path(inputs)
    folder = candidate / service
    if folder.is_symlink() or not folder.is_dir() or folder.resolve() != folder:
        raise ValueError('Cold native store must belong to the exact isolated candidate')
    command = ['docker', 'run', '-d', '--pull=never', '--name', name, '--user=999:999',
               '--read-only', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--memory=1g', '--cpus=1', '--pids-limit=256', '--log-driver=none',
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m,mode=1777']
    target = '/data' if service == 'redis' else '/var/lib/rabbitmq'
    config = '/run/restore/redis.conf' if service == 'redis' else '/etc/rabbitmq/rabbitmq.conf'
    # Docker applies private SELinux labels only to these new candidate binds.
    # Debian/AppArmor installations need no separate SELinux host command.
    command += ['--volume', f'{folder}:{target}:Z',
                '--volume', f'{inputs / (service + ".conf")}:{config}:ro,Z']
    if service == 'rabbitmq':
        command += ['--hostname=rabbitmq', '--env', 'RABBITMQ_NODENAME=rabbit@rabbitmq',
                    '--env', 'HOME=/var/lib/rabbitmq']
    return command + [image] + (['redis-server', config] if service == 'redis' else ['rabbitmq-server'])


def validate_clone(value, identifier, service, image, image_id, candidate, inputs, running=True):
    candidate, inputs = candidate_path(candidate), candidate_path(inputs)
    if not isinstance(value, dict) or not ID.fullmatch(identifier) or value.get('Id') != identifier or value.get('Image') != image_id or not ID.fullmatch(image_id.removeprefix('sha256:')):
        raise ValueError('Exact cold-recovery container/image identity differs')
    config, host, state = value.get('Config', {}), value.get('HostConfig', {}), value.get('State', {})
    if service not in {'redis', 'rabbitmq'} or not NAME.fullmatch(value.get('Name', '')) or not value['Name'].endswith('-' + service) or config.get('Image') != image or not PIN.fullmatch(image) or config.get('User') != '999:999':
        raise ValueError('Cold-recovery service provenance differs')
    if host.get('NetworkMode') != 'none' or host.get('Privileged') or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host' or host.get('Devices') or host.get('CapAdd') or host.get('CapDrop') != ['ALL'] or host.get('ReadonlyRootfs') is not True or host.get('PortBindings'):
        raise ValueError('Cold-recovery isolation policy differs')
    if host.get('Memory') != 1024**3 or host.get('NanoCpus') != 10**9 or host.get('PidsLimit') != 256 or not any(item in {'no-new-privileges', 'no-new-privileges:true'} for item in host.get('SecurityOpt') or []):
        raise ValueError('Cold-recovery resource or privilege limits differ')
    if state.get('Running') is not running or state.get('Paused') or state.get('Restarting') or state.get('Dead'):
        raise ValueError('Cold-recovery running state is uncertain')
    networks = value.get('NetworkSettings', {}).get('Networks', {})
    if not isinstance(networks, dict) or set(networks) - {'none'} or any(item.get('IPAddress') or item.get('GlobalIPv6Address') for item in networks.values()) or any(value.get('NetworkSettings', {}).get('Ports', {}).values()):
        raise ValueError('Cold-recovery namespace has an external address or port')
    target = '/data' if service == 'redis' else '/var/lib/rabbitmq'
    config_target = '/run/restore/redis.conf' if service == 'redis' else '/etc/rabbitmq/rabbitmq.conf'
    expected = {target: (str(candidate / service), True), config_target: (str(inputs / (service + '.conf')), False)}
    mounts = value.get('Mounts')
    if not isinstance(mounts, list) or len(mounts) != 2:
        raise ValueError('Cold-recovery mount inventory differs')
    seen = set()
    for mount in mounts:
        destination = mount.get('Destination')
        if destination in seen or destination not in expected or mount.get('Type') != 'bind' or (mount.get('Source'), mount.get('RW')) != expected[destination]:
            raise ValueError('Cold-recovery bind is outside the independently extracted store')
        seen.add(destination)
    expected_cmd = ['redis-server', config_target] if service == 'redis' else ['rabbitmq-server']
    if config.get('Cmd') != expected_cmd:
        raise ValueError('Cold-recovery command differs from the fixed native operation')
    if service == 'rabbitmq' and (config.get('Hostname') != 'rabbitmq' or 'RABBITMQ_NODENAME=rabbit@rabbitmq' not in config.get('Env', [])):
        raise ValueError('RabbitMQ physical restoration requires the original fixed node name')


def _redis_evidence(identifier, candidate, scratch):
    password = regular_file(candidate / 'secrets/runtime/redis-admin', 4096).read_text().strip()
    if not password or '\n' in password or '\r' in password:
        raise ValueError('Recovery Redis credential is unavailable')
    base = ['docker', 'exec', '-i', identifier, 'redis-cli', '-h', '127.0.0.1',
            '-p', '6379', '--user', 'provisioner', '--askpass', '--raw']
    info = _output(base + ['INFO', 'persistence'], stdin=(password + '\n').encode(), scratch=scratch)
    parsed = dict(line.split(':', 1) for line in info.splitlines() if ':' in line and not line.startswith('#'))
    if parsed.get('loading') == '1' or 'LOADING Redis is loading' in info:
        raise StoreNotReady('Redis native store is still loading')
    if parsed.get('loading') != '0' or parsed.get('aof_enabled') != '1' or parsed.get('aof_last_write_status') != 'ok':
        raise ValueError('Redis persistence did not load cleanly')
    if _output(base + ['PING'], stdin=(password + '\n').encode(), scratch=scratch).strip() != 'PONG':
        raise ValueError('Redis native authenticated read check failed')
    acl = _output(base + ['ACL', 'LIST'], stdin=(password + '\n').encode(), scratch=scratch)
    # Store only a digest and count; ACL entries contain authentication hashes.
    users = sorted(line for line in acl.splitlines() if line.startswith('user '))
    if not users or not any(line.startswith('user provisioner ') for line in users):
        raise ValueError('Redis restored ACL scope is unavailable')
    keyspace = _output(base + ['INFO', 'keyspace'], stdin=(password + '\n').encode(), scratch=scratch)
    dbs = []
    for line in keyspace.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'db(\d+):keys=(\d+),expires=(\d+),avg_ttl=(\d+)(?:,.*)?', line)
        if not match or len(dbs) >= 16 or int(match[1]) in {item['database'] for item in dbs}:
            raise ValueError('Redis native keyspace metadata is invalid')
        dbs.append({'database': int(match[1]), 'keys': int(match[2]), 'expiringKeys': int(match[3])})
    return dict(nativeLoad='passed', authenticatedRead='passed', aclUsers=len(users),
                aclHash=hashlib.sha256('\n'.join(users).encode()).hexdigest(), keyspace=dbs,
                contentBaseline='unavailable; no archived logical baseline comparison',
                scope='Disposable Redis store/ACL native readability; expiring cache contents are not business recovery evidence')


def _rabbit_evidence(identifier, scratch):
    base = ['docker', 'exec', identifier, 'rabbitmqctl', '--quiet', '--formatter=json']
    vhosts = json.loads(_output(base + ['list_vhosts', 'name'], scratch=scratch))
    if not isinstance(vhosts, list) or len(vhosts) > 1000 or any(not isinstance(item, dict) or not isinstance(item.get('name'), str) or len(item['name']) > 255 or '\x00' in item['name'] for item in vhosts):
        raise ValueError('RabbitMQ restored virtual host inventory is invalid')
    if len({item['name'] for item in vhosts}) != len(vhosts):
        raise ValueError('RabbitMQ restored virtual host identities are duplicated')
    queue_count, message_count, queue_state = 0, 0, []
    for vhost in sorted(item['name'] for item in vhosts):
        rows = json.loads(_output(base + ['list_queues', '-p', vhost, 'name', 'durable', 'messages_ready', 'messages_unacknowledged'], scratch=scratch))
        if not isinstance(rows, list) or len(rows) > 10_000:
            raise ValueError('RabbitMQ restored queue inventory exceeds its bound')
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('name'), str) or len(row['name']) > 255 or '\x00' in row['name'] or not isinstance(row.get('durable'), bool) or any(type(row.get(key)) is not int or row[key] < 0 for key in ('messages_ready', 'messages_unacknowledged')):
                raise ValueError('RabbitMQ restored queue metadata is invalid')
            if row['messages_unacknowledged'] != 0:
                raise ValueError('Isolated recovery candidate unexpectedly has active consumers')
            queue_count += 1
            if queue_count > 10_000:
                raise ValueError('RabbitMQ restored aggregate queue inventory exceeds its bound')
            message_count += row['messages_ready']
            queue_state.append(dict(vhost=vhost, **row))
    digest = hashlib.sha256(json.dumps(sorted(queue_state, key=lambda item: (item['vhost'], item['name'])), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return dict(nativeLoad='passed', vhosts=len(vhosts), queues=queue_count, readyMessages=message_count,
                queueInventoryHash=digest, messageContent='not consumed or compared',
                managementTransport='Loopback HTTP in network-none isolated clone; never exposed or used',
                scope='Cold fixed-node RabbitMQ store native readability; queued work is never executed')


def check_cold_services(candidate, recorded_images, company_images):
    if os.geteuid() != 0:
        raise ValueError('Cold-store verification requires trusted host root')
    candidate = candidate_path(candidate)
    result = {}
    with tempfile.TemporaryDirectory(dir=candidate.parent, prefix='store-inputs-') as directory:
        inputs = Path(directory).resolve(strict=True)
        os.chmod(inputs, 0o755)
        for service, config in [('redis', REDIS_CONFIG), ('rabbitmq', RABBIT_CONFIG)]:
            image = recorded_images.get(service)
            if not isinstance(image, str) or not PIN.fullmatch(image) or company_images.get(service) != image:
                raise ValueError('Cold-store image is not in the current company-qualified lock')
            config_file = inputs / (service + '.conf')
            config_file.write_text(config)
            os.chmod(config_file, 0o444)
            name = 'autosoft-store-' + uuid.uuid4().hex[:12] + '-' + service
            image_id = _output(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], scratch=inputs).strip()
            if not image_id.startswith('sha256:') or not ID.fullmatch(image_id[7:]):
                raise ValueError('Cold-store exact image identity is unavailable before launch')
            identifier = None
            def verify(running=True):
                records = json.loads(_output(['docker', 'inspect', identifier], scratch=inputs))
                if not isinstance(records, list) or len(records) != 1:
                    raise ValueError('Cold-store container inspection is unavailable')
                validate_clone(records[0], identifier, service, image, image_id, candidate, inputs, running)
            try:
                identifier = _output(clone_command(service, image, candidate, inputs, name), scratch=inputs).strip()
                if not ID.fullmatch(identifier):
                    identifier = None
                    raise ValueError('Cold-store launch outcome is uncertain')
                verify()
                for attempt in range(45):
                    try:
                        evidence = _redis_evidence(identifier, candidate, inputs) if service == 'redis' else _rabbit_evidence(identifier, inputs)
                        verify()
                        result[service] = dict(image=image, containerId=identifier, **evidence)
                        break
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, StoreNotReady):
                        if attempt == 44: raise
                        time.sleep(2)
                else: raise ValueError('Cold-store readiness was not proven')
            finally:
                # The immutable ID came directly from our trusted docker run.
                # Resource drift must still permit containment of this exact
                # process; do not address a reusable name or remove its volumes.
                try:
                    if identifier is None:
                        raise ValueError('Cold-store launch has no original immutable ID')
                    records = json.loads(_output(['docker', 'inspect', identifier], scratch=inputs))
                    if not isinstance(records, list) or len(records) != 1 or records[0].get('Id') != identifier or records[0].get('Image') != image_id or records[0].get('Name') != '/' + name or records[0].get('Config', {}).get('Image') != image:
                        raise ValueError('Cold-store cleanup identity is unavailable')
                    subprocess.run(['docker', 'rm', '-f', identifier], check=True, timeout=45, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if _output(['docker','ps','-a','--no-trunc','--filter','id='+identifier,'--format','{{.ID}}'], scratch=inputs).strip():
                        raise ValueError('Cold-store cleanup could not be independently confirmed')
                except Exception:
                    # Keep config/diagnostic scratch too: an unknown clone may
                    # still hold its bind. The caller retains the whole workdir.
                    retained = inputs.with_name('pending-store-inputs-'+uuid.uuid4().hex)
                    try:
                        inputs.rename(retained)
                    except OSError:
                        retained = inputs
                    raise ColdStoreCleanupUncertain(identifier, name, str(retained)) from None
    return dict(checkedAt=datetime.now(timezone.utc).isoformat(), scope='Isolated cold-store readability; not full platform restoration', services=result,
                productionModified=False, queuedWorkExecuted=False, destructiveCheckpointEligible=False)
