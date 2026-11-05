#!/usr/bin/env python3
"""Trusted bounded maintenance scanner with fixed operational diagnostics."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import threading
import tempfile
import time
import uuid

PIN = re.compile(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}')
ID = re.compile(r'[a-f0-9]{64}')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
MANIFEST_TYPES = {'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'}
INDEX_TYPES = {'application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'}
LABEL = 'io.autosoft.maintenance-scanner'
INPUT_PREFIXES = ('image-','host-advisory-','kernel-advisory-')
STAMP = lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
LOCAL_DOCKER_HOST = 'unix:///var/run/docker.sock'
_DOCKER_CONFIGURATION = ContextVar('maintenance_scanner_docker_configuration', default=None)
ROOTFS = ('rootfs', '--pkg-types', 'os', '--list-all-pkgs', '--cache-dir', '/cache/trivy',
          '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--scanners', 'vuln', '--format', 'json', '/inventory')
IMAGE = ('image', '--input', '/input/image.tar', '--cache-dir', '/cache/trivy', '--cache-backend', 'memory', '--skip-db-update',
         '--skip-java-db-update', '--offline-scan', '--scanners', 'vuln', '--format', 'json')
DB = ('image', '--download-db-only', '--cache-dir', '/cache/trivy')
JAVA = ('image', '--download-java-db-only', '--cache-dir', '/cache/trivy')


class ScannerUnavailable(ValueError):
    """Fixed credential-free reason; a scan has not passed."""


def require(condition, reason):
    if not condition:
        raise ScannerUnavailable(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def typed_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-scanner-json-field')
            result[key] = value
        return result
    def invalid(_):
        raise ScannerUnavailable('invalid-scanner-json-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def protected(path, *, directory=False, maximum=2 * 1024**3):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'untrusted-scanner-path')
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode), 'untrusted-scanner-ancestors')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1 and info.st_size <= maximum, 'untrusted-scanner-input')
    return path


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exclusive(path, value):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(canonical(value) + b'\n'); stream.flush(); os.fsync(stream.fileno())
    fsync_directory(path.parent)


def replace_pointer(path, value):
    temporary = path.with_name('.pending-' + uuid.uuid4().hex)
    write_exclusive(temporary, value)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def bounded_process(argv, *, timeout=30, maximum=8 * 1024**2, expected=0, outputs=None):
    """No shell/stdin; stop reading before any stream exceeds its ceiling."""
    require(type(timeout) in (int, float) and 0 < timeout <= 1800, 'scanner-deadline-unavailable')
    require(type(maximum) is int and 0 < maximum <= 32 * 1024**2, 'scanner-output-bound-unavailable')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    buffers = {process.stdout:bytearray(), process.stderr:bytearray()}
    ceilings = {process.stdout:maximum, process.stderr:maximum}
    if outputs is not None:
        ceilings = {process.stdout:32 * 1024**2, process.stderr:1024**2}
    files, counts = {}, {pipe:0 for pipe in buffers}
    selector = None
    try:
        selector = selectors.DefaultSelector(); deadline = time.monotonic() + timeout
        if outputs is not None:
            require(set(outputs) == {'stdout', 'stderr'}, 'scanner-private-output-contract')
            for pipe,name in ((process.stdout,'stdout'),(process.stderr,'stderr')):
                files[pipe] = outputs[name].open('xb'); os.fchmod(files[pipe].fileno(), 0o600)
        for pipe in buffers:
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            require(time.monotonic() < deadline, 'scanner-process-timeout')
            for key,_ in selector.select(min(.1, max(0, deadline-time.monotonic()))):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    selector.unregister(key.fileobj); continue
                allowed = max(0, ceilings[key.fileobj]-counts[key.fileobj])
                retained = raw[:allowed]; counts[key.fileobj] += len(raw)
                if files:
                    files[key.fileobj].write(retained)
                else:
                    buffers[key.fileobj].extend(retained)
                require(counts[key.fileobj] <= ceilings[key.fileobj], 'scanner-process-output-limit')
        code = process.wait(timeout=max(.001, deadline-time.monotonic()))
        require(expected is None or code == expected, 'scanner-process-command-unavailable')
        return subprocess.CompletedProcess(argv, code, bytes(buffers[process.stdout]), bytes(buffers[process.stderr]))
    finally:
        # Every release is attempted even when storage or another close fails.
        # Reaping the CLI is not container cleanup evidence; inspect separately.
        prior_error = sys.exc_info()[1]
        release_errors = []
        def release(action):
            try: action()
            except BaseException as error: release_errors.append(error)
        for stream in files.values():
            release(stream.flush)
            release(lambda:os.fsync(stream.fileno()))
            release(stream.close)
        if selector is not None: release(selector.close)
        try: running = process.poll() is None
        except BaseException as error:
            release_errors.append(error);running = True
        if running:
            release(process.kill)
            release(lambda:process.wait(timeout=5))
        release(process.stdout.close);release(process.stderr.close)
        if release_errors and prior_error is None:
            raise release_errors[0]



# These names are product constants, never subprocess or external text.
PROGRESS_STAGES = (
    'create_requested', 'created_container_inspection', 'container_ownership',
    'binding_confirmed', 'source_identity_before_start', 'attachment',
    'exit_and_ownership', 'post_scan_preservation', 'output_decoding',
    'scan_output_completed', 'cleanup', 'post_cleanup_preservation', 'receipt_prepared',
)
PROGRESS_FILES = {f'progress-{number:02d}-{stage}.json':stage
                  for number,stage in enumerate(PROGRESS_STAGES,1)}
FAILURE_CATEGORIES = frozenset((
    'process_timeout', 'output_limit', 'command_unavailable',
    'container_exit_unavailable', 'ownership_unavailable',
    'preservation_unavailable', 'interrupted', 'invalid_output',
    'local_io_unavailable', 'operation_unavailable', 'diagnostic_storage_unavailable',
))
FIXED_FAILURES = {
    'scanner-process-timeout':'process_timeout',
    'scanner-process-output-limit':'output_limit',
    'scanner-process-command-unavailable':'command_unavailable',
    'maintenance-scanner-exit-unavailable':'container_exit_unavailable',
    'maintenance-scanner-interrupted':'interrupted',
    **dict.fromkeys((
        'maintenance-scanner-input-identity-drift',
        'maintenance-scanner-final-image-identity-drift',
        'maintenance-scanner-input-bytes-drift',
        'maintenance-scanner-readonly-feed-drift',
    ), 'preservation_unavailable'),
    **dict.fromkeys((
        'maintenance-scanner-provenance-drift', 'maintenance-scanner-inherited-config-drift',
        'maintenance-scanner-config-drift', 'maintenance-scanner-mount-drift',
        'maintenance-scanner-resource-drift', 'maintenance-scanner-host-isolation-drift',
        'maintenance-scanner-never-started-unconfirmed', 'maintenance-scanner-state-unavailable',
        'maintenance-scanner-cleanup-unconfirmed', 'scanner-exact-platform',
        'scanner-implicit-volumes-unavailable', 'unknown-maintenance-scanner-create-output',
    ), 'ownership_unavailable'),
}


def failure_category(error):
    # No str/repr/formatting of exceptions: args may contain credentials or argv.
    if isinstance(error, ScannerUnavailable):
        reason = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
        return FIXED_FAILURES.get(reason, 'operation_unavailable')
    if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)):
        return 'process_timeout'
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'interrupted'
    if isinstance(error, UnicodeError):
        return 'invalid_output'
    if isinstance(error, OSError):
        return 'local_io_unavailable'
    return 'operation_unavailable'


def validate_progress(path, operation, *, now):
    require(path.name in PROGRESS_FILES, 'foreign-scanner-progress-file-preserved')
    record = typed_json(protected(path,maximum=4096).read_bytes())
    require(isinstance(record,dict) and set(record)=={'operationId','stage','checkedAt'}
            and record['operationId']==operation and record['stage']==PROGRESS_FILES[path.name],
            'scanner-progress-binding-unavailable')
    checked = record['checkedAt']
    require(type(checked) is str and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z',checked),
        'scanner-progress-time-unavailable')
    require(datetime.fromisoformat(checked.replace('Z','+00:00'))<=now,
            'scanner-progress-time-unavailable')


class ScanDiagnostics:
    """Fixed progress records; diagnostic I/O can never skip exact-ID cleanup."""
    def __init__(self, folder, operation):
        self.folder, self.operation = folder, operation
        self.stage = 'create_requested'
        self.storage_failed = False
        self.values = {}

    def mark(self, stage, *, required=True):
        require(stage in PROGRESS_STAGES, 'scanner-diagnostic-stage-unavailable')
        self.stage = stage
        filename = next(name for name,value in PROGRESS_FILES.items() if value==stage)
        try:
            protected(self.folder,directory=True)
            write_exclusive(self.folder/filename,
                dict(operationId=self.operation,stage=stage,checkedAt=STAMP()))
        except BaseException:
            self.storage_failed = True
            if 'failureStage' not in self.values:
                self.values.update(failureStage=stage,failureCategory='diagnostic_storage_unavailable')
            if required:raise

    def fail(self, error, *, cleanup=False):
        category = failure_category(error)
        if cleanup:self.values['cleanupFailureCategory']=category
        if 'failureStage' not in self.values:
            self.values.update(failureStage=self.stage,failureCategory=category)

    def observed_exit(self, name, value):
        require(name in ('cliExitCode','containerExitCode'), 'scanner-diagnostic-exit-name-unavailable')
        if type(value) is int and -255<=value<=255:self.values[name]=value

    def summary(self):
        result=dict(self.values,lastStage=self.stage,diagnosticsConfirmed=not self.storage_failed)
        if self.storage_failed:
            result['diagnosticFailureCategory']='diagnostic_storage_unavailable'
        return result


def unavailable_diagnostic(outcome):
    """Fixed-only optional caller summary; journal paths and external data stay private."""
    value={}
    for key in ('failureStage','lastStage'):
        if type(outcome.get(key)) is str and outcome[key] in PROGRESS_STAGES:value[key]=outcome[key]
    for key in ('failureCategory','cleanupFailureCategory','diagnosticFailureCategory'):
        if type(outcome.get(key)) is str and outcome[key] in FAILURE_CATEGORIES:value[key]=outcome[key]
    for key in ('cliExitCode','containerExitCode'):
        if type(outcome.get(key)) is int and -255<=outcome[key]<=255:value[key]=outcome[key]
    for key in ('cleanupConfirmed','diagnosticsConfirmed'):
        if type(outcome.get(key)) is bool:value[key]=outcome[key]
    error=ScannerUnavailable('maintenance-scanner-unavailable-inspect-protected-journal')
    error.diagnosticSummary=value
    return error


def local_socket_proof():
    require(not any(name in os.environ for name in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_API_VERSION')),
            'maintenance-scanner-docker-environment-override')
    requested = Path('/var/run/docker.sock'); actual = Path('/run/docker.sock')
    require(requested.resolve(strict=True) == actual and actual.resolve(strict=True) == actual,
            'maintenance-scanner-local-socket-only')
    protected(actual.parent,directory=True)
    info = actual.lstat(); alias = requested.lstat()
    require(stat.S_ISSOCK(info.st_mode) and stat.S_ISSOCK(alias.st_mode)
            and info.st_uid == 0 and type(info.st_gid) is int and 0 <= info.st_gid < 2**31
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o600,0o660)
            and (alias.st_dev,alias.st_ino) == (info.st_dev,info.st_ino),
            'maintenance-scanner-protected-local-socket')
    return dict(device=info.st_dev,inode=info.st_ino,group=info.st_gid,mode=stat.S_IMODE(info.st_mode))


@contextmanager
def local_docker_configuration(data):
    """One fresh empty protected CLI configuration; no operator proxy settings."""
    require(os.name == 'posix' and os.geteuid() == 0, 'root-local-scanner-configuration-only')
    socket_proof = local_socket_proof()
    security = protected(Path(data)/'security',directory=True)
    folder = Path(tempfile.mkdtemp(dir=security,prefix='.scanner-cli-'));os.chmod(folder,0o700)
    identity = input_identity(folder);token = None
    try:
        write_exclusive(folder/'config.json',{})
        token = _DOCKER_CONFIGURATION.set(dict(folder=folder,identity=identity,socket=socket_proof))
        yield
    finally:
        prior_error = sys.exc_info()[1]
        if token is not None:_DOCKER_CONFIGURATION.reset(token)
        try:
            require(input_identity(folder)==identity and list(folder.iterdir())==[folder/'config.json'],
                    'maintenance-scanner-cli-cleanup-identity-unavailable')
            require(protected(folder/'config.json',maximum=1024).read_bytes()==b'{}\n',
                    'maintenance-scanner-cli-config-drift')
            (folder/'config.json').unlink();folder.rmdir();fsync_directory(security)
        except BaseException:
            if prior_error is None:raise ScannerUnavailable('maintenance-scanner-cli-config-retained') from None


def docker_command(*arguments):
    configuration = _DOCKER_CONFIGURATION.get()
    require(isinstance(configuration,dict), 'maintenance-scanner-local-configuration-required')
    folder = configuration['folder']
    require(local_socket_proof()==configuration['socket'] and input_identity(folder)==configuration['identity']
            and list(folder.iterdir())==[folder/'config.json']
            and protected(folder/'config.json',maximum=1024).read_bytes()==b'{}\n',
            'maintenance-scanner-local-endpoint-or-config-drift')
    return ['docker','--host='+LOCAL_DOCKER_HOST,'--config',str(folder),*arguments]


def docker(*arguments, **kwargs):
    return bounded_process(docker_command(*arguments), **kwargs)


def abort_signal(number, frame):
    raise ScannerUnavailable('maintenance-scanner-interrupted')


def profile(value):
    projection = {key:value.get(key) for key in ('Id','Name','Image','Config','HostConfig','Mounts','Platform','ImageManifestDescriptor')}
    host = projection['HostConfig']
    require(isinstance(host,dict) and 'OomKillDisable' in host and (host['OomKillDisable'] is None or host['OomKillDisable'] is False), 'scanner-oom-profile-unavailable')
    projection['HostConfig'] = dict(host, OomKillDisable=False)
    return hashlib.sha256(canonical(projection)).hexdigest()


def policy(arguments, mounts, network, writable_cache):
    arguments = tuple(arguments)
    if arguments == ROOTFS or arguments == IMAGE:
        require(network == 'none' and writable_cache is False and len(mounts) == 1
                and mounts[0][1] == ('/inventory' if arguments == ROOTFS else '/input'), 'offline-scanner-contract-only')
        return dict(mode='rootfs' if arguments == ROOTFS else 'image', memory=1024**3, temporary='128m', timeout=300, cacheWritable=False)
    if arguments == DB or arguments == JAVA:
        # A container memory limit does not bound writes through a cache bind.
        # Enable refresh only after bounded acquisition and activation qualify.
        raise ScannerUnavailable('bounded-vulnerability-feed-refresh-not-ready')
    raise ScannerUnavailable('unsupported-maintenance-scanner-command')


def tree_hashes(root, maximum=2 * 1024**3):
    protected(root, directory=True)
    values = {}; total = 0
    for count,path in enumerate(root.rglob('*'),1):
        require(count <= 512, 'scanner-input-entry-limit')
        info = path.lstat(); require(not stat.S_ISLNK(info.st_mode), 'linked-scanner-input')
        if stat.S_ISDIR(info.st_mode):
            protected(path,directory=True);continue
        protected(path)
        total += info.st_size; require(total <= maximum, 'scanner-input-byte-limit')
        values[path.relative_to(root).as_posix()] = dict(bytes=info.st_size,sha256=sha(path))
    return values


def input_identity(path):
    protected(path,directory=True)
    info=path.lstat()
    return {'device':info.st_dev,'inode':info.st_ino}


def remove_input(path, security, identity):
    """Remove only a captured fresh scanner input tree; never follow links."""
    require(path.parent == security and path.name.startswith(INPUT_PREFIXES)
            and input_identity(path)==identity, 'scanner-input-cleanup-identity-unavailable')
    tree_hashes(path)
    # rmtree's fd-based Linux implementation refuses symlink substitutions.
    require(shutil.rmtree.avoids_symlink_attacks, 'scanner-input-cleanup-requires-safe-rmtree')
    shutil.rmtree(path)
    fsync_directory(security)


def retained_intent_inputs(intent, operation, security):
    """A malformed retained intent can never authorize input deletion."""
    require(isinstance(intent, dict) and intent.get('operationId') == operation,
            'pending-input-intent-unavailable')
    mode = intent.get('mode')
    require(isinstance(mode, str) and mode in ('image', 'rootfs', 'os-feed', 'java-feed'),
            'pending-input-mode-unavailable')
    paths = intent.get('inputPaths')
    require(isinstance(paths, list) and len(paths) == (1 if mode in ('image', 'rootfs') else 0),
            'pending-input-count-unavailable')
    prefixes = ('image-',) if mode == 'image' else ('host-advisory-', 'kernel-advisory-')
    result = []
    for raw in paths:
        require(isinstance(raw, str) and 0 < len(raw) <= 4096 and '\x00' not in raw,
                'pending-input-path-unavailable')
        path = Path(raw)
        require(path.is_absolute() and str(path) == raw and path.parent == security
                and path.name.startswith(prefixes) and path.name not in prefixes,
                'pending-input-scope-unavailable')
        protected(path, directory=True)
        result.append(raw)
    return result


@contextmanager
def scanner_input_directory(data, *, prefix):
    """Fresh owned inputs survive any unknown scanner's caller unwinding."""
    security=protected(Path(data)/'security',directory=True)
    require(prefix in INPUT_PREFIXES, 'fixed-scanner-input-prefix-only')
    active=security/'scanner-runs/active.json'
    require(not os.path.lexists(active), 'pending-scanner-input-retained-inspect-protected-journal')
    path=Path(tempfile.mkdtemp(dir=security,prefix=prefix));os.chmod(path,0o700)
    identity=input_identity(path)
    try:yield str(path)
    finally:
        retain=False
        if os.path.lexists(active):
            try:
                pointer=typed_json(protected(active,maximum=65536).read_bytes())
                operation=pointer.get('operationId')
                require(isinstance(operation,str) and re.fullmatch(r'[a-f0-9]{32}',operation), 'pending-input-operation-unavailable')
                intent=typed_json(protected(active.parent/operation/'intent.json',maximum=1024**2).read_bytes())
                retain=str(path) in retained_intent_inputs(intent,operation,security)
            except BaseException:retain=True
        if not retain:
            remove_input(path,security,identity)


class MaintenanceScanner:
    def __init__(self, data, image):
        require(os.name == 'posix' and os.geteuid() == 0 and isinstance(image,str) and PIN.fullmatch(image), 'root-immutable-maintenance-scanner-only')
        self.data = protected(Path(data),directory=True)
        actual = Path(bounded_process(['findmnt','-n','-o','SOURCE','--target',str(self.data)]).stdout.decode().strip()).resolve(strict=True)
        require(actual == Path('/dev/mapper/autosoft-data').resolve(strict=True), 'scanner-encrypted-data-unavailable')
        protected(self.data / '.autosoft-encrypted',maximum=65536)
        self.image = image
        self.cache = protected(self.data / 'security-cache',directory=True)
        self.security = protected(self.data / 'security',directory=True)
        self.journals = self.security / 'scanner-runs'
        self.journals.mkdir(mode=0o700,exist_ok=True); protected(self.journals,directory=True)
        self.active = self.journals / 'active.json'
        self.lock = self.journals / 'scanner.lock'
        self.content_root = protected(self.data / 'containerd/io.containerd.content.v1.content/blobs/sha256',directory=True)
        self.lock_proof()

    def lock_proof(self):
        lock = protected(self.data / 'config/images.lock.json',maximum=1024**2)
        require(typed_json(lock.read_bytes()).get('trivy') == self.image, 'scanner-must-match-company-image-lock')
        return sha(lock)

    @contextmanager
    def serialized(self):
        import fcntl
        descriptor = os.open(self.lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        info = os.fstat(descriptor)
        try:
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077, 'protected-scanner-lock')
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    def content(self, descriptor):
        require(isinstance(descriptor,dict) and DIGEST.fullmatch(descriptor.get('digest',''))
                and type(descriptor.get('size')) is int and 0 < descriptor['size'] <= 4 * 1024**2, 'scanner-descriptor-unavailable')
        path = protected(self.content_root / descriptor['digest'][7:],maximum=4 * 1024**2)
        raw = path.read_bytes()
        require(len(raw) == descriptor['size'] and hashlib.sha256(raw).hexdigest() == descriptor['digest'][7:], 'scanner-protected-content-mismatch')
        return raw

    def identity(self):
        values = typed_json(docker('image','inspect','--platform','linux/amd64',self.image).stdout)
        require(isinstance(values,list) and len(values) == 1, 'one-maintenance-scanner-image')
        selected = values[0]; descriptor = selected.get('Descriptor')
        require(selected.get('Os') == 'linux' and selected.get('Architecture') == 'amd64' and isinstance(descriptor,dict)
                and descriptor.get('mediaType') in MANIFEST_TYPES and descriptor.get('digest') == selected.get('Id'), 'concrete-maintenance-scanner-image')
        manifest_raw = self.content(descriptor); manifest = typed_json(manifest_raw)
        reference_digest = self.image.split('@')[1]
        if reference_digest != selected['Id']:
            path = protected(self.content_root / reference_digest[7:],maximum=4 * 1024**2)
            parent_raw = path.read_bytes(); parent = typed_json(parent_raw)
            require(hashlib.sha256(parent_raw).hexdigest() == reference_digest[7:] and parent.get('mediaType') in INDEX_TYPES,
                    'exact-maintenance-scanner-parent-index')
            members = parent.get('manifests')
            require(isinstance(members,list) and 1 <= len(members) <= 64 and sum(canonical(item) == canonical(descriptor) for item in members) == 1
                    and sum(item.get('platform',{}).get('os') == 'linux' and item.get('platform',{}).get('architecture') == 'amd64' for item in members) == 1,
                    'unique-maintenance-scanner-parent-selection')
        config_descriptor = manifest.get('config'); config_raw = self.content(config_descriptor); config = typed_json(config_raw)
        require(config.get('os') == 'linux' and config.get('architecture') == 'amd64'
                and config.get('rootfs',{}).get('diff_ids') == selected.get('RootFS',{}).get('Layers')
                and all(selected.get('Config',{}).get(key) == value for key,value in config.get('config',{}).items()), 'independent-maintenance-scanner-config-rootfs')
        require(not selected['Config'].get('Volumes'), 'scanner-implicit-volumes-unavailable')
        container_descriptor = dict(descriptor)
        if 'platform' not in container_descriptor:
            container_descriptor['platform'] = {'architecture':'amd64','os':'linux'}
        require(container_descriptor['platform'] == {'architecture':'amd64','os':'linux'}, 'scanner-exact-platform')
        return dict(selected=selected,descriptor=descriptor,containerDescriptor=container_descriptor,
                    requestedImage=self.image, runtimeImageId=reference_digest,
                    selectedManifestSha256=hashlib.sha256(manifest_raw).hexdigest(),configSha256=hashlib.sha256(config_raw).hexdigest(),
                    compressedLayerBytesHashed=False)

    def inspect(self, identifier):
        require(isinstance(identifier,str) and ID.fullmatch(identifier), 'full-scanner-id-required')
        rows = typed_json(docker('inspect',identifier).stdout)
        require(isinstance(rows,list) and len(rows) == 1 and rows[0].get('Id') == identifier, 'exact-scanner-id-inspection')
        return rows[0]

    def owned(self,binding,running=None):
        value = self.inspect(binding['id']); host=value.get('HostConfig',{}); state=value.get('State',{})
        require(value.get('Name') == '/'+binding['name'] and value.get('Image') == binding['runtimeImageId']
                and value.get('Platform') == 'linux' and canonical(value.get('ImageManifestDescriptor')) == canonical(binding['containerDescriptor'])
                and profile(value) == binding['profileSha256'], 'maintenance-scanner-provenance-drift')
        config = value.get('Config',{})
        require(config.get('Image') == self.image and config.get('Cmd') == binding['arguments']
                and config.get('Labels') == dict(binding['inheritedConfig'].get('Labels') or {},**{LABEL:binding['operationId']}), 'maintenance-scanner-config-drift')
        for key,item in binding['inheritedConfig'].items():
            if key not in ('Image','Cmd','Labels'):
                require(config.get(key) == item, 'maintenance-scanner-inherited-config-drift')
        limits = binding['policy']
        require(host.get('Runtime') == 'runsc' and host.get('NetworkMode') == binding['network']
                and host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
                and all(type(host.get(key)) is int and host[key] == target for key,target in
                        (('Memory',limits['memory']),('NanoCpus',2 * 10**9),('PidsLimit',128)))
                and host.get('RestartPolicy') == {'Name':'no','MaximumRetryCount':0}, 'maintenance-scanner-resource-drift')
        require(host.get('IpcMode') == 'private' and host.get('PidMode') == '' and host.get('UTSMode') in ('',None)
                and host.get('Tmpfs') == {'/tmp':'size='+limits['temporary']+',mode=1777'}
                and host.get('CapDrop') == ['ALL'] and host.get('CapAdd') in (None,[])
                and host.get('SecurityOpt') in (['no-new-privileges'],['no-new-privileges:true'])
                and host.get('LogConfig',{}).get('Type') == 'none'
                and not any(host.get(key) for key in ('PortBindings','ExtraHosts','Links','VolumesFrom','Devices','DeviceRequests','DeviceCgroupRules','Sysctls')),
                'maintenance-scanner-host-isolation-drift')
        mounts = value.get('Mounts',[])
        actual = [dict(source=item.get('Source'),target=item.get('Destination'),writable=item.get('RW')) for item in mounts if item.get('Type') == 'bind']
        expected_binds = [item['source']+':'+item['target']+(':rw,z' if item['writable'] else ':ro,z') for item in binding['mounts']]
        require(canonical(sorted(actual,key=lambda item:item['target'])) == canonical(sorted(binding['mounts'],key=lambda item:item['target']))
                and canonical(sorted(host.get('Binds') or [])) == canonical(sorted(expected_binds))
                and len({item.get('Destination') for item in mounts}) == len(mounts)
                and all(item.get('Type') == 'bind' or item.get('Type') == 'tmpfs' and item.get('Destination') == '/tmp' for item in mounts), 'maintenance-scanner-mount-drift')
        require(type(state.get('Running')) is bool and all(state.get(key) is False for key in ('OOMKilled','Paused','Restarting','Dead')), 'maintenance-scanner-state-unavailable')
        if running is not None:
            require(state['Running'] is running, 'maintenance-scanner-running-unconfirmed')
        return value

    def absent(self, identifier):
        values = docker('ps','--all','--no-trunc','--format','{{.ID}}').stdout.decode('ascii').splitlines()
        require(len(values) == len(set(values)) and len(values) <= 10000 and all(ID.fullmatch(item) for item in values), 'maintenance-scanner-inventory-unavailable')
        return identifier not in values

    def cleanup(self,binding):
        current = self.owned(binding)
        if current['State']['Running']:
            docker('stop','--time','60',binding['id'],timeout=75)
        self.owned(binding,False)
        docker('rm',binding['id'],timeout=30)
        require(self.absent(binding['id']), 'maintenance-scanner-cleanup-unconfirmed')

    def inputs(self,mounts):
        result = []
        for source,target in mounts:
            source = protected(Path(source),directory=True)
            require(source.parent == self.security and source.name.startswith(INPUT_PREFIXES)
                    and source != self.cache and not source.is_relative_to(self.cache), 'scoped-maintenance-scanner-input')
            result.append((source,target))
        return result

    def reconcile_pending(self):
        if not os.path.lexists(self.active):
            return
        prior = typed_json(protected(self.active,maximum=65536).read_bytes())
        operation = prior.get('operationId')
        require(isinstance(operation,str) and re.fullmatch(r'[a-f0-9]{32}',operation), 'pending-maintenance-scanner-unavailable')
        folder = protected(self.journals/operation,directory=True)
        binding_path = folder/'binding.json'
        require(os.path.lexists(binding_path), 'unknown-maintenance-scanner-create-retained')
        binding = typed_json(protected(binding_path,maximum=1024**2).read_bytes())
        captured = typed_json(protected(folder/'created-id.json',maximum=1024).read_bytes())
        require(binding.get('operationId') == operation and binding.get('imageLockSha256') == self.lock_proof()
                and binding.get('name') == 'autosoft-maintenance-scan-'+operation
                and isinstance(binding.get('id'),str) and ID.fullmatch(binding['id'])
                and captured == {'id':binding['id']}
                and binding.get('contentIdentitySha256') == hashlib.sha256(canonical(self.identity())).hexdigest(),
                'pending-maintenance-scanner-binding-unavailable')
        result_path=folder/'result.json'
        if os.path.lexists(result_path):
            previous=typed_json(protected(result_path,maximum=65536).read_bytes())
            require(previous.get('status')!='quarantined' and isinstance(previous.get('preservation'),dict)
                    and previous['preservation'] and all(value is True for value in previous['preservation'].values()),
                    'quarantined-scanner-preservation-requires-company-reconciliation')
        inputs=self.inputs([(Path(path),target) for path,target in binding['inputPaths']])
        current_policy=policy(binding['arguments'],inputs,binding['network'],binding['policy']['cacheWritable'])
        require(canonical(current_policy)==canonical(binding['policy']), 'pending-scanner-policy-unavailable')
        require({str(path):tree_hashes(path) for path,_ in inputs}==binding['inputHashes']
                and {str(path):input_identity(path) for path,_ in inputs}==binding['inputIdentities'],
                'pending-scanner-input-preservation-unavailable')
        cache=tree_hashes(self.cache)
        require(binding['policy']['cacheWritable'] is True or cache==binding['cacheHashes'], 'pending-scanner-cache-preservation-unavailable')
        if not self.absent(binding['id']):
            self.cleanup(binding)
        require(self.absent(binding['id']), 'pending-maintenance-scanner-absence-unconfirmed')
        final_cache=tree_hashes(self.cache)
        require(self.lock_proof()==binding['imageLockSha256']
                and hashlib.sha256(canonical(self.identity())).hexdigest()==binding['contentIdentitySha256']
                and {str(path):tree_hashes(path) for path,_ in inputs}==binding['inputHashes']
                and {str(path):input_identity(path) for path,_ in inputs}==binding['inputIdentities']
                and (binding['policy']['cacheWritable'] is True or final_cache==binding['cacheHashes']),
                'pending-scanner-final-preservation-unavailable')
        write_exclusive(folder/('reconciled-'+uuid.uuid4().hex+'.json'),dict(status='captured_scanner_absent',operationId=operation,
                        checkedAt=STAMP(),cleanupConfirmed=True,preservation={'confirmed':True}))
        self.active.unlink();fsync_directory(self.journals)

    def prune_confirmed(self, *, now=None):
        """Seven-day private scanner evidence only; uncertain journals survive."""
        now=now or datetime.now(timezone.utc)
        require(not os.path.lexists(self.active), 'pending-scanner-journal-retained')
        for folder in self.journals.iterdir():
            if not re.fullmatch(r'[a-f0-9]{32}',folder.name):continue
            protected(folder,directory=True)
            receipts=[path for path in folder.iterdir() if path.name=='result.json' or re.fullmatch(r'reconciled-[a-f0-9]{32}\.json',path.name)]
            valid=[];quarantined=False
            for path in receipts:
                proof=typed_json(protected(path,maximum=65536).read_bytes())
                require(proof.get('operationId')==folder.name, 'scanner-journal-operation-unavailable')
                if proof.get('status')=='quarantined':quarantined=True;continue
                if proof.get('status') not in ('completed','unavailable','captured_scanner_absent'):continue
                if proof.get('cleanupConfirmed') is not True or not proof.get('preservation') or not all(value is True for value in proof['preservation'].values()):continue
                checked=datetime.fromisoformat(proof['checkedAt'].replace('Z','+00:00'))
                require(checked.tzinfo is not None and checked<=now, 'scanner-journal-time-unavailable')
                valid.append(checked)
            if quarantined or not valid or (now-max(valid)).total_seconds()<=7*86400:continue
            binding=typed_json(protected(folder/'binding.json',maximum=1024**2).read_bytes())
            captured=typed_json(protected(folder/'created-id.json',maximum=1024).read_bytes())
            require(binding.get('operationId')==folder.name and captured=={'id':binding.get('id')}
                    and isinstance(binding.get('id'),str) and ID.fullmatch(binding['id']), 'scanner-expired-journal-identity-unavailable')
            require(self.absent(binding['id']), 'scanner-expired-journal-container-not-absent')
            paths=list(folder.iterdir())
            allowed={'intent.json','created-id.json','binding.json','start-intent.json','result.json','stdout','stderr'}
            for path in paths:
                require(path.name in allowed or path.name in PROGRESS_FILES or re.fullmatch(r'reconciled-[a-f0-9]{32}\.json',path.name), 'foreign-scanner-journal-file-preserved')
                protected(path,maximum=32*1024**2)
                if path.name in PROGRESS_FILES:validate_progress(path,folder.name,now=now)
            inputs=self.inputs([(Path(path),target) for path,target in binding['inputPaths'] if os.path.lexists(path)])
            for path,_ in inputs:
                require(tree_hashes(path)==binding['inputHashes'][str(path)], 'expired-scanner-input-bytes-unavailable')
                remove_input(path,self.security,binding['inputIdentities'][str(path)])
            for path in paths:path.unlink()
            folder.rmdir();fsync_directory(self.journals)

    def scan(self,arguments,mounts=(),network='none',writable_cache=False):
        require(threading.current_thread() is threading.main_thread(), 'maintenance-scanner-main-process-only')
        limits = policy(arguments,mounts,network,writable_cache)
        with self.serialized():
            self.reconcile_pending()
            self.prune_confirmed()
            inputs = self.inputs(mounts)
            cache_before = tree_hashes(self.cache)
            input_before = {str(path):tree_hashes(path) for path,_ in inputs}
            input_identities={str(path):input_identity(path) for path,_ in inputs}
            image_lock = self.lock_proof(); identity=self.identity()
            # Bounded retained evidence; no automatic deletion of unknown journals.
            records = list(self.journals.iterdir())
            require(len(records) < 512, 'maintenance-scanner-history-capacity-unavailable')
            operation = uuid.uuid4().hex; name='autosoft-maintenance-scan-'+operation
            folder=self.journals/operation;folder.mkdir(mode=0o700);fsync_directory(self.journals)
            cache_option='rw,z' if writable_cache else 'ro,z'
            create=['create','--platform','linux/amd64','--pull=never','--name',name,'--label',LABEL+'='+operation,
                    '--runtime=runsc','--network',network,'--ipc=private','--restart=no','--read-only','--cap-drop=ALL',
                    '--security-opt=no-new-privileges','--memory='+str(limits['memory']),'--cpus=2','--pids-limit=128',
                    '--log-driver=none','--tmpfs','/tmp:size='+limits['temporary']+',mode=1777',
                    '--volume',str(self.cache)+':/cache:'+cache_option]
            for source,target in inputs:create.extend(('--volume',str(source)+':'+target+':ro,z'))
            create.extend((self.image,*arguments))
            intent=dict(operationId=operation,mode=limits['mode'],imageLockSha256=image_lock,
                        commandSha256=hashlib.sha256(canonical(create)).hexdigest(),status='create_pending',inputPaths=[str(path) for path,_ in inputs])
            write_exclusive(folder/'intent.json',intent);replace_pointer(self.active,intent)
            binding=None;complete=False;raw_output=None
            diagnostics=ScanDiagnostics(folder,operation)
            outcome=dict(operationId=operation,status='unavailable',cleanupConfirmed=False,mode=limits['mode'])
            old_handlers={number:signal.signal(number,abort_signal) for number in (signal.SIGINT,signal.SIGTERM)}
            try:
                diagnostics.mark('create_requested')
                identifier=docker(*create).stdout.decode('ascii').strip()
                require(ID.fullmatch(identifier), 'unknown-maintenance-scanner-create-output')
                write_exclusive(folder/'created-id.json',dict(id=identifier))
                diagnostics.mark('created_container_inspection')
                created=self.inspect(identifier)
                candidate=dict(id=identifier,name=name,operationId=operation,imageLockSha256=image_lock,
                  contentIdentitySha256=hashlib.sha256(canonical(identity)).hexdigest(),
                  runtimeImageId=identity['runtimeImageId'],containerDescriptor=identity['containerDescriptor'],
                  inheritedConfig=identity['selected']['Config'],profileSha256=profile(created),
                  arguments=list(arguments),network=network,policy=limits,
                  inputPaths=[(str(path),target) for path,target in inputs],inputHashes=input_before,inputIdentities=input_identities,cacheHashes=cache_before,
                  mounts=[dict(source=str(self.cache),target='/cache',writable=writable_cache)]+
                         [dict(source=str(path),target=target,writable=False) for path,target in inputs])
                diagnostics.mark('container_ownership')
                state=self.owned(candidate,False)['State']
                require(state.get('Status')=='created' and type(state.get('Pid')) is int and state['Pid']==0
                        and type(state.get('ExitCode')) is int and state['ExitCode']==0
                        and state.get('StartedAt')==state.get('FinishedAt')=='0001-01-01T00:00:00Z', 'maintenance-scanner-never-started-unconfirmed')
                write_exclusive(folder/'binding.json',candidate);binding=candidate
                diagnostics.mark('binding_confirmed')
                diagnostics.mark('source_identity_before_start')
                require(self.lock_proof()==image_lock and canonical(self.identity())==canonical(identity), 'maintenance-scanner-input-identity-drift')
                write_exclusive(folder/'start-intent.json',dict(id=identifier,operationId=operation))
                diagnostics.mark('attachment')
                result=bounded_process(docker_command('start','--attach',identifier),timeout=limits['timeout'],expected=None,
                    outputs={'stdout':folder/'stdout','stderr':folder/'stderr'})
                diagnostics.observed_exit('cliExitCode',result.returncode)
                diagnostics.mark('exit_and_ownership')
                stopped=self.owned(binding,False)
                diagnostics.observed_exit('containerExitCode',stopped['State'].get('ExitCode'))
                require(type(stopped['State'].get('ExitCode')) is int and stopped['State']['ExitCode']==result.returncode==0, 'maintenance-scanner-exit-unavailable')
                diagnostics.mark('post_scan_preservation')
                require(self.lock_proof()==image_lock and canonical(self.identity())==canonical(identity), 'maintenance-scanner-final-image-identity-drift')
                require({str(path):tree_hashes(path) for path,_ in inputs}==input_before, 'maintenance-scanner-input-bytes-drift')
                if not writable_cache:
                    require(tree_hashes(self.cache)==cache_before, 'maintenance-scanner-readonly-feed-drift')
                else:
                    tree_hashes(self.cache)
                diagnostics.mark('output_decoding')
                raw_output=protected(folder/'stdout',maximum=32 * 1024**2).read_text(encoding='utf-8',errors='strict')
                outcome.update(status='completed',exitCode=0,stdoutSha256=sha(folder/'stdout'),stderrSha256=sha(folder/'stderr'))
                diagnostics.mark('scan_output_completed')
                complete=True
            except BaseException as error:
                # Never include raw subprocess argv/stderr, credentials or paths.
                diagnostics.fail(error)
                outcome['status']='unavailable'
            finally:
                for number in (signal.SIGINT,signal.SIGTERM):signal.signal(number,signal.SIG_IGN)
                try:
                    diagnostics.mark('cleanup',required=False)
                    if binding is not None:
                        try:
                            self.cleanup(binding);outcome['cleanupConfirmed']=True
                        except BaseException as error:
                            diagnostics.fail(error,cleanup=True)
                            outcome['status']='quarantined'
                    else:
                        outcome['status']='quarantined'
                    diagnostics.mark('post_cleanup_preservation',required=False)
                    checks={
                        'companyImageLock':lambda:self.lock_proof()==image_lock,
                        'scannerContentIdentity':lambda:canonical(self.identity())==canonical(identity),
                        'inputBytes':lambda:{str(path):tree_hashes(path) for path,_ in inputs}==input_before,
                        'cache':lambda:bool(tree_hashes(self.cache) == cache_before) if not writable_cache else isinstance(tree_hashes(self.cache),dict),
                    }
                    outcome['preservation']={}
                    for key,check in checks.items():
                        try:outcome['preservation'][key]=check() is True
                        except BaseException:outcome['preservation'][key]=False
                    if not all(outcome['preservation'].values()):
                        diagnostics.fail(ScannerUnavailable('maintenance-scanner-input-bytes-drift'))
                        outcome['status']='quarantined'
                    diagnostics.mark('receipt_prepared',required=False)
                    outcome.update(diagnostics.summary())
                    if diagnostics.storage_failed:
                        complete=False
                        if outcome['status']!='quarantined':outcome['status']='unavailable'
                    outcome['checkedAt']=STAMP();write_exclusive(folder/'result.json',outcome)
                    if outcome['cleanupConfirmed'] and all(outcome['preservation'].values()):
                        self.active.unlink();fsync_directory(self.journals)
                finally:
                    for number,handler in old_handlers.items():signal.signal(number,handler)
            if not (complete and outcome['cleanupConfirmed'] and all(outcome['preservation'].values())):
                raise unavailable_diagnostic(outcome)
            return raw_output


def run_scanner(data,image,arguments,mounts=(),network='none',writable_cache=False):
    # Refuse unsupported/writable work before even creating Docker configuration.
    policy(arguments,mounts,network,writable_cache)
    with local_docker_configuration(data):
        return MaintenanceScanner(data,image).scan(arguments,mounts,network,writable_cache)
