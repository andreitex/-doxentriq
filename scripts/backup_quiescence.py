#!/usr/bin/env python3
"""Quiesce only independently inspected, immutable platform container IDs.

No container is deleted or addressed by a reusable name. An uncertain shutdown,
new writer, changed container configuration, paused process or forced kill makes
the checkpoint fail. Only original running processes stopped here may restart.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from backup_recovery import BackupJournal, MAX_ORIGINALS, digest, observation, reconcile

ID = re.compile(r'^[a-f0-9]{64}$')
PIN = re.compile(r'^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$')


def _local_command(args):
    """The existing four fixed operations, on the local daemon only."""
    fixed = args == ['docker', 'ps', '--no-trunc', '--filter', 'label=io.autosoft.managed=true', '--format', '{{.ID}}']
    fixed = fixed or (len(args) == 3 and args[:2] in (['docker', 'inspect'], ['docker', 'start']) and ID.fullmatch(args[-1]))
    fixed = fixed or (len(args) == 5 and args[:4] == ['docker', 'stop', '--time', '60'] and ID.fullmatch(args[-1]))
    if not fixed:
        raise ValueError('Unknown checkpoint control operation')
    socket = Path('/var/run/docker.sock')
    target = socket.resolve(strict=True)
    value = socket.stat()
    if target != Path('/run/docker.sock') or not stat.S_ISSOCK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o007:
        raise ValueError('Checkpoint local Docker socket is unavailable')
    return ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', *args[1:]]


def _capture(args):
    # POSIX production transport: stop reading before the output bound, with
    # process creation, descriptor setup and reap in one failure envelope.
    command = _local_command(args)
    process, selector, raw = None, None, bytearray()
    deadline = time.monotonic() + 30
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Checkpoint inspection timed out')
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                elif len(raw) + len(chunk) > 2 * 1024**2:
                    raise ValueError('Checkpoint inspection exceeds its bound')
                else:
                    raw.extend(chunk)
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise ValueError('Checkpoint inspection is unavailable')
        return raw.decode('utf-8', errors='strict')
    finally:
        try:
            if process is not None and process.poll() is None:
                process.kill()
        finally:
            try:
                if process is not None:
                    process.wait(timeout=5)
            finally:
                try:
                    if selector is not None:
                        selector.close()
                finally:
                    if process is not None and process.stdout is not None:
                        process.stdout.close()


def _execute(args):
    subprocess.run(_local_command(args), check=True, timeout=120, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})


def container_identity(value, identifier, data):
    """Return an in-memory digest; never retain environment values in evidence."""
    if not isinstance(value, dict) or not isinstance(identifier, str) or not ID.fullmatch(identifier) or value.get('Id') != identifier:
        raise ValueError('Checkpoint container identity is unavailable')
    config, host, mounts = value.get('Config', {}), value.get('HostConfig', {}), value.get('Mounts')
    if type(config) is not dict or type(host) is not dict or type(mounts) is not list or len(mounts) > 256:
        raise ValueError('Checkpoint mount/configuration provenance is unavailable')
    labels = config.get('Labels') or {}
    if type(labels) is not dict or labels.get('io.autosoft.managed') != 'true' or type(config.get('Image')) is not str or not PIN.fullmatch(config['Image']) or type(value.get('Image')) is not str or not ID.fullmatch(value['Image'].removeprefix('sha256:')):
        raise ValueError('Checkpoint requires an owned immutable image')
    if labels.get('com.docker.compose.project') == 'autosoft':
        if type(labels.get('com.docker.compose.service')) is not str or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', labels['com.docker.compose.service']) or str(labels.get('com.docker.compose.oneoff', '')).lower() != 'false' or labels.get('com.docker.compose.container-number') != '1' or labels.get('io.autosoft.app') or labels.get('io.autosoft.connector.scope'):
            raise ValueError('Checkpoint requires a normal company service')
    else:
        owners = [labels.get(key) for key in ('io.autosoft.app', 'io.autosoft.connector.scope') if labels.get(key)]
        if labels.get('com.docker.compose.project') or len(owners) != 1 or type(owners[0]) is not str or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,128}', owners[0]):
            raise ValueError('Checkpoint container ownership is ambiguous')
    data = Path(data).resolve(strict=True)
    # Every managed process must have at least one known encrypted bind;
    # helper/socket mounts may be outside it, but cannot supply app data.
    encrypted = False
    bindings = []
    data_device = data.stat().st_dev
    def storage_identity(info):
        # Directory mtime/size changes with ordinary writes. Bind identity,
        # ownership and mode must remain fixed across stop and resumption.
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    for index, item in enumerate(mounts):
        if type(item) is not dict:
            raise ValueError('Checkpoint mount provenance is unavailable')
        if item.get('Type') == 'bind' and isinstance(item.get('Source'), str):
            source = Path(item['Source'])
            if source == data or data in source.parents:
                try:
                    before = source.lstat()
                    resolved = source.resolve(strict=True)
                    after = source.lstat()
                    if resolved != source or not (stat.S_ISREG(after.st_mode) or stat.S_ISDIR(after.st_mode)) or after.st_dev != data_device or storage_identity(before) != storage_identity(after):
                        raise ValueError('Checkpoint encrypted bind identity is unavailable')
                    encrypted = True
                    bindings.append((index, storage_identity(after)))
                except OSError:
                    raise ValueError('Checkpoint encrypted bind is unavailable') from None
    if not encrypted:
        raise ValueError('Checkpoint process has no canonical encrypted bind')
    immutable = {key: value.get(key) for key in ('Id', 'Image', 'Name', 'Config', 'HostConfig', 'Mounts')}
    immutable['encryptedBindIdentities'] = bindings
    return hashlib.sha256(json.dumps(immutable, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def container_observation(value, identifier, data):
    profile = container_identity(value, identifier, data)
    state = value.get('State')
    if type(state) is not dict or any(type(state.get(key)) is not bool for key in ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled')):
        raise ValueError('Checkpoint lifecycle state is unavailable')
    if any(state[key] for key in ('Paused', 'Restarting', 'Dead', 'OOMKilled')):
        raise ValueError('Checkpoint lifecycle state is uncertain')
    if any(type(state.get(key)) is not int or state[key] < 0 for key in ('ExitCode', 'Pid')) or type(value.get('RestartCount')) is not int or value['RestartCount'] < 0:
        raise ValueError('Checkpoint lifecycle counters are invalid')
    if any(type(state.get(key)) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z', state[key]) for key in ('StartedAt', 'FinishedAt')):
        raise ValueError('Checkpoint lifecycle timestamps are unavailable')
    if state['Running']:
        if state.get('Status') != 'running' or state['Pid'] <= 0:
            raise ValueError('Checkpoint running state is unavailable')
    elif state.get('Status') != 'exited' or state['Pid'] != 0:
        raise ValueError('Checkpoint stopped state is unavailable')
    fixed = {key: state[key] for key in ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled', 'ExitCode', 'Pid', 'Status', 'StartedAt', 'FinishedAt')}
    fixed['RestartCount'] = value['RestartCount']
    return dict(profileSha256=profile, stateSha256=digest(fixed), running=state['Running'],
                cleanStopped=not state['Running'] and state['ExitCode'] in {0, 130, 143})


class QuiescedContainers:
    def __init__(self, data, mode, capture=_capture, execute=_execute):
        if mode not in {'nightly', 'incremental'}:
            raise ValueError('Unknown checkpoint shutdown scope')
        self.data, self.mode, self.capture, self.execute = Path(data), mode, capture, execute
        self.original, self.attempted = {}, []
        self.journal = BackupJournal(self.data)

    @staticmethod
    def require_idle(data):
        BackupJournal(data).require_idle()

    @classmethod
    def recover(cls, data, resume=False, capture=_capture, execute=_execute):
        helper = cls(data, 'nightly', capture, execute)
        return reconcile(data, helper.observe, (lambda identifier: execute(['docker', 'start', identifier])) if resume else None)

    def observe(self, identifier):
        return observation(container_observation(self.inspect(identifier), identifier, self.data))

    def inspect(self, identifier):
        text = self.capture(['docker', 'inspect', identifier])
        if len(text) > 2 * 1024**2:
            raise ValueError('Checkpoint inspection exceeds its bound')
        values = json.loads(text)
        if not isinstance(values, list) or len(values) != 1:
            raise ValueError('Checkpoint requires one exact inspected container')
        return values[0]

    def selected(self):
        text = self.capture(['docker', 'ps', '--no-trunc', '--filter', 'label=io.autosoft.managed=true', '--format', '{{.ID}}'])
        ids = text.splitlines()
        if len(ids) > MAX_ORIGINALS or len(ids) != len(set(ids)) or any(not ID.fullmatch(item) for item in ids):
            raise ValueError('Checkpoint running-process inventory is invalid')
        chosen = {}
        for identifier in ids:
            value = self.inspect(identifier)
            digest = container_identity(value, identifier, self.data)
            labels = value['Config']['Labels']
            # Compose services also carry managed=true. Incremental backups
            # must leave MySQL/Redis/RabbitMQ running while stopping writers.
            company = labels.get('com.docker.compose.project') == 'autosoft'
            if self.mode == 'nightly' or not company or labels['com.docker.compose.service'] in {'broker', 'worker', 'control', 'packager'}:
                chosen[identifier] = (digest, value)
        return chosen

    def __enter__(self):
        self.journal.require_idle()
        try:
            selected = self.selected()
            # Validate every state before making the first mutation.
            for identifier, (digest, value) in selected.items():
                current = container_observation(value, identifier, self.data)
                if current['running'] is not True:
                    raise ValueError('Paused or uncertain running state cannot enter a checkpoint')
                self.original[identifier] = current
            self.journal.begin(self.mode, self.original)
            for identifier in self.original:
                if self.observe(identifier) != self.original[identifier]:
                    raise ValueError('Checkpoint original changed before shutdown')
                self.journal.record('stop-intent', identifier)
                try:
                    self.attempted.append(identifier)
                    self.execute(['docker', 'stop', '--time', '60', identifier])
                    stopped = self.confirm_stopped(identifier)
                    self.journal.record('stopped', identifier, state=stopped['stateSha256'])
                except BaseException:
                    self.journal.uncertain(identifier, 'stop')
                    raise
            if self.selected():
                raise ValueError('A new or resumed writer prevents a consistent checkpoint')
            return self
        except BaseException:
            if self.journal.intent is not None:
                # Only a published active intent can have authorized stops.
                # If setup failed earlier, no recovery command is dispatched.
                try:
                    if self.journal.active.exists():
                        try:
                            self.journal.failure()
                        except Exception:
                            # A missing failure marker cannot skip original
                            # reconciliation. A partial marker still fails the
                            # closed journal validation before any command.
                            pass
                        finally:
                            self.resume()
                except Exception:
                    raise ValueError('Original checkpoint process could not be safely resumed; review host state') from None
            raise

    def confirm_identity(self, identifier):
        value = self.inspect(identifier)
        if container_identity(value, identifier, self.data) != self.original[identifier]['profileSha256']:
            raise ValueError('Checkpoint process configuration or storage changed')
        return value

    def confirm_stopped(self, identifier):
        current = container_observation(self.confirm_identity(identifier), identifier, self.data)
        if current['cleanStopped'] is not True:
            raise ValueError('Checkpoint shutdown was not confirmed clean')
        receipt = self.journal.read_event(identifier + '-stopped.json')
        if receipt is not None and current['stateSha256'] != receipt['stateSha256']:
            raise ValueError('Checkpoint stopped lifecycle state changed')
        return current

    def confirm_boundary(self):
        for identifier in self.original:
            self.confirm_stopped(identifier)
        if self.selected():
            raise ValueError('Checkpoint writer boundary changed')

    def resume(self):
        result = self.recover(self.data, True, self.capture, self.execute)
        if result['status'] != 'originals_resumed_backup_unverified':
            raise ValueError('Original checkpoint process could not be safely resumed; review host state')
        self.attempted = []

    def __exit__(self, kind, value, traceback):
        try:
            if kind is not None:
                try:
                    self.journal.failure()
                except Exception:
                    # Preserve the capture exception after safe resumption.
                    pass
        finally:
            self.resume()
        return False
