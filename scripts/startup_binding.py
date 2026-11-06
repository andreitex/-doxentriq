"""Read-only initialized startup binding; no readiness, adoption or startup effects."""
from contextlib import contextmanager
import importlib.util
import math
import os
from pathlib import Path
import re
import stat
import sys
import time


def _sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if '__company_captured_dependencies__' in globals():
    from types import MappingProxyType, ModuleType
    _captured_dependencies = __company_captured_dependencies__
    if type(_captured_dependencies) is not MappingProxyType or set(_captured_dependencies) != {'scripts/runtime_layout.py', 'scripts/installation_identity.py'}:
        raise ValueError('company-captured-dependencies-unavailable')
    if any(type(_captured_dependencies[key]) is not ModuleType for key in _captured_dependencies):
        raise ValueError('company-captured-dependencies-unavailable')
    L = _captured_dependencies['scripts/runtime_layout.py']
    I = _captured_dependencies['scripts/installation_identity.py']
else:
    L = _sibling('startup_runtime_layout', 'runtime_layout.py')
    I = _sibling('startup_installation_identity', 'installation_identity.py')
    Q, A, C = L.Q, L.Q._allocation, L.C
Q, A, C = L.Q, L.Q._allocation, L.C
SCOPE = 'STARTUP_BINDING_ONLY'


@contextmanager
def _controls(files, directories, records, *, backing_file=None):
    """Hold exact controls; allow ciphertext timestamps only on named backing.

    The authenticated storage record selects this one metadata-only file. Its
    device, inode, mode, owner, group, link count and size stay exact. Keys and
    configuration retain all nine fields. No backing/key bytes are read.
    """
    C.require(type(directories) is dict and 0 < len(directories) <= 64)
    C.require(type(records) is dict and 0 < len(records) <= 8)
    C.require(backing_file is None or backing_file in records and records[backing_file] is None)
    handles, errors = [], []
    try:
        for path, (uid, gid, modes) in directories.items():
            before = files.directory(path, uid, gid, modes)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            handles.append((path, fd, before, True, (uid, gid, modes)))
            files.compare_opened(before, files.descriptor(fd))
        for path, maximum in records.items():
            before = files.protected(path, private=True)
            C.require(maximum is None or type(maximum) is int and 0 < before.st_size <= maximum)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, 'O_BINARY', 0))
            length = 7 if path == backing_file else 9
            handles.append((path, fd, files.descriptor(fd), False, (maximum, length)))
            C.require(C.identity(before)[:length] == C.identity(files.descriptor(fd))[:length])
        yield
        for path, fd, before, directory, policy in handles:
            current = files.directory(path, *policy) if directory else files.protected(path, private=True)
            opened = files.descriptor(fd)
            if directory:
                files.compare_opened(current, opened)
                C.require(C.directory_binding(opened) == C.directory_binding(before),
                          'Startup control directory changed during verification')
            else:
                length = policy[1]
                C.require(C.identity(current)[:length] == C.identity(opened)[:length] == C.identity(before)[:length],
                          'Startup control record changed during verification')
    finally:
        for _, fd, _, _, _ in reversed(handles):
            try: os.close(fd)
            except BaseException as failure: errors.append(failure)
        if errors and sys.exc_info()[1] is None: raise errors[0]


def _host(data, root, directory, files):
    intent = I.read_intent(directory, files=files)
    final = I.verify_host_record(directory, files=files)
    C.require(final['data_dir'] == str(data) and final['install_root'] == str(root))
    C.require(not os.path.lexists(directory / 'installation.pending.json'),
              'Pending host storage evidence requires company reconciliation')
    receipt = C.fields(files.read(directory / 'installation.storage-receipt.json'),
                       {'data_dir', 'install_root', 'storage_file', 'installation_id', 'creation_stage', 'luks_uuid'})
    C.require(receipt['creation_stage'] == 'new-luks-created')
    I.installation_id(receipt['luks_uuid'])
    C.require({key: receipt[key] for key in final} == final)
    config = files.read(data / 'config/installation.json')
    installation_id = I.verify_reference(intent, config)
    return intent, final, receipt, config, installation_id


def encrypted_proof(data, receipt, *, command=Q.output):
    """Fixed read-only Linux queries; UUID/backing/target are all compulsory."""
    data, storage = Path(data), Path(receipt['storage_file'])
    I.path_value(str(data)); I.path_value(str(storage))
    uuid = I.installation_id(receipt['luks_uuid'])
    actual = command(['/usr/sbin/cryptsetup', 'luksUUID', str(storage)]).strip()
    C.require(actual == uuid, 'Encrypted backing UUID differs from the recorded storage receipt')
    rows = command(['/usr/sbin/cryptsetup', 'status', 'autosoft-data']).splitlines()
    C.require(0 < len(rows) <= 32)
    types, devices = [], []
    for row in rows:
        C.require(len(row) <= 4096)
        label, separator, value = row.strip().partition(':')
        if separator and label == 'type': types.append(value.strip())
        if separator and label == 'device': devices.append(value.strip())
    C.require(types == ['LUKS2'] and len(devices) == 1
              and re.fullmatch(r'/dev/loop[0-9]{1,10}', devices[0]) is not None)
    backing = command(['/usr/sbin/losetup', '--noheadings', '--output', 'BACK-FILE', '--', devices[0]]).strip()
    C.require(backing == str(storage) and storage.resolve(strict=True) == storage,
              'Encrypted mapper belongs to another backing file')
    fields = command(['/usr/bin/findmnt', '-n', '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS', '--target', str(data)]).strip().split()
    C.require(len(fields) == 4 and fields[0] == str(data) and fields[2] == 'xfs')
    options = fields[3].split(',')
    keys = [value.split('=', 1)[0] for value in options]
    C.require(len(keys) == len(set(keys)) and {'rw', 'nosuid', 'nodev'} <= set(options)
              and 'ro' not in options and bool({'prjquota', 'pquota'} & set(options)))
    mapper = Path('/dev/mapper/autosoft-data')
    C.require(Path(fields[1]).resolve(strict=True) == mapper.resolve(strict=True))
    source = Q.mount_proof(data, command)
    C.require(source == fields[1])
    return dict(target=str(data), filesystem='xfs', source=source, storageFile=str(storage),
                luksUuid=uuid, options=sorted(options),
                mapperIdentity=[str(value) for value in C.identity(mapper.stat())],
                mapperPathIdentity=[str(value) for value in C.identity(mapper.lstat())])


def verify(data, root, *, host_directory=Path('/etc/autosoft'), files=None, command=Q.output,
           mount=encrypted_proof, layout=L.verify, gate_factory=None, allocation_factory=None,
           read_state=Q.load_state, clock=time.monotonic, timeout=50):
    """Only independently initialized exact records qualify this held invocation.

    All injected adapters are trusted company test seams, never app inputs.
    Lock wait budgets do not bound journal traversal, OS creation or filesystem IO.
    A returned observation cannot protect future actions after these locks release.
    """
    C.require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 50)
    files = files or L.NativeFiles(); files.require_root()
    data, root, host_directory = Path(data), Path(root), Path(host_directory)
    deadline = clock() + timeout
    before = _host(data, root, host_directory, files)
    intent, final, receipt, config, installation_id = before
    storage = Path(final['storage_file'])
    C.require(storage != host_directory / 'storage.key', 'Backing file cannot alias the unlock key')
    directories = {}
    for path in (*reversed(data.parents), data, *reversed(root.parents), root,
                 *reversed(host_directory.parents), host_directory,
                 *reversed(storage.parent.parents), storage.parent):
        info = files.protected(path, directory=True)
        directories[path] = (info.st_uid, info.st_gid, {stat.S_IMODE(info.st_mode)})
    directories.update({host_directory: (0, 0, {0o700}), data / 'config': (0, 0, {0o700}),
                        data / 'quota': (0, 0, {0o700}), data / 'runtime': (0, 0, {0o755}),
                        data / 'runtime/storage': (0, 0, {0o700})})
    for name in ('checkpoint-admission', 'checkpoint-admission/operations', 'checkpoint-admission/fences',
                 'allocation', 'allocation/commits'):
        directories[data / 'quota' / name] = (0, 0, {0o700})
    records = {host_directory / I.INTENT: C.MAX_RECORD,
               host_directory / 'installation.json': C.MAX_RECORD,
               host_directory / 'installation.storage-receipt.json': C.MAX_RECORD,
               data / 'config/installation.json': C.MAX_RECORD,
               storage: None, host_directory / 'storage.key': None}
    with _controls(files, directories, records, backing_file=storage):
        C.require(_host(data, root, host_directory, files) == before,
                  'Host binding changed before initialized inspection')
        backing = files.protected(storage, private=True)
        C.require(intent['proposal']['capacity_gib'] * 1024**3 <= backing.st_size < 2**63)
        gate = (gate_factory or C.Gate)(data)
        with gate.inspect_initialized(installation_id, timeout=deadline - clock()) as admission:
            allocation = (allocation_factory or A.Allocation)(data)
            with allocation.inspect_initialized(installation_id, read_state=read_state,
                                                timeout=min(10, deadline - clock())) as quota:
                encrypted = mount(data, receipt, command=command)
                placement = layout(data, files=files)
                C.require(placement == dict(scope='RUNTIME_PLACEMENT_ONLY', status='verified', changed=False, backupReady=False))
                C.require(_host(data, root, host_directory, files) == before,
                          'Host or configuration evidence changed during initialized inspection')
                C.require(mount(data, receipt, command=command) == encrypted,
                          'Encrypted mount changed during initialized inspection')
                result = dict(scope=SCOPE, status='verified', installationId=installation_id,
                              hostSha256=C.digest(dict(intent=intent, final=final, receipt=receipt)),
                              configurationSha256=C.digest(config), admissionSha256=C.digest(admission),
                              allocationSha256=C.digest(quota), encryptedMountSha256=C.digest(encrypted),
                              layoutSha256=C.digest(placement), changed=False, backupReady=False)
    return result


@contextmanager
def fresh_storage_context(data, root, *, host_directory=Path('/etc/autosoft'), files=None,
                          command=Q.output, mount=encrypted_proof, layout=L.verify):
    """Hold read-only storage evidence before and across explicit fresh setup.

    This context grants no installer, admission, allocation or native authority.
    It deliberately does not require or create either runtime journal. All
    adapters are trusted company test seams. IO/command timing and native mount
    behavior require separate qualification; the returned copy is observation.
    """
    files = files or L.NativeFiles(); files.require_root()
    data, root, host_directory = Path(data), Path(root), Path(host_directory)
    before = _host(data, root, host_directory, files)
    intent, final, receipt, config, installation_id = before
    storage = Path(final['storage_file'])
    C.require(storage != host_directory / 'storage.key', 'Backing file cannot alias the unlock key')
    directories = {}
    for path in (*reversed(data.parents), data, *reversed(root.parents), root,
                 *reversed(host_directory.parents), host_directory,
                 *reversed(storage.parent.parents), storage.parent):
        info = files.protected(path, directory=True)
        directories[path] = (info.st_uid, info.st_gid, {stat.S_IMODE(info.st_mode)})
    directories.update({host_directory: (0, 0, {0o700}), data / 'config': (0, 0, {0o700}),
                        data / 'quota': (0, 0, {0o700}), data / 'runtime': (0, 0, {0o755}),
                        data / 'runtime/storage': (0, 0, {0o700}),
                        data / 'config/runtime-layout': (0, 0, {0o700})})
    for name in L.BROKER_DIRECTORIES:
        directories[data / 'runtime' / name] = (10001, 10001, {0o700})
    records = {host_directory / I.INTENT: C.MAX_RECORD,
               host_directory / 'installation.json': C.MAX_RECORD,
               host_directory / 'installation.storage-receipt.json': C.MAX_RECORD,
               data / 'config/installation.json': C.MAX_RECORD,
               storage: None, host_directory / 'storage.key': None}
    base = data / 'config/runtime-layout'
    layout_records = {base / name: C.MAX_RECORD for name in ('intent.json', 'layout.json', 'confirmed.json')}
    with _controls(files, directories, records, backing_file=storage), _controls(files, {base: (0, 0, {0o700})}, layout_records):
        C.require(_host(data, root, host_directory, files) == before)
        backing = files.protected(storage, private=True)
        C.require(intent['proposal']['capacity_gib'] * 1024**3 <= backing.st_size < 2**63)
        encrypted = mount(data, receipt, command=command)
        C.require(type(encrypted) is dict and type(encrypted.get('source')) is str)
        placement = layout(data, files=files)
        C.require(placement == dict(scope='RUNTIME_PLACEMENT_ONLY', status='verified', changed=False, backupReady=False))
        saved = {name: files.read(base / name) for name in ('intent.json', 'layout.json', 'confirmed.json')}
        proof = dict(scope='FRESH_STORAGE_BINDING_ONLY', installationId=installation_id,
                     dataRootSha256=files.root(data), hostSha256=C.digest(dict(intent=intent, final=final, receipt=receipt)),
                     configurationSha256=C.digest(config), encryptedMountSha256=C.digest(encrypted),
                     layoutSha256=C.digest(saved), mountSource=encrypted['source'], changed=False, backupReady=False)
        yield json_copy(proof)
        C.require(_host(data, root, host_directory, files) == before,
                  'Host or configuration changed during fresh storage inspection')
        C.require(mount(data, receipt, command=command) == encrypted,
                  'Encrypted mount changed during fresh storage inspection')
        C.require(layout(data, files=files) == placement)
        C.require({name: files.read(base / name) for name in saved} == saved,
                  'Retained layout changed during fresh storage inspection')


def json_copy(value):
    """Copy bounded trusted evidence without sharing mutable adapter results."""
    import json
    return json.loads(C.canonical(value))
