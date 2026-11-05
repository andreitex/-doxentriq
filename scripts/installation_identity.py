"""Company host identity records; no storage creation, initialization or migration.

An intent must commit before a fresh install creates its backing file or key.
Existing records are verified independently; this module never adopts or resets
an interrupted installation. Installer wiring is a separate, reviewed operation.
"""
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import uuid

if '__company_captured_dependencies__' in globals():
    from types import MappingProxyType, ModuleType
    _captured_dependencies = __company_captured_dependencies__
    if type(_captured_dependencies) is not MappingProxyType or set(_captured_dependencies) != {'scripts/checkpoint_admission.py'}:
        raise ValueError('company-captured-dependencies-unavailable')
    if any(type(_captured_dependencies[key]) is not ModuleType for key in _captured_dependencies):
        raise ValueError('company-captured-dependencies-unavailable')
    C = _captured_dependencies['scripts/checkpoint_admission.py']
else:
    _spec = importlib.util.spec_from_file_location('installation_identity_records', Path(__file__).resolve().with_name('checkpoint_admission.py'))
    C = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(C)
SCOPE = 'HOST_INSTALLATION_IDENTITY_ONLY'
INTENT = 'installation.intent.json'
INPUTS = {'data_dir', 'install_root', 'storage_file', 'capacity_gib'}


def installation_id(value):
    C.require(type(value) is str and str(uuid.UUID(value)) == value, 'A canonical persisted installation UUID is required')
    return value


def path_value(value):
    C.require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+', value) is not None)
    path = PurePosixPath(value)
    C.require(path.is_absolute() and path.as_posix() == value and value != '/' and not value.startswith('//') and '..' not in path.parts)
    return value


def proposal(data_dir, install_root, storage_file, capacity_gib):
    values = {name: path_value(value) for name, value in (('data_dir', data_dir), ('install_root', install_root), ('storage_file', storage_file))}
    C.require(type(capacity_gib) is int and 32 <= capacity_gib < 2**31)
    C.require(len(set(values.values())) == 3)
    C.require(not storage_file.startswith(data_dir + '/'), 'The backing file cannot be inside its encrypted mount')
    return dict(values, capacity_gib=capacity_gib)


def _directory(directory, files):
    files.require_root()
    directory = Path(directory)
    binding = C.directory_binding(files.protected(directory, directory=True, private=True))
    for parent in directory.parents:
        files.protected(parent, directory=True)
    return directory, binding


def _intent(value):
    C.fields(value, {'schemaVersion', 'scope', 'installation_id', 'directory', 'proposal'})
    C.require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and value['scope'] == SCOPE)
    installation_id(value['installation_id'])
    C.fields(value['directory'], {'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'})
    C.require(all(type(item) is str and item.isascii() and item.isdecimal() for item in value['directory'].values()))
    C.fields(value['proposal'], INPUTS)
    C.require(value['proposal'] == proposal(**value['proposal']))
    return value


def read_intent(directory, *, files=None):
    """Read exact protected evidence without creating, repairing or reopening it."""
    files = files or C.NativeFiles()
    directory, binding = _directory(directory, files)
    value = _intent(files.read(directory / INTENT))
    C.require(value['directory'] == binding, 'The recorded host directory was replaced or its permissions changed')
    C.require(C.directory_binding(files.protected(directory, directory=True, private=True)) == binding)
    return value


def create_intent(directory, data_dir, install_root, storage_file, capacity_gib, *, files=None, exists=os.path.lexists, uuid_factory=uuid.uuid4):
    """Explicit fresh-only commit before any backing/key/LUKS effect.

    A lost acknowledgement retains the exclusive original record. Calling this
    function again cannot generate a second identity; use read_intent() to inspect
    the original and a separately reviewed installer stage to continue.
    """
    requested = proposal(data_dir, install_root, storage_file, capacity_gib)
    files = files or C.NativeFiles()
    directory, binding = _directory(directory, files)
    for name in (INTENT, 'installation.json', 'installation.pending.json', 'storage.key'):
        C.require(not exists(directory / name), 'Existing host installation evidence is never adopted by fresh setup')
    C.require(not exists(storage_file), 'The selected backing file already exists; nothing will be overwritten')
    value = dict(schemaVersion=1, scope=SCOPE, installation_id=installation_id(str(uuid_factory())), directory=binding, proposal=requested)
    C.require(C.directory_binding(files.protected(directory, directory=True, private=True)) == binding)
    files.write(directory / INTENT, value)
    C.require(read_intent(directory, files=files) == value)
    return value


def verify_proposal(intent, data_dir, install_root, storage_file, capacity_gib):
    """Reject changed requested geometry instead of replacing the prior identity."""
    _intent(intent)
    C.require(intent['proposal'] == proposal(data_dir, install_root, storage_file, capacity_gib))
    return intent['installation_id']


def verify_reference(intent, record):
    _intent(intent)
    C.require(type(record) is dict)
    expected = installation_id(intent['installation_id'])
    C.require('installation_id' in record and installation_id(record['installation_id']) == expected, 'Missing, legacy or conflicting installation identity requires company review')
    return expected


def verify_host_record(directory, *, pending=False, files=None):
    """Exact read-only pending/final host binding. No LUKS or mount authority."""
    C.require(type(pending) is bool)
    files = files or C.NativeFiles()
    intent = read_intent(directory, files=files)
    path = Path(directory) / ('installation.pending.json' if pending else 'installation.json')
    record = files.read(path)
    names = {'data_dir', 'install_root', 'storage_file', 'installation_id'}
    C.fields(record, names | ({'creation_stage', 'luks_uuid'} if pending else set()))
    verify_reference(intent, record)
    C.require(all(record[key] == intent['proposal'][key] for key in ('data_dir', 'install_root', 'storage_file')))
    if pending:
        C.require(record['creation_stage'] == 'new-luks-created')
        installation_id(record['luks_uuid'])
    C.require(read_intent(directory, files=files) == intent)
    return record
