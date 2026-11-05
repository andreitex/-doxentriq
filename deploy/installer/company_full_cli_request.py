"""Inert bounded full-retention CLI inputs; no execution or ACK authority.

The future company entry authenticates this module before using it. Returned
values describe inputs only; they are not live parent/source/storage objects.
No filesystem, adapter, process, environment or native default is selected.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re

STAGES = ('company-platform-store', 'company-source-materialize')
COMMANDS = ('plan-stage', 'execute-stage', 'verify-stage')
MAX_REQUEST = 4096
MAX_INVOCATION = 4096
REQUEST_FIELDS = frozenset(('schemaVersion', 'mode', 'operationId', 'releaseSha256',
    'bundleRoot', 'sourceRoot', 'keyPath', 'dataDir', 'backingFile', 'capacityGiB',
    'runscVersion', 'runscSha512'))
INVOCATION_FIELDS = frozenset(('schemaVersion', 'scope', 'command', 'stage',
    'requestSha256', 'releaseSha256', 'operationId', 'storeOperationId',
    'planSha256', 'outcomeSha256', 'parent'))


class FullCliRequestUnavailable(ValueError):
    pass


def require(value):
    if value is not True:
        raise FullCliRequestUnavailable('company-full-cli-request-unavailable')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _hash(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)


def _decode(raw, expected, limit):
    _hash(expected)
    require(type(raw) is bytes and 0 < len(raw) <= limit and sha(raw) == expected)
    try:
        value = json.loads(raw)
        require(type(value) is dict and canonical(value) == raw)
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise FullCliRequestUnavailable('company-full-cli-request-unavailable') from None
    return value


def _path(value):
    require(type(value) is str and 1 < len(value) <= 1024 and value.isascii()
            and not value.startswith('//') and re.fullmatch('/[A-Za-z0-9_./-]+', value) is not None)
    path = PurePosixPath(value)
    require(path.as_posix() == value and '..' not in path.parts and len(path.parts) <= 32
            and all(len(part) <= 255 for part in path.parts))


def validate_request(raw, *, request_sha256):
    """Preserve the original planner's closed full-installation request policy."""
    value = _decode(raw, request_sha256, MAX_REQUEST)
    require(set(value) == REQUEST_FIELDS and type(value['schemaVersion']) is int
            and value['schemaVersion'] == 1 and type(value['mode']) is str
            and value['mode'] == 'full-installation')
    for name, pattern in (('operationId', '[a-f0-9]{32}'), ('releaseSha256', '[a-f0-9]{64}'),
                          ('runscVersion', '[0-9]{8}\\.[0-9]{1,8}'), ('runscSha512', '[a-f0-9]{128}')):
        require(type(value[name]) is str and re.fullmatch(pattern, value[name]) is not None)
    for name in ('bundleRoot', 'sourceRoot', 'keyPath', 'dataDir', 'backingFile'):
        _path(value[name])
    require(type(value['capacityGiB']) is int and 32 <= value['capacityGiB'] <= 4096)
    data, backing, base = value['dataDir'], value['backingFile'], '/opt/autosoft-company'
    require(data.startswith('/srv/') and data != '/srv/autosoft-company'
            and not data.startswith('/srv/autosoft-company/') and backing != data
            and not backing.startswith(data + '/') and not data.startswith(backing + '/')
            and backing != base and not backing.startswith(base + '/') and not base.startswith(backing + '/'))
    for name in ('bundleRoot', 'sourceRoot'):
        require(value[name].startswith(base + '/incoming/') and not value[name].startswith(data + '/'))
    require(value['keyPath'].startswith(base + '/bootstrap/') and value['keyPath'].endswith('.pem'))
    return value


def _parent(value, stage, request_sha256):
    require(type(value) is list and len(value) == 7
            and all(type(item) is str and 0 < len(item) <= 64 for item in value))
    require(all(re.fullmatch('0|[1-9][0-9]{0,9}', item) is not None for item in value[:3]))
    pid, directory, lock = (int(item) for item in value[:3])
    require(1 < pid < 2**31 and 3 <= directory <= 1048575 and 3 <= lock <= 1048575 and directory != lock)
    require(re.fullmatch('s-[A-Za-z0-9]{12}', value[3]) is not None
            and value[4] == request_sha256 and value[5] == stage)
    _hash(value[6])


def validate_invocation(raw, *, invocation_sha256, request_raw, request_sha256):
    """Closed fixed command/stage bindings; the controller must rederive action.

    Plan/action/outcome hashes are references, not evidence of effect or release.
    The original P.ParentInput parser and actual held parent remain mandatory.
    """
    request = validate_request(request_raw, request_sha256=request_sha256)
    value = _decode(raw, invocation_sha256, MAX_INVOCATION)
    require(set(value) == INVOCATION_FIELDS and type(value['schemaVersion']) is int
            and value['schemaVersion'] == 1 and value['scope'] == 'FULL_RETENTION_CLI_INVOCATION_ONLY'
            and type(value['command']) is str and value['command'] in COMMANDS
            and type(value['stage']) is str and value['stage'] in STAGES
            and type(value['requestSha256']) is str and value['requestSha256'] == request_sha256
            and type(value['releaseSha256']) is str and value['releaseSha256'] == request['releaseSha256'])
    require(all(type(value[name]) is str and re.fullmatch('[a-f0-9]{32}', value[name]) is not None
                for name in ('operationId', 'storeOperationId')))
    # This CLI's Store transaction uses the complete request's original op ID;
    # Source may use a separately bound op ID carried in its canonical plan.
    require(value['storeOperationId'] == request['operationId']
            and (value['stage'] != STAGES[0] or value['operationId'] == value['storeOperationId']))
    if value['command'] == COMMANDS[0]:
        require(value['parent'] is None and value['planSha256'] is None and value['outcomeSha256'] is None)
    else:
        _hash(value['planSha256'])
        _parent(value['parent'], value['stage'], request_sha256)
        if value['command'] == COMMANDS[1]:
            require(value['outcomeSha256'] is None)
        else:
            _hash(value['outcomeSha256'])
    return value
