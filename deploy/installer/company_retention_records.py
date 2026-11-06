"""Bounded original retention-record DATA and exclusive protected persistence.

These files/flags never establish execution origin on their own. The company
Bash parent must authenticate its worker, observe successful direct-child exit,
and hold the original admission lock before using an inspected confirmation.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat

STAGES = ('company-platform-store', 'company-source-materialize')
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid')
RECORD_FIELDS = frozenset(('schemaVersion','scope','command','deliveryIdentitySha256','binding',
    'planBase64','result','outcomeSha256','stageAcknowledged','fullInstallationCompleted','nativeQualified'))
PLAN_FIELDS = frozenset(('schemaVersion','scope','stage','installationRequestSha256','operationId',
    'storeOperationId','stageRequest','stageRequestSha256','actionSha256'))
UNKNOWN = []


def require(value, reason='retention-record-unavailable'):
    if value is not True: raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False)+'\n').encode('ascii')


def decode(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = json.loads(raw)
    require(type(value) is dict and canonical(value) == raw)
    return value


def digest(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)
    return value


def operation(request, stage):
    require(stage in STAGES)
    return request['operationId'] if stage == STAGES[0] else sha(('source:'+request['operationId']).encode())[:32]


def delivery_identity(auth):
    return sha(canonical(dict(delivery=auth['delivery_pin'], package=auth['package_pins'],
        operational=auth['operational_catalog'], bootstrap=auth['bootstrap_pins'], fingerprint=auth['fingerprint'])))


def record(raw, command, identity):
    value = decode(raw, 32768)
    require(set(value) == RECORD_FIELDS and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
        and value['scope'] == 'FULL_RETENTION_CLI_CLOSED_SCOPE_ONLY' and value['command'] == command
        and value['deliveryIdentitySha256'] == digest(identity) and type(value['binding']) is dict
        and value['stageAcknowledged'] is False and value['fullInstallationCompleted'] is False
        and value['nativeQualified'] is False)
    return value


def bound_plan(raw, request, request_raw, stage):
    plan = decode(raw, 16384)
    require(set(plan) == PLAN_FIELDS and type(plan['schemaVersion']) is int and plan['schemaVersion'] == 1
        and plan['scope'] == 'RETENTION_STAGE_PLAN_ONLY' and plan['stage'] == stage
        and plan['installationRequestSha256'] == sha(request_raw)
        and plan['operationId'] == operation(request, stage) and plan['storeOperationId'] == request['operationId']
        and type(plan['stageRequest']) is dict and plan['stageRequestSha256'] == sha(canonical(plan['stageRequest'])))
    digest(plan['actionSha256'])
    return plan


def binding(request, request_raw, stage, plan_raw=None, parent=None):
    value = dict(stage=stage, requestSha256=sha(request_raw), releaseSha256=request['releaseSha256'],
        operationId=operation(request, stage), storeOperationId=request['operationId'],
        planSha256=sha(plan_raw) if plan_raw else None)
    if parent is not None:
        require(type(parent) is list and len(parent) == 7 and all(type(item) is str for item in parent)
            and parent[4] == sha(request_raw) and parent[5] == stage
            and re.fullmatch('s-[A-Za-z0-9]{12}', parent[3]) is not None)
        value.update(session=parent[3], actionSha256=digest(parent[6]))
    return value


def planning_record(raw, request, request_raw, stage, identity):
    value = record(raw, 'plan-stage', identity)
    require(value['binding'] == binding(request, request_raw, stage)
        and value['result'] is None and value['outcomeSha256'] is None
        and type(value['planBase64']) is str and len(value['planBase64']) <= 21848)
    plan_raw = base64.b64decode(value['planBase64'], validate=True)
    require(base64.b64encode(plan_raw).decode('ascii') == value['planBase64'])
    plan = bound_plan(plan_raw, request, request_raw, stage)
    return plan_raw, plan['actionSha256']


def completion(executed_raw, verified_raw, plan_raw, request, request_raw, stage, parent, identity):
    plan = bound_plan(plan_raw, request, request_raw, stage)
    expected = binding(request, request_raw, stage, plan_raw, parent)
    require(expected['actionSha256'] == plan['actionSha256'])
    executed = record(executed_raw, 'execute-stage', identity)
    verified = record(verified_raw, 'verify-stage', identity)
    for value in (executed, verified):
        require(value['binding'] == expected and value['planBase64'] is None and type(value['result']) is dict)
        result = value['result']
        require(result['ownedResourcesKnownReleased'] is True and result['stageAcknowledged'] is False
            and result['nativeAuthorized'] is False and result['stagePlanSha256'] == sha(plan_raw)
            and type(result['operationResult']) is dict
            and result['operationOutcomeSha256'] == digest(value['outcomeSha256'])
            and sha(canonical(result['operationResult'])) == value['outcomeSha256'])
    require(executed['outcomeSha256'] == verified['outcomeSha256']
        and executed['result']['operationResult'] == verified['result']['operationResult'])
    effects = verified['result']['retainedEffectsObservation']
    require(type(effects) is dict and set(effects) == {'operationResult','operationOutcomeSha256',
        'exactEffectsReread','ownedReadHandlesKnownReleased','outerContextsRequireClosure','stageAcknowledged','nativeQualified'}
        and effects['operationResult'] == verified['result']['operationResult']
        and effects['operationOutcomeSha256'] == verified['outcomeSha256']
        and effects['exactEffectsReread'] is True and effects['ownedReadHandlesKnownReleased'] is True
        and effects['outerContextsRequireClosure'] is True and effects['stageAcknowledged'] is False
        and effects['nativeQualified'] is False)
    outcome = verified['outcomeSha256']
    return ('retention-verified-v1\nrequest='+sha(request_raw)+'\nsession='+parent[3]+'\nstage='+stage+
        '\naction='+plan['actionSha256']+'\noutcome='+outcome+'\nverification='+sha(verified_raw)+'\n').encode('ascii')


def stage_path(operation_id, stage):
    require(type(operation_id) is str and re.fullmatch('[a-f0-9]{32}', operation_id) is not None
        and operation_id != '0'*32 and stage in STAGES)
    return '/opt/autosoft-company/evidence/'+operation_id+'/'+stage


@contextmanager
def directory(path):
    """Hold nofollow protected directory ancestry; permit our own directory writes."""
    require(type(path) is str and PurePosixPath(path).as_posix() == path and path.startswith('/')
        and '..' not in PurePosixPath(path).parts and len(PurePosixPath(path).parts) <= 32 and not UNKNOWN)
    rows = []
    try:
        for name in PurePosixPath(path).parts:
            parent = rows[-1][0] if rows else None
            fd = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent)
            rows.append((fd,parent,name,None))
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
            rows[-1] = (fd,parent,name,tuple(getattr(info,key) for key in FIELDS))
        def check():
            require(not UNKNOWN)
            for fd,parent,name,expected in rows:
                require(expected == tuple(getattr(os.fstat(fd),key) for key in FIELDS)
                    == tuple(getattr(os.stat(name,dir_fd=parent,follow_symlinks=False),key) for key in FIELDS))
        check()
        require(stat.S_IMODE(os.fstat(rows[-1][0]).st_mode) == 0o700)
        yield rows[-1][0], check
        check()
    finally:
        failed = False
        for fd,*_ in reversed(rows):
            try: os.close(fd)
            except BaseException: UNKNOWN.append(fd); failed = True
        require(not failed, 'retention-directory-close-unknown')


def prepare_stage(operation_id, stage):
    path = stage_path(operation_id, stage)
    with directory('/opt/autosoft-company/evidence') as (base,check):
        try: os.mkdir(operation_id,0o700,dir_fd=base)
        except FileExistsError: pass  # Existing foundation evidence is read-only.
        check(); os.fsync(base)
    with directory(str(PurePosixPath(path).parent)) as (operation_fd,check):
        os.mkdir(stage,0o700,dir_fd=operation_fd)  # Never adopt a prior stage.
        check(); os.fsync(operation_fd)
    with directory(path) as (stage_fd,check):
        os.fsync(stage_fd); check()
    return path


def write_record(path, name, raw, *, mode=0o400):
    require(re.fullmatch(r'/opt/autosoft-company/evidence/[a-f0-9]{32}/(company-platform-store|company-source-materialize)',path) is not None
        and name in ('planned.json','plan.json','verified.json','confirmation')
        and type(raw) is bytes and 0 < len(raw) <= 32768 and mode in (0o400,0o600)
        and (name == 'confirmation') == (mode == 0o600))
    with directory(path) as (directory_fd,check):
        fd = os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(fd,raw[offset:offset+65536]);require(type(count) is int and count > 0);offset += count
            os.fchmod(fd,mode);os.fsync(fd)
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == mode and info.st_size == len(raw)
                and os.pread(fd,len(raw)+1,0) == raw)
            require((info.st_dev,info.st_ino) == tuple(getattr(os.stat(name,dir_fd=directory_fd,follow_symlinks=False),key) for key in ('st_dev','st_ino')))
            check();os.fsync(directory_fd);check()
        finally:
            try: os.close(fd)
            except BaseException: UNKNOWN.append(fd);raise
