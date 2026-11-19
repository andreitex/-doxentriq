"""Read-only observation of one completed initial identity provisioning attempt.

This is data verification, not release authentication or installer authority.
The caller must supply expected identities from authenticated stage inputs and
bind the resulting observation to the genuine parent before accepting it.
Close this reader before a declared sibling-directory mutation, then reopen and
compare the observation afterward. No existing record is rewritten or adopted.
"""
import hashlib
import json
import os
import re
import stat
from pathlib import Path

EVENTS = ('intent', 'created', 'start-intent', 'completed', 'removed')
MESSAGE = b'Scoped app realm provisioner configured.\n'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def require(value):
    if not value:
        raise ValueError('Identity provisioning evidence is incomplete or changed; preserve it for IT review')


def identity(value):
    return tuple(getattr(value, field) for field in FIELDS)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


class ProvisionEvidence:
    PHASE = 'provision'
    SCOPE = 'IDENTITY_PROVISION_RECORD_OBSERVATION_ONLY'

    def output(self):
        return MESSAGE

    def __init__(self, data, expected, *, check_authority):
        require(os.name == 'posix' and os.geteuid() == 0 and callable(check_authority))
        require(type(expected) is dict and set(expected) == {'operationId', 'sourceSha256', 'caSha256',
            'image', 'imageId', 'networkId', 'keycloakId'})
        require(type(expected['operationId']) is str and re.fullmatch('[a-f0-9]{32}', expected['operationId'])
            and expected['operationId'] != '0'*32)
        require(type(expected['image']) is str and re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}', expected['image']))
        require(type(expected['imageId']) is str and re.fullmatch('sha256:[a-f0-9]{64}', expected['imageId']))
        for key in ('sourceSha256', 'caSha256', 'networkId', 'keycloakId'):
            require(type(expected[key]) is str and re.fullmatch('[a-f0-9]{64}', expected[key]))
        data = Path(data)
        require(data.is_absolute() and str(data) == str(data.resolve(strict=True)))
        self.path = data/'company'/('identity-'+expected['operationId'])
        self.expected = dict(expected)
        self.authority = check_authority
        self.dirs, self.files, self.closed = [], {}, False
        try:
            current = Path('/')
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.dirs.append((current, fd, identity(os.fstat(fd))))
            for part in self.path.parts[1:]:
                current /= part
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                self.dirs.append((current, fd, identity(os.fstat(fd))))
            for _, _, before in self.dirs:
                require(before[3:5] == (0, 0) and not stat.S_IMODE(before[2]) & 0o022)
            require(stat.S_IMODE(self.dirs[-1][2][2]) == 0o700)
            self.authority()
            names = {'provision.mjs', 'ca.crt'} | {f'{i:03}-{self.PHASE}-{event}.json' for i, event in enumerate(EVENTS, 1)}
            require(set(os.listdir(fd)) == names)
            self.rows = {}
            for name in sorted(names):
                limit = 131072 if name == 'provision.mjs' else 32768 if name == 'ca.crt' else 4096
                opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
                self.files[name] = [opened, None, None]
                before = identity(os.fstat(opened))
                owner = 10001 if name in ('provision.mjs', 'ca.crt') else 0
                require(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) == 0o400
                    and before[3:5] == (owner, owner) and before[5] == 1 and 0 < before[6] <= limit
                    and before[0] == self.dirs[-1][2][0])
                raw = os.pread(opened, limit+1, 0)
                require(len(raw) == before[6] and identity(os.fstat(opened)) == before)
                self.files[name] = [opened, before, sha(raw)]
                if name.endswith('.json'):
                    value = json.loads(raw, object_pairs_hook=unique_object)
                    require(canonical(value) == raw)
                    self.rows[name] = value
            require(self.files['provision.mjs'][2] == expected['sourceSha256']
                and self.files['ca.crt'][2] == expected['caSha256'])
            self._validate_events()
            self.check()
        except BaseException:
            self.close(check=False)
            raise

    def _validate_events(self):
        expected = self.expected
        initial = {key: expected[key] for key in ('image', 'imageId', 'networkId', 'keycloakId', 'sourceSha256', 'caSha256')}
        container = None
        for index, event in enumerate(EVENTS, 1):
            row = self.rows[f'{index:03}-{self.PHASE}-{event}.json']
            require(type(row) is dict and set(row) == {'phase', 'event', 'values'}
                and row['phase'] == self.PHASE and row['event'] == event and type(row['values']) is dict)
            values = row['values']
            if event == 'intent':
                require(values == initial)
                continue
            if event == 'created':
                container = values.get('containerId')
                require(type(container) is str and re.fullmatch('[a-f0-9]{64}', container))
            wanted = {'containerId': container}
            if event == 'completed':
                wanted['outputSha256'] = sha(self.output())
            require(values == wanted)
        self.container = container

    def check(self):
        require(not self.closed)
        self.authority()
        for path, fd, before in self.dirs:
            require(identity(os.fstat(fd)) == before == identity(path.lstat()))
        require(set(os.listdir(self.dirs[-1][1])) == set(self.files))
        for name, (fd, before, digest) in self.files.items():
            require(identity(os.fstat(fd)) == before
                == identity(os.stat(name, dir_fd=self.dirs[-1][1], follow_symlinks=False)))
            raw = os.pread(fd, before[6]+1, 0)
            require(len(raw) == before[6] and sha(raw) == digest)

    def observation(self):
        self.check()
        result = dict(schemaVersion=1, scope=self.SCOPE,
            expected=dict(self.expected), containerId=self.container,
            directoryIdentity=list(self.dirs[-1][2]),
            files={name: dict(identity=list(before), sha256=digest) for name, (_, before, digest) in sorted(self.files.items())},
            livePolicyVerified=False, parentAuthorityEstablished=False, publicStartupAllowed=False)
        self.check()
        return result

    def close(self, *, check=True):
        if self.closed:
            return
        failure = None
        if check:
            try:
                self.check()
            except BaseException as error:
                failure = error
        for fd in [value[0] for value in self.files.values()] + [value[1] for value in reversed(self.dirs)]:
            try:
                os.close(fd)
            except BaseException as error:
                failure = failure or error
        self.closed = True
        if failure:
            raise failure

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.close()


class VerificationEvidence(ProvisionEvidence):
    """Read the closed separate verification; never assert current live policy."""
    PHASE = 'verify'
    SCOPE = 'IDENTITY_VERIFICATION_RECORD_OBSERVATION_ONLY'

    def __init__(self, data, expected, *, owner_subject, check_authority):
        require(type(owner_subject) is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', owner_subject))
        self.owner = owner_subject
        super().__init__(data, expected, check_authority=check_authority)

    def output(self):
        # Match the original helper's JSON.stringify insertion order and newline.
        return (json.dumps(dict(scope='INITIAL_IDENTITY_POLICY_READBACK',ownerSubject=self.owner,
            configuredPolicyVerified=True,browserMfaQualified=False,publicStartupAllowed=False),
            separators=(',', ':'))+'\n').encode()
