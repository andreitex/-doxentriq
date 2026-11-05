"""Read-only evidence for the original held Bash installer parent; no activation."""
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
import platform
import re
import select
import stat
import sys


BASE = '/etc/autosoft-install-admission'
RECORD_MAX = 4096
PROC_MAX = 16384
SESSION_MAX = 1024
STAGE_MAX = 64
SCOPE = 'HELD_INSTALLER_PARENT_EVIDENCE_ONLY'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
SESSION = re.compile(r's-[A-Za-z0-9]{12}')
LABEL = re.compile(r'[a-z][a-z0-9-]{0,47}')
DIGEST = re.compile(r'[0-9a-f]{64}')
DECIMAL = re.compile(r'0|[1-9][0-9]{0,19}')


class ParentUnavailable(ValueError):
    """Fixed diagnostics; private input and arbitrary OS errors never escape."""


def require(condition):
    if not condition:
        raise ParentUnavailable('installer-parent-unavailable')


@dataclass(frozen=True)
class ParentInput:
    parent_pid: int
    directory_fd: int
    lock_fd: int
    session: str
    request: str
    stage: str
    action: str

    def validate(self):
        require(type(self.parent_pid) is int and 1 < self.parent_pid < 2**31)
        require(all(type(n) is int and 3 <= n <= 1048575 for n in (self.directory_fd, self.lock_fd)))
        require(self.directory_fd != self.lock_fd)
        for value, pattern in ((self.session, SESSION), (self.request, DIGEST),
                               (self.stage, LABEL), (self.action, DIGEST)):
            require(type(value) is str and pattern.fullmatch(value) is not None)
        return self

    @classmethod
    def from_argv(cls, argv):
        require(type(argv) in (list, tuple) and len(argv) == 7)
        require(all(type(value) is str and 0 < len(value) <= 64 for value in argv))
        require(all(DECIMAL.fullmatch(value) is not None for value in argv[:3]))
        return cls(*(int(value) for value in argv[:3]), *argv[3:]).validate()


@dataclass(frozen=True)
class Metadata:
    st_dev: int
    st_ino: int
    st_mode: int
    st_uid: int
    st_gid: int
    st_nlink: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int

    @classmethod
    def of(cls, value):
        return cls(*(getattr(value, field) for field in FIELDS))

    def validate(self):
        require(all(type(getattr(self, field)) is int for field in FIELDS))
        require(all(getattr(self, field) >= 0 for field in FIELDS[:7]))
        require(self.st_ino > 0 and self.st_nlink > 0)
        return self

    def directory(self):
        self.validate()
        return self.st_dev, self.st_ino, self.st_mode, self.st_uid, self.st_gid


def protected(metadata, directory=False, ancestor=False):
    require(type(metadata) is Metadata)
    metadata.validate()
    require(metadata.st_uid == metadata.st_gid == 0)
    if directory:
        require(stat.S_ISDIR(metadata.st_mode))
        require(not stat.S_IMODE(metadata.st_mode) & 0o022 if ancestor else stat.S_IMODE(metadata.st_mode) == 0o700)
    else:
        require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600)
        require(metadata.st_nlink == 1 and 0 <= metadata.st_size <= RECORD_MAX)
    return metadata


def record(raw, title, keys):
    require(type(raw) is bytes and 0 < len(raw) <= RECORD_MAX and b'\0' not in raw)
    require(all(value < 128 for value in raw))
    text = raw.decode('ascii', 'strict')
    lines = text.split('\n')
    require(len(lines) == len(keys) + 2 and lines[0] == title and lines[-1] == '')
    values = {}
    for line, key in zip(lines[1:-1], keys):
        require(line.startswith(key + '=') and line.count('=') == 1)
        value = line[len(key) + 1:]
        require(value != '')
        values[key] = value
    return values


def shell_metadata(text, current, directory=False):
    """Compare GNU stat's saved fields by exact meaning, including nanoseconds."""
    parts = text.split(':')
    require(len(parts) == (6 if directory else 10))
    require(all(DECIMAL.fullmatch(parts[i]) for i in (0, 1, 3, 4)))
    require(re.fullmatch(r'[0-9a-f]{1,16}', parts[2]) is not None)
    require(re.fullmatch(r'[0-7]{3,4}', parts[5]) is not None)
    expected = (int(parts[0]), int(parts[1]), int(parts[2], 16), int(parts[3]), int(parts[4]))
    require(expected == current.directory() and int(parts[5], 8) == stat.S_IMODE(current.st_mode))
    if not directory:
        require(DECIMAL.fullmatch(parts[6]) and DECIMAL.fullmatch(parts[7]))
        require(int(parts[6]) == current.st_nlink and int(parts[7]) == current.st_size)
        for part, actual in zip(parts[8:], (current.st_mtime_ns, current.st_ctime_ns)):
            require(re.fullmatch(r'-?(0|[1-9][0-9]{0,18})\.[0-9]{1,9}', part) is not None)
            whole, fraction = part.split('.')
            require(int(whole) * 10**9 + int(fraction.ljust(9, '0')) == actual)


def fdinfo(raw, metadata, locked, device):
    require(type(metadata) is Metadata and type(locked) is bool)
    metadata.validate()
    require(type(raw) is bytes and 0 < len(raw) <= RECORD_MAX and b'\0' not in raw)
    require(all(value < 128 for value in raw))
    require(type(device) is tuple and len(device) == 2 and all(type(n) is int and n >= 0 for n in device))
    text = raw.decode('ascii', 'strict')
    require(text.endswith('\n'))
    rows = text.splitlines()
    require(len(rows) == (5 if locked else 4))
    values = {}
    for row in rows:
        key, separator, value = row.partition(':')
        require(separator == ':' and key not in values)
        values[key] = value.strip()
    require(set(values) == ({'pos', 'flags', 'mnt_id', 'ino', 'lock'} if locked else {'pos', 'flags', 'mnt_id', 'ino'}))
    require(values['pos'] == '0' and re.fullmatch(r'[0-7]{1,16}', values['flags']) is not None)
    # Linux amd64 O_ACCMODE/O_RDONLY; parser controls also run on Windows.
    require(int(values['flags'], 8) & 3 == 0)
    require(DECIMAL.fullmatch(values['mnt_id']) and int(values['mnt_id']) > 0)
    require(DECIMAL.fullmatch(values['ino']) and int(values['ino']) == metadata.st_ino)
    if locked:
        match = re.fullmatch(r'[1-9][0-9]{0,9}:\s+FLOCK\s+ADVISORY\s+WRITE\s+(-?[0-9]{1,10})\s+([0-9a-f]{1,8}):([0-9a-f]{1,8}):([0-9]{1,20})\s+0\s+EOF', values['lock'])
        require(match is not None)
        # The acquiring flock helper may have exited; this number is never authority.
        require(-2**31 <= int(match[1]) < 2**31)
        require((int(match[2], 16), int(match[3], 16), int(match[4])) == (*device, metadata.st_ino))
        lock = tuple(match.groups())
    else:
        lock = None
    return int(values['mnt_id']), int(values['flags'], 8), int(values['ino']), lock


def pidfdinfo(raw, metadata, pid):
    require(type(metadata) is Metadata and type(pid) is int and 1 < pid < 2**31)
    metadata.validate()
    require(type(raw) is bytes and 0 < len(raw) <= RECORD_MAX and b'\0' not in raw)
    require(all(value < 128 for value in raw) and raw.endswith(b'\n'))
    rows = raw.decode('ascii').splitlines()
    require(len(rows) == 6)
    values = {}
    for row in rows:
        key, separator, value = row.partition(':')
        require(separator == ':' and key not in values)
        values[key] = value.strip()
    require(set(values) == {'pos', 'flags', 'mnt_id', 'ino', 'Pid', 'NSpid'})
    require(values['pos'] == '0' and re.fullmatch(r'[0-7]{1,16}', values['flags']))
    require(int(values['flags'], 8) & 3 == 2)
    require(DECIMAL.fullmatch(values['mnt_id']) and int(values['mnt_id']) > 0)
    require(DECIMAL.fullmatch(values['ino']) and int(values['ino']) == metadata.st_ino)
    # Host installer profile: one matching procfs PID view, no namespace nesting.
    require(values['Pid'] == values['NSpid'] == str(pid))
    return int(values['mnt_id']), int(values['flags'], 8), int(values['ino']), pid


def parent_stat(raw, pid):
    require(type(raw) is bytes and 0 < len(raw) <= PROC_MAX and b'\0' not in raw)
    require(all(value < 128 for value in raw))
    text = raw.decode('ascii', 'strict')
    prefix = str(pid) + ' (bash) '
    require(text.startswith(prefix) and text.endswith('\n'))
    values = text[len(prefix):-1].split(' ')
    require(len(values) == 50 and values[0] in ('R', 'S', 'D', 'T', 't', 'I'))
    require(all(re.fullmatch(r'-?[0-9]{1,20}', value) for value in values[1:]))
    require(int(values[19]) > 0)
    return int(values[19])


def process_status(raw, pid, ppid=None, bash=False):
    require(type(raw) is bytes and 0 < len(raw) <= PROC_MAX and b'\0' not in raw)
    require(all(value < 128 for value in raw))
    values = {}
    for row in raw.decode('ascii', 'strict').splitlines():
        key, separator, value = row.partition(':')
        require(separator == ':' and key not in values)
        values[key] = value.strip()
    require(values.get('Pid') == str(pid) and values.get('Tgid') == str(pid))
    require(values.get('TracerPid') == '0')
    require(all(values.get(key, '').split() == ['0'] * 4 for key in ('Uid', 'Gid')))
    state = values.get('State', '').split()
    require(state and state[0] in ('R', 'S', 'D', 'T', 't', 'I'))
    if ppid is not None:
        require(values.get('PPid') == str(ppid))
    if bash:
        require(values.get('Name') == 'bash')


class NativeSystem:
    """Linux amd64 read-only syscalls; never opens the parent's admission OFD."""

    def __init__(self):
        require(sys.platform == 'linux' and platform.machine() in ('x86_64', 'amd64'))
        require(all(hasattr(os, name) for name in ('pidfd_open', 'pread', 'major', 'minor', 'getresuid', 'getresgid', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_DIRECTORY')))
        require(all(hasattr(select, name) for name in ('poll', 'POLLIN', 'POLLHUP', 'POLLERR')))
        self.proc_fd = None

    def lstat(self, path):
        return Metadata.of(os.stat(path, follow_symlinks=False))

    def fstat(self, fd):
        return Metadata.of(os.fstat(fd))

    def open(self, parent, name, directory):
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0)
        return os.open(name, flags, dir_fd=parent)

    def cloexec(self, fd):
        return not os.get_inheritable(fd)

    def close(self, fd):
        os.close(fd)

    def device(self, value):
        return os.major(value), os.minor(value)

    def filesystem(self, fd):
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.fstatfs
        function.argtypes = (ctypes.c_int, ctypes.c_void_p)
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(512)
        require(function(fd, ctypes.byref(buffer)) == 0)
        return ctypes.c_ulong.from_buffer(buffer).value

    def read(self, fd, limit):
        return os.pread(fd, limit + 1, 0)

    def names(self, fd, limit):
        result = []
        with os.scandir(fd) as entries:
            for entry in entries:
                require(len(result) < limit)
                result.append(entry.name)
        require(len(result) == len(set(result)))
        return tuple(sorted(result))

    def _proc_read(self, name, limit):
        require(self.proc_fd is not None and '/fd/' not in name and 'environ' not in name)
        fd = self.open(self.proc_fd, name, False)
        try:
            require(self.cloexec(fd))
            before = self.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0)
            raw = os.read(fd, limit + 1)
            require(0 < len(raw) <= limit and self.fstat(fd) == before)
            return raw
        finally:
            self.close(fd)

    def identity(self, arguments):
        own = os.getpid()
        require(os.getppid() == arguments.parent_pid and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        process_status(self._proc_read(f'{own}/status', PROC_MAX), own, arguments.parent_pid)
        process_status(self._proc_read(f'{arguments.parent_pid}/status', PROC_MAX), arguments.parent_pid, bash=True)
        start = parent_stat(self._proc_read(f'{arguments.parent_pid}/stat', PROC_MAX), arguments.parent_pid)
        boot = self._proc_read('sys/kernel/random/boot_id', 64)
        require(re.fullmatch(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n', boot) is not None)
        namespaces = []
        for kind in ('pid', 'mnt'):
            observed = []
            for pid in (own, arguments.parent_pid):
                path = f'{pid}/ns/{kind}'
                value = os.stat(path, dir_fd=self.proc_fd)
                link = os.readlink(path, dir_fd=self.proc_fd)
                require(link == kind + ':[' + str(value.st_ino) + ']')
                observed.append((value.st_dev, value.st_ino))
            require(observed[0] == observed[1])
            namespaces.append(observed[0])
        exe = f'{arguments.parent_pid}/exe'
        target = os.readlink(exe, dir_fd=self.proc_fd)
        require(target in ('/usr/bin/bash', '/bin/bash'))
        binary = Metadata.of(os.stat(exe, dir_fd=self.proc_fd))
        require(binary == Metadata.of(os.stat(target)))
        require(stat.S_ISREG(binary.st_mode) and binary.st_uid == binary.st_gid == 0)
        require(not stat.S_IMODE(binary.st_mode) & 0o022 and stat.S_IMODE(binary.st_mode) & 0o111)
        return own, arguments.parent_pid, boot.decode().strip(), start, tuple(namespaces), binary

    def pidfd(self, pid):
        return os.pidfd_open(pid, 0)

    def alive(self, fd):
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return not poller.poll(0)

    def parent_descriptor(self, pid, fd):
        path = f'{pid}/fd/{fd}'
        return Metadata.of(os.stat(path, dir_fd=self.proc_fd)), os.readlink(path, dir_fd=self.proc_fd)

    def descriptor_info(self, pid, fd):
        return self._proc_read(f'{pid}/fdinfo/{fd}', RECORD_MAX)

    def inherited(self, directory, lock):
        targets = {(directory.st_dev, directory.st_ino), (lock.st_dev, lock.st_ino)}
        count = 0
        with os.scandir('/proc/' + str(os.getpid()) + '/fd') as entries:
            for entry in entries:
                count += 1
                require(count <= 1024 and re.fullmatch(r'0|[1-9][0-9]{0,6}', entry.name))
                value = os.stat(entry.path)
                if (value.st_dev, value.st_ino) in targets:
                    return True
        return False


class HeldParent:
    def __init__(self, arguments, system, injected):
        self.arguments = arguments.validate()
        self.system, self.injected = system, injected
        self.handles, self.directories, self.files = [], {}, {}
        self.live = False
        self.fdinfo_binding = None

    def _own(self, fd):
        require(type(fd) is int and fd >= 0 and fd not in self.handles)
        self.handles.append(fd)
        require(self.system.cloexec(fd))
        return fd

    def _directory(self, path, parent, leaf, ancestor=False):
        before = protected(self.system.lstat(path), directory=True, ancestor=ancestor)
        fd = self._own(self.system.open(parent, leaf, True))
        require(self.system.fstat(fd).directory() == before.directory())
        require(self.system.lstat(path).directory() == before.directory())
        self.directories[path] = fd, before, ancestor
        return fd

    def _file(self, path, parent, leaf):
        before = protected(self.system.lstat(path))
        fd = self._own(self.system.open(parent, leaf, False))
        require(self.system.fstat(fd) == before)
        raw = self.system.read(fd, RECORD_MAX)
        require(type(raw) is bytes and len(raw) == before.st_size and len(raw) <= RECORD_MAX)
        require(self.system.fstat(fd) == before and self.system.lstat(path) == before)
        self.files[path] = fd, before, raw
        return raw

    def acquire(self):
        root = self._directory('/', None, '/', True)
        proc = self._directory('/proc', root, 'proc', True)
        require(self.system.filesystem(proc) == 0x9fa0)
        self.system.proc_fd = proc
        initial = self.system.identity(self.arguments)
        self.pid_fd = self._own(self.system.pidfd(self.arguments.parent_pid))
        require(self.system.alive(self.pid_fd))
        require(self.system.identity(self.arguments) == initial)
        self.identity = initial
        self.pidfd_metadata = self.system.fstat(self.pid_fd)
        require(type(self.pidfd_metadata) is Metadata)
        self.pidfd_metadata.validate()
        self.pidfd_binding = pidfdinfo(self.system.descriptor_info(initial[0], self.pid_fd), self.pidfd_metadata, self.arguments.parent_pid)
        self._pidfd_guard()
        parent_directory, target = self.system.parent_descriptor(self.arguments.parent_pid, self.arguments.directory_fd)
        protected(parent_directory, directory=True)
        require(target == BASE)
        parent_lock, target = self.system.parent_descriptor(self.arguments.parent_pid, self.arguments.lock_fd)
        protected(parent_lock)
        require(target == BASE + '/install.lock' and parent_lock.st_size == 0)
        require(not self.system.inherited(parent_directory, parent_lock))
        etc = self._directory('/etc', root, 'etc', True)
        base = self._directory(BASE, etc, 'autosoft-install-admission')
        sessions = self._directory(BASE + '/sessions', base, 'sessions')
        session_path = BASE + '/sessions/' + self.arguments.session
        session = self._directory(session_path, sessions, self.arguments.session)
        self.base, self.sessions, self.session_path, self.session_fd = base, sessions, session_path, session
        lock_raw = self._file(BASE + '/install.lock', base, 'install.lock')
        require(lock_raw == b'')
        binding_raw = self._file(BASE + '/binding', base, 'binding')
        binding = record(binding_raw, 'install-lock-v1', ('base', 'directory', 'lock', 'sessions', 'filesystem'))
        require(binding['base'] == BASE)
        shell_metadata(binding['directory'], self.directories[BASE][1], True)
        shell_metadata(binding['lock'], self.files[BASE + '/install.lock'][1])
        shell_metadata(binding['sessions'], self.directories[BASE + '/sessions'][1], True)
        local_types = {0xef53: 'ext2/ext3', 0x58465342: 'xfs', 0x9123683e: 'btrfs'}
        require(local_types.get(self.system.filesystem(base)) == binding['filesystem'])
        self.binding_hash = hashlib.sha256(binding_raw).hexdigest()
        session_raw = self._file(session_path + '/intent', session, 'intent')
        value = record(session_raw, 'install-session-v1', ('session', 'request', 'binding', 'directory', 'closed'))
        require(value['session'] == self.arguments.session and value['request'] == self.arguments.request)
        require(value['binding'] == self.binding_hash and value['closed'] == 'true')
        shell_metadata(value['directory'], self.directories[session_path][1], True)
        self.namespace_names = self.system.names(base, 3)
        require(self.namespace_names == ('binding', 'install.lock', 'sessions'))
        self.session_names = self.system.names(sessions, SESSION_MAX)
        require(self.arguments.session in self.session_names and all(SESSION.fullmatch(n) for n in self.session_names))
        self.stage_names = self.system.names(session, 129)
        require('intent' in self.stage_names and 'complete' not in self.stage_names)
        current = self.arguments.stage + '.intent'
        require(current in self.stage_names and self.arguments.stage + '.confirmed' not in self.stage_names)
        labels = set()
        for name in self.stage_names:
            if name == 'intent':
                continue
            label, dot, suffix = name.rpartition('.')
            require(dot and LABEL.fullmatch(label) and suffix in ('intent', 'confirmed'))
            labels.add(label)
        require(0 < len(labels) <= STAGE_MAX)
        for label in sorted(labels):
            require(label + '.intent' in self.stage_names)
            raw = self._file(session_path + '/' + label + '.intent', session, label + '.intent')
            value = record(raw, 'install-stage-v1', ('session', 'stage', 'action', 'closed'))
            require(value['session'] == self.arguments.session and value['stage'] == label)
            require(DIGEST.fullmatch(value['action']) and value['closed'] == 'true')
            if label == self.arguments.stage:
                require(value['action'] == self.arguments.action)
                self.stage_hash = hashlib.sha256(raw).hexdigest()
            else:
                require(label + '.confirmed' in self.stage_names)
                confirmed = self._file(session_path + '/' + label + '.confirmed', session, label + '.confirmed')
                evidence = record(confirmed, 'install-stage-confirmed-v1', ('session', 'stage', 'action', 'outcome', 'independently_confirmed'))
                require(evidence['session'] == self.arguments.session and evidence['stage'] == label and evidence['action'] == value['action'])
                require(DIGEST.fullmatch(evidence['outcome']) and evidence['independently_confirmed'] == 'true')
        self.live = True
        return self.check()

    def _pidfd_guard(self):
        require(self.system.cloexec(self.pid_fd) and self.system.fstat(self.pid_fd) == self.pidfd_metadata)
        require(pidfdinfo(self.system.descriptor_info(self.identity[0], self.pid_fd), self.pidfd_metadata, self.arguments.parent_pid) == self.pidfd_binding)
        require(self.system.fstat(self.pid_fd) == self.pidfd_metadata and self.system.alive(self.pid_fd))

    def _check(self):
        require(self.live)
        self._pidfd_guard()
        require(self.system.identity(self.arguments) == self.identity)
        for path, (fd, expected, ancestor) in self.directories.items():
            require(self.system.cloexec(fd))
            current = protected(self.system.lstat(path), directory=True, ancestor=ancestor)
            require(current.directory() == expected.directory() == self.system.fstat(fd).directory())
        for path, (fd, expected, raw) in self.files.items():
            require(self.system.cloexec(fd) and protected(self.system.lstat(path)) == expected)
            require(self.system.fstat(fd) == expected and self.system.read(fd, RECORD_MAX) == raw)
            require(self.system.fstat(fd) == expected and self.system.lstat(path) == expected)
        require(self.system.names(self.base, 3) == self.namespace_names)
        require(self.system.names(self.sessions, SESSION_MAX) == self.session_names)
        require(self.system.names(self.session_fd, 129) == self.stage_names)
        directory, path = self.system.parent_descriptor(self.arguments.parent_pid, self.arguments.directory_fd)
        require(path == BASE and directory.directory() == self.directories[BASE][1].directory())
        lock, path = self.system.parent_descriptor(self.arguments.parent_pid, self.arguments.lock_fd)
        require(path == BASE + '/install.lock' and lock == self.files[BASE + '/install.lock'][1])
        parent_dir_info = fdinfo(self.system.descriptor_info(self.arguments.parent_pid, self.arguments.directory_fd), directory, False, self.system.device(directory.st_dev))
        parent_lock_info = fdinfo(self.system.descriptor_info(self.arguments.parent_pid, self.arguments.lock_fd), lock, True, self.system.device(lock.st_dev))
        own_dir_info = fdinfo(self.system.descriptor_info(self.identity[0], self.base), directory, False, self.system.device(directory.st_dev))
        own_lock_fd = self.files[BASE + '/install.lock'][0]
        own_lock_info = fdinfo(self.system.descriptor_info(self.identity[0], own_lock_fd), lock, False, self.system.device(lock.st_dev))
        require(parent_dir_info[0] == own_dir_info[0] and parent_lock_info[0] == own_lock_info[0])
        observed = parent_dir_info, parent_lock_info, own_dir_info, own_lock_info
        if self.fdinfo_binding is None:
            self.fdinfo_binding = observed
        require(observed == self.fdinfo_binding)
        for path, (fd, expected, ancestor) in self.directories.items():
            require(protected(self.system.lstat(path), directory=True, ancestor=ancestor).directory() == expected.directory() == self.system.fstat(fd).directory())
        for pid, fd, metadata, locked, expected in (
            (self.arguments.parent_pid, self.arguments.directory_fd, directory, False, parent_dir_info),
            (self.arguments.parent_pid, self.arguments.lock_fd, lock, True, parent_lock_info),
            (self.identity[0], self.base, directory, False, own_dir_info),
            (self.identity[0], own_lock_fd, lock, False, own_lock_info),
        ):
            require(fdinfo(self.system.descriptor_info(pid, fd), metadata, locked, self.system.device(metadata.st_dev)) == expected)
        require(self.system.identity(self.arguments) == self.identity)
        self._pidfd_guard()
        return dict(schemaVersion=1, scope=SCOPE, parentPid=self.arguments.parent_pid,
                    session=self.arguments.session, request=self.arguments.request, stage=self.arguments.stage,
                    action=self.arguments.action, bootId=self.identity[2], parentStartTicks=str(self.identity[3]),
                    bindingSha256=self.binding_hash, stageIntentSha256=self.stage_hash,
                    qualification='INJECTED_PARENT_EVIDENCE_UNQUALIFIED' if self.injected else 'LINUX_PARENT_EVIDENCE_UNQUALIFIED',
                    nativeAuthorized=False, effectsConfirmed=False, backupReady=False)

    def check(self):
        try:
            return self._check()
        except BaseException:
            self.close()
            raise ParentUnavailable('installer-parent-unavailable') from None

    @contextmanager
    def use(self):
        evidence = self.check()
        try:
            yield evidence
        finally:
            self.check()

    def close(self):
        self.live = False
        failed = False
        handles, self.handles = self.handles, []
        for fd in reversed(handles):
            try:
                self.system.close(fd)
            except BaseException:
                failed = True
        self.system.proc_fd = None
        require(not failed)


@contextmanager
def hold_parent(arguments, *, system=None):
    require(type(arguments) is ParentInput)
    arguments.validate()
    injected = system is not None
    held = None
    try:
        held = HeldParent(arguments, NativeSystem() if system is None else system, injected)
        held.acquire()
        yield held
        held.check()
    except BaseException:
        raise ParentUnavailable('installer-parent-unavailable') from None
    finally:
        if held is not None:
            held.close()


def main(argv):
    try:
        with hold_parent(ParentInput.from_argv(argv)) as held:
            evidence = held.check()
        print(json.dumps(evidence, sort_keys=True, separators=(',', ':')))
        return 0
    except (ParentUnavailable, OSError, UnicodeError):
        print('installer-parent-unavailable', file=sys.stderr)
        return 74


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
