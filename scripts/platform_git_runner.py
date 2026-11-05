"""Producer-only seven-command Git runner, never installer or activation authority.

The caller supplies an independently authenticated Git SHA256 and protected clean
source root/revision. Sealed executable bytes do not authenticate the ELF loader
or libraries: a trusted company station OS is still required. The existing
platform_source guard must continue around each call. Native Linux/process/IO
behavior requires separate qualification; no escaped-process cancellation claim.
The native caller must be a dedicated single-task company station process with
exclusive ownership of every child wait/reap. A named contract is a caller
obligation, not proof against arbitrary trusted code racing a wait consumer.
"""
import hashlib
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


BINARY = '/usr/bin/git'
STDOUT_LIMIT = 1024 ** 2
STDERR_LIMIT = 65536
TOOL_LIMIT = 8 * 1024 ** 2
CALL_SECONDS = 30
DISPOSAL_SECONDS = 5
MAX_CALLS = 128
MAX_SECONDS = 1800
STATION_CONTRACT = 'trusted-company-station-exclusive-child-reaper-v1'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
ENV = dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LANG='C', LC_ALL='C', TZ='UTC',
           GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
           GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
UNRELEASED_RESOURCES = []


class GitUnavailable(ValueError):
    """Fixed failure; never return captured stderr or local path diagnostics."""


def require(value):
    if not value:
        raise GitUnavailable('company-git-unavailable')


def identity(info):
    require(all(type(getattr(info, name)) is int for name in FIELDS))
    return tuple(getattr(info, name) for name in FIELDS)


def instant(clock):
    value = clock()
    require(type(value) in (int, float) and math.isfinite(value))
    return value


class NativeFiles:
    def __init__(self):
        require(sys.platform.startswith('linux') and os.name == 'posix'
                and all(hasattr(os, name) for name in
                        ('O_NOFOLLOW', 'O_CLOEXEC', 'O_DIRECTORY', 'O_NONBLOCK', 'pread')))
    def lstat(self, path): return os.stat(path, follow_symlinks=False)
    def fstat(self, fd): return os.fstat(fd)
    def cloexec(self, fd): return not os.get_inheritable(fd)
    def open(self, parent, name, directory):
        return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                       (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=parent)
    def read(self, fd, size, offset): return os.pread(fd, size, offset)
    def close(self, fd): os.close(fd)


class _Paths:
    def __init__(self, files, source_root, owner, clock, deadline):
        self.files, self.source, self.owner = files, source_root, owner
        self.clock, self.deadline = clock, deadline
        self.handles, self.directories, self.tool = [], {}, None
    def timely(self): require(instant(self.clock) < self.deadline)
    def protected(self, info, directory, owner):
        identity(info)
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        require((info.st_uid, info.st_gid) in owner and not stat.S_IMODE(info.st_mode) & 0o022)
        if not directory:
            require(info.st_nlink == 1 and 0 < info.st_size <= TOOL_LIMIT
                    and stat.S_IMODE(info.st_mode) in (0o555, 0o755))
        return info
    def own(self, fd):
        if type(fd) is not int or fd < 0 or fd in self.handles:
            UNRELEASED_RESOURCES.append((self.files, fd))
            raise GitUnavailable('company-git-unavailable')
        self.handles.append(fd)
        require(self.files.cloexec(fd))
        return fd
    def directory(self, path, parent, name, owner):
        if path in self.directories:
            fd, before, permitted = self.directories[path]
            require((before.st_uid, before.st_gid) in owner)
            return fd
        self.timely(); require(len(self.directories) < 32)
        before = self.protected(self.files.lstat(path), True, owner)
        fd = self.own(self.files.open(parent, name, True))
        require(identity(before) == identity(self.files.fstat(fd)) == identity(self.files.lstat(path)))
        self.directories[path] = fd, before, owner
        return fd
    def walk(self, root, leaf_owner):
        path = Path(root.anchor)
        parent = self.directory(path, None, str(path), {(0, 0), self.owner})
        for part in root.parts[1:]:
            path /= part
            parent = self.directory(path, parent, part, leaf_owner if path == root else {(0, 0), self.owner})
        return parent
    def guard(self):
        self.timely()
        for path, (fd, before, owner) in self.directories.items():
            require(self.files.cloexec(fd) and identity(before) ==
                    identity(self.protected(self.files.lstat(path), True, owner)) == identity(self.files.fstat(fd)))
        if self.tool is not None:
            path, fd, before = self.tool
            require(self.files.cloexec(fd) and identity(before) ==
                    identity(self.protected(self.files.lstat(path), False, {(0, 0)})) == identity(self.files.fstat(fd)))
    def read_tool(self):
        self.guard(); path, fd, before = self.tool
        parts, offset = [], 0
        while offset <= before.st_size:
            self.timely(); amount = min(65536, before.st_size + 1 - offset)
            raw = self.files.read(fd, amount, offset)
            require(type(raw) is bytes and len(raw) <= amount)
            if not raw: break
            parts.append(raw); offset += len(raw)
        require(offset == before.st_size); self.guard()
        return b''.join(parts)
    def acquire(self):
        self.walk(self.source, {self.owner})
        path = Path(BINARY); parent = self.walk(path.parent, {(0, 0)})
        before = self.protected(self.files.lstat(path), False, {(0, 0)})
        fd = self.own(self.files.open(parent, path.name, False))
        require(identity(before) == identity(self.files.fstat(fd)) == identity(self.files.lstat(path)))
        self.tool = path, fd, before
        return self.read_tool()
    def close(self):
        failed = False
        for fd in reversed(self.handles):
            try: require(self.files.close(fd) is None)
            except BaseException:
                UNRELEASED_RESOURCES.append((self.files, fd)); failed = True
        self.handles = []
        require(not failed)


class NativeSystem:
    def __init__(self, *, station_contract=None):
        require(not UNRELEASED_RESOURCES and type(station_contract) is str and station_contract == STATION_CONTRACT)
        self.station_contract = station_contract
        require(sys.platform.startswith('linux') and os.name == 'posix'
                and all(hasattr(os, name) for name in
                    ('memfd_create', 'MFD_CLOEXEC', 'MFD_ALLOW_SEALING', 'pidfd_open',
                     'P_PIDFD', 'waitid', 'WEXITED', 'WNOHANG', 'WNOWAIT',
                     'CLD_EXITED', 'CLD_KILLED', 'CLD_DUMPED', 'getpid', 'scandir'))
                and hasattr(signal, 'pidfd_send_signal')
                and callable(getattr(selectors, 'DefaultSelector', None)))
        self.check_station()
        import fcntl
        require(all(hasattr(fcntl, name) for name in
            ('F_ADD_SEALS', 'F_GET_SEALS', 'F_SEAL_SEAL', 'F_SEAL_WRITE', 'F_SEAL_GROW', 'F_SEAL_SHRINK')))
        self.fcntl = fcntl
        self.seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
    def check_station(self):
        require(not UNRELEASED_RESOURCES and self.station_contract == STATION_CONTRACT
                and sys.platform.startswith('linux') and os.name == 'posix'
                and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
        pid = os.getpid(); require(type(pid) is int and pid > 0)
        # Read actual Linux tasks, rather than Python's thread registry. Inspect
        # at most two entries; a second task or unavailable procfs denies launch.
        tasks = os.scandir('/proc/self/task')
        try:
            first = next(tasks, None)
            require(first is not None and first.name == str(pid)
                    and first.is_dir(follow_symlinks=False) and next(tasks, None) is None)
        finally:
            try: require(tasks.close() is None)
            except BaseException:
                UNRELEASED_RESOURCES.append((self, tasks))
                raise GitUnavailable('company-git-unavailable') from None
    def executable(self):
        return os.memfd_create('company-git-executable', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | getattr(os, 'MFD_EXEC', 0))
    def populate(self, fd, raw):
        offset = 0
        while offset < len(raw):
            chunk = raw[offset:offset + 65536]
            count = os.write(fd, chunk); require(type(count) is int and 0 < count <= len(chunk))
            offset += count
        os.fchmod(fd, 0o555)
        self.fcntl.fcntl(fd, self.fcntl.F_ADD_SEALS, self.seals)
        require(os.fstat(fd).st_size == len(raw))
    def check(self, fd, expected, size):
        require(not os.get_inheritable(fd) and self.fcntl.fcntl(fd, self.fcntl.F_GET_SEALS) == self.seals
                and os.fstat(fd).st_size == size)
        parts, offset = [], 0
        while offset <= size:
            raw = os.pread(fd, min(65536, size + 1 - offset), offset)
            if not raw: break
            parts.append(raw); offset += len(raw)
        require(offset == size and hashlib.sha256(b''.join(parts)).hexdigest() == expected)
    def close(self, fd): os.close(fd)
    def job(self, clock): return _NativeJob(clock, station_guard=self.check_station)


class _NativeJob:
    """Own the leader until group signal, then reap; no post-reap PGID query."""
    def __init__(self, clock, *, station_guard=None):
        self.clock, self.station_guard = clock, station_guard
        self.process, self.pidfd, self.selector = None, None, None
        self.streams, self.buffers = [], {'stdout': bytearray(), 'stderr': bytearray()}
        self.possible_launch, self.known_status, self.eof, self.disposed = False, None, False, False
    def start(self, argv, env, executable, deadline):
        require(instant(self.clock) < deadline)
        require(not UNRELEASED_RESOURCES and callable(self.station_guard)); self.station_guard()
        self.possible_launch = True
        self.process = subprocess.Popen(argv, executable='/proc/self/fd/' + str(executable),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd='/', close_fds=True, pass_fds=(executable,), start_new_session=True)
        self.streams = [self.process.stdout, self.process.stderr]
        require(all(stream is not None for stream in self.streams))
        self.pidfd = os.pidfd_open(self.process.pid)
        self.selector = selectors.DefaultSelector()
        for label, stream in zip(('stdout', 'stderr'), self.streams):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, label)
    def drain(self, end):
        require(self.selector is not None)
        remaining = max(0, end - instant(self.clock))
        for key, _ in self.selector.select(min(0.05, remaining)):
            limit = STDOUT_LIMIT if key.data == 'stdout' else STDERR_LIMIT
            require(len(self.buffers[key.data]) <= limit)
            raw = os.read(key.fileobj.fileno(), min(65536, limit + 1 - len(self.buffers[key.data])))
            if not raw: self.selector.unregister(key.fileobj)
            else:
                self.buffers[key.data].extend(raw)
                require(len(self.buffers[key.data]) <= limit)
        self.eof = not self.selector.get_map()
    def capture(self, end):
        while not self.eof or self.known_status is None:
            require(instant(self.clock) < end)
            self.drain(end)
            status = os.waitid(os.P_PIDFD, self.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                require(status.si_pid == self.process.pid)
                self.known_status = status
        require(self.known_status.si_code == os.CLD_EXITED and self.known_status.si_status == 0)
        return bytes(self.buffers['stdout'])
    def dispose(self, end):
        require(not self.disposed)
        self.disposed = True; failed, reaped = False, False
        if self.process is None:
            if self.possible_launch:
                UNRELEASED_RESOURCES.append(self); raise GitUnavailable('company-git-unavailable')
            return
        # The non-consuming probe must still recognize our child before ANY
        # numeric group signal. It does not close the check-to-signal race if an
        # unrelated wait consumer violates the exclusive sole-reaper contract.
        owned = False
        try:
            require(instant(self.clock) < end and callable(self.station_guard)
                    and self.process.returncode is None and type(self.pidfd) is int)
            self.station_guard()
            status = os.waitid(os.P_PIDFD, self.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is None:
                require(self.known_status is None)
            else:
                require(type(status.si_pid) is int and status.si_pid == self.process.pid
                        and type(status.si_code) is int
                        and status.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
                        and type(status.si_status) is int)
                if self.known_status is not None:
                    require((status.si_pid, status.si_code, status.si_status) ==
                            (self.known_status.si_pid, self.known_status.si_code, self.known_status.si_status))
            owned = True
        except BaseException: failed = True
        if owned:
            try: os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except BaseException: failed = True
            if failed:
                try: signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                except ProcessLookupError: pass
                except BaseException: failed = True
            try:
                remaining = end - instant(self.clock); require(remaining > 0)
                code = self.process.wait(timeout=remaining); reaped = True
                require(type(code) is int and type(self.process.returncode) is int and code == self.process.returncode)
                if self.known_status is not None and self.known_status.si_code == os.CLD_EXITED:
                    require(code == self.known_status.si_status)
            except BaseException: failed = True
        if reaped and self.selector is not None:
            try:
                while self.selector.get_map():
                    require(instant(self.clock) < end); self.drain(end)
            except BaseException: failed = True
        for item in (*self.streams, self.selector):
            if item is not None:
                try: require(item.close() is None)
                except BaseException: failed = True
        if reaped and self.pidfd is not None:
            try: os.close(self.pidfd); self.pidfd = None
            except BaseException: failed = True
        require_deadline = instant(self.clock) < end
        if failed or not reaped or not self.eof or not require_deadline:
            UNRELEASED_RESOURCES.append(self)
            raise GitUnavailable('company-git-unavailable')


class NativeGitRunner:
    """Context-owned trusted producer adapter for platform_source.NativeGit."""
    def __init__(self, tool_sha256, source_root, revision, *, files=None, system=None,
                 clock=time.monotonic, seconds=MAX_SECONDS, calls=MAX_CALLS, owner_uid=0, owner_gid=0,
                 station_contract=None):
        require(not UNRELEASED_RESOURCES and type(tool_sha256) is str
                and re.fullmatch('[a-f0-9]{64}', tool_sha256) is not None
                and type(revision) is str and re.fullmatch('[a-f0-9]{40}', revision) is not None)
        self.root = Path(source_root)
        require(self.root.is_absolute() and self.root != Path(self.root.anchor)
                and len(self.root.parts) <= 16 and str(self.root) == os.path.normpath(str(self.root))
                and str(self.root).isascii() and len(str(self.root).encode()) <= 256)
        require(type(seconds) is int and 2 * DISPOSAL_SECONDS < seconds <= MAX_SECONDS
                and type(calls) is int and 0 < calls <= MAX_CALLS
                and type(owner_uid) is int and type(owner_gid) is int
                and 0 <= owner_uid < 2**31 and 0 <= owner_gid < 2**31 and callable(clock))
        self.clock, self.deadline, self.max_calls = clock, instant(clock) + seconds, calls
        self.files, self.system = files if files is not None else NativeFiles(), system if system is not None else NativeSystem(station_contract=station_contract)
        self.sha, self.revision = tool_sha256, revision
        self.paths = _Paths(self.files, self.root, (owner_uid, owner_gid), clock, self.deadline - DISPOSAL_SECONDS)
        self.fd, self.tool_bytes, self.jobs = None, None, []
        self.active, self.entered, self.failed, self.calls = False, False, False, 0
    def close(self):
        self.active = False; failed = False
        if self.fd is not None:
            fd, self.fd = self.fd, None
            try: require(self.system.close(fd) is None)
            except BaseException: UNRELEASED_RESOURCES.append((self.system, fd)); failed = True
        try: self.paths.close()
        except BaseException: failed = True
        require(not failed and not UNRELEASED_RESOURCES and instant(self.clock) < self.deadline)
    def __enter__(self):
        require(not self.entered and not self.failed and not UNRELEASED_RESOURCES)
        self.entered = True
        try:
            raw = self.paths.acquire()
            require(hashlib.sha256(raw).hexdigest() == self.sha and len(raw) >= 64
                    and raw[:7] == b'\x7fELF\x02\x01\x01' and raw[18:20] == b'\x3e\x00')
            fd = self.system.executable()
            if type(fd) is not int or fd < 0:
                UNRELEASED_RESOURCES.append((self.system, fd)); raise GitUnavailable('company-git-unavailable')
            self.fd = fd
            self.system.populate(fd, raw); self.system.check(fd, self.sha, len(raw))
            self.paths.guard(); self.tool_bytes = raw; self.active = True
            return self
        except BaseException:
            self.failed = True
            try: self.close()
            finally: raise GitUnavailable('company-git-unavailable') from None
    def __exit__(self, *_):
        try:
            if self.active:
                self.paths.guard(); require(self.paths.read_tool() == self.tool_bytes)
                self.system.check(self.fd, self.sha, len(self.tool_bytes))
        finally: self.close()
    def request(self, argv, env, limit, timeout):
        require(type(argv) is tuple and 0 < len(argv) <= 32
                and all(type(arg) is str and 0 < len(arg.encode()) <= 512 and '\x00' not in arg for arg in argv)
                and sum(len(arg.encode()) + 1 for arg in argv) <= 4096
                and type(env) is dict and all(type(k) is str and type(v) is str for k, v in env.items())
                and env == ENV and type(limit) is int and limit == STDOUT_LIMIT
                and type(timeout) is int and timeout == CALL_SECONDS)
        prefix = (BINARY, '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch',
            '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
            '-c', 'core.untrackedCache=false', '-c', 'core.attributesFile=/dev/null', '-C', str(self.root))
        tails = (('rev-parse', '--show-toplevel'), ('rev-parse', '--verify', 'HEAD^{commit}'),
                 ('rev-parse', '--verify', self.revision + '^{tree}'),
                 ('ls-files', '--others', '--exclude-standard', '-z'),
                 ('ls-files', '--others', '--ignored', '--exclude-standard', '-z'),
                 ('ls-tree', '-rz', '--full-tree', self.revision),
                 ('ls-files', '--stage', '--full-name', '-z'))
        require(argv[:len(prefix)] == prefix and argv[len(prefix):] in tails)
    def __call__(self, argv, *, env, limit, timeout):
        job = None
        try:
            require(self.active and not self.failed and not UNRELEASED_RESOURCES)
            self.request(argv, env, limit, timeout)
            self.paths.guard(); require(self.paths.read_tool() == self.tool_bytes)
            self.system.check(self.fd, self.sha, len(self.tool_bytes))
            end = min(instant(self.clock) + CALL_SECONDS, self.deadline - DISPOSAL_SECONDS)
            capture_end = end - DISPOSAL_SECONDS
            require(instant(self.clock) < capture_end and self.calls < self.max_calls)
            self.calls += 1
            job = self.system.job(self.clock); self.jobs.append(job)
            try:
                job.start(argv, dict(env), self.fd, capture_end)
                raw = job.capture(capture_end)
                require(type(raw) is bytes and len(raw) <= STDOUT_LIMIT)
            finally:
                try: require(job.dispose(end) is None)
                except BaseException:
                    UNRELEASED_RESOURCES.append(job); raise
                else: self.jobs.remove(job)
            self.paths.guard(); require(self.paths.read_tool() == self.tool_bytes)
            self.system.check(self.fd, self.sha, len(self.tool_bytes))
            require(instant(self.clock) < end and not UNRELEASED_RESOURCES)
            return raw
        except BaseException:
            self.failed = True; self.active = False
            raise GitUnavailable('company-git-unavailable') from None
