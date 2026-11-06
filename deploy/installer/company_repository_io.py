"""Company-owned native repository IO, never an application execution service.

The caller authenticates this module independently, keeps its signed source and
real installer parent live, and supplies the original bootstrap's seed plan.
This adapter writes only those planned repository bytes and two seed records.
It cannot initialize a database, replace a file, launch a shell or acknowledge
an installer stage. Root, the interpreter and installed Git remain trusted.
"""
import hashlib
import os
from pathlib import PurePosixPath
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time

FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
ENV = dict(PATH='/usr/bin:/bin', HOME='/nonexistent', LANG='C', LC_ALL='C', TZ='UTC',
    GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM='/dev/null', GIT_CONFIG_GLOBAL='/dev/null',
    GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
UNKNOWN = []


def require(value, reason='native-repository-unavailable'):
    if value is not True:
        raise ValueError(reason)


def path(value):
    require(type(value) is str and value.startswith('/') and len(value) <= 4096
        and value == str(PurePosixPath(value)) and not value.startswith('//')
        and all(re.fullmatch('[A-Za-z0-9_.-]{1,255}', item) and item not in ('.', '..')
                for item in PurePosixPath(value).parts[1:]))
    return value


def metadata(value):
    return {name: getattr(value, name) for name in FIELDS}


def identity(value):
    return tuple(getattr(value, name) for name in FIELDS)


class SeedBackend:
    """Exact writes plus protected, bounded reads for original SeedFiles."""
    def __init__(self, *, data, install_root, storage_file, operation_id, plan,
                 broker_directories, writable, clock=time.monotonic):
        require(sys.platform == 'linux' and os.getuid() == os.getgid() == os.geteuid() == os.getegid() == 0
                and not UNKNOWN and type(writable) is bool)
        self.data, self.root, self.storage = map(path, (data, install_root, storage_file))
        require(data.startswith('/srv/') and re.fullmatch('[a-f0-9]{32}', operation_id) is not None)
        self.repo, self.journal = data + '/runtime/repository', data + '/config/repository-seed'
        self.operation = self.journal + '/' + operation_id
        require(type(plan) is dict and type(plan['output']) is dict and type(plan['directories']) is set)
        self.output = {path(self.repo + '/' + name): raw for name, raw in plan['output'].items()}
        self.directories = {path(self.repo + '/' + name) for name in plan['directories']}
        require(0 < len(self.output) + len(self.directories) <= 8192
                and len(self.directories) <= 1024 and all(type(raw) is bytes and len(raw) <= 9*1024**2
                    for raw in self.output.values()))
        self.modes = {name: 0o755 if plan['modes'].get(name[len(self.repo)+1:]) == '100755'
            else 0o644 if name[len(self.repo)+1:] in plan['leaves'] else 0o600 for name in self.output}
        self.total = sum(map(len, self.output.values()))
        require(self.total <= 144*1024**2)
        controls = [data + '/config/installation.json',
            *('/etc/autosoft/' + name for name in ('installation.intent.json', 'installation.json',
                                                'installation.storage-receipt.json', 'storage.key')),
            *(data + '/config/runtime-layout/' + name for name in ('intent.json', 'layout.json', 'confirmed.json')),
            self.storage, '/usr/bin/git', self.operation + '/intent.json', self.operation + '/objects-verified.json']
        self.files = set(controls) | set(self.output)
        self.dirs = {self.repo, self.journal, self.operation, self.root, self.data,
                     data + '/runtime/storage', self.repo + '/.git/info', *self.directories,
                     *(data + '/runtime/' + name for name in broker_directories)}
        for name in (*self.files, *tuple(self.dirs)):
            self.dirs.update(str(item) for item in PurePosixPath(name).parents)
        require(not self.files.intersection(self.dirs))
        self.writable, self.clock, self.deadline = writable, clock, clock() + 600
        self.handles, self.parents, self.unknown_fds = {}, {}, set()
        self.written, self.read_bytes = 0, 0
        self.max_fds = len(self.files) + 2*len(self.dirs) + 32
        require(resource.getrlimit(resource.RLIMIT_NOFILE)[0] >= len(os.listdir('/proc/self/fd')) + self.max_fds + 128,
                'repository-descriptor-capacity-required')
        self.closed = False
        if writable: self.admit_write_capacity()

    def admit_write_capacity(self):
        """Read-only prerequisite observation; does not grant write capability."""
        self.tick()
        capacity = os.statvfs(self.repo)
        require(capacity.f_bavail * capacity.f_frsize >= self.total + 64*1024**2,
                'repository-storage-capacity-required')

    def tick(self):
        require(not self.closed and not UNKNOWN and self.clock() < self.deadline)

    def _directory(self, name):
        self.tick(); require(name in self.dirs)
        if name not in self.parents:
            parent = str(PurePosixPath(name).parent)
            prior = None if name == '/' else self._directory(parent)
            leaf = '/' if name == '/' else PurePosixPath(name).name
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=prior)
            self.parents[name] = (fd, None)
            value = os.fstat(fd)
            expected_uid = 10001 if name == self.repo or name.startswith(self.repo + '/') else 0
            require(stat.S_ISDIR(value.st_mode) and value.st_uid == value.st_gid == expected_uid
                    and not value.st_mode & 0o022)
            self.parents[name] = (fd, identity(value)[:5])
        fd, expected = self.parents[name]
        value = os.fstat(fd)
        parent = str(PurePosixPath(name).parent)
        observed = os.stat('/' if name == '/' else PurePosixPath(name).name,
                           dir_fd=None if name == '/' else self._directory(parent), follow_symlinks=False)
        require(expected is not None and identity(value)[:5] == identity(observed)[:5] == expected)
        return fd

    def lstat(self, name):
        self.tick(); name = path(name); require(name in self.files or name in self.dirs)
        if name == '/': return metadata(os.fstat(self._directory('/')))
        parent = self._directory(str(PurePosixPath(name).parent))
        value = os.stat(PurePosixPath(name).name, dir_fd=parent, follow_symlinks=False)
        require((stat.S_ISDIR if name in self.dirs else stat.S_ISREG)(value.st_mode))
        return metadata(value)

    def _register(self, fd, name, created=False):
        require(fd not in self.handles)
        self.handles[fd] = dict(path=name, created=created, written=0)
        require(len(self.handles) + len(self.parents) <= self.max_fds and not os.get_inheritable(fd))
        return fd

    def open(self, name, kind):
        self.tick(); name = path(name)
        require(kind in ('directory', 'file') and name in (self.dirs if kind == 'directory' else self.files))
        if kind == 'directory':
            return self._register(os.dup(self._directory(name)), name)
        parent = self._directory(str(PurePosixPath(name).parent)) if name != '/' else None
        fd = os.open('/' if name == '/' else PurePosixPath(name).name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if kind == 'directory' else os.O_NONBLOCK),
            dir_fd=parent)
        return self._register(fd, name)

    def fstat(self, fd):
        self.tick(); require(fd in self.handles); return metadata(os.fstat(fd))

    def inheritable(self, fd):
        self.tick(); require(fd in self.handles); return os.get_inheritable(fd)

    def read(self, fd, maximum):
        self.tick(); require(fd in self.handles and type(maximum) is int and 0 <= maximum <= 32*1024**2)
        require(self.handles[fd]['path'] not in (self.storage, '/etc/autosoft/storage.key'))
        before = identity(os.fstat(fd)); require(stat.S_ISREG(before[2]) and before[6] <= maximum)
        require(self.read_bytes + before[6] <= 512*1024**2)
        self.read_bytes += before[6]
        output = bytearray()
        while len(output) < before[6]:
            self.tick(); raw = os.pread(fd, min(65536, before[6] - len(output)), len(output))
            require(bool(raw)); output.extend(raw)
        require(not os.pread(fd, 1, len(output)) and before == identity(os.fstat(fd)))
        return bytes(output)

    def names(self, fd, maximum):
        self.tick(); require(fd in self.handles and type(maximum) is int and 0 <= maximum <= 8192)
        require(stat.S_ISDIR(os.fstat(fd).st_mode)); values = []
        with os.scandir(fd) as rows:
            for row in rows:
                self.tick(); require(len(values) < maximum and re.fullmatch('[A-Za-z0-9_.-]+', row.name) is not None
                                     and row.name not in ('.', '..'))
                values.append(row.name)
        return sorted(values)

    def _new(self, parent, name, uid, gid, mode, directory):
        self.tick(); require(self.writable and parent in self.handles
            and type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+', name) is not None and name not in ('.', '..'))
        root = self.handles[parent]['path']; target = path(root + '/' + name)
        require(identity(os.fstat(parent))[:5] == tuple(self.lstat(root)[key] for key in FIELDS[:5]))
        if target == self.operation:
            require(directory and uid == gid == 0 and mode == 0o700)
        elif root == self.operation:
            require(not directory and name in ('intent.json', 'objects-verified.json')
                    and uid == gid == 0 and mode == 0o600)
        else:
            require(target in (self.directories if directory else self.output) and uid == gid == 10001
                    and mode == (0o700 if directory else self.modes[target]))
        if directory:
            os.mkdir(name, mode, dir_fd=parent)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        else:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        self._register(fd, target, True)
        os.fchown(fd, uid, gid); os.fchmod(fd, mode)
        info = os.fstat(fd)
        require(info.st_dev == os.fstat(parent).st_dev and (directory or info.st_nlink == 1 and info.st_size == 0))
        return fd

    def mkdir(self, parent, name, uid, gid, mode): return self._new(parent, name, uid, gid, mode, True)
    def create(self, parent, name, uid, gid, mode): return self._new(parent, name, uid, gid, mode, False)

    def write(self, fd, raw):
        self.tick(); require(fd in self.handles and type(raw) is bytes and 0 < len(raw) <= 65536)
        row = self.handles[fd]; require(row['created'] and stat.S_ISREG(os.fstat(fd).st_mode))
        expected = self.output.get(row['path'])
        if expected is not None:
            require(expected[row['written']:row['written']+len(raw)] == raw)
        else: require(row['path'].startswith(self.operation + '/') and row['written'] + len(raw) <= 65536)
        require(self.written + len(raw) <= self.total + 131072)
        count = os.write(fd, raw); require(0 < count <= len(raw))
        row['written'] += count; self.written += count
        return count

    def sync(self, fd):
        self.tick(); require(fd in self.handles); os.fsync(fd)

    def close(self, fd):
        require(fd in self.handles and fd not in self.unknown_fds)
        try: os.close(fd)
        except BaseException:
            self.unknown_fds.add(fd); UNKNOWN.append((self, fd)); raise
        del self.handles[fd]

    def finish(self):
        failures = []
        for fd in tuple(self.handles):
            if fd in self.unknown_fds:
                failures.append(fd)
                continue  # A failed close is never retried on a possibly reused descriptor.
            try: self.close(fd)
            except BaseException: failures.append(fd)
        for name, (fd, _) in reversed(tuple(self.parents.items())):
            if fd in self.unknown_fds:
                failures.append(fd)
                continue
            try: os.close(fd); del self.parents[name]
            except BaseException:
                self.unknown_fds.add(fd); UNKNOWN.append((self, fd)); failures.append(fd)
        self.closed = True
        require(not failures and not UNKNOWN)

    def require_released(self):
        require(self.closed and not self.handles and not self.parents and not UNKNOWN)


class SeedRunner:
    """Original host-read runner plus a fixed read-only Git plumbing grammar."""
    def __init__(self, *, host_runner, backend, repository, plan, git_pin, clock=time.monotonic):
        require(type(backend) is SeedBackend and not UNKNOWN)
        self.host, self.backend, self.repo, self.plan = host_runner, backend, path(repository), plan
        require(self.repo == backend.repo and type(git_pin) is dict and set(git_pin) == {'path', 'bytes', 'sha256'}
                and git_pin['path'] == '/usr/bin/git' and type(git_pin['bytes']) is int
                and 0 < git_pin['bytes'] <= 32*1024**2 and re.fullmatch('[a-f0-9]{64}', git_pin['sha256']) is not None)
        self.pin, self.clock, self.deadline, self.calls, self.active = dict(git_pin), clock, clock()+600, 0, None

    def _git(self, argv, stdin, maximum, timeout, tool, environment):
        require(type(argv) is list and environment == ENV and timeout == 60 and type(maximum) is int
                and 0 <= maximum <= 96*1024**2 and tool in self.backend.handles)
        require(self.backend.handles[tool]['path'] == '/usr/bin/git')
        info = os.fstat(tool)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o755 and info.st_size == self.pin['bytes'])
        raw = self.backend.read(tool, 32*1024**2)
        require(hashlib.sha256(raw).hexdigest() == self.pin['sha256'])
        prefix = ['/usr/bin/git', '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch',
            '-c', 'safe.directory='+self.repo, '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
            '-c', 'commit.gpgSign=false', '-c', 'core.attributesFile=/dev/null',
            '--git-dir='+self.repo+'/.git', '--work-tree='+self.repo]
        require(argv[:len(prefix)] == prefix)
        tail = argv[len(prefix):]
        if tail == ['cat-file', '--batch']:
            require(stdin == ('\n'.join(sorted(self.plan['objects']))+'\n').encode()
                    and len(stdin) <= 512*1024 and maximum == sum(len(raw)+100 for _, raw in self.plan['objects'].values()))
        elif tail == ['version']:
            require(stdin is None and maximum == 256)
        else:
            require(stdin is None and (tail in (['rev-parse', '--verify', 'HEAD'], ['ls-files', '--stage', '-z'])
                or len(tail) == 4 and tail[:2] == ['merge-base', '--is-ancestor'] and tail[2] == self.plan['commit']
                    and re.fullmatch('[a-f0-9]{40}', tail[3]) is not None
                or len(tail) == 3 and tail[0] == 'rev-parse'
                    and re.fullmatch('[a-f0-9]{40}:platform', tail[1]) is not None
                    and tail[2] == tail[1][:40]+':company-release'))
        return identity(info)

    def preflight(self, tool):
        """Refuse unsupported installed Git before any repository write."""
        prefix = ['/usr/bin/git', '--no-optional-locks', '--no-replace-objects', '--no-lazy-fetch',
            '-c', 'safe.directory='+self.repo, '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
            '-c', 'commit.gpgSign=false', '-c', 'core.attributesFile=/dev/null',
            '--git-dir='+self.repo+'/.git', '--work-tree='+self.repo]
        result = self.run(prefix+['version'], stdin=None, maximum=256, timeout=60, tool=tool, environment=ENV)
        version = re.fullmatch(rb'git version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:[A-Za-z0-9.() +_-]{0,100})\n', result['stdout'])
        require(result['exitCode'] == 0 and version is not None
                and tuple(int(n) for n in version.groups()) >= (2,45,1),
                'compatible-installed-git-required')
        return result['stdout'].decode('ascii').strip()

    def run(self, argv, *, stdin, maximum, timeout, tool, environment):
        require(self.active is None and not UNKNOWN and self.clock() < self.deadline)
        if not argv or argv[0] != '/usr/bin/git':
            require(self.host is not None)
            return self.host.run(argv, stdin=stdin, maximum=maximum, timeout=timeout, tool=tool, environment=environment)
        before = self._git(argv, stdin, maximum, timeout, tool, environment)
        require(self.calls < 8); self.calls += 1
        end = min(self.deadline, self.clock()+60)
        output, errors, sent = bytearray(), bytearray(), 0
        process = subprocess.Popen(argv, executable='/proc/self/fd/'+str(tool), env=dict(ENV),
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(tool,), close_fds=True, start_new_session=True)
        self.active = process
        try:
            with selectors.DefaultSelector() as selector:
                for stream, value in ((process.stdout, output), (process.stderr, errors)):
                    os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, value)
                if stdin is not None:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, None)
                while selector.get_map():
                    require(self.clock() < end, 'repository-git-deadline')
                    for key, _ in selector.select(max(0, min(.2, end-self.clock()))):
                        if key.data is None:
                            try: count = os.write(key.fd, stdin[sent:sent+65536])
                            except BrokenPipeError: count = 0
                            sent += count
                            if not count or sent == len(stdin): selector.unregister(key.fileobj); key.fileobj.close()
                        else:
                            raw = os.read(key.fd, 65536)
                            if not raw: selector.unregister(key.fileobj)
                            else:
                                key.data.extend(raw)
                                require(len(output) <= maximum and len(errors) <= 65536, 'repository-git-output-limit')
            # Keep the child waitable until group cleanup; reaping here could
            # allow its PID/group number to be reused before killpg below.
            while True:
                require(self.clock() < end, 'repository-git-deadline')
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    code = observed.si_status if observed.si_code == os.CLD_EXITED else -observed.si_status
                    break
                time.sleep(.01)
            require(before == identity(os.fstat(tool)) and self.backend.lstat('/usr/bin/git') == metadata(os.fstat(tool)))
            require(code != 0 or not errors and (stdin is None or sent == len(stdin)), 'repository-git-incomplete-success')
            return dict(exitCode=code, stdout=bytes(output), stderr=bytes(errors), ownedReleased=True)
        finally:
            failure = None
            try:
                # Also terminate a same-group descendant retaining a pipe after
                # the original executable exits. Never assume exit == closure.
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=5)
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: pass
                else: raise ValueError('repository-git-descendant-release-unknown')
            except BaseException as error:
                UNKNOWN.append((self, process)); failure = error
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try: stream.close()
                    except BaseException as error: UNKNOWN.append((self, stream)); failure = error
            if failure is not None: raise ValueError('repository-git-release-unknown') from failure
            self.active = None

    def require_released(self):
        require(self.active is None and not UNKNOWN)
