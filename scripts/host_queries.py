#!/usr/bin/env python3
"""Internal read-only package-query adapter; no maintenance/apply entry point.

Only installed inventory is currently available. Repository signature/advisory
normalization and a qualified complete solver adapter are absent. No caller JSON,
typed caller authentication object, unsigned cache, or simulation can replace
those missing verifiers. The planner therefore cannot yet be driven live.

Queries use a fresh protected copy, never the original package DB. The two local
inventory decoders still need exact native manager/version qualification.
Primary format contracts: Debian dpkg-query(1) --showformat/source virtual fields,
https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html and RPM queryformat,
https://rpm.org/docs/4.20.x/man/rpm.8.html . No package or repository is acquired.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import posixpath
import re
import signal
import stat
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True


class QueryUnavailable(ValueError):
    pass


def require(value, code):
    if not value:
        raise QueryUnavailable(code)


def _sibling(name):
    path = Path(__file__).resolve().parent / (name + '.py')
    prior = sys.modules.get(name)
    if prior is not None:
        require(getattr(prior, '__file__', None) is not None and
                Path(prior.__file__).resolve() == path, 'host-query-module-origin')
        return prior
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, 'host-query-module-unavailable')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise QueryUnavailable('host-query-module-unavailable') from None
    return module


_sibling('host_kernel_security')
H = _sibling('host_package_inventory')
R = _sibling('host_remediation')

STDOUT_BYTES = 4 * 1024**2
STDERR_BYTES = 64 * 1024
QUERY_SECONDS = 30
ENVIRONMENT = {'PATH': '/usr/bin:/usr/sbin:/bin:/sbin', 'LANG': 'C',
               'LC_ALL': 'C', 'HOME': '/nonexistent'}
DEB_FORMAT = '${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\t${source:Version}\t${Essential}\n'
RPM_FORMAT = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'


def _rows(raw, fields):
    require(type(raw) is bytes and 0 < len(raw) <= STDOUT_BYTES,
            'installed-query-size')
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeError:
        raise QueryUnavailable('installed-query-encoding') from None
    require(text.endswith('\n') and '\r' not in text and '\x00' not in text,
            'installed-query-format')
    lines = text[:-1].split('\n')
    require(0 < len(lines) <= R.MAX_PACKAGES, 'installed-query-count')
    result = []
    for line in lines:
        row = line.split('\t')
        require(len(row) == fields and all(len(v) <= 500 for v in row) and
                all(not any(ord(c) < 32 for c in v) for v in row),
                'installed-query-format')
        result.append(row)
    return result


def decode_debian(raw, distro):
    result, seen = [], set()
    for name, version, arch, status, source, source_version, essential in _rows(raw, 7):
        R.text(name, R.NAME, 'installed-query-format')
        require(name not in seen, 'installed-query-duplicate')
        seen.add(name)
        # Residual configurations are not installed packages. Other partial or
        # pending states do not establish a stable installed inventory.
        words = status.split(' ')
        require(len(words) == 3 and words[0] in {'install', 'hold', 'deinstall', 'purge'}
                and words[1] == 'ok' and words[2] in {'installed', 'config-files', 'not-installed'},
                'installed-query-partial-state')
        if words[2] != 'installed':
            require(words[0] in {'deinstall', 'purge'}, 'installed-query-partial-state')
            continue
        require(words[0] in {'install', 'hold'} and essential in {'', 'yes', 'no'},
                'installed-query-partial-state')
        row = dict(name=name, version=version, arch=arch, source=source,
                   source_version=source_version, essential=essential == 'yes')
        R.package(row, distro)
        result.append(row)
    return [dict(name=p.name, version=p.version, arch=p.arch, source=p.source,
                 source_version=p.source_version, essential=p.essential)
            for p in R.package_set(result, distro)]


def decode_rpm(raw, distro):
    result = []
    for name, epoch, version, release, arch, srpm in _rows(raw, 6):
        # SOURCERPM does not contain a source epoch. Do not guess equivalence
        # with the binary epoch in the first supported decoder scope.
        require(epoch == '0', 'rpm-source-epoch-unavailable')
        require(srpm.endswith('.src.rpm'), 'rpm-source-package-unavailable')
        parts = srpm[:-8].rsplit('-', 2)
        require(len(parts) == 3, 'rpm-source-package-unavailable')
        source, source_version, source_release = parts
        R.text(version, R.VERSION, 'installed-query-format')
        R.text(release, R.VERSION, 'installed-query-format')
        R.text(source_version, R.VERSION, 'installed-query-format')
        R.text(source_release, R.VERSION, 'installed-query-format')
        row = dict(name=name, version=version + '-' + release, arch=arch,
                   source=source, source_version=source_version + '-' + source_release,
                   # RPM has no Debian Essential field. This is not authority
                   # to remove protected system packages during future apply.
                   essential=False)
        R.package(row, distro)
        result.append(row)
    return [dict(name=p.name, version=p.version, arch=p.arch, source=p.source,
                 source_version=p.source_version, essential=p.essential)
            for p in R.package_set(result, distro)]


def query_argv(family, copy_root, rpm_root=None):
    require(type(copy_root) is Path or isinstance(copy_root, Path), 'host-query-copy-path')
    # The command contract is Linux, even when pure tests run on Windows.
    root = copy_root.as_posix()
    require(re.fullmatch(r'/[A-Za-z0-9_./-]{1,1000}', root)
            and root == posixpath.normpath(root), 'host-query-copy-path')
    if family == 'debian':
        require(rpm_root is None, 'host-query-copy-path')
        return ['/usr/bin/dpkg-query', '--admindir=' + root + '/var/lib/dpkg',
                '--no-pager', '--show', '--showformat=' + DEB_FORMAT]
    require(family == 'rocky' and rpm_root in {'var/lib/rpm', 'usr/lib/sysimage/rpm'},
            'host-query-copy-path')
    return ['/usr/bin/rpm', '--dbpath', root + '/' + rpm_root,
            '--query', '--all', '--queryformat', RPM_FORMAT]


@dataclass(frozen=True)
class Capture:
    stdout: bytes
    stderr: bytes
    return_code: int | None
    duration_millis: int
    overflow: bool
    timed_out: bool
    reaped: bool
    pipes_closed: bool
    command_sha256: str

    def evidence(self):
        # Raw bytes remain private. Never export stderr/exception/argv strings.
        return dict(stdoutSha256=R.sha(self.stdout), stdoutBytes=len(self.stdout),
                    stderrSha256=R.sha(self.stderr), stderrBytes=len(self.stderr),
                    returnCode=self.return_code, durationMillis=self.duration_millis,
                    overflow=self.overflow, timedOut=self.timed_out, reaped=self.reaped,
                    pipesClosed=self.pipes_closed, commandSha256=self.command_sha256)


def _bounded_capture(argv, *, _popen=None, _signal=None):
    """Internal fixed-command executor; test injection never enables host APIs.

    Production callers must construct argv with query_argv and seal executable
    identity. No public CLI or arbitrary command dispatcher is supplied.
    Detached descendants are not attested; uncertain pipe/exit is unavailable.
    """
    require(type(argv) is list and argv and all(type(x) is str for x in argv), 'host-query-command')
    started = time.monotonic()
    process, threads = None, []
    streams = [bytearray(), bytearray()]
    overflow, fault = threading.Event(), threading.Event()
    timed_out, reaped, closed = False, False, False
    popen = _popen or subprocess.Popen
    notify = _signal or os.killpg
    def pump(pipe, destination, maximum):
        try:
            while True:
                block = pipe.read(65536)
                if not block:
                    return
                if type(block) is not bytes or len(destination) + len(block) > maximum:
                    overflow.set(); return
                destination.extend(block)
        except BaseException:
            fault.set()
    def release():
        if process is None:
            return False
        try:
            # Own process-group signalling also closes inherited pipes when
            # the direct child has already exited. Detached descendants remain
            # outside this proof; incomplete pipe closure is unavailable.
            notify(process.pid, signal.SIGTERM)
        except BaseException:
            pass
        try:
            process.wait(timeout=5)
        except BaseException:
            try:
                notify(process.pid, signal.SIGKILL)
            except BaseException:
                pass
            try:
                process.wait(timeout=5)
            except BaseException:
                return False
        return process.poll() is not None
    try:
        # Startup and reader setup are inside the same release boundary.
        process = popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, env=dict(ENVIRONMENT), close_fds=True,
                        start_new_session=True, bufsize=0)
        for i, maximum in enumerate((STDOUT_BYTES, STDERR_BYTES)):
            thread = threading.Thread(target=pump, args=((process.stdout, process.stderr)[i], streams[i], maximum), daemon=True)
            thread.start(); threads.append(thread)
        end = started + QUERY_SECONDS
        while process.poll() is None and not overflow.is_set() and not fault.is_set() and time.monotonic() < end:
            time.sleep(0.01)
        timed_out = time.monotonic() >= end
        if overflow.is_set() or fault.is_set() or timed_out or process.poll() is None:
            reaped = release()
        else:
            process.wait(timeout=max(0.01, end - time.monotonic())); reaped = True
        for thread in threads:
            thread.join(max(0, end - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            fault.set(); reaped = release()
            for thread in threads:
                thread.join(1)
    except BaseException:
        fault.set(); reaped = release()
    finally:
        closed = len(threads) == 2 and not any(thread.is_alive() for thread in threads)
        if process is not None and not any(thread.is_alive() for thread in threads):
            for pipe in (process.stdout, process.stderr):
                try:
                    if pipe is not None:
                        pipe.close()
                except BaseException:
                    closed = False
    code = process.returncode if process is not None and type(process.returncode) is int else None
    # Setup/pipe failures remain unusable even if the direct child was reaped.
    closed = closed and not fault.is_set()
    return Capture(bytes(streams[0]), bytes(streams[1]), code,
                   int((time.monotonic() - started) * 1000), overflow.is_set(), timed_out,
                   reaped, closed, R.sha(R.canonical(argv)))


def _accepted(capture):
    return (type(capture) is Capture and type(capture.stdout) is bytes and type(capture.stderr) is bytes
            and type(capture.duration_millis) is int and capture.duration_millis >= 0
            and type(capture.return_code) is int and capture.return_code == 0
            and capture.reaped is True and capture.pipes_closed is True
            and capture.overflow is False and capture.timed_out is False
            and len(capture.stdout) <= STDOUT_BYTES and capture.stderr == b'')


def _put(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _Native:
    def destination(self, path):
        require(os.name == 'posix' and os.geteuid() == 0 and os.uname().machine == 'x86_64', 'host-query-platform')
        require(path.is_absolute() and path.resolve(strict=True) == path, 'host-query-destination')
        H.ancestors(path, Path('/'))
        require(stat.S_IMODE(path.lstat().st_mode) == 0o700 and not any(path.iterdir()), 'host-query-destination')
        device = Path('/dev/mapper/autosoft-data').stat()
        require(stat.S_ISBLK(device.st_mode) and path.stat().st_dev == device.st_rdev, 'host-query-encrypted-workspace')

    def source(self):
        return H.metadata_sources(Path('/'))

    def hashes(self, source):
        return {name: H.read_file(path, proof)[0] for name, (path, proof) in sorted(source['files'].items())}

    def copy(self, path):
        path.mkdir(mode=0o700)
        return H.snapshot_host_packages(path)

    def copied(self, path, proof):
        actual = {}
        for file in path.rglob('*'):
            if file.is_dir() and not file.is_symlink():
                H.trusted_directory(file)
            else:
                actual[file.relative_to(path).as_posix()] = H.read_file(file, H.ordinary_file(file))[0]
        require(actual == proof['files'], 'host-query-copy-changed')
        return actual

    def tool(self, name):
        path = Path(name)
        require(name in {'/usr/bin/dpkg-query', '/usr/bin/rpm'}, 'host-query-command')
        H.ancestors(path.parent, Path('/'))
        proof = H.ordinary_file(path)
        require(proof[2] & 0o111 and proof[6] <= 32 * 1024**2, 'host-query-tool-format')
        digest, _ = H.read_file(path, proof)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            require(H.stable(os.fstat(stream.fileno())) == proof and stream.read(4) == b'\x7fELF'
                    and H.stable(os.fstat(stream.fileno())) == proof and H.stable(path.lstat()) == proof,
                    'host-query-tool-format')
        return dict(identity=proof, sha256=digest['sha256'])

    def run(self, argv):
        return _bounded_capture(argv)

    def retain(self, destination, index, capture):
        _put(destination / (str(index) + '.stdout'), capture.stdout)
        _put(destination / (str(index) + '.stderr'), capture.stderr)
        _put(destination / (str(index) + '.json'), R.canonical(capture.evidence()))


@dataclass(frozen=True)
class InventoryResult:
    inventory: bytes
    captures: tuple[Capture, ...]
    metadata_sha256: str
    tool_sha256: str
    apply_authorized: bool = False
    native_qualified: bool = False


class HostQueries:
    """Internal only. Explicit injected backend is for trusted synthetic tests."""
    def __init__(self, *, _backend=None):
        self._io = _backend if _backend is not None else _Native()

    def capture_inventory(self, destination):
        destination = Path(destination)
        self._io.destination(destination)
        before = self._io.source()
        hashes = self._io.hashes(before)
        distro = R.distribution(before['distribution'])
        metadata = R.sha(R.canonical(dict(distribution=before['distribution'], rpmRoot=before['rpmRoot'], files=hashes)))
        copy_root = destination / 'inventory'
        command = query_argv(distro.family, copy_root, before['rpmRoot'])
        tool = self._io.tool(command[0])
        proof = None
        captures = []
        failure = None
        packages = None
        try:
            proof = self._io.copy(copy_root)
            require(proof['distribution'] == before['distribution'] and proof['rpmRoot'] == before['rpmRoot']
                    and proof['files'] == hashes, 'host-query-copy-changed')
            for index in range(2):
                capture = self._io.run(command)
                self._io.retain(destination, index, capture)
                captures.append(capture)
                require(_accepted(capture) and capture.command_sha256 == R.sha(R.canonical(command)),
                        'host-query-unavailable')
                current = decode_debian(capture.stdout, distro) if distro.family == 'debian' else decode_rpm(capture.stdout, distro)
                require(packages is None or current == packages, 'installed-query-changed')
                packages = current
        except BaseException:
            failure = 'host-query-unavailable'
        finally:
            # Independently attempt every available final reader, including on
            # decode, capture, storage, overflow and failed-copy paths.
            checks = [lambda: self._io.source() == before,
                      lambda: self._io.hashes(before) == hashes,
                      lambda: self._io.tool(command[0]) == tool]
            if proof is not None:
                checks.append(lambda: self._io.copied(copy_root, proof) == hashes)
            for check in checks:
                try:
                    if check() is not True:
                        failure = 'host-query-preservation-unavailable'
                except BaseException:
                    failure = 'host-query-preservation-unavailable'
        require(failure is None and packages is not None, failure or 'host-query-unavailable')
        checked = datetime.now(timezone.utc)
        inventory = R.canonical(dict(schemaVersion=1, distribution=before['distribution'], packages=packages,
                                     metadataSha256=metadata, capturedAt=checked.isoformat()))
        R.parse_inventory(inventory, checked)
        return InventoryResult(inventory, tuple(captures), metadata, tool['sha256'])

    def repository_evidence(self):
        # No caller argument can masquerade as a live signature/advisory verifier.
        raise QueryUnavailable('repository-authentication-unavailable')

    def simulate(self):
        # APT diagnostic has no concrete authenticated consumer; DNF complete
        # resolve/store requires a separately qualified copied-cache API adapter.
        # Neither is dispatched while vendor authentication remains absent.
        raise QueryUnavailable('authenticated-simulation-adapter-unavailable')
