"""Linux collaborators for the company-owned retention worker.

The authenticated worker and root-installed OS are the trust boundary. These
observations detect replacement; hashes of the installed OS are not signatures
or proof that an already compromised host is clean. No candidate code is loaded.
"""
from contextlib import contextmanager
import ctypes
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import platform
import resource
import select
import signal
import stat
import subprocess
import sys
import time
import fcntl

FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
TOOLS = ('/usr/bin/systemctl','/usr/bin/docker','/usr/sbin/cryptsetup',
         '/usr/sbin/losetup','/usr/bin/findmnt','/usr/sbin/xfs_quota')
UNRELEASED = []


def require(value, reason='native-station-unavailable'):
    if value is not True:
        raise ValueError(reason)


def metadata(info):
    return {key: getattr(info, key) for key in FIELDS}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def baseline():
    require(sys.platform == 'linux' and platform.machine() == 'x86_64'
            and os.getuid() == os.getgid() == os.geteuid() == os.getegid() == 0
            and sys.flags.isolated == 1 and sys.dont_write_bytecode)
    require(not UNRELEASED and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
            and len(os.listdir('/proc/self/task')) == 1 and not subprocess._active)
    require(not any(key.startswith(('LD_', 'PYTHON')) for key in os.environ), 'clean-worker-environment-required')
    require(resource.getrlimit(resource.RLIMIT_NOFILE)[0] >= 4096, 'worker-nofile-4096-required')


@contextmanager
def held_file(path, maximum, *, executable=False):
    """Hold every nofollow ancestor and the leaf until bounded readback ends."""
    path = str(path)
    parts = PurePosixPath(path).parts
    require(path == PurePosixPath(path).as_posix() and path.startswith('/')
            and len(parts) <= 32 and '..' not in parts and len(parts) > 1)
    rows = []
    try:
        for index, name in enumerate(parts):
            directory = index != len(parts)-1
            parent = rows[-1][0] if rows else None
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
            fd = os.open(name, flags, dir_fd=parent)
            rows.append((fd, parent, name, None))
            info = os.fstat(fd)
            require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode)
                    and info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
            if not directory:
                require(info.st_nlink == 1 and 0 < info.st_size <= maximum
                        and (not executable or bool(info.st_mode & 0o111)))
            rows[-1] = (fd, parent, name, metadata(info))
        def check():
            require(not UNRELEASED)
            for fd, parent, name, before in rows:
                require(before == metadata(os.fstat(fd)) == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        check()
        yield rows[-1][0], rows[-1][3], check
        check()
    finally:
        failed = False
        for fd, *_ in reversed(rows):
            try:
                os.close(fd)
            except BaseException:
                UNRELEASED.append(fd)
                failed = True
        require(not failed, 'native-station-close-unknown')


def read_protected(path, maximum=131072):
    with held_file(path, maximum) as (fd, info, check):
        raw = bytearray()
        while len(raw) < info['st_size']:
            part = os.pread(fd, min(65536, info['st_size']-len(raw)), len(raw))
            require(bool(part))
            raw.extend(part)
        require(os.pread(fd, 1, len(raw)) == b'')
        check()
        return bytes(raw)


def tool_pin(path):
    with held_file(path, 128*1024**2, executable=True) as (fd, info, check):
        digest = hashlib.sha256()
        amount = 0
        while amount < info['st_size']:
            raw = os.pread(fd, min(65536, info['st_size']-amount), amount)
            require(bool(raw))
            digest.update(raw)
            amount += len(raw)
        check()
        return dict(bytes=amount, sha256=digest.hexdigest(), identity=info)


class SourceFiles:
    """Actual V file adapter with a close ledger, including failed opens."""
    def __init__(self):
        self.owned = set()
    def lstat(self, path): return os.stat(path, follow_symlinks=False)
    def open(self, parent, name, directory):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                     (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=parent)
        self.owned.add(fd)
        return fd
    def fstat(self, fd): return os.fstat(fd)
    def cloexec(self, fd): return not os.get_inheritable(fd)
    def read(self, fd, amount, offset): return os.pread(fd, amount, offset)
    def close(self, fd):
        require(fd in self.owned)
        try:
            os.close(fd)
            self.owned.remove(fd)
        except BaseException:
            UNRELEASED.append((self, fd))
            raise
    def require_released(self):
        require(not self.owned and not UNRELEASED, 'native-source-release-unknown')


def stage_inputs(controller, request_raw, crypto_module):
    """Select real collaborators; original signed-source/controller checks remain."""
    baseline()
    # All imports complete before the original modules snapshot station globals.
    libc = ctypes.CDLL(None, use_errno=True)
    files = SourceFiles()
    crypto = crypto_module.ReleaseCrypto(openssl_pin=tool_pin('/usr/bin/openssl'),
        budget=dict(calls=8, seconds=240), os_module=os, sys_module=sys,
        subprocess_module=subprocess, select_module=select, signal_module=signal,
        fcntl_module=fcntl, clock=time.monotonic,
        station_contract=crypto_module.STATION_CONTRACT, protected_fds=())
    collaborators = controller.native_stage_inputs(request_raw,
        os_module=os, sys_module=sys, platform_module=platform, select_module=select,
        ctypes_module=ctypes, libc=libc, subprocess_module=subprocess, signal_module=signal,
        io_module=io, fcntl_module=fcntl, tool_catalog={path: tool_pin(path) for path in TOOLS},
        backend_budget=dict(sourceFiles=2048, sourceDirectories=512, ownedFds=2700,
            externalFdReserve=128, seconds=600, readBytes=512*1024**2, writeBytes=104*1024**2),
        runner_budget=dict(calls=256, seconds=600, toolReadBytes=4*1024**3, outputBytes=32*1024**2),
        clock=time.monotonic, files=files, crypto=crypto)
    return collaborators


def require_released(collaborators):
    for name in ('files', 'crypto', 'backend', 'runner', 'parent_system'):
        collaborators[name].require_released()
    require(not UNRELEASED)
