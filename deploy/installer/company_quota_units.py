"""Exclusive installation of only the reviewed private quota support units.

No service enablement, timer, arbitrary path or overwrite API is exposed. The
caller holds original source/storage/parent authority. A partial write remains
in place and requires explicit reconciliation; it is never adopted or replayed.
"""
from contextlib import ExitStack
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat

UNIT='/etc/systemd/system/autosoft-quota.service'
DROPIN='/etc/systemd/system/docker.service.d/autosoft-quota.conf'
BUILDS='/etc/systemd/system/docker.service.d/autosoft-builds.conf'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
UNKNOWN=[]


def require(value):
    if not value:raise ValueError('Quota support units are unconfirmed; preserve the installation for IT review')


def identity(info):return tuple(getattr(info,name) for name in FIELDS)


def plan(B,data,root,builds_raw):
    """Reuse signed bootstrap's unit, retain the already-qualified build mount."""
    require(type(builds_raw) is bytes and 0<len(builds_raw)<=4096)
    match=re.fullmatch(rb'\[Unit\]\nRequires=([A-Za-z0-9_.\\-]+\.mount)\nAfter=\1\n',builds_raw)
    require(match is not None)
    mount=match[1].decode('ascii')
    unit=B.quota_service_unit(data,root).encode('ascii')
    require(0<len(unit)<=16384 and unit.startswith(b'[Unit]\n'))
    # Paths admitted by bootstrap contain only ASCII alphanumerics, underscore,
    # dot and hyphen. Bind the existing mount name to that exact path using
    # systemd's path escaping (slash separator, literal hyphen as hex).
    path=str(data)+'/runtime/builds';escaped=path.lstrip('/').replace('-',r'\x2d').replace('/','-')
    if escaped.startswith('.'):escaped=r'\x2e'+escaped[1:]
    require(mount==escaped+'.mount')
    dropin=('[Unit]\nRequires=autosoft-quota.service '+mount+
        '\nAfter=autosoft-quota.service '+mount+'\n').encode('ascii')
    return {UNIT:unit,DROPIN:dropin}


class QuotaUnits:
    """Nofollow target ancestry and exact bytes for the two fixed new files."""
    def __init__(self,expected,*,authority,builds_raw,installed=False):
        require(os.name=='posix' and os.geteuid()==0 and not UNKNOWN and callable(authority)
            and type(installed) is bool and type(expected) is dict and set(expected)=={UNIT,DROPIN}
            and all(type(v) is bytes and 0<len(v)<=16384 for v in expected.values()))
        require(type(builds_raw) is bytes and 0<len(builds_raw)<=4096)
        self.expected=dict(expected);self.builds_raw=builds_raw;self.authority=authority;self.installed=installed
        self.stack=ExitStack();self.parents={};self.files={};self.closed=False
        try:
            for path in sorted({str(PurePosixPath(p).parent) for p in expected}):
                fd=None;rows=[]
                for part in PurePosixPath(path).parts:
                    parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                    self.stack.callback(os.close,fd);before=identity(os.fstat(fd))
                    require(stat.S_ISDIR(before[2]) and before[3:5]==(0,0) and not before[2]&0o022)
                    rows.append((parent,part,fd,before[:5]))
                names=set(os.listdir(fd));require(len(names)<=4096)
                self.parents[path]=(fd,rows,names)
            for path in sorted(expected):
                if installed:self._capture(path)
                else:require(PurePosixPath(path).name not in self.parents[str(PurePosixPath(path).parent)][2])
            self._capture(BUILDS,builds_raw)
            self.check()
        except BaseException:self.close(check=False);raise

    def _capture(self,path,raw=None):
        parent=self.parents[str(PurePosixPath(path).parent)][0]
        fd=os.open(PurePosixPath(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
        self.stack.callback(os.close,fd);before=identity(os.fstat(fd));raw=self.expected[path] if raw is None else raw
        require(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2])==0o644 and before[3:5]==(0,0)
            and before[5]==1 and before[6]==len(raw) and os.pread(fd,len(raw)+1,0)==raw)
        self.files[path]=(fd,before)

    def check(self):
        require(not self.closed and not UNKNOWN);self.authority()
        for fd,rows,names in self.parents.values():
            for parent,name,opened,before in rows:
                require(identity(os.fstat(opened))[:5]==before
                    ==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))[:5])
            require(set(os.listdir(fd))==names)
        for path,raw in dict(self.expected,**{BUILDS:self.builds_raw}).items():
            parent=self.parents[str(PurePosixPath(path).parent)][0];name=PurePosixPath(path).name
            if path not in self.files:require(name not in os.listdir(parent));continue
            fd,before=self.files[path]
            require(identity(os.fstat(fd))==before==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
                and os.pread(fd,len(raw)+1,0)==raw)

    def install(self):
        require(not self.installed and set(self.files)=={BUILDS});self.check()
        for path,raw in self.expected.items():
            self.check();parent,_,names=self.parents[str(PurePosixPath(path).parent)]
            name=PurePosixPath(path).name
            fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            try:
                offset=0
                while offset<len(raw):
                    count=os.write(fd,raw[offset:]);require(count>0);offset+=count
                os.fchmod(fd,0o644);os.fsync(fd)
                require(os.pread(fd,len(raw)+1,0)==raw)
            finally:os.close(fd)
            names.add(name);self._capture(path);os.fsync(parent);self.check()
        self.installed=True

    def observation(self):
        self.check();require(self.installed and set(self.files)==set(self.expected)|{BUILDS})
        return {path:dict(sha256=hashlib.sha256(raw).hexdigest(),identity=list(self.files[path][1]))
                for path,raw in sorted(self.expected.items())}

    def close(self,*,check=True):
        if self.closed:return
        try:
            if check:self.check()
        finally:
            self.closed=True
            try:self.stack.close()
            except BaseException:UNKNOWN.append(self);raise

    def __enter__(self):return self
    def __exit__(self,*args):self.close(check=args[0] is None)
