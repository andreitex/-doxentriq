"""Explicit tracked Linux parent evidence adapter; no activation or OS defaults.

The trusted company entry supplies ORIGINAL installer_parent/backend modules and
independently trusted interpreter, OS, libc and getdents capabilities. This module
does not establish their authenticity. Tests inject every syscall. Readonly proc
magic-link observations never open/duplicate the original parent's lock OFD.
Logical limits do not bound an uninterruptible syscall or qualify native capacity.
"""
import math
import re
import stat
import weakref
from types import ModuleType, MappingProxyType

MAX_OWNED, MAX_CALLS, MAX_NAMES, MAX_PROC_READS = 256, 65536, 1024, 4096
MAX_SECONDS, MAX_READ, DIR_BUFFER = 600, 16384, 4096
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
UNRELEASED_RESOURCES = []
_SYSTEM_STATE = {}


class ParentSystemUnavailable(ValueError): pass


def require(value):
    if not value: raise ParentSystemUnavailable('company-parent-system-unavailable')


def _stamp(value):
    function = getattr(value, '__func__', value)
    return function, getattr(function, '__code__', None)


class ParentSystem:
    """Original P System protocol, with owned/transient descriptors tracked.

    No constructor argument is a grant. Exact module/dependency identity and
    signed delivery are outer trusted-entry obligations. close() may use only
    the originally captured close syscall, once per owned acquisition. Unknown
    results/close outcomes remain sticky, retaining this adapter and exact refs.
    The caller must use original P.hold_parent and then require_released().
    """
    def __init__(self, parent_module, *, os_module, sys_module, platform_module,
                 select_module, ctypes_module, libc, backend_module, getdents64,
                 clock, seconds=MAX_SECONDS):
        require(not UNRELEASED_RESOURCES and type(parent_module) is ModuleType
            and type(backend_module) is ModuleType)
        p, bk, c = parent_module, backend_module, ctypes_module
        require(getattr(p, 'BASE', None) == '/etc/autosoft-install-admission'
            and p.FIELDS == FIELDS and p.PROC_MAX == MAX_READ and p.RECORD_MAX == 4096)
        require(getattr(os_module, 'name', None) == 'posix'
            and sys_module.platform == 'linux' and sys_module.byteorder == 'little'
            and platform_module.machine() == 'x86_64')
        require(type(getdents64) is bk.LinuxAMD64Getdents64)
        require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= MAX_SECONDS
            and callable(clock))
        self._p, self._bk = p, bk
        self._modules = ((p, dict(vars(p))), (bk, dict(vars(bk))))
        self._classes = tuple((kind, dict(vars(kind))) for kind in
            (type(self), p.Metadata, p.ParentInput, bk.LinuxAMD64Getdents64))
        names = ('open','stat','fstat','get_inheritable','pread','read','readlink','close',
                 'getpid','getppid','getresuid','getresgid','pidfd_open','major','minor')
        calls = {name:getattr(os_module, name, None) for name in names}
        require(all(callable(value) for value in calls.values()))
        require(calls['open'] in os_module.supports_dir_fd and calls['stat'] in os_module.supports_dir_fd
            and calls['readlink'] in os_module.supports_dir_fd)
        flags = {name:getattr(os_module,name,None) for name in
            ('O_RDONLY','O_NOFOLLOW','O_CLOEXEC','O_DIRECTORY','O_NONBLOCK')}
        require(type(flags['O_RDONLY']) is int and flags['O_RDONLY'] == 0)
        values = [v for k,v in flags.items() if k != 'O_RDONLY']
        require(all(type(v) is int and v > 0 for v in values)
            and all(not a & b for i,a in enumerate(values) for b in values[i+1:]))
        require(all(callable(getattr(c,n,None)) for n in ('sizeof','CFUNCTYPE','create_string_buffer','byref')))
        require(c.sizeof(c.c_int) == 4 and c.sizeof(c.c_long) == 8 and c.sizeof(c.c_void_p) == 8)
        function = c.CFUNCTYPE(c.c_int,c.c_int,c.c_void_p,use_errno=True)(('fstatfs',libc))
        require(callable(function) and callable(getdents64.read) and callable(select_module.poll))
        require(all(type(getattr(select_module,n,None)) is int and getattr(select_module,n) > 0
            for n in ('POLLIN','POLLHUP','POLLERR')))
        self._dependencies = []
        for obj, keys in ((os_module, names + tuple(flags)),
                          (sys_module, ('platform','byteorder')),
                          (platform_module, ('machine',)),
                          (select_module, ('poll','POLLIN','POLLHUP','POLLERR')),
                          (c, ('sizeof','CFUNCTYPE','create_string_buffer','byref','c_int','c_long','c_void_p')),
                          (libc, ('fstatfs',)), (getdents64, ('read',))):
            self._dependencies.extend((obj,k,getattr(obj,k),_stamp(getattr(obj,k))) for k in keys)
        self._calls, self._flags = MappingProxyType(calls), MappingProxyType(flags)
        self._raw_close = calls['close']; self._raw_close_stamp = _stamp(calls['close'])
        self._fstatfs, self._buffer, self._byref = function, c.create_string_buffer, c.byref
        self._dents, self._poll = getdents64.read, select_module.poll
        self._events = select_module.POLLIN | select_module.POLLHUP | select_module.POLLERR
        self._clock, self._clock_stamp = clock, _stamp(clock)
        now = clock(); require(type(now) in (int,float) and math.isfinite(now))
        self._deadline = now + seconds
        self._owned, self._attempted, self._paths = set(), set(), {}
        self._unknown, self._calls_count, self._proc_reads = False, 0, 0
        self.proc_fd, self._arguments, self._own_pid = None, None, None
        owned, attempted, paths = self._owned, self._attempted, self._paths
        raw_close, stamp = self._raw_close, self._raw_close_stamp
        instance, retained = vars(self), UNRELEASED_RESOURCES
        identity = id(self)
        reference = weakref.ref(self,lambda unused:_SYSTEM_STATE.pop(identity,None))
        def known_close(fd):
            require(type(fd) is int and 0 <= fd < 2**31 and fd in owned and fd not in attempted)
            attempted.add(fd)
            try:
                require(_stamp(raw_close) == stamp and raw_close(fd) is None)
            except BaseException:
                dict.__setitem__(instance,'_unknown',True)
                retained.append((reference(),'close-unknown',(fd,raw_close),raw_close))
                raise ParentSystemUnavailable('company-parent-system-unavailable') from None
            owned.remove(fd); paths.pop(fd,None)
            if not owned: _SYSTEM_STATE[identity]['hold'] = None
        _SYSTEM_STATE[identity] = dict(value=reference,hold=None,owned=owned,attempted=attempted,paths=paths,
            instance=instance,close=known_close)

    def _retain(self, kind, value, release=None):
        self._unknown = True
        UNRELEASED_RESOURCES.append((self, kind, value, release))

    def _ready(self):
        require(not self._unknown and not UNRELEASED_RESOURCES)
        try:
            require(_stamp(self._clock) == self._clock_stamp)
            now = self._clock(); require(type(now) in (int,float) and math.isfinite(now) and now < self._deadline)
            require(self._calls_count < MAX_CALLS); self._calls_count += 1
            state = _SYSTEM_STATE.get(id(self))
            require(type(state) is dict and state['value']() is self and vars(self) is state['instance']
                and self._owned is state['owned'] and type(self._owned) is set
                and self._attempted is state['attempted'] and type(self._attempted) is set
                and self._paths is state['paths'] and type(self._paths) is dict)
            for obj, expected in self._modules + self._classes:
                current = vars(obj)
                require(set(current) == set(expected) and all(current[k] is v for k,v in expected.items()))
            for obj,key,value,stamp in self._dependencies:
                current = getattr(obj,key)
                require(current == value and _stamp(current) == stamp)
        except BaseException:
            self._retain('trust-or-boundary', (self._modules,self._classes,self._dependencies))
            raise ParentSystemUnavailable('company-parent-system-unavailable') from None

    def _fd(self, fd):
        require(type(fd) is int and 0 <= fd < 2**31 and fd in self._owned and fd not in self._attempted)
        return fd

    def _metadata(self, value):
        result = self._p.Metadata(*(getattr(value,n,None) for n in FIELDS))
        return result.validate()

    def _component(self, value):
        require(type(value) is str and 0 < len(value) <= 64 and value.isascii()
            and re.fullmatch(r'[A-Za-z0-9_.-]+',value) is not None and value not in ('.','..'))
        return value

    def _allowed(self, path):
        if path in ('/','/proc'): return path
        require(self._arguments is not None)
        base, session = self._p.BASE, self._p.BASE + '/sessions/' + self._arguments.session
        require(path in ('/etc',base,base+'/sessions',session,base+'/binding',base+'/install.lock',session+'/intent')
            or (path.startswith(session+'/') and re.fullmatch(r'[a-z][a-z0-9-]{0,47}\.(intent|confirmed)',path[len(session)+1:]) is not None))
        return path

    def _open_at(self, parent, name, directory, path):
        self._ready(); require(type(directory) is bool and len(self._owned) < MAX_OWNED)
        state = _SYSTEM_STATE[id(self)]; close = state['close']
        if parent is not None: self._fd(parent)
        flags = self._flags['O_NOFOLLOW'] | self._flags['O_CLOEXEC'] | self._flags['O_NONBLOCK']
        if directory: flags |= self._flags['O_DIRECTORY']
        call = self._calls['open']
        fd = call(name,flags) if parent is None else call(name,flags,dir_fd=parent)
        if not (type(fd) is int and 0 <= fd < 2**31 and fd not in self._owned):
            self._retain('open-result', (call,fd), self._raw_close)
            raise ParentSystemUnavailable('company-parent-system-unavailable')
        state['owned'].add(fd); state['attempted'].discard(fd); state['paths'][fd] = path; state['hold'] = self
        try:
            require(self._calls['get_inheritable'](fd) is False)
            value = self._metadata(self._calls['fstat'](fd))
            require((stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
                and value.st_uid == value.st_gid == 0)
            return fd
        except BaseException:
            close(fd); raise

    def lstat(self, path):
        self._ready(); self._allowed(path)
        return self._metadata(self._calls['stat'](path,follow_symlinks=False))

    def fstat(self, fd):
        self._ready(); return self._metadata(self._calls['fstat'](self._fd(fd)))

    def open(self, parent, name, directory):
        if parent is None:
            require(name == '/' and directory is True); path = '/'
        else:
            self._fd(parent); self._component(name)
            path = self._paths[parent].rstrip('/') + '/' + name
        self._allowed(path)
        return self._open_at(parent,name,directory,path)

    def cloexec(self, fd):
        self._ready(); return self._calls['get_inheritable'](self._fd(fd)) is False

    def close(self, fd):
        # Cleanup is permitted after trust/time failure; no current callback lookup.
        state = _SYSTEM_STATE.get(id(self)); require(type(state) is dict and state['value']() is self)
        state['close'](fd)

    def require_released(self):
        self._ready(); require(not self._owned and self.proc_fd is None)
        return self

    def device(self, value):
        self._ready(); require(type(value) is int and value >= 0)
        result = self._calls['major'](value),self._calls['minor'](value)
        require(all(type(n) is int and n >= 0 for n in result)); return result

    def filesystem(self, fd):
        self._ready(); self._fd(fd)
        before = self.fstat(fd); buffer = self._buffer(512)
        answer = self._fstatfs(fd,self._byref(buffer)); require(type(answer) is int and answer == 0)
        raw = buffer.raw; require(type(raw) is bytes and len(raw) == 512)
        require(self.fstat(fd) == before)
        return int.from_bytes(raw[:8],'little')

    def read(self, fd, limit):
        self._ready(); self._fd(fd)
        require(type(limit) is int and 0 < limit <= self._p.RECORD_MAX)
        before = self.fstat(fd); raw = self._calls['pread'](fd,limit+1,0)
        require(type(raw) is bytes and len(raw) <= limit and self.fstat(fd) == before)
        return raw

    def _enumerate(self, fd, limit, proc=False):
        self._ready(); self._fd(fd)
        require(type(limit) is int and 0 < limit <= MAX_NAMES)
        before = self.fstat(fd); require(stat.S_ISDIR(before.st_mode))
        close = _SYSTEM_STATE[id(self)]['close']
        enum = self._open_at(fd,'.',True,self._paths[fd])
        try:
            require(self.fstat(enum).directory() == before.directory())
            result, seen, chunks = [], set(), 0
            while True:
                self._ready(); raw = self._dents(enum,DIR_BUFFER); chunks += 1
                require(type(raw) is bytes and len(raw) <= DIR_BUFFER and chunks <= MAX_NAMES+1)
                if not raw: break
                offset = 0
                while offset < len(raw):
                    require(len(raw)-offset >= 24)
                    length = int.from_bytes(raw[offset+16:offset+18],'little')
                    require(24 <= length <= 280 and length % 8 == 0 and offset+length <= len(raw))
                    ino = int.from_bytes(raw[offset:offset+8],'little'); kind = raw[offset+18]
                    body = raw[offset+19:offset+length]; end = body.find(b'\0')
                    require(ino > 0 and kind in ((0,4,8,10) if proc else (0,4,8)) and end > 0)
                    name = body[:end].decode('ascii','strict'); offset += length
                    if name in ('.','..'): continue
                    self._component(name); require(name not in seen and len(seen) < limit)
                    if proc: require(re.fullmatch(r'0|[1-9][0-9]{0,6}',name) is not None)
                    seen.add(name)
                    # The separately owned enumeration FD is closed below.
                    # Count it toward the original1024 inventory bound, but do
                    # not later stat that now-closed transient numeric identity.
                    if not (proc and name == str(enum)): result.append(name)
            require(self.fstat(fd).directory() == before.directory()
                and self.fstat(enum).directory() == before.directory())
            return tuple(sorted(result))
        finally:
            close(enum)

    def names(self, fd, limit):
        self._allowed(self._paths[self._fd(fd)])
        require(not self._paths[fd].startswith('/proc'))
        return self._enumerate(fd,limit)

    def _proc_root(self):
        self._ready(); self._fd(self.proc_fd)
        require(self._paths[self.proc_fd] == '/proc')
        return self.proc_fd

    def _proc_read(self, parts, limit):
        require(type(parts) is tuple and 1 <= len(parts) <= 4
            and type(limit) is int and 0 < limit <= MAX_READ and self._proc_reads < MAX_PROC_READS)
        if parts != ('sys','kernel','random','boot_id'):
            require(self._arguments is not None and self._own_pid is not None)
            pid = parts[0]
            require(pid in (str(self._own_pid),str(self._arguments.parent_pid)))
            if len(parts) == 2:
                require(parts[1] == 'status' or (parts[1] == 'stat' and pid == str(self._arguments.parent_pid)))
            else:
                require(len(parts) == 3 and parts[1] == 'fdinfo' and re.fullmatch(r'0|[1-9][0-9]{0,9}',parts[2]) is not None)
                fd = int(parts[2])
                require((pid == str(self._own_pid) and fd in self._owned and fd not in self._attempted)
                    or (pid == str(self._arguments.parent_pid) and fd in (self._arguments.directory_fd,self._arguments.lock_fd)))
        self._proc_reads += 1; current = self._proc_root(); owned = []
        close = _SYSTEM_STATE[id(self)]['close']
        try:
            for i,name in enumerate(parts):
                self._component(name)
                path = self._paths[current] + '/' + name
                current = self._open_at(current,name,i < len(parts)-1,path); owned.append(current)
            before = self.fstat(current); raw = self._calls['read'](current,limit+1)
            require(type(raw) is bytes and 0 < len(raw) <= limit and self.fstat(current) == before)
            return raw
        finally:
            failed = False
            for fd in reversed(owned):
                try: close(fd)
                except BaseException: failed = True
            require(not failed)

    def _magic(self, parts):
        self._ready(); root = self._proc_root()
        require(type(parts) is tuple and len(parts) in (2,3) and self._arguments is not None and self._own_pid is not None)
        parent,own = str(self._arguments.parent_pid),str(self._own_pid)
        if len(parts) == 2:
            require(parts == (parent,'exe'))
        elif parts[1] == 'ns':
            require(parts[0] in (parent,own) and parts[2] in ('pid','mnt'))
        else:
            require(parts[1] == 'fd' and re.fullmatch(r'0|[1-9][0-9]{0,6}',parts[2]) is not None
                and (parts[0] == own or (parts[0] == parent and int(parts[2]) in
                    (self._arguments.directory_fd,self._arguments.lock_fd))))
        path = '/'.join(self._component(n) for n in parts)
        # Metadata/readlink only: never os.open this proc magic-link path.
        before = self._metadata(self._calls['stat'](path,dir_fd=root))
        link = self._calls['readlink'](path,dir_fd=root)
        require(type(link) is str and 0 < len(link) <= 4096
            and self._metadata(self._calls['stat'](path,dir_fd=root)) == before
            and self._calls['readlink'](path,dir_fd=root) == link)
        return before,link

    def identity(self, arguments):
        self._ready(); require(type(arguments) is self._p.ParentInput); arguments.validate()
        if self._arguments is None: self._arguments = arguments
        require(arguments == self._arguments)
        own = self._calls['getpid']()
        uid,gid = self._calls['getresuid'](),self._calls['getresgid']()
        require(type(own) is int and 1 < own < 2**31 and self._calls['getppid']() == arguments.parent_pid
            and type(uid) is tuple and type(gid) is tuple and len(uid) == len(gid) == 3
            and all(type(n) is int and n == 0 for n in uid+gid))
        if self._own_pid is None: self._own_pid = own
        require(own == self._own_pid)
        self._p.process_status(self._proc_read((str(own),'status'),MAX_READ),own,arguments.parent_pid)
        self._p.process_status(self._proc_read((str(arguments.parent_pid),'status'),MAX_READ),arguments.parent_pid,bash=True)
        start = self._p.parent_stat(self._proc_read((str(arguments.parent_pid),'stat'),MAX_READ),arguments.parent_pid)
        boot = self._proc_read(('sys','kernel','random','boot_id'),64)
        require(re.fullmatch(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n',boot) is not None)
        namespaces = []
        for kind in ('pid','mnt'):
            values = []
            for pid in (own,arguments.parent_pid):
                meta,link = self._magic((str(pid),'ns',kind))
                require(link == kind + ':[' + str(meta.st_ino) + ']'); values.append((meta.st_dev,meta.st_ino))
            require(values[0] == values[1]); namespaces.append(values[0])
        binary,target = self._magic((str(arguments.parent_pid),'exe'))
        require(target in ('/bin/bash','/usr/bin/bash')
            and self._metadata(self._calls['stat'](target)) == binary
            and stat.S_ISREG(binary.st_mode) and binary.st_uid == binary.st_gid == 0
            and not stat.S_IMODE(binary.st_mode) & 0o022 and stat.S_IMODE(binary.st_mode) & 0o111)
        return own,arguments.parent_pid,boot.decode().strip(),start,tuple(namespaces),binary

    def pidfd(self, pid):
        self._ready(); require(self._arguments is not None and type(pid) is int and pid == self._arguments.parent_pid
            and len(self._owned) < MAX_OWNED)
        call = self._calls['pidfd_open']; fd = call(pid,0)
        close = _SYSTEM_STATE[id(self)]['close']
        if not (type(fd) is int and 0 <= fd < 2**31 and fd not in self._owned):
            self._retain('pidfd-result',(call,fd),self._raw_close)
            raise ParentSystemUnavailable('company-parent-system-unavailable')
        state = _SYSTEM_STATE[id(self)]
        state['owned'].add(fd); state['attempted'].discard(fd); state['paths'][fd] = 'pidfd'; state['hold'] = self
        try:
            require(self.cloexec(fd)); self.fstat(fd); return fd
        except BaseException:
            close(fd); raise

    def alive(self, fd):
        self._ready(); self._fd(fd); require(self._paths[fd] == 'pidfd')
        poller = self._poll(); register,poll = poller.register,poller.poll
        stamps = _stamp(register),_stamp(poll)
        register(fd,self._events); result = poll(0)
        require((_stamp(poller.register),_stamp(poller.poll)) == stamps and type(result) is list)
        return not result

    def parent_descriptor(self, pid, fd):
        self._ready(); require(self._arguments is not None and type(pid) is int and pid == self._arguments.parent_pid
            and type(fd) is int and fd in (self._arguments.directory_fd,self._arguments.lock_fd))
        return self._magic((str(pid),'fd',str(fd)))

    def descriptor_info(self, pid, fd):
        self._ready(); require(self._arguments is not None and type(pid) is int and type(fd) is int)
        require((pid == self._arguments.parent_pid and fd in (self._arguments.directory_fd,self._arguments.lock_fd))
            or (pid == self._own_pid and fd in self._owned and fd not in self._attempted))
        return self._proc_read((str(pid),'fdinfo',str(fd)),self._p.RECORD_MAX)

    def inherited(self, directory, lock):
        self._ready(); require(type(directory) is self._p.Metadata and type(lock) is self._p.Metadata
            and self._own_pid is not None)
        directory.validate(); lock.validate(); root = self._proc_root(); own = None; fd = None
        close = _SYSTEM_STATE[id(self)]['close']
        try:
            own = self._open_at(root,str(self._own_pid),True,'/proc/'+str(self._own_pid))
            fd = self._open_at(own,'fd',True,'/proc/'+str(self._own_pid)+'/fd')
            names = self._enumerate(fd,MAX_NAMES,True)
            targets = {(directory.st_dev,directory.st_ino),(lock.st_dev,lock.st_ino)}
            for name in names:
                value,_ = self._magic((str(self._own_pid),'fd',name))
                if (value.st_dev,value.st_ino) in targets: return True
            return False
        finally:
            failed = False
            for value in (fd,own):
                if value is not None:
                    try: close(value)
                    except BaseException: failed = True
            require(not failed)
