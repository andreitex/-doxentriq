"""Explicit Linux readonly OS adapter; no guard issuance or storage authority.

Construct with independently trusted os_module and sys_module references. This
adapter does not authorize execution, encryption, placement or native capacity.
It supplies only finite readonly syscall operations for company_source_guard.
No default instance, syscall invocation on import, shell or write API exists.
The caller owns its successfully returned descriptors. Native acceptance is a
separate qualification; the focused tests use injected syscalls only.
"""
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_PATH,MAX_READ,MAX_OFFSET,MAX_NAMES,MAX_OWNED=4096,65536,8*1024**2,2561,2700
GETDENTS64_X86_64,DIR_BUFFER=217,4096
UNRELEASED_RESOURCES=[]
UNRELEASED_HANDLES=UNRELEASED_RESOURCES


class SourceBackendUnavailable(ValueError):pass


def require(value,code='company_source_backend_unavailable'):
    if not value:raise SourceBackendUnavailable(code)


def component(value):
    require(type(value) is str and 0<len(value)<=256 and value.isascii()
        and re.fullmatch('[A-Za-z0-9_.-]+',value) and value not in ('.','..')
        and not value.endswith('.'))
    return value


def absolute(value):
    require(type(value) is str and 0<len(value)<=MAX_PATH and value.isascii()
        and value.startswith('/') and str(PurePosixPath(value))==value
        and '\\' not in value and '//' not in value)
    require(len(PurePosixPath(value).parts)<=64)
    for name in PurePosixPath(value).parts[1:]:component(name)
    return value


class LinuxAMD64Getdents64:
    """Explicit trusted libc/ctypes binding, Linux x86_64 little-endian only.

    No library is opened here. The trusted caller supplies the independently
    verified libc and interpreter references. Construction checks ABI widths;
    calls occur only in read(). Other architectures are unsupported.
    """
    def __init__(self,*,ctypes_module,libc,sys_module,machine_module):
        require(getattr(sys_module,'platform',None)=='linux' and getattr(sys_module,'byteorder',None)=='little'
            and callable(getattr(machine_module,'machine',None)) and machine_module.machine()=='x86_64')
        c=ctypes_module
        require(all(callable(getattr(c,name,None)) for name in ('sizeof','CFUNCTYPE','create_string_buffer','byref','get_errno','set_errno')))
        require(c.sizeof(c.c_long)==8 and c.sizeof(c.c_void_p)==8 and c.sizeof(c.c_uint)==4)
        self._function=c.CFUNCTYPE(c.c_long,c.c_long,c.c_uint,c.c_void_p,c.c_uint,use_errno=True)(('syscall',libc))
        require(callable(self._function))
        self._buffer,self._byref,self._errno,self._set_errno=c.create_string_buffer,c.byref,c.get_errno,c.set_errno
    def read(self,fd,size):
        require(type(fd) is int and 0<=fd<2**31 and type(size) is int and 0<size<=DIR_BUFFER)
        buffer=self._buffer(size);self._set_errno(0)
        result=self._function(GETDENTS64_X86_64,fd,self._byref(buffer),size)
        require(type(result) is int and -1<=result<=size)
        if result==-1:
            error=self._errno();require(type(error) is int and 0<error<4096)
            raise OSError(error,'company_source_getdents64')
        raw=buffer.raw;require(type(raw) is bytes and len(raw)==size)
        return raw[:result]


class ReadOnlySourceBackend:
    """Finite trusted OS/interpreter seam, explicitly supplied to the guard.

    os_module/sys_module are trusted caller capabilities, not candidate inputs.
    Linux capability checks are prerequisites, not an authorization boolean or
    defense against a trusted caller substituting its own Python objects.
    Getdents iteration stops at limit: the guard asks expected-count+1, so an
    overflow sentinel is retained rather than enumerating an unbounded directory.
    Unknown cleanup is sticky, with no retry/reset/adoption API.
    """
    def __init__(self,*,os_module,sys_module,getdents64):
        require(not UNRELEASED_RESOURCES and getattr(os_module,'name',None)=='posix'
            and getattr(sys_module,'platform',None)=='linux')
        require(type(getdents64) is LinuxAMD64Getdents64)
        calls={name:getattr(os_module,name,None) for name in ('open','lstat','fstat','get_inheritable','pread','close')}
        require(all(callable(call) for call in calls.values()))
        require(calls['open'] in getattr(os_module,'supports_dir_fd',()))
        flags={name:getattr(os_module,name,None) for name in ('O_RDONLY','O_NOFOLLOW','O_CLOEXEC','O_DIRECTORY','O_NONBLOCK')}
        require(type(flags['O_RDONLY']) is int and flags['O_RDONLY']==0
            and all(type(value) is int and value>0 for name,value in flags.items() if name!='O_RDONLY'))
        values=[value for name,value in flags.items() if name!='O_RDONLY']
        require(all(not a&b for i,a in enumerate(values) for b in values[i+1:]))
        self._calls,self._flags=MappingProxyType(calls),MappingProxyType(flags)
        self._getdents64=getdents64
        self._owned,self._close_attempted=set(),set()
        self._enumeration=None;self._unknown=False
    def _ready(self):require(not self._unknown and not UNRELEASED_RESOURCES)
    def _fd(self,fd):
        require(type(fd) is int and 0<=fd<2**31 and fd in self._owned and fd not in self._close_attempted)
        return fd
    def _unknown_resource(self,kind,value,release):
        self._unknown=True
        UNRELEASED_RESOURCES.append((self,kind,value,release))
    def _metadata(self,value):
        row={name:getattr(value,name,None) for name in FIELDS}
        require(all(type(value) is int and value>=0 for value in row.values()))
        return row
    def open(self,parent,name,directory):
        self._ready();require(type(directory) is bool and len(self._owned)<MAX_OWNED)
        if parent is None:
            require(name=='/' and directory is True);path='/'
        else:
            self._fd(parent);path=component(name)
        return self._open_at(parent,path,directory)
    def _open_at(self,parent,path,directory):
        self._ready();require(len(self._owned)<MAX_OWNED)
        flags=self._flags['O_RDONLY']|self._flags['O_NOFOLLOW']|self._flags['O_CLOEXEC']|self._flags['O_NONBLOCK']
        if directory:flags|=self._flags['O_DIRECTORY']
        call=self._calls['open']
        fd=call(path,flags) if parent is None else call(path,flags,dir_fd=parent)
        if not (type(fd) is int and 0<=fd<2**31 and fd not in self._owned and fd not in self._close_attempted):
            self._unknown_resource('open-result',fd,self._calls['close'])
            raise SourceBackendUnavailable('company_source_backend_open_unknown')
        self._owned.add(fd)
        try:require(self._calls['get_inheritable'](fd) is False)
        except BaseException:
            self.close(fd);raise
        return fd
    def lstat(self,path):
        self._ready();return self._metadata(self._calls['lstat'](absolute(path)))
    def fstat(self,fd):
        self._ready();return self._metadata(self._calls['fstat'](self._fd(fd)))
    def inheritable(self,fd):
        self._ready();value=self._calls['get_inheritable'](self._fd(fd))
        require(type(value) is bool);return value
    def pread(self,fd,count,offset):
        self._ready();self._fd(fd)
        require(type(count) is int and 0<count<=MAX_READ and type(offset) is int
            and 0<=offset<=MAX_OFFSET and count<=MAX_OFFSET+1-offset)
        value=self._calls['pread'](fd,count,offset)
        require(type(value) is bytes and len(value)<=count)
        return value
    def names(self,fd,limit):
        self._ready();self._fd(fd)
        require(type(limit) is int and 0<limit<=MAX_NAMES and self._enumeration is None)
        before=self.fstat(fd);require(stat.S_ISDIR(before['st_mode']))
        enumeration=self._open_at(fd,'.',True);self._enumeration=enumeration
        try:
            require(self.fstat(enumeration)==before)
            names=self._directory_records(enumeration,limit)
            require(self.fstat(fd)==before and self.fstat(enumeration)==before)
            return names
        finally:
            try:self.close(enumeration)
            finally:self._enumeration=None
    def _directory_records(self,fd,limit):
        names=[];dots=set();records=0;total=0
        for _ in range(limit+3):
            raw=self._getdents64.read(fd,DIR_BUFFER)
            require(type(raw) is bytes and len(raw)<=DIR_BUFFER)
            total+=len(raw);require(total<=(limit+2)*280+DIR_BUFFER)
            if not raw:return names
            offset=0
            while offset<len(raw):
                require(len(raw)-offset>=24)
                length=int.from_bytes(raw[offset+16:offset+18],'little')
                require(24<=length<=280 and length%8==0 and offset+length<=len(raw))
                require(int.from_bytes(raw[offset:offset+8],'little')>0 and raw[offset+18] in (0,4,8))
                body=raw[offset+19:offset+length];end=body.find(b'\0')
                require(0<end<=255 and length==(19+end+1+7)//8*8)
                try:name=body[:end].decode('ascii')
                except UnicodeError:raise SourceBackendUnavailable('company_source_backend_directory_name') from None
                records+=1;require(records<=limit+2)
                if name in ('.','..'):
                    require(name not in dots);dots.add(name)
                else:
                    component(name);require(name not in names);names.append(name)
                    if len(names)==limit:return names
                offset+=length
        raise SourceBackendUnavailable('company_source_backend_directory_calls')
    def close(self,fd):
        # Known outer-owned closes remain allowed during uncertain unwind, once.
        self._fd(fd);self._close_attempted.add(fd);release=self._calls['close']
        try:require(release(fd) is None)
        except BaseException:
            self._unknown_resource('fd',fd,release)
            raise SourceBackendUnavailable('company_source_backend_fd_close_unknown') from None
        self._owned.remove(fd)
        self._close_attempted.remove(fd)
    def require_released(self):
        """Caller must assert this after the guard's known FD unwind, before ack.

        Closing the guard's own FDs alone cannot establish release of an adapter's
        transient enumeration resource. Unknown records are never reset here.
        """
        self._ready()
        require(not self._owned and not self._close_attempted and self._enumeration is None)
        return self
