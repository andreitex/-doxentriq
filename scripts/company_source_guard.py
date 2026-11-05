"""Held complete immutable source bytes, read-only and without loader authority.

The caller supplies independently trusted verifier/backend modules and a genuine
live verifier-issued source. expected_device is only a caller constraint. This
module does not prove encryption, prior stages, native capacity, executing-module
origin, reboot eligibility or permission to execute stored code. No native
backend is supplied. Capture and each complete check get a separate 600-second
logical budget; this is neither a kernel IO deadline nor a caller lifetime bound.
Every original path/FD observation remains fixed across those checks.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat
import time
from types import MappingProxyType

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_FILES,MAX_DIRS=2048,512
MAX_FILE_BYTES,MAX_TOTAL_BYTES=8*1024**2,64*1024**2
MANIFEST_MAX,CHUNK,MAX_HELD=1024**2,65536,2700
UNRELEASED_HANDLES=[]
_ISSUED_GUARDS=set()


class SourceGuardUnavailable(ValueError):
    pass


def require(value,code='company_source_guard_unavailable'):
    if not value:raise SourceGuardUnavailable(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'


def immutable(value):
    if type(value) is dict:return MappingProxyType({key:immutable(item) for key,item in value.items()})
    if type(value) in (list,tuple):return tuple(immutable(item) for item in value)
    require(type(value) in (str,bytes,int,bool,type(None)))
    return value


def relative(value):
    require(type(value) is str and 0<len(value)<=256 and value.isascii())
    parts=value.split('/')
    require(len(parts)<=16 and all(re.fullmatch('[A-Za-z0-9_.-]+',part)
        and part not in ('.','..') and not part.endswith('.') for part in parts))
    return value


def root_path(value,release_sha):
    require(type(value) is str and 0<len(value)<=2048 and value.isascii()
        and value.startswith('/') and str(PurePosixPath(value))==value
        and '\\' not in value and '//' not in value)
    path=PurePosixPath(value);parts=path.parts
    require(6<=len(parts)<=32 and all(re.fullmatch('[A-Za-z0-9_.-]+',part)
        and part not in ('.','..') and not part.endswith('.') for part in parts[1:]))
    require(parts[-4:]==('company','source-releases',release_sha,'source'))
    return path


def source_plan(files,modes,manifest_raw):
    """Independent closed rows, caps and raw Git tree; no filesystem effects."""
    require(type(files) is dict and type(modes) is dict and 0<len(files)<=MAX_FILES
        and all(type(name) is str for name in files) and set(files)==set(modes))
    require(type(manifest_raw) is bytes and 0<len(manifest_raw)<=MANIFEST_MAX)
    def pairs(items):
        row={}
        for key,value in items:
            require(key not in row);row[key]=value
        return row
    def constant(_):raise SourceGuardUnavailable('company_source_guard_json')
    try:header=json.loads(manifest_raw,object_pairs_hook=pairs,parse_constant=constant)
    except (ValueError,TypeError,UnicodeError):raise SourceGuardUnavailable('company_source_guard_json') from None
    require(type(header) is dict and set(header)=={'schemaVersion','scope','policyVersion','sourceRevision','sourceTree','fileCount','totalBytes','archive','files'}
        and canonical(header)==manifest_raw and type(header['schemaVersion']) is int and header['schemaVersion']==1
        and type(header['policyVersion']) is int and header['policyVersion']==1
        and header['scope']=='COMPANY_FULL_PLATFORM_SOURCE_BYTES_ONLY')
    require(all(type(header[name]) is str and re.fullmatch('[a-f0-9]{40}',header[name]) for name in ('sourceRevision','sourceTree')))
    require(type(header['fileCount']) is int and type(header['totalBytes']) is int
        and type(header['files']) is list and type(header['archive']) is dict
        and set(header['archive'])=={'bytes','sha256'} and type(header['archive']['bytes']) is int
        and 0<header['archive']['bytes']<=32*1024**2
        and type(header['archive']['sha256']) is str and re.fullmatch('[a-f0-9]{64}',header['archive']['sha256']))
    require(len(header['files'])<=MAX_FILES and all(type(row) is dict
        and set(row)=={'path','bytes','sha256','gitMode'} and type(row['path']) is str
        and type(row['bytes']) is int and 0<=row['bytes']<=MAX_FILE_BYTES
        and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256'])
        and type(row['gitMode']) is str and row['gitMode'] in ('100644','100755') for row in header['files']))
    directories=set();rows=[];total=0;trie={}
    for name in sorted(files):
        relative(name);raw=files[name];mode=modes[name]
        require(type(raw) is bytes and len(raw)<=MAX_FILE_BYTES and type(mode) is str and mode in ('100644','100755'))
        total+=len(raw);require(total<=MAX_TOTAL_BYTES)
        parts=name.split('/');directories.update('/'.join(parts[:n]) for n in range(1,len(parts)))
        current=trie
        for part in parts[:-1]:
            current=current.setdefault(part,{})
            require(type(current) is dict)
        require(parts[-1] not in current)
        oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).digest()
        current[parts[-1]]=(mode,oid)
        rows.append(dict(path=name,bytes=len(raw),sha256=sha(raw),gitMode=mode))
    require(len(directories)<=MAX_DIRS and len({name.lower() for name in files})==len(files)
        and len({name.lower() for name in directories})==len(directories)
        and not {name.lower() for name in files}.intersection(name.lower() for name in directories))
    def tree(current):
        entries=[]
        for name,value in current.items():
            is_dir=type(value) is dict
            mode,oid=('40000',tree(value)) if is_dir else value
            entries.append((name.encode()+ (b'/' if is_dir else b''),mode.encode()+b' '+name.encode()+b'\0'+oid))
        raw=b''.join(row for _,row in sorted(entries))
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
    source_tree=tree(trie).hex()
    require(header['fileCount']==len(files) and header['totalBytes']==total
        and header['files']==rows and header['sourceTree']==source_tree)
    return dict(files=files,modes=modes,header=header,rows=rows,sourceTree=source_tree,
        directories=sorted(directories,key=lambda name:(name.count('/'),name)),totalBytes=total)


def live_source(verifier,held):
    validator=getattr(verifier,'require_platform_source',None)
    require(callable(validator) and validator(held) is held,'company_source_guard_source_issuance')


class HeldCompanySource:
    """Only the context factory issues a live guard; data aliases are not authority."""
    __slots__=('_verifier','_source','_backend','_clock','_root','_data_root','_device',
        '_plan','_values','_rows','_owned','_active','_deadline','_closed')
    def __init__(self,verifier,held,backend,clock,root,device,plan,metadata):
        self._verifier,self._source,self._backend,self._clock=verifier,held,backend,clock
        self._root,self._data_root,self._device=root,root.parents[3],device
        self._plan,self._values=plan,immutable(dict(files=plan['files'],git_modes=plan['modes'],metadata=metadata,root=str(root)))
        self._rows,self._owned={},[]
        self._active,self._closed=True,False
        self._begin()
    @property
    def active(self):return self._active
    def _begin(self):
        now=self._clock();require(type(now) in (int,float) and not isinstance(now,bool) and 0<=now<float('inf'))
        self._deadline=now+600
    def _tick(self):
        now=self._clock();require(type(now) in (int,float) and not isinstance(now,bool) and 0<=now<self._deadline)
    def _identity(self,info):
        require(type(info) is dict and set(info)==set(FIELDS)
            and all(type(info[name]) is int and info[name]>=0 for name in FIELDS))
        return tuple(info[name] for name in FIELDS)
    def _protected(self,path,info,directory):
        self._identity(info)
        require(info['st_uid']==info['st_gid']==0 and not stat.S_IMODE(info['st_mode'])&0o022)
        require(stat.S_ISDIR(info['st_mode']) if directory else stat.S_ISREG(info['st_mode']))
        if path==self._data_root or self._data_root in path.parents:require(info['st_dev']==self._device)
        if not directory:require(stat.S_IMODE(info['st_mode'])==0o400 and info['st_nlink']==1)
        elif path==self._root.parent or path==self._root or self._root in path.parents:
            require(stat.S_IMODE(info['st_mode'])==0o500)
        return info
    def _own(self,fd):
        if not (type(fd) is int and fd>=0 and fd not in self._owned and len(self._owned)<MAX_HELD):
            # The trusted open adapter reported an uncertain owned result. Do
            # not close an opaque or borrowed value or lose its exact identity.
            UNRELEASED_HANDLES.append((self._backend,fd))
            raise SourceGuardUnavailable('company_source_guard_open_unknown')
        self._owned.append(fd)
        require(self._backend.inheritable(fd) is False)
        return fd
    def _observe(self,path,directory,parent,name):
        self._tick();require(path not in self._rows and len(self._owned)<MAX_HELD)
        before=self._protected(path,self._backend.lstat(str(path)),directory)
        fd=self._own(self._backend.open(parent,name,directory))
        at_fd=self._protected(path,self._backend.fstat(fd),directory)
        after=self._protected(path,self._backend.lstat(str(path)),directory)
        require(self._identity(before)==self._identity(at_fd)==self._identity(after))
        self._rows[path]=dict(fd=fd,before=dict(before),directory=directory)
        return fd
    def _guard_rows(self):
        for path,row in self._rows.items():
            self._tick();fd=row['fd']
            require(self._backend.inheritable(fd) is False)
            current=self._protected(path,self._backend.lstat(str(path)),row['directory'])
            at_fd=self._protected(path,self._backend.fstat(fd),row['directory'])
            require(self._identity(current)==self._identity(at_fd)==self._identity(row['before']))
    def _read(self,path,expected):
        self._tick();row=self._rows[path];require(not row['directory'])
        require(row['before']['st_size']==len(expected))
        fd=row['fd'];offset=0;parts=[]
        while offset<len(expected):
            self._tick();amount=min(CHUNK,len(expected)-offset)
            part=self._backend.pread(fd,amount,offset)
            require(type(part) is bytes and 0<len(part)<=amount)
            parts.append(part);offset+=len(part)
        self._tick();end=self._backend.pread(fd,1,offset)
        require(type(end) is bytes and end==b'')
        require(b''.join(parts)==expected)
    def _inventory(self):
        expected={self._root:[]}
        for name in self._plan['directories']:expected[self._root/name]=[]
        for name in list(self._plan['directories'])+list(self._plan['files']):
            path=self._root/name;expected[path.parent].append(path.name)
        # These are fixed output sibling names, not journal authority.
        expected[self._root.parent]=['source','intent.json','bytes-verified.json']
        for path,names in expected.items():
            self._tick();actual=self._backend.names(self._rows[path]['fd'],len(names)+1)
            require(type(actual) is list and len(actual)<=len(names)+1
                and all(type(name) is str and relative(name)==name and '/' not in name for name in actual)
                and len(actual)==len(set(actual)) and sorted(actual)==sorted(names))
    def _capture(self):
        parent=None;path=PurePosixPath('/')
        parent=self._observe(path,True,None,'/')
        for name in self._root.parts[1:]:
            path/=name;parent=self._observe(path,True,parent,name)
        for name in self._plan['directories']:
            path=self._root/name;self._observe(path,True,self._rows[path.parent]['fd'],path.name)
        for name,raw in self._plan['files'].items():
            path=self._root/name;self._observe(path,False,self._rows[path.parent]['fd'],path.name)
            self._guard_rows();self._read(path,raw);self._guard_rows()
        self._inventory();self._guard_rows()
    def _check(self):
        self._begin();require(self._active and not self._closed and not UNRELEASED_HANDLES)
        live_source(self._verifier,self._source);self._tick()
        self._guard_rows();self._inventory();self._guard_rows()
        for name,raw in self._plan['files'].items():
            self._read(self._root/name,raw)
        self._guard_rows();self._inventory();self._guard_rows()
        live_source(self._verifier,self._source);self._tick()
    def recheck(self):
        require_live_company_source(self)
        return self
    def _value(self,name):
        require_live_company_source(self);return self._values[name]
    @property
    def files(self):return self._value('files')
    @property
    def git_modes(self):return self._value('git_modes')
    @property
    def metadata(self):return self._value('metadata')
    @property
    def root(self):return self._value('root')
    def _expire(self):
        self._active=False;_ISSUED_GUARDS.discard(self)
    def _close(self):
        require(not self._closed);self._closed=True;self._expire();failed=False
        owned,self._owned=self._owned,[]
        for fd in reversed(owned):
            try:
                result=self._backend.close(fd)
                require(result is None,'company_source_guard_close_result')
            except BaseException:
                UNRELEASED_HANDLES.append((self._backend,fd));failed=True
        require(not failed,'company_source_guard_close_unknown')


def require_live_company_source(value):
    require(type(value) is HeldCompanySource)
    try:
        require(value in _ISSUED_GUARDS and value.active and not UNRELEASED_HANDLES)
        value._check()
        require(value in _ISSUED_GUARDS and value.active and not UNRELEASED_HANDLES)
    except BaseException:
        value._expire();raise
    return value


def require_company_source_guard(value,*,verifier_module,held):
    """Match original issued identities before rechecking any physical byte.

    The independently trusted caller supplies the original verifier module and
    original genuine source. This does not prove storage or loader authority.
    """
    require(type(value) is HeldCompanySource)
    try:
        require(value in _ISSUED_GUARDS and value.active and not UNRELEASED_HANDLES
            and value._verifier is verifier_module and value._source is held)
        return require_live_company_source(value)
    except BaseException:
        value._expire();raise


@contextmanager
def hold_authenticated_company_source(held,*,verifier_module,source_root,expected_device,
                                      backend_module,backend,clock=None):
    """Hold all physical source bytes; outer storage/prior-stage trust is required.

    The explicitly trusted readonly backend uses nofollow/openat and CLOEXEC,
    full-nine closed dict metadata, pread and bounded names(fd,limit). Its exact
    ReadOnlySourceBackend type must be supplied. No default/native adapter exists.
    Caller-owned verifier context remains live through this nested guard and
    remains the caller's closing obligation. Existing byte aliases are data only.
    Sibling journal bytes and prior-stage outcomes remain outer responsibilities;
    this guard verifies their fixed names only, never journal-based authority.
    """
    require(not UNRELEASED_HANDLES)
    live_source(verifier_module,held)
    require(type(expected_device) is int and 0<=expected_device<2**64)
    require(type(backend) is getattr(backend_module,'ReadOnlySourceBackend',None)
        and all(callable(getattr(backend,name,None)) for name in ('open','lstat','fstat','inheritable','pread','names','close')))
    metadata=dict(held.metadata);files=dict(held.files);modes=dict(held.git_modes);configs=dict(held.configs)
    release_sha=metadata.get('releaseSha256')
    require(type(release_sha) is str and re.fullmatch('[a-f0-9]{64}',release_sha)
        and sha(held.provenance['release.json'])==release_sha)
    root=root_path(source_root,release_sha)
    plan=source_plan(files,modes,configs['platform-sources.json'])
    header=plan['header']
    require(all(metadata.get(name)==header[name] for name in ('sourceRevision','sourceTree','fileCount','totalBytes'))
        and metadata.get('platformManifestSha256')==sha(configs['platform-sources.json'])
        and metadata.get('archiveSha256')==header['archive']['sha256']
        and type(metadata.get('archiveBytes')) is int and metadata['archiveBytes']==header['archive']['bytes'])
    require(len(root.parts)+len(plan['directories'])+len(files)<=MAX_HELD)
    logical_clock=clock or time.monotonic;require(callable(logical_clock))
    values=dict(status='COMPLETE_PHYSICAL_COMPANY_SOURCE_BYTES_HELD',releaseSha256=release_sha,
        sourceRevision=header['sourceRevision'],sourceTree=header['sourceTree'],fileCount=len(files),
        totalBytes=plan['totalBytes'],sourceRoot=str(root),expectedDevice=expected_device,
        encryptionProven=False,priorStagesAuthorized=False,nativeCapacityQualified=False,
        operationalExecutionAuthorized=False,installerActivated=False,productionAuthorized=False)
    guard=HeldCompanySource(verifier_module,held,backend,logical_clock,root,expected_device,plan,values)
    try:
        guard._capture();guard._check();_ISSUED_GUARDS.add(guard)
        try:
            yield guard
        finally:
            try:require_live_company_source(guard)
            finally:guard._expire()
    finally:
        guard._close()
