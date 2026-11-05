"""Protected unsigned full-package emission with explicit trusted IO only.

The company caller independently authenticates this executing module, the
original builder, OS/interpreter and readonly adapter before supplying them.
Object identity and supplied pins do not establish their initial code origin.
No signing, CLI, native instance, installation or production authority exists.
The logical time/FD/byte limits are not kernel deadlines or capacity reservation.
"""
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat
import time
from types import MappingProxyType, ModuleType

PACKAGE_PATHS = ('scripts/company_captured_loader.py', 'scripts/verify-release.py',
    'scripts/installer_parent.py', 'scripts/company_source_guard.py',
    'scripts/company_source_guard_backend.py', 'scripts/installer_materialize.py',
    'deploy/installer/company_full_entry.py', 'deploy/installer/company_stored_startup.py',
    'deploy/installer/company_full_plan.py')
OPERATIONAL_PATHS = ('scripts/bootstrap.py', 'scripts/checkpoint_admission.py',
    'scripts/company_platform_store.py', 'scripts/company_source_tree.py',
    'scripts/installation_identity.py', 'scripts/installer_parent.py',
    'scripts/platform_source.py', 'scripts/quota_allocation.py', 'scripts/quota_runtime.py',
    'scripts/registry_manifest.py', 'scripts/resolve-images.py', 'scripts/runtime_layout.py',
    'scripts/runtime_pair_init.py', 'scripts/startup_binding.py', 'scripts/verify-release.py')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
LEAVES = ('intent.json', 'full-package.json', 'verified.json')
CHUNK, RECORD_MAX, PACKAGE_MAX, SOURCE_MAX, MEMBER_MAX = 65536, 16384, 524288, 16*1024**2, 8*1024**2
MAX_HELD, LOGICAL_SECONDS = 192, 180
UNRELEASED = []


class FullPackageEmitUnavailable(ValueError): pass


def require(value, code='full_package_emit_unavailable'):
    if value is not True: raise FullPackageEmitUnavailable(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')


def absolute(value):
    require(type(value) is str and 0<len(value)<=1024 and value.isascii()
        and value.startswith('/') and '//' not in value and '\\' not in value
        and str(PurePosixPath(value))==value and len(PurePosixPath(value).parts)<=24)
    for name in PurePosixPath(value).parts[1:]: component(name)
    return value


def component(value):
    require(type(value) is str and 0<len(value)<=255 and re.fullmatch('[A-Za-z0-9_.-]+',value) is not None
        and value not in ('.','..') and not value.endswith('.'))
    return value


def identity(value):
    require(type(value) is dict and set(value)==set(FIELDS)
        and all(type(value[name]) is int and value[name]>=0 for name in FIELDS))
    return tuple(value[name] for name in FIELDS)


def namespace(module):
    return {name:value for name,value in vars(module).items() if name!='__builtins__'}


class FullPackageBackend:
    """Concrete Linux write adapter borrowing an explicit original readonly IO.

    No native refs are imported or selected. read_backend_module and its exact
    ReadOnlySourceBackend instance provide reviewed bounded getdents enumeration.
    Successfully returned FDs remain owned by this adapter or that readonly
    instance until one confirmed close. Caller must not concurrently use either.
    Unsupported OS/ABI, native writes and capacity remain separately qualified.
    """
    def __init__(self, *, os_module, sys_module, read_backend_module, read_backend):
        require(not UNRELEASED and getattr(os_module,'name',None)=='posix'
            and getattr(sys_module,'platform',None)=='linux' and type(read_backend_module) is ModuleType)
        cls=getattr(read_backend_module,'ReadOnlySourceBackend',None)
        require(type(cls) is type and type(read_backend) is cls)
        calls={name:getattr(os_module,name,None) for name in
            ('open','fstat','get_inheritable','pread','write','fsync','fchmod','mkdir','close','geteuid','getegid')}
        require(all(callable(value) for value in calls.values()) and calls['geteuid']()==0 and calls['getegid']()==0
            and calls['open'] in getattr(os_module,'supports_dir_fd',())
            and calls['mkdir'] in getattr(os_module,'supports_dir_fd',()))
        flags={name:getattr(os_module,name,None) for name in
            ('O_RDWR','O_CREAT','O_EXCL','O_NOFOLLOW','O_CLOEXEC','O_NONBLOCK')}
        require(all(type(value) is int and value>0 for value in flags.values())
            and all(not a&b for i,a in enumerate(flags.values()) for b in list(flags.values())[i+1:]))
        self._os,self._sys,self._calls,self._flags=os_module,sys_module,MappingProxyType(calls),MappingProxyType(flags)
        self._read_module,self._read,self._read_cls=read_backend_module,read_backend,cls
        self._read_globals=namespace(read_backend_module);self._read_methods=dict(vars(cls))
        self._owned,self._attempted,self._unknown=set(),set(),False
        self.require_released()

    def _ready(self):
        require(not UNRELEASED and not self._unknown and type(self._read) is self._read_cls
            and getattr(self._sys,'platform',None)=='linux' and getattr(self._os,'name',None)=='posix'
            and all(getattr(self._os,k,None) is v for k,v in self._calls.items())
            and all(getattr(self._os,k,None)==v for k,v in self._flags.items())
            and self._calls['geteuid']()==0 and self._calls['getegid']()==0)
        current=namespace(self._read_module)
        require(set(current)==set(self._read_globals) and all(current[k] is self._read_globals[k] for k in current)
            and dict(vars(self._read_cls))==self._read_methods
            and not self._read_module.UNRELEASED_RESOURCES)
        self._read_cls._ready(self._read)

    def _unknown_fd(self, fd, reason):
        self._unknown=True;UNRELEASED.append((self,reason,fd,self._calls['close'],self._read))

    def _fd(self, fd):
        require(type(fd) is int and 0<=fd<2**31 and fd not in self._attempted
            and (fd in self._owned or fd in self._read._owned))
        return fd

    def open(self, parent, name, directory):
        self._ready();return self._read_cls.open(self._read,parent,name,directory)

    def lstat(self, path):
        self._ready();return self._read_cls.lstat(self._read,path)

    def fstat(self, fd):
        self._ready();self._fd(fd)
        if fd not in self._owned: return self._read_cls.fstat(self._read,fd)
        observed=self._calls['fstat'](fd);row={name:getattr(observed,name,None) for name in FIELDS}
        identity(row);return row

    def inheritable(self, fd):
        self._ready();value=self._calls['get_inheritable'](self._fd(fd))
        require(type(value) is bool);return value

    def pread(self, fd, size, offset):
        self._ready();self._fd(fd)
        require(type(size) is int and 0<size<=CHUNK and type(offset) is int
            and 0<=offset<=MEMBER_MAX and size<=MEMBER_MAX+1-offset)
        value=self._calls['pread'](fd,size,offset)
        require(type(value) is bytes and len(value)<=size);return value

    def names(self, fd, limit):
        self._ready();return self._read_cls.names(self._read,self._fd(fd),limit)

    def mkdir(self, parent, name, mode):
        self._ready();self._fd(parent);component(name);require(mode==0o700 and type(mode) is int)
        require(self._calls['mkdir'](name,mode,dir_fd=parent) is None)

    def create(self, parent, name, mode):
        self._ready();self._fd(parent);component(name)
        require(type(mode) is int and mode==0o400 and len(self._owned)+len(self._read._owned)<MAX_HELD)
        flags=0
        for value in self._flags.values(): flags|=value
        fd=self._calls['open'](name,flags,mode,dir_fd=parent)
        if not (type(fd) is int and 0<=fd<2**31 and fd not in self._owned
                and fd not in self._read._owned and fd not in self._attempted):
            self._unknown_fd(fd,'create-return-unknown');raise FullPackageEmitUnavailable('full_package_create_unknown')
        self._owned.add(fd)
        try:require(self._calls['get_inheritable'](fd) is False)
        except BaseException:
            self.close(fd);raise
        return fd

    def write(self, fd, raw):
        self._ready();self._fd(fd)
        require(fd in self._owned and type(raw) is bytes and 0<len(raw)<=CHUNK)
        count=self._calls['write'](fd,raw)
        require(type(count) is int and 0<count<=len(raw));return count

    def sync(self, fd):
        self._ready();require(self._calls['fsync'](self._fd(fd)) is None)

    def chmod(self, fd, mode):
        self._ready();self._fd(fd)
        require(type(mode) is int and mode in (0o400,0o500))
        require(self._calls['fchmod'](fd,mode) is None)

    def close(self, fd):
        # Cleanup remains permitted after sticky unknown, at most once per FD.
        self._fd(fd)
        if fd not in self._owned: return self._read_cls.close(self._read,fd)
        self._attempted.add(fd)
        try:require(self._calls['close'](fd) is None)
        except BaseException:
            self._unknown_fd(fd,'write-fd-close-unknown');raise
        self._owned.remove(fd);self._attempted.remove(fd)

    def require_released(self):
        self._ready();require(not self._owned and not self._attempted)
        require(self._read_cls.require_released(self._read) is self._read)
        return self


def captured_release(backend, owned):
    """Capture concrete ownership and raw releases before any output effects.

    Unwind never resolves backend methods, readonly helpers or current OS refs.
    Exact bounded plain registries establish ownership; replacement, overlap or
    an earlier attempted close retains uncertainty rather than retrying. This
    is not isolation from concurrent trusted-interpreter mutation.
    """
    write_state=vars(backend);read=write_state['_read'];read_state=vars(read)
    write_owned,write_attempted=write_state['_owned'],write_state['_attempted']
    read_owned,read_attempted=read_state['_owned'],read_state['_close_attempted']
    cap=MAX_HELD;error_type=FullPackageEmitUnavailable;unknown=UNRELEASED
    read_module=write_state['_read_module'];read_unknown=vars(read_module)['UNRELEASED_RESOURCES']
    write_close=write_state['_calls']['close'];read_close=read_state['_calls']['close']
    require(type(owned) is list and not owned and type(unknown) is list and not unknown
        and type(read_unknown) is list and not read_unknown and callable(write_close) and callable(read_close)
        and all(type(registry) is set and not registry for registry in
            (write_owned,write_attempted,read_owned,read_attempted)))
    used=False

    def release():
        nonlocal used
        if used:raise error_type('full_package_release_already_attempted')
        used=True;errors=[]
        def retain(reason, value):
            write_state['_unknown']=True
            record=(backend,reason,value,write_close,read,read_close)
            unknown.append(record);errors.append(record)
        def bounded(registry):
            if type(registry) is not set or len(registry)>cap:return None
            if not all(type(fd) is int and 0<=fd<2**31 for fd in registry):return None
            return set.copy(registry)
        originals=(write_owned,write_attempted,read_owned,read_attempted)
        current=(write_state.get('_owned'),write_state.get('_attempted'),
            read_state.get('_owned'),read_state.get('_close_attempted'))
        snapshots=tuple(bounded(value) for value in originals)
        current_snapshots=tuple(bounded(value) for value in current)
        same=tuple(a is b for a,b in zip(originals,current))
        if (object.__getattribute__(backend,'__dict__') is not write_state
                or object.__getattribute__(read,'__dict__') is not read_state):
            retain('instance-state-replaced',(write_state,read_state));snapshots=(None,)*4
        for index,(original,observed) in enumerate(zip(originals,current)):
            if not same[index] or snapshots[index] is None or current_snapshots[index] is None:
                retain('ownership-registry-unknown',(index,original,observed))
        if type(owned) is not list or len(owned)>cap or not all(type(fd) is int and 0<=fd<2**31 for fd in owned):
            retain('io-ownership-unknown',owned);io_fds=None
        else:io_fds=set(owned)
        if any(value is None for value in (*snapshots,*current_snapshots)) or io_fds is None:
            retain('bounded-ownership-unavailable',originals)
        else:
            wo,wa,ro,ra=snapshots;cwo,cwa,cro,cra=current_snapshots
            candidates=wo|ro|io_fds
            if len(candidates)>cap:
                retain('ownership-count-exceeded',(originals,owned))
            else:
                for fd in sorted(candidates,reverse=True):
                    writer=fd in wo;reader=fd in ro
                    if writer==reader or fd in wa or fd in ra or fd in cwa or fd in cra:
                        retain('fd-ownership-overlap-or-attempted',fd);continue
                    index=0 if writer else 2;other=cro if writer else cwo
                    if not same[index] or not same[index+1] or fd in other:
                        retain('fd-registry-replaced-or-overlap',fd);continue
                    registry,attempted,call=(write_owned,write_attempted,write_close) if writer else (read_owned,read_attempted,read_close)
                    set.add(attempted,fd)
                    try:
                        if call(fd) is not None:raise error_type('raw_close_not_confirmed')
                    except BaseException as error:
                        if reader:read_state['_unknown']=True
                        retain('raw-fd-close-unknown',(fd,call,error));continue
                    set.remove(registry,fd);set.remove(attempted,fd)
                    if reader and read_state.get('_enumeration')==fd:read_state['_enumeration']=None
                    if fd in owned:list.remove(owned,fd)
        # Inspect only captured plain state; never call a live release helper.
        if (any(write_state.get(name) is not expected for name,expected in
                (('_owned',write_owned),('_attempted',write_attempted)))
                or any(read_state.get(name) is not expected for name,expected in
                    (('_owned',read_owned),('_close_attempted',read_attempted)))
                or any(type(value) is not set or len(value)!=0 for value in originals)
                or read_state.get('_enumeration') is not None or owned
                or write_state.get('_unknown') is not False or read_state.get('_unknown') is not False
                or unknown or read_unknown):
            retain('captured-release-not-known',(originals,owned,read_state.get('_enumeration'),read_unknown))
        if errors:raise error_type('full_package_owned_release_unknown')
    return release


class FullPackageIO:
    def __init__(self, backend_module, backend, builder, clock):
        require(type(backend_module) is ModuleType and backend_module.FullPackageBackend is FullPackageBackend
            and type(backend) is FullPackageBackend and type(builder) is ModuleType and not UNRELEASED)
        self.module,self.backend,self.builder=backend_module,backend,builder
        self.methods=dict(vars(FullPackageBackend));self.builder_globals=namespace(builder)
        self.clock=clock;require(callable(clock))
        start=clock();require(type(start) in (int,float) and math.isfinite(start))
        self.started=start;self.deadline=start+LOGICAL_SECONDS;self.owned=[];self.rows={};self.active=True
        self.check_trust();FullPackageBackend.require_released(backend)
        self._release_owned=captured_release(backend,self.owned)

    def check_trust(self):
        now=self.clock()
        require(self.active and not UNRELEASED and type(now) in (int,float) and math.isfinite(now) and self.started<=now<=self.deadline
            and self.module.FullPackageBackend is FullPackageBackend and type(self.backend) is FullPackageBackend
            and dict(vars(FullPackageBackend))==self.methods)
        current=namespace(self.builder)
        require(set(current)==set(self.builder_globals)
            and all(current[k] is self.builder_globals[k] for k in current) and not self.builder.UNRELEASED)
        FullPackageBackend._ready(self.backend)

    def call(self, name, *args):
        self.check_trust();value=self.methods[name](self.backend,*args);self.check_trust();return value

    def own(self, fd):
        if not (type(fd) is int and 0<=fd<2**31 and fd not in self.owned and len(self.owned)<MAX_HELD):
            UNRELEASED.append((self.backend,'returned-fd-unknown',fd));raise FullPackageEmitUnavailable()
        self.owned.append(fd);require(self.call('inheritable',fd) is False);return fd

    def open_owned(self, name, *args):
        self.check_trust();require(len(self.owned)<MAX_HELD)
        fd=self.methods[name](self.backend,*args)
        # Register a returned handle before post-open trust or metadata checks.
        fd=self.own(fd);self.check_trust();return fd

    def hold(self, path, directory, mode=None):
        self.check_trust();absolute(path)
        if path in self.rows: self.check_one(path);return self.rows[path]
        require(len(self.owned)<MAX_HELD)
        parent=None if path=='/' else self.hold(str(PurePosixPath(path).parent),True)['fd']
        before=self.call('lstat',path);identity(before)
        require(before['st_uid']==before['st_gid']==0 and stat.S_IFMT(before['st_mode'])==(stat.S_IFDIR if directory else stat.S_IFREG)
            and not stat.S_IMODE(before['st_mode'])&0o022
            and (mode is None or stat.S_IMODE(before['st_mode'])==mode)
            and (directory or before['st_nlink']==1))
        fd=self.open_owned('open',parent,'/' if path=='/' else PurePosixPath(path).name,directory)
        require(identity(self.call('fstat',fd))==identity(before)==identity(self.call('lstat',path)))
        row=dict(fd=fd,identity=before,directory=directory,raw=None);self.rows[path]=row;return row

    def check_one(self, path, contents=False):
        row=self.rows[path]
        require(identity(self.call('lstat',path))==identity(row['identity'])==identity(self.call('fstat',row['fd'])))
        if contents and row['raw'] is not None: require(self.read(row,len(row['raw']))==row['raw'])
        require(identity(self.call('lstat',path))==identity(row['identity'])==identity(self.call('fstat',row['fd'])))

    def read(self, row, maximum):
        require(type(maximum) is int and 0<maximum<=MEMBER_MAX)
        raw=bytearray();offset=0
        while offset<=maximum:
            piece=self.call('pread',row['fd'],min(CHUNK,maximum+1-offset),offset)
            if not piece: break
            raw.extend(piece);offset+=len(piece);require(offset<=maximum)
        require(len(raw)==row['identity']['st_size']);return bytes(raw)

    def check(self, contents=True):
        self.check_trust()
        for path in tuple(self.rows):self.check_one(path,contents)

    def names(self, path, maximum):
        self.check_one(path);value=self.call('names',self.rows[path]['fd'],maximum)
        require(type(value) is list and len(value)<=maximum and len(value)==len(set(value)))
        for name in value:component(name)
        self.check_one(path);return sorted(value)

    def transition(self, path, old, *, mode=None, nlink_delta=0):
        # Only this operation's owned directory mutations permit a new snapshot.
        current=self.call('fstat',self.rows[path]['fd']);named=self.call('lstat',path)
        identity(current);require(current==named and all(current[k]==old[k] for k in FIELDS[:5] if k!='st_mode'))
        require(stat.S_IFMT(current['st_mode'])==stat.S_IFDIR
            and current['st_nlink']==old['st_nlink']+nlink_delta
            and stat.S_IMODE(current['st_mode'])==(mode if mode is not None else stat.S_IMODE(old['st_mode'])))
        self.rows[path]['identity']=current

    def put(self, root, name, raw, expected_before):
        require(name in LEAVES and type(raw) is bytes and 0<len(raw)<= (PACKAGE_MAX if name=='full-package.json' else RECORD_MAX))
        self.check();require(self.names(root,4)==sorted(expected_before))
        old=dict(self.rows[root]['identity']);fd=self.open_owned('create',self.rows[root]['fd'],name,0o400)
        path=root+'/'+name;info=self.call('fstat',fd)
        require(identity(info)==identity(self.call('lstat',path)) and info['st_uid']==info['st_gid']==0
            and info['st_nlink']==1 and stat.S_IFMT(info['st_mode'])==stat.S_IFREG and stat.S_IMODE(info['st_mode'])==0o400)
        self.rows[path]=dict(fd=fd,identity=info,directory=False,raw=None)
        offset=0
        while offset<len(raw):offset+=self.call('write',fd,raw[offset:offset+CHUNK])
        self.call('sync',fd);final=self.call('fstat',fd)
        require(final==self.call('lstat',path) and all(final[k]==info[k] for k in FIELDS[:6]) and final['st_size']==len(raw))
        self.rows[path]['identity'],self.rows[path]['raw']=final,raw
        self.transition(root,old);self.call('sync',self.rows[root]['fd'])
        require(self.names(root,4)==sorted([*expected_before,name]));self.check()

    def close(self):
        self.active=False;self._release_owned()


def emit_full_package(source_root, destination, *, builder_module, package_pins,
        operational_catalog, key_fingerprint, backend_module, backend, clock=time.monotonic):
    """Create three exact unsigned leaves; return only after known owned closes.

    A pre-existing protected output parent must be quiet and outside source_root.
    Only its owned child-create metadata transition is recognized; all source
    and common ancestors stay full-nine immutable. Every partial output remains.
    The caller supplies capacity reservation, trusted delivery, signing and any
    native qualification separately. No arbitrary reader callback is accepted.
    """
    source_root=absolute(source_root);destination=absolute(destination)
    require(source_root!='/' and destination!='/' and destination!=source_root
        and not destination.startswith(source_root+'/') and not source_root.startswith(destination+'/'))
    parent=str(PurePosixPath(destination).parent)
    require(parent!='/' and parent!=source_root and not source_root.startswith(parent+'/') and not parent.startswith(source_root+'/'))
    B=builder_module
    require(type(B) is ModuleType and tuple(B.PACKAGE_PATHS)==PACKAGE_PATHS
        and tuple(B.OPERATIONAL_PATHS)==OPERATIONAL_PATHS and B.MAX_PACKAGE_BYTES==PACKAGE_MAX
        and B.MAX_SOURCE_BYTES==262144 and B.MAX_CAPTURE_BYTES==131072 and B.MAX_OPERATIONAL_BYTES==SOURCE_MAX
        and B.MAX_OPERATIONAL_MEMBER==MEMBER_MAX and B.MAX_CATALOG_BYTES==RECORD_MAX)
    pins,catalog,fingerprint=B._inputs(package_pins,operational_catalog,key_fingerprint)
    io=FullPackageIO(backend_module,backend,B,clock);release=io._release_owned;result=None
    try:
        captures={}
        for name in sorted(set(PACKAGE_PATHS)|set(OPERATIONAL_PATHS)):
            row=io.hold(source_root+'/'+name,False,0o644)
            expected=pins[name] if name in pins else catalog[name]
            raw=io.read(row,expected['bytes']);require(len(raw)==expected['bytes'] and sha(raw)==expected['sha256'])
            row['raw']=raw;captures[name]=raw
        io.check()
        # This reader accesses only authenticated, held captures; no candidate IO.
        def captured_reader(path, maximum):
            name=path.relative_to(B.Path(source_root)).as_posix()
            require(name in captures and len(captures[name])<=maximum);io.check();return captures[name]
        raw=B.assemble(source_root,fingerprint,package_pins=pins,operational_catalog=catalog,reader=captured_reader)
        B.validate_package(raw,package_pins=pins,operational_catalog=catalog,fingerprint=fingerprint);io.check()
        intent=canonical(dict(schemaVersion=1,scope='UNSIGNED_FULL_PACKAGE_EMISSION_ONLY',
            keyFingerprint=fingerprint,packageSha256=sha(raw),packageBytes=len(raw),
            packagePins=pins,operationalCatalog=catalog))
        verified=canonical(dict(schemaVersion=1,scope='UNSIGNED_FULL_PACKAGE_EMISSION_ONLY',
            packageSha256=sha(raw),packageBytes=len(raw),keyFingerprint=fingerprint,
            sourceCaptured=True,signatureCreated=False,installationAuthorized=False))
        require(len(intent)<=RECORD_MAX and len(verified)<=RECORD_MAX)
        io.hold(parent,True);prior=io.names(parent,65);require(len(prior)<=64 and PurePosixPath(destination).name not in prior)
        old=dict(io.rows[parent]['identity'])
        io.call('mkdir',io.rows[parent]['fd'],PurePosixPath(destination).name,0o700)
        io.transition(parent,old,nlink_delta=1);require(io.names(parent,65)==sorted([*prior,PurePosixPath(destination).name]))
        io.call('sync',io.rows[parent]['fd']);io.hold(destination,True,0o700);require(io.names(destination,1)==[])
        io.put(destination,'intent.json',intent,[])
        io.put(destination,'full-package.json',raw,['intent.json'])
        io.put(destination,'verified.json',verified,['intent.json','full-package.json'])
        old=dict(io.rows[destination]['identity']);io.check();io.call('chmod',io.rows[destination]['fd'],0o500)
        io.transition(destination,old,mode=0o500);io.call('sync',io.rows[destination]['fd']);io.call('sync',io.rows[parent]['fd'])
        require(io.names(destination,4)==sorted(LEAVES));io.check()
        result=dict(scope='UNSIGNED_FULL_PACKAGE_EMISSION_ONLY',destination=destination,
            files={name:dict(bytes=len(io.rows[destination+'/'+name]['raw']),sha256=sha(io.rows[destination+'/'+name]['raw'])) for name in LEAVES},
            ownedResourcesReleased=True,signatureCreated=False,nativeQualified=False,installationAuthorized=False)
    finally:
        io.active=False;release()
    return result
