"""Trusted quota boundaries; no pending operation is automatically replayed.

Native Linux/XFS behavior needs company qualification. Local tests of this module
do not qualify quota enforcement, power loss, or an installed host service.
"""
from __future__ import annotations
import hmac,importlib.util,json,os,re,signal,stat,subprocess,threading,time,uuid
from pathlib import Path

if '__company_captured_dependencies__' in globals():
    from types import MappingProxyType, ModuleType
    _captured_dependencies = __company_captured_dependencies__
    if type(_captured_dependencies) is not MappingProxyType or set(_captured_dependencies) != {'scripts/quota_allocation.py'}:
        raise ValueError('company-captured-dependencies-unavailable')
    if any(type(_captured_dependencies[key]) is not ModuleType for key in _captured_dependencies):
        raise ValueError('company-captured-dependencies-unavailable')
    _allocation = _captured_dependencies['scripts/quota_allocation.py']
else:
    _allocation_spec=importlib.util.spec_from_file_location('quota_runtime_allocation',Path(__file__).resolve().with_name('quota_allocation.py'))
    _allocation=importlib.util.module_from_spec(_allocation_spec);_allocation_spec.loader.exec_module(_allocation)

def checkpoint_gate(data):return _allocation.C.Gate(data)
def allocation_store(data):return _allocation.Allocation(data)

NAME=re.compile(r'[a-z][a-z0-9_-]{0,31}')
MAX_STATE=4*1024**2
COMMAND_SECONDS=10
COMMAND_BYTES=32768
INODE_HARD=100000

class QuotaUnavailable(ValueError):pass

def require(condition):
    if not condition:raise QuotaUnavailable('Storage quota could not be independently verified')

def decode(raw,maximum=MAX_STATE):
    require(type(raw) is bytes and 0<len(raw)<=maximum)
    def pairs(items):
        value={}
        for key,item in items:require(key not in value);value[key]=item
        return value
    def nonfinite(_):raise QuotaUnavailable('Invalid quota state')
    return json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pairs,parse_constant=nonfinite)

def validate_request(value):
    require(type(value) is dict and set(value)=={'appId','name','sizeMb'})
    require(type(value['appId']) is str and str(uuid.UUID(value['appId']))==value['appId'])
    require(type(value['name']) is str and NAME.fullmatch(value['name']) is not None)
    require(type(value['sizeMb']) is int and 1<=value['sizeMb']<=32768)
    return dict(value)

def validate_state(value):
    require(type(value) is dict and set(value)=={'nextProjectId','projects'})
    require(type(value['nextProjectId']) is int and 10000<=value['nextProjectId']<2**31)
    require(type(value['projects']) is dict and len(value['projects'])<=10000)
    seen=set()
    for key,item in value['projects'].items():
        require(type(key) is str and key.count('/')==1)
        app,name=key.split('/')
        require(type(item) is dict and set(item)=={'projectId','sizeMb','status'})
        validate_request(dict(appId=app,name=name,sizeMb=item['sizeMb']))
        require(type(item['projectId']) is int and 10000<=item['projectId']<value['nextProjectId'] and item['projectId'] not in seen)
        require(type(item['status']) is str and item['status'] in ('pending','active'))
        seen.add(item['projectId'])
    return value

def identity(s):
    return tuple(getattr(s,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def protected_directory(path):
    require(path.is_absolute() and path.resolve(strict=True)==path)
    for parent in (path,*path.parents):
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
    return path.lstat()

def read_protected(path,maximum=MAX_STATE,mode=0o600):
    protected_directory(path.parent)
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==mode and before.st_size<=maximum)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as handle:
        require(identity(os.fstat(handle.fileno()))==identity(before))
        raw=handle.read(maximum+1)
        require(identity(os.fstat(handle.fileno()))==identity(before))
    require(len(raw)==before.st_size and identity(path.lstat())==identity(before))
    return raw

def load_state(path):
    protected_directory(path.parent)
    require(os.path.lexists(path)) # Only explicit fresh initialization may create it.
    return validate_state(decode(read_protected(path)))

def save_state(path,value):
    """Random exclusive sibling, exact old identity, file and parent fsync.

    Failure retains the private temporary evidence. Callers must not dispatch
    quota writes if the pending commit cannot be confirmed.
    """
    validate_state(value);protected_directory(path.parent)
    previous=None
    if os.path.lexists(path):
        read_protected(path);previous=identity(path.lstat())
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    require(len(raw)<=MAX_STATE)
    temporary=path.parent/(path.name+'.'+uuid.uuid4().hex+'.pending')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as handle:
        require(os.fstat(handle.fileno()).st_nlink==1)
        handle.write(raw);handle.flush();os.fsync(handle.fileno())
    require((identity(path.lstat()) if os.path.lexists(path) else None)==previous)
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    require(read_protected(path)==raw)

_COMMAND_LOCK=threading.Lock()
_COMMAND_UNCERTAIN=None

def output(args,*,seconds=COMMAND_SECONDS,maximum=COMMAND_BYTES):
    """Trusted sole-reaper context; retain the leader until group cleanup ends.

    The company helper may have request threads, but every command uses this
    lock and no other code reaps children. POSIX needs default SIGCHLD plus
    pidfd/P_PIDFD. Missing pidfd creation permits cleanup only, never success.
    Unknown cleanup latches admission closed; no operation is silently replayed.
    """
    global _COMMAND_UNCERTAIN
    require(type(args) is list and bool(args) and all(type(item) is str for item in args))
    require(type(seconds) in (int,float) and 0<seconds<=10 and type(maximum) is int and 0<maximum<=COMMAND_BYTES)
    end=time.monotonic()+seconds
    process=None;reader=None;pidfd=None;fd_identity=None;fallback=False;reaping=False;reaped=False;group_clean=False
    capture=bytearray();overflow=threading.Event();failure=threading.Event();locked=False;uncertain=False
    posix=os.name=='posix'
    def child_status(info):
        require(info is not None and type(info.si_pid) is int and info.si_pid==process.pid)
        require(type(info.si_code) is int and type(info.si_status) is int)
        if info.si_code==os.CLD_EXITED:
            require(0<=info.si_status<=255);return info.si_status
        require(info.si_code in (os.CLD_KILLED,os.CLD_DUMPED) and 0<info.si_status<signal.NSIG)
        return -info.si_status
    def ownership():
        require(process is not None and type(process.pid) is int and process.pid>0 and not reaping and not reaped and process.returncode is None)
        require(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL)
        if pidfd is not None:
            info=os.fstat(pidfd)
            require((info.st_dev,info.st_ino,info.st_mode)==fd_identity and not os.get_inheritable(pidfd))
            kind,identifier=os.P_PIDFD,pidfd
        else:
            require(fallback);kind,identifier=os.P_PID,process.pid
        info=os.waitid(kind,identifier,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        if info is not None:child_status(info)
        return info
    def reap(deadline):
        nonlocal reaping,reaped
        if not posix:
            process.wait(timeout=max(0,deadline-time.monotonic()));reaped=True;return
        info=ownership() # A direct-child lease is still present before the first reap.
        expected=child_status(info) if info is not None else None
        kind,identifier=(os.P_PIDFD,pidfd) if pidfd is not None else (os.P_PID,process.pid)
        reaping=True # No subsequent numeric group signal, including on error.
        while True:
            info=os.waitid(kind,identifier,os.WEXITED|os.WNOHANG)
            if info is not None:
                code=child_status(info)
                require(expected is None or expected==code)
                process.returncode=code;reaped=True;return
            require(time.monotonic()<deadline);time.sleep(0.01)
    def stop():
        if process is None:return
        if posix:
            ownership() # WNOWAIT keeps this owned leader from releasing its group ID.
            require(os.getpgid(process.pid)==process.pid)
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass # Group already absent; still reap the owned leader.
        elif process.returncode is None:process.kill()
    def group_absent(deadline):
        if not posix:return
        # After reaping, signal 0 only observes. A possibly reused group is
        # never terminated; continued presence prevents confirmation.
        while True:
            try:os.killpg(process.pid,0)
            except ProcessLookupError:return
            require(time.monotonic()<deadline);time.sleep(0.01)
    try:
        require(_COMMAND_LOCK.acquire(timeout=max(0,end-time.monotonic())));locked=True
        require(_COMMAND_UNCERTAIN is None and time.monotonic()<end)
        if posix:
            require(all(hasattr(os,name) for name in ('pidfd_open','P_PIDFD','P_PID','waitid','WEXITED','WNOHANG','WNOWAIT','CLD_EXITED','CLD_KILLED','CLD_DUMPED','getpgid')))
            require(all(callable(getattr(os,name)) for name in ('pidfd_open','waitid','getpgid')) and signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL)
        process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/usr/sbin:/bin:/sbin','LANG':'C','LC_ALL':'C'},start_new_session=True,close_fds=True)
        if posix:
            try:pidfd=os.pidfd_open(process.pid,0)
            except OSError:
                fallback=True;raise
            require(type(pidfd) is int and pidfd>=0)
            info=os.fstat(pidfd);fd_identity=(info.st_dev,info.st_ino,info.st_mode)
            ownership()
        def pump():
            try:
                while True:
                    block=process.stdout.read(4096)
                    if not block:return
                    if len(capture)+len(block)>maximum:overflow.set();return
                    capture.extend(block)
            except BaseException:failure.set()
        reader=threading.Thread(target=pump,daemon=True);reader.start()
        if posix:
            info=ownership()
            while info is None and not overflow.is_set() and not failure.is_set() and time.monotonic()<end:
                time.sleep(0.01);info=ownership()
            require(info is not None and child_status(info)==0)
        else:
            while process.poll() is None and not overflow.is_set() and not failure.is_set() and time.monotonic()<end:time.sleep(0.01)
            require(process.returncode==0)
        reader.join(max(0,end-time.monotonic()))
        require(not reader.is_alive() and not overflow.is_set() and not failure.is_set())
        result=bytes(capture).decode('ascii','strict') # Decode while POSIX group cleanup remains owned.
        if posix:stop() # End remaining trusted-command group members before releasing the leader.
        reap(end)
        group_absent(end);group_clean=True
        return result
    except BaseException:
        if process is not None:
            deadline=time.monotonic()+5
            if not reaped and not reaping:
                try:stop()
                except BaseException:uncertain=True
            if not reaped:
                try:reap(deadline)
                except BaseException:uncertain=True
            if reaped and not group_clean:
                try:group_absent(deadline);group_clean=True
                except BaseException:uncertain=True
            if reader is not None:
                try:
                    reader.join(max(0,deadline-time.monotonic()))
                    if reader.is_alive():uncertain=True
                except BaseException:uncertain=True
            if not reaped:uncertain=True
        raise QuotaUnavailable('Quota command exit is uncertain' if uncertain else 'Quota command is unavailable') from None
    finally:
        if pidfd is not None:
            try:
                info=os.fstat(pidfd)
                require(fd_identity is not None and (info.st_dev,info.st_ino,info.st_mode)==fd_identity)
                os.close(pidfd)
            except BaseException:uncertain=True
        if process is not None and process.stdout is not None:
            try:
                if reader is None or not reader.is_alive():process.stdout.close()
                else:uncertain=True
            except BaseException:uncertain=True
        if uncertain:
            # Keep Popen out of its destructor's numeric waitpid cleanup.
            _COMMAND_UNCERTAIN=(process,reader,pidfd)
        if locked:
            try:_COMMAND_LOCK.release()
            except BaseException:
                uncertain=True;_COMMAND_UNCERTAIN=(process,reader,pidfd)
        if uncertain:raise QuotaUnavailable('Quota command exit is uncertain') from None

def mount_proof(data,command=output):
    protected_directory(data)
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(data)) is not None)
    marker=data/'.autosoft-encrypted';read_protected(marker,1024)
    mapper=Path('/dev/mapper/autosoft-data')
    require(stat.S_ISBLK(mapper.stat().st_mode) and data.stat().st_dev==mapper.stat().st_rdev)
    value=command(['/usr/bin/findmnt','-n','-o','SOURCE,FSTYPE,OPTIONS','--target',str(data)]).strip().split()
    require(len(value)==3 and Path(value[0]).resolve(strict=True)==mapper.resolve(strict=True) and value[1]=='xfs')
    options=set(value[2].split(','));require('rw' in options and bool(options&{'prjquota','pquota'}))
    rows=command(['/usr/sbin/xfs_quota','-x','-c','state -p',str(data)]).splitlines()
    require(len(rows)<=32 and sum('quota state on ' in line for line in rows)==1 and rows.count('Project quota state on '+str(data)+' ('+value[0]+')')==1)
    require(sum(line.strip()=='Accounting: ON' for line in rows)==1 and sum(line.strip()=='Enforcement: ON' for line in rows)==1 and not any('OFF' in row for row in rows))
    return value[0]

def parse_inode_stat(text,project,flags):
    projects=[];observed_flags=[]
    for row in text.splitlines():
        if row.startswith('fsxattr.projid = '):
            match=re.fullmatch(r'fsxattr[.]projid = ([0-9]{1,10})',row)
            require(match is not None);projects.append(int(match[1]))
        if row.startswith('fsxattr.xflags = '):
            match=re.fullmatch(r'fsxattr[.]xflags = 0x([a-f0-9]{1,8}) \[[A-Za-z_, -]*\]',row)
            require(match is not None);observed_flags.append(int(match[1],16))
    require(projects==[project] and observed_flags==[flags])

def parse_quota_dump(text,record,source):
    rows=[row.strip() for row in text.splitlines() if row.strip()]
    require(len(rows)==2 and rows[0]=='fs = '+source)
    values=rows[1].split();require(len(values)==5 and all(re.fullmatch('[0-9]{1,20}',item) for item in values))
    require([int(item) for item in values]==[record['projectId'],0,record['sizeMb']*2048,0,INODE_HARD])

def native_limits(data,path,record,source,command=output):
    """Fixed read-only xfs_io stat and numeric GETQUOTA dump, no quota-sync."""
    before=path.lstat();require(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode) and before.st_dev==data.stat().st_dev and before.st_uid==before.st_gid and before.st_uid in (0,10001) and stat.S_IMODE(before.st_mode)==0o700)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        require(identity(os.fstat(fd))==identity(before))
        # FS_IOC_FSGETXATTR is supported only by the declared Linux amd64 target.
        import fcntl,struct,sys
        require(os.name=='posix' and os.uname().machine=='x86_64' and sys.byteorder=='little')
        raw=fcntl.ioctl(fd,0x801c581f,bytes(28))
        flags,extent,extents,project,cow,padding=struct.unpack('<IIIII8s',raw)
        require(project==record['projectId'] and bool(flags&0x200) and padding==bytes(8))
        text=command(['/usr/sbin/xfs_io','-r','-c','stat',str(path)])
        parse_inode_stat(text,project,flags)
        parse_quota_dump(command(['/usr/sbin/xfs_quota','-x','-c',f'dump -p -L {project} -U {project}',str(data)]),record,source)
        require(identity(path.lstat())==identity(before) and identity(os.fstat(fd))==identity(before))
    finally:os.close(fd)

def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def storage_owner(path):
    info=path.lstat();require(info.st_uid==info.st_gid==10001)

def initialize_allocation(data,installation_id,*,command=output,read_state=load_state,write_state=save_state,mount=mount_proof,gate_factory=None,allocation_factory=None):
    """Explicit company setup only; Gate initialization and installer wiring are separate.

    Validate placement first. Existing allocations/storage and partial setup are
    never adopted or reset. The admitted initializer retains unknown effects on
    errors, including a lost completion acknowledgement.
    """
    source=mount(data,command)
    require(type(installation_id) is str and str(uuid.UUID(installation_id))==installation_id)
    lease=(gate_factory or checkpoint_gate)(data).admit(_allocation.C.digest(dict(kind='quota-allocation-initialize',installationId=installation_id)))
    try:
        lease.mark_possible_effect()
        store=(allocation_factory or allocation_store)(data)
        store.initialize(installation_id,read_state=read_state,write_state=write_state)
        with store.acquire() as allocation:
            require(allocation.read_state(read_state)==_allocation.EMPTY_STATE and mount(data,command)==source)
            lease.complete(_allocation.C.digest(dict(kind='confirmed-fresh-quota-allocation',source=source,state=_allocation.EMPTY_STATE)))
    finally:lease.release()

def provision(data,value,*,command=output,read_state=load_state,write_state=save_state,limits=native_limits,mount=mount_proof,sync=sync_directory,gate_factory=None,allocation_factory=None):
    value=validate_request(value);source=mount(data,command)
    lease=(gate_factory or checkpoint_gate)(data).admit(_allocation.C.digest(dict(kind='quota-provision',request=value)))
    effect_attempted=False;completion_attempted=False
    try:
        with (allocation_factory or allocation_store)(data).acquire() as allocation:
            state_file=data/'quota/projects.json';state=validate_state(allocation.read_state(read_state))
            key=value['appId']+'/'+value['name'];record=state['projects'].get(key)
            root=data/'runtime/storage';protected_directory(root)
            parent=root/value['appId'];path=parent/value['name']
            if record:
                require(record['sizeMb']==value['sizeMb'] and record['status']=='active')
                protected_directory(parent);limits(data,path,record,source,command)
                storage_owner(path)
                # Business state is read-only; the admitted intent still needs an outcome.
            else:
                require(len(state['projects'])<10000 and state['nextProjectId']<2**31-1)
                require(not os.path.lexists(path))
                if os.path.lexists(parent):protected_directory(parent)
                project=state['nextProjectId'];state['nextProjectId']+=1
                record={'projectId':project,'sizeMb':value['sizeMb'],'status':'pending'}
                state['projects'][key]=record
                effect_attempted=True # Set before marker acknowledgement, never assume it failed to persist.
                lease.mark_possible_effect()
                allocation.commit(state,read_state=read_state,write_state=write_state)
                # Durable pending allocation and admission fence precede all business writes.
                if not os.path.lexists(parent):
                    parent.mkdir(mode=0o700);os.chmod(parent,0o755)
                protected_directory(parent);require(stat.S_IMODE(parent.lstat().st_mode)==0o755);path.mkdir(mode=0o700)
                command(['/usr/sbin/xfs_quota','-x','-c',f'project -s -p {path} {project}',str(data)])
                command(['/usr/sbin/xfs_quota','-x','-c',f'limit -p bsoft=0 bhard={value["sizeMb"]}m isoft=0 ihard={INODE_HARD} {project}',str(data)])
                limits(data,path,record,source,command)
                os.chown(path,10001,10001)
                limits(data,path,record,source,command)
                sync(path);sync(parent);sync(root)
                record['status']='active';allocation.commit(state,read_state=read_state,write_state=write_state)
            require(mount(data,command)==source)
            require(validate_state(allocation.read_state(read_state))==state and record['status']=='active')
            limits(data,path,record,source,command) # Independent final path/size/ownership/quota readback.
            storage_owner(path)
            require(validate_state(allocation.read_state(read_state))==state)
            result={'hostPath':str(path),'containerPath':'/data/runtime/storage/'+key,'projectId':record['projectId'],'sizeMb':record['sizeMb'],'quotaEnforced':True}
            completion_attempted=True
            lease.complete(_allocation.C.digest(dict(scope=_allocation.SCOPE,source=source,resource=result,projectsSha256=_allocation.C.digest(state))))
            return result
    except BaseException:
        if not effect_attempted and not completion_attempted:lease.abort_before_effect()
        raise
    finally:lease.release()

def authenticated(actual,token):
    if type(actual) is not str:return False
    try:return hmac.compare_digest(actual.encode('utf-8'),b'Bearer '+token.encode('ascii'))
    except UnicodeError:return False
