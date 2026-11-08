"""Current host containment for private service startup; no host mutation API.

The original source/storage/parent remain outer prerequisites. Observing a
distro systemctl executable detects replacement; it is not vendor security
qualification. Docker is queried only through the company-pinned transport.
"""
from contextlib import ExitStack
import grp
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import select
import selectors
import signal
import stat
import subprocess
import time

UNITS={
    'docker.service':('ActiveState','SubState','LoadState','MainPID','ControlPID','Requires','After','RequiresMountsFor','DropInPaths','ExecStartPre','NeedDaemonReload'),
    'containerd.service':('ActiveState','SubState','LoadState','MainPID','ControlPID','Requires','After','RequiresMountsFor','DropInPaths','ExecStartPre','NeedDaemonReload'),
    'var-log-journal.mount':('ActiveState','SubState','LoadState','Where','What','Options','FragmentPath','NeedDaemonReload'),
    'systemd-journal-flush.service':('LoadState','Requires','After','DropInPaths','NeedDaemonReload'),
}
JOURNAL=b'[Journal]\nStorage=persistent\nMaxRetentionSec=7day\nMaxFileSec=1day\nSystemMaxUse=2G\nSystemKeepFree=1G\nRuntimeMaxUse=64M\nForwardToSyslog=no\n'
JOURNAL_FIELDS={'Storage':'persistent','MaxRetentionSec':'7day','MaxFileSec':'1day','SystemMaxUse':'2G',
                'SystemKeepFree':'1G','RuntimeMaxUse':'64M','ForwardToSyslog':'no'}
JOURNAL_MAIN=('/etc/systemd/journald.conf','/run/systemd/journald.conf','/usr/local/lib/systemd/journald.conf','/usr/lib/systemd/journald.conf')
JOURNAL_DIRS=tuple(path+'.d' for path in JOURNAL_MAIN)
UNKNOWN=[]

def require(value,message='Current host runtime containment is unconfirmed; preserve evidence'):
    if not value:raise ValueError(message)

def identity(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def require_decoder():
    try:import tomllib
    except ModuleNotFoundError:raise ValueError('Private infrastructure containment requires the company-approved Python 3.11+ TOML decoder') from None
    return tomllib

def expected_files(data,root):
    storage=f'[Unit]\nRequiresMountsFor={data}\nRequires=var-log-journal.mount\nAfter=systemd-cryptsetup@autosoft\\x2ddata.service var-log-journal.mount\n[Service]\nExecStartPre=/bin/bash {root}/scripts/storage-guard.sh\n'.encode()
    return {
        '/etc/systemd/system/docker.service.d/autosoft-storage.conf':storage,
        '/etc/systemd/system/containerd.service.d/autosoft-storage.conf':storage,
        '/etc/systemd/system/var-log-journal.mount':f'[Unit]\nDescription=Encrypted persistent journals\nRequiresMountsFor={data}\nBefore=docker.service systemd-journal-flush.service\n[Mount]\nWhat={data}/journal\nWhere=/var/log/journal\nType=none\nOptions=bind,nosuid,nodev\n[Install]\nWantedBy=local-fs.target\n'.encode(),
        '/etc/systemd/journald.conf.d/autosoft.conf':JOURNAL,
        '/etc/systemd/system/systemd-journal-flush.service.d/autosoft.conf':b'[Unit]\nRequires=var-log-journal.mount\nAfter=var-log-journal.mount\n',
    }

def json_object(raw):
    def unique(rows):
        result={}
        for key,value in rows:require(key not in result);result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False))
    require(type(value) is dict);return value

def mount_rows(raw,targets):
    require(type(raw) is bytes and 0<len(raw)<=1024**2 and b'\0' not in raw)
    lines=raw.decode('ascii').splitlines();require(len(lines)<=8192);found={}
    for line in lines:
        fields=line.split();require(len(fields)>=10 and fields.count('-')==1)
        i=fields.index('-');require(i>=6 and len(fields)==i+4)
        target=fields[4]
        if target not in targets:continue
        require(target not in found and fields[0].isdecimal() and fields[1].isdecimal() and re.fullmatch('[0-9]+:[0-9]+',fields[2]))
        found[target]=dict(id=int(fields[0]),device=fields[2],root=fields[3],target=target,
            options=sorted(fields[5].split(',')),filesystem=fields[i+1],source=fields[i+2],superOptions=sorted(fields[i+3].split(',')))
    require(set(found)==set(targets));return found

def unit_value(unit,raw):
    require(unit in UNITS and type(raw) is bytes and len(raw)<=65536)
    rows=[line.split('=',1) for line in raw.decode('utf-8').splitlines()]
    require(len(rows)==len(UNITS[unit]) and all(len(row)==2 for row in rows))
    result=dict(rows);require(set(result)==set(UNITS[unit]) and len(result)==len(rows));return result

def daemon_arguments(unit,raw):
    require(unit in ('docker.service','containerd.service') and type(raw) is bytes and 0<len(raw)<=4096)
    argv=raw.split(b'\0');require(argv[-1:]==[b'']);argv=argv[:-1]
    if unit=='containerd.service':
        require(argv in ([b'/usr/bin/containerd'],[b'/usr/bin/containerd',b'--config',b'/etc/containerd/config.toml']))
    else:
        require(argv in ([b'/usr/bin/dockerd',b'-H',b'fd://',b'--containerd=/run/containerd/containerd.sock'],
            [b'/usr/bin/dockerd',b'--containerd=/run/containerd/containerd.sock']))

def journal_assignments(raw):
    """Conservative bounded policy: extra critical overrides must agree exactly."""
    require(type(raw) is bytes and len(raw)<=65536 and b'\0' not in raw)
    section=None;result={}
    for line in raw.decode('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';')):continue
        require(not line.endswith('\\'),'Unsupported continued journal configuration requires company review')
        if line.startswith('['):require(line.endswith(']'));section=line[1:-1];continue
        require('=' in line)
        name,value=(v.strip() for v in line.split('=',1))
        if section=='Journal' and name in JOURNAL_FIELDS:
            require(value==JOURNAL_FIELDS[name],'Another journal configuration conflicts with encrypted seven-day logging')
            result[name]=value
    return result

def validate(*,data,root,files,directories,mounts,units,daemon,mapper_device,journal_gid,guard_raw):
    require(type(data) is str and data.startswith('/srv/') and type(root) is str and root.startswith(data+'/company/host-releases/'))
    for name,raw in expected_files(data,root).items():require(files[name]==raw)
    require(files[root+'/scripts/storage-guard.sh']==guard_raw and 0<len(guard_raw)<=32768)
    docker=json_object(files['/etc/docker/daemon.json'])
    require(docker.get('data-root')==data+'/docker' and docker.get('log-driver')=='journald'
        and docker.get('containerd','/run/containerd/containerd.sock')=='/run/containerd/containerd.sock')
    containerd=require_decoder().loads(files['/etc/containerd/config.toml'].decode())
    require(containerd.get('root')==data+'/containerd' and containerd.get('state','/run/containerd')=='/run/containerd'
        and containerd.get('imports',[])==[] and containerd.get('grpc',{}).get('address','/run/containerd/containerd.sock')=='/run/containerd/containerd.sock')
    for path,raw in files.items():
        if path in JOURNAL_MAIN or any(path.startswith(d+'/') for d in JOURNAL_DIRS):journal_assignments(raw)
    require(daemon['DockerRootDir']==data+'/docker' and daemon['LoggingDriver']=='journald'
        and 'journald' in daemon['Plugins']['Log'] and type(daemon['ID']) is str and 0<len(daemon['ID'])<=256)
    base=directories[data];journal=directories[data+'/journal'];mounted=directories['/var/log/journal']
    require(base[0]==mapper_device and journal[:2]==mounted[:2] and journal[0]==base[0]
        and journal[2:5]==(stat.S_IFDIR|0o2755,0,journal_gid) and mounted[2:5]==journal[2:5])
    for path in (data+'/docker',data+'/containerd'):
        info=directories[path];require(info[0]==base[0] and stat.S_ISDIR(info[2]) and info[3:5]==(0,0) and not info[2]&0o022)
    actual=mounts[data];log=mounts['/var/log/journal'];device=str(os.major(base[0]))+':'+str(os.minor(base[0]))
    for row in (actual,log):
        require(row['device']==device and row['filesystem']=='xfs' and row['source']=='/dev/mapper/autosoft-data'
            and {'rw','nosuid','nodev'}<=set(row['options']) and 'ro' not in row['options'])
    require(actual['root']=='/' and log['root']=='/journal' and actual['id']!=log['id'])
    require(bool({'prjquota','pquota'}&set(actual['superOptions']+actual['options'])))
    for name,state in units.items():require(state['LoadState']=='loaded' and state['NeedDaemonReload']=='no')
    require(set(units)==set(UNITS))
    for name in ('docker.service','containerd.service'):
        state=units[name]
        require(state['ActiveState']=='active' and state['SubState']=='running' and state['ControlPID']=='0'
            and re.fullmatch('[1-9][0-9]{0,9}',state['MainPID']) is not None and int(state['MainPID'])>1)
        require('var-log-journal.mount' in state['Requires'].split() and {'var-log-journal.mount','systemd-cryptsetup@autosoft\\x2ddata.service'}<=set(state['After'].split())
            and data in state['RequiresMountsFor'].split()
            and '/etc/systemd/system/'+name+'.d/autosoft-storage.conf' in state['DropInPaths'].split())
        pre=state['ExecStartPre'];records=re.findall(r'\{ [^{}]+ \}',pre)
        require(' '.join(records)==pre and len(records)==(2 if name=='containerd.service' else 1))
        commands=[]
        for record in records:
            pairs=[part.strip().split('=',1) for part in record[2:-2].split(' ; ')]
            require(all(len(row)==2 for row in pairs) and len({row[0] for row in pairs})==len(pairs))
            parts=dict(pairs);commands.append((parts.get('path'),parts.get('argv[]'),parts.get('ignore_errors')))
        expected=[('/bin/bash','/bin/bash '+root+'/scripts/storage-guard.sh','no')]
        if name=='containerd.service':expected.insert(0,('/sbin/modprobe','/sbin/modprobe overlay','yes'))
        require(commands==expected)
    state=units['var-log-journal.mount']
    require(state['ActiveState']=='active' and state['SubState']=='mounted' and state['Where']=='/var/log/journal'
        and state['What']==data+'/journal' and {'bind','nosuid','nodev'}<=set(state['Options'].split(','))
        and state['FragmentPath']=='/etc/systemd/system/var-log-journal.mount')
    state=units['systemd-journal-flush.service']
    require('var-log-journal.mount' in state['Requires'].split() and 'var-log-journal.mount' in state['After'].split()
        and '/etc/systemd/system/systemd-journal-flush.service.d/autosoft.conf' in state['DropInPaths'].split())
    return dict(scope='CURRENT_HOST_RUNTIME_CONTAINMENT_ONLY',daemonId=daemon['ID'],
        configurationSha256=sha(canonical({name:sha(raw) for name,raw in sorted(files.items())})),
        storageDirectoriesSha256=sha(canonical({name:list(row[:5]) for name,row in sorted(directories.items())})),
        mountsSha256=sha(canonical(mounts)),unitsSha256=sha(canonical(units)),
        vendorUtilitiesQualified=False,wholeInstallationQualified=False)


class Systemctl:
    """Only four fixed read-only property queries, with held executable bytes."""
    def __init__(self,S,check):self.S=S;self.authority=check;self.stack=ExitStack();self.closed=False;self.failed=False
    def __enter__(self):
        try:
            require(not UNKNOWN)
            self.fd,self.info,self.tool_check=self.stack.enter_context(self.S.held_file('/usr/bin/systemctl',32*1024**2,executable=True))
            digest=hashlib.sha256();offset=0
            while offset<self.info['st_size']:
                raw=os.pread(self.fd,min(65536,self.info['st_size']-offset),offset);require(raw);digest.update(raw);offset+=len(raw)
            self.observed_sha256=digest.hexdigest();self.tool_check();return self
        except BaseException:self.stack.close();raise
    def query(self,unit):
        require(not self.closed and not self.failed and not UNKNOWN and unit in UNITS);self.authority();self.tool_check()
        argv=['/usr/bin/systemctl','show',*['--property='+n for n in UNITS[unit]],'--',unit]
        try:return unit_value(unit,self._execute(argv,8))
        except BaseException:self.failed=True;raise
    def _execute(self,argv,timeout):
        """Internal bounded transport; fixed caller methods select all commands."""
        require(not self.closed and not self.failed and not UNKNOWN and type(argv) is list
            and argv[0]=='/usr/bin/systemctl' and type(timeout) is int and 1<=timeout<=100)
        self.authority();self.tool_check()
        deadline=time.monotonic()+timeout;buffers=[bytearray(),bytearray()];proc=None;selector=None;attempted=False
        try:
            attempted=True
            proc=subprocess.Popen(argv,executable='/proc/self/fd/'+str(self.fd),stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=(self.fd,),start_new_session=True,
                cwd='/',env=dict(PATH='/usr/bin:/bin',HOME='/',LANG='C',LC_ALL='C',TZ='UTC'),bufsize=0)
            selector=selectors.DefaultSelector()
            for stream,buffer in zip((proc.stdout,proc.stderr),buffers):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,buffer)
            while selector.get_map():
                require(time.monotonic()<deadline);self.authority();self.tool_check()
                for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
                    raw=os.read(key.fileobj.fileno(),16384)
                    if raw:key.data.extend(raw);require(sum(map(len,buffers))<=65536)
                    else:selector.unregister(key.fileobj);key.fileobj.close()
            while True:
                observed=os.waitid(os.P_PID,proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if observed is not None:break
                require(time.monotonic()<deadline);self.authority();self.tool_check();time.sleep(0.01)
            require(observed.si_pid==proc.pid and observed.si_code==os.CLD_EXITED and observed.si_status==0 and time.monotonic()<deadline)
            self.authority();self.tool_check();return bytes(buffers[0])
        except BaseException:self.failed=True;raise
        finally:
            errors=[];reaped=False;group_absent=False
            if proc is not None:
                # The leader is still waitable here. Never signal a reused PID
                # after reaping; only signal0 observes remaining group members.
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except BaseException as error:errors.append(('group-kill',error))
                try:proc.wait(timeout=2);reaped=True
                except BaseException as error:errors.append(('leader-reap',error))
                if reaped:
                    try:
                        end=time.monotonic()+2
                        while True:
                            try:os.killpg(proc.pid,0)
                            except ProcessLookupError:group_absent=True;break
                            require(time.monotonic()<end);time.sleep(0.01)
                    except BaseException as error:errors.append(('group-absence',error))
            elif attempted:errors.append(('process-construction-unknown',None))
            if selector is not None:
                try:selector.close()
                except BaseException as error:errors.append(('selector-close',error))
            if proc is not None:
                for stream in (proc.stdout,proc.stderr):
                    try:
                        if not stream.closed:stream.close()
                        require(stream.closed)
                    except BaseException as error:errors.append(('pipe-close',stream,error))
            if errors or proc is not None and not (reaped and group_absent):
                UNKNOWN.append((self,proc,selector,tuple(errors)));self.failed=True
                raise ValueError('Host query resource release is unknown; preserve the failed stage') from None
    def __exit__(self,*args):
        self.closed=True
        try:return self.stack.__exit__(*args)
        except BaseException:
            UNKNOWN.append((self,'held-systemctl-close-unknown'));raise


class HostContainment:
    """Hold current configuration and directory identity across service writes."""
    def __init__(self,S,*,data,root,mount_source,guard_raw,check_authority):
        require(mount_source=='/dev/mapper/autosoft-data' and callable(check_authority))
        self.S=S;self.data=data;self.root=root;self.guard=guard_raw;self.authority=check_authority
        self.stack=ExitStack();self.directories={};self.files={};self.checks=[];self.absent=[];self.inventories=[]
        self.processes={};self.result=None;self.closed=False;self.deadline=time.monotonic()+600

    def _directory(self,path,*,inventory=False):
        parts=PurePosixPath(path).parts;require(path==PurePosixPath(path).as_posix() and '..' not in parts and len(parts)<=32)
        rows=[];parent=None
        for name in parts:
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            self.stack.callback(os.close,fd)
            before=identity(os.fstat(fd));require(before[3]==0 and not before[2]&0o022)
            rows.append((parent,name,fd,before[:5]));parent=fd
        def check():
            for parent,name,fd,before in rows:
                require(identity(os.fstat(fd))[:5]==before==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))[:5])
        check();self.checks.append(check)
        if inventory:
            names=sorted(os.listdir(fd));require(len(names)<=64)
            self.inventories.append((fd,names))
        return identity(os.fstat(fd)),fd

    def _file(self,path,maximum=65536):
        fd,info,check=self.stack.enter_context(self.S.held_file(path,maximum))
        raw=os.pread(fd,maximum+1,0);require(len(raw)==info['st_size'])
        self.files[path]=raw;self.checks.append(check)

    @staticmethod
    def _read_kernel(path,maximum):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            raw=bytearray()
            while len(raw)<=maximum:
                part=os.read(fd,min(65536,maximum+1-len(raw)))
                if not part:break
                raw.extend(part)
            require(0<len(raw)<=maximum);return bytes(raw)
        finally:os.close(fd)

    def __enter__(self):
        try:
            self.authority()
            for path in (self.data,self.data+'/docker',self.data+'/containerd',self.data+'/journal','/var/log/journal'):
                self.directories[path],_=self._directory(path)
            names=set(expected_files(self.data,self.root))|{'/etc/docker/daemon.json','/etc/containerd/config.toml',self.root+'/scripts/storage-guard.sh'}
            for path in sorted(names):self._file(path)
            for path in JOURNAL_MAIN:
                if os.path.lexists(path):self._file(path)
                else:self.absent.append(path)
            for path in JOURNAL_DIRS:
                if not os.path.lexists(path):self.absent.append(path);continue
                _,fd=self._directory(path,inventory=True)
                for name in sorted(os.listdir(fd)):
                    require(re.fullmatch('[A-Za-z0-9_.-]{1,128}',name) is not None)
                    if name.endswith('.conf') and path+'/'+name not in self.files:self._file(path+'/'+name)
            self.mapper=identity(os.stat('/dev/mapper/autosoft-data'))
            require(stat.S_ISBLK(self.mapper[2]));self.mapper_device=os.stat('/dev/mapper/autosoft-data').st_rdev
            require(self.mapper_device==self.directories[self.data][0])
            self.journal_gid=grp.getgrnam('systemd-journal').gr_gid
            self.selected_mounts=mount_rows(self._read_kernel('/proc/self/mountinfo',1024**2),{self.data,'/var/log/journal'})
            self.systemctl=self.stack.enter_context(Systemctl(self.S,self.check))
            self.check();return self
        except BaseException:self.closed=True;self.stack.close();raise

    def check(self):
        require(not self.closed and not UNKNOWN and time.monotonic()<self.deadline);self.authority()
        for check in self.checks:check()
        require(all(not os.path.lexists(path) for path in self.absent))
        for fd,names in self.inventories:require(sorted(os.listdir(fd))==names)
        mapper=os.stat('/dev/mapper/autosoft-data')
        require(identity(mapper)[:7]==self.mapper[:7] and mapper.st_rdev==self.mapper_device)
        require(mount_rows(self._read_kernel('/proc/self/mountinfo',1024**2),{self.data,'/var/log/journal'})==self.selected_mounts)
        for pidfd,path,cmdline,executable in self.processes.values():
            poll=select.poll();poll.register(pidfd,select.POLLIN);require(poll.poll(0)==[])
            require(self._read_kernel(path+'/cmdline',4096)==cmdline and os.readlink(path+'/exe')==executable)
            running=os.stat(path+'/exe');installed=os.stat(executable,follow_symlinks=False)
            require((running.st_dev,running.st_ino)==(installed.st_dev,installed.st_ino)
                and stat.S_ISREG(installed.st_mode) and installed.st_uid==installed.st_gid==0 and not installed.st_mode&0o022)

    def _processes(self,units):
        for unit in ('docker.service','containerd.service'):
            pid=int(units[unit]['MainPID']);path='/proc/'+str(pid)
            executable='/usr/bin/dockerd' if unit=='docker.service' else '/usr/bin/containerd'
            raw=self._read_kernel(path+'/cmdline',4096);daemon_arguments(unit,raw)
            require(os.readlink(path+'/exe')==executable)
            if unit in self.processes:require(self.processes[unit][1:]==(path,raw,executable))
            else:
                pidfd=os.pidfd_open(pid,0);self.stack.callback(os.close,pidfd)
                self.processes[unit]=(pidfd,path,raw,executable)
        self.check()

    def verify(self,transport):
        self.check();units={name:self.systemctl.query(name) for name in UNITS}
        self._processes(units)
        result=transport.run('docker',['--host','unix:///run/docker.sock','info','--format','{{json .}}'],timeout=15)
        require(result.returncode==0 and type(result.stdout) is bytes and len(result.stdout)<=2*1024**2)
        observation=validate(data=self.data,root=self.root,files=self.files,directories=self.directories,
            mounts=self.selected_mounts,units=units,daemon=json_object(result.stdout),mapper_device=self.mapper_device,
            journal_gid=self.journal_gid,guard_raw=self.guard)
        observation['systemctlObservedSha256']=self.systemctl.observed_sha256
        observation['absentJournalInputsSha256']=sha(canonical(sorted(self.absent)))
        observation['daemonProcessesSha256']=sha(canonical({name:dict(pid=int(row[1].rsplit('/',1)[1]),cmdlineSha256=sha(row[2]),executable=row[3]) for name,row in self.processes.items()}))
        self.check()
        if self.result is not None:require(observation==self.result)
        self.result=observation;self.units=units;return dict(observation)

    def __exit__(self,*args):
        try:
            if args[0] is None:self.check()
        finally:self.closed=True;self.stack.__exit__(*args)
