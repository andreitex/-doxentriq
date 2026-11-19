"""Fixed private quota service activation and independent process observation."""
from contextlib import ExitStack,contextmanager
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct

FIELDS=('ActiveState','SubState','LoadState','MainPID','ControlPID','ControlGroup','NeedDaemonReload',
    'FragmentPath','SourcePath','DropInPaths','Environment','EnvironmentFiles','User','Group','Type','NotifyAccess')
UNIT='autosoft-quota.service'


def require(value):
    if not value:raise ValueError('Quota service readiness is unconfirmed; preserve evidence and do not retry startup')


def systemctl_class(H):
    class QuotaSystemctl(H.Systemctl):
        """Reuse the held executable/supervisor; only these three fixed actions."""
        def __init__(self,*args):super().__init__(*args);self.started=False;self.reloaded=False
        @contextmanager
        def _effect(self,check_effect):
            require(callable(check_effect));original=self.authority
            def check():original();check_effect()
            self.authority=check
            try:check();yield;check()
            finally:self.authority=original
        def reload(self,*,check_effect):
            require(not self.reloaded and not self.started);self.reloaded=True
            with self._effect(check_effect):require(self._execute(['/usr/bin/systemctl','daemon-reload'],30)==b'')
        def start(self,*,check_effect):
            require(self.reloaded and not self.started);self.started=True
            with self._effect(check_effect):require(self._execute(['/usr/bin/systemctl','start','--',UNIT],100)==b'')
        def state(self):
            raw=self._execute(['/usr/bin/systemctl','show',*['--property='+n for n in FIELDS],'--',UNIT],8)
            pairs=[line.split('=',1) for line in raw.decode().splitlines()]
            require(len(pairs)==len(FIELDS) and all(len(row)==2 for row in pairs))
            result=dict(pairs);require(set(result)==set(FIELDS) and len(result)==len(pairs));return result
    return QuotaSystemctl


def active(state):
    require(type(state) is dict and set(state)==set(FIELDS))
    require(state['ActiveState']=='active' and state['SubState']=='running' and state['LoadState']=='loaded'
        and state['ControlPID']=='0' and re.fullmatch('[1-9][0-9]{0,9}',state['MainPID'])
        and int(state['MainPID'])>1 and state['NeedDaemonReload']=='no'
        and state['FragmentPath']=='/etc/systemd/system/'+UNIT and state['SourcePath']==''
        and state['DropInPaths']==state['Environment']==state['EnvironmentFiles']==state['User']==state['Group']==''
        and state['ControlGroup']=='/system.slice/'+UNIT and state['Type']=='notify' and state['NotifyAccess']=='main')
    return int(state['MainPID'])


def installed_sources(S,root,source_files):
    """Return a scope holding installed runtime bytes before service execution."""
    from contextlib import contextmanager
    @contextmanager
    def held():
        require(type(source_files) is dict and 'scripts/quota-helper.py' in source_files)
        with ExitStack() as stack:
            checks=[]
            for relative,raw in sorted(source_files.items()):
                require(re.fullmatch(r'scripts/[A-Za-z0-9_.-]+',relative) and type(raw) is bytes)
                fd,info,check=stack.enter_context(S.held_file(root+'/'+relative,1024**2))
                require(info['st_size']==len(raw) and os.pread(fd,len(raw)+1,0)==raw);checks.append(check)
            def check_all():
                for check in checks:check()
            check_all();yield check_all;check_all()
    return held()


def host_transition(H,before,after,before_units,after_units,builds_unit):
    """Only add the installed quota dependency; keep every other field exact."""
    require(before['unitsSha256']==H.sha(H.canonical(before_units))
        and after['unitsSha256']==H.sha(H.canonical(after_units)))
    require({k:v for k,v in before.items() if k!='unitsSha256'}
        =={k:v for k,v in after.items() if k!='unitsSha256'})
    require(set(before_units)==set(after_units)==set(H.UNITS))
    for unit in before_units:
        wanted=dict(before_units[unit])
        if unit=='docker.service':
            for key in ('Requires','After'):
                previous=wanted[key].split();current=after_units[unit][key].split()
                require(len(previous)==len(set(previous)) and len(current)==len(set(current))
                    and UNIT not in previous and builds_unit in previous
                    and set(current)==set(previous)|{UNIT})
                wanted[key]=after_units[unit][key]
            previous=wanted['DropInPaths'].split();current=after_units[unit]['DropInPaths'].split()
            dropin='/etc/systemd/system/docker.service.d/autosoft-quota.conf'
            require(len(previous)==len(set(previous)) and len(current)==len(set(current))
                and dropin not in previous and set(current)==set(previous)|{dropin})
            wanted['DropInPaths']=after_units[unit]['DropInPaths']
        require(wanted==after_units[unit])


class QuotaProcess:
    """Hold the actual root service, exact signed files and ready Unix peer."""
    def __init__(self,S,H,ctl,*,root,source_files,check_authority):
        self.S=S;self.H=H;self.ctl=ctl;self.root=root;self.authority=check_authority
        self.stack=ExitStack();self.checks=[];self.closed=False
        try:
            self.state=ctl.state();self.pid=active(self.state)
            self.pidfd=os.pidfd_open(self.pid,0);self.stack.callback(os.close,self.pidfd)
            self.command=('/usr/bin/python3\0-I\0-B\0'+root+'/scripts/quota-helper.py\0').encode()
            # All installed operational sources are compared with the original
            # signed bytes; this includes quota_runtime and its transitive loads.
            require(type(source_files) is dict and 'scripts/quota-helper.py' in source_files)
            for relative,raw in sorted(source_files.items()):
                fd,info,check=self.stack.enter_context(S.held_file(root+'/'+relative,1024**2))
                require(info['st_size']==len(raw) and os.pread(fd,len(raw)+1,0)==raw);self.checks.append(check)
            self.executable=os.path.realpath('/usr/bin/python3')
            require(self.executable.startswith('/usr/bin/python3') and re.fullmatch(r'/usr/bin/python3(?:\.[0-9]+)*',self.executable))
            _,_,check=self.stack.enter_context(S.held_file(self.executable,32*1024**2,executable=True));self.checks.append(check)
            self.socket=Path('/run/autosoft/quota.sock');self.directory=Path('/run/autosoft')
            self.socket_identity=H.identity(self.socket.lstat());self.directory_identity=H.identity(self.directory.lstat())
            require(self.directory_identity[2:5]==(stat.S_IFDIR|0o750,0,10001)
                and self.socket_identity[2:5]==(stat.S_IFSOCK|0o660,0,10001))
            self.check();self._peer();self.check()
        except BaseException:self.close(check=False);raise

    def _peer(self):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(2);client.connect(str(self.socket))
            require(struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))==(self.pid,0,0))

    def check(self):
        require(not self.closed);self.authority()
        for check in self.checks:check()
        poll=select.poll();poll.register(self.pidfd,select.POLLIN);require(poll.poll(0)==[])
        require(self.H.HostContainment._read_kernel('/proc/'+str(self.pid)+'/cmdline',4096)==self.command
            and os.readlink('/proc/'+str(self.pid)+'/exe')==self.executable)
        executing=os.stat('/proc/'+str(self.pid)+'/exe');installed=os.stat(self.executable,follow_symlinks=False)
        require((executing.st_dev,executing.st_ino)==(installed.st_dev,installed.st_ino))
        require(self.H.identity(self.socket.lstat())==self.socket_identity
            and self.H.identity(self.directory.lstat())==self.directory_identity)
        require(self.ctl.state()==self.state)

    def observation(self):
        self.check();return dict(pid=self.pid,state=self.state,socketIdentity=list(self.socket_identity),
            directoryIdentity=list(self.directory_identity),publicStartupAllowed=False)

    def close(self,*,check=True):
        if self.closed:return
        try:
            if check:self.check()
        finally:self.closed=True;self.stack.close()

    def __enter__(self):return self
    def __exit__(self,*args):self.close(check=args[0] is None)
