"""Pinned installed Docker/standalone Compose commands, bounded by held IO.

Pins are company-worker inputs, not administrator-provided execution grants.
Native package wiring must bind them to authenticated installation evidence.
"""
import hashlib
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from types import SimpleNamespace

ALLOWED={'docker':{'/usr/bin/docker'},'compose':{'/usr/libexec/docker/cli-plugins/docker-compose',
    '/usr/lib/docker/cli-plugins/docker-compose','/usr/local/lib/docker/cli-plugins/docker-compose'}}

def require(value,reason='Pinned infrastructure transport unavailable; preserve uncertain effects'):
    if not value:raise ValueError(reason)

def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

class NativeTransport:
    def __init__(self,io,pins):
        require(type(pins) is dict and set(pins)==set(ALLOWED));self.io=io;self.pins={name:dict(value) for name,value in pins.items()}
        self.tools={};self.parents=[];self.failed=False;self.socket=None;self.selinux=False

    def preflight(self):
        require(not self.tools and not self.failed and os.geteuid()==0)
        try:
            for name,pin in self.pins.items():
                require(set(pin)=={'path','bytes','sha256'} and pin['path'] in ALLOWED[name]
                    and type(pin['bytes']) is int and 0<pin['bytes']<=256*1024**2 and re.fullmatch('[a-f0-9]{64}',pin['sha256']))
                fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                self.parents.append((Path('/'),fd,ident(os.fstat(fd))))
                parent=Path('/')
                for part in Path(pin['path']).parts[1:-1]:
                    parent=parent/part;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    self.parents.append((parent,fd,ident(os.fstat(fd))))
                for _,_,before in self.parents:require(before[3:5]==(0,0) and not stat.S_IMODE(before[2])&0o022)
                tool=os.open(Path(pin['path']).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                before=ident(os.fstat(tool));self.tools[name]=(tool,before)
                require(stat.S_ISREG(before[2]) and before[3:6]==(0,0,1) and not stat.S_IMODE(before[2])&0o022
                    and stat.S_IMODE(before[2])&0o111 and before[6]==pin['bytes'])
                digest=hashlib.sha256();offset=0
                while offset<before[6]:
                    block=os.pread(tool,min(1024**2,before[6]-offset),offset);require(block);digest.update(block);offset+=len(block)
                require(digest.hexdigest()==pin['sha256'] and ident(os.fstat(tool))==before)
            socket=os.stat('/run/docker.sock',follow_symlinks=False)
            require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid==0 and stat.S_IMODE(socket.st_mode)==0o660)
            self.socket=ident(socket)
            self.selinux=os.path.exists('/sys/fs/selinux/enforce')
            if self.selinux:
                fd=os.open('/sys/fs/selinux/enforce',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
                try:require(os.read(fd,8) in (b'0',b'1',b'0\n',b'1\n'))
                finally:os.close(fd)
            self.check()
        except BaseException:self.failed=True;self.close();raise

    def check(self):
        require(not self.failed and self.socket is not None);self.io.check()
        require(ident(os.stat('/run/docker.sock',follow_symlinks=False))==self.socket)
        for path,fd,before in self.parents:
            require(ident(os.fstat(fd))[:5]==before[:5] and ident(path.lstat())[:5]==before[:5])
        for name,(fd,before) in self.tools.items():
            require(ident(os.fstat(fd))==before and ident(os.stat(self.pins[name]['path'],follow_symlinks=False))==before)

    def run(self,name,args,*,timeout=30):
        self.check();require(name in self.tools and type(args) is list and all(type(a) is str and '\0' not in a for a in args)
            and type(timeout) in (int,float) and math.isfinite(timeout) and 0<timeout<=180)
        fd=self.tools[name][0];deadline=min(self.io.deadline,time.monotonic()+timeout)
        # Standalone Compose honors this fixed daemon selection. No inherited
        # COMPOSE_*, Docker credentials, proxy settings or shell are present.
        env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL='C',HOME='/nonexistent',DOCKER_CONFIG='/nonexistent',
            DOCKER_HOST='unix:///run/docker.sock',COMPOSE_DISABLE_ENV_FILE='1')
        process=subprocess.Popen(['/proc/self/fd/'+str(fd),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=env,cwd='/',start_new_session=True,close_fds=True,pass_fds=(fd,))
        selector=None;out=bytearray();err=bytearray();finished=False
        try:
            selector=selectors.DefaultSelector()
            for stream,buffer in ((process.stdout,out),(process.stderr,err)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,buffer)
            while selector.get_map():
                require(time.monotonic()<deadline,'Infrastructure command deadline exceeded; do not repeat uncertain effects');self.check()
                for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
                    raw=os.read(key.fileobj.fileno(),65536)
                    if raw:key.data.extend(raw);require(len(out)+len(err)<=2*1024**2)
                    else:selector.unregister(key.fileobj);key.fileobj.close()
            while os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                require(time.monotonic()<deadline);self.check();time.sleep(0.01)
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            code=process.wait(timeout=2);finished=True;self.check()
            return SimpleNamespace(returncode=code,stdout=bytes(out),stderr=bytes(err))
        finally:
            if not finished:
                self.failed=True
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:pass
            if selector:selector.close()
            for stream in (process.stdout,process.stderr):
                if not stream.closed:stream.close()

    def close(self):
        errors=[]
        for fd in [value[0] for value in self.tools.values()]+[value[1] for value in reversed(self.parents)]:
            try:os.close(fd)
            except BaseException as error:errors.append(error)
        self.tools.clear();self.parents=[]
        if errors:raise errors[0]
