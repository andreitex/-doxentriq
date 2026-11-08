"""Private finite identity-operation files; caller supplies real held authority.

This adapter does not authenticate a release or grant an installer capability.
Original source bytes and CA must be bound by the caller's verified inputs.
"""
import hashlib,json,os,re,stat,time
from pathlib import Path

def require(value,message='Identity operation changed; preserve evidence for IT review'):
    if not value:raise ValueError(message)
def identity(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def sha(raw):return hashlib.sha256(raw).hexdigest()

class IdentityIO:
    def __init__(self,data,operation,source,ca,*,check_authority,clock=time.monotonic):
        require(os.geteuid()==0 and re.fullmatch('[0-9a-f]{32}',operation) and callable(check_authority))
        data=Path(data);require(data.is_absolute() and str(data)==str(data.resolve(strict=True)))
        require(type(source) is bytes and 1<=len(source)<=131072 and type(ca) is bytes and 1<=len(ca)<=32768)
        self.authority=check_authority;self.clock=clock;self.deadline=clock()+600
        self.root=str(data/'company'/('identity-'+operation));self.operation=operation
        self.dirs=[];self.files={};self.failed=False;self.counter=0;self.closed=False
        self.copy_hashes={'provision.mjs':sha(source),'ca.crt':sha(ca)}
        try:
            path=Path('/');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.dirs.append([path,fd,None]);self.dirs[-1][2]=identity(os.fstat(fd))
            for part in (data/'company').parts[1:]:
                path=path/part;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                self.dirs.append([path,fd,None]);self.dirs[-1][2]=identity(os.fstat(fd))
            for path,fd,before in self.dirs:
                require(before[3:5]==(0,0) and not stat.S_IMODE(before[2])&0o022)
            require(stat.S_IMODE(self.dirs[-1][2][2])==0o700)
            self.authority();self._parents()
            name=Path(self.root).name;parent=self.dirs[-1]
            os.mkdir(name,0o700,dir_fd=parent[1]);os.fsync(parent[1])
            parent[2]=identity(os.fstat(parent[1]))
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent[1])
            self.dirs.append([Path(self.root),fd,None]);self.dirs[-1][2]=identity(os.fstat(fd))
            self._write('provision.mjs',source,0o400,10001)
            self._write('ca.crt',ca,0o400,10001)
            self.check()
        except BaseException:
            self.failed=True;self.close(check=False);raise

    def _parents(self):
        for path,fd,before in self.dirs:
            require(identity(os.fstat(fd))==before and identity(path.lstat())==before)

    def check(self):
        require(not self.closed and not self.failed and self.clock()<self.deadline)
        self.authority();self._parents()
        require(set(os.listdir(self.dirs[-1][1]))==set(self.files))
        for name,(fd,before,digest) in self.files.items():
            require(identity(os.fstat(fd))==before and identity(os.stat(name,dir_fd=self.dirs[-1][1],follow_symlinks=False))==before)
            raw=os.pread(fd,before[6]+1,0);require(len(raw)==before[6] and sha(raw)==digest)

    def _write(self,name,raw,mode,uid):
        require(not self.failed and re.fullmatch(r'(provision\.mjs|ca\.crt|[0-9]{3}-[a-z-]+\.json)',name))
        self.authority();self._parents();require(self.clock()<self.deadline)
        parent=self.dirs[-1];fd=None
        try:
            fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent[1])
            self.files[name]=(fd,None,sha(b''))
            self.files[name]=(fd,identity(os.fstat(fd)),sha(b''))
            offset=0
            while offset<len(raw):
                require(self.clock()<self.deadline);count=os.write(fd,raw[offset:offset+65536]);require(count>0);offset+=count
            os.fchown(fd,uid,uid);os.fchmod(fd,mode);os.fsync(fd);os.fsync(parent[1])
            self.files[name]=(fd,identity(os.fstat(fd)),sha(raw));parent[2]=identity(os.fstat(parent[1]))
        except BaseException:self.failed=True;raise

    def record(self,phase,event,values):
        self.check();require(phase in ('provision','verify') and event in ('intent','created','start-intent','completed','removed'))
        require(type(values) is dict and set(values)<= {'image','imageId','networkId','keycloakId','containerId','sourceSha256','caSha256','outputSha256'})
        for key,value in values.items():
            require(type(value) is str and len(value)<=256)
            if key=='image':require(re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}',value))
            elif key=='imageId':require(re.fullmatch('sha256:[0-9a-f]{64}',value))
            else:require(re.fullmatch('[0-9a-f]{64}',value))
        self.counter+=1;require(self.counter<=10)
        raw=(json.dumps(dict(phase=phase,event=event,values=values),sort_keys=True,separators=(',',':'))+'\n').encode()
        self._write(f'{self.counter:03}-{phase}-{event}.json',raw,0o400,0);self.check()

    def labels(self,enabled):
        """Only newly owned copies may receive Docker's shared readonly label."""
        self.check()
        if not enabled:return
        expected=b'system_u:object_r:container_file_t:s0'
        for name in ('provision.mjs','ca.crt'):
            fd,before,digest=self.files[name]
            os.setxattr(fd,'security.selinux',expected)
            after=identity(os.fstat(fd))
            require(after[:8]==before[:8] and sha(os.pread(fd,before[6]+1,0))==digest
                and os.getxattr(fd,'security.selinux').rstrip(b'\0')==expected)
            os.fsync(fd);self.files[name]=(fd,after,digest)
        self.check()

    def close(self,*,check=True):
        if self.closed:return
        failure=None
        if check:
            try:self.check()
            except BaseException as error:failure=error
        for fd in [row[0] for row in self.files.values()]+[row[1] for row in reversed(self.dirs)]:
            try:os.close(fd)
            except BaseException as error:failure=failure or error
        self.closed=True
        if failure:raise failure
