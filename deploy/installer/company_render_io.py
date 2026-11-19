"""Finite fresh-render filesystem capability; no host shell or overwrite adoption.

Only trusted captured renderer code receives this object. It is not a Python
sandbox. Every path is in a company-defined plan, every ancestor stays held by
descriptor, and permitted directory changes are accounted for immediately.
"""
from contextlib import contextmanager
from pathlib import PurePosixPath
import hashlib
import errno
import io
import json
import os
import secrets
import stat
import time
from types import SimpleNamespace

TEMPLATES = ('grafana-datasources.yml','loki.yml','mysql.cnf','otel.yml',
    'prometheus-web.yml','prometheus.yml','rabbitmq.conf','redis.conf','squid.conf')
SERVICES = dict(mysql=999,redis=999,rabbitmq=999,keycloak=1000,registry=0,
    control=10001,broker=10001,packager=10001,prometheus=65534,loki=10001,grafana=472,otel=10001)
SERVICE_DATA = dict(platform=10001,workspaces=10001,caddy=10001,**{'caddy-config':10001,
    'caddy-admin':10001,'public-tls':10001,'mysql-keyring':999},mysql=999,redis=999,
    rabbitmq=999,prometheus=65534,loki=10001,grafana=472)
SECRET_OWNERS = dict(platform=10001,control=10001,runtime=10001,packager=10001,
    mysql=999,keycloak=1000,grafana=472,metrics=65534,registry=0)
MAX_FILE = 2*1024*1024
MAX_TOTAL = 24*1024*1024


def require(condition, message='Render boundary refused; preserve partial outputs for company review'):
    if not condition: raise ValueError(message)


def identity(s):
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def canonical(value): return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def digest(value): return hashlib.sha256(canonical(value)).hexdigest()


def plan(cfg):
    """Return all names, final permissions and finite temporary certificate files."""
    outputs={}
    def add(name,mode=0o600,uid=0,gid=None): outputs[name]=(mode,uid,uid if gid is None else gid)
    for name in TEMPLATES: add('config/'+name,0o644)
    for name in ('redis/redis.conf','keycloak-start.sh','mysqld.my','component_keyring_file.cnf','Caddyfile','caddy.json'):
        add('config/'+name,0o644)
    add('config/filesystem-sources.json',0o640,0,10001)
    add('config/redis/users.acl',uid=999);add('redis/users.acl',uid=999)
    add('config/mysql-init.sql',uid=999);add('config/rabbitmq-definitions.json',uid=999)
    add('config/realm.json',uid=1000);add('config/compose.env')
    groups={
      'platform':'mysql-platform oidc-client broker-token publication-proof-key secret-key redis-password rabbitmq-password redis-url rabbitmq-url',
      'runtime':'mysql-provisioner broker-token publication-proof-key vault-key quota-token redis-admin rabbitmq-admin registry-password registry.json config.json keycloak-client keycloak-platform-client keycloak-directory-reader app-issuer.key app-issuer.crt',
      'mysql':'mysql-root mysql-backup client.cnf backup.cnf',
      'keycloak':'mysql-password bootstrap-password','control':'report-token metrics-token',
      'metrics':'metrics-token','packager':'broker-token registry.json','registry':'htpasswd','grafana':'grafana-password'}
    for group,names in groups.items():
        for name in names.split(): add('secrets/'+group+'/'+name,uid=SECRET_OWNERS[group])
    for name in ('owner-password','owner-bootstrap.txt','backup-key'):add('secrets/'+name)
    add('tls/ca.key');add('tls/ca.crt',0o644)
    temporary={'tls/app-issuer.csr','tls/app-issuer.cnf'}
    for service,uid in SERVICES.items():
        add('tls/'+service+'/'+service+'.key',uid=uid)
        add('tls/'+service+'/'+service+'.crt',0o644,uid)
        add('tls/'+service+'/ca.crt',0o644,uid)
        temporary.update({'tls/'+service+'/request.csr','tls/'+service+'/extensions.cnf'})
    if cfg['certificate_mode']=='selfsigned':
        add('public-tls/server.key',uid=10001);add('public-tls/server.crt',uid=10001)
        temporary.update({'public-tls/request.csr','public-tls/extensions.cnf'})
    fresh_dirs={'otel-offsets':(0o750,10001,10001),'imports':(0o755,0,0),
        'config/redis':(0o700,999,999),'secrets/control':(0o700,10001,10001),
        'secrets/metrics':(0o700,65534,65534)}
    fresh_dirs.update({'tls/'+name:(0o700,uid,uid) for name,uid in SERVICES.items()})
    inputs={'config/'+name for name in ('installation.json','images.lock.json','runtime-manifest.json','approved-mirrors.json','models.json')}
    credentials={'secrets/platform/openai-key','secrets/platform/anthropic-key','secrets/dns.env'}
    for provider in ('google','microsoft'):
        if cfg['sso'] in (provider,'both'):credentials.add('secrets/keycloak/'+provider+'-client-secret')
    if cfg['certificate_mode']=='gcloud':credentials.add('secrets/dns/gcloud.json')
    if cfg.get('company_registry'):credentials.add('secrets/docker-client/config.json')
    if cfg.get('notification_email'):credentials.add('secrets/notifications/smtp-password')
    inputs.update(credentials)
    directories={''}
    for name in set(outputs)|inputs|temporary|set(fresh_dirs)|set(SERVICE_DATA)|{'logs','quota'}:
        p=PurePosixPath(name)
        while str(p.parent)!='.':directories.add(str(p.parent));p=p.parent
    directories.update(SERVICE_DATA);directories.update(('logs','quota','tls'));directories.update(fresh_dirs)
    directories.update('secrets/'+n for n in ('platform','mysql','keycloak','registry','runtime','packager','grafana','dns'))
    return dict(outputs=outputs,temporary=temporary,freshDirectories=fresh_dirs,
        inputs=inputs,credentials=credentials,directories=directories)


class RenderPath:
    def __init__(self,owner,name='',source=False):self.owner,self.name_,self.source=owner,name,source
    def __truediv__(self,name):
        require(type(name) is str and name and not name.startswith('/') and '\\' not in name)
        value=(self.name_+'/' if self.name_ else '')+name
        require(all(p not in ('','.', '..') for p in value.split('/')))
        return RenderPath(self.owner,value,self.source)
    def __str__(self):return (self.owner.source_root if self.source else self.owner.root)+('/'+self.name_ if self.name_ else '')
    def __fspath__(self):return str(self)
    @property
    def name(self):return self.name_.split('/')[-1]
    @property
    def suffix(self):return PurePosixPath(self.name_).suffix
    @property
    def parent(self):return RenderPath(self.owner,self.name_.rsplit('/',1)[0] if '/' in self.name_ else '',self.source)
    def exists(self):return self.owner.exists(self)
    def is_symlink(self):self.owner.check();return False
    def is_file(self):return self.exists() and self.name_ not in self.owner.spec['directories']
    def lstat(self):return self.owner.stat(self)
    def stat(self):return self.lstat()
    def read_bytes(self):return self.owner.read(self)
    def read_text(self):return self.read_bytes().decode('utf-8')
    def mkdir(self,mode=0o777,parents=False,exist_ok=False):return self.owner.mkdir(self,mode,parents,exist_ok)
    def iterdir(self):return self.owner.children(self)
    def rglob(self,pattern):
        require(pattern=='*' and not self.source)
        return [RenderPath(self.owner,n) for n in sorted(self.owner.files) if n.startswith(self.name_+'/')]
    def unlink(self):return self.owner.unlink(self)
    @contextmanager
    def open(self,mode):
        require(mode=='a' and self.name_=='config/mysql-init.sql' and not self.source)
        value=io.StringIO();yield value
        self.owner.write(self,self.read_text()+value.getvalue())


class RenderIO:
    """Open a finite fresh transaction, or read-only independently measured result.

    check_authority is fixed worker wiring to the original live HeldParent and
    signed source. No administrator-provided callable is accepted by the worker.
    Expected directory inventory/metadata is refreshed only for the single
    declared local operation; arbitrary ancestor changes are never adopted.
    """
    def __init__(self,root,source_root,source_bytes,cfg,*,check_authority,process_factory,
                 readonly=False,expected=None,clock=time.monotonic,timeout=600):
        require(os.name=='posix' and os.geteuid()==0 and 0<timeout<=600)
        self.root=str(root);self.source_root=str(source_root)
        require(self.root.startswith('/') and self.root.rstrip('/')==self.root and '..' not in self.root.split('/'))
        self.cfg=cfg;self.spec=plan(cfg);self.source_bytes=source_bytes
        self.authority,self.clock,self.deadline=check_authority,clock,clock()+timeout
        self.readonly=readonly;self.dirs={};self.files={};self.created=set();self.deleted=set();self.poisoned=False
        self.calls=0;self.total=0;self.pending={};self.labels={};self.unknown=[]
        self.data,self.source=RenderPath(self),RenderPath(self,source=True)
        self.os=SimpleNamespace(chown=self.chown,chmod=self.chmod,stat=self.host_stat)
        self.process=None
        try:
            flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
            # Walk absolute ancestors without following links; keep them all open.
            self.ancestors=[];fd=os.open('/',flags);self.ancestors.append((fd,None))
            for part in self.root.strip('/').split('/'):
                before=os.fstat(fd);require(before.st_uid==0 and before.st_gid==0 and not stat.S_IMODE(before.st_mode)&0o022)
                self.ancestors[-1]=(fd,identity(before))
                fd=os.open(part,flags,dir_fd=fd)
                self.ancestors.append((fd,None))
            self.device=os.fstat(fd).st_dev
            self.ancestors.pop() # _hold_dir owns the final descriptor immediately.
            self._hold_dir('',fd,initial=True)
            for name in sorted(self.spec['directories']-{''},key=lambda n:(n.count('/'),n)):
                if not readonly and name in self.spec['freshDirectories']:
                    self._absent(name);continue
                self._hold_dir(name,self._open(name,flags),initial=not readonly)
            for name in sorted(self.spec['inputs']):self._hold_file(name,initial=not readonly)
            if not readonly:
                for name in sorted(set(self.spec['outputs'])|self.spec['temporary']):self._absent(name)
                # A secret directory has exactly the admitted credential children.
                for name,row in self.dirs.items():
                    if name=='secrets' or name.startswith('secrets/'):
                        allowed={p[len(name)+1:].split('/')[0] for p in self.spec['inputs'] if p.startswith(name+'/')}
                        allowed.update(p[len(name)+1:].split('/')[0] for p in self.dirs if p.startswith(name+'/'))
                        require(row['names']==allowed)
            else:
                for name in sorted(self.spec['outputs']):self._hold_file(name,initial=False)
                for name in self.spec['temporary']:self._absent(name)
            self.baseline={name:dict(rawSha256=row['hash'],identity=list(row['id'])) for name,row in self.files.items() if name in self.spec['inputs']}
            self.process=process_factory(self)
            self.process.preflight()
            self.check()
            if readonly:
                require(type(expected) is dict)
                require(self.manifest()==expected,'Rendered output differs from the closed execute result')
        except BaseException:
            self.close(check=False);raise

    def _open(self,name,flags):
        parent,leaf=name.rsplit('/',1) if '/' in name else ('',name)
        return os.open(leaf,flags,0o600,dir_fd=self.dirs[parent]['fd'])

    def _hold_dir(self,name,fd,*,initial):
        try:
            s=os.fstat(fd);require(stat.S_ISDIR(s.st_mode) and s.st_dev==self.device and not stat.S_IMODE(s.st_mode)&0o022)
            if initial:require(s.st_uid==s.st_gid==0)
            names=set(os.listdir(fd));require(len(names)<=256)
            self.dirs[name]=dict(fd=fd,id=identity(s),names=names)
        except BaseException:
            try:os.close(fd)
            except BaseException:self.unknown.append(fd)
            raise

    def _hold_file(self,name,*,initial):
        fd=self._open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_dev==self.device and s.st_nlink==1 and 0<=s.st_size<=MAX_FILE)
            if initial:
                uid=1000 if name.startswith('secrets/keycloak/') else 0
                require(s.st_uid==s.st_gid==uid and not stat.S_IMODE(s.st_mode)&(0o077 if name.startswith('secrets/') else 0o022))
            raw=self._readfd(fd);require(identity(os.fstat(fd))==identity(s))
            self.files[name]=dict(fd=fd,id=identity(s),hash=hashlib.sha256(raw).hexdigest())
        except BaseException:
            try:os.close(fd)
            except BaseException:self.unknown.append(fd)
            raise

    def _readfd(self,fd):
        raw=bytearray();offset=0
        while len(raw)<=MAX_FILE:
            block=os.pread(fd,min(65536,MAX_FILE+1-len(raw)),offset)
            if not block:break
            raw.extend(block);offset+=len(block)
        require(len(raw)<=MAX_FILE);return bytes(raw)

    def _absent(self,name):
        parent,leaf=name.rsplit('/',1) if '/' in name else ('',name)
        if parent not in self.dirs:return
        try:os.stat(leaf,dir_fd=self.dirs[parent]['fd'],follow_symlinks=False)
        except FileNotFoundError:return
        raise ValueError('Fresh render output already exists; preserve it for company review')

    def _path(self,path):
        require(type(path) is RenderPath and path.owner is self and not path.source)
        require(path.name_ in self.spec['directories']|set(self.spec['outputs'])|self.spec['temporary']|self.spec['inputs'])
        return path.name_

    def check(self):
        require(not self.poisoned and not self.unknown and self.calls<10000 and self.clock()<self.deadline)
        self.calls+=1;self.authority()
        for fd,before in self.ancestors:
            # Ancestor contents are unrelated, but inode/owner/mode cannot change.
            require(identity(os.fstat(fd))[:5]==before[:5])
        for name,row in self.dirs.items():
            require(identity(os.fstat(row['fd']))==row['id'] and set(os.listdir(row['fd']))==row['names'])
            if name:
                parent,leaf=name.rsplit('/',1) if '/' in name else ('',name)
                require(identity(os.stat(leaf,dir_fd=self.dirs[parent]['fd'],follow_symlinks=False))==row['id'])
            else:require(identity(os.stat(self.root,follow_symlinks=False))==row['id'])
        for name,row in self.files.items():
            parent,leaf=name.rsplit('/',1)
            now=identity(os.fstat(row['fd']))
            require(identity(os.stat(leaf,dir_fd=self.dirs[parent]['fd'],follow_symlinks=False))==now)
            if name in self.pending:require(now[:6]==row['id'][:6] and now[6]<=MAX_FILE)
            else:require(now==row['id'])

    def _refresh_parent(self,name,*,added=None,removed=None):
        parent=name.rsplit('/',1)[0] if '/' in name else '';row=self.dirs[parent]
        expected=set(row['names'])
        if added:require(added not in expected);expected.add(added)
        if removed:require(removed in expected);expected.remove(removed)
        now=identity(os.fstat(row['fd']))
        require(now[:5]==row['id'][:5] and set(os.listdir(row['fd']))==expected)
        os.fsync(row['fd']);row['id']=identity(os.fstat(row['fd']));row['names']=expected

    def exists(self,path):
        self.check()
        if path.source:return path.name_ in self.source_bytes or path.name_=='deploy/config'
        name=self._path(path);return name in self.dirs or name in self.files

    def stat(self,path):
        name=self._path(path);self.check();return os.fstat((self.dirs if name in self.dirs else self.files)[name]['fd'])

    def read(self,path):
        self.check()
        if path.source:
            require(path.name_ in {'deploy/config/'+n for n in TEMPLATES}|{'scripts/keycloak-start.sh'})
            raw=self.source_bytes[path.name_];require(type(raw) is bytes and len(raw)<=MAX_FILE);return raw
        name=self._path(path);require(name in self.files)
        raw=self._readfd(self.files[name]['fd']);require(hashlib.sha256(raw).hexdigest()==self.files[name]['hash']);self.check();return raw

    def children(self,path):
        self.check()
        if path.source:
            require(path.name_=='deploy/config');return [path/name for name in TEMPLATES]
        name=self._path(path);require(name in self.dirs)
        return [path/leaf for leaf in sorted(self.dirs[name]['names'])]

    def mkdir(self,path,mode,parents,exist_ok):
        name=self._path(path);self.check();require(not self.readonly)
        if name in self.dirs:require(exist_ok);return
        require(name in self.spec['freshDirectories'])
        parent,leaf=name.rsplit('/',1) if '/' in name else ('',name)
        require(parent in self.dirs);os.mkdir(leaf,0o700,dir_fd=self.dirs[parent]['fd'])
        self._refresh_parent(name,added=leaf)
        self._hold_dir(name,self._open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW),initial=True)
        # Every final mode is applied explicitly, independent of installer umask.
        self.chmod(path, self.spec['freshDirectories'][name][0]);self.check()

    def write(self,path,value,mode=0o600,uid=None):
        name=self._path(path);self.check();require(not self.readonly and name in set(self.spec['outputs'])|self.spec['temporary'])
        raw=(value if isinstance(value,str) else json.dumps(value,indent=2)+'\n').encode()
        self.write_bytes(path,raw)
        self.chmod(path,mode)
        if uid is not None:self.chown(path,uid,uid)

    def write_bytes(self,path,raw):
        name=self._path(path);self.check();require(not self.readonly and type(raw) is bytes and len(raw)<=MAX_FILE)
        require(name in set(self.spec['outputs'])|self.spec['temporary'])
        self.total+=len(raw);require(self.total<=MAX_TOTAL)
        rewrite=name in self.files
        require(not rewrite or (name in self.created and name in {'config/mysql-init.sql','config/grafana-datasources.yml'}))
        if rewrite:
            row=self.files[name];fd=self._open(name,os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        else:
            self._absent(name);fd=self._open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            if rewrite:require(identity(os.fstat(fd))==row['id']);os.ftruncate(fd,0)
            else:os.fchmod(fd,0o600)
            offset=0
            while offset<len(raw):
                require(self.clock()<self.deadline);n=os.write(fd,raw[offset:offset+65536]);require(n>0);offset+=n
            os.fsync(fd)
        except BaseException:self.poisoned=True;raise
        finally:
            try:os.close(fd)
            except BaseException:self.unknown.append(fd);raise
        if rewrite:os.close(self.files.pop(name)['fd'])
        else:self._refresh_parent(name,added=PurePosixPath(name).name);self.created.add(name)
        self._hold_file(name,initial=False);self.check()

    def secret(self,path,size=32):
        require(size==32)
        if not self.exists(path):self.write(path,secrets.token_urlsafe(size))
        return self.read(path).decode().strip()

    def copyfile(self,source,target):self.write_bytes(target,self.read(source))

    def command_output(self,name):
        """Exclusively open one predetermined OpenSSL output; never reopen by path."""
        path=RenderPath(self,name);self._path(path);self.check()
        require(not self.readonly and name in set(self.spec['outputs'])|self.spec['temporary'])
        require(name not in self.files and (name.endswith(('.key','.crt','.csr'))))
        self._absent(name);fd=self._open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW)
        # Own the descriptor before chmod/fsync/inventory checks can fail.
        try:self.files[name]=dict(fd=fd,id=identity(os.fstat(fd)),hash=hashlib.sha256(b'').hexdigest())
        except BaseException:
            self.poisoned=True
            try:os.close(fd)
            except BaseException:self.unknown.append(fd)
            raise
        self.created.add(name);self.pending[name]=fd
        try:
            os.fchmod(fd,0o600);os.fsync(fd);self.files[name]['id']=identity(os.fstat(fd))
            self._refresh_parent(name,added=PurePosixPath(name).name);self.check();return fd
        except BaseException:self.poisoned=True;raise

    def finish_command(self,names,success):
        try:
            self.check()
            for name in names:
                require(name in self.pending);row=self.files[name];os.fsync(row['fd'])
                raw=self._readfd(row['fd']);require(bool(raw) and len(raw)<=MAX_FILE)
                row['id']=identity(os.fstat(row['fd']));row['hash']=hashlib.sha256(raw).hexdigest()
                del self.pending[name]
            self.check()
        finally:
            if not success:self.poisoned=True

    def _permission(self,path,mode=None,uid=None,gid=None):
        name=self._path(path);self.check();require(not self.readonly)
        require(name in self.created or name in self.spec['freshDirectories'] or name in SERVICE_DATA
            or name in ('logs','secrets/metrics') or name.startswith('secrets/') and
            (name in self.spec['credentials'] or name.split('/')[-1] in SECRET_OWNERS))
        row=(self.dirs if name in self.dirs else self.files)[name]
        if name in self.spec['outputs']:final=self.spec['outputs'][name]
        elif name in self.spec['temporary']:final=(0o600,0,0)
        elif name in self.spec['freshDirectories']:final=self.spec['freshDirectories'][name]
        elif name in SERVICE_DATA:final=(stat.S_IMODE(row['id'][2]),SERVICE_DATA[name],SERVICE_DATA[name])
        elif name=='logs':final=(0o750,10001,10001)
        elif name.startswith('secrets/'):
            service=name.split('/')[1];owner=SECRET_OWNERS.get(service,0)
            final=(0o700 if name in self.dirs else 0o600,owner,owner)
        else:raise ValueError('Unplanned permission transition')
        # Intermediate freshly-created files start root0600; subsequent explicit
        # renderer calls may apply only their declared final owner and mode.
        require(uid is None or (uid,gid)==final[1:])
        require(mode is None or mode in (final[0],0o600) and (name not in self.dirs or mode==final[0]))
        if uid is not None:os.fchown(row['fd'],uid,gid)
        if mode is not None:os.fchmod(row['fd'],mode)
        os.fsync(row['fd']);row['id']=identity(os.fstat(row['fd']));self.check()

    def chmod(self,path,mode):self._permission(path,mode=mode)
    def chown(self,path,uid,gid):self._permission(path,uid=uid,gid=gid)

    def unlink(self,path):
        name=self._path(path);self.check();require(not self.readonly and name in self.spec['temporary'] and name in self.created)
        parent,leaf=name.rsplit('/',1);os.unlink(leaf,dir_fd=self.dirs[parent]['fd']);os.close(self.files.pop(name)['fd'])
        self._refresh_parent(name,removed=leaf);self.deleted.add(name);self.check()

    def host_stat(self,path):
        require(path=='/var/run/docker.sock');self.check();return self.process.socket_stat()

    def caddy_label(self,enabled,*,mutate=False):
        """One explicit owned-file SELinux transition; Docker never relabels."""
        require(type(enabled) is bool and type(mutate) is bool)
        name='config/Caddyfile';self.check();require(name in self.files)
        row=self.files[name];before=row['id'];raw=self._readfd(row['fd'])
        wanted=b'system_u:object_r:container_file_t:s0'
        def label():
            try:return os.getxattr(row['fd'],'security.selinux').rstrip(b'\x00')
            except OSError as error:
                if error.errno in (errno.ENODATA,errno.ENOTSUP):return None
                raise
        if mutate and enabled:
            require(not self.readonly and name in self.created and name not in self.labels)
            try:
                os.setxattr(row['fd'],'security.selinux',wanted)
                now=identity(os.fstat(row['fd']))
                require(now[:8]==before[:8] and self._readfd(row['fd'])==raw and label()==wanted)
                os.fsync(row['fd']);row['id']=identity(os.fstat(row['fd']))
            except BaseException:self.poisoned=True;raise
        measured=label()
        require(not enabled or measured==wanted)
        self.labels[name]=dict(selinuxEnabled=enabled,value=measured.hex() if measured is not None else None)
        self.check()

    def manifest(self):
        self.check();require(not self.pending and set(self.files)==self.spec['inputs']|set(self.spec['outputs']))
        require(set(self.dirs)==self.spec['directories'])
        for name,(mode,uid,gid) in self.spec['outputs'].items():
            s=os.fstat(self.files[name]['fd']);require((stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid)==(mode,uid,gid))
        for name,(mode,uid,gid) in self.spec['freshDirectories'].items():
            s=os.fstat(self.dirs[name]['fd']);require((stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid)==(mode,uid,gid))
        for name,uid in SERVICE_DATA.items():require(self.dirs[name]['id'][3:5]==(uid,uid))
        require(self.dirs['logs']['id'][2:5]==(stat.S_IFDIR|0o750,10001,10001))
        for name,uid in SECRET_OWNERS.items():
            directory='secrets/'+name
            require(self.dirs[directory]['id'][2:5]==(stat.S_IFDIR|0o700,uid,uid))
        result={'files':{},'directories':{},'labels':dict(self.labels)}
        for name,row in sorted(self.files.items()):
            raw=self.read(RenderPath(self,name));sha=hashlib.sha256(raw).hexdigest()
            if name in self.baseline:
                require(sha==self.baseline[name]['rawSha256'])
                old=self.baseline[name]['identity'];now=row['id']
                if name.startswith(('secrets/platform/','secrets/keycloak/')):
                    owner=SECRET_OWNERS[name.split('/')[1]]
                    require(now[:2]==tuple(old[:2]) and now[5:8]==tuple(old[5:8])
                        and now[2:5]==(stat.S_IFREG|0o600,owner,owner))
                else:require(now==tuple(old))
            result['files'][name]=dict(identity=list(row['id']),sha256=sha)
        for name,saved in self.labels.items():
            self.caddy_label(saved['selinuxEnabled'])
            require(self.labels[name]==saved)
        for name,row in sorted(self.dirs.items()):result['directories'][name]=dict(identity=list(row['id']),children=sorted(row['names']))
        return result

    def close(self,*,check=True):
        error=None
        if check:
            try:self.check()
            except BaseException as exc:error=exc
        if self.process is not None:
            try:self.process.close()
            except BaseException as exc:error=error or exc
        for row in list(self.files.values())+list(self.dirs.values()):
            try:os.close(row['fd'])
            except BaseException as exc:error=error or exc
        for fd,_ in getattr(self,'ancestors',[]):
            try:os.close(fd)
            except BaseException as exc:error=error or exc
        self.files.clear();self.dirs.clear();self.ancestors=[];self.poisoned=True
        if error:raise error
