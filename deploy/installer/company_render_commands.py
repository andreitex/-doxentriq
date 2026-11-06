"""Fixed OpenSSL/bcrypt/Caddy transport for the trusted native renderer.

No arbitrary command API is exported to a request. Docker effects are explicitly
named and never retried: an uncertain outcome leaves the operation for IT review.
"""
import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import time
import urllib.parse
from types import SimpleNamespace

TOOLS={'openssl':'/usr/bin/openssl','htpasswd':'/usr/bin/htpasswd','docker':'/usr/bin/docker'}
LIMIT=2*1024*1024


def require(ok,message='Fixed rendering command refused; preserve the operation for company review'):
    if not ok:raise ValueError(message)


def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def canonical_digest_reference(value):
    """Normalize only Docker Hub's implicit registry and library namespace."""
    require(type(value) is str and re.fullmatch(r'[a-z0-9._:/-]+@sha256:[a-f0-9]{64}',value) is not None)
    repository,digest=value.split('@');parts=repository.split('/')
    require(all(part and part not in ('.','..') for part in parts))
    if len(parts)>1 and ('.' in parts[0] or ':' in parts[0] or parts[0]=='localhost'):
        registry,parts=parts[0],parts[1:]
    else:registry='docker.io'
    require(not any(':' in part for part in parts),'Tagged pinned aliases are unsupported')
    if registry=='docker.io' and len(parts)==1:parts=['library',*parts]
    return registry+'/'+('/'.join(parts))+'@'+digest


def pinned_reference_present(wanted,references):
    require(type(references) is list)
    expected=canonical_digest_reference(wanted)
    return any(canonical_digest_reference(value)==expected for value in references)


def grammar(io):
    """The exact original renderer's finite OpenSSL command set."""
    d=io.root;ca=d+'/tls/ca.crt';key=d+'/tls/ca.key';allowed={}
    def add(args,inputs=(),outputs=()):allowed[tuple(['openssl',*args])]=(tuple(inputs),tuple(outputs))
    add(['req','-x509','-newkey','rsa:4096','-nodes','-days','3650','-subj','/CN=Doxentriq Installation CA',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-keyout',key,'-out',ca],outputs=(key,ca))
    add(['verify','-x509_strict','-CAfile',ca,ca],inputs=(ca,))
    add(['x509','-in',ca,'-noout','-ext','basicConstraints,keyUsage'],inputs=(ca,))
    certificates=[('Autosoft Application Issuer',d+'/secrets/runtime/app-issuer.key',
        d+'/secrets/runtime/app-issuer.crt',d+'/tls/app-issuer.csr',d+'/tls/app-issuer.cnf','1825',None)]
    for service in io.spec['freshDirectories']:
        if not service.startswith('tls/'):continue
        name=service.split('/')[1];base=d+'/'+service
        certificates.append((name,base+'/'+name+'.key',base+'/'+name+'.crt',base+'/request.csr',base+'/extensions.cnf','365',name))
    if io.cfg['certificate_mode']=='selfsigned':
        host=urllib.parse.urlsplit(io.cfg['admin_origin']).hostname
        certificates.append((host,d+'/public-tls/server.key',d+'/public-tls/server.crt',d+'/public-tls/request.csr',d+'/public-tls/extensions.cnf','365',host))
    for subject,private,crt,csr,ext,days,hostname in certificates:
        add(['req','-new','-newkey','rsa:3072','-nodes','-subj','/CN='+subject,'-keyout',private,'-out',csr],outputs=(private,csr))
        add(['x509','-req','-in',csr,'-CA',ca,'-CAkey',key,'-CAcreateserial','-days',days,'-extfile',ext,'-out',crt],inputs=(csr,ca,key,ext),outputs=(crt,))
        args=['verify','-x509_strict','-CAfile',ca]
        if hostname:args+=['-purpose','sslserver','-verify_hostname',hostname]
        add(args+[crt],inputs=(ca,crt))
        add(['verify','-CAfile',ca,crt],inputs=(ca,crt))
        add(['x509','-checkend','2592000' if hostname is None else '604800','-noout','-in',crt],inputs=(crt,))
        add(['pkey','-in',private,'-pubout'],inputs=(private,))
        add(['x509','-in',crt,'-pubkey','-noout'],inputs=(crt,))
    add(['pkey','-in',key,'-pubout'],inputs=(key,))
    add(['x509','-in',ca,'-pubkey','-noout'],inputs=(ca,))
    if io.cfg['certificate_mode']=='selfsigned':
        crt=d+'/public-tls/server.crt'
        for name in ('admin_origin','apps_base_url','auth_origin'):
            host=urllib.parse.urlsplit(io.cfg[name]).hostname
            add(['verify','-x509_strict','-CAfile',ca,'-purpose','sslserver','-verify_hostname',host,crt],inputs=(ca,crt))
        host='probe.'+urllib.parse.urlsplit(io.cfg['apps_base_url']).hostname
        add(['verify','-x509_strict','-CAfile',ca,'-purpose','sslserver','-verify_hostname',host,crt],inputs=(ca,crt))
    return allowed


class NativeCommands:
    DEVNULL=subprocess.DEVNULL
    def __init__(self,io,operation_id):
        require(re.fullmatch('[a-f0-9]{32}',operation_id) is not None)
        self.io=io;self.name='doxentriq-render-'+operation_id;self.tools={};self.container=None
        self.failed=False;self.known=grammar(io);self.image=json.loads(io.read(io.data/'config/images.lock.json'))['caddy']
        require(re.fullmatch('[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',self.image) is not None)

    def _tool(self,name):
        path=TOOLS[name];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        owned=[fd];exe=None
        try:
            for part in path.strip('/').split('/')[:-1]:
                s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and not stat.S_IMODE(s.st_mode)&0o022)
                fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);owned.append(fd)
            s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and not stat.S_IMODE(s.st_mode)&0o022)
            exe=os.open(path.split('/')[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
            s=os.fstat(exe);require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and not stat.S_IMODE(s.st_mode)&0o022 and stat.S_IMODE(s.st_mode)&0o111)
            self.tools[name]=(exe,ident(s))
        finally:
            failures=[]
            if exe is not None and name not in self.tools:owned.append(exe)
            for descriptor in reversed(owned):
                try:os.close(descriptor)
                except BaseException as failure:failures.append(failure)
            if failures:self.failed=True;raise failures[0]

    def _check(self):
        require(not self.failed);self.io.check()
        for name,(fd,before) in self.tools.items():
            require(ident(os.fstat(fd))==before and ident(os.stat(TOOLS[name],follow_symlinks=False))==before)
        require(ident(os.stat('/run/docker.sock',follow_symlinks=False))==self.socket)

    def _execute(self,name,argv,*,stdin=b'',fds=(),timeout=45):
        """Bounded output, stdin, lifetime and same-process-group cleanup.

        The fixed installed tools are trusted. This is not containment for
        adversarial programs that create a new session or compromise the daemon.
        """
        self._check();require(type(stdin) is bytes and len(stdin)<=65536)
        exe=self.tools[name][0];deadline=min(self.io.deadline,time.monotonic()+timeout)
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/nonexistent','DOCKER_CONFIG':'/nonexistent'}
        selector=None;outputs={'out':bytearray(),'err':bytearray()};sent=0;unknown=True
        process=subprocess.Popen(['/proc/self/fd/'+str(exe),*argv],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=env,cwd='/',start_new_session=True,close_fds=True,pass_fds=tuple(set((exe,*fds))))
        try:
            selector=selectors.DefaultSelector()
            for label,stream in (('out',process.stdout),('err',process.stderr)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,label)
            os.set_blocking(process.stdin.fileno(),False)
            if stdin:selector.register(process.stdin,selectors.EVENT_WRITE,'in')
            else:process.stdin.close()
            while selector.get_map():
                require(time.monotonic()<deadline,'Rendering command exceeded its deadline; outcome requires company review')
                self._check()
                for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
                    stream,label=key.fileobj,key.data
                    if label=='in':
                        n=os.write(stream.fileno(),stdin[sent:sent+16384]);sent+=n
                        if sent==len(stdin):selector.unregister(stream);stream.close()
                    else:
                        data=os.read(stream.fileno(),65536)
                        if data:outputs[label].extend(data);require(len(outputs[label])<=LIMIT)
                        else:selector.unregister(stream);stream.close()
            while os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                require(time.monotonic()<deadline);self._check();time.sleep(0.01)
            # Leader remains waitable, so its group number cannot be reused here.
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            code=process.wait(timeout=2);unknown=False;self._check()
            return SimpleNamespace(returncode=code,stdout=bytes(outputs['out']),stderr=bytes(outputs['err']))
        finally:
            if unknown:
                self.failed=True
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:pass
            if selector is not None:selector.close()
            for stream in (process.stdin,process.stdout,process.stderr):
                if not stream.closed:stream.close()

    def _docker(self,args):
        result=self._execute('docker',['--host','unix:///run/docker.sock',*args],timeout=30)
        require(result.returncode==0,'Docker render operation failed; do not retry or remove an unconfirmed container')
        return result.stdout

    def preflight(self):
        require(not self.tools)
        for name in TOOLS:self._tool(name)
        sock=os.stat('/run/docker.sock',follow_symlinks=False)
        require(stat.S_ISSOCK(sock.st_mode) and sock.st_uid==0 and stat.S_IMODE(sock.st_mode)==0o660)
        self.socket=ident(sock)
        self.selinux=os.path.exists('/sys/fs/selinux/enforce')
        if self.selinux:
            fd=os.open('/sys/fs/selinux/enforce',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
            try:require(os.read(fd,8) in (b'0',b'1',b'0\n',b'1\n'))
            finally:os.close(fd)
        image=json.loads(self._docker(['image','inspect',self.image]))
        require(type(image) is list and len(image)==1 and image[0].get('Os')=='linux' and image[0].get('Architecture')=='amd64')
        require(pinned_reference_present(self.image,image[0].get('RepoDigests',[]))
            and re.fullmatch('sha256:[a-f0-9]{64}',image[0].get('Id','')) is not None)
        self.image_id=image[0]['Id']
        config=image[0]['Config'];require(config.get('Entrypoint') in (None,[]))
        volumes=config.get('Volumes') or {}
        require(type(volumes) is dict and set(volumes) in (set(),{'/data','/config'})
            and all(value=={} for value in volumes.values()),'Unsupported Caddy image volume profile')
        self.tmpfs={name:'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700' for name in sorted(volumes)}
        require(self._docker(['container','ls','--all','--quiet'])==b'','Render requires an otherwise inactive container engine')
        if self.io.readonly:self.io.caddy_label(self.selinux)
        self._check()

    def socket_stat(self):self._check();return os.stat('/run/docker.sock',follow_symlinks=False)

    def run(self,args,**kwargs):
        require(type(args) is list and set(kwargs)<= {'check','stdout','stderr','capture_output','text','input'})
        if args==['htpasswd','-iBn','platform']:
            value=kwargs.get('input');require(type(value) is str and re.fullmatch('[A-Za-z0-9_-]{40,64}\n',value) is not None)
            result=self._execute('htpasswd',args[1:],stdin=value.encode())
            require(result.returncode==0 and re.fullmatch(rb'platform:\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}\n',result.stdout) is not None)
        else:
            require(tuple(args) in self.known)
            reads,writes=self.known[tuple(args)];fds=[];outputs=[];rewritten=list(args[1:]);success=False
            try:
                for path in reads:
                    name=path[len(self.io.root)+1:];require(path.startswith(self.io.root+'/') and name in self.io.files)
                    fd=self.io.files[name]['fd'];fds.append(fd)
                    rewritten=[('/proc/self/fd/'+str(fd)) if value==path else value for value in rewritten]
                for path in writes:
                    name=path[len(self.io.root)+1:];require(path.startswith(self.io.root+'/'))
                    fd=self.io.command_output(name);fds.append(fd);outputs.append(name)
                    rewritten=[('/proc/self/fd/'+str(fd)) if value==path else value for value in rewritten]
                if '-CAcreateserial' in rewritten:
                    index=rewritten.index('-CAcreateserial')
                    # No implicit shared serial file and no adoption of partial PKI.
                    rewritten[index:index+1]=['-set_serial','0x'+secrets.token_hex(16)]
                result=self._execute('openssl',rewritten,fds=fds)
                success=result.returncode==0
            finally:
                if outputs:self.io.finish_command(outputs,success)
        if kwargs.get('check'):require(result.returncode==0)
        if kwargs.get('text'):
            result.stdout=result.stdout.decode('utf-8');result.stderr=result.stderr.decode('utf-8')
        return result

    def _container(self,identifier,*,exited=False):
        rows=json.loads(self._docker(['container','inspect',identifier]));require(type(rows) is list and len(rows)==1)
        v=rows[0];require(v['Id']==identifier and v['Name']=='/'+self.name and v['Image']==self.image_id)
        c,h,s=v['Config'],v['HostConfig'],v['State']
        require(c['Image']==self.image and c['User']=='10001:10001' and c['Cmd']==['caddy','adapt','--config','/etc/caddy/Caddyfile'])
        require(c.get('Entrypoint') in (None,[]))
        require(c['Labels'].get('com.doxentriq.render')==self.name and not h['Privileged'] and h['ReadonlyRootfs'])
        require(h['NetworkMode']=='none' and h['Memory']==134217728 and h['PidsLimit']==64)
        require(set(h['CapDrop'])=={'ALL'} and set(h['CapAdd'])=={'NET_BIND_SERVICE'} and h['SecurityOpt']==['no-new-privileges'])
        require(h['Binds']==[self.io.root+'/config/Caddyfile:/etc/caddy/Caddyfile:ro'] and not h.get('PortBindings'))
        require((h.get('Tmpfs') or {})==self.tmpfs)
        require(h['LogConfig']['Type']=='none' and h['RestartPolicy']['Name']=='no')
        mounts=v['Mounts'];binds=[row for row in mounts if row['Type']=='bind']
        require(len(binds)==1 and binds[0]['Source']==self.io.root+'/config/Caddyfile' and binds[0]['Destination']=='/etc/caddy/Caddyfile' and not binds[0]['RW'])
        transient=[row for row in mounts if row['Type']!='bind']
        require(len(transient)<=len(self.tmpfs) and all(row['Type']=='tmpfs' and row['Destination'] in self.tmpfs and not row.get('Source') and row['RW'] for row in transient)
            and len({row['Destination'] for row in transient})==len(transient))
        if exited:require(s['Status']=='exited' and s['ExitCode']==0 and s['Pid']==0 and not s['OOMKilled'] and not s['Error'])
        else:require(s['Status']=='created' and s['Pid']==0)

    def check_output(self,args,*,text):
        expected=['docker','run','--rm','--network=none','--read-only','--user=10001:10001','--cap-drop=ALL','--cap-add=NET_BIND_SERVICE',
            '--security-opt=no-new-privileges','--memory=128m','--pids-limit=64','--volume',self.io.root+'/config/Caddyfile:/etc/caddy/Caddyfile:ro,z',
            self.image,'caddy','adapt','--config','/etc/caddy/Caddyfile']
        require(args==expected and text is True and not self.io.readonly and self.container is None)
        actual=['container','create','--pull=never','--name',self.name,'--label','com.doxentriq.render='+self.name,'--log-driver=none',*args[3:]]
        actual=[value[:-2] if value==self.io.root+'/config/Caddyfile:/etc/caddy/Caddyfile:ro,z' else value for value in actual]
        for name,options in self.tmpfs.items():actual[2:2]=['--tmpfs',name+':'+options]
        self.io.caddy_label(self.selinux,mutate=True)
        raw=self._docker(actual);identifier=raw.decode().strip();require(re.fullmatch('[a-f0-9]{64}',identifier) is not None)
        self.container=identifier;self._container(identifier)
        adapted=self._docker(['container','start','--attach',identifier]);self._container(identifier,exited=True)
        parsed=json.loads(adapted);require(type(parsed) is dict)
        removed=self._docker(['container','rm',identifier]);require(removed.decode().strip()==identifier)
        require(self._docker(['container','ls','--all','--quiet'])==b'');self.container=None
        return adapted.decode('utf-8')

    def verify_command(self,args):
        require(args[0]=='/usr/bin/openssl')
        self.run(['openssl',*args[1:]],check=True)

    def verify_bcrypt(self):
        """Fixed read-only bcrypt verification, password only through stdin."""
        self.io.check();password=self.io.read(self.io.data/'secrets/runtime/registry-password')
        require(re.fullmatch(rb'[A-Za-z0-9_-]{40,64}',password) is not None)
        fd=self.io.files['secrets/registry/htpasswd']['fd']
        result=self._execute('htpasswd',['-vi','/proc/self/fd/'+str(fd),'platform'],stdin=password+b'\n',fds=(fd,))
        require(result.returncode==0)

    def close(self):
        error=self.container is not None or self.failed;failures=[]
        for fd,_ in self.tools.values():
            try:os.close(fd)
            except BaseException as failure:failures.append(failure)
        self.tools.clear()
        if failures:raise failures[0]
        require(not error,'Render command/container outcome is unconfirmed; retained evidence needs IT review')
