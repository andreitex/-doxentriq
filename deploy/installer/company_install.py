"""Trusted packaged foundation worker. Full installation is deliberately unfinished."""
import argparse
import base64
from contextlib import ExitStack, contextmanager
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from types import ModuleType
import uuid

TRUSTED_CODE = {}  # @TRUSTED_CODE@
COMPANY_FINGERPRINT = '@COMPANY_FINGERPRINT@'
BASE = Path('/opt/autosoft-company')
FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C','HOME':'/','TZ':'UTC'}
UNKNOWN = []
CAP = 4*1024**2

class FoundationUnavailable(ValueError):pass
def require(value):
    if value is not True:raise FoundationUnavailable('company-foundation-unavailable')
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(info):return tuple(getattr(info,key) for key in FIELDS)
def path(value):
    require(type(value) is str and re.fullmatch('/[A-Za-z0-9_./-]+',value) is not None)
    p=PurePosixPath(value);require(p.as_posix() == value and value != '/' and '..' not in p.parts);return value

def validate(request, fingerprint=COMPANY_FINGERPRINT):
    names={'schemaVersion','mode','operationId','releaseSha256','bundleRoot','sourceRoot','keyPath',
           'dataDir','backingFile','capacityGiB','runscVersion','runscSha512'}
    require(type(request) is dict and set(request) == names)
    require(type(request['schemaVersion']) is int and request['schemaVersion'] == 1 and request['mode'] == 'foundation-only')
    for key,pattern in (('operationId','[a-f0-9]{32}'),('releaseSha256','[a-f0-9]{64}'),
                        ('runscVersion','[0-9]{8}\\.[0-9]+'),('runscSha512','[a-f0-9]{128}')):
        require(type(request[key]) is str and re.fullmatch(pattern,request[key]) is not None)
    require(type(fingerprint) is str and re.fullmatch('[a-f0-9]{64}',fingerprint) is not None)
    for key in ('bundleRoot','sourceRoot','keyPath','dataDir','backingFile'):path(request[key])
    require(type(request['capacityGiB']) is int and 32 <= request['capacityGiB'] <= 4096)
    data=request['dataDir'];backing=request['backingFile']
    require(data.startswith('/srv/') and not data.startswith('/srv/autosoft-company/') and not backing.startswith(data+'/')
        and backing != data and not data.startswith(str(BASE)+'/'))
    require(all(request[key].startswith(str(BASE)+'/incoming/') for key in ('bundleRoot','sourceRoot')))
    require(request['keyPath'].startswith(str(BASE)+'/bootstrap/') and request['keyPath'].endswith('.pem'))
    require(not request['bundleRoot'].startswith(data+'/') and not request['sourceRoot'].startswith(data+'/'))
    return dict(request)

def load_trusted(records=TRUSTED_CODE):
    require(type(records) is dict and set(records) == {'verify-release.py','installer_materialize.py','installer_parent.py'})
    result={}
    for name,row in records.items():
        require(type(row) is dict and set(row) == {'sha256','bytes','base64'} and type(row['bytes']) is int and 0 < row['bytes'] <= 131072)
        raw=base64.b64decode(row['base64'],validate=True);require(len(raw) == row['bytes'] and sha(raw) == row['sha256'])
        module=ModuleType('trusted_company_'+name.replace('-','_').replace('.','_'));module.__file__='<trusted embedded '+name+'>'
        sys.modules[module.__name__]=module
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
        result[name]=module
    return result

class NativeState:
    """Finite protected native paths; no repairs, overwrites, deletion or adoption."""
    def __init__(self):require(os.name == 'posix' and os.geteuid() == os.getegid() == 0 and not UNKNOWN)
    def protected(self,p,directory=False):
        info=Path(p).lstat();require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode)
            and info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode)&0o022)
        if not directory:require(info.st_nlink == 1)
        return info
    def ancestors(self,p):
        for value in reversed(Path(p).parents):self.protected(value,True)
    def read(self,p,maximum=131072):
        p=Path(p);self.ancestors(p);before=self.protected(p);require(0 < before.st_size <= maximum)
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            require(identity(os.fstat(fd)) == identity(before));raw=bytearray()
            while len(raw) <= maximum:
                block=os.read(fd,min(65536,maximum+1-len(raw)))
                if not block:break
                raw.extend(block)
            require(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before) == identity(self.protected(p)))
            return bytes(raw)
        finally:
            try:os.close(fd)
            except BaseException:UNKNOWN.append((self,fd));raise
    def mkdir(self,p,mode=0o700):
        p=Path(p);self.ancestors(p);require(not os.path.lexists(p));os.mkdir(p,mode)
        require(stat.S_IMODE(self.protected(p,True).st_mode) == mode);self.sync(p);self.sync(p.parent)
    def sync(self,p):
        fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:
            try:os.close(fd)
            except BaseException:UNKNOWN.append((self,fd));raise
    def write(self,p,raw):
        p=Path(p);require(type(raw) is bytes and 0 < len(raw) <= 131072);self.ancestors(p)
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            offset=0
            while offset < len(raw):
                count=os.write(fd,raw[offset:offset+65536]);require(type(count) is int and count > 0);offset+=count
            os.fsync(fd)
        finally:
            try:os.close(fd)
            except BaseException:UNKNOWN.append((self,fd));raise
        self.sync(p.parent);require(self.read(p) == raw)
    def exists(self,p):return os.path.lexists(p)
    def names(self,p):return sorted(os.listdir(p))
    def observe_directory(self,p):
        p=Path(p);self.ancestors(p);before=p.lstat();require(stat.S_ISDIR(before.st_mode))
        fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd);require(identity(info)[:5] == identity(before)[:5] == identity(p.lstat())[:5]);return info
        finally:
            try:os.close(fd)
            except BaseException:UNKNOWN.append((self,fd));raise
    def journal_gid(self):
        import grp
        return grp.getgrnam('systemd-journal').gr_gid

class NativeRunner:
    """Single-thread pipe capture; sole reaper retains leader until group termination."""
    def __init__(self):
        require(os.name == 'posix' and hasattr(os,'waitid') and hasattr(os,'WNOWAIT') and hasattr(os,'pidfd_open') and not UNKNOWN)
        require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
        self.deadline=time.monotonic()+3600;self.calls=0
    def run(self,argv,timeout=600):
        require(not UNKNOWN and type(argv) is list and 0 < len(argv) <= 32 and type(timeout) is int and 0 < timeout <= 1800)
        require(all(type(arg) is str and 0 < len(arg.encode()) <= 65536 and '\x00' not in arg for arg in argv)
            and sum(len(arg.encode())+1 for arg in argv) <= 131072 and argv[0] in ('/bin/bash','/usr/bin/python3','/usr/bin/findmnt',
                '/usr/bin/systemctl','/usr/bin/docker','/usr/sbin/cryptsetup','/usr/sbin/losetup','/usr/sbin/swapon','/usr/bin/systemd-escape','/usr/local/bin/runsc'))
        require(time.monotonic() < self.deadline);self.calls+=1;require(self.calls <= 48)
        process=None;pidfd=None;selector=None;streams=[];buffers={};failed=False;known=False;released=False
        end=min(self.deadline,time.monotonic()+timeout)
        try:
            process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env=ENV,cwd='/',close_fds=True,start_new_session=True)
            streams=[process.stdout,process.stderr];buffers={'stdout':bytearray(),'stderr':bytearray()}
            pidfd=os.pidfd_open(process.pid);selector=selectors.DefaultSelector()
            for label,stream in (('stdout',process.stdout),('stderr',process.stderr)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,label)
            while selector.get_map():
                require(time.monotonic() < end)
                for key,_ in selector.select(min(0.05,max(0,end-time.monotonic()))):
                    raw=os.read(key.fileobj.fileno(),65536)
                    if not raw:selector.unregister(key.fileobj)
                    else:buffers[key.data].extend(raw);require(len(buffers[key.data]) <= CAP)
                status=os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if status is not None and status.si_pid == process.pid:
                    known=True;break
            if not known:
                while time.monotonic() < end:
                    status=os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                    if status is not None and status.si_pid == process.pid:known=True;break
                    time.sleep(0.01)
            require(known)
        except BaseException:failed=True
        finally:
            if process is not None:
                try:
                    # Ownership remains unreaped here even on direct success.
                    require(process.returncode is None)
                    os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except BaseException:failed=True;UNKNOWN.append((self,process,pidfd))
                try:process.wait(timeout=5);released=True
                except BaseException:failed=True;UNKNOWN.append((self,process,pidfd,streams,selector))
                if released:
                    try:os.killpg(process.pid,0);failed=True;UNKNOWN.append((self,process,pidfd))
                    except ProcessLookupError:pass
                    except BaseException:failed=True;UNKNOWN.append((self,process,pidfd))
            if selector is not None and released:
                try:
                    end=time.monotonic()+5
                    while selector.get_map() and time.monotonic() < end:
                        for key,_ in selector.select(0.05):
                            raw=os.read(key.fileobj.fileno(),65536)
                            if not raw:selector.unregister(key.fileobj)
                            else:buffers[key.data].extend(raw);require(len(buffers[key.data]) <= CAP)
                    require(not selector.get_map())
                except BaseException:failed=True
            for item in (*streams,selector):
                if item is not None:
                    try:item.close()
                    except BaseException:failed=True;UNKNOWN.append((self,item))
            if pidfd is not None and released:
                try:os.close(pidfd)
                except BaseException:failed=True;UNKNOWN.append((self,pidfd))
        require(not failed and released and known and not UNKNOWN and type(process.returncode) is int and process.returncode == 0)
        return bytes(buffers['stdout'])

class NativeOutputFiles:
    """Read-only finite tree backend. Every successful open transfers to the guard."""
    def __init__(self):require(os.name == 'posix' and os.geteuid() == os.getegid() == 0 and not UNKNOWN)
    def stat(self,p):return os.lstat(p)
    def open(self,p,directory):return os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_DIRECTORY if directory else 0))
    def fstat(self,fd):return os.fstat(fd)
    def read(self,fd,amount,offset):return os.pread(fd,amount,offset)
    def names(self,fd):return os.listdir(fd)
    def close(self,fd):os.close(fd)

class PersistedOutput:
    """Hold exact62 files, five tree directories and all ancestors through effects."""
    def __init__(self,held,root,catalog,*,files=None,clock=time.monotonic):
        self.held=held;self.root=Path(root);self.files=files or NativeOutputFiles();self.clock=clock
        self.active=True;self.unknown=False;self.owned=[];self.records={};self.expected={};self.started=self.clock()
        try:
            require(not UNKNOWN);held.recheck();require(self.root.is_absolute())
            for group,attribute,count in (('sources','SOURCES',44),('templates','TEMPLATES',10),('configs','CONFIGS',5),('provenance','PROVENANCE',3)):
                allowed=getattr(catalog,attribute);captured=getattr(held,group)
                require(type(allowed) is tuple and len(allowed) == count and len(set(allowed)) == count
                    and isinstance(captured,Mapping) and set(captured) == set(allowed))
                for name in allowed:
                    require(type(name) is str and not name.startswith('/') and '..' not in PurePosixPath(name).parts
                        and PurePosixPath(name).as_posix() == name and '\\' not in name)
                    raw=captured[name];require(type(raw) is bytes and 0 < len(raw) <= 1024**2)
                    relative=name if group in ('sources','templates') else 'company-release/'+name
                    require(relative not in self.expected);self.expected[relative]=raw
            require(len(self.expected) == 62 and sum(map(len,self.expected.values())) <= 20*1024**2)
            ancestors=tuple(reversed(self.root.parents));require(len(ancestors) <= 32)
            for p in ancestors:self._open(p,True,False)
            for name in ('','scripts','deploy','deploy/config','company-release'):self._open(self.root/name,True,True)
            for name in sorted(self.expected):self._open(self.root/name,False,True)
            self.recheck()
        except BaseException:
            self.active=False;self.close();raise
    def _tick(self):require(self.clock()-self.started < 60 and self.active and not self.unknown and not UNKNOWN)
    def _open(self,p,directory,tree):
        self._tick();before=self.files.stat(p)
        require((stat.S_ISDIR if directory else stat.S_ISREG)(before.st_mode) and before.st_uid == before.st_gid == 0
            and not stat.S_IMODE(before.st_mode)&0o022)
        if tree:require(stat.S_IMODE(before.st_mode) == (0o500 if directory else 0o400))
        if directory:require(0 <= before.st_size <= 65536)
        else:require(before.st_nlink == 1 and before.st_size == len(self.expected[str(p.relative_to(self.root))]))
        fd=self.files.open(p,directory);self.owned.append(fd) # Before first fstat or content read.
        opened=self.files.fstat(fd);require(identity(before) == identity(opened) == identity(self.files.stat(p)))
        self.records[p]=(fd,identity(before),directory)
    def _guard(self,p):
        try:
            self._tick();fd,expected,_=self.records[p]
            require(identity(self.files.stat(p)) == identity(self.files.fstat(fd)) == expected)
            return fd
        except BaseException:self.active=False;raise
    def names(self,p):
        p=Path(p);fd=self._guard(p);require(self.records[p][2])
        names=self.files.names(fd)
        require(type(names) is list and len(names) <= 64 and all(type(name) is str and '/' not in name and '\\' not in name and name not in ('','.', '..') for name in names)
            and len(set(names)) == len(names))
        self._guard(p);return sorted(names)
    def read(self,p,maximum=1024**2):
        p=Path(p);fd=self._guard(p);require(not self.records[p][2])
        expected=self.expected[str(p.relative_to(self.root))];require(len(expected) <= maximum);raw=bytearray()
        while len(raw) <= len(expected):
            self._tick();part=self.files.read(fd,min(65536,len(expected)+1-len(raw)),len(raw))
            require(type(part) is bytes and len(part) <= min(65536,len(expected)+1-len(raw)))
            if not part:break
            raw.extend(part)
        self._guard(p);require(bytes(raw) == expected);return bytes(raw)
    def recheck(self):
        self.started=self.clock()
        try:
            self._tick();self.held.recheck()
            for p in self.records:self._guard(p)
            result=inventory(self,self.root,self.held)
            for p in self.records:self._guard(p)
            self.held.recheck();self._tick();return result
        except BaseException:self.active=False;raise
    def close(self):
        failed=False
        for fd in reversed(tuple(self.owned)):
            try:self.files.close(fd);self.owned.remove(fd)
            except BaseException:failed=True;self.unknown=True;UNKNOWN.append((self.files,fd))
        self.active=False
        require(not failed and not self.unknown)

@contextmanager
def persisted_output(held,root,catalog,*,files=None,clock=time.monotonic):
    output=PersistedOutput(held,root,catalog,files=files,clock=clock)
    try:
        yield output
        output.recheck()
    finally:output.close()

def roots(request):
    op=request['operationId'];data=Path(request['dataDir'])
    return BASE/'staging',data/'company/host-releases',data/'company/host-releases'/('install-'+op),BASE/'evidence'/op

def phase_command(held,name,execution_root,final_root,request):
    require(name in ('packages','storage','prepare','activate'))
    install=held.sources['scripts/install.sh']
    require(install.startswith(b'#!/usr/bin/env bash\n# Candidate phase definitions only.')
            and all(install.count(('company_'+phase+'_phase() {').encode()) == 1 for phase in ('packages','storage','prepare','activate')))
    # Package code runs from signed captured bytes before full-nine output capture.
    raw=b'\n'.join(held.sources[key] for key in ('scripts/lib.sh','scripts/install-runtime-gate.sh'))+b'\n'+install
    require(len(raw) < 65536)
    call='\ncompany_'+name+'_phase "$@"\n'
    return ['/bin/bash','--noprofile','--norc','-c',raw.decode()+call,'company-foundation',
            str(execution_root),str(final_root),request['dataDir'],request['backingFile'],str(request['capacityGiB']),
            request['runscVersion'],request['runscSha512']]

def inventory(state,root,held):
    expected={name:raw for group in (held.sources,held.templates) for name,raw in group.items()}
    expected.update({'company-release/'+name:raw for group in (held.configs,held.provenance) for name,raw in group.items()})
    require(len(expected) == 62)
    parents={Path(''),Path('scripts'),Path('deploy'),Path('deploy/config'),Path('company-release')}
    for parent in parents:
        names={Path(name).relative_to(parent).parts[0] for name in expected if parent == Path('') or parent in Path(name).parents}
        require(state.names(Path(root)/parent) == sorted(names))
    for name,raw in expected.items():require(state.read(Path(root)/name,1024**2) == raw)
    return sha(canonical({name:{'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(expected.items())}))

def measure(state,runner,request,final_root,held,*,output=None):
    data=Path(request['dataDir']);host=Path('/etc/autosoft')
    records={name:json.loads(state.read(host/name)) for name in ('installation.intent.json','installation.json','installation.storage-receipt.json')}
    require(not state.exists(host/'installation.pending.json') and not state.exists(host/'installation.complete'))
    intent=records['installation.intent.json'];final=records['installation.json'];receipt=records['installation.storage-receipt.json']
    require(type(intent) is dict and set(intent) == {'schemaVersion','scope','installation_id','directory','proposal'}
        and type(intent['schemaVersion']) is int and intent['schemaVersion'] == 1 and intent['scope'] == 'HOST_INSTALLATION_IDENTITY_ONLY')
    host_info=state.observe_directory(host)
    require(host_info.st_uid == host_info.st_gid == 0 and stat.S_IMODE(host_info.st_mode) == 0o700
        and intent['directory'] == {key:str(getattr(host_info,key)) for key in FIELDS[:5]})
    require(type(final) is dict and set(final) == {'data_dir','install_root','storage_file','installation_id'}
        and type(receipt) is dict and set(receipt) == set(final)|{'creation_stage','luks_uuid'} and receipt['creation_stage'] == 'new-luks-created')
    wanted={'data_dir':str(data),'install_root':str(final_root),'storage_file':request['backingFile'],'capacity_gib':request['capacityGiB']}
    require(type(intent['proposal']) is dict and intent['proposal'] == wanted and type(intent['installation_id']) is str and str(uuid.UUID(intent['installation_id'])) == intent['installation_id'])
    require(final == {key:receipt[key] for key in ('data_dir','install_root','storage_file','installation_id')})
    require(all(final[key] == wanted[key] for key in ('data_dir','install_root','storage_file')) and final['installation_id'] == intent['installation_id'])
    actual_uuid=runner.run(['/usr/sbin/cryptsetup','luksUUID',request['backingFile']],30).decode().strip();require(actual_uuid == receipt['luks_uuid'])
    require(str(uuid.UUID(actual_uuid)) == actual_uuid)
    status=runner.run(['/usr/sbin/cryptsetup','status','autosoft-data'],30).decode().splitlines()
    properties={key.strip():value.strip() for line in status for key,sep,value in [line.partition(':')] if sep}
    require(properties.get('type') == 'LUKS2' and re.fullmatch('/dev/loop[0-9]{1,10}',properties.get('device','')) is not None)
    require(runner.run(['/usr/sbin/losetup','--noheadings','--output','BACK-FILE','--',properties['device']],30).decode().strip() == request['backingFile'])
    mount=runner.run(['/usr/bin/findmnt','-n','-o','TARGET,SOURCE,FSTYPE,OPTIONS','--target',str(data)],30).decode().strip().split()
    require(len(mount) == 4 and mount[0] == str(data) and mount[1] == '/dev/mapper/autosoft-data' and mount[2] == 'xfs'
            and {'rw','nosuid','nodev'} <= set(mount[3].split(',')) and bool({'prjquota','pquota'} & set(mount[3].split(','))))
    require(state.exists(data/'.autosoft-encrypted'))
    docker=json.loads(state.read('/etc/docker/daemon.json'));require(docker['data-root'] == str(data/'docker') and docker['log-driver'] == 'journald' and 'runsc' in docker['runtimes'])
    require('root = "'+str(data/'containerd')+'"' in state.read('/etc/containerd/config.toml').decode())
    require(runner.run(['/usr/bin/docker','info','--format','{{.DockerRootDir}}'],30).decode().strip() == str(data/'docker'))
    require(runner.run(['/usr/bin/docker','info','--format','{{.LoggingDriver}}'],30).decode().strip() == 'journald')
    require('runsc' in json.loads(runner.run(['/usr/bin/docker','info','--format','{{json .Runtimes}}'],30)))
    for unit in ('docker.service','containerd.service'):
        require(runner.run(['/usr/bin/systemctl','is-active',unit],30).decode().strip() == 'active')
        expected=f'[Unit]\nRequiresMountsFor={data}\nRequires=var-log-journal.mount\nAfter=systemd-cryptsetup@autosoft\\x2ddata.service var-log-journal.mount\n[Service]\nExecStartPre=/bin/bash {final_root}/scripts/storage-guard.sh\n'
        require(state.read('/etc/systemd/system/'+unit+'.d/autosoft-storage.conf') == expected.encode())
    builds_unit=runner.run(['/usr/bin/systemd-escape','--path','--suffix=mount',str(data/'runtime/builds')],30).decode().strip()
    require(re.fullmatch('[A-Za-z0-9_.\\\\-]+\\.mount',builds_unit) is not None)
    require(state.read('/etc/systemd/system/docker.service.d/autosoft-builds.conf') == f'[Unit]\nRequires={builds_unit}\nAfter={builds_unit}\n'.encode())
    builds=runner.run(['/usr/bin/findmnt','-n','-o','TARGET,FSTYPE,OPTIONS','--target',str(data/'runtime/builds')],30).decode().strip().split()
    require(len(builds) == 3 and builds[:2] == [str(data/'runtime/builds'),'tmpfs'] and {'nosuid','nodev','uid=10001','gid=10001','mode=700'} <= set(builds[2].split(',')))
    size=runner.run(['/usr/bin/findmnt','-n','-o','SIZE','--bytes','--target',str(data/'runtime/builds')],30).decode().strip()
    require(size.isascii() and size.isdecimal() and 0 < int(size) <= 2147483648)
    journal=runner.run(['/usr/bin/findmnt','-n','-o','TARGET,SOURCE,FSTYPE','--target','/var/log/journal'],30).decode().strip().split()
    journal_info=state.observe_directory(data/'journal');mounted_info=state.observe_directory('/var/log/journal')
    require(len(journal) == 3 and journal[0] == '/var/log/journal' and journal[2] == 'xfs'
        and journal[1] == '/dev/mapper/autosoft-data[/journal]' and journal_info.st_dev == mounted_info.st_dev == state.observe_directory(data).st_dev
        and stat.S_ISDIR(journal_info.st_mode) and journal_info.st_uid == 0
        and journal_info.st_gid == state.journal_gid() and stat.S_IMODE(journal_info.st_mode) == 0o2755)
    require(state.read('/etc/autosoft/runtime-bootstrap.ready') == b'encrypted-runtime-bootstrap-v1\n')
    installed=json.loads(state.read('/etc/autosoft/runtime-installed.json'));require(installed == {'version':request['runscVersion'],'archive_sha512':request['runscSha512']})
    archive=state.read(data/'company/work/gvisor.tar.zstd',128*1024**2);require(hashlib.sha512(archive).hexdigest() == request['runscSha512'])
    runtime=runner.run(['/usr/bin/python3','-I','-B','-c',RUNTIME_IDENTITY,str(data/'company/work/gvisor.tar.zstd'),request['runscSha512']],60)
    binary_pins=json.loads(runtime);require(type(binary_pins) is dict and set(binary_pins) in (set(RUNTIME_PRIMARY_FILES),set(RUNTIME_PRIMARY_FILES+RUNTIME_SIDECAR_FILES))
        and all(type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None for value in binary_pins.values()))
    version=runner.run(['/usr/local/bin/runsc','--version'],30);require(version and len(version) <= 4096)
    require('MaxRetentionSec=7day' in state.read('/etc/systemd/journald.conf.d/autosoft.conf').decode())
    require(not any(line.split()[2] == 'swap' for line in state.read('/etc/fstab').decode().splitlines() if line.strip() and not line.lstrip().startswith('#') and len(line.split()) >= 3))
    require(runner.run(['/usr/sbin/swapon','--noheadings','--show'],30).strip() == b'')
    return {'scope':'FOUNDATION_ONLY','status':'effects-independently-confirmed','operationId':request['operationId'],
        'installationId':final['installation_id'],'releaseSha256':held.metadata['releaseSha256'],'treeSha256':output.recheck() if output is not None else inventory(state,final_root,held),
        'hostSha256':sha(canonical(records)),'runscVersionSha256':sha(version),'runtimeBinaryPins':binary_pins,'fullPlatformActivated':False,'backupReady':False,'runtimePairInitialized':False}

RUNTIME_PRIMARY_FILES = ('runsc', 'containerd-shim-runsc-v1')
RUNTIME_SIDECAR_FILES = ('gvisor-bin/checkpointgofer', 'gvisor-bin/gvisor-sentry-prewarmer',
    'gvisor-bin/gvisor_sentry', 'gvisor-bin/runsc-fd-parking', 'gvisor-bin/runsc-metric-server')

# The complete pinned archive determines whether this is a legacy two-file
# release or the supported sidecar layout. Never ignore an unmeasured sidecar.
RUNTIME_IDENTITY = 'PRIMARY='+repr(RUNTIME_PRIMARY_FILES)+'\nSIDECARS='+repr(RUNTIME_SIDECAR_FILES)+'\n'+r'''
import contextlib,fcntl,hashlib,json,os,re,stat,subprocess,sys,tarfile
KEYS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def identity(info):return tuple(getattr(info,key) for key in KEYS)
def close_all(fds):
 failed=False
 for fd in reversed(fds):
  try:os.close(fd)
  except OSError:failed=True
 assert not failed
@contextlib.contextmanager
def pinned_archive(path,expected):
 assert os.geteuid()==os.getegid()==0 and re.fullmatch('[a-f0-9]{128}',expected)
 assert path.startswith('/') and all(part not in ('','.','..') for part in path[1:].split('/'))
 owned=[];directories=[]
 def check():
  for fd,name,before in directories:assert identity(os.fstat(fd))==before==identity(os.lstat(name))
  assert identity(os.fstat(archive))==original==identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False))
 try:
  parent=None;current=''
  for part in ('/',*path[1:].split('/')[:-1]):
   current='/' if part=='/' else current.rstrip('/')+'/'+part
   before=os.lstat(current)
   assert stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0 and not before.st_mode&0o022
   fd=os.open(current if parent is None else part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
   owned.append(fd);directories.append((fd,current,identity(before)));parent=fd
   assert identity(os.fstat(fd))==identity(before)
  leaf=path.rsplit('/',1)[1];before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
  assert stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
  assert not before.st_mode&0o022 and 0<before.st_size<=128*1024**2
  archive=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);owned.append(archive)
  original=identity(before);check()
  captured=os.memfd_create('doxentriq-runtime-archive',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);owned.append(captured)
  digest=hashlib.sha512();size=0
  while size<before.st_size:
   raw=os.pread(archive,min(65536,before.st_size-size),size);assert raw
   digest.update(raw);size+=len(raw);view=memoryview(raw)
   while view:
    written=os.write(captured,view);assert written>0;view=view[written:]
  assert digest.hexdigest()==expected and not os.pread(archive,1,size)
  check()
  seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE
  fcntl.fcntl(captured,fcntl.F_ADD_SEALS,seals);assert fcntl.fcntl(captured,fcntl.F_GET_SEALS)==seals
  os.lseek(captured,0,os.SEEK_SET)
  yield captured
  check()
  final=hashlib.sha512();offset=0
  while offset<size:
   raw=os.pread(archive,min(65536,size-offset),offset);assert raw
   final.update(raw);offset+=len(raw)
  assert final.hexdigest()==expected and not os.pread(archive,1,offset)
  check()
 finally:close_all(owned)
def verify_stream(stream,root='/usr/local/bin'):
 assert os.geteuid()==os.getegid()==0 and root.startswith('/') and root!='/'
 assert all(part not in ('','.','..') for part in root[1:].split('/'))
 held=[];leaves=[];owned=[];rows={};seen=set();total=0;sidecars=False
 def hold(path,parent=None,name=None):
  before=os.lstat(path) if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
  assert stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0 and not before.st_mode&0o022
  fd=os.open(path if parent is None else name,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=parent)
  owned.append(fd)
  held.append((fd,path,identity(before)))
  assert identity(os.fstat(fd))==identity(before)
  return fd
 def check():
  for fd,path,before in held:assert identity(os.fstat(fd))==before==identity(os.lstat(path))
  for fd,parent,name,before,size,digest in leaves:
   assert identity(os.fstat(fd))==before==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
 def read_digest(fd,size):
  digest=hashlib.sha256();offset=0
  while offset<size:
   raw=os.pread(fd,min(65536,size-offset),offset);assert raw
   offset+=len(raw);digest.update(raw)
  assert not os.pread(fd,1,size)
  return digest.hexdigest()
 def file_digest(parent,name,expected_size):
  before=os.stat(name,dir_fd=parent,follow_symlinks=False)
  assert stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
  assert stat.S_IMODE(before.st_mode)==0o755 and before.st_size==expected_size
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
  owned.append(fd)
  old=identity(before);assert old==identity(os.fstat(fd))
  digest=read_digest(fd,expected_size)
  leaves.append((fd,parent,name,old,expected_size,digest));check()
  return digest
 class Bounded:
  def __init__(self,source):self.source=source;self.size=0
  def read(self,size):
   assert isinstance(size,int) and size>=0
   raw=self.source.read(min(size,65536));self.size+=len(raw)
   assert self.size<=512*1024**2+128*1024
   return raw
 bounded=Bounded(stream)
 try:
  parent=hold('/');path=''
  for part in root[1:].split('/'):
   path+='/'+part;parent=hold(path,parent,part)
  root_fd=parent;sidecar_fd=None
  with tarfile.open(fileobj=bounded,mode='r|') as tar:
   for member in tar:
    name=member.name.removeprefix('./')
    assert name not in seen and len(seen)<8 and not member.linkname and member.sparse is None
    assert member.mode==0o755
    seen.add(name);check()
    if name=='gvisor-bin':
     assert member.isdir() and member.size==0
     sidecar_fd=hold(root+'/gvisor-bin',root_fd,'gvisor-bin');sidecars=True
     continue
    assert name in PRIMARY+SIDECARS and member.isfile() and 0<member.size<=256*1024**2
    if name in SIDECARS:
     if sidecar_fd is None:sidecar_fd=hold(root+'/gvisor-bin',root_fd,'gvisor-bin')
     sidecars=True;file_parent=sidecar_fd;basename=name.split('/')[1]
    else:file_parent=root_fd;basename=name
    source=tar.extractfile(member);digest=hashlib.sha256();amount=0
    while True:
     raw=source.read(65536)
     if not raw:break
     amount+=len(raw);total+=len(raw);assert amount<=member.size and total<=512*1024**2;digest.update(raw)
    source.close();assert amount==member.size
    assert file_digest(file_parent,basename,member.size)==digest.hexdigest()
    rows[name]=digest.hexdigest();check()
  while bounded.read(65536):pass
  expected=set(PRIMARY+SIDECARS) if sidecars else set(PRIMARY)
  assert set(rows)==expected and seen==(expected|{'gvisor-bin'} if sidecars else expected)
  if sidecars:assert set(os.listdir(sidecar_fd))=={name.split('/')[1] for name in SIDECARS}
  else:assert not os.path.lexists(root+'/gvisor-bin')
  for fd,_,_,_,size,digest in leaves:
   check();assert read_digest(fd,size)==digest
  check();return rows
 finally:close_all(owned)
def decode_archive(archive):
 p=subprocess.Popen(['/usr/bin/zstd','-dc'],stdin=archive,stdout=subprocess.PIPE,
     stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'},cwd='/',close_fds=True)
 try:
  rows=verify_stream(p.stdout)
  assert p.wait(timeout=5)==0
  return rows
 finally:
  if p.stdout is not None:p.stdout.close()
  if p.returncode is None:p.kill();p.wait(timeout=5)
def main():
 assert len(sys.argv)==3
 with pinned_archive(sys.argv[1],sys.argv[2]) as archive:rows=decode_archive(archive)
 print(json.dumps(rows,sort_keys=True))
if __name__=='__main__':main()
'''

class Worker:
    def __init__(self,modules,state,runner,*,output_guard=persisted_output):
        self.modules,self.state,self.runner,self.output_guard=modules,state,runner,output_guard
    def run(self,request,parent_input,*,verify=False):
        request=validate(request,COMPANY_FINGERPRINT);stage_parent,final_parent,final_root,evidence=roots(request)
        P=self.modules['installer_parent.py'];V=self.modules['verify-release.py'];M=self.modules['installer_materialize.py']
        with P.hold_parent(parent_input) as parent, V.authenticated_deployment(request['bundleRoot'],request['keyPath'],COMPANY_FINGERPRINT,
            expected_architecture='x86_64',source_root=request['sourceRoot']) as held:
            require(held.metadata['releaseSha256'] == request['releaseSha256'])
            def check():require(not UNKNOWN);parent.check();held.recheck()
            check()
            if verify:
                with self.output_guard(held,final_root,M) as output:
                    output.recheck();retained=json.loads(self.state.read(evidence/'result.json'))
                    measured=measure(self.state,self.runner,request,final_root,held,output=output)
                    require(retained == measured);check();output.recheck()
            else:
                for name in ('installation.intent.json','installation.json','installation.pending.json','storage.key'):
                    require(not self.state.exists(Path('/etc/autosoft')/name))
                require(not self.state.exists(evidence) and not self.state.exists(final_root))
                self.state.mkdir(evidence);self.state.write(evidence/'intent.json',canonical(request));check()
                self.runner.run(phase_command(held,'packages',stage_parent,final_root,request),1800);check()
                with M.materialized_deployment(held,stage_parent,'install-'+request['operationId']) as staged:
                    staged.recheck();check()
                    self.runner.run(phase_command(held,'storage',staged.root,final_root,request),900);staged.recheck();check()
                    self.runner.run(phase_command(held,'prepare',staged.root,final_root,request),600);staged.recheck();check()
                    # prepare completes every DATA direct-child creation before this stricter guard.
                    with M.materialized_deployment(held,final_parent,'install-'+request['operationId']) as final:
                        final.recheck();check()
                        self.runner.run(phase_command(held,'activate',final.root,final_root,request),240);final.recheck();check()
                        with self.output_guard(held,final_root,M) as output:
                            output.recheck();measured=measure(self.state,self.runner,request,final_root,held,output=output)
                            output.recheck();final.recheck();check()
                    staged.recheck();check()
                check();self.state.write(evidence/'result.json',canonical(measured));check()
        require(not UNKNOWN) # Every independent held close has completed before acknowledgement.
        if verify:self.state.write(evidence/'verified',f"foundation-verified-v1\noperation={request['operationId']}\noutcome={sha(canonical(measured))}\n".encode())
        return measured

def main(argv=None):
    require(os.name == 'posix' and os.geteuid() == os.getegid() == 0 and sys.flags.isolated == 1 and sys.dont_write_bytecode)
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True);choice.add_argument('--foundation-only',action='store_true');choice.add_argument('--verify',action='store_true');choice.add_argument('--describe',action='store_true')
    parser.add_argument('--request',required=True);parser.add_argument('--worker-sha',required=True);parser.add_argument('--parent',nargs=7)
    args=parser.parse_args(argv);state=NativeState()
    require(type(args.worker_sha) is str and re.fullmatch('[a-f0-9]{64}',args.worker_sha) is not None and sha(state.read(Path(__file__),262144)) == args.worker_sha)
    raw=state.read(path(args.request),4096);request=validate(json.loads(raw),COMPANY_FINGERPRINT);require(canonical(request) == raw)
    if args.describe:require(args.parent is None);print(request['operationId']);return
    modules=load_trusted();parent=modules['installer_parent.py'].ParentInput.from_argv(args.parent)
    require(parent.request == sha(raw) and parent.stage == 'foundation' and parent.action == sha(f'foundation-v1:{sha(raw)}:{args.worker_sha}'.encode()))
    # Quiet fixed ancestors prepared before either materializer. No chmod/adoption.
    for p in (BASE,BASE/'bootstrap',BASE/'incoming',BASE/'staging',BASE/'evidence'):
        info=state.protected(p,True);require(stat.S_IMODE(info.st_mode) == 0o700)
    result=Worker(modules,state,NativeRunner()).run(request,parent,verify=args.verify)
    print(sha(canonical(result)))

if __name__ == '__main__':
    try:main()
    except BaseException:
        print('company-foundation-unavailable; preserve partial effects and admission evidence',file=sys.stderr);sys.exit(74)
