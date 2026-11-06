"""Portable injected source controls; no native FS/Git/VM or installer dispatch."""
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from types import SimpleNamespace, ModuleType
import unittest
import uuid
import zlib

ROOT=Path(__file__).resolve().parents[1]
source=ROOT/'scripts/bootstrap.py'
tree=ast.parse(source.read_bytes())
selected=[]
for node in tree.body:
    if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and (node.name.startswith(('_seed_','Seed')) or node.name in ('authenticated_seed_request','seed_authenticated_repository','confirm_authenticated_seed','seed_repository')):
        selected.append(node)
    elif isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id.startswith('SEED_') for t in node.targets): selected.append(node)
B=ModuleType('authenticated_seed_test_source')
B.__dict__.update(hashlib=hashlib,json=json,Path=Path,re=re,stat=stat)
exec(compile(ast.Module(body=selected,type_ignores=[]),str(source),'exec'),B.__dict__)


class SeedBackend:
    def __init__(self):
        self.nodes={};self.handles={};self.next_fd=10;self.next_inode=10;self.tick=1
        self.effects=[];self.reads=[];self.close_attempts=[];self.fail_close=None;self.fail_sync=None
        self.after_create=None;self.after_write=None
        self.directory('/',mode=0o755)
    def info(self,directory,uid,gid,mode,size=0):
        self.next_inode+=1
        return dict(zip(B.SEED_FIELDS,(1,self.next_inode,(stat.S_IFDIR if directory else stat.S_IFREG)|mode,uid,gid,
            2 if directory else 1,size,self.tick,self.tick)))
    def directory(self,path,uid=0,gid=0,mode=0o700):
        if path in self.nodes:return
        parent=path.rsplit('/',1)[0] or '/'
        if path!='/':self.directory(parent,mode=0o755)
        self.nodes[path]=dict(info=self.info(True,uid,gid,mode),raw=None)
    def file(self,path,raw=b'',uid=0,gid=0,mode=0o600,size=None):
        self.directory(path.rsplit('/',1)[0] or '/')
        self.nodes[path]=dict(info=self.info(False,uid,gid,mode,len(raw) if size is None else size),raw=raw)
    def lstat(self,path):return dict(self.nodes[path]['info'])
    def open(self,path,kind):
        self.next_fd+=1;self.handles[self.next_fd]=self.nodes[path];return self.next_fd
    def fstat(self,fd):return dict(self.handles[fd]['info'])
    def inheritable(self,fd):return False
    def read(self,fd,maximum):
        self.reads.append(next((p for p,n in self.nodes.items() if n is self.handles[fd]),'<replaced>'))
        raw=self.handles[fd]['raw'];return raw if len(raw)<=maximum else raw[:maximum+1]
    def names(self,fd,maximum):
        node=self.handles[fd];path=next(p for p,n in self.nodes.items() if n is node)
        prefix=path+'/' if path!='/' else '/'
        answer=[p[len(prefix):] for p in self.nodes if p.startswith(prefix) and '/' not in p[len(prefix):] and p!=path]
        return answer
    def change(self,path):
        self.tick+=1;info=self.nodes[path]['info'];info['st_mtime_ns']=info['st_ctime_ns']=self.tick
        info['st_size']+=1
    def _new(self,fd,name,uid,gid,mode,directory):
        parent=next(p for p,n in self.nodes.items() if n is self.handles[fd]);path=parent+'/'+name
        if path in self.nodes:raise FileExistsError(path)
        self.nodes[path]=dict(info=self.info(directory,uid,gid,mode),raw=None if directory else b'')
        self.change(parent)
        if directory:self.nodes[parent]['info']['st_nlink']+=1
        self.effects.append(path);handle=self.open(path,'directory' if directory else 'file')
        if self.after_create:self.after_create(path)
        return handle
    def mkdir(self,fd,name,uid,gid,mode):return self._new(fd,name,uid,gid,mode,True)
    def create(self,fd,name,uid,gid,mode):return self._new(fd,name,uid,gid,mode,False)
    def write(self,fd,raw):
        node=self.handles[fd];node['raw']+=raw;node['info']['st_size']=len(node['raw'])
        self.tick+=1;node['info']['st_mtime_ns']=node['info']['st_ctime_ns']=self.tick
        if self.after_write:self.after_write(fd)
        return len(raw)
    def sync(self,fd):
        path=next(p for p,n in self.nodes.items() if n is self.handles[fd])
        if self.fail_sync and self.fail_sync in path:raise OSError('injected-sync')
    def close(self,fd):
        self.close_attempts.append(fd)
        if fd==self.fail_close:raise OSError('injected-close')
        del self.handles[fd]


def parse_index(raw):
    """Independent strict v2 parser: checksum, network order, flags and padding."""
    if raw[:4]!=b'DIRC' or hashlib.sha1(raw[:-20]).digest()!=raw[-20:]:raise ValueError('index')
    version,count=struct.unpack('!II',raw[4:12])
    if version!=2:raise ValueError('version')
    offset=12;rows=[]
    for _ in range(count):
        start=offset;fields=struct.unpack('!10I',raw[offset:offset+40]);offset+=40
        sha=raw[offset:offset+20].hex();offset+=20;flags=struct.unpack('!H',raw[offset:offset+2])[0];offset+=2
        end=raw.index(b'\0',offset);name=raw[offset:end];offset=end+1
        while (offset-start)%8:
            if raw[offset]!=0:raise ValueError('padding')
            offset+=1
        if flags!=len(name) or fields[6] not in (0o100644,0o100755):raise ValueError('flags')
        rows.append((name.decode(),format(fields[6],'o'),sha))
    if offset!=len(raw)-20 or [p for p,_,_ in rows]!=sorted(p for p,_,_ in rows):raise ValueError('tail/order')
    return rows


class SeedRunner:
    def __init__(self,backend):
        self.backend=backend;self.calls=[];self.active_unit=False;self.container=False;self.corrupt=None
        self.unknown=False;self.child_failure=False;self.lingering_pid=False;self.active_timer=False;self.corrupt_kind=None
    def object(self,repo,sha):
        raw=zlib.decompress(self.backend.nodes[repo+'/.git/objects/'+sha[:2]+'/'+sha[2:]]['raw'])
        header,data=raw.split(b'\0',1);kind,count=header.split(b' ')
        if int(count)!=len(data) or hashlib.sha1(raw).hexdigest()!=sha:raise ValueError('object')
        return kind.decode(),data
    def head(self,repo):
        ref=self.backend.nodes[repo+'/.git/HEAD']['raw'].decode().strip()[5:]
        return self.backend.nodes[repo+'/.git/'+ref]['raw'].decode().strip()
    def tree_child(self,repo,commit,path):
        kind,raw=self.object(repo,commit);sha=raw.splitlines()[0][5:].decode()
        for part in path.split('/'):
            _,raw=self.object(repo,sha);offset=0
            while offset<len(raw):
                end=raw.index(b'\0',offset);mode,name=raw[offset:end].split(b' ',1);oid=raw[end+1:end+21].hex();offset=end+21
                if name.decode()==part:sha=oid;break
            else:raise ValueError('tree child')
        return sha
    def run(self,argv,*,stdin,maximum,timeout,tool,environment):
        self.calls.append((list(argv),stdin,dict(environment),tool))
        out=b'';code=0
        if argv[0]=='/usr/bin/systemctl':
            active=self.active_unit or self.active_timer and argv[-1].endswith('.timer')
            values=dict(ActiveState='active' if active else 'inactive',SubState='running' if active else 'dead',
                MainPID='12' if self.lingering_pid else '0',ControlPID='0',ControlGroup='',LoadState='loaded')
            fields=[item.removeprefix('--property=') for item in argv if item.startswith('--property=')]
            out=''.join(name+'='+values[name]+'\n' for name in fields).encode()
        elif argv[0]=='/usr/bin/docker':out=b'f'*64+b'\n' if self.container else b''
        elif argv[0]=='/usr/bin/git':
            repo=next(x for x in argv if x.startswith('--work-tree='))[12:]
            args=argv[argv.index('--work-tree='+repo)+1:]
            if args==['cat-file','--batch']:
                for sha in stdin.decode().splitlines():
                    kind,raw=self.object(repo,sha);header=(sha+' '+kind+' '+str(len(raw))+'\n').encode()
                    if kind==self.corrupt_kind:raw=b'!'+raw[1:] if raw else b'!'
                    out+=header+raw+b'\n'
            elif args==['rev-parse','--verify','HEAD']:out=self.head(repo).encode()+b'\n'
            elif args==['ls-files','--stage','-z']:
                out=b''.join(f'{mode} {sha} 0\t{name}\0'.encode() for name,mode,sha in parse_index(self.backend.nodes[repo+'/.git/index']['raw']))
            elif args[0]=='merge-base':
                seed,current=args[-2:]
                _,raw=self.object(repo,current);code=0 if current==seed or b'parent '+seed.encode()+b'\n' in raw else 1
            elif args[0]=='rev-parse':out=b''.join((self.tree_child(repo,*item.split(':',1))+'\n').encode() for item in args[1:])
            else:raise AssertionError(args)
            if self.corrupt and self.corrupt in args:out=b'x'+out[1:]
        else:raise AssertionError(argv)
        return dict(exitCode=code if not self.child_failure else 1,stdout=out,stderr=b'',ownedReleased=not self.unknown)


def independent_source_tree(files,modes):
    """Bottom-up source tree oracle, independent of the seeder's recursive trie."""
    buckets={};directories={''}
    for path,raw in files.items():
        parent,_,name=path.rpartition('/');parts=parent.split('/') if parent else []
        directories.update('/'.join(parts[:n]) for n in range(1,len(parts)+1))
        oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).digest()
        buckets.setdefault(parent,[]).append((name.encode(),modes[path].encode(),oid,False))
    hashes={}
    for directory in sorted(directories,key=lambda p:(-p.count('/'),-len(p),p)):
        rows=buckets.get(directory,[])
        raw=b''.join(mode+b' '+name+b'\0'+oid for name,mode,oid,isdir in sorted(rows,key=lambda r:r[0]+(b'/' if r[3] else b'')))
        oid=hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest();hashes[directory]=oid
        if directory:
            parent,_,name=directory.rpartition('/');buckets.setdefault(parent,[]).append((name.encode(),b'40000',oid,True))
    return hashes[''].hex()


class HeldSource:
    def __init__(self):
        self.files={'scripts/bootstrap.py':b'fixed trusted bootstrap\n','package.json':b'{}\n','empty.txt':b'',
                    '.gitattributes':b'*.py filter=hostile\n','bin/run.sh':b'#!/bin/sh\nexit 0\n'}
        self.git_modes={name:'100755' if name.endswith('.sh') else '100644' for name in self.files}
        self.configs={name:b'{}' for name in B.SEED_CONFIGS};self.provenance={name:b'captured-'+name.encode() for name in B.SEED_PROVENANCE}
        self.metadata=dict(releaseSha256='a'*64,platformManifestSha256='b'*64,sourceRevision='c'*40,
            sourceTree=independent_source_tree(self.files,self.git_modes))
        self.live=True;self.calls=0


class HeldParent:
    def __init__(self):self.arguments=SimpleNamespace(stage='repository-seed',request='',action='');self.live=True;self.calls=0
    def check(self):
        self.calls+=1
        if not self.live:raise ValueError('parent dead')


def identity_module():
    path=ROOT/'scripts/installation_identity.py';tree=ast.parse(path.read_bytes())
    names={'installation_id','path_value','proposal','_intent','verify_reference'}
    module=ModuleType('seed_identity_pure_test')
    def fields(v,n):
        B._seed_require(type(v) is dict and set(v)==set(n));return v
    module.__dict__.update(uuid=uuid,re=re,PurePosixPath=PurePosixPath,C=SimpleNamespace(require=B._seed_require,fields=fields),INPUTS={'data_dir','install_root','storage_file','capacity_gib'},SCOPE='HOST_INSTALLATION_IDENTITY_ONLY')
    exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]),str(path),'exec'),module.__dict__)
    return module


class Fixture:
    DATA='/srv/seed-data';INSTALL='/opt/company/release';HOST='/etc/autosoft';OP='1'*32
    def __init__(self,backend=None,*,fresh=True):
        self.backend=backend or SeedBackend();fs=self.backend;self.source=HeldSource();self.parent=HeldParent()
        self.allowed={self.source};self.V=SimpleNamespace(HeldPlatformSource=HeldSource,require_platform_source=self.require_source)
        self.P=SimpleNamespace(HeldParent=HeldParent)
        lt=ast.parse((ROOT/'scripts/runtime_layout.py').read_bytes())
        self.names=ast.literal_eval(next(n.value for n in lt.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BROKER_DIRECTORIES' for t in n.targets)))
        if backend is None:
            for path,mode in ((self.DATA,0o700),(self.DATA+'/config',0o700),(self.DATA+'/config/runtime-layout',0o700),
                (self.DATA+'/config/repository-seed',0o700),(self.DATA+'/runtime',0o755),(self.DATA+'/runtime/storage',0o700),(self.HOST,0o700),(self.INSTALL,0o700)):
                fs.directory(path,mode=mode)
            for name in self.names:fs.directory(self.DATA+'/runtime/'+name,10001,10001)
            binding=lambda path:{key:str(fs.nodes[path]['info'][key]) for key in B.SEED_FIELDS[:5]}
            proposal=dict(data_dir=self.DATA,install_root=self.INSTALL,storage_file='/srv/backing.luks',capacity_gib=32)
            self.intent=dict(schemaVersion=1,scope='HOST_INSTALLATION_IDENTITY_ONLY',installation_id='12345678-1234-4234-8234-123456789012',directory=binding(self.HOST),proposal=proposal)
            final=dict(data_dir=self.DATA,install_root=self.INSTALL,storage_file=proposal['storage_file'],installation_id=self.intent['installation_id'])
            receipt=dict(final,creation_stage='new-luks-created',luks_uuid='87654321-4321-4321-8321-210987654321')
            initial=dict(schemaVersion=1,scope='RUNTIME_PLACEMENT_ONLY',dataRootSha256=hashlib.sha256(B._seed_json(dict(path=self.DATA,device=1,
                inode=fs.nodes[self.DATA]['info']['st_ino'],mode=fs.nodes[self.DATA]['info']['st_mode'],uid=0,gid=0))).hexdigest(),
                directories=list(self.names),controls={'config':binding(self.DATA+'/config'),'base':binding(self.DATA+'/config/runtime-layout')})
            mount=dict(target=self.DATA+'/runtime/builds',filesystem='tmpfs',maximumBytes=2147483648,uid=10001,gid=10001,mode=0o700,nosuid=True,nodev=True)
            layout=dict(intentSha256=hashlib.sha256(B._seed_json(initial)).hexdigest(),directories={name:binding(self.DATA+'/runtime' if name=='runtime' else self.DATA+'/runtime/'+name) for name in ('runtime','storage',*self.names)},buildMount=mount)
            for path,value in ((self.HOST+'/installation.intent.json',self.intent),(self.HOST+'/installation.json',final),
                (self.HOST+'/installation.storage-receipt.json',receipt),(self.DATA+'/config/installation.json',{'installation_id':final['installation_id']}),
                (self.DATA+'/config/runtime-layout/intent.json',initial),(self.DATA+'/config/runtime-layout/layout.json',layout),
                (self.DATA+'/config/runtime-layout/confirmed.json',{'layoutSha256':hashlib.sha256(B._seed_json(layout)).hexdigest()})):
                fs.file(path,B._seed_json(value))
            fs.file('/srv/backing.luks',b'',size=32*1024**3);fs.file(self.HOST+'/storage.key',b'secret-never-read')
            fs.file('/usr/bin/git',b'exact-injected-git',mode=0o755)
        self.runner=SeedRunner(fs);self.commands=B.SeedCommands(SimpleNamespace(SeedRunner=SeedRunner),self.runner)
        self.files=B.SeedFiles(SimpleNamespace(SeedBackend=SeedBackend),fs)
        self.mount=dict(target=self.DATA,filesystem='xfs',source='/dev/mapper/autosoft-data',storageFile='/srv/backing.luks',
            luksUuid='87654321-4321-4321-8321-210987654321',options=['nodev','nosuid','prjquota','rw'],mapperIdentity=['1','2','3','4','5','6','7','8','9'],mapperPathIdentity=['1','2','3','4','5','6','7','8','9'])
        self.S=SimpleNamespace(I=identity_module(),L=SimpleNamespace(BROKER_DIRECTORIES=self.names,
            validate_build_mount=lambda value:B._seed_require(value==dict(target=self.DATA+'/runtime/builds',filesystem='tmpfs',maximumBytes=2147483648,uid=10001,gid=10001,mode=0o700,nosuid=True,nodev=True))),
            encrypted_proof=lambda data,receipt,command:json.loads(json.dumps(self.mount)))
        self.storage=B.SeedStorage(self.DATA,self.INSTALL,startup_module=self.S,files=self.files,commands=self.commands,fresh=fresh)
        tool=fs.nodes['/usr/bin/git']['raw'];self.git=B.SeedGit(self.files,self.commands,dict(path='/usr/bin/git',bytes=len(tool),sha256=hashlib.sha256(tool).hexdigest()))
        _,request,action=B.authenticated_seed_request(self.DATA,self.INSTALL,self.source,verifier_module=self.V,storage=self.storage,git=self.git,operation_id=self.OP)
        self.parent.arguments.request=request;self.parent.arguments.action=action
    def require_source(self,value):
        if type(value) is not HeldSource or value not in self.allowed or not value.live:raise ValueError('not-issued')
        value.calls+=1;return value
    def seed(self):
        return B.seed_authenticated_repository(self.DATA,self.INSTALL,self.source,verifier_module=self.V,parent_module=self.P,parent=self.parent,storage=self.storage,files=self.files,git=self.git,operation_id=self.OP)
    def confirm(self):
        return B.confirm_authenticated_seed(self.DATA,self.INSTALL,self.source,verifier_module=self.V,parent_module=self.P,parent=self.parent,storage=self.storage,files=self.files,git=self.git,operation_id=self.OP)


class AuthenticatedSeedTests(unittest.TestCase):
    def setUp(self):B.SEED_UNRELEASED.clear()
    def tearDown(self):B.SEED_UNRELEASED.clear()
    def deny(self,fixture,match=None):
        with self.assertRaises((ValueError,OSError,KeyError)) as raised:fixture.seed()
        if match:self.assertIn(match,str(raised.exception))
        return raised.exception
    def test_fresh_raw_seed_exact_objects_index_and_provenance(self):
        f=Fixture();result=f.seed();repo=f.DATA+'/runtime/repository'
        self.assertTrue(result['objectBytesVerified']);self.assertTrue(result['ownedSeedHandlesReleased']);self.assertFalse(result['installationActivated'])
        self.assertEqual(f.backend.nodes[repo+'/platform/empty.txt']['raw'],b'');self.assertEqual(f.backend.nodes[repo+'/platform/.gitattributes']['raw'],f.source.files['.gitattributes'])
        rows=parse_index(f.backend.nodes[repo+'/.git/index']['raw']);self.assertEqual(len(rows),len(f.source.files)+9)
        self.assertEqual(dict((p,m) for p,m,_ in rows)['platform/bin/run.sh'],'100755')
        self.assertEqual(f.backend.nodes[repo+'/company-release/release.sig']['raw'],f.source.provenance['release.sig'])
        self.assertEqual(f.backend.handles,{});self.assertNotIn(f.HOST+'/storage.key',f.backend.reads);self.assertNotIn('/srv/backing.luks',f.backend.reads)
    def test_intent_fsync_readback_precedes_repository_effect(self):
        f=Fixture();f.seed();effects=f.backend.effects;intent=f.DATA+'/config/repository-seed/'+f.OP+'/intent.json'
        self.assertLess(effects.index(intent),next(i for i,p in enumerate(effects) if '/runtime/repository/' in p))
    def test_missing_issuance_validator_denies_zero_writes(self):
        f=Fixture();del f.V.require_platform_source;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_forged_same_class_never_reads_source_properties(self):
        f=Fixture();forged=HeldSource();forged.files=None;f.source=forged;self.deny(f);self.assertEqual(f.backend.effects,[]);self.assertEqual(forged.calls,0)
    def test_expired_source_denies_zero_writes(self):
        f=Fixture();f.source.live=False;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_wrong_parent_action_denies_zero_writes(self):
        f=Fixture();f.parent.arguments.action='f'*64;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_parent_death_after_intent_preserves_no_replay(self):
        f=Fixture();f.backend.after_create=lambda p:setattr(f.parent,'live',False) if p.endswith('intent.json') else None
        self.deny(f);self.assertFalse(any('/runtime/repository/' in p for p in f.backend.effects));self.assertTrue(any(p.endswith('intent.json') for p in f.backend.effects))
    def test_nonempty_repository_preserves_sentinel(self):
        f=Fixture();p=f.storage.repository+'/sentinel';f.backend.file(p,b'keep',10001,10001);self.deny(f);self.assertEqual(f.backend.nodes[p]['raw'],b'keep');self.assertEqual(f.backend.effects,[])
    def test_prior_partial_journal_preserves_sentinel(self):
        f=Fixture();p=f.storage.journal+'/unknown';f.backend.file(p,b'keep');self.deny(f);self.assertEqual(f.backend.nodes[p]['raw'],b'keep');self.assertEqual(f.backend.effects,[])
    def test_pending_host_denies_zero_writes(self):
        f=Fixture();f.backend.file(f.HOST+'/installation.pending.json',b'{}');self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_prior_completion_denies_zero_writes(self):
        f=Fixture();f.backend.file(f.HOST+'/installation.complete',b'');self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_runtime_operation_journal_denies_zero_writes(self):
        f=Fixture();f.backend.file(f.DATA+'/runtime/operations/effect',b'{}',10001,10001);self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_active_service_denies_zero_writes(self):
        f=Fixture();f.runner.active_unit=True;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_inactive_service_with_lingering_pid_denies(self):
        f=Fixture();f.runner.lingering_pid=True;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_active_timer_denies_future_dispatch(self):
        f=Fixture();f.runner.active_timer=True;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_stopped_managed_container_still_denies(self):
        f=Fixture();f.runner.container=True;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_wrong_mount_identity_denies_zero_writes(self):
        f=Fixture();f.mount['mapperIdentity'][1]='123';self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_backing_timestamp_write_policy_allows_only_time_changes(self):
        f=Fixture();f.backend.nodes['/srv/backing.luks']['info']['st_mtime_ns']+=10;f.backend.nodes['/srv/backing.luks']['info']['st_ctime_ns']+=10
        f.mount['mapperIdentity'][7]='99';f.mount['mapperIdentity'][8]='99';self.assertTrue(f.seed()['objectBytesVerified'])
    def test_backing_size_change_denies(self):
        f=Fixture();f.backend.nodes['/srv/backing.luks']['info']['st_size']-=1;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_readonly_configuration_timestamp_drift_denies(self):
        f=Fixture();f.backend.nodes[f.DATA+'/config/installation.json']['info']['st_ctime_ns']+=1;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_repository_inode_replacement_denies(self):
        f=Fixture();p=f.storage.repository;f.backend.nodes[p]=dict(info=f.backend.info(True,10001,10001,0o700),raw=None);self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_source_path_traversal_denies_before_intent(self):
        f=Fixture();f.source.files['../escape']=b'x';f.source.git_modes['../escape']='100644';self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_case_alias_denies_before_intent(self):
        f=Fixture();f.source.files['Package.json']=b'x';f.source.git_modes['Package.json']='100644';self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_symlink_git_mode_denies_before_intent(self):
        f=Fixture();f.source.git_modes['package.json']='120000';self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_extra_provenance_denies_before_intent(self):
        f=Fixture();f.source.provenance['private.key']=b'x';self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_intent_sync_failure_preserves_and_stops(self):
        f=Fixture();f.backend.fail_sync='intent.json';self.deny(f);self.assertFalse(any('/runtime/repository/' in p for p in f.backend.effects));self.assertEqual(f.backend.handles,{})
    def test_extra_parent_entry_during_owned_transition_denies(self):
        f=Fixture()
        def inject(p):
            if p==f.storage.repository+'/.git':f.backend.file(f.storage.repository+'/unowned',b'x',10001,10001)
        f.backend.after_create=inject;self.deny(f);self.assertIn(f.storage.repository+'/unowned',f.backend.nodes)
    def test_created_file_byte_corruption_denies(self):
        f=Fixture()
        def corrupt(fd):
            n=f.backend.handles[fd]
            if n['raw']==b'{}\n':n['raw']=b'[]\n'
        f.backend.after_write=corrupt;self.deny(f);self.assertFalse(any(p.endswith('objects-verified.json') for p in f.backend.effects))
    def test_git_exit_zero_bad_object_bytes_denies(self):
        f=Fixture();f.runner.corrupt='cat-file';self.deny(f);self.assertFalse(any(p.endswith('objects-verified.json') for p in f.backend.effects))
    def test_git_exit_zero_altered_blob_body_denies(self):
        f=Fixture();f.runner.corrupt_kind='blob';self.deny(f);self.assertFalse(any(p.endswith('objects-verified.json') for p in f.backend.effects))
    def test_git_exit_zero_altered_tree_body_denies(self):
        f=Fixture();f.runner.corrupt_kind='tree';self.deny(f);self.assertFalse(any(p.endswith('objects-verified.json') for p in f.backend.effects))
    def test_git_exit_zero_altered_commit_body_denies(self):
        f=Fixture();f.runner.corrupt_kind='commit';self.deny(f);self.assertFalse(any(p.endswith('objects-verified.json') for p in f.backend.effects))
    def test_git_exit_zero_bad_index_denies(self):
        f=Fixture();f.runner.corrupt='ls-files';self.deny(f);self.assertFalse(any(p.endswith('objects-verified.json') for p in f.backend.effects))
    def test_unknown_command_release_latches_and_retains(self):
        f=Fixture();f.runner.unknown=True;self.deny(f);self.assertTrue(B.SEED_UNRELEASED);self.assertEqual(f.backend.effects,[])
        self.assertRaises(ValueError,B.SeedCommands(SimpleNamespace(SeedRunner=SeedRunner),f.runner).call,['/usr/bin/docker'])
    def test_every_owned_close_attempted_and_uncertain_reference_retained(self):
        f=Fixture();allfds=set(f.backend.handles);f.backend.fail_close=min(allfds);self.deny(f)
        self.assertTrue(allfds<=set(f.backend.close_attempts));self.assertEqual(len(B.SEED_UNRELEASED),1);self.assertEqual(len(f.backend.handles),1)
    def test_readonly_confirmation_preserves_advanced_commit(self):
        f=Fixture();result=f.seed();fs=f.backend;repo=f.storage.repository;seed=result['commit'];kind,old=f.runner.object(repo,seed)
        raw=old.replace(b'\nauthor ',b'\nparent '+seed.encode()+b'\nauthor ',1);full=b'commit '+str(len(raw)).encode()+b'\0'+raw;head=hashlib.sha1(full).hexdigest()
        fs.file(repo+'/.git/objects/'+head[:2]+'/'+head[2:],zlib.compress(full),10001,10001)
        fs.nodes[repo+'/.git/refs/heads/main']['raw']=head.encode()+b'\n';effects=list(fs.effects)
        second=Fixture(fs,fresh=False);answer=second.confirm();self.assertEqual(answer['preservedHead'],head);self.assertEqual(fs.effects,effects);self.assertEqual(fs.handles,{})
    def test_confirmation_rejects_changed_company_worktree_without_reset(self):
        f=Fixture();f.seed();fs=f.backend;p=f.storage.repository+'/platform/package.json';fs.nodes[p]['raw']=b'changed'
        fs.nodes[p]['info']['st_size']=7;second=Fixture(fs,fresh=False)
        with self.assertRaises(ValueError):second.confirm()
        self.assertEqual(fs.nodes[p]['raw'],b'changed')
    def test_confirmation_missing_terminal_preserves_orphan(self):
        f=Fixture();f.seed();fs=f.backend;p=f.storage.journal+'/'+f.OP+'/objects-verified.json';del fs.nodes[p];second=Fixture(fs,fresh=False)
        with self.assertRaises(ValueError):second.confirm()
        self.assertIn(f.storage.journal+'/'+f.OP+'/intent.json',fs.nodes)
    def test_confirmation_unreachable_seed_preserves_existing_head(self):
        f=Fixture();f.seed();fs=f.backend;repo=f.storage.repository;seed=f.runner.head(repo);_,raw=f.runner.object(repo,seed)
        raw=raw.replace(b'Reviewed platform seed',b'Unrelated parentless history');full=b'commit '+str(len(raw)).encode()+b'\0'+raw;head=hashlib.sha1(full).hexdigest()
        fs.file(repo+'/.git/objects/'+head[:2]+'/'+head[2:],zlib.compress(full),10001,10001);fs.nodes[repo+'/.git/refs/heads/main']['raw']=head.encode()+b'\n'
        second=Fixture(fs,fresh=False)
        with self.assertRaises(ValueError):second.confirm()
        self.assertEqual(fs.nodes[repo+'/.git/refs/heads/main']['raw'],head.encode()+b'\n')
    def test_storage_setup_failure_attempts_every_owned_close(self):
        f=Fixture();f.files.close();files=B.SeedFiles(SimpleNamespace(SeedBackend=SeedBackend),f.backend)
        f.backend.nodes[f.DATA+'/config/installation.json']['raw']=B._seed_json({'installation_id':'22345678-1234-4234-8234-123456789012'})
        f.backend.nodes[f.DATA+'/config/installation.json']['info']['st_size']=len(f.backend.nodes[f.DATA+'/config/installation.json']['raw'])
        with self.assertRaises(ValueError):B.SeedStorage(f.DATA,f.INSTALL,startup_module=f.S,files=files,commands=f.commands)
        self.assertEqual(f.backend.handles,{});self.assertEqual(f.backend.effects,[])
    def test_independent_index_parser_rejects_checksum_and_flag_drift(self):
        f=Fixture();plan=B._seed_plan(f.source);self.assertEqual(len(parse_index(plan['index'])),len(plan['leaves']))
        changed=bytearray(plan['index']);changed[72]^=0x80;changed[-20:]=hashlib.sha1(changed[:-20]).digest()
        self.assertRaises(ValueError,parse_index,bytes(changed));self.assertRaises(ValueError,parse_index,plan['index'][:-1]+b'X')
        f.files.close()
    def test_known_git_blob_vector_and_tree_directory_sort(self):
        self.assertEqual(hashlib.sha1(b'blob 6\0hello\n').hexdigest(),'ce013625030ba8dba906f756967f9e9ca394464a')
        f=Fixture();plan=B._seed_plan(f.source);self.assertTrue(plan['objects'][plan['commit']][1].startswith(b'tree '));self.assertNotIn(b'\nparent ',plan['objects'][plan['commit']][1]);f.files.close()
    def test_tree_sort_directory_slash_differs_from_plain_name(self):
        f=Fixture();f.source.files.update({'order/dir/file':b'a','order/dir.ext':b'b','order/dir0':b'c'})
        f.source.git_modes.update({name:'100644' for name in ('order/dir/file','order/dir.ext','order/dir0')})
        f.source.metadata['sourceTree']=independent_source_tree(f.source.files,f.source.git_modes)
        plan=B._seed_plan(f.source);raw=plan['objects'][plan['trees']['platform/order']][1];names=[];offset=0
        while offset<len(raw):
            end=raw.index(b'\0',offset);names.append(raw[offset:end].split(b' ',1)[1]);offset=end+21
        self.assertEqual(names,[b'dir.ext',b'dir',b'dir0']);f.files.close()
    def test_wrong_issued_source_tree_denies_before_intent_or_git(self):
        f=Fixture();f.source.metadata['sourceTree']='e'*40
        _,request,action=B.authenticated_seed_request(f.DATA,f.INSTALL,f.source,verifier_module=f.V,
            storage=f.storage,git=f.git,operation_id=f.OP)
        f.parent.arguments.request=request;f.parent.arguments.action=action
        self.deny(f,'seed_platform_tree');self.assertEqual(f.backend.effects,[])
        self.assertFalse(any(row[0][0]=='/usr/bin/git' for row in f.runner.calls))
    def test_logical_deadline_denies_before_effect(self):
        f=Fixture();f.files.clock=lambda:f.files.deadline+1;self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_oversize_source_denies_before_effect(self):
        f=Fixture();f.source.files['package.json']=b'x'*(8*1024**2+1);self.deny(f);self.assertEqual(f.backend.effects,[])
    def test_wrong_git_tool_pin_denies_and_preserves(self):
        f=Fixture();tool=dict(f.git.tool_pin,sha256='f'*64)
        with self.assertRaises(ValueError):B.SeedGit(f.files,f.commands,tool)
        self.assertEqual(f.backend.effects,[]);self.assertEqual(f.backend.handles,{});f.files.close()
    def test_git_tool_setup_close_failure_retains_unknown_reference(self):
        f=Fixture();f.backend.fail_close=min(f.backend.handles)
        with self.assertRaises(ValueError):B.SeedGit(f.files,f.commands,dict(f.git.tool_pin,sha256='f'*64))
        self.assertEqual(f.backend.effects,[]);self.assertEqual(len(f.backend.handles),1);self.assertTrue(B.SEED_UNRELEASED)
    def test_terminal_sync_failure_never_acknowledges_success(self):
        f=Fixture();f.backend.fail_sync='objects-verified.json';self.deny(f)
        self.assertIn(f.storage.journal+'/'+f.OP+'/objects-verified.json',f.backend.nodes);self.assertEqual(f.backend.handles,{})
    def test_command_environment_and_inherited_tool_contract(self):
        f=Fixture();f.seed();calls=[row for row in f.runner.calls if row[0][0]=='/usr/bin/git'];self.assertTrue(calls)
        for argv,stdin,env,tool in calls:
            self.assertIn('--no-replace-objects',argv);self.assertIn('--no-lazy-fetch',argv);self.assertEqual(env['GIT_CONFIG_GLOBAL'],'/dev/null');self.assertEqual(tool,f.git.tool)
            self.assertNotIn('add',argv);self.assertNotIn('status',argv);self.assertNotIn('init',argv)
    def test_legacy_mutable_seed_disabled(self):
        self.assertRaises(ValueError,B.seed_repository,Path('/irrelevant'),Path('/irrelevant'))
    def test_fast_writes_do_not_repeat_host_process_fanout(self):
        f=Fixture(); now=[f.storage.last_host_probe];f.files.clock=lambda:now[0]
        before=len(f.runner.calls);f.seed()
        # Initial/phase probes remain real; every file does not spawn 17 host tools.
        self.assertLess(len(f.runner.calls)-before,180)
        self.assertGreater(f.parent.calls,len(f.backend.effects))
    def test_changed_host_at_elapsed_checkpoint_stops_next_write(self):
        f=Fixture();now=[f.storage.last_host_probe];f.files.clock=lambda:now[0];effects=[]
        def change(path):
            if path==f.storage.repository+'/.git':
                f.runner.active_timer=True;now[0]+=5;effects.extend(f.backend.effects)
        f.backend.after_create=change;self.deny(f,'seed_writer_active')
        self.assertEqual(f.backend.effects,effects)
    def test_changed_mount_at_elapsed_checkpoint_stops_next_write(self):
        f=Fixture();now=[f.storage.last_host_probe];f.files.clock=lambda:now[0];effects=[]
        def change(path):
            if path==f.storage.repository+'/.git':
                f.mount['mapperIdentity'][1]='999';now[0]+=5;effects.extend(f.backend.effects)
        f.backend.after_create=change;self.deny(f,'seed_mount_changed')
        self.assertEqual(f.backend.effects,effects)
    def test_expired_source_is_checked_between_sampled_host_probes(self):
        f=Fixture();now=f.storage.last_host_probe;f.files.clock=lambda:now;effects=[]
        def change(path):
            if path==f.storage.repository+'/.git':f.source.live=False;effects.extend(f.backend.effects)
        f.backend.after_create=change;self.deny(f)
        self.assertEqual(f.backend.effects,effects)
    def test_final_git_boundary_forces_host_probe_without_elapsed_time(self):
        f=Fixture();now=f.storage.last_host_probe;f.files.clock=lambda:now;original=f.git.verify
        def changed(*args,**kwargs):
            result=original(*args,**kwargs);f.runner.container=True;return result
        f.git.verify=changed;self.deny(f,'seed_writer_present')
        self.assertFalse(any(p.endswith('objects-verified.json') for p in f.backend.effects))
    def test_slow_host_probe_never_authorizes_a_write(self):
        f=Fixture();now=[f.storage.last_host_probe];f.files.clock=lambda:now[0];original=f.S.encrypted_proof
        def slow(*args,**kwargs):now[0]+=5;return original(*args,**kwargs)
        f.S.encrypted_proof=slow;self.deny(f,'seed_host_probe_too_slow');self.assertEqual(f.backend.effects,[])
    def test_host_probe_budget_exhaustion_preserves_zero_effects(self):
        f=Fixture();f.storage.host_probes=136;self.deny(f,'seed_host_probe_budget')
        self.assertEqual(f.backend.effects,[])


if __name__=='__main__':unittest.main(verbosity=2)
