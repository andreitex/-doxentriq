"""Read-only closed component inputs, never parent/source/adoption authority.

The genuine outer worker supplies the original render manifest, exact executed
digest, company tool binding and live authority. This module never starts or
retries services and cannot publish a parent confirmation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

def require(value):
    if not value:raise ValueError('Private infrastructure evidence differs; preserve the unresolved stage')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def unique(pairs):
    result={}
    for key,value in pairs:require(key not in result);result[key]=value
    return result
def decode(raw,limit):
    require(type(raw) is bytes and 0<len(raw)<=limit)
    value=json.loads(raw,object_pairs_hook=unique);require(type(value) is dict and canonical(value)==raw);return value
def digest(value):require(type(value) is str and re.fullmatch('[a-f0-9]{64}',value));return value

def infrastructure_evidence(IO,P):
    class ReadOnlyInputs:
        # Reuse held-FD read/check/close mechanics, not any mutation interface.
        _attrs=staticmethod(IO.InfrastructureIO._attrs)
        _bytes=staticmethod(IO.InfrastructureIO._bytes)
        _mutable=IO.InfrastructureIO._mutable
        check=IO.InfrastructureIO.check
        read=IO.InfrastructureIO.read
        close=IO.InfrastructureIO.close

        def __init__(self,data,after,*,authority,clock):
            require(os.name=='posix' and os.geteuid()==0)
            self.root=str(Path(data));require(self.root.startswith('/') and str(Path(data).resolve(strict=True))==self.root)
            self.authority=authority;self.clock=clock;self.deadline=clock()+300
            self.nodes={};self.ancestors=[];self.failed=False;self.closed=False
            self.transition=None;self.started=set(P.SERVICES);self.mutable=P.MUTABLE
            try:
                flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
                fd=os.open('/',flags);self.ancestors.append((Path('/'),fd,IO.identity(os.fstat(fd))));current=Path('/')
                for part in Path(data).parts[1:]:
                    current=current/part;fd=os.open(part,flags,dir_fd=fd);self.ancestors.append((current,fd,IO.identity(os.fstat(fd))))
                require(all(row[2][3:5]==(0,0) and not stat.S_IMODE(row[2][2])&0o022 for row in self.ancestors))
                self.device=os.fstat(fd).st_dev
                for name in sorted(after,key=lambda n:(n.count('/'),n!='',n)):
                    saved=after[name];parent_name=name.rsplit('/',1)[0] if '/' in name else ''
                    require(name=='' or parent_name in self.nodes and self.nodes[parent_name]['directory'])
                    parent=self.ancestors[-1][1] if name=='' else self.nodes[parent_name]['fd']
                    leaf=Path(name).name if name else '.'
                    before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
                    require((stat.S_ISDIR if saved['directory'] else stat.S_ISREG)(before.st_mode))
                    opened=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|(os.O_DIRECTORY if saved['directory'] else 0),dir_fd=parent)
                    row={'fd':opened,'identity':IO.identity(os.fstat(opened)),'directory':saved['directory']};self.nodes[name]=row
                    require(row['identity']==IO.identity(before) and before.st_dev==self.device and not stat.S_IMODE(before.st_mode)&0o022)
                    row['xattrs']=self._attrs(opened)
                    require({k:sha(v) for k,v in row['xattrs'].items()}==saved['xattrs'])
                    if self._mutable(name):
                        require(saved['directory'] and row['identity'][:5]==tuple(saved['identity'][:5]))
                        row['children']=saved['children']  # No traversal of admitted mutable data contents.
                    else:
                        require(list(row['identity'])==saved['identity'])
                        if saved['directory']:
                            row['children']=sorted(os.listdir(opened));require(row['children']==saved['children'])
                        else:
                            require(before.st_nlink==1);row['sha256']=sha(self._bytes(opened));require(row['sha256']==saved['sha256'])
                self.check()
            except BaseException:self.failed=True;self.close(check=False);raise

    class InfrastructureEvidence:
        def __init__(self,data,records_path,render_manifest,executed_raw,executed_sha256,*,tool_binding,check_authority,clock=time.monotonic):
            require(os.name=='posix' and os.geteuid()==0 and callable(check_authority))
            require(sha(executed_raw)==digest(executed_sha256))
            self.execution=decode(executed_raw,32768);self.execution_sha256=executed_sha256
            self.authority=check_authority;self.clock=clock;self.deadline=clock()+300
            self.dirs=[];self.files={};self.inputs=None;self.closed=False
            wanted={'scope','containerIds','networkIds','imageIds','daemonId','toolContext','modelSha256','immutableInputsSha256',
                'configHashes','privateInfrastructureReady','identityProvisioned','publicStartupAllowed','backupReady','wholeSignedStageQualified'}
            e=self.execution;require(set(e)==wanted and e['scope']=='PRIVATE_INFRASTRUCTURE_COMPONENT'
                and e['privateInfrastructureReady'] is True and all(e[k] is False for k in ('identityProvisioned','publicStartupAllowed','backupReady','wholeSignedStageQualified'))
                and e['toolContext']==P.tool_context(tool_binding) and type(e['daemonId']) is str and 1<=len(e['daemonId'])<=256)
            for key,names in (('containerIds',P.SERVICES),('imageIds',P.SERVICES),('networkIds',P.NETWORKS),('configHashes',P.SERVICES)):
                require(type(e[key]) is dict and set(e[key])==set(names))
                for value in e[key].values():digest(value.removeprefix('sha256:') if key=='imageIds' and type(value) is str else value)
                if key!='configHashes':require(len(set(e[key].values()))==len(e[key]))
                if key=='imageIds':require(all(v.startswith('sha256:') for v in e[key].values()))
            digest(e['modelSha256']);digest(e['immutableInputsSha256'])
            path=Path(records_path);require(path.is_absolute() and str(path)==str(path.resolve(strict=True)))
            try:
                current=Path('/');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                self.dirs.append((current,fd,IO.identity(os.fstat(fd))))
                for part in path.parts[1:]:
                    current=current/part;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    self.dirs.append((current,fd,IO.identity(os.fstat(fd))))
                require(all(r[2][3:5]==(0,0) and not stat.S_IMODE(r[2][2])&0o022 for r in self.dirs)
                    and stat.S_IMODE(self.dirs[-1][2][2])==0o700)
                self.expected_events=[('create-intent',None)]+[('created',s) for s in P.SERVICES]+[('labels-verified',None)]
                for service in P.SERVICES:self.expected_events.extend([('start-intent',service),('started',service)])
                self.expected_events.append(('verified',None))
                names={'immutable-inputs.json'}|{f'{i:03}-{event}.json' for i,(event,_) in enumerate(self.expected_events,1)}
                require(set(os.listdir(fd))==names);self.rows={}
                for name in sorted(names):
                    limit=512*1024 if name=='immutable-inputs.json' else 4096
                    opened=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                    self.files[name]=[opened,None,None];before=IO.identity(os.fstat(opened))
                    require(before[2:6]==(stat.S_IFREG|0o400,0,0,1) and before[0]==self.dirs[-1][2][0] and 0<before[6]<=limit)
                    raw=os.pread(opened,limit+1,0);require(len(raw)==before[6] and IO.identity(os.fstat(opened))==before)
                    self.files[name]=[opened,before,sha(raw)];self.rows[name]=decode(raw,limit)
                require(self.files['immutable-inputs.json'][2]==e['immutableInputsSha256'])
                self.snapshot=self.rows['immutable-inputs.json'];self._snapshot(data,render_manifest)
                self._events();self.inputs=ReadOnlyInputs(data,self.snapshot['after'],authority=self._records_check,clock=clock)
                self.deadline=min(self.deadline,self.inputs.deadline);self.check()
            except BaseException:self.close(check=False);raise

        def _snapshot(self,data,manifest):
            s=self.snapshot
            require(set(s)=={'schema','scope','root','renderManifestSha256','selinuxEnabled','before','after','labelTransitions','mutableRoots','immutableExceptions'}
                and type(s['schema']) is int and s['schema']==1 and s['scope']=='INFRASTRUCTURE_INPUTS_AFTER_DECLARED_LABEL_TRANSITION'
                and s['root']==data and s['renderManifestSha256']==sha(canonical(manifest)) and type(s['selinuxEnabled']) is bool
                and s['mutableRoots']=={name:list(roots) for name,roots in P.MUTABLE.items()} and s['immutableExceptions']==['redis/users.acl'])
            expected=set(manifest['files'])|set(manifest['directories'])|{'registry'}
            require(type(s['before']) is dict and type(s['after']) is dict and set(s['before'])==set(s['after'])==expected and len(expected)<=2048)
            roots={r[0] for rows in P.BINDS.values() for r in rows}
            transitioned={n for n in expected if any(n==r or n.startswith(r+'/') for r in roots)} if s['selinuxEnabled'] else set()
            require(type(s['labelTransitions']) is dict and set(s['labelTransitions'])==transitioned)
            for name in expected:
                require(type(name) is str and (name=='' or not name.startswith('/') and '\\' not in name and all(p not in ('','.','..') for p in name.split('/'))))
                before,after=s['before'][name],s['after'][name]
                for row in (before,after):
                    require(type(row) is dict and set(row)=={'identity','directory','sha256','children','xattrs'} and type(row['directory']) is bool
                        and type(row['identity']) is list and len(row['identity'])==9 and all(type(v) is int and v>=0 for v in row['identity'])
                        and type(row['xattrs']) is dict and len(row['xattrs'])<=16)
                    for key,value in row['xattrs'].items():require(type(key) is str and 0<len(key)<=255);digest(value)
                    if row['directory']:require(row['sha256'] is None and type(row['children']) is list and row['children']==sorted(set(row['children'])) and len(row['children'])<=256)
                    else:digest(row['sha256']);require(row['children'] is None)
                if name in manifest['files']:
                    require(not before['directory'] and before['identity']==manifest['files'][name]['identity'] and before['sha256']==manifest['files'][name]['sha256'])
                elif name in manifest['directories']:
                    require(before['directory'] and before['identity']==manifest['directories'][name]['identity'] and before['children']==manifest['directories'][name]['children'])
                else:require(name=='registry' and before['directory'] and before['children']==[] and before['identity'][2:5]==[stat.S_IFDIR|0o700,0,0])
                require(before['directory']==after['directory'] and before['sha256']==after['sha256'] and before['children']==after['children'])
                if name not in transitioned:require(before==after);continue
                change=s['labelTransitions'][name]
                require(set(change)=={'beforeIdentity','afterIdentity','beforeLabelSha256','afterLabel'} and change['beforeIdentity']==before['identity']
                    and change['afterIdentity']==after['identity'] and before['identity'][:8]==after['identity'][:8]
                    and change['beforeLabelSha256']==before['xattrs'].get('security.selinux',sha(b'')))
                require(type(change['afterLabel']) is str and re.fullmatch(r'system_u:object_r:container_file_t:s0(?::c[0-9]+,c[0-9]+)?',change['afterLabel']))
                raw=change['afterLabel'].encode();require(after['xattrs'].get('security.selinux') in (sha(raw),sha(raw+b'\0')))
                require({k:v for k,v in before['xattrs'].items() if k!='security.selinux'}=={k:v for k,v in after['xattrs'].items() if k!='security.selinux'})

        def _events(self):
            for number,(event,service) in enumerate(self.expected_events,1):
                row=self.rows[f'{number:03}-{event}.json'];e=self.execution;s=self.snapshot
                wanted={'service':service,'containerId':e['containerIds'][service]} if service else {}
                if event=='create-intent':wanted={'inputsSha256':s['renderManifestSha256'],'bindInventorySha256':sha(canonical(s['before']))}
                if event=='labels-verified':wanted={'inputsSha256':e['immutableInputsSha256'],'labelsSha256':sha(canonical(s['labelTransitions']))}
                if event=='verified':wanted={'outcomeSha256':self.execution_sha256}
                require(row==dict(schema=1,sequence=number,event=event,values=wanted))

        def _records_check(self):
            require(not self.closed and self.clock()<self.deadline);self.authority()
            for path,fd,before in self.dirs:require(IO.identity(os.fstat(fd))==before==IO.identity(path.lstat()))
            require(set(os.listdir(self.dirs[-1][1]))==set(self.files))
            for name,(fd,before,hashed) in self.files.items():
                require(IO.identity(os.fstat(fd))==before==IO.identity(os.stat(name,dir_fd=self.dirs[-1][1],follow_symlinks=False)))
                require(sha(os.pread(fd,before[6]+1,0))==hashed)

        def check(self):self._records_check();self.inputs.check()
        def read(self,name):self.check();return self.inputs.read(name)
        def close(self,*,check=True):
            if self.closed:return
            error=None
            if check:
                try:self.check()
                except BaseException as exc:error=exc
            if self.inputs is not None:
                try:self.inputs.close(check=check)
                except BaseException as exc:error=error or exc
            for fd in [v[0] for v in self.files.values()]+[v[1] for v in reversed(self.dirs)]:
                try:os.close(fd)
                except BaseException as exc:error=error or exc
            self.closed=True
            if error:raise error
        def __enter__(self):return self
        def __exit__(self,*unused):self.close()
    return InfrastructureEvidence
