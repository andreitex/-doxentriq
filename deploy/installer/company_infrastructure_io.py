"""Held immutable render inputs and explicit create-time bind label transitions.

This is trusted worker plumbing, not authentication. It never refreshes a
signed-source guard or adopts an unmeasured file. No service-data content is
claimed immutable after its exact recorded start intent.
"""
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

def require(value,reason='Infrastructure files changed; preserve partial evidence'):
    if not value:raise ValueError(reason)

def identity(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()

class InfrastructureIO:
    def __init__(self,data,manifest,binds,mutable,*,check_authority,record_directory,clock=time.monotonic):
        require(os.name=='posix' and os.geteuid()==0 and callable(check_authority))
        self.root=str(Path(data));require(self.root.startswith('/') and str(Path(data).resolve(strict=True))==self.root)
        self.manifest=manifest;self.binds=binds;self.mutable=mutable;self.authority=check_authority
        self.clock=clock;self.deadline=clock()+900;self.records=record_directory;self.sequence=0
        self.nodes={};self.ancestors=[];self.failed=False;self.closed=False;self.started=set();self.transition=None
        self.label_evidence=None
        self.sealed_inputs=None
        try:
            flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
            fd=os.open('/',flags);self.ancestors.append((Path('/'),fd,identity(os.fstat(fd))))
            current=Path('/')
            for name in Path(data).parts[1:]:
                current=current/name;fd=os.open(name,flags,dir_fd=fd)
                self.ancestors.append((current,fd,identity(os.fstat(fd))))
            require(all(row[2][3:5]==(0,0) and not stat.S_IMODE(row[2][2])&0o022 for row in self.ancestors))
            self.device=os.fstat(fd).st_dev
            # Keep the root and every original rendered parent directory held.
            # All later opens/readbacks are relative to these exact descriptors.
            require(type(manifest) is dict and set(manifest)=={'files','directories','labels'} and '' in manifest['directories'])
            self._inventory('',recursive=False)
            for name in sorted(set(manifest['directories'])-{''},key=lambda s:(s.count('/'),s)):
                self._inventory(name,recursive=False)
            # Only bind roots and their bounded recursive children can be relabeled.
            roots={source for rows in binds.values() for source,_,_,_ in rows}
            for name in sorted(roots,key=lambda s:(s.count('/'),s)):self._inventory(name)
            # Other rendered files are held too, but can never be relabeled.
            for name in sorted(manifest['files']):
                if name not in self.nodes:self._inventory(name,recursive=False)
            for name,row in self.nodes.items():
                if not row['directory']:
                    expected=manifest['files'].get(name);require(expected is not None)
                    require(list(row['identity'])==expected['identity'] and row['sha256']==expected['sha256'])
                elif name in manifest['directories']:
                    expected=manifest['directories'][name]
                    require(list(row['identity'])==expected['identity'] and row['children']==expected['children'])
                else:
                    # Registry was created by the original configuration stage
                    # and is deliberately absent from RenderIO's own write set.
                    require(name=='registry' and row['identity'][2:5]==(stat.S_IFDIR|0o700,0,0) and row['children']==[])
            for service,names in mutable.items():
                for name in names:
                    node=self.nodes[name];require(node['directory'])
                    require(node['children']==(['users.acl'] if name=='redis' else []))
            self.check()
        except BaseException:self.failed=True;self.close(check=False);raise

    def _inventory(self,name,*,recursive=True):
        require(type(name) is str and (name=='' or not name.startswith('/') and '\\' not in name
            and all(p not in ('','.','..') for p in name.split('/'))))
        if name in self.nodes:
            row=self.nodes[name]
            if recursive and row['directory'] and not row.get('recursed'):
                for child in row['children']:self._inventory((name+'/' if name else '')+child)
                row['recursed']=True
            return
        require(len(self.nodes)<2048)
        parent_name=name.rsplit('/',1)[0] if '/' in name else ''
        require(name=='' or parent_name in self.nodes and self.nodes[parent_name]['directory'])
        parent=self.ancestors[-1][1] if name=='' else self.nodes[parent_name]['fd']
        leaf=PurePosixPath(name).name if name else '.'
        s=os.stat(leaf,dir_fd=parent,follow_symlinks=False);directory=stat.S_ISDIR(s.st_mode)
        require(directory or stat.S_ISREG(s.st_mode) and s.st_nlink==1)
        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK|(os.O_DIRECTORY if directory else 0)
        fd=os.open(leaf,flags,dir_fd=parent)
        # Register ownership before any subsequent operation can fail.
        row={'fd':fd,'identity':identity(os.fstat(fd)),'directory':directory};self.nodes[name]=row
        require(row['identity']==identity(s) and s.st_dev==self.device)
        require(not stat.S_IMODE(s.st_mode)&0o022)
        row['xattrs']=self._attrs(fd)
        if directory:
            row['children']=sorted(os.listdir(fd));require(len(row['children'])<=256)
            if recursive:
                for child in row['children']:self._inventory((name+'/' if name else '')+child)
                row['recursed']=True
        else:
            row['sha256']=sha(self._bytes(fd));require(sum(r['identity'][6] for r in self.nodes.values() if not r['directory'])<=24*1024**2)

    @staticmethod
    def _attrs(fd):
        values={}
        try:names=os.listxattr(fd)
        except OSError as error:
            if error.errno==errno.ENOTSUP:return values
            raise
        require(len(names)<=16)
        for name in names:
            value=os.getxattr(fd,name);require(len(value)<=65536);values[name]=value
        return values

    @staticmethod
    def _bytes(fd):
        raw=os.pread(fd,2*1024**2+1,0);require(len(raw)<=2*1024**2);return raw

    def _mutable(self,name):
        if name=='redis/users.acl':return False
        return any(name==root or name.startswith(root+'/') for service in self.started for root in self.mutable[service])

    def check(self):
        require(not self.closed and not self.failed and self.clock()<self.deadline);self.authority()
        for path,fd,before in self.ancestors:
            require(identity(os.fstat(fd))[:5]==before[:5] and identity(path.lstat())[:5]==before[:5])
        for name,row in self.nodes.items():
            parent_name=name.rsplit('/',1)[0] if '/' in name else ''
            parent=self.nodes[parent_name]['fd'] if name else self.ancestors[-1][1]
            now=identity(os.fstat(row['fd']));path=identity(os.stat(PurePosixPath(name).name if name else '.',dir_fd=parent,follow_symlinks=False))
            require(now==path)
            if self._mutable(name):
                require(now[:5]==row['identity'][:5] and self._attrs(row['fd'])==row['xattrs']);continue
            permitted=self.transition is not None and name in self.transition
            require(now[:8]==row['identity'][:8] if permitted else now==row['identity'])
            attrs=self._attrs(row['fd'])
            require({k:v for k,v in attrs.items() if k!='security.selinux'}=={k:v for k,v in row['xattrs'].items() if k!='security.selinux'})
            if not permitted:require(attrs==row['xattrs'])
            if row['directory']:require(sorted(os.listdir(row['fd']))==row['children'])
            else:require(sha(self._bytes(row['fd']))==row['sha256'])

    def read(self,name):
        self.check();require(name in self.nodes and not self.nodes[name]['directory'] and not self._mutable(name))
        raw=self._bytes(self.nodes[name]['fd']);require(sha(raw)==self.nodes[name]['sha256']);self.check();return raw

    def begin_labels(self,enabled):
        self.check();require(self.transition is None and self.label_evidence is None and type(enabled) is bool)
        self.selinux=enabled;scopes={source for rows in self.binds.values() for source,_,_,_ in rows}
        self.transition={name for name in self.nodes if any(name==root or name.startswith(root+'/') for root in scopes)} if enabled else set()
        self.initial_inventory=self.inventory()
        self.record('create-intent',{'inputsSha256':sha(canonical(self.manifest)),'bindInventorySha256':sha(canonical(self.initial_inventory))})

    def inventory(self):
        # Private evidence never exports raw credential bytes or xattr values.
        return {name:dict(identity=list(row['identity']),directory=row['directory'],sha256=row.get('sha256'),
            children=row.get('children'),xattrs={key:sha(value) for key,value in row['xattrs'].items()}) for name,row in sorted(self.nodes.items())}

    def finish_labels(self,containers):
        self.check();require(self.transition is not None and self.label_evidence is None)
        expected={}
        if self.selinux:
            for service,rows in self.binds.items():
                label=containers[service]['MountLabel']
                require(type(label) is str and re.fullmatch(r'system_u:object_r:container_file_t:s0:c[0-9]+,c[0-9]+',label))
                for root,_,_,kind in rows:
                    wanted=(label if kind=='Z' else 'system_u:object_r:container_file_t:s0').encode()
                    for name in self.transition:
                        if name==root or name.startswith(root+'/'):
                            require(name not in expected or expected[name]==wanted);expected[name]=wanted
            require(set(expected)==self.transition)
        evidence={}
        for name in self.transition:
            row=self.nodes[name];attrs=self._attrs(row['fd'])
            require(attrs.get('security.selinux',b'').rstrip(b'\0')==expected[name])
            now=identity(os.fstat(row['fd']));require(now[:8]==row['identity'][:8])
            evidence[name]=dict(beforeIdentity=list(row['identity']),afterIdentity=list(now),
                beforeLabelSha256=sha(row['xattrs'].get('security.selinux',b'')),afterLabel=expected[name].decode())
            row['identity']=now;row['xattrs']=attrs
        self.transition=None;self.label_evidence=evidence
        self.check()
        # This closed input snapshot is evidence, never authority. A separate
        # verifier must bind its exact digest to the original executed record,
        # original render manifest, same-session parent and actual live IDs.
        sealed=dict(schema=1,scope='INFRASTRUCTURE_INPUTS_AFTER_DECLARED_LABEL_TRANSITION',
            root=self.root,renderManifestSha256=sha(canonical(self.manifest)),selinuxEnabled=self.selinux,
            before=self.initial_inventory,after=self.inventory(),labelTransitions=evidence,
            mutableRoots=self.mutable,immutableExceptions=['redis/users.acl'])
        raw=canonical(sealed);require(0<len(raw)<=512*1024)
        self._write('immutable-inputs.json',raw)
        self.sealed_inputs=dict(sha256=sha(raw),bytes=len(raw))
        self.record('labels-verified',{'labelsSha256':sha(canonical(evidence)),'inputsSha256':self.sealed_inputs['sha256']})

    def start_intent(self,service,identifier):
        self.check();require(self.label_evidence is not None and self.sealed_inputs is not None and service in self.mutable and service not in self.started)
        self.record('start-intent',{'service':service,'containerId':identifier});self.started.add(service)

    def record(self,event,values):
        require(event in ('create-intent','created','labels-verified','start-intent','started','verified') and type(values) is dict)
        require(set(values)<={'service','containerId','inputsSha256','bindInventorySha256','labelsSha256','outcomeSha256'})
        for key,value in values.items():
            require(type(value) is str and (value in self.mutable if key=='service' else re.fullmatch('[a-f0-9]{64}',value)))
        self.authority();require(self.clock()<self.deadline and self.sequence<32);self.sequence+=1
        raw=canonical(dict(schema=1,sequence=self.sequence,event=event,values=values))
        self._write(f'{self.sequence:03}-{event}.json',raw)

    def _write(self,name,raw):
        require(name=='immutable-inputs.json' or re.fullmatch('[0-9]{3}-(?:create-intent|created|labels-verified|start-intent|started|verified)\\.json',name))
        self.authority();require(self.clock()<self.deadline)
        # The genuine worker provides an already held records directory context.
        with self.records() as (parent,check):
            fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            try:
                offset=0
                while offset<len(raw):n=os.write(fd,raw[offset:]);require(n>0);offset+=n
                os.fchmod(fd,0o400);os.fsync(fd);require(os.pread(fd,len(raw)+1,0)==raw)
                before=identity(os.fstat(fd));after=identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
                require(before==after and before[2:6]==(stat.S_IFREG|0o400,0,0,1) and before[6]==len(raw))
                os.fsync(parent);check()
            finally:os.close(fd)

    def close(self,*,check=True):
        if self.closed:return
        error=None
        if check:
            try:self.check();require(self.transition is None)
            except BaseException as failure:error=failure
        for fd in [row['fd'] for row in self.nodes.values()]+[row[1] for row in reversed(self.ancestors)]:
            try:os.close(fd)
            except BaseException as failure:error=error or failure
        self.closed=True
        if error:raise error
