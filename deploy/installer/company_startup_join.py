"""One credentialed sibling startup exchange; no execution evidence issuer.

Initial company source, OS/socket/interpreter/procfs origin, exclusive endpoint
copies, privileged credential-forging exclusions and complete station capacity
are fixed-entry obligations. Only an expressly transferred endpoint is adopted.
No sockets, processes, scope files, default native station or ACK are created.
"""
import hashlib
import math
import struct
from types import (BuiltinFunctionType, FunctionType, GetSetDescriptorType,
                   MappingProxyType, MemberDescriptorType, MethodDescriptorType,
                   MethodType, ModuleType)

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BINDING=('requestSha256','releaseSha256','deliveryIdentitySha256','planSha256',
         'actionSha256','inputSha256','sourceSha256','stage','session')
UNRELEASED=[]


class StartupUnavailable(ValueError):
    pass


def _factory(namespace,public,error_kind,primitives):
    (type,dict,tuple,list,set,str,int,float,bool,bytes,len,all,any,vars,object,
     range,min,max,reversed,id,next,property,classmethod,staticmethod,BaseException)=primitives
    gettype=type.__getattribute__;new_error,init_error=BaseException.__new__,BaseException.__init__
    fn,method,builtin,modulekind=FunctionType,MethodType,BuiltinFunctionType,ModuleType
    proxy=MappingProxyType;descriptor_kinds=(GetSetDescriptorType,MemberDescriptorType)
    raw_hash,finite=hashlib.sha256,math.isfinite
    credentials=struct.Struct('=iii').unpack;rights_fd=struct.Struct('=i').unpack
    fields,binding_fields=FIELDS,BINDING;used=failed=False;records={};permits={};retained=[]
    def deny():
        value=new_error(error_kind);init_error(value,'company-startup-join-unavailable');raise value
    def need(value):
        if value is not True:deny()
    def kinds(value,expected):return any(type(value) is kind for kind in expected)
    def closed(value,keys):
        need(type(value) is dict and len(value)==len(keys) and all(type(key) is str for key in value) and set(value)==set(keys));return value
    def same(value,items):
        need(kinds(value,(dict,proxy)) and len(value)==len(items) and all(type(key) is str for key in value)
             and all(key in value and value[key] is original for key,original in items))
    def function(value):
        if type(value) is method:value=value.__func__
        if type(value) is builtin:return None
        need(type(value) is fn)
        return value,value.__code__,value.__closure__,value.__defaults__,value.__kwdefaults__,tuple(vars(value).items())
    def function_same(row):
        if row is None:return
        value,code,closure,defaults,kwdefaults,items=row
        need(value.__code__ is code and value.__closure__ is closure and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults);same(vars(value),items)
    def tables(kind):
        need(type(kind) is type);mro=gettype(kind,'__mro__');need(len(mro)<=8 and all(type(owner) is type for owner in mro))
        rows=tuple((owner,gettype(owner,'__bases__'),gettype(owner,'__mro__'),tuple(gettype(owner,'__dict__').items())) for owner in mro)
        need(all(len(items)<=128 and all(type(key) is str for key,value in items) for owner,bases,lineage,items in rows));functions=[]
        for owner,bases,lineage,items in rows:
            for key,value in items:
                if type(value) is fn:functions.append(function(value))
                elif type(value) is property:
                    for getter in (value.fget,value.fset,value.fdel):
                        if getter is not None:functions.append(function(getter))
                elif kinds(value,(classmethod,staticmethod)):
                    if type(value.__func__) is fn:functions.append(function(value.__func__))
        return rows,tuple(functions)
    def table_same(row):
        for owner,bases,mro,items in row[0]:
            need(gettype(owner,'__bases__') is bases and gettype(owner,'__mro__') is mro);same(gettype(owner,'__dict__'),items)
        for value in row[1]:function_same(value)
    def definition(row,name):return next((value for owner,bases,mro,items in row[0] for key,value in items if key==name),None)
    def capture(module):
        need(type(module) is modulekind);items=tuple(vars(module).items());need(len(items)<=512 and all(type(key) is str for key,value in items))
        name=dict(items).get('__name__');need(type(name) is str);classes=[]
        for key,value in items:
            if type(value) is type:
                origin=gettype(value,'__module__');need(type(origin) is str)
                if origin==name:classes.append(tables(value))
        return module,items,tuple(function(value) for key,value in items if kinds(value,(fn,method))),tuple(classes)
    def captured_same(row):
        module,items,functions,classes=row;same(vars(module),items)
        for value in functions:function_same(value)
        for value in classes:table_same(value)
    def digest(raw):return raw_hash(raw).hexdigest()
    def number(value,maximum=2**31):need(type(value) is int and 2<=value<maximum);return value
    def decimal(raw,maximum=2**31):
        need(type(raw) is bytes and 0<len(raw)<=20 and all(48<=c<=57 for c in raw));value=int(raw)
        need(2<=value<maximum and str(value).encode('ascii')==raw);return value
    def boot(value):
        need(type(value) is str and len(value)==36 and value[8]==value[13]==value[18]==value[23]=='-'
             and len(value.replace('-',''))==32 and all(c in '0123456789abcdef' for c in value.replace('-','')));return value
    def binding(value):
        closed(value,binding_fields);copy=dict(value)
        for key in binding_fields[:7]:need(type(copy[key]) is str and len(copy[key])==64 and all(c in '0123456789abcdef' for c in copy[key]))
        need(type(copy['stage']) is str and copy['stage'] in ('company-platform-store','company-source-materialize'))
        session=copy['session'];need(type(session) is str and len(session)==14 and session.startswith('s-') and session[2:].isascii() and session[2:].isalnum())
        body=('|'.join(copy[key] for key in binding_fields)+'\n').encode('ascii');return proxy(copy),digest(body)
    def retain(record,phase,problem):
        nonlocal failed
        failed=True
        if record['failed']:return
        record['failed']=True;record['problem_refs'].append((phase,problem));retained.append(record)
        if type(public) is list:public.append((record,phase,problem))
    def guard(record):
        same(namespace,record['own'])
        for row in record['own_functions']:function_same(row)
        table_same(record['error_tables']);table_same(join_tables);table_same(permit_tables)
        for row in record['modules']:captured_same(row)
        for row in record['functions'].values():function_same(row)
        table_same(record['socket_tables']);table_same(record['stat_tables']);table_same(record['uname_tables'])
        if record['poll_tables'] is not None:
            table_same(record['poll_tables']);need(type(record['poll']) is record['poll_kind'])
    def call(record,name,*args,**kwargs):
        guard(record);need(record['calls']<432);record['calls']+=1
        value=record['ops'][name](*args,**kwargs);record['returns'].append((name,value));guard(record);return value
    def metadata(record,value):
        need(type(value) is record['stat_kind']);result=tuple(record['stat_fields'][key].__get__(value,record['stat_kind']) for key in fields)
        need(all(type(n) is int and 0<=n<2**64 for n in result) and result[1]>0 and result[5]>0);return result
    def own(record,fd,role,path=None,wrapper=None,expected=None):
        matches=[old for old in record['rows'] if not old['closed'] and
            (old['fd'] is fd or type(fd) is int and type(old['fd']) is int and old['fd']==fd)]
        if len(record['rows'])>=32:
            record['excess_acquisitions'].append((fd,role,path,wrapper,expected));record['unknown']=True
            for old in matches:old['ambiguous']=True
            deny()
        row=dict(fd=fd,role=role,path=path,wrapper=wrapper,identity=expected,attempted=False,closed=False,ambiguous=False)
        record['rows'].append(row)
        if type(fd) is not int or not 3<=fd<1048576 or fd in record['protected'] or matches:
            row['ambiguous']=True;record['unknown']=True
            for old in matches:old['ambiguous']=True
            deny()
        return row
    def observe_fd(record,row):
        current=metadata(record,call(record,'fstat',row['fd']))
        if row['identity'] is None:row['identity']=current
        else:need(current==row['identity'])
        return current
    def socket_check(record):
        guard(record);row=record['endpoint_row'];endpoint=record['endpoint'];kind=record['socket_kind'];need(type(endpoint) is kind)
        values={key:descriptor.__get__(endpoint,kind) for key,descriptor in record['socket_fields'].items()}
        need(all(type(values[key]) is int for key in ('family','type','proto','_io_refs')) and values['family']==1 and values['type']==5
             and values['proto']==0 and values['_io_refs']==0 and type(values['_closed']) is bool and values['_closed'] is False)
        fd=call(record,'fileno');need(type(fd) is int and fd==row['fd']);observe_fd(record,row)
        flags=call(record,'fcntl',fd,3);fdflags=call(record,'fcntl',fd,1);passcred=call(record,'getsockopt',1,16)
        need(type(flags) is type(fdflags) is type(passcred) is int and flags==2050 and fdflags==1 and passcred==1)
    def close_row(record,row):
        need(not row['closed'] and not row['attempted'] and not row['ambiguous']);row['attempted']=True
        try:
            need(record['cleanup_calls']<80);record['cleanup_calls']+=1
            function_same(record['functions']['fstat']);actual=record['ops']['fstat'](row['fd']);record['returns'].append(('cleanup-fstat',row,actual))
            table_same(record['stat_tables']);need(row['identity'] is not None and metadata(record,actual)==row['identity']);function_same(record['functions']['fstat'])
            if row['wrapper'] is None:
                need(record['cleanup_calls']<80);record['cleanup_calls']+=1
                function_same(record['functions']['close']);answer=record['ops']['close'](row['fd']);record['returns'].append(('cleanup-close',row,answer))
                need(answer is None);row['closed']=True;function_same(record['functions']['close'])
            else:
                table_same(record['socket_tables']);need(type(row['wrapper']) is record['socket_kind'])
                endpoint=row['wrapper'];kind=record['socket_kind'];descriptors=record['socket_fields']
                need(record['cleanup_calls']<80);record['cleanup_calls']+=1
                function_same(record['functions']['fileno']);fd=record['ops']['fileno']();record['returns'].append(('cleanup-socket-live-fileno',row,fd))
                table_same(record['socket_tables']);function_same(record['functions']['fileno']);need(type(fd) is int and fd==row['fd'])
                count=descriptors['_io_refs'].__get__(endpoint,kind);closed_value=descriptors['_closed'].__get__(endpoint,kind)
                need(type(count) is int and count==0 and type(closed_value) is bool and closed_value is False)
                need(record['cleanup_calls']<80);record['cleanup_calls']+=1
                function_same(record['functions']['socket_close']);answer=record['ops']['socket_close']();record['returns'].append(('cleanup-socket-close',row,answer))
                need(answer is None);table_same(record['socket_tables']);need(type(endpoint) is kind)
                need(record['cleanup_calls']<80);record['cleanup_calls']+=1
                observed=record['ops']['fileno']();record['returns'].append(('cleanup-socket-fileno',row,observed));table_same(record['socket_tables'])
                need(type(observed) is int and observed==-1 and descriptors['_closed'].__get__(endpoint,kind) is True);row['closed']=True
        except BaseException as problem:
            record['unknown']=True;record['cleanup_errors'].append((row,problem));raise
    def protected(record,row,directory):
        current=observe_fd(record,row);need(current[2]&0o170000==(0o040000 if directory else 0o100000) and current[3:5]==(0,0)
             and current[2]&0o022==0 and (directory or current[5]==1))
        need(metadata(record,call(record,'stat',row['path'],follow_symlinks=False))==current)
        flags=call(record,'fcntl',row['fd'],3);base=2048|131072|(65536 if directory else 0)
        fdflags=call(record,'fcntl',row['fd'],1);need(type(flags) is type(fdflags) is int and flags&~32768==base and fdflags==1)
    def opened(record,path,parent=None,name=None,directory=False):
        guard(record);need(record['calls']<432);record['calls']+=1
        flags=2048|131072|524288|(65536 if directory else 0)
        record['acquisition_attempts'].append((path,flags,None if parent is None else parent['fd']))
        try:value=record['ops']['open'](path if parent is None else name,flags,**({} if parent is None else dict(dir_fd=parent['fd'])))
        except BaseException:record['unknown']=True;raise
        record['returns'].append(('open',value));row=own(record,value,'proc',path);guard(record);protected(record,row,directory);return row
    def read_file(record,row,cap):
        protected(record,row,False);body=b''
        for unused in range(cap+2):
            tick(record);amount=min(4096,cap+1-len(body));need(amount>0)
            part=call(record,'pread',row['fd'],amount,len(body));need(type(part) is bytes and len(part)<=amount)
            record['read_bytes']+=len(part);need(record['read_bytes']<=131072)
            if part==b'':protected(record,row,False);return body
            body+=part;need(len(body)<=cap)
        deny()
    def tick(record):
        value=call(record,'clock');need(kinds(value,(int,float)) and finite(value) and record['last']<=value<record['deadline']);record['last']=value;return value
    def proc_setup(record):
        root=opened(record,'/',directory=True);proc=opened(record,'/proc',root,'proc',True);record['proc']=proc
        parent=proc
        for name in ('sys','kernel','random'):parent=opened(record,parent['path']+'/'+name,parent,name,True)
        record['boot_row']=opened(record,parent['path']+'/boot_id',parent,'boot_id')
        actual=read_file(record,record['boot_row'],64);need(actual==(record['parent']['bootId']+'\n').encode('ascii'))
    def process(record,pid,bash=False):
        if pid not in record['process_rows']:
            proc=record['proc'];directory=opened(record,'/proc/'+str(pid),proc,str(pid),True)
            record['process_rows'][pid]=(opened(record,directory['path']+'/stat',directory,'stat'),opened(record,directory['path']+'/status',directory,'status'))
        stat_row,status_row=record['process_rows'][pid];raw=read_file(record,stat_row,4096);status=read_file(record,status_row,8192)
        need(call(record,'process_status',status,pid,None if bash else record['parent']['pid'],bash=bash) is None)
        if bash:start=call(record,'parent_stat',raw,pid);ppid=None
        else:
            need(0<len(raw)<=4096 and raw.endswith(b'\n') and b'\0' not in raw and b'\r' not in raw and all(c<128 for c in raw))
            end=raw.rfind(b')');need(end>0 and raw[:end+1].startswith(str(pid).encode('ascii')+b' ('))
            parts=raw[end+2:-1].split(b' ');need(len(parts)==50 and parts[0] in (b'R',b'S',b'D',b'T',b't',b'I'))
            need(all(0<len(item)<=21 and (item.isdigit() or item[:1]==b'-' and item[1:].isdigit()) for item in parts[1:]))
            start=decimal(parts[19],2**64);ppid=decimal(parts[1]);need(ppid==record['parent']['pid'])
        need(type(start) is int and 2<=start<2**64)
        actual=(pid,start,ppid)
        if pid in record['births']:need(record['births'][pid]==actual)
        else:record['births'][pid]=actual
        return actual
    def wait_ready(record,mask):
        need(call(record,'poll_register',record['endpoint_row']['fd'],mask|16|8) is None)
        for unused in range(32):
            remaining=record['deadline']-tick(record);value=call(record,'poll_wait',min(100, max(1,int(remaining*1000))))
            need(type(value) is list and len(value)<=1)
            if value:
                row=value[0];need(type(row) is tuple and len(row)==2 and type(row[0]) is type(row[1]) is int and row[0]==record['endpoint_row']['fd'])
                need(0<row[1]<2**31 and row[1]&~(mask|16)==0 and row[1]&mask==mask);return
        deny()
    def disclose(record,value):
        # All actual recv returns remain retained even when their shape is opaque.
        if type(value) is not tuple or len(value)!=4:record['unknown']=True;deny()
        payload,anc,flags,address=value
        if type(anc) is not list or len(anc)>8:record['unknown']=True;deny()
        raw_fds=[];has_rights=False
        for item in anc:
            if type(item) is not tuple or len(item)!=3:record['unknown']=True;continue
            level,kind,data=item
            if type(level) is not int or type(kind) is not int or not -2**31<=level<2**31 or not -2**31<=kind<2**31 or type(data) is not bytes:record['unknown']=True;continue
            if level==1 and kind==1:
                has_rights=True
                if len(data)>64 or len(data)%4:record['unknown']=True;continue
                for offset in range(0,len(data),4):raw_fds.append(rights_fd(data[offset:offset+4])[0])
            elif (level,kind)!=(1,2):record['unknown']=True
        # Register every disclosed descriptor before any later guard/denial.
        for fd in raw_fds:
            try:own(record,fd,'received-right')
            except BaseException as problem:record['problem_refs'].append(('rights-registration',problem))
        if type(flags) is not int or not 0<=flags<2**31 or flags&(8|32):record['unknown']=True
        guard(record)
        for row in record['rows']:
            if row['role']=='received-right' and not row['ambiguous'] and row['identity'] is None:
                observe_fd(record,row)
        need(not record['unknown'] and not has_rights)
        need(type(payload) is bytes and 0<len(payload)<=512 and type(flags) is int and flags&~1073741824==0
             and (address is None or type(address) is bytes and address==b'' or type(address) is str and address=='') and len(anc)==1)
        item=anc[0];need(type(item) is tuple and len(item)==3 and type(item[0]) is type(item[1]) is int
             and item[:2]==(1,2) and type(item[2]) is bytes and len(item[2])==12)
        pid,uid,gid=credentials(item[2]);number(pid);need(uid==gid==0);return payload,pid
    def recv(record):
        need(not record['recv_attempted']);wait_ready(record,1);socket_check(record);guard(record)
        record['recv_attempted']=True;need(record['calls']<432);record['calls']+=1
        try:value=record['ops']['recvmsg'](512,96,1073741824)
        except BaseException:record['unknown']=True;raise
        record['returns'].append(('recvmsg',value));record['raw_recv']=value
        return disclose(record,value)
    def send(record,raw):
        need(type(raw) is bytes and 0<len(raw)<=512 and not record['send_attempted']);wait_ready(record,4);socket_check(record)
        record['send_attempted']=True;guard(record);need(record['calls']<432);record['calls']+=1
        value=record['ops']['sendmsg']([raw]);record['returns'].append(('sendmsg',value));record['send_return']=value;guard(record)
        need(type(value) is int and value==len(raw))
    def frame(record,magic,execute,capture=None,request_sha=None):
        parent=record['parent'];items=[magic]
        if request_sha is not None:items.append(request_sha)
        items.extend((record['binding_sha'],str(parent['pid']),str(parent['start']),parent['bootId'],str(execute[0]),str(execute[1])))
        if capture is not None:items.extend((str(capture[0]),str(capture[1])))
        raw=('|'.join(items)+'\n').encode('ascii');need(len(raw)<=512);return raw
    def split(raw,count,magic):
        need(type(raw) is bytes and 0<len(raw)<=512 and raw.endswith(b'\n') and raw.count(b'\n')==1 and b'\r' not in raw and b'\0' not in raw)
        parts=raw[:-1].split(b'|');need(len(parts)==count and parts[0]==magic);return parts
    def finish(record):
        for row in reversed(record['rows']):
            if not row['closed'] and not row['attempted'] and not row['ambiguous']:
                try:close_row(record,row)
                except BaseException:pass
        need(not record['unknown'] and all(row['closed'] for row in record['rows']));guard(record);record['known_closed']=True
    def issued(value):
        record=records.get(id(value));need(type(record) is dict and record['join'] is value)
        need(not record['failed'] and not failed and not retained)
        try:need(type(value) is join_kind and not failed and not retained and not record['failed']);guard(record)
        except BaseException as problem:retain(record,'issued-boundary',problem);deny()
        return record

    class RolePermit:
        __slots__=()
        @property
        def data(self):
            record=permits.get(id(self));need(type(record) is dict and record['permit'] is self)
            require_startup_permit(self,record['subject'],role=record['role']);return record['data']

    class StartupJoin:
        __slots__=()
        def join(self):
            record=issued(self)
            try:
                need(record['phase']=='prepared');record['phase']='attempted';socket_check(record)
                now=call(record,'clock');need(kinds(now,(int,float)) and finite(now) and now>=0);record['last']=now;record['deadline']=now+record['seconds']
                uname=call(record,'uname');need(type(uname) is record['uname_kind']);machine=record['uname_machine'].__get__(uname,record['uname_kind']);need(type(machine) is str and machine=='x86_64')
                own_pid=call(record,'getpid');own_ppid=call(record,'getppid');number(own_pid);need(type(own_ppid) is int and own_ppid==record['parent']['pid'])
                uid=call(record,'getresuid');gid=call(record,'getresgid');need(type(uid) is type(gid) is tuple and len(uid)==len(gid)==3 and all(type(v) is int and v==0 for v in uid+gid))
                proc_setup(record);parent=process(record,record['parent']['pid'],True);need(parent[1]==record['parent']['start']);own_birth=process(record,own_pid)
                if record['role']=='execute':
                    request=frame(record,'CSJ1',own_birth);record['request_raw']=request;send(record,request);raw,sender=recv(record)
                    need(sender==record['peer_pid'] and sender not in (own_pid,record['parent']['pid']));peer=process(record,sender)
                    split(raw,10,b'CSJP1');need(raw==frame(record,'CSJP1',own_birth,peer,digest(request)))
                else:
                    raw,sender=recv(record);need(sender not in (own_pid,record['parent']['pid']));peer=process(record,sender)
                    split(raw,7,b'CSJ1');need(raw==frame(record,'CSJ1',peer));record['request_raw']=raw
                    send(record,frame(record,'CSJP1',peer,own_birth,digest(raw)))
                record['peer_birth']=peer;record['own_birth']=own_birth
                need(process(record,record['parent']['pid'],True)==parent and process(record,own_pid)==own_birth and process(record,peer[0])==peer)
                need(read_file(record,record['boot_row'],64)==(record['parent']['bootId']+'\n').encode('ascii'));socket_check(record);finish(record)
                permit=object.__new__(permit_kind);record['permit']=permit;permits[id(permit)]=record;record['phase']='closed'
                record['data']=proxy(dict(scope='SAME_ROLE_STARTUP_JOIN_ONLY',role=record['role'],binding=record['binding'],bindingSha256=record['binding_sha'],
                    parent=proxy(dict(record['parent'])),ownPid=own_birth[0],ownStart=own_birth[1],peerPid=peer[0],peerStart=peer[1],
                    requestSha256=digest(record['request_raw']),ownedStartupHandlesKnownClosed=True,
                    initialOriginsQualified=False,completeCopyGraphQualified=False,executionEvidenceIssued=False,stageAcknowledged=False))
                guard(record);return permit
            except BaseException as problem:
                retain(record,'startup-join',problem)
                try:finish(record)
                except BaseException as cleanup:record['problem_refs'].append(('finish',cleanup))
                deny()

    join_kind,permit_kind=StartupJoin,RolePermit;join_tables,permit_tables=tables(join_kind),tables(permit_kind)

    def require_startup_permit(value,subject,*,role):
        record=permits.get(id(value));need(type(record) is dict and record['permit'] is value and type(value) is permit_kind)
        need(not record['failed'] and not failed and not retained)
        try:
            need(record['subject'] is subject and type(role) is str and role==record['role'] and record['phase']=='closed' and record['known_closed'] and not record['unknown'] and not record['failed'] and not failed and not retained);guard(record)
        except BaseException as problem:retain(record,'permit-boundary',problem);deny()
        return value

    def prepare_startup_join(role,subject,*,endpoint,endpoint_identity,expected_parent,expected_binding,expected_peer_pid,
            parent_module,os_module,sys_module,socket_module,raw_constants_module,fcntl_module,select_module,clock,seconds=15,protected_fds=()):
        nonlocal used
        need(not used and not failed and not retained and type(public) is list and not public)
        need(type(role) is str and role in ('execute','capture') and subject is not None)
        end=closed(endpoint_identity,('fd','identity'));number(end['fd'],1048576);need(end['fd']>=3)
        identity=closed(end['identity'],fields);need(all(type(identity[key]) is int and identity[key]>=0 for key in fields));identity=tuple(identity[key] for key in fields)
        need(identity[2]&0o170000==0o140000 and identity[3:5]==(0,0) and identity[1]>0 and identity[5]>0)
        parent=closed(expected_parent,('pid','start','bootId'));parent=dict(parent);number(parent['pid']);number(parent['start'],2**64);boot(parent['bootId'])
        bound,binding_sha=binding(expected_binding)
        if role=='execute':number(expected_peer_pid);need(expected_peer_pid!=parent['pid'])
        else:need(expected_peer_pid is None)
        need(type(protected_fds) is tuple and len(protected_fds)<=32 and all(type(fd) is int and 3<=fd<1048576 for fd in protected_fds)
             and len(set(protected_fds))==len(protected_fds) and end['fd'] not in protected_fds)
        need(kinds(seconds,(int,float)) and finite(seconds) and 0<seconds<=15)
        modules=tuple(capture(value) for value in (parent_module,os_module,sys_module,socket_module,raw_constants_module,fcntl_module,select_module))
        o,s,c,f,se,p=(os_module,socket_module,raw_constants_module,fcntl_module,select_module,parent_module)
        need(type(vars(sys_module).get('platform')) is str and vars(sys_module)['platform']=='linux' and type(vars(o).get('name')) is str and vars(o)['name']=='posix')
        constants=dict(AF_UNIX=1,SOCK_SEQPACKET=5,SOL_SOCKET=1,SO_PASSCRED=16,SCM_CREDENTIALS=2,SCM_RIGHTS=1,MSG_CTRUNC=8,MSG_TRUNC=32,MSG_CMSG_CLOEXEC=1073741824)
        need(all(type(vars(c).get(key)) is int and vars(c)[key]==value for key,value in constants.items()))
        need(vars(s).get('_socket') is c)
        socket_kind=vars(s).get('socket');socket_tables=tables(socket_kind);need(type(endpoint) is socket_kind and gettype(socket_kind,'__dictoffset__')==0)
        socket_fields={key:next((value for owner,bases,mro,items in socket_tables[0] for name,value in items if name==key and kinds(value,descriptor_kinds)),None) for key in ('family','type','proto','_io_refs','_closed')}
        need(all(kinds(value,descriptor_kinds) for value in socket_fields.values()))
        ops={name:vars(o).get(name) for name in ('getpid','getppid','getresuid','getresgid','uname','open','stat','fstat','pread','close')}
        ops.update(clock=clock,fcntl=vars(f).get('fcntl'),poll_factory=vars(se).get('poll'),parent_stat=vars(p).get('parent_stat'),process_status=vars(p).get('process_status'))
        for name in ('fileno','sendmsg','recvmsg','getsockopt','close'):
            descriptor=definition(socket_tables,name);need(kinds(descriptor,(fn,MethodDescriptorType)));ops['socket_close' if name=='close' else name]=descriptor.__get__(endpoint,socket_kind)
        stat_kind=vars(o).get('stat_result');uname_kind=vars(o).get('uname_result');stat_tables,uname_tables=tables(stat_kind),tables(uname_kind)
        stat_fields={key:definition(stat_tables,key) for key in fields};machine=definition(uname_tables,'machine');need(all(kinds(value,descriptor_kinds) for value in (*stat_fields.values(),machine)))
        functions={key:function(value) for key,value in ops.items()}
        record=dict(role=role,subject=subject,endpoint=endpoint,socket_kind=socket_kind,socket_tables=socket_tables,socket_fields=socket_fields,
            parent=proxy(parent),binding=bound,binding_sha=binding_sha,peer_pid=expected_peer_pid,protected=protected_fds,seconds=seconds,
            modules=modules,ops=ops,functions=functions,stat_kind=stat_kind,stat_tables=stat_tables,stat_fields=stat_fields,
            uname_kind=uname_kind,uname_tables=uname_tables,uname_machine=machine,own=tuple(namespace.items()),
            own_functions=tuple(function(value) for value in namespace.values() if type(value) is fn),error_tables=tables(error_kind),
            rows=[],excess_acquisitions=[],returns=[],problem_refs=[],cleanup_errors=[],acquisition_attempts=[],calls=0,cleanup_calls=0,read_bytes=0,unknown=False,known_closed=False,failed=False,
            phase='prepared',send_attempted=False,recv_attempted=False,raw_recv=None,send_return=None,process_rows={},births={},
            poll=None,poll_kind=None,poll_tables=None,last=None,deadline=None)
        used=True;join=object.__new__(join_kind);record['join']=join;records[id(join)]=record
        record['endpoint_row']=own(record,end['fd'],'endpoint',wrapper=endpoint,expected=identity)
        try:
            guard(record);poll=call(record,'poll_factory');record['poll']=poll;record['poll_kind']=type(poll);record['poll_tables']=tables(type(poll))
            need(gettype(type(poll),'__dictoffset__')==0)
            for key,name in (('poll_register','register'),('poll_wait','poll')):
                descriptor=definition(record['poll_tables'],name);need(kinds(descriptor,(fn,MethodDescriptorType)));ops[key]=descriptor.__get__(poll,type(poll));functions[key]=function(ops[key])
            need(call(record,'poll_register',end['fd'],1|4|16|8) is None);socket_check(record);return join
        except BaseException as problem:
            retain(record,'startup-prepare',problem)
            try:finish(record)
            except BaseException as cleanup:record['problem_refs'].append(('prepare-finish',cleanup))
            deny()

    def main():deny()
    return StartupJoin,RolePermit,prepare_startup_join,require_startup_permit,main


StartupJoin,RolePermit,prepare_startup_join,require_startup_permit,main=_factory(globals(),UNRELEASED,StartupUnavailable,
    (type,dict,tuple,list,set,str,int,float,bool,bytes,len,all,any,vars,object,range,min,max,reversed,id,next,property,classmethod,staticmethod,BaseException))
del _factory


if __name__=='__main__':
    raise SystemExit(74)
