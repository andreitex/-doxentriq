"""Explicit bounded Ed25519 verifier; no native defaults or initial self-trust.

The company authenticates this module, supplied station modules/procfs, ELF
loader/libraries and independent OpenSSL pin before use. The literal sole-reaper
contract is a caller obligation, not proof from a boolean. A single Linux task
and default SIGCHLD are checked; they do not exclude another trusted wait user.
All input/executable bytes use sealed memfds. Only fixed verification arguments
are supported. Fifteen seconds includes disposal admission; blocking syscalls
and escaped descendants do not gain a universal deadline/cancellation claim.
OpenSSL semantics: https://docs.openssl.org/3.0/man1/openssl-pkeyutl/
WNOWAIT: https://man7.org/linux/man-pages/man2/waitid.2.html
"""
import base64
import hashlib
import math
import re
import stat
import sys as _python
from types import FunctionType, MappingProxyType, ModuleType

TOOL='/usr/bin/openssl'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ENV=MappingProxyType(dict(PATH='/usr/bin:/bin',HOME='/nonexistent',LANG='C',LC_ALL='C',TZ='UTC',
                        OPENSSL_CONF='/dev/null',OPENSSL_MODULES='/nonexistent'))
STATION_CONTRACT='trusted-company-release-crypto-exclusive-child-reaper-v1'
MAX_TOOL=8*1024**2
CHUNK=65536
CALL_SECONDS=15
DISPOSAL_SECONDS=3
UNRELEASED=[]
_OWNERS={}


class ReleaseCryptoUnavailable(ValueError):pass


def require(value):
    if value is not True:raise ReleaseCryptoUnavailable('company-release-crypto-unavailable')


def _items(current,expected):
    require(type(current) is dict and all(type(k) is str for k in current)
            and set(current)==set(expected) and all(current[k] is expected[k] for k in expected))


def _meta(value):
    answer={name:getattr(value,name,None) for name in FIELDS}
    require(all(type(number) is int and number>=0 for number in answer.values()))
    return answer


def _pin(value):
    require(type(value) is dict and set(value)=={'bytes','sha256','identity'}
            and type(value['bytes']) is int and 64<=value['bytes']<=MAX_TOOL
            and type(value['sha256']) is str and re.fullmatch('[a-f0-9]{64}',value['sha256']) is not None
            and type(value['identity']) is dict and set(value['identity'])==set(FIELDS)
            and all(type(number) is int and number>=0 for number in value['identity'].values())
            and value['identity']['st_size']==value['bytes'])
    return dict(bytes=value['bytes'],sha256=value['sha256'],identity=dict(value['identity']))


def _inputs(message,signature,key):
    require(type(message) is bytes and 0<len(message)<=16384 and type(signature) is bytes
            and len(signature)==64 and type(key) is bytes and 0<len(key)<=4096)
    match=re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----\r?\n',key)
    require(match is not None)
    try:der=base64.b64decode(match[1].replace(b'\r',b'').replace(b'\n',b''),validate=True)
    except ValueError:raise ReleaseCryptoUnavailable('company-release-crypto-unavailable') from None
    require(len(der)==44 and der[:12]==bytes.fromhex('302a300506032b6570032100'))
    return (message,signature,key)


def _tick(r,end):
    value=r['clock']()
    require(type(value) in (int,float) and math.isfinite(value) and value>=r['last'] and value<end)
    r['last']=value
    return value


def _signal_number(value):
    # Actual CPython signal constants/handlers are int-backed enums. Read the
    # builtin integer payload without invoking a supplied __int__ callback.
    require(isinstance(value,int) and type(value) is not bool)
    return int.__int__(value)


def _record(value):
    r=_OWNERS.get(id(value));require(type(r) is dict and r['owner'] is value and type(value) is r['kind'])
    _items(dict(vars(r['kind'])),r['methods'])
    state=object.__getattribute__(value,'__dict__')
    require(type(state) is dict and state is r['state'] and not state)
    require(type(r['module']) is ModuleType)
    _items({k:v for k,v in vars(r['module']).items() if k!='__builtins__'},r['namespace'])
    for name,module in r['modules'].items():
        require(type(module) is ModuleType)
        require(all(vars(module).get(key) is ref for key,ref in r['bound'][name].items()))
    _items(dict(vars(r['process_type'])),r['process_methods'])
    _items(dict(vars(r['info_type'])),r['info_methods'])
    return r


def _own(j,fd,role):
    require(j['rows'] is j['r']['pending'][1] and j['registrations'] is j['r']['pending'][2])
    if type(fd) is not int or fd<3 or fd in j['protected'] or any(row['fd']==fd and row['closed'] is not True for row in j['rows']) or len(j['rows'])>=16:
        j['unknown']=True;j['unknown_refs'].append((role,fd))
        raise ReleaseCryptoUnavailable('company-release-crypto-unavailable')
    row=dict(fd=fd,role=role,attempted=False,closed=False);j['rows'].append(row)
    j['registrations'].append((fd,row,role))
    j['r']['pending'][3].append(j['registrations'][-1])
    require(j['r']['bound']['os']['get_inheritable'](fd) is False)
    return fd


def _station(j):
    r=j['r'];_record(r['owner']);o=r['bound']['os'];sig=r['bound']['signal'];_tick(r,j['end'])
    pid=o['getpid']();require(type(pid) is int and pid>1)
    path='/proc/'+str(pid)+'/status';fd=None;registration=None
    try:
        fd=_own(j,o['open'](path,o['O_RDONLY']|o['O_NOFOLLOW']|o['O_CLOEXEC']|o['O_NONBLOCK']),'station')
        registration=j['rows'][-1]
        before=_meta(o['fstat'](fd));require(stat.S_ISREG(before['st_mode']) and before['st_uid']==before['st_gid']==0)
        raw=b''
        for attempt in range(5):
            _tick(r,j['end']);part=o['pread'](fd,min(4096,16385-len(raw)),len(raw))
            require(type(part) is bytes and len(part)<=min(4096,16385-len(raw)));raw+=part
            require(len(raw)<=16384)
            if not part:break
        else:raise ReleaseCryptoUnavailable('company-release-crypto-unavailable')
        require(_meta(o['fstat'](fd))==before==_meta(o['lstat'](path)))
        tasks=[line for line in raw.splitlines() if line.startswith(b'Threads:')]
        require(len(tasks)==1 and re.fullmatch(rb'Threads:[ \t]+1',tasks[0]) is not None
                and _signal_number(sig['getsignal'](j['r']['signals']['SIGCHLD']))==j['r']['signals']['SIG_DFL'])
        require(type(r['active_processes']) is list and not r['active_processes'])
    finally:
        if registration is not None:
            registration['attempted']=True
            require(r['raw_close'](fd) is None);registration['closed']=True


def _read(j,fd,size,offset):
    r=j['r'];_tick(r,j['end']);require(type(size) is int and 0<size<=CHUNK
            and type(offset) is int and offset>=0 and j['read_bytes']+size<=8*MAX_TOOL+131072)
    raw=r['bound']['os']['pread'](fd,size,offset)
    require(type(raw) is bytes and len(raw)<=size);j['read_bytes']+=len(raw)
    return raw


def _sealed(j,fd,raw):
    o=j['r']['bound']['os'];f=j['r']['bound']['fcntl'];_tick(j['r'],j['end'])
    before=_meta(o['fstat'](fd))
    require(stat.S_ISREG(before['st_mode']) and before['st_nlink']==0 and before['st_size']==len(raw)
            and before['st_uid']==before['st_gid']==0 and o['get_inheritable'](fd) is False
            and f['fcntl'](fd,f['F_GET_SEALS'])==j['seals'])
    digest=hashlib.sha256();offset=0
    while offset<len(raw):
        part=_read(j,fd,min(CHUNK,len(raw)-offset),offset);require(len(part)>0)
        digest.update(part);offset+=len(part)
    require(_read(j,fd,1,offset)==b'' and digest.digest()==hashlib.sha256(raw).digest())
    require(_meta(o['fstat'](fd))==before==_meta(o['stat']('/proc/self/fd/'+str(fd))))


def _memfd(j,name,raw,executable=False):
    o=j['r']['bound']['os'];f=j['r']['bound']['fcntl']
    fd=_own(j,o['memfd_create'](name,o['MFD_CLOEXEC']|o['MFD_ALLOW_SEALING']),'executable' if executable else 'input')
    offset=0
    while offset<len(raw):
        _tick(j['r'],j['capture_end']);count=o['write'](fd,raw[offset:offset+CHUNK])
        require(type(count) is int and 0<count<=min(CHUNK,len(raw)-offset));offset+=count
    require(o['fchmod'](fd,0o500 if executable else 0o400) is None)
    answer=f['fcntl'](fd,f['F_ADD_SEALS'],j['seals']);require(type(answer) is int and answer==0)
    _sealed(j,fd,raw);j['sealed'].append((fd,raw));return fd


def _tool(j):
    o=j['r']['bound']['os'];parent=None
    for path,name,directory in (('/','/',True),('/usr','usr',True),('/usr/bin','bin',True),(TOOL,'openssl',False)):
        _tick(j['r'],j['capture_end']);before=_meta(o['lstat'](path))
        require(before['st_uid']==before['st_gid']==0 and not stat.S_IMODE(before['st_mode'])&0o022
                and stat.S_IFMT(before['st_mode'])==(stat.S_IFDIR if directory else stat.S_IFREG)
                and (directory or before['st_nlink']==1 and stat.S_IMODE(before['st_mode']) in (0o500,0o555,0o755)))
        fd=_own(j,o['open'](name,o['O_RDONLY']|o['O_NOFOLLOW']|o['O_CLOEXEC']|
                (o['O_DIRECTORY'] if directory else o['O_NONBLOCK']),dir_fd=parent),'tool-directory' if directory else 'tool')
        require(before==_meta(o['fstat'](fd))==_meta(o['lstat'](path)));j['paths'].append((path,fd,before));parent=fd
    pin=j['r']['pin'];require(before==pin['identity']);raw=b''
    while len(raw)<pin['bytes']:
        part=_read(j,parent,min(CHUNK,pin['bytes']-len(raw)),len(raw));require(len(part)>0);raw+=part
    require(_read(j,parent,1,len(raw))==b'' and hashlib.sha256(raw).hexdigest()==pin['sha256']
            and raw[:7]==b'\x7fELF\x02\x01\x01' and raw[18:20]==b'\x3e\x00')
    j['tool_bytes']=raw;j['executable']=_memfd(j,'company-release-openssl',raw,True)


def _guard(j):
    r=j['r'];_record(r['owner']);o=r['bound']['os']
    for path,fd,before in j['paths']:
        require(o['get_inheritable'](fd) is False and before==_meta(o['lstat'](path))==_meta(o['fstat'](fd)))
    for fd,raw in j['sealed']:_sealed(j,fd,raw)
    raw=j['tool_bytes'];digest=hashlib.sha256();offset=0;fd=j['paths'][-1][1]
    while offset<len(raw):
        part=_read(j,fd,min(CHUNK,len(raw)-offset),offset);require(len(part)>0);digest.update(part);offset+=len(part)
    require(_read(j,fd,1,offset)==b'' and digest.hexdigest()==r['pin']['sha256'])


def _info(j,info):
    r=j['r'];require(type(info) is r['info_type']);o=r['bound']['os']
    require(type(info.si_pid) is int and info.si_pid==j['pid'] and type(info.si_code) is int and type(info.si_status) is int)
    if info.si_code==o['CLD_EXITED']:require(0<=info.si_status<=255);return info.si_status
    require(info.si_code in (o['CLD_KILLED'],o['CLD_DUMPED']) and 0<info.si_status<r['signals']['NSIG'])
    return -info.si_status


def _ownership(j):
    r=j['r'];_record(r['owner']);o=r['bound']['os'];require(j['pidfd'] is not None and not j['reaped'])
    original=r['child'];require(type(original) is tuple and len(original)==5
            and j['process'] is original[0] and type(j['process']) is r['process_type']
            and j['process_state'] is original[1] and type(j['pid']) is int and j['pid']==original[2]
            and type(j['pidfd']) is int and j['pidfd']==original[3])
    state=object.__getattribute__(j['process'],'__dict__')
    require(type(j['process']) is r['process_type'] and type(state) is dict and state is j['process_state']
            and dict.get(state,'pid')==j['pid'] and dict.get(state,'returncode') is None
            and all(dict.get(state,name) is None for name in ('stdin','stdout','stderr')))
    require(_meta(o['fstat'](j['pidfd']))==original[4] and o['get_inheritable'](j['pidfd']) is False)
    info=o['waitid'](o['P_PIDFD'],j['pidfd'],o['WEXITED']|o['WNOHANG']|o['WNOWAIT'])
    if info is not None:
        code=_info(j,info);require(j['exit_code'] is None or j['exit_code']==code)
    return info


def _poll(j,end):
    remaining=end-_tick(j['r'],end);j['poll_count']+=1;require(j['poll_count']<=500)
    kind=j['poll_type'];require(type(j['poller']) is kind);_items(dict(vars(kind)),j['poll_methods'])
    events=j['poll_function'](j['poller'],min(40,max(1,int(remaining*1000))))
    require(type(events) is list and len(events)<=1 and all(type(row) is tuple and len(row)==2
            and type(row[0]) is int and row[0]==j['pidfd'] and type(row[1]) is int for row in events))
    for fd,mask in events:
        allowed=j['r']['bound']['select'];require(mask>0 and not mask&allowed['POLLNVAL']
            and mask&~(allowed['POLLIN']|allowed['POLLHUP']|allowed['POLLERR'])==0)


def _start(j):
    r=j['r'];o=r['bound']['os'];_guard(j);_station(j);_tick(r,j['capture_end'])
    null=_own(j,o['open']('/dev/null',o['O_RDWR']|o['O_NOFOLLOW']|o['O_CLOEXEC']|o['O_NONBLOCK']),'null')
    meta=_meta(o['fstat'](null));device=o['fstat'](null).st_rdev
    require(stat.S_ISCHR(meta['st_mode']) and meta['st_uid']==meta['st_gid']==0
            and type(device) is int and o['major'](device)==1 and o['minor'](device)==3
            and meta==_meta(o['lstat']('/dev/null')))
    message,signature,key=j['inputs']
    argv=[TOOL,'pkeyutl','-verify','-rawin','-pubin','-inkey','/proc/self/fd/'+str(key),
          '-in','/proc/self/fd/'+str(message),'-sigfile','/proc/self/fd/'+str(signature)]
    j['possible_launch']=True
    process=r['bound']['subprocess']['Popen'](argv,executable='/proc/self/fd/'+str(j['executable']),
            stdin=null,stdout=null,stderr=null,env=dict(ENV),cwd='/',close_fds=True,
            pass_fds=(j['executable'],message,signature,key),start_new_session=True,shell=False)
    j['process']=process;require(type(process) is r['process_type'])
    state=object.__getattribute__(process,'__dict__');require(type(state) is dict)
    j['process_state']=state;j['pid']=dict.get(state,'pid');require(type(j['pid']) is int and j['pid']>1)
    r['child']=(process,state,j['pid'],None,None)
    j['pidfd']=_own(j,o['pidfd_open'](j['pid'],0),'pidfd');j['pidfd_meta']=_meta(o['fstat'](j['pidfd']))
    r['child']=(process,state,j['pid'],j['pidfd'],dict(j['pidfd_meta']))
    poll=r['bound']['select']['poll']();kind=type(poll);require(type(kind) is type)
    methods=dict(vars(kind));require(callable(methods.get('register')) and callable(methods.get('poll')))
    j.update(poller=poll,poll_type=kind,poll_methods=methods,poll_function=methods['poll'])
    require(methods['register'](poll,j['pidfd'],r['bound']['select']['POLLIN']|r['bound']['select']['POLLHUP']|r['bound']['select']['POLLERR']) is None)
    while True:
        _tick(r,j['capture_end']);info=_ownership(j)
        if info is not None:j['exit_code']=_info(j,info);break
        _poll(j,j['capture_end'])
    _guard(j)


def _finish(j):
    # Captured raw close is used even when module/class callbacks drift. No
    # foreign close method, numeric-PID fallback or uncertain-close retry.
    r=j['r'];errors=[];stable=False
    try:
        # No live module helper/class callback is invoked before this check.
        if type(r['module']) is not ModuleType or type(r['owner']) is not r['kind']:
            raise ValueError('original-owner-type-drift')
        current={k:v for k,v in vars(r['module']).items() if k!='__builtins__'}
        methods=dict(vars(r['kind']))
        state=object.__getattribute__(r['owner'],'__dict__')
        stable=(type(r['owner']) is r['kind'] and type(state) is dict and state is r['state'] and not state
                and set(current)==set(r['namespace']) and all(current[k] is v for k,v in r['namespace'].items())
                and set(methods)==set(r['methods']) and all(methods[k] is v for k,v in r['methods'].items())
                and all(type(module) is ModuleType and all(vars(module).get(k) is ref for k,ref in r['bound'][name].items())
                        for name,module in r['modules'].items()))
        if not stable:errors.append('station-or-callback-drift')
    except BaseException as error:errors.append(error)
    if j['possible_launch'] and stable:
        try:
            _station(j);o=r['bound']['os'];require(j['process'] is not None and j['pidfd'] is not None)
            require(o['getpgid'](j['pid'])==j['pid']);_ownership(j) # immediately before group signal
            try:require(o['killpg'](j['pid'],r['signals']['SIGKILL']) is None)
            except ProcessLookupError:pass
            for attempt in range(75):
                _tick(r,j['end']);info=o['waitid'](o['P_PIDFD'],j['pidfd'],o['WEXITED']|o['WNOHANG'])
                if info is not None:
                    code=_info(j,info);require(j['exit_code'] is None or code==j['exit_code'])
                    j['exit_code']=code;j['reaped']=True;dict.__setitem__(j['process_state'],'returncode',code);break
                _poll(j,j['end'])
            require(j['reaped'])
            try:o['killpg'](j['pid'],0)
            except ProcessLookupError:j['group_absent']=True
            require(j['group_absent'])
        except BaseException as error:errors.append(error)
    elif j['possible_launch']:errors.append('child-release-unknown')
    pending=r['pending'];rows,registrations,originals=pending[1:]
    if r['job'] is not j or j['rows'] is not rows or j['registrations'] is not registrations:
        errors.append(('owned-ledger-replaced',r['job'],j.get('rows'),j.get('registrations')))
    elif type(rows) is not list or type(registrations) is not list or type(originals) is not list or len(rows)!=len(registrations) or len(rows)!=len(originals) or len(rows)>16:
        errors.append(('owned-ledger-opaque',rows,registrations))
    else:
        roles=('station','tool-directory','tool','executable','input','null','pidfd')
        for original in reversed(originals):
            if type(original) is not tuple or len(original)!=3 or type(original[0]) is not int or original[0]<3 or type(original[1]) is not dict or type(original[2]) is not str or original[2] not in roles:
                errors.append(('original-registration-opaque',original));continue
            fd,row,role=original
            if not any(item is original for item in registrations) or not any(item is row for item in rows):
                errors.append(('owned-registration-missing',original));continue
            if type(row) is not dict or set(row)!= {'fd','role','attempted','closed'} or type(row.get('fd')) is not int or row['fd']!=fd or type(row.get('role')) is not str or row['role']!=role or type(row.get('attempted')) is not bool or type(row.get('closed')) is not bool:
                errors.append(('owned-row-opaque',fd,row));continue
            if row['attempted']:continue
            if role=='pidfd' and not j['reaped']:errors.append(('unreaped-pidfd',fd,row));continue
            row['attempted']=True
            try:
                if r['raw_close'](fd) is not None:raise ValueError('close-result-unknown')
                row['closed']=True
            except BaseException as error:errors.append((row,error))
    known=(not j['unknown'] and not errors and all(row['closed'] for row in rows)
           and (not j['possible_launch'] or j['reaped'] and j['group_absent']))
    j['released']=known
    if not known:list.append(r['unknown_ledger'],(r,j,pending,tuple(errors),tuple(j['unknown_refs'])))
    if not known:raise ValueError('company-release-crypto-release-unknown')


class ReleaseCrypto:
    def __init__(self,*,openssl_pin,budget,os_module,sys_module,subprocess_module,select_module,
                 signal_module,fcntl_module,clock,station_contract,protected_fds):
        require(type(self) is ReleaseCrypto and not UNRELEASED and len(_OWNERS)<64
                and type(station_contract) is str and station_contract==STATION_CONTRACT)
        pin=_pin(openssl_pin)
        require(type(budget) is dict and set(budget)=={'calls','seconds'} and type(budget['calls']) is int
                and 1<=budget['calls']<=16 and type(budget['seconds']) is int and 15<=budget['seconds']<=240
                and callable(clock) and type(protected_fds) is tuple and len(protected_fds)<=64
                and all(type(fd) is int and fd>=0 for fd in protected_fds) and len(set(protected_fds))==len(protected_fds))
        modules=dict(os=os_module,sys=sys_module,subprocess=subprocess_module,select=select_module,signal=signal_module,fcntl=fcntl_module)
        require(all(type(module) is ModuleType for module in modules.values()))
        names=dict(os=('name','open','lstat','stat','fstat','get_inheritable','pread','write','fchmod','close','memfd_create',
          'pidfd_open','waitid','waitid_result','getpgid','killpg','getpid','getuid','getgid','uname','major','minor',
          'O_RDONLY','O_RDWR','O_NOFOLLOW','O_CLOEXEC','O_DIRECTORY','O_NONBLOCK','MFD_CLOEXEC','MFD_ALLOW_SEALING',
          'P_PIDFD','WEXITED','WNOHANG','WNOWAIT','CLD_EXITED','CLD_KILLED','CLD_DUMPED'),sys=('platform','byteorder'),
          subprocess=('Popen','_active'),select=('poll','POLLIN','POLLHUP','POLLERR','POLLNVAL'),
          signal=('getsignal','SIGCHLD','SIG_DFL','SIGKILL','NSIG'),
          fcntl=('fcntl','F_ADD_SEALS','F_GET_SEALS','F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'))
        bound={name:{key:vars(modules[name]).get(key) for key in keys} for name,keys in names.items()}
        o=bound['os'];require(o['name']=='posix' and bound['sys']['platform']=='linux' and bound['sys']['byteorder']=='little')
        require(all(callable(o[key]) for key in names['os'] if key not in ('name','waitid_result') and not key.isupper())
                and all(type(o[key]) is int for key in names['os'] if key.isupper()))
        require(type(bound['subprocess']['Popen']) is type and type(o['waitid_result']) is type
                and type(bound['subprocess']['_active']) is list and not bound['subprocess']['_active'])
        require(callable(bound['select']['poll']) and callable(bound['signal']['getsignal']) and callable(bound['fcntl']['fcntl']))
        require(all(type(bound[name][key]) is int for name in ('select','fcntl') for key in names[name] if key.isupper()))
        signals={key:_signal_number(bound['signal'][key]) for key in names['signal'] if key.isupper()}
        require(signals['SIGCHLD']==17 and signals['SIGKILL']==9 and signals['SIG_DFL']==0 and signals['NSIG']==65)
        uid,gid,machine=o['getuid'](),o['getgid'](),o['uname']().machine
        require(type(uid) is int and type(gid) is int and uid==gid==0 and type(machine) is str and machine=='x86_64')
        initial=clock();require(type(initial) in (int,float) and math.isfinite(initial) and initial>=0)
        module=_python.modules[__name__]
        r=dict(owner=self,kind=type(self),methods=dict(vars(type(self))),state=vars(self),module=module,
               namespace={k:v for k,v in vars(module).items() if k!='__builtins__'},modules=modules,bound=bound,
               process_type=bound['subprocess']['Popen'],process_methods=dict(vars(bound['subprocess']['Popen'])),
               info_type=o['waitid_result'],info_methods=dict(vars(o['waitid_result'])),active_processes=bound['subprocess']['_active'],
               raw_close=o['close'],clock=clock,last=initial,deadline=initial+budget['seconds'],pin=pin,
               signals=signals,
               max_calls=budget['calls'],calls=0,job=None,pending=None,child=None,failed=False,protected=tuple(protected_fds),finish=_finish,
               unknown_ledger=UNRELEASED,unavailable=ReleaseCryptoUnavailable)
        _OWNERS[id(self)]=r
        # Copy this finite owned helper graph into an unexposed globals map.
        # Saved code cannot resolve a replaced module helper during unwind,
        # including drift caused by a station callback after its first check.
        namespace=dict(vars(module))
        for name in ('require','_items','_meta','_record','_own','_station','_tick','_signal_number','_info','_ownership','_poll','_finish'):
            original=namespace[name]
            namespace[name]=FunctionType(original.__code__,namespace,name,original.__defaults__,original.__closure__)
        r['finish']=namespace['_finish'];r['cleanup_namespace']=namespace

    def verify(self,message,signature,key):
        r=_record(self);job=None;error=None;unavailable=r['unavailable']
        try:
            require(not UNRELEASED and not r['failed'] and r['job'] is None and r['calls']<r['max_calls'])
            inputs=_inputs(message,signature,key);start=_tick(r,r['deadline']);end=min(start+CALL_SECONDS,r['deadline'])
            require(end-start>DISPOSAL_SECONDS);r['calls']+=1
            seals=0
            for name in ('F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'):seals|=r['bound']['fcntl'][name]
            job=dict(r=r,end=end,capture_end=end-DISPOSAL_SECONDS,rows=[],registrations=[],paths=[],sealed=[],seals=seals,
              read_bytes=0,protected=r['protected'],unknown=False,unknown_refs=[],possible_launch=False,process=None,
              process_state=None,pid=None,pidfd=None,pidfd_meta=None,reaped=False,group_absent=False,
              exit_code=None,released=False,poll_count=0)
            r['job']=job;r['child']=None;r['pending']=(job,job['rows'],job['registrations'],[]);_station(job);_tool(job)
            job['inputs']=tuple(_memfd(job,'company-release-'+str(index),raw) for index,raw in enumerate(inputs))
            _start(job);require(job['exit_code']==0)
        except BaseException as caught:error=caught;r['failed']=True
        finally:
            if job is not None:
                try:r['finish'](job);_tick(r,job['end'])
                except BaseException as caught:error=caught;r['failed']=True
                if job['released']:r['job']=None
        if error is not None:raise unavailable('company-release-crypto-unavailable') from None
        require(job is not None and job['released'] and job['exit_code']==0)
        return True

    def require_released(self):
        r=_record(self);require(r['job'] is None and not UNRELEASED)
        return self
