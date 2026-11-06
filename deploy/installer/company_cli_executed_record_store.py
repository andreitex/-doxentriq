"""Exclusive executed.json storage DATA, with explicit trusted Linux primitives.

The bytes are opaque. Original CLI closure, their semantic/origin validation,
encrypted backing and complete endpoint/OFD-copy ownership remain external.
The caller must close its original borrowed PublisherIO before this directory
mutation. No flag is accepted as proof, and no evidence/ACK is issued here.
"""
import hashlib
import math
from types import BuiltinFunctionType, FunctionType, MappingProxyType, ModuleType

FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_RECORD = 32768
MAX_ROWS = 8
MAX_CALLS = 384
UNRELEASED = []


class RecordStoreUnavailable(ValueError):
    pass


def _factory(namespace, public, error_type, primitives):
    # Fixed one-shot primitive refs; adding public builtin aliases cannot
    # execute new callbacks while the original namespace guard refuses drift.
    type,dict,vars,all,any,len,set,tuple,int,float,str,bytes,zip,reversed,object,BaseException=primitives
    used = failed = active = False
    retained = []
    last = None
    fields, maximum, row_limit, call_limit = FIELDS, MAX_RECORD, MAX_ROWS, MAX_CALLS
    proxy, module_kind = MappingProxyType, ModuleType
    function_kind, builtin_kind = FunctionType, BuiltinFunctionType
    finite, raw_hash = math.isfinite, hashlib.sha256
    def isdir(value):return value&0o170000==0o040000
    def isreg(value):return value&0o170000==0o100000
    def mode(value):return value&0o7777
    getattribute = object.__getattribute__
    origin = None
    original_methods = ()
    error_table = tuple(vars(error_type).items())
    error_bases, error_mro = error_type.__bases__, error_type.__mro__
    error_new, error_init = BaseException.__new__, BaseException.__init__

    def refusal():
        # Construct through saved built-ins, never a live public class method.
        problem=error_new(error_type)
        error_init(problem,'company-executed-record-store-unavailable')
        return problem

    def need(value):
        if value is not True:
            raise refusal()

    def same(current, expected):
        need(type(current) is dict and all(type(k) is str for k in current) and len(current) == len(expected)
             and all(k in current and current[k] is v for k,v in expected))

    def source_guard():
        same(namespace, origin)
        same(dict(vars(error_type)), error_table)
        need(error_type.__bases__ is error_bases and error_type.__mro__ is error_mro)
        for row in original_methods:callback_guard(row)

    def callback_snapshot(value):
        need(type(value) in (function_kind,builtin_kind))
        if type(value) is function_kind:
            return (value,value.__code__,value.__closure__,value.__defaults__,value.__kwdefaults__,tuple(vars(value).items()))
        return (value,None,None,None,None,None)

    def callback_guard(row):
        value,code,closure,defaults,kwdefaults,attributes = row
        if code is not None:
            need(type(value) is function_kind and value.__code__ is code and value.__closure__ is closure
                 and value.__defaults__ is defaults and value.__kwdefaults__ is kwdefaults)
            same(dict(vars(value)),attributes)

    def shape(value, keys):
        need(type(value) is dict and all(type(k) is str for k in value) and set(value) == set(keys))

    def metadata(value):
        shape(value,fields)
        need(all(type(v) is int and 0 <= v < 2**64 for v in value.values()))
        return tuple(value[key] for key in fields)

    def observe_release():
        """Detached private-ledger facts only, never closure/evidence authority."""
        source_guard()
        need(last is not None and not active)
        return proxy(dict(scope='EXECUTED_RECORD_STORAGE_RELEASE_DATA_ONLY', operationSucceeded=last['success'],
            ownedResourcesKnownReleased=last['known'], unknownReferences=len(last['unknown']),
            fileMayExist=last['file_possible'], repeatPermitted=False, sourceOriginQualified=False,
            recordOriginQualified=False, encryptedBackingQualified=False, executionEvidenceIssued=False, stageAcknowledged=False))

    def store_executed_record(stage_directory, *, expected_directory_metadata, completed_record_raw,
            os_module, sys_module, fcntl_module, clock, protected_fds=(), seconds=5):
        nonlocal used,failed,active,last
        source_guard()
        need(not used and not failed and not retained and not active)
        need(type(stage_directory) is str)
        parts=stage_directory.split('/')
        need(len(parts)==6 and parts[:4]==['','opt','autosoft-company','evidence']
             and len(parts[4])==32 and all(c in 'abcdef0123456789' for c in parts[4]) and parts[4]!='0'*32
             and parts[5] in ('company-platform-store','company-source-materialize'))
        expected = metadata(expected_directory_metadata)
        need(isdir(expected[2]) and mode(expected[2]) == 0o700 and expected[3:5] == (0,0) and expected[5] >= 2)
        need(type(completed_record_raw) is bytes and 0 < len(completed_record_raw) <= maximum)
        need(type(protected_fds) is tuple and len(protected_fds) <= 64
             and all(type(fd) is int and 3 <= fd < 1048576 for fd in protected_fds) and len(set(protected_fds)) == len(protected_fds))
        need(type(seconds) in (int,float) and finite(seconds) and 0 < seconds <= 5)
        need(all(type(m) is module_kind for m in (os_module,sys_module,fcntl_module)))
        names = ('open','fstat','stat','pread','write','fchmod','fsync','close','getuid','getgid','geteuid','getegid')
        ops = {key:vars(os_module).get(key) for key in names}
        constants = {key:vars(os_module).get(key) for key in ('O_RDONLY','O_RDWR','O_DIRECTORY','O_NOFOLLOW','O_CLOEXEC','O_NONBLOCK','O_CREAT','O_EXCL')}
        need(all(type(v) is int for v in constants.values()) and tuple(constants.values()) == (0,2,65536,131072,524288,2048,64,128))
        native_name, native_platform = vars(os_module).get('name'),vars(sys_module).get('platform')
        need(type(native_name) is type(native_platform) is str and native_name == 'posix' and native_platform == 'linux')
        supports, follows = vars(os_module).get('supports_dir_fd'),vars(os_module).get('supports_follow_symlinks')
        need(type(supports) is type(follows) is set
             and all(type(v) in (function_kind,builtin_kind) for v in supports)
             and all(type(v) in (function_kind,builtin_kind) for v in follows)
             and all(type(v) in (function_kind,builtin_kind) for v in ops.values()))
        need(ops['open'] in supports and ops['stat'] in supports and ops['stat'] in follows)
        stat_kind = vars(os_module).get('stat_result')
        need(type(stat_kind) is type)
        stat_table = tuple(vars(stat_kind).items())
        fc = vars(fcntl_module).get('fcntl')
        fconstants=tuple(vars(fcntl_module).get(k) for k in ('F_GETFL','F_GETFD','FD_CLOEXEC'))
        need(all(type(v) is int for v in fconstants) and fconstants == (3,1,1))
        callbacks = tuple(callback_snapshot(value) for value in (*ops.values(),fc,clock))
        namespaces = tuple((m,tuple(vars(m).items())) for m in (os_module,sys_module,fcntl_module))
        need(all(len(table)<=512 and all(type(k) is str for k,v in table) for m,table in namespaces))
        memberships = ((supports,tuple(supports)),(follows,tuple(follows)))
        record = dict(path=stage_directory+'/executed.json', raw=completed_record_raw, expected=expected,
            rows=[], attempts=[], returns=[], acquisitions=[], unknown=[], directories=[], file=None,
            success=False, known=False, file_possible=False, calls=0, namespaces=namespaces,
            callbacks=callbacks, stat_kind=stat_kind, stat_table=stat_table, memberships=memberships,
            os=os_module,sys=sys_module,fcntl=fcntl_module,clock=clock,source=namespace,
            ops=ops, raw_close=ops['close'], error=None, release_errors=[])
        used = active = True
        last = record

        def guard():
            source_guard()
            for m,table in namespaces:same(dict(vars(m)),table)
            same(dict(vars(stat_kind)),stat_table)
            for row in callbacks:callback_guard(row)
            for current,table in memberships:
                need(type(current) is set and len(current)==len(table)
                     and all(any(value is old for old in table) for value in current))

        def call(label,*args,**kwargs):
            guard();record['calls']+=1;need(record['calls']<=call_limit)
            record['attempts'].append((label,args,kwargs))
            try:answer=(fc if label=='fcntl' else ops[label])(*args,**kwargs)
            except BaseException as problem:
                record['returns'].append((label,'raised',problem));raise
            record['returns'].append((label,'returned',answer))
            guard();return answer

        def tick():
            guard();answer=clock();record['returns'].append(('clock','returned',answer));guard()
            need(type(answer) in (int,float) and finite(answer) and start <= answer < end)

        def values(info):
            need(type(info) is stat_kind)
            result=tuple(getattribute(info,k) for k in fields)
            need(all(type(v) is int and 0<=v<2**64 for v in result));return result

        def pair(row):
            actual=values(call('fstat',row['fd']))
            path=values(call('stat',row['name'],dir_fd=row['parent'],follow_symlinks=False))
            if actual != path:
                row['uncertain']=True;need(False)
            return actual

        def acquire(name, flags, parent, role, mode_value=None):
            tick();args=(name,flags) if mode_value is None else (name,flags,mode_value)
            guard();record['calls']+=1;need(record['calls']<=call_limit)
            attempt=(ops['open'],args,parent,role);record['attempts'].append(('open',attempt))
            if role=='file':record['file_possible']=True
            try:fd=ops['open'](*args,dir_fd=parent)
            except BaseException as problem:
                outcome=(attempt,'unreturned',problem);record['acquisitions'].append(outcome);record['unknown'].append(outcome);raise
            outcome=(attempt,'returned',fd);record['acquisitions'].append(outcome);record['returns'].append(('open','returned',fd))
            # Save the actual acquisition before ANY post-call check. Numeric
            # alias/baseline/protected outcomes are never guessed or closed.
            live=[row for row in record['rows'] if not row['closed']]
            if not(type(fd) is int and 3<=fd<1048576 and fd not in protected_fds and len(record['rows'])<row_limit and all(row['fd']!=fd for row in live)):
                for row in live:
                    if type(fd) is int and row['fd']==fd:row['uncertain']=True
                record['unknown'].append(outcome);need(False)
            row=dict(fd=fd,name=name,parent=parent,role=role,identity=None,flags=None,attempted=False,closed=False,uncertain=False)
            record['rows'].append(row)
            guard()
            row['identity']=pair(row)
            flags_observed,fdflags=call('fcntl',fd,3),call('fcntl',fd,1)
            wanted=131072|2048|(65536 if role=='directory' else 2)
            need(type(flags_observed) is type(fdflags) is int and flags_observed&~32768==wanted and fdflags==1)
            row['flags']=flags_observed
            return row

        def check_row(row):
            actual=pair(row)
            if actual!=row['identity']:
                row['uncertain']=True;need(False)
            flags_now,fdflags=call('fcntl',row['fd'],3),call('fcntl',row['fd'],1)
            if type(flags_now) is not int or type(fdflags) is not int or flags_now!=row['flags'] or fdflags!=1:
                row['uncertain']=True;need(False)

        def anchors():
            tick()
            for row in record['directories']:check_row(row)

        def refresh(row, expected_mode=None, expected_size=None):
            actual=pair(row);old=row['identity']
            stable=(0,1,3,4,5) if row['role']=='file' else (0,1,2,3,4,5)
            need(all(actual[k]==old[k] for k in stable))
            if expected_mode is not None:need(isreg(actual[2]) and mode(actual[2])==expected_mode)
            if expected_size is not None:need(actual[6]==expected_size)
            row['identity']=actual

        def close_known(row):
            if row['attempted'] or row['closed']:return
            if row['identity'] is None or row['uncertain']:
                record['unknown'].append(('unbound-owned-row',row));return
            try:
                guard();check_row(row)
            except BaseException as problem:
                row['uncertain']=True;record['unknown'].append(('close-boundary-unknown',row,problem));return
            row['attempted']=True
            # Saved primitive only. No live adapter method or close fallback.
            record['attempts'].append(('close',row,ops['close']))
            try:
                answer=ops['close'](row['fd']);record['returns'].append(('close','returned',answer))
                need(answer is None);row['closed']=True
            except BaseException as problem:
                record['returns'].append(('close','raised',problem));record['unknown'].append(('close-unknown',row,ops['close'],problem))
            try:guard()
            except BaseException as problem:record['unknown'].append(('post-close-origin-unknown',row,problem))

        start=end=None
        try:
            guard();start=clock();record['returns'].append(('clock','returned',start));guard()
            need(type(start) in (int,float) and finite(start) and start>=0);end=start+seconds
            for name in ('getuid','getgid','geteuid','getegid'):need(type(answer:=call(name)) is int and answer==0)
            parent=None
            for name in ['/',*stage_directory.split('/')[1:]]:
                row=acquire(name,0|65536|131072|524288|2048,parent,'directory')
                # Rocky may mount the root directory with mode0555. This is
                # stricter than0755; the terminal stage remains exactly0700.
                actual=row['identity'];need(isdir(actual[2]) and mode(actual[2]) in (0o555,0o700,0o755) and actual[3:5]==(0,0) and actual[5]>=2)
                record['directories'].append(row);parent=row['fd']
            stage=record['directories'][-1]
            need(stage['identity']==expected and mode(stage['identity'][2])==0o700)
            anchors()
            file=acquire('executed.json',2|64|128|131072|524288|2048,parent,'file',0o600);record['file']=file
            # Only this observed exclusive creation changes the held terminal
            # directory. Every ancestor remains full-nine immutable.
            refresh(stage)
            actual=file['identity'];need(isreg(actual[2]) and mode(actual[2])==0o600 and actual[3:6]==(0,0,1) and actual[6]==0)
            anchors();check_row(file)
            written=call('write',file['fd'],completed_record_raw)
            need(type(written) is int and 0<=written<=len(completed_record_raw))
            refresh(file,0o600,written)
            need(written==len(completed_record_raw))  # A short write is never looped/retried.
            anchors();check_row(file)
            need(call('fchmod',file['fd'],0o400) is None);refresh(file,0o400,len(completed_record_raw))
            anchors();check_row(file)
            need(call('fsync',file['fd']) is None)
            anchors();check_row(file)
            need(call('fsync',stage['fd']) is None)
            anchors();check_row(file)
            readback=call('pread',file['fd'],maximum+1,0);record['readback']=readback
            need(type(readback) is bytes and readback==completed_record_raw)
            check_row(file);anchors();record['success']=True
        except BaseException as problem:
            record['error']=problem;failed=True
        finally:
            for row in reversed(record['rows']):close_known(row)
            active=False
            record['known']=not record['unknown'] and all(row['closed'] for row in record['rows'])
            if record['error'] is not None or not record['known']:
                failed=True;record['success']=False;retained.append(record);public.append(record)
        if not record['success'] or not record['known']:
            raise refusal() from None
        file_meta=dict(zip(fields,record['file']['identity']))
        return proxy(dict(scope='EXECUTED_RECORD_STORED_DATA_ONLY',path=record['path'],sha256=raw_hash(completed_record_raw).hexdigest(),bytes=len(completed_record_raw),syscallAttempts=record['calls'],
            fileMetadata=proxy(file_meta),fileAndParentFsyncReturned=True,ownedResourcesKnownReleased=True,
            recordOriginQualified=False,sourceOriginQualified=False,encryptedBackingQualified=False,executionEvidenceIssued=False,stageAcknowledged=False))

    original_methods=tuple(callback_snapshot(value) for value in (store_executed_record,observe_release))
    origin=tuple((key,value) for key,value in namespace.items() if key!='_factory')
    origin=dict(origin);origin.update(store_executed_record=store_executed_record,observe_release=observe_release);origin=tuple(origin.items())
    return store_executed_record,observe_release


store_executed_record,observe_release=_factory(globals(),UNRELEASED,RecordStoreUnavailable,
    (type,dict,vars,all,any,len,set,tuple,int,float,str,bytes,zip,reversed,object,BaseException))
del _factory
