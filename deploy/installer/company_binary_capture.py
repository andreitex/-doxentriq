"""Explicit sibling binary pipe capture DATA only, no native defaults/evidence.

Company-authenticated original Bash hands over sole-owned read endpoints and
the fixed producer binding. FD numbers/metadata/JSON are not proof of that
origin or stage identity. This helper never spawns, waits, signals or ACKs.
"""
import errno,math,re,stat
from types import MappingProxyType,ModuleType
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
CAPS={'stdout':32768,'stderr':8192}
TOTAL=40960;CHUNK=4096;MAX_READS=4096;MAX_POLLS=8192
UNRELEASED=[]
class CaptureUnavailable(ValueError):pass
def _make_capture(ledger,error_type):
 failed=False;retained_records=[]
 def capture_binary(handoff,*,os_module,select_module,fcntl_module,clock,deadline):
  """Take exactly two caller-owned nonblocking/CLOEXEC read FDs once.
 
  Return immutable bytes/detached capture facts only after both syscall EOFs
  and known closes. On any uncertainty retain exact inputs/ops/rows/objects;
  ownership is never reconstructed from a later serialized report.
  """
  nonlocal failed
  error_kind=error_type;unknown_ledger=ledger;private_records=retained_records;proxy=MappingProxyType
  fields=FIELDS;caps=dict(CAPS);ifmt=stat.S_IFMT;fifo=stat.S_IFIFO
  max_polls=MAX_POLLS;max_reads=MAX_READS;chunk=CHUNK;total_cap=TOTAL
  again=(errno.EAGAIN,errno.EWOULDBLOCK);interrupted=errno.EINTR
  blocked_kind=BlockingIOError;interrupted_kind=InterruptedError
  def need(value):
   if value is not True:raise error_kind('company-binary-capture-unavailable')
  def metadata(info):
   value={name:getattr(info,name,None) for name in fields}
   need(all(type(item) is int and item>=0 for item in value.values()));return value
  need(not failed and not private_records and type(unknown_ledger) is list and not unknown_ledger and callable(clock))
  start=clock();need(type(start) in (int,float) and math.isfinite(start)
   and type(deadline) in (int,float) and math.isfinite(deadline) and 1<=deadline-start<=30)
  end=deadline-.25;last=start;polls=reads=total=0;poller=None;rows=[];error=None;errors=[]
  need(type(handoff) is dict and all(type(key) is str for key in handoff) and set(handoff)=={'binding','channels'})
  binding=handoff['binding'];channels=handoff['channels']
  wanted={'requestSha256','releaseSha256','deliverySha256','planSha256','actionSha256','inputSha256','stage','session','parentPid','childPid','parentStart','childStart','bootId'}
  need(type(binding) is dict and all(type(key) is str for key in binding) and set(binding)==wanted)
  need(all(type(binding[name]) is str and re.fullmatch('[a-f0-9]{64}',binding[name]) is not None for name in wanted if name.endswith('Sha256')))
  need(type(binding['stage']) is str and binding['stage'] in ('company-platform-store','company-source-materialize')
   and type(binding['session']) is str and re.fullmatch('s-[A-Za-z0-9]{12}',binding['session']) is not None
   and type(binding['bootId']) is str and re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',binding['bootId']) is not None)
  need(all(type(binding[name]) is int and binding[name]>1 for name in ('parentPid','childPid','parentStart','childStart'))
   and binding['parentPid']!=binding['childPid'])
  frozen_binding=dict(binding)
  need(type(channels) is dict and all(type(key) is str for key in channels) and set(channels)==set(caps))
  specs=[]
  for role in ('stdout','stderr'):
   value=channels[role];need(type(value) is dict and all(type(key) is str for key in value) and set(value)=={'fd','identity','flags','fdFlags'})
   need(type(value['fd']) is int and 3<=value['fd']<2**31 and type(value['flags']) is int and type(value['fdFlags']) is int
    and type(value['identity']) is dict and all(type(key) is str for key in value['identity']) and set(value['identity'])==set(fields)
    and all(type(number) is int and number>=0 for number in value['identity'].values()))
   specs.append((role,value['fd'],dict(value['identity']),value['flags'],value['fdFlags']))
  need(specs[0][1]!=specs[1][1])
  need((specs[0][2]['st_dev'],specs[0][2]['st_ino'])!=(specs[1][2]['st_dev'],specs[1][2]['st_ino']))
  need(all(type(module) is ModuleType for module in (os_module,select_module,fcntl_module)))
  o={name:vars(os_module).get(name) for name in ('read','fstat','close','O_ACCMODE','O_RDONLY','O_NONBLOCK','O_LARGEFILE')}
  s={name:vars(select_module).get(name) for name in ('poll','POLLIN','POLLHUP','POLLERR','POLLNVAL')}
  f={name:vars(fcntl_module).get(name) for name in ('fcntl','F_GETFL','F_GETFD','FD_CLOEXEC')}
  need(all(callable(o[name]) for name in ('read','fstat','close')) and callable(s['poll']) and callable(f['fcntl']))
  need(all(type(value) is int for name,value in o.items() if name.startswith('O_'))
   and all(type(value) is int for name,value in s.items() if name!='poll')
   and all(type(value) is int for name,value in f.items() if name!='fcntl'))
  raw_read,raw_stat,raw_close,raw_fcntl=o['read'],o['fstat'],o['close'],f['fcntl']
  for role,fd,identity,flags,fdflags in specs:
   need(ifmt(identity['st_mode'])==fifo and flags&o['O_ACCMODE']==o['O_RDONLY'] and flags&o['O_NONBLOCK']==o['O_NONBLOCK']
    and flags&~(o['O_NONBLOCK']|o['O_LARGEFILE'])==0 and fdflags==f['FD_CLOEXEC'])
  # Syntax/caps/uniqueness/collaborator admission completes before ownership.
  rows=[dict(role=role,fd=fd,identity=identity,flags=flags,fdFlags=fdflags,admitted=False,
   eof=False,attempted=False,closed=False,uncertain=False,chunks=[],bytes=0,views=[]) for role,fd,identity,flags,fdflags in specs]
  originals=tuple(rows)
  def tick(limit):
   nonlocal last
   value=clock();need(type(value) in (int,float) and math.isfinite(value) and last<=value<limit);last=value;return value
  def guard(row):
   view=metadata(raw_stat(row['fd']))
   if len(row['views'])<2:row['views'].append(view)
   else:row['views'][-1]=view
   expected=row['identity'];stable=('st_dev','st_ino','st_uid','st_gid','st_nlink')
   observed_flags=raw_fcntl(row['fd'],f['F_GETFL']);observed_fdflags=raw_fcntl(row['fd'],f['F_GETFD'])
   if not (all(view[k]==expected[k] for k in stable) and ifmt(view['st_mode'])==fifo
    and type(observed_flags) is int and type(observed_fdflags) is int
    and observed_flags==row['flags'] and observed_fdflags==row['fdFlags']):
    row['uncertain']=True;need(False)
   row['admitted']=True
  try:
   for row in originals:guard(row)
   poller=s['poll']();kind=type(poller);need(type(kind) is type)
   methods=dict(vars(kind));register=methods.get('register');poll=methods.get('poll');unregister=methods.get('unregister')
   need(all(callable(value) for value in (register,poll,unregister)))
   for row in originals:need(register(poller,row['fd'],s['POLLIN']|s['POLLHUP']|s['POLLERR']) is None)
   while not all(row['eof'] for row in originals):
    remaining=end-tick(end);polls+=1;need(polls<=max_polls)
    for row in originals:
     if not row['eof']:guard(row)
    try:events=poll(poller,min(40,max(1,int(remaining*1000))))
    except interrupted_kind as transient:
     need(type(transient) is interrupted_kind and type(transient.errno) is int and transient.errno==interrupted);continue
    need(type(events) is list and len(events)<=2)
    seen=set()
    for event in events:
     need(type(event) is tuple and len(event)==2 and type(event[0]) is int and type(event[1]) is int)
     fd,mask=event;need(fd not in seen);seen.add(fd)
     row=next((item for item in originals if item['fd']==fd and not item['eof']),None)
     need(row is not None and mask>0 and not mask&s['POLLNVAL']
      and mask&~(s['POLLIN']|s['POLLHUP']|s['POLLERR'])==0)
     guard(row);tick(end);reads+=1;need(reads<=max_reads)
     # Request one sentinel byte beyond remaining caps, never an unbounded read.
     count=min(chunk,caps[row['role']]-row['bytes']+1,total_cap-total+1);need(count>0)
     try:piece=raw_read(fd,count)
     except (blocked_kind,interrupted_kind) as transient:
      need(type(transient) in (blocked_kind,interrupted_kind) and type(transient.errno) is int
       and (type(transient) is blocked_kind and transient.errno in again
        or type(transient) is interrupted_kind and transient.errno==interrupted));continue
     need(type(piece) is bytes and len(piece)<=count)
     if piece==b'':row['eof']=True;need(unregister(poller,fd) is None)
     else:
      row['bytes']+=len(piece);total+=len(piece);need(row['bytes']<=caps[row['role']] and total<=total_cap)
      row['chunks'].append(piece)
   for row in originals:guard(row)
  except BaseException as caught:error=caught
  finally:
   # Captured raw operations/local helpers only; no live class/module cleanup.
   for row in reversed(originals):
    if row['attempted']:continue
    if not row['admitted'] or row['uncertain']:
     errors.append(('identity-unknown',row));continue
    try:guard(row)
    except BaseException as caught:row['uncertain']=True;errors.append(('identity-unknown',row,caught));continue
    row['attempted']=True
    try:
     need(raw_close(row['fd']) is None);row['closed']=True
    except BaseException as caught:errors.append(('close-unknown',row,caught))
   try:tick(deadline)
   except BaseException as caught:errors.append(('disposal-deadline',caught))
   known=not errors and all(row['closed'] for row in originals)
   if error is not None or not known:
    record=(handoff,originals,poller,raw_read,raw_stat,raw_fcntl,raw_close,os_module,select_module,fcntl_module,error,tuple(errors),known,tuple(s.items()))
    failed=True;private_records.append(record);unknown_ledger.append(record)
  if error is not None or not known:raise error_kind('company-binary-capture-unavailable') from None
  return proxy(dict(scope='BINARY_CAPTURE_DATA_ONLY',stdout=b''.join(originals[0]['chunks']),stderr=b''.join(originals[1]['chunks']),
   binding=proxy(frozen_binding),eofRoles=('stdout','stderr'),knownReaderCloses=True,readCalls=reads,pollCalls=polls,
   descriptorViews=tuple((row['role'],tuple(proxy(dict(view)) for view in row['views'])) for row in originals),
   executionEvidenceIssued=False,stageTerminalQualified=False,sourceResourcesQualified=False,stageAcknowledged=False))
 return capture_binary

capture_binary=_make_capture(UNRELEASED,CaptureUnavailable)
del _make_capture
