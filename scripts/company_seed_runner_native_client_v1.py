"""Emit-only disabled carrier; explicit dispatch is a separate Root action.

Windows station, initial Linux interpreter/libc and fixed session are trusted
prerequisites. Readback pins are not held-through-launch executable authority.
Local owned Plink closure never establishes remote cancellation.
"""
import ast,gzip,hashlib,json,os,re,stat,subprocess,sys,threading,time,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROPOSAL=ROOT/'.local/company-seed-runner-native-proposal-v1'
PLINK=r'C:\Program Files\PuTTY\plink.exe'
PLINK_PIN=('460e62e304361fb6f73ef215530b93d6f97c263b1442ee48134cdcdf94d3f1de',1037936)
SESSION=''  # Configure only for an explicitly approved company diagnostic.
HOSTKEY=''  # Configure only for an explicitly approved company diagnostic.
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_COMPRESSED=131072;MAX_EXPANDED=262144;MAX_COMMAND=131072;MAX_OUTPUT=16384;TOTAL_SECONDS=100
UNRELEASED=[]
INPUT_PINS = {'deploy/installer/company_seed_runner.py': {'sha256': '42af406862e9e2f6a81f436851453f525f1f35bf044fc0dc24708ee61fa21e17', 'bytes': 25874}, 'scripts/company_source_guard_backend.py': {'sha256': '08819a69449f28c4b568d58930ead4bade0475726138fa039945f2365322126d', 'bytes': 10600}}
WORKER_PIN = ('273cdd916f6bcc1e1bdf608bde763c824711a190540aec7ea1e71e404c08d078', 13630)
class Denied(ValueError):pass
def need(value):
 if value is not True:raise Denied('seed-runner-transport-unavailable')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')+b'\n'
def decode(raw,limit):
 need(type(raw) is bytes and 0<len(raw)<=limit)
 def pairs(items):
  value={}
  for key,item in items:need(key not in value);value[key]=item
  return value
 try:value=json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=lambda _:need(False))
 except (ValueError,UnicodeError,RecursionError):raise Denied() from None
 need(canonical(value)==raw);return value
def pin(raw,expected):need(type(raw) is bytes and (sha(raw),len(raw))==expected)
def row(raw):return dict(sha256=sha(raw),bytes=len(raw))
def validate_members(members):
 need(type(members) is dict and set(members)==set(INPUT_PINS) and len(members)==2)
 for path,expected in INPUT_PINS.items():pin(members[path],(expected['sha256'],expected['bytes']))
def packet(scope,worker,catalog,members):
 """Pure framing; catalog is separately bound by the Root scope digest."""
 validate_members(members);pin(worker,WORKER_PIN);value=decode(scope,8192);decode(catalog,16384)
 need(sha(catalog)==value['toolCatalogSha256'])
 header=canonical(dict(schemaVersion=1,scope=row(scope),worker=row(worker),catalog=row(catalog),members=INPUT_PINS))
 need(len(header)<=16384)
 raw=len(header).to_bytes(4,'big')+header+scope+worker+catalog+b''.join(members[p] for p in sorted(INPUT_PINS))
 need(len(raw)<=MAX_EXPANDED);packed=gzip.compress(raw,compresslevel=9,mtime=0);need(len(packed)<=MAX_COMPRESSED);return packed
def unpack(packed,*,packed_pin,scope_pin,worker_pin):
 pin(packed,packed_pin);need(len(packed)<=MAX_COMPRESSED and worker_pin==WORKER_PIN)
 try:
  inflater=zlib.decompressobj(31);raw=inflater.decompress(packed,MAX_EXPANDED+1)
  need(len(raw)<=MAX_EXPANDED and inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail)
  need(len(raw)>4);length=int.from_bytes(raw[:4],'big');need(0<length<=16384 and 4+length<=len(raw))
  header=decode(raw[4:4+length],16384)
  need(type(header) is dict and set(header)=={'schemaVersion','scope','worker','catalog','members'} and type(header['schemaVersion']) is int and header['schemaVersion']==1)
  need(type(header['members']) is dict and set(header['members'])==set(INPUT_PINS))
  for path,value in header['members'].items():
   need(type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int and type(value['sha256']) is str and value==INPUT_PINS[path])
  for label,expected in (('scope',scope_pin),('worker',worker_pin)):
   value=header[label];need(type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int and type(value['sha256']) is str and value==dict(sha256=expected[0],bytes=expected[1]))
  c=header['catalog'];need(type(c) is dict and set(c)=={'bytes','sha256'} and type(c['bytes']) is int and 0<c['bytes']<=16384 and type(c['sha256']) is str and re.fullmatch('[a-f0-9]{64}',c['sha256']) is not None)
  offset=4+length;scope=raw[offset:offset+scope_pin[1]];offset+=scope_pin[1]
  worker=raw[offset:offset+worker_pin[1]];offset+=worker_pin[1];catalog=raw[offset:offset+c['bytes']];offset+=c['bytes']
  pin(scope,scope_pin);value=decode(scope,8192);pin(worker,worker_pin);pin(catalog,(c['sha256'],c['bytes']));decode(catalog,16384);need(sha(catalog)==value['toolCatalogSha256'])
  members={}
  for path,expected in sorted(INPUT_PINS.items()):members[path]=raw[offset:offset+expected['bytes']];offset+=expected['bytes']
  need(offset==len(raw));validate_members(members);return scope,worker,catalog,members
 except (ValueError,OverflowError,UnicodeError,RecursionError,zlib.error):raise Denied() from None
def bootstrap(packed_pin,scope_pin):
 """Trusted code template; packet/two-pin validation precedes worker compile."""
 names={'Denied','need','sha','canonical','decode','pin','unpack','validate_members'}
 tree=ast.parse(Path(__file__).read_bytes());parts=[]
 for node in tree.body:
  if isinstance(node,(ast.ClassDef,ast.FunctionDef)) and node.name in names:parts.append(ast.get_source_segment(Path(__file__).read_text(),node))
 need(len(parts)==len(names))
 prefix='import hashlib,json,zlib,sys,time,resource,signal,re\nfrom types import ModuleType\n'
 constants='MAX_COMPRESSED=131072\nMAX_EXPANDED=262144\nINPUT_PINS='+repr(INPUT_PINS)+'\nWORKER_PIN='+repr(WORKER_PIN)+'\n'
 safety='''
STARTED=time.monotonic()
for which,bounds in ((resource.RLIMIT_AS,(268435456,268435456)),(resource.RLIMIT_CPU,(60,61)),(resource.RLIMIT_NOFILE,(96,96)),(resource.RLIMIT_FSIZE,(0,16777216)),(resource.RLIMIT_CORE,(0,0))):resource.setrlimit(which,bounds)
def expired(*_):raise ValueError('seed-runner-remote-deadline')
signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,70)
'''
 entry='''
def main():
 packed=sys.stdin.buffer.read(PACKED_PIN[1]+1)
 scope,worker,catalog,members=unpack(packed,packed_pin=PACKED_PIN,scope_pin=SCOPE_PIN,worker_pin=WORKER_PIN)
 module=ModuleType('company_seed_runner_native_worker');sys.modules[module.__name__]=module
 exec(compile(worker,'<root-pinned emitter worker>','exec'),module.__dict__)
 module.sources_admission(members);v=module.scope(scope,time.time());module.catalog(catalog,v['toolCatalogSha256'])
 # These native origins are externally supplied by the trusted company station.
 import os,subprocess,select,io,fcntl
 station=module.NativeStation(os_module=os,sys_module=sys,subprocess_module=subprocess,select_module=select,signal_module=signal,io_module=io,fcntl_module=fcntl,resource_module=resource,clock=time.monotonic,wall=time.time,started=STARTED)
 result=module.run(scope,catalog,members,station=station)
 raw=canonical(result);need(len(raw)<=16384);sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
 return 0 if result['status']=='NATIVE_READONLY_SEED_RUNNER_OBSERVED_ONLY' else 1
try:CODE=main()
except BaseException:
 sys.stdout.buffer.write(b'{"schemaVersion":1,"status":"NATIVE_READONLY_SEED_RUNNER_LOADER_UNAVAILABLE"}\\n');sys.stdout.buffer.flush();CODE=1
raise SystemExit(CODE)
'''
 text=prefix+constants+'\n\n'.join(parts)+'\n'+safety+'PACKED_PIN='+repr(packed_pin)+'\nSCOPE_PIN='+repr(scope_pin)+'\n'+entry
 import shlex
 command='/usr/bin/sudo -n /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC /usr/bin/python3 -I -B -c '+shlex.quote(text)+'\n'
 need(len(command.encode('utf-8'))<=MAX_COMMAND);return command.encode()
def build(scope,worker,catalog,members):
 packed=packet(scope,worker,catalog,members);command=bootstrap((sha(packed),len(packed)),(sha(scope),len(scope)))
 return dict(packet=packed,command=command,scope=scope,measurement=dict(compressedBytes=len(packed),expandedCap=MAX_EXPANDED,commandBytes=len(command),sourceMemberCount=2,sourceMemberBytes=sum(map(len,members.values())),catalogBytes=len(catalog)))
def metadata(info):return {field:str(getattr(info,field)) for field in FIELDS}
def read(path,expected=None,*,limit=MAX_EXPANDED):
 path=Path(path);before=path.stat(follow_symlinks=False)
 need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit)
 with path.open('rb') as source:
  fbefore=os.fstat(source.fileno());raw=source.read(limit+1);fafter=os.fstat(source.fileno())
 after=path.stat(follow_symlinks=False)
 need(metadata(before)==metadata(after) and metadata(fbefore)==metadata(fafter) and len(raw)==before.st_size)
 executable=str(path)==PLINK and expected==PLINK_PIN and os.name=='nt'
 need(all(getattr(before,k)==getattr(fbefore,k) for k in FIELDS if k not in (('st_ctime_ns','st_mode') if executable else ('st_ctime_ns',))))
 if executable:need(before.st_mode==fbefore.st_mode|0o111)
 if expected is not None:pin(raw,expected)
 return raw,dict(path=str(path),**row(raw),pathMetadata=metadata(before),fdMetadata=metadata(fbefore),windowsCtimeCrossViewQualified=before.st_ctime_ns!=fbefore.st_ctime_ns)
def supervise(argv,payload,*,factory=subprocess.Popen,clock=time.monotonic,thread_factory=threading.Thread):
 """One 100s local lifetime; three owned pipes, binary input, no remote claim."""
 need(not UNRELEASED and type(payload) is bytes and 0<len(payload)<=MAX_COMPRESSED)
 started=clock();deadline=started+TOTAL_SECONDS;work_end=deadline-10
 process=None;threads=[];started_threads=[];buffers={};counts={};errors=[];eof=set();sent=False;reaped=False;joined=False;pipes_closed=False;code=None;reason=None;stop=threading.Event()
 try:
  need(clock()<work_end)
  process=factory(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,close_fds=True,
   creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),env={k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP') if k in os.environ})
  need(process is not None and all(getattr(process,k,None) is not None for k in ('stdin','stdout','stderr')))
  def feed():
   nonlocal sent
   try:
    offset=0
    while offset<len(payload):
     amount=process.stdin.write(payload[offset:offset+65536]);need(type(amount) is int and 0<amount<=min(65536,len(payload)-offset));offset+=amount
    process.stdin.flush();process.stdin.close();sent=True
   except BaseException:errors.append('stdin_write_unknown');stop.set()
  def drain(label,stream):
   chunks=[];total=0;kept=0
   try:
    while True:
     piece=stream.read(4096)
     if not piece:eof.add(label);break
     need(type(piece) is bytes);total+=len(piece);take=piece[:max(0,MAX_OUTPUT-kept)];chunks.append(take);kept+=len(take)
     if total>MAX_OUTPUT:errors.append(label+'_overflow');stop.set();break
   except BaseException:errors.append(label+'_capture_unknown');stop.set()
   finally:buffers[label]=b''.join(chunks);counts[label]=total
  for target,args in ((drain,('stdout',process.stdout)),(drain,('stderr',process.stderr)),(feed,())):
   thread=thread_factory(target=target,args=args,daemon=True);threads.append(thread);thread.start();started_threads.append(thread)
  while True:
   if stop.is_set():reason='capture_unknown';break
   left=work_end-clock()
   if left<=0:reason='local_deadline_remote_unknown';break
   try:code=process.wait(timeout=min(.25,left));need(type(code) is int);reaped=True;break
   except subprocess.TimeoutExpired:pass
 except BaseException:reason='transport_exception_remote_unknown'
 finally:
  if process is not None:
   if not reaped:
    try:
     need(clock()<deadline-5);process.kill();remaining=deadline-5-clock();need(remaining>0)
     code=process.wait(timeout=remaining);need(type(code) is int);reaped=True
    except BaseException:reason='local_reap_unknown'
   join_end=min(deadline,clock()+5)
   for thread in threads:
    if thread.ident is not None:
     try:thread.join(timeout=max(0,join_end-clock()))
     except BaseException:errors.append('thread_join_unknown')
   try:joined=all(not thread.is_alive() for thread in threads)
   except BaseException:joined=False
   if joined:
    pipes_closed=True
    for name in ('stdin','stdout','stderr'):
     stream=getattr(process,name,None)
     if stream is not None:
      try:
       if not stream.closed:stream.close()
      except BaseException:errors.append('pipe_close_unknown');pipes_closed=False
   else:reason='owned_thread_unknown'
  known=reaped and joined and pipes_closed and sent and not errors and eof=={'stdout','stderr'} and clock()<deadline
  if not known:UNRELEASED.append(dict(process=process,threads=threads,buffers=buffers,errors=errors))
 return dict(stdout=buffers.get('stdout',b''),stderr=buffers.get('stderr',b''),exitCode=code,
  localProcessReaped=reaped,threadsJoined=joined,pipesClosed=pipes_closed,binaryInputSent=sent,localLifetimeKnown=known,
  observedOutputBytes=counts,captureEof=sorted(eof),reason=reason,errors=errors,elapsedMilliseconds=max(0,int((clock()-started)*1000)),
  remoteCancellationProven=False,automaticRetry=False)
def write_new(path,raw):
 with Path(path).open('xb') as file:
  need(file.write(raw)==len(raw));file.flush();os.fsync(file.fileno())
 pin(read(path,limit=MAX_EXPANDED)[0],(sha(raw),len(raw)))
def fixed_argv(folder):
 folder=Path(folder)
 need(folder.parent==ROOT/'.local' and re.fullmatch('company-seed-runner-native-dispatch-v1-[a-f0-9]{32}',folder.name) is not None)
 result=[PLINK,'-batch','-T','-load',SESSION,'-hostkey',HOSTKEY,'-m',str(folder/'command.sh')]
 need(len(subprocess.list2cmdline(result).encode('utf-16-le'))//2+1<4096);return result
def dispatch_once(folder,*,expected_command,expected_packet,expected_scope,explicit_action):
 need(bool(SESSION) and bool(HOSTKEY))
 """No default CLI. Root creates the fresh exact packet and supplies its pins."""
 need(explicit_action=='ROOT_DISPATCH_ONCE' and not UNRELEASED)
 folder=Path(folder);name=folder.name;match=re.fullmatch('company-seed-runner-native-dispatch-v1-([a-f0-9]{32})',name)
 need(match is not None and folder.parent==ROOT/'.local' and folder.is_dir() and not folder.is_symlink())
 need(sorted(p.name for p in folder.iterdir())==['command.sh','packet.bin','scope.json'])
 command,_=read(folder/'command.sh',expected_command,limit=MAX_COMMAND);payload,_=read(folder/'packet.bin',expected_packet,limit=MAX_COMPRESSED);scope,_=read(folder/'scope.json',expected_scope,limit=8192)
 scope_v,worker,catalog,members=unpack(payload,packed_pin=expected_packet,scope_pin=expected_scope,worker_pin=WORKER_PIN)
 need(scope_v==scope)
 value=decode(scope,8192);now=time.time()
 need(type(value) is dict and value.get('nativeOneAttempt') is True and value.get('status')=='ROOT_AUTHORIZED_ONE_READONLY_SEED_RUNNER_PROBE'
  and value.get('operationId')==match[1] and type(value.get('notBefore')) is int and type(value.get('expiresAt')) is int
  and value['notBefore']<=now and 100<value['expiresAt']-now<=1800)
 need(bootstrap(expected_packet,expected_scope)==command)
 _,tool_pin=read(PLINK,PLINK_PIN,limit=2*1024**2)
 argv=fixed_argv(folder)
 now=time.time();need(value['notBefore']<=now and value['expiresAt']-now>100)
 intent=canonical(dict(schemaVersion=1,scope='ONE_READONLY_SEED_RUNNER_DISPATCH_ONLY',operationId=match[1],command=row(command),packet=row(payload),grant=row(scope),plink=tool_pin,automaticRetry=False))
 write_new(folder/'dispatch-intent.json',intent)
 # Intent is consumed even if the constructor/remote acknowledgement is lost.
 def fresh_launch(*args,**kwargs):
  launch=time.time();need(value['notBefore']<=launch and value['expiresAt']-launch>100)
  return subprocess.Popen(*args,**kwargs)
 result=supervise(argv,payload,factory=fresh_launch)
 write_new(folder/'stdout.raw',result.pop('stdout'));write_new(folder/'stderr.raw',result.pop('stderr'))
 result['sourceContinuityConfirmed']=read(folder/'command.sh',expected_command,limit=MAX_COMMAND)[0]==command and read(folder/'packet.bin',expected_packet,limit=MAX_COMPRESSED)[0]==payload and read(folder/'scope.json',expected_scope,limit=8192)[0]==scope
 write_new(folder/'transport-result.json',canonical(result));return result
