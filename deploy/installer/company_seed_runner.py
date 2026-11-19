"""Explicit tracked read-only SeedStorage commands; no native defaults or ACK.

The entry authenticates this module, collaborators, six executable pins and the
OS/dynamic loader independently. Supplied modules are trusted code, not request
callbacks. The dedicated Linux/amd64 caller is the sole child reaper. A pidfd
does not remove an external wait consumer's check-to-signal race. Native tools,
storage placement, descriptors/memory reservation and whole installer lifetime
remain separately qualified. No shell, Git, mutation, secrets or child threads.
"""
import hashlib
import math
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType, ModuleType

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
TOOLS=('/usr/bin/systemctl','/usr/bin/docker','/usr/sbin/cryptsetup','/usr/sbin/losetup','/usr/bin/findmnt','/usr/sbin/xfs_quota')
UNITS=('autosoft.service','autosoft-quota.service','autosoft-security.service','autosoft-log-retention.service',
 'autosoft-certificates.service','autosoft-logs.service','autosoft-backup.service','autosoft-incremental.service',
 'autosoft-restore-verify.service','autosoft-security.timer','autosoft-certificates.timer','autosoft-log-retention.timer',
 'autosoft-logs.timer','autosoft-backup.timer','autosoft-incremental.timer','autosoft-restore-verify.timer')
PROPERTIES=('ActiveState','SubState','MainPID','ControlPID','ControlGroup','LoadState')
TIMER_PROPERTIES=('ActiveState','SubState','LoadState')
ENV=dict(PATH='/usr/bin:/bin',HOME='/nonexistent',LANG='C',LC_ALL='C',TZ='UTC',
 GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_SYSTEM='/dev/null',GIT_CONFIG_GLOBAL='/dev/null',
 GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0')
STATION_CONTRACT='trusted-company-seed-worker-exclusive-child-reaper-v1'
CHUNK=65536
MAX_TOOL=128*1024**2
CALL_SECONDS=60
DISPOSAL_SECONDS=5
UNRELEASED=[]

class SeedRunnerUnavailable(ValueError):pass

def require(value):
 if value is not True:raise SeedRunnerUnavailable('company_seed_runner_unavailable')

def instant(clock):
 value=clock();require(type(value) in (int,float) and math.isfinite(value) and value>=0);return value

def absolute(value):
 require(type(value) is str and value.isascii() and 0<len(value)<=1024 and value.startswith('/')
  and not value.startswith('//') and str(PurePosixPath(value))==value and len(PurePosixPath(value).parts)<=32)
 for name in PurePosixPath(value).parts[1:]:
  require(len(name)<=255 and re.fullmatch('[A-Za-z0-9_.-]+',name) is not None and name not in ('.','..'))
 return value

def metadata(value):
 answer={k:getattr(value,k,None) for k in FIELDS}
 require(all(type(x) is int and x>=0 for x in answer.values()));return answer

def catalog(value):
 require(type(value) is dict and set(value)==set(TOOLS));answer={}
 for path,row in value.items():
  require(type(row) is dict and set(row)=={'sha256','bytes','identity'} and type(row['sha256']) is str
   and re.fullmatch('[a-f0-9]{64}',row['sha256']) is not None and type(row['bytes']) is int and 64<=row['bytes']<=MAX_TOOL
   and type(row['identity']) is dict and set(row['identity'])==set(FIELDS)
   and all(type(x) is int and x>=0 for x in row['identity'].values()) and row['identity']['st_size']==row['bytes'])
  answer[path]=MappingProxyType(dict(sha256=row['sha256'],bytes=row['bytes'],identity=MappingProxyType(dict(row['identity']))))
 return MappingProxyType(answer)

def budgets(value):
 require(type(value) is dict and set(value)=={'calls','seconds','toolReadBytes','outputBytes'}
  and all(type(x) is int for x in value.values()) and 1<=value['calls']<=4096 and 6<=value['seconds']<=600
  and 1<=value['toolReadBytes']<=4*1024**3 and 1<=value['outputBytes']<=32*1024**2)
 return MappingProxyType(dict(value))

class _Primitives:
 """Capture exact trusted primitive calls before effects, including raw closes."""
 def __init__(self,os_module,sys_module,subprocess_module,select_module,signal_module,io_module,fcntl_module):
  modules=dict(os=os_module,sys=sys_module,subprocess=subprocess_module,select=select_module,signal=signal_module,io=io_module,fcntl=fcntl_module)
  require(all(type(m) is ModuleType for m in modules.values()))
  names=dict(os=('open','lstat','fstat','get_inheritable','pread','write','fchmod','close','memfd_create',
   'pidfd_open','waitid','getpgid','killpg','set_blocking','read','getpid','getuid','getgid','uname',
   'O_RDONLY','O_NOFOLLOW','O_CLOEXEC','O_DIRECTORY','O_NONBLOCK','MFD_CLOEXEC','MFD_ALLOW_SEALING',
   'P_PIDFD','P_PID','WEXITED','WNOHANG','WNOWAIT','CLD_EXITED','CLD_KILLED','CLD_DUMPED','name'),
   sys=('platform','byteorder'),subprocess=('Popen','PIPE','DEVNULL'),select=('poll','POLLIN','POLLHUP','POLLERR','POLLNVAL'),
   signal=('getsignal','pidfd_send_signal','SIGCHLD','SIG_DFL','SIGKILL','NSIG'),io=('FileIO',),
   fcntl=('fcntl','F_ADD_SEALS','F_GET_SEALS','F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'))
  self.modules=modules;self.bound={name:{k:vars(modules[name]).get(k) for k in keys} for name,keys in names.items()}
  self.os,self.subprocess,self.select,self.signal,self.io,self.fcntl=(self.bound[k] for k in ('os','subprocess','select','signal','io','fcntl'))
  require(self.os['name']=='posix' and self.bound['sys']['platform']=='linux' and self.bound['sys']['byteorder']=='little')
  for name in ('open','lstat','fstat','get_inheritable','pread','write','fchmod','close','memfd_create','pidfd_open',
               'waitid','getpgid','killpg','set_blocking','read','getpid','getuid','getgid','uname'):require(callable(self.os[name]))
  require(type(self.subprocess['Popen']) is type and type(self.io['FileIO']) is type
   and all(callable(x) for x in (self.select['poll'],self.signal['getsignal'],self.signal['pidfd_send_signal'],self.fcntl['fcntl'])))
  require(all(type(self.os[k]) is int for k in names['os'] if k.isupper())
   and all(type(self.select[k]) is int for k in names['select'] if k.isupper())
   and all(type(self.fcntl[k]) is int for k in names['fcntl'] if k.isupper()))
  self.process_type,self.file_type=self.subprocess['Popen'],self.io['FileIO']
  self.process_methods,self.file_methods=dict(vars(self.process_type)),dict(vars(self.file_type))
  self.file_close,self.file_fileno=self.file_methods.get('close'),self.file_methods.get('fileno')
  self.probes=[]
  require(callable(self.file_close) and callable(self.file_fileno))
  require(self.os['uname']().machine=='x86_64' and self.os['getuid']()==self.os['getgid']()==0)
 def check(self):
  require(all(vars(self.modules[name]).get(k) is v for name,rows in self.bound.items() for k,v in rows.items())
   and dict(vars(self.process_type))==self.process_methods and dict(vars(self.file_type))==self.file_methods)
 def station(self,protected_fds=()):
  # Trusted procfs/OS placement is external. This own-PID diagnostic reads no
  # credentials and emits none of its bytes; every returned FD is accounted.
  self.check();require(not self.probes and not UNRELEASED)
  pid=self.os['getpid']();require(type(pid) is int and pid>0)
  path='/proc/'+str(pid)+'/status';row=None;error=None
  fd=self.os['open'](path,self.os['O_RDONLY']|self.os['O_NOFOLLOW']|self.os['O_CLOEXEC']|self.os['O_NONBLOCK'])
  if type(fd) is not int or fd<0 or fd in protected_fds:
   UNRELEASED.append((self,'station-probe-open-unknown',fd));raise SeedRunnerUnavailable('company_seed_runner_unavailable')
  row=dict(fd=fd,attempted=False,closed=False);self.probes.append(row)
  try:
   before=metadata(self.os['fstat'](fd))
   require(stat.S_ISREG(before['st_mode']) and before['st_uid']==before['st_gid']==0 and self.os['get_inheritable'](fd) is False)
   raw=b''
   for attempt in range(5):
    part=self.os['pread'](fd,min(4096,16385-len(raw)),len(raw))
    require(type(part) is bytes and len(part)<=min(4096,16385-len(raw)));raw+=part
    require(len(raw)<=16384)
    if not part:break
   else:raise SeedRunnerUnavailable('company_seed_runner_unavailable')
   require(metadata(self.os['fstat'](fd))==before and metadata(self.os['lstat'](path))==before)
   threads=[line for line in raw.splitlines() if line.startswith(b'Threads:')]
   require(len(threads)==1 and re.fullmatch(rb'Threads:[ \t]+1',threads[0]) is not None
    and self.signal['getsignal'](self.signal['SIGCHLD'])==self.signal['SIG_DFL'])
  except BaseException as e:error=e
  finally:
   row['attempted']=True
   try:require(self.os['close'](fd) is None);row['closed']=True;self.probes.remove(row)
   except BaseException as e:
    UNRELEASED.append((self,'station-probe-close-unknown',row,e));error=e
  if error is not None:raise SeedRunnerUnavailable('company_seed_runner_unavailable') from error
  self.check()

class _Call:
 """Single-thread capture. Keep a sole-owned leader until final group kill."""
 def __init__(self,runner,argv,end,capture_end):
  self.runner,self.p,self.argv,self.end,self.capture_end=runner,runner._p,argv,end,capture_end
  self.raw=[];self.paths=[];self.streams=[];self.process=None;self.process_state=None
  self.pid=None;self.pidfd=None;self.pidfd_identity=None;self.poller=None;self.poll_calls=None
  self.possible_launch=False;self.reaped=False;self.group_absent=False;self.disposed=False;self.known=None;self.exit_code=None
  self.buffers={'stdout':bytearray(),'stderr':bytearray()};self.read_bytes=0;self.poll_count=0;self.cleanup_known=False;self.unknown=False
 def tick(self,end=None):require(instant(self.runner.clock)<(self.capture_end if end is None else end))
 def own(self,fd,role):
  if type(fd) is not int or fd<0 or len(self.raw)+len(self.streams)>=32 or any(r['fd']==fd for r in self.raw) or any(s.get('fd')==fd for s in self.streams):
   self.unknown=True
   UNRELEASED.append((self,'invalid-returned-fd',role,fd));raise SeedRunnerUnavailable('company_seed_runner_unavailable')
  row=dict(fd=fd,role=role,attempted=False,closed=False);self.raw.append(row)
  require(self.p.os['get_inheritable'](fd) is False);return fd
 def protected(self,row,directory):
  require(row['st_uid']==row['st_gid']==0 and not stat.S_IMODE(row['st_mode'])&0o022
   and stat.S_IFMT(row['st_mode'])==(stat.S_IFDIR if directory else stat.S_IFREG)
   and (directory or row['st_nlink']==1 and stat.S_IMODE(row['st_mode']) in (0o500,0o555,0o755)))
 def tool(self):
  path=self.argv[0];parts=PurePosixPath(path).parts;parent=None;current=''
  for index,name in enumerate(parts):
   self.tick();current='/' if index==0 else current.rstrip('/')+'/'+name
   directory=index<len(parts)-1;before=metadata(self.p.os['lstat'](current));self.protected(before,directory)
   flags=self.p.os['O_RDONLY']|self.p.os['O_NOFOLLOW']|self.p.os['O_CLOEXEC']|(self.p.os['O_DIRECTORY'] if directory else self.p.os['O_NONBLOCK'])
   fd=self.own(self.p.os['open'](name,flags,dir_fd=parent),'directory' if directory else 'tool')
   require(before==metadata(self.p.os['fstat'](fd))==metadata(self.p.os['lstat'](current)))
   self.paths.append((current,fd,before,directory));parent=fd
  approved=self.runner.tools[path];require(before==dict(approved['identity']))
  fd=self.own(self.p.os['memfd_create']('company-seed-tool',self.p.os['MFD_CLOEXEC']|self.p.os['MFD_ALLOW_SEALING']),'executable')
  self.executable=fd;digest=hashlib.sha256();offset=0;header=b''
  while offset<approved['bytes']:
   self.tick();amount=min(CHUNK,approved['bytes']-offset);raw=self.runner.read_tool(parent,amount,offset)
   require(type(raw) is bytes and 0<len(raw)<=amount)
   if offset==0:header=raw[:64]
   digest.update(raw);written=0
   while written<len(raw):
    self.tick();count=self.p.os['write'](fd,raw[written:]);require(type(count) is int and 0<count<=len(raw)-written);written+=count
   offset+=len(raw)
  require(self.runner.read_tool(parent,1,offset)==b'' and digest.hexdigest()==approved['sha256']
   and header[:7]==b'\x7fELF\x02\x01\x01' and header[18:20]==b'\x3e\x00')
  require(self.p.os['fchmod'](fd,0o500) is None)
  seals=sum(self.p.fcntl[k] for k in ('F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'))
  answer=self.p.fcntl['fcntl'](fd,self.p.fcntl['F_ADD_SEALS'],seals)
  require(type(answer) is int and answer==0 and self.p.fcntl['fcntl'](fd,self.p.fcntl['F_GET_SEALS'])==seals)
  require(metadata(self.p.os['fstat'](fd))['st_size']==approved['bytes']);self.seals=seals;self.guard(True)
 def guard(self,bytes_check=False):
  self.p.check()
  for path,fd,before,directory in self.paths:
   require(self.p.os['get_inheritable'](fd) is False and metadata(self.p.os['lstat'](path))==before==metadata(self.p.os['fstat'](fd)))
  if hasattr(self,'executable'):
   require(self.p.fcntl['fcntl'](self.executable,self.p.fcntl['F_GET_SEALS'])==self.seals)
  if bytes_check:
   approved=self.runner.tools[self.argv[0]]
   for fd in (self.paths[-1][1],self.executable):
    digest=hashlib.sha256();offset=0
    while offset<approved['bytes']:
     self.tick(self.end);amount=min(CHUNK,approved['bytes']-offset);raw=self.runner.read_tool(fd,amount,offset)
     require(type(raw) is bytes and 0<len(raw)<=amount);digest.update(raw);offset+=len(raw)
    require(self.runner.read_tool(fd,1,offset)==b'' and digest.hexdigest()==approved['sha256'])
   for path,fd,before,directory in self.paths:require(metadata(self.p.os['lstat'](path))==before==metadata(self.p.os['fstat'](fd)))
 def start(self):
  self.tick();self.guard(True);self.p.station(tuple(r['fd'] for r in self.raw));self.possible_launch=True
  process=self.p.subprocess['Popen'](list(self.argv),executable='/proc/self/fd/'+str(self.executable),
   stdin=self.p.subprocess['DEVNULL'],stdout=self.p.subprocess['PIPE'],stderr=self.p.subprocess['PIPE'],
   env=dict(ENV),cwd='/',close_fds=True,pass_fds=(self.executable,),start_new_session=True,bufsize=0,shell=False)
  self.process=process
  require(type(process) is self.p.process_type and type(vars(process)) is dict);self.process_state=vars(process)
  self.pid=dict.get(self.process_state,'pid');require(type(self.pid) is int and self.pid>0 and dict.get(self.process_state,'returncode') is None)
  for label in ('stdout','stderr'):
   stream=dict.get(self.process_state,label);row=dict(object=stream,label=label,fd=None,eof=False,attempted=False,closed=False);self.streams.append(row)
  if len({id(r['object']) for r in self.streams})!=len(self.streams):
   self.unknown=True
   for row in self.streams:row['alias_unknown']=True
   raise SeedRunnerUnavailable('company_seed_runner_unavailable')
  self.poller=self.p.select['poll']();self.poll_calls={k:getattr(self.poller,k,None) for k in ('register','unregister','poll')}
  require(all(callable(x) for x in self.poll_calls.values()))
  for row in self.streams:
   stream=row['object']
   require(type(stream) is self.p.file_type);fd=self.p.file_fileno(stream);row['fd']=fd
   if type(fd) is not int or fd<0 or any(r['fd']==fd for r in self.raw) or sum(r.get('fd')==fd for r in self.streams)!=1:
    self.unknown=True
    for candidate in self.streams:
     if candidate.get('fd')==fd:candidate['alias_unknown']=True
    raise SeedRunnerUnavailable('company_seed_runner_unavailable')
   require(self.p.os['get_inheritable'](fd) is False)
   row['identity']=metadata(self.p.os['fstat'](fd));require(stat.S_ISFIFO(row['identity']['st_mode']))
   require(self.p.os['set_blocking'](fd,False) is None)
   require(self.poll_calls['register'](fd,self.p.select['POLLIN']|self.p.select['POLLHUP']|self.p.select['POLLERR']) is None)
  self.pidfd=self.own(self.p.os['pidfd_open'](self.pid,0),'pidfd');self.pidfd_identity=metadata(self.p.os['fstat'](self.pidfd))
 def status(self,info):
  require(type(info.si_pid) is int and info.si_pid==self.pid and type(info.si_code) is int and type(info.si_status) is int)
  if info.si_code==self.p.os['CLD_EXITED']:require(0<=info.si_status<=255);return info.si_status
  require(info.si_code in (self.p.os['CLD_KILLED'],self.p.os['CLD_DUMPED']) and 0<info.si_status<self.p.signal['NSIG']);return -info.si_status
 def ownership(self):
  self.p.station(tuple(r['fd'] for r in self.raw)+tuple(r['fd'] for r in self.streams));require(not self.reaped and type(self.pid) is int and self.pid>0 and self.process_state is not None
   and dict.get(self.process_state,'returncode') is None)
  if self.pidfd is None:kind,identifier=self.p.os['P_PID'],self.pid # Cleanup only if pidfd creation failed.
  else:
   require(metadata(self.p.os['fstat'](self.pidfd))==self.pidfd_identity and self.p.os['get_inheritable'](self.pidfd) is False)
   kind,identifier=self.p.os['P_PIDFD'],self.pidfd
  info=self.p.os['waitid'](kind,identifier,self.p.os['WEXITED']|self.p.os['WNOHANG']|self.p.os['WNOWAIT'])
  if info is not None:
   self.status(info)
   if self.known is not None:require((info.si_pid,info.si_code,info.si_status)==self.known)
  else:require(self.known is None)
  return info
 def drain(self,end,discard=False):
  self.tick(end);require(self.poll_count<2400);self.poll_count+=1
  events=self.poll_calls['poll'](min(50,max(1,int((end-instant(self.runner.clock))*1000))))
  require(type(events) is list and len(events)<=2 and all(type(e) is tuple and len(e)==2 and all(type(x) is int for x in e) for e in events)
   and len({e[0] for e in events})==len(events))
  for fd,flags in events:
   rows=[r for r in self.streams if r['fd']==fd and not r['eof']];require(len(rows)==1 and flags>=0
    and not flags&self.p.select['POLLNVAL'] and flags&~(self.p.select['POLLIN']|self.p.select['POLLHUP']|self.p.select['POLLERR'])==0)
   row=rows[0];limit=CHUNK
   amount=CHUNK if discard else min(CHUNK,limit+1-len(self.buffers[row['label']]))
   require(amount>0 and self.read_bytes<4*CHUNK)
   try:raw=self.p.os['read'](fd,amount)
   except BlockingIOError:continue
   require(type(raw) is bytes and len(raw)<=amount);self.read_bytes+=len(raw);require(self.read_bytes<=4*CHUNK)
   if raw==b'':
    require(self.poll_calls['unregister'](fd) is None);row['eof']=True
   elif not discard:
    self.buffers[row['label']].extend(raw);require(len(self.buffers[row['label']])<=limit)
 def capture(self):
  while self.known is None or not all(r['eof'] for r in self.streams):
   self.tick();info=self.ownership()
   if info is not None:self.known=(info.si_pid,info.si_code,info.si_status)
   self.drain(self.capture_end)
  self.exit_code=self.status(info)
 def dispose(self):
  require(not self.disposed);self.disposed=True;errors=[]
  if self.process is not None and type(self.pid) is int:
   owned=False
   try:
    self.ownership();require(self.p.os['getpgid'](self.pid)==self.pid);owned=True
   except BaseException as e:errors.append(('child-ownership',e))
   if owned:
    try:require(self.p.os['killpg'](self.pid,self.p.signal['SIGKILL']) is None)
    except ProcessLookupError:pass
    except BaseException as e:
     errors.append(('group-kill',e))
     if self.pidfd is not None:
      try:require(self.p.signal['pidfd_send_signal'](self.pidfd,self.p.signal['SIGKILL']) is None)
      except ProcessLookupError:pass
      except BaseException as e:errors.append(('pidfd-kill',e))
    try:
     for attempt in range(2400):
      self.tick(self.end);kind,identifier=(self.p.os['P_PIDFD'],self.pidfd) if self.pidfd is not None else (self.p.os['P_PID'],self.pid)
      info=self.p.os['waitid'](kind,identifier,self.p.os['WEXITED']|self.p.os['WNOHANG'])
      if info is not None:
       code=self.status(info);self.reaped=True;dict.__setitem__(self.process_state,'returncode',code)
       require(self.exit_code is None or self.exit_code==code);break
      if self.poll_calls is not None:self.drain(self.end,True)
     else:raise SeedRunnerUnavailable('company_seed_runner_unavailable')
    except BaseException as e:errors.append(('child-reap',e))
   if self.reaped:
    try:
     for attempt in range(2400):
      self.tick(self.end)
      try:require(self.p.os['killpg'](self.pid,0) is None)
      except ProcessLookupError:self.group_absent=True;break
      if self.poll_calls is not None:self.drain(self.end,True)
     else:raise SeedRunnerUnavailable('company_seed_runner_unavailable')
     while self.streams and not all(r['eof'] for r in self.streams):self.drain(self.end,True)
    except BaseException as e:errors.append(('post-reap-observation',e))
  elif self.possible_launch:errors.append(('ambiguous-process-construction',self.process))
  for row in reversed(self.streams):
   if row['attempted']:continue
   row['attempted']=True
   try:
    require(not row.get('alias_unknown',False))
    require(type(row['object']) is self.p.file_type and dict(vars(self.p.file_type))==self.p.file_methods)
    require(self.p.file_close(row['object']) is None and row['object'].closed is True);row['closed']=True
   except BaseException as e:errors.append(('pipe-close',row,e))
  for row in reversed(self.raw):
   if row['attempted']:continue
   if row['role']=='pidfd' and not self.reaped:errors.append(('unreaped-pidfd',row));continue
   row['attempted']=True
   try:require(self.p.os['close'](row['fd']) is None);row['closed']=True
   except BaseException as e:errors.append(('raw-close',row,e))
  no_child=not self.possible_launch or self.reaped and self.group_absent
  self.cleanup_known=not self.unknown and not errors and no_child and all(r['closed'] for r in self.raw) and all(r['closed'] and r['eof'] for r in self.streams)
  if not self.cleanup_known:
   UNRELEASED.append((self,'command-owned-release-unknown',self.process,self.pid,self.pidfd,tuple(self.raw),tuple(self.streams),tuple(errors)))
   raise SeedRunnerUnavailable('company_seed_runner_unavailable')

class SeedRunner:
 """Original SeedCommands protocol, explicit Linux collaborators and tool pins.

 require_released is an observation, including before first use; it never resets
 a failure or cancels an escaped descendant. Each run owns and closes its tools
 and pipes. Deadline includes disposal but cannot interrupt a blocking syscall.
 """
 def __init__(self,*,tool_catalog,data_directory,storage_file,budget,os_module,sys_module,subprocess_module,
              select_module,signal_module,io_module,fcntl_module,clock,station_contract):
  require(not UNRELEASED and station_contract==STATION_CONTRACT and type(station_contract) is str and callable(clock))
  self.data,self.storage=absolute(data_directory),absolute(storage_file)
  require(self.data.startswith('/srv/') and self.data!=self.storage and not self.storage.startswith(self.data+'/') and not self.data.startswith(self.storage+'/'))
  self.tools,self.budget,self.clock=catalog(tool_catalog),budgets(budget),clock
  self._p=_Primitives(os_module,sys_module,subprocess_module,select_module,signal_module,io_module,fcntl_module)
  self.deadline=instant(clock)+self.budget['seconds'];self.calls=0;self.tool_read=0;self.output_bytes=0
  self.jobs=[];self.failed=False;self._observations=[]
 def request(self,argv,stdin,maximum,timeout,tool,environment):
  require(type(argv) is list and 0<len(argv)<=10 and all(type(x) is str and x.isascii() and 0<len(x)<=1024 and '\0' not in x for x in argv)
   and stdin is None and type(maximum) is int and maximum==CHUNK and type(timeout) is int and timeout==CALL_SECONDS
   and tool is None and type(environment) is dict and environment==ENV and all(type(k) is str and type(v) is str for k,v in environment.items()))
  args=tuple(argv);systemctl=('/usr/bin/systemctl','show',*('--property='+v for v in PROPERTIES),'--')
  timer=('/usr/bin/systemctl','show',*('--property='+v for v in TIMER_PROPERTIES),'--')
  fixed=(('/usr/bin/docker','ps','-aq','--no-trunc'),('/usr/sbin/cryptsetup','luksUUID',self.storage),
   ('/usr/sbin/cryptsetup','status','autosoft-data'),('/usr/bin/findmnt','-n','-o','TARGET,SOURCE,FSTYPE,OPTIONS','--target',self.data),
   ('/usr/bin/findmnt','-n','-o','TARGET,FSTYPE,OPTIONS,SIZE','--bytes','--target',self.data+'/runtime/builds'),
   ('/usr/bin/findmnt','-n','-o','SOURCE,FSTYPE,OPTIONS','--target',self.data),('/usr/sbin/xfs_quota','-x','-c','state -p',self.data))
  loop=(len(args)==6 and args[:5]==('/usr/sbin/losetup','--noheadings','--output','BACK-FILE','--')
        and re.fullmatch('/dev/loop[0-9]{1,10}',args[5]) is not None)
  service_query=args[:len(systemctl)]==systemctl and len(args)==len(systemctl)+1 and args[-1] in UNITS and args[-1].endswith('.service')
  timer_query=args[:len(timer)]==timer and len(args)==len(timer)+1 and args[-1] in UNITS and args[-1].endswith('.timer')
  require(args in fixed or service_query or timer_query or loop)
  return args
 def read_tool(self,fd,size,offset):
  require(type(size) is int and 0<size<=CHUNK and type(offset) is int and offset>=0 and self.tool_read+size<=self.budget['toolReadBytes'])
  raw=self._p.os['pread'](fd,size,offset);require(type(raw) is bytes and len(raw)<=size);self.tool_read+=len(raw);return raw
 @property
 def observations(self):return tuple(self._observations)
 def run(self,argv,*,stdin,maximum,timeout,tool,environment):
  job=None;error=None
  try:
   require(not self.failed and not UNRELEASED and not self.jobs)
   args=self.request(argv,stdin,maximum,timeout,tool,environment)
   self._p.station();start=instant(self.clock);end=min(start+CALL_SECONDS,self.deadline)
   require(start<end-DISPOSAL_SECONDS and self.calls<self.budget['calls']);self.calls+=1
   job=_Call(self,args,end,end-DISPOSAL_SECONDS);self.jobs.append(job)
   job.tool();job.start();job.capture();job.guard(True)
   self.output_bytes+=sum(len(b) for b in job.buffers.values());require(self.output_bytes<=self.budget['outputBytes'])
  except BaseException as e:error=e;self.failed=True
  finally:
   if job is not None:
    try:job.dispose()
    except BaseException as e:error=e;self.failed=True
    try:require(instant(self.clock)<job.end)
    except BaseException as e:error=e;self.failed=True
    self._observations.append(MappingProxyType(dict(argv=job.argv,stdout=bytes(job.buffers['stdout'][:CHUNK]),stderr=bytes(job.buffers['stderr'][:CHUNK]),
     exitCode=job.exit_code,ownedReleased=job.cleanup_known,captureComplete=error is None,sourceOnlyNativeQualificationAbsent=True)))
    if job.cleanup_known:self.jobs.remove(job)
  if error is not None:raise SeedRunnerUnavailable('company_seed_runner_unavailable') from error
  require(job is not None and job.cleanup_known)
  stdout,stderr=bytes(job.buffers['stdout']),bytes(job.buffers['stderr'])
  return dict(exitCode=job.exit_code,stdout=stdout,stderr=stderr,ownedReleased=True)
 def require_released(self):
  require(not self.jobs and not self._p.probes and not UNRELEASED);return self
