#!/usr/bin/env python3
"""Root-only XFS quota service. Uncertain allocations are preserved, never replayed."""
from http.server import BaseHTTPRequestHandler
import errno,importlib.util,json,os,re,shutil,signal,socket,socketserver,stat,threading,uuid
from pathlib import Path

# Resolve only the company-managed sibling, including under isolated Python and
# importlib callers. Do not add a directory to Python's import search path.
_spec=importlib.util.spec_from_file_location('autosoft_quota_runtime',Path(__file__).resolve().with_name('quota_runtime.py'))
_runtime=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_runtime)
authenticated,decode,mount_proof,output,protected_directory,create_storage,read_protected,require,validate_request=(getattr(_runtime,name) for name in ('authenticated','decode','mount_proof','output','protected_directory','provision','read_protected','require','validate_request'))

LOCK=threading.Lock()

def provision(value):
    """Retain the trusted foundation-check API with the same hardened boundary."""
    return create_storage(DATA,validate_request(value))

class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()
        def expire():
            try:self.request.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.read_deadline=threading.Timer(10,expire)
        self.read_deadline.daemon=True;self.read_deadline.start()

    def finish(self):
        self.read_deadline.cancel()
        super().finish()

    def log_message(self,*_):pass

    def do_POST(self):
        self.close_connection=True
        if self.path not in {'/v1/storage','/v1/telemetry'} or len(self.headers.get_all('Authorization',[]))!=1 or not authenticated(self.headers.get('Authorization',''),TOKEN):
            self.send_error(403);return
        try:
            lengths=self.headers.get_all('Content-Length',[])
            require(len(lengths)==1 and re.fullmatch('[0-9]{1,4}',lengths[0]) is not None and not self.headers.get_all('Transfer-Encoding',[]))
            count=int(lengths[0]);require(0<count<=4096)
            raw=self.rfile.read(count);require(len(raw)==count)
            value=decode(raw,4096)
            self.read_deadline.cancel()
            if self.path=='/v1/telemetry':
                require(type(value) is dict and not value)
                response={'host':host_telemetry()}
            else:
                value=validate_request(value)
                require(LOCK.acquire(timeout=5))
                try:response=create_storage(DATA,value)
                finally:LOCK.release()
            data=json.dumps(response,allow_nan=False).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        except Exception:
            self.send_error(503,'Storage quota could not be independently verified')

# BaseServer permits host-independent import/validation on Windows. main()
# rejects unsupported hosts before any service construction.
class Server(socketserver.ThreadingMixIn,getattr(socketserver,'UnixStreamServer',socketserver.BaseServer)):
    # A service stop must wait for admitted requests to record their actual
    # result. A daemon thread could otherwise disappear mid quota allocation.
    daemon_threads=False
    block_on_close=True
    request_queue_size=8
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(4)
        super().__init__(*args,**kwargs)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()
    def handle_error(self,*_):pass

def host_telemetry():
    mount_proof(DATA)
    memory={line.split(':',1)[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:'))}
    disk=shutil.disk_usage(DATA)
    return dict(name='vm',status='healthy',detail='Actual host CPU, RAM, disk and uptime; encrypted XFS data and project enforcement verified.',cpuCount=os.cpu_count(),loadAverage=list(os.getloadavg()),memoryTotalBytes=memory['MemTotal'],memoryAvailableBytes=memory['MemAvailable'],diskTotalBytes=disk.total,diskFreeBytes=disk.free,uptimeSeconds=float(Path('/proc/uptime').read_text().split()[0]),encryptedDataMounted=True)

def service_lock(directory):
    import fcntl
    path=directory/'quota.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return fd
    except BaseException:os.close(fd);raise

def stale_socket(path):
    if not os.path.lexists(path):return
    # systemd may restore a preserved RuntimeDirectory and its children to the
    # unit's root group before ExecStart. Both groups are company-owned states;
    # the held service lock, exact type/mode and refused connection still bind
    # removal to a stale listener. An active or foreign socket is never removed.
    info=path.lstat();require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and info.st_gid in (0,10001) and stat.S_IMODE(info.st_mode)==0o660)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        try:probe.connect(str(path))
        except OSError as error:require(error.errno==errno.ECONNREFUSED)
        else:raise ValueError('Existing quota service is active')
    require(path.lstat()==info);path.unlink()

def prepare_socket_directory(directory):
    protected_directory(directory.parent)
    if not os.path.lexists(directory):
        directory.mkdir(mode=0o700);os.chmod(directory,0o750)
    protected_directory(directory)
    info=directory.lstat()
    require(info.st_uid==0 and info.st_gid in (0,10001) and stat.S_IMODE(info.st_mode)==0o750)
    # systemd RuntimeDirectory with User=root creates root:root. Transition
    # only this protected exact directory; never re-own an arbitrary path.
    if info.st_gid==0:os.chown(directory,0,10001)
    info=directory.lstat()
    require(info.st_uid==0 and info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o750)

def verify_startup(data,installation_id):
    """Inspect initialized state without creating, adopting or reopening it."""
    require(type(installation_id) is str and str(uuid.UUID(installation_id))==installation_id)
    mount_proof(data)
    with _runtime.checkpoint_gate(data).inspect_initialized(installation_id,timeout=10):
        with _runtime.allocation_store(data).inspect_initialized(installation_id,read_state=_runtime.load_state,timeout=10):
            mount_proof(data)

def notify_service(address,message):
    """The stable systemd Unix datagram protocol; no subprocess or dependency."""
    require(message in ('READY=1','STOPPING=1'))
    if address is None:return
    require(type(address) is str and 1<len(address.encode('utf-8'))<=107 and address[0] in ('/','@') and not any(c in address for c in ('\0','\r','\n')))
    target='\0'+address[1:] if address.startswith('@') else address
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        require(client.sendto(message.encode('ascii'),target)==len(message))

def serve_ready(server,stopping,notify_address,notify=notify_service):
    server.timeout=0.25
    if stopping.is_set():return
    notify(notify_address,'READY=1')
    try:
        while not stopping.is_set():server.handle_request()
    finally:
        # Socket close waits for the non-daemon request threads in the caller's
        # Server context, retaining the service lock throughout their drain.
        notify(notify_address,'STOPPING=1')

def main():
    global DATA,TOKEN
    require(os.name=='posix' and os.geteuid()==0 and os.uname().machine=='x86_64')
    override=os.environ.get('QUOTA_TOKEN_FILE')
    notify_address=os.environ.get('NOTIFY_SOCKET')
    os.environ.clear();os.environ.update(PATH='/usr/bin:/usr/sbin:/bin:/sbin',LANG='C',LC_ALL='C');os.umask(0o077)
    metadata=decode(read_protected(Path('/etc/autosoft/installation.json'),32768),32768)
    DATA=Path(metadata['data_dir']);verify_startup(DATA,metadata['installation_id'])
    TOKEN=read_protected(Path(override) if override else DATA/'secrets/runtime/quota-token',1024).decode('ascii').strip()
    require(re.fullmatch('[A-Za-z0-9_-]{32,256}',TOKEN) is not None)
    directory=Path('/run/autosoft')
    prepare_socket_directory(directory)
    lock=service_lock(directory)
    previous={}
    try:
        path=directory/'quota.sock';stale_socket(path)
        with Server(str(path),Handler) as server:
            os.chmod(path,0o660);os.chown(path,0,10001)
            info=path.lstat();require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o660)
            stopping=threading.Event()
            previous={number:signal.signal(number,lambda *_:stopping.set()) for number in (signal.SIGTERM,signal.SIGINT)}
            serve_ready(server,stopping,notify_address)
    finally:
        for number,handler in previous.items():signal.signal(number,handler)
        os.close(lock)

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Quota helper unavailable; retained pending allocations require company review') from None
