"""Fixed private TLS/read-only probes. Credentials never appear in argv/logs."""
import base64
import http.client
import ipaddress
import json
import socket
import ssl
import time

def require(value,reason='Private service readiness is unconfirmed'):
    if not value:raise ValueError(reason)

class LimitedReader:
    """Bounded socket reader; no buffered file read can hide repeated recv calls."""
    def __init__(self,sock,deadline,clock):
        self.socket=sock;self.deadline=deadline;self.clock=clock;self.remaining=73728
        self.buffer=bytearray();self.eof=False;self.closed=False
    def _before(self):
        require(not self.closed)
        left=self.deadline-self.clock()
        if left<=0:raise TimeoutError('Private service response deadline exceeded')
        self.socket.settimeout(min(3,left))
    def _receive(self):
        self._before()
        raw=self.socket.recv(min(8192,self.remaining+1))
        self._before()  # A final byte arriving after the deadline is not success.
        self.remaining-=len(raw);require(self.remaining>=0)
        if raw:self.buffer.extend(raw)
        else:self.eof=True
    def read(self,n=-1):
        self._before();require(type(n) is int)
        if n<0:
            while not self.eof:self._receive()
            n=len(self.buffer)
        else:
            require(n<=73729)
            while len(self.buffer)<n and not self.eof:self._receive()
        raw=bytes(self.buffer[:n]);del self.buffer[:n];return raw
    def readline(self,n=-1):
        self._before();require(type(n) is int);limit=8193 if n<0 else min(n,8193)
        while True:
            end=self.buffer.find(b'\n',0,limit)
            count=end+1 if end>=0 else min(len(self.buffer),limit)
            if end>=0 or len(self.buffer)>=limit or self.eof:
                require(count<=8192)
                raw=bytes(self.buffer[:count]);del self.buffer[:count];return raw
            self._receive()
    def flush(self):pass  # http.client closes its read-only file via IOBase.flush.
    def close(self):self.closed=True;self.buffer.clear()

class HttpSocket:
    def __init__(self,sock,deadline,clock):self.socket=sock;self.deadline=deadline;self.clock=clock
    def makefile(self,mode):
        require(mode=='rb');return LimitedReader(self.socket,self.deadline,self.clock)

class Readiness:
    def __init__(self,io,transport,*,clock=time.monotonic):self.io=io;self.transport=transport;self.clock=clock
    def _connect(self,service,row,port,deadline):
        network={'redis':'cache','rabbitmq':'queue','registry':'artifact','keycloak':'identity'}[service]
        address=row['NetworkSettings']['Networks']['autosoft_'+network]['IPAddress']
        require(ipaddress.ip_address(address).version==4)
        # Trust only the rendered installation CA, not ambient machine roots.
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=self.io.read('tls/ca.crt').decode('ascii'))
        remaining=deadline-self.clock();require(remaining>0)
        raw=socket.create_connection((address,port),timeout=min(3,remaining))
        try:
            remaining=deadline-self.clock();require(remaining>0);raw.settimeout(min(3,remaining))
            return context.wrap_socket(raw,server_hostname=service)
        except BaseException:raw.close();raise
    def _http(self,service,row,path,deadline,authorization=None):
        with self._connect(service,row,9000 if service=='keycloak' else 5000,deadline) as sock:
            header=('GET '+path+' HTTP/1.1\r\nHost: '+service+'\r\nConnection: close\r\n').encode()
            if authorization:header+=b'Authorization: Basic '+authorization+b'\r\n'
            require(deadline>self.clock());sock.settimeout(min(3,deadline-self.clock()));sock.sendall(header+b'\r\n')
            response=http.client.HTTPResponse(HttpSocket(sock,deadline,self.clock))
            try:
                response.begin();require(response.status==200 or service=='keycloak' and response.status==503)
                raw=response.read(65537);require(len(raw)<=65536)
                value=json.loads(raw or b'{}')
                if response.status==503:require(type(value) is dict and value.get('status')=='DOWN')
                return value
            finally:response.close()
    def ready(self,service,row,*,deadline):
        self.io.check();deadline=min(deadline,self.clock()+8)
        try:
            if self.clock()>=deadline:raise TimeoutError('Private service readiness deadline exceeded')
            result=self._ready(service,row,deadline)
            self.io.check()
            if self.clock()>=deadline:raise TimeoutError('Private service readiness deadline exceeded')
            return result
        except (ConnectionRefusedError,TimeoutError,socket.timeout):return False
        except ssl.SSLCertVerificationError:raise ValueError('Private service TLS identity verification failed') from None
        finally:self.io.check()

    def _ready(self,service,row,deadline):
            if service=='mysql':
                # Protected backup.cnf specifies TCP/VERIFY_IDENTITY/CA and
                # hostname mysql. SELECT1 is repeatable and has no data writes.
                args=['--host','unix:///run/docker.sock','container','exec','--user','999:999',row['Id'],'mysql',
                    '--defaults-extra-file=/run/secrets/backup.cnf','--connect-timeout=5','--batch','--skip-column-names','--execute','SELECT 1']
                remaining=deadline-self.clock()
                if remaining<=0:raise TimeoutError('Private service readiness deadline exceeded')
                result=self.transport.run('docker',args,timeout=min(8,remaining))
                require(result.returncode in (0,1));return result.returncode==0 and result.stdout==b'1\n'
            if service=='rabbitmq':
                with self._connect(service,row,5671,deadline):return True
            if service=='redis':
                password=self.io.read('secrets/runtime/redis-admin');require(32<=len(password)<=256 and b'\r' not in password and b'\n' not in password)
                with self._connect(service,row,6379,deadline) as sock:
                    request=b'*3\r\n$4\r\nAUTH\r\n$11\r\nprovisioner\r\n$'+str(len(password)).encode()+b'\r\n'+password+b'\r\n'
                    require(deadline>self.clock());sock.settimeout(min(3,deadline-self.clock()));sock.sendall(request)
                    limited=LimitedReader(sock,deadline,self.clock)
                    try:
                        require(limited.readline(128)==b'+OK\r\n')
                        require(deadline>self.clock());sock.settimeout(min(3,deadline-self.clock()));sock.sendall(b'*1\r\n$4\r\nPING\r\n')
                        require(limited.readline(128)==b'+PONG\r\n')
                    finally:limited.close()
                return True
            if service=='registry':
                password=self.io.read('secrets/runtime/registry-password');require(32<=len(password)<=256)
                require(self._http(service,row,'/v2/',deadline,base64.b64encode(b'platform:'+password))=={});return True
            require(service=='keycloak')
            value=self._http(service,row,'/health/ready',deadline)
            if type(value) is dict and value.get('status')=='DOWN':return False
            require(type(value) is dict and value.get('status')=='UP' and type(value.get('checks')) is list
                and all(check.get('status')=='UP' for check in value['checks']));return True
