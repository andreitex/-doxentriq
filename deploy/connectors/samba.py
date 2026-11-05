#!/usr/bin/env python3
"""Company-maintained, share-scoped read-only SMB3 adapter and fixed-target TLS relay.

The adapter never accepts a server, share, credentials or network destination in an
application request.  Only the relay can reach the approved literal-IP SMB server.
"""
import base64
from collections import deque
from contextlib import ExitStack
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import selectors
import socket
import socketserver
import ssl
import sys
import threading
import time
import uuid

MAX_FILE = 16 * 1024 * 1024
MAX_ENTRIES = 1000
MAX_REQUEST = 16 * 1024
MAX_TUNNEL_BYTES = 32 * 1024 * 1024
OPERATION_SECONDS = 8
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class PolicyError(ValueError):
    pass


def json_object(raw):
    def unique(items):
        result = {}
        for name, value in items:
            if name in result:
                raise PolicyError('Duplicate fields are rejected')
            result[name] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise PolicyError('A JSON object is required')
    return value


def secret_file(name):
    value = Path(os.environ[name]).read_text().strip()
    if not TOKEN.fullmatch(value):
        raise PolicyError('A scoped 256-bit bearer token is required')
    return value


def expiry(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        raise PolicyError('A valid scope expiry is required') from None
    if result.tzinfo is None or result <= datetime.now(timezone.utc):
        raise PolicyError('The approved connection has expired')
    return result


def server_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise PolicyError('An approved literal IPv4 SMB destination is required') from None
    if address.version != 4 or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved or str(address) != value or value == '255.255.255.255':
        raise PolicyError('An approved unicast IPv4 SMB destination is required')
    return value


def safe_name(value):
    return isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 240 and value not in {'.', '..'} and not re.search(r'[\\/:%<>|?*"\x00-\x1f\x7f]', value) and value[-1] not in {'.', ' '} and value[0] != ' '


def relative_path(value, allow_empty=True):
    if not isinstance(value, str) or len(value) > 2048 or (not allow_empty and value == ''):
        raise PolicyError('A bounded relative path is required')
    if value == '' and allow_empty:
        return ''
    parts = value.split('/')
    if len(parts) > 24 or not all(safe_name(part) for part in parts):
        raise PolicyError('Traversal, alternate streams and ambiguous paths are rejected')
    return value


def validate_config(value, mode):
    required = {'schemaVersion', 'appId', 'connectionId', 'serverIp', 'expiresAt'}
    if mode == 'adapter':
        required |= {'root', 'share', 'relayHost', 'relayPort', 'relayServerName', 'readonlyAclEvidenceSha256'}
    if set(value) != required or value.get('schemaVersion') != 1 or any(not isinstance(value.get(name), str) or not ID.fullmatch(value[name]) for name in ('appId', 'connectionId')):
        raise PolicyError('Unexpected or incomplete sealed connector configuration')
    server_ip(value['serverIp'])
    expiry(value['expiresAt'])
    if mode == 'adapter':
        if not safe_name(value['share']) or value['share'].endswith('$') or not safe_name(value['root']):
            raise PolicyError('One ordinary share and one logical root are required')
        if not re.fullmatch(r'[a-f0-9]{64}', value['readonlyAclEvidenceSha256']):
            raise PolicyError('A company-reviewed remote readonly ACL record is required')
        if not re.fullmatch(r'app-[a-f0-9]{24}\.internal', value['relayHost']) or value['relayHost'] != value['relayServerName'] or type(value['relayPort']) is not int or value['relayPort'] != 8444:
            raise PolicyError('The private trusted relay identity is invalid')
    return value


def request_scope(config, connection_id, operation, body):
    expiry(config['expiresAt'])
    if operation not in {'list', 'read'} or connection_id != config['connectionId'] or set(body) != {'appId', 'root', 'path'} or body.get('appId') != config['appId'] or body.get('root') != config['root']:
        raise PolicyError('The request is outside this approved application/share scope')
    return relative_path(body.get('path'), allow_empty=operation == 'list')


def client_tls():
    context = ssl.create_default_context(cafile=os.environ['CONNECTOR_CA_FILE'])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def server_tls():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ['CONNECTOR_TLS_CERT_FILE'], os.environ['CONNECTOR_TLS_KEY_FILE'])
    return context


def read_header(connection, maximum=2048):
    # Read exactly through CRLFCRLF. No SMB payload is consumed as HTTP headers.
    result = bytearray()
    while not result.endswith(b'\r\n\r\n'):
        value = connection.recv(1)
        if not value or len(result) >= maximum:
            raise PolicyError('The bounded tunnel authorization header is invalid')
        result.extend(value)
    return bytes(result)


def relay_header(token):
    return ('CONNECT /smb HTTP/1.1\r\nAuthorization: Bearer ' + token + '\r\n\r\n').encode('ascii')


def valid_relay_header(header, token):
    return hmac.compare_digest(header, relay_header(token))


def pump(left, right):
    """Bidirectional bounded tunnel, with an absolute lifetime and idle deadline."""
    deadline = time.monotonic() + OPERATION_SECONDS
    idle = time.monotonic() + 3
    transferred = 0
    with selectors.DefaultSelector() as selector:
        selector.register(left, selectors.EVENT_READ, right)
        selector.register(right, selectors.EVENT_READ, left)
        while time.monotonic() < min(deadline, idle):
            events = selector.select(timeout=min(0.1, max(0, min(deadline, idle)-time.monotonic())))
            for event, _ in events:
                value = event.fileobj.recv(64 * 1024)
                if not value:
                    return
                transferred += len(value)
                if transferred > MAX_TUNNEL_BYTES:
                    raise PolicyError('The tunnel exceeded its byte limit')
                event.data.sendall(value)
                idle = time.monotonic() + 3


class BoundedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.slots = threading.BoundedSemaphore(2)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # Never log authentication material, server/share paths or SMB payloads.
        print(json.dumps({'event': 'connector_tunnel_rejected', 'errorClass': type(sys.exc_info()[1]).__name__}), flush=True)


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        with self.server.tls.wrap_socket(self.request, server_side=True) as connection:
            if not valid_relay_header(read_header(connection), self.server.token):
                connection.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                return
            expiry(self.server.config['expiresAt'])
            # Fixed sealed IPv4 destination/port: no DNS, request-selected target,
            # forwarded HTTP URL, SMB credentials or fallback destination.
            with socket.create_connection((self.server.config['serverIp'], 445), timeout=2) as upstream:
                upstream.settimeout(2)
                connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                pump(connection, upstream)


class TunnelHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        config = self.server.config
        expiry(config['expiresAt'])
        with socket.create_connection((config['relayHost'], config['relayPort']), timeout=2) as raw:
            with self.server.tls.wrap_socket(raw, server_hostname=config['relayServerName']) as connection:
                connection.settimeout(2)
                connection.sendall(relay_header(self.server.token))
                if read_header(connection) != b'HTTP/1.1 200 Connection Established\r\n\r\n':
                    raise PolicyError('The trusted relay rejected the scope')
                pump(self.request, connection)


class SMBReader:
    def __init__(self, config, credentials, tunnel_port):
        self.config, self.credentials, self.tunnel_port = config, credentials, tunnel_port

    def operation(self, operation, path):
        # Low-level protocol only: no smbclient DFS caches/referrals, remote URLs,
        # shares, write/create operations, symlink resolution or process execution.
        from smbprotocol import Dialects
        from smbprotocol.connection import Connection
        from smbprotocol.exceptions import NoMoreFiles
        from smbprotocol.file_info import FileAttributes, FileInformationClass
        from smbprotocol.open import Open, ImpersonationLevel, FilePipePrinterAccessMask, DirectoryAccessMask, CreateDisposition, CreateOptions, ShareAccess, QueryDirectoryFlags
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect

        deadline = time.monotonic() + OPERATION_SECONDS
        class ScopedConnection(Connection):
            def receive(self, request, wait=True, timeout=None, resolve_symlinks=False):
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise PolicyError('The SMB operation exceeded its deadline')
                return super().receive(request, wait=wait, timeout=min(remaining, timeout) if timeout else remaining, resolve_symlinks=False)
        connection = ScopedConnection(uuid.uuid4(), '127.0.0.1', port=self.tunnel_port, require_signing=True)
        try:
            connection.connect(dialect=Dialects.SMB_3_1_1, timeout=2)
            if connection.dialect != Dialects.SMB_3_1_1 or not connection.supports_encryption:
                raise PolicyError('SMB3.1.1 encryption is required without downgrade')
            session = Session(connection, username=self.credentials['username'], password=self.credentials['password'], require_encryption=True, hostname_override=self.config['serverIp'], auth_protocol='ntlm')
            session.connect()
            if not session.encrypt_data or not session.session_key:
                raise PolicyError('Authenticated encrypted SMB3.1.1 is required')
            tree = TreeConnect(session, '\\\\' + self.config['serverIp'] + '\\' + self.config['share'])
            tree.connect()
            if tree.is_dfs_share:
                raise PolicyError('DFS referral shares are unavailable in the scoped connector')
            with ExitStack() as opened:
                def open_path(name, directory):
                    handle = Open(tree, name.replace('/', '\\'))
                    access = (DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_READ_ATTRIBUTES) if directory else (FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES)
                    options = CreateOptions.FILE_OPEN_REPARSE_POINT | (CreateOptions.FILE_DIRECTORY_FILE if directory else CreateOptions.FILE_NON_DIRECTORY_FILE)
                    handle.create(ImpersonationLevel.Identification, access, 0, ShareAccess.FILE_SHARE_READ, CreateDisposition.FILE_OPEN, options)
                    opened.callback(handle.close)
                    if handle.file_attributes & FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT:
                        raise PolicyError('Reparse points are rejected')
                    return handle
                # Hold ancestor directory handles without SHARE_WRITE/DELETE while
                # reading, and reject every advertised reparse point in the path.
                parts = path.split('/') if path else []
                for count in range(1, len(parts)):
                    open_path('/'.join(parts[:count]), True)
                handle = open_path(path, operation == 'list')
                if operation == 'list':
                    entries, first = [], True
                    while True:
                        try:
                            page = handle.query_directory('*', FileInformationClass.FILE_DIRECTORY_INFORMATION, flags=QueryDirectoryFlags.SMB2_RESTART_SCANS if first else 0, max_output=64*1024)
                        except NoMoreFiles:
                            break
                        first = False
                        if not page:
                            break
                        for item in page:
                            name = item['file_name'].get_value().decode('utf-16-le', errors='strict')
                            if name in {'.', '..'}:
                                continue
                            attributes = item['file_attributes'].get_value()
                            if not safe_name(name) or attributes & FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT:
                                continue
                            entries.append({'name': name, 'kind': 'directory' if attributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY else 'file'})
                            if len(entries) > MAX_ENTRIES:
                                raise PolicyError('Directory exceeds the approved listing limit')
                    return {'entries': entries}
                size = handle.end_of_file
                if type(size) is not int or size < 0 or size > MAX_FILE:
                    raise PolicyError('File exceeds the approved read limit')
                result = bytearray()
                while len(result) < size:
                    block = handle.read(len(result), min(64*1024, size-len(result), connection.max_read_size))
                    if not block or len(block) > size-len(result):
                        raise PolicyError('Remote file changed during the bounded read')
                    result.extend(block)
                return {'contentBase64': base64.b64encode(result).decode('ascii'), 'mime': 'application/octet-stream'}
        finally:
            connection.disconnect(close=False, timeout=1)


class AdapterHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, format, *args):
        pass

    def send_json(self, status, value):
        content = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(content)
        self.close_connection = True

    def authorized(self):
        actual = self.headers.get_all('Authorization') or []
        return len(actual) == 1 and hmac.compare_digest(actual[0], 'Bearer '+self.server.token)

    def do_GET(self):
        if self.path != '/health' or not self.authorized():
            self.send_json(403, {'error':'Scoped connector authorization required'})
            return
        try:
            expiry(self.server.config['expiresAt'])
            self.send_json(200, {'status':'passed','scope':'adapter_process','upstreamVerified':False})
        except PolicyError:
            self.send_json(409, {'error':'The approved connection has expired'})

    def do_POST(self):
        started = time.monotonic()
        if not self.authorized():
            # Drain only a small well-framed body so a TCP reset cannot hide the
            # explicit denial from the caller. Never parse or execute its content.
            sizes = self.headers.get_all('Content-Length') or []
            if len(sizes)==1 and re.fullmatch(r'[1-9][0-9]{0,4}',sizes[0]) and int(sizes[0])<=MAX_REQUEST and not self.headers.get('Transfer-Encoding'):
                try:
                    self.rfile.read(int(sizes[0]))
                except OSError:
                    pass
            self.send_json(403, {'error':'Scoped connector authorization required'})
            return
        try:
            now = time.monotonic()
            while self.server.requests and now-self.server.requests[0] > 60:
                self.server.requests.popleft()
            if len(self.server.requests) >= 30:
                self.send_json(429, {'error':'The scoped connector request limit was reached'})
                return
            self.server.requests.append(now)
            match = re.fullmatch(r'/v1/connections/([A-Za-z0-9][A-Za-z0-9_-]{0,79})/(list|read)', self.path)
            sizes = self.headers.get_all('Content-Length') or []
            if len(sizes) != 1 or not re.fullmatch(r'[1-9][0-9]{0,4}', sizes[0]) or int(sizes[0]) > MAX_REQUEST or self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                raise PolicyError('Only bounded read-only connector requests are accepted')
            body = self.rfile.read(int(sizes[0]))
            if len(body) != int(sizes[0]):
                raise PolicyError('Incomplete JSON request')
            if not match:
                raise PolicyError('Only read-only connector operations are accepted')
            operation = match.group(2)
            path = request_scope(self.server.config, match.group(1), operation, json_object(body))
            result = self.server.reader.operation(operation, path)
            self.send_json(200, result)
            print(json.dumps({'event':'connector_read','operation':operation,'durationMs':round((time.monotonic()-started)*1000)}), flush=True)
        except (PolicyError, ValueError, UnicodeError) as error:
            self.send_json(400, {'error':'The read-only connector scope or response limit was rejected'})
            print(json.dumps({'event':'connector_policy_rejected','errorClass':type(error).__name__}),flush=True)
        except Exception as error:
            # SDK errors can include usernames/share names; return/log no raw detail.
            self.send_json(503, {'error':'The approved SMB connection is unavailable; ask the company operator to verify connectivity and server permissions'})
            print(json.dumps({'event':'connector_upstream_unavailable','errorClass':type(error).__name__}), flush=True)


class AdapterServer(HTTPServer):
    request_queue_size = 8

    def get_request(self):
        connection, address = self.socket.accept()
        connection.settimeout(2)
        try:
            return self.tls.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise


def main():
    mode = os.environ.get('CONNECTOR_MODE')
    if mode not in {'adapter', 'relay'}:
        raise PolicyError('A fixed company connector mode is required')
    config = validate_config(json_object(Path(os.environ['CONNECTOR_CONFIG_FILE']).read_bytes()), mode)
    token = secret_file('CONNECTOR_TOKEN_FILE')
    if mode == 'relay':
        server = BoundedTCPServer(('0.0.0.0', 8444), RelayHandler)
        server.config, server.token, server.tls = config, token, server_tls()
        server.serve_forever(poll_interval=0.1)
        return
    credentials = json_object(Path(os.environ['CONNECTOR_CREDENTIALS_FILE']).read_bytes())
    if set(credentials) != {'username', 'password'} or any(not isinstance(credentials[name], str) or not 1 <= len(credentials[name]) <= 1024 or '\x00' in credentials[name] for name in credentials):
        raise PolicyError('Dedicated remote read-only account credentials are required')
    # Disable SDK logging: it contains share names, usernames and packet contents.
    for name in ('smbprotocol', 'spnego'):
        logging.getLogger(name).disabled = True
        logging.getLogger(name).setLevel(logging.CRITICAL+1)
    os.environ['LM_COMPAT_LEVEL'] = '5'
    tunnel = BoundedTCPServer(('127.0.0.1', 0), TunnelHandler)
    tunnel.config, tunnel.token, tunnel.tls = config, secret_file('CONNECTOR_RELAY_TOKEN_FILE'), client_tls()
    threading.Thread(target=tunnel.serve_forever, daemon=True).start()
    server = AdapterServer(('0.0.0.0', 8443), AdapterHandler)
    server.config, server.token = config, token
    server.reader, server.requests = SMBReader(config, credentials, tunnel.server_address[1]), deque()
    server.tls = server_tls()
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        tunnel.shutdown()
        tunnel.server_close()


if __name__ == '__main__':
    main()
