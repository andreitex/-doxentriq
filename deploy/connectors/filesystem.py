#!/usr/bin/env python3
"""Fixed-root, read-only company filesystem adapter. No outbound client exists.

All paths are opened beneath a preopened read-only mount using Linux openat2.
The container must mount one independently approved import root at /run/source.
"""
import base64
from collections import deque
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time

MAX_FILE = 4 * 1024 * 1024
MAX_ENTRIES = 1000
MAX_REQUEST = 16 * 1024
OPERATION_SECONDS = 8
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$')
TOKEN = re.compile(r'^[A-Za-z0-9_-]{43}$')
SHA = re.compile(r'^[a-f0-9]{64}$')
# Linux UAPI openat2.h: no cross-mount, magic link, symlink or root escape.
RESOLVE = 0x01 | 0x02 | 0x04 | 0x08


class PolicyError(ValueError):
    pass


def json_object(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PolicyError('Duplicate fields are rejected')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise PolicyError('A JSON object is required')
    return value


def expiry(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (AttributeError, ValueError):
        raise PolicyError('A valid scope expiry is required') from None
    current = datetime.now(timezone.utc)
    if result.tzinfo is None or result <= current or (result - current).total_seconds() > 90 * 86400:
        raise PolicyError('The approved connection has expired or exceeds 90 days')
    return result


def safe_name(value):
    return isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 240 and value not in {'.', '..'} and not re.search(r'[\\/:%<>|?*"\x00-\x1f\x7f]', value) and value[0] != ' ' and value[-1] not in {'.', ' '}


def relative_path(value, allow_empty=True):
    if not isinstance(value, str) or len(value.encode('utf-8')) > 2048:
        raise PolicyError('A bounded relative path is required')
    if value == '' and allow_empty:
        return ''
    parts = value.split('/')
    if len(parts) > 24 or not all(safe_name(part) for part in parts):
        raise PolicyError('Traversal and ambiguous paths are rejected')
    return value


def validate_config(value):
    required = {'schemaVersion', 'appId', 'connectionId', 'sourceRootId', 'root', 'expiresAt', 'sourceEvidenceHash', 'templateSourceHash', 'capabilities'}
    if set(value) != required or type(value.get('schemaVersion')) is not int or value['schemaVersion'] != 1 or any(not isinstance(value.get(name), str) or not ID.fullmatch(value[name]) for name in ('appId', 'connectionId', 'sourceRootId')):
        raise PolicyError('Unexpected or incomplete sealed filesystem configuration')
    if not safe_name(value.get('root')) or any(not isinstance(value.get(name), str) or not SHA.fullmatch(value[name]) for name in ('sourceEvidenceHash', 'templateSourceHash')):
        raise PolicyError('One approved logical root and company evidence hashes are required')
    if value.get('capabilities') != ['files.list', 'files.read']:
        raise PolicyError('Only explicit files.list and files.read are supported')
    expiry(value.get('expiresAt'))
    return value


def request_scope(config, connection_id, operation, body):
    expiry(config['expiresAt'])
    if operation not in {'list', 'read'} or connection_id != config['connectionId'] or set(body) != {'appId', 'root', 'path'} or body.get('appId') != config['appId'] or body.get('root') != config['root']:
        raise PolicyError('The request is outside the approved application/root scope')
    return relative_path(body.get('path'), allow_empty=operation == 'list')


class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]


def beneath(root_fd, path, directory=False):
    if sys.platform != 'linux' or os.uname().machine not in {'x86_64', 'amd64'}:
        raise PolicyError('Linux amd64 openat2 containment is required')
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    how = OpenHow(flags, 0, RESOLVE)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(ctypes.c_long(437), ctypes.c_int(root_fd), ctypes.c_char_p((path or '.').encode('utf-8')), ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
    if result < 0:
        # Do not return requested names, host paths or OS diagnostic contents.
        if ctypes.get_errno() in {errno.ENOSYS, errno.EINVAL}:
            raise PolicyError('Required openat2 containment is unavailable')
        raise PolicyError('The entry is unavailable or outside the approved root')
    return result


def readonly_mount(fd):
    return bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)


class RootReader:
    def __init__(self, root='/run/source'):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            if not readonly_mount(self.fd):
                raise PolicyError('The approved source mount must be read-only')
            probe = beneath(self.fd, '', True)
            os.close(probe)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    def list(self, path):
        relative_path(path)
        directory = beneath(self.fd, path, True)
        started = time.monotonic()
        entries = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    if len(entries) >= MAX_ENTRIES or time.monotonic() - started > OPERATION_SECONDS:
                        raise PolicyError('The directory exceeds the bounded listing limit')
                    if not safe_name(entry.name):
                        raise PolicyError('The directory contains an unsupported entry name')
                    child = beneath(directory, entry.name)
                    try:
                        info = os.fstat(child)
                        if stat.S_ISDIR(info.st_mode):
                            kind = 'directory'
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                            kind = 'file'
                        else:
                            raise PolicyError('Links and special files cannot be exposed')
                        entries.append({'name': entry.name, 'kind': kind, 'size': info.st_size if kind == 'file' else 0})
                    finally:
                        os.close(child)
            return {'entries': sorted(entries, key=lambda item: item['name'])}
        finally:
            os.close(directory)

    def read(self, path):
        relative_path(path, False)
        descriptor = beneath(self.fd, path)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
                raise PolicyError('Only bounded ordinary single-link files may be read')
            started, content = time.monotonic(), bytearray()
            while True:
                if time.monotonic() - started > OPERATION_SECONDS:
                    raise PolicyError('The bounded read timed out')
                block = os.read(descriptor, min(65536, MAX_FILE + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
                if len(content) > MAX_FILE:
                    raise PolicyError('The file exceeds the bounded read limit')
            after = os.fstat(descriptor)
            fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if fingerprint(before) != fingerprint(after) or len(content) != before.st_size:
                raise PolicyError('The source changed during the read; retry after it is stable')
            return {'contentBase64': base64.b64encode(content).decode('ascii'), 'mimeType': 'application/octet-stream', 'sha256': hashlib.sha256(content).hexdigest()}
        finally:
            os.close(descriptor)


def handler(config, token, reader):
    requests = deque()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def log_message(self, *_):
            pass

        def reply(self, code, value):
            body = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def authorized(self):
            expiry(config['expiresAt'])
            values = self.headers.get_all('Authorization', [])
            if len(values) != 1 or not hmac.compare_digest(values[0], 'Bearer ' + token):
                raise PolicyError('A current scoped bearer token is required')
            current = time.monotonic()
            while requests and current - requests[0] > 60:
                requests.popleft()
            if len(requests) >= 30:
                raise PolicyError('The bounded request rate was exceeded')
            requests.append(current)

        def do_GET(self):
            try:
                self.authorized()
                if self.path != '/health':
                    return self.reply(404, {'error': 'Unknown operation'})
                self.reply(200, {'status': 'passed', 'readonlyRoot': True, 'upstreamVerified': False})
            except (PolicyError, ValueError):
                self.reply(403, {'error': 'Scope unavailable or unauthorized'})

        def do_POST(self):
            try:
                self.authorized()
                match = re.fullmatch(r'/v1/connections/([A-Za-z0-9][A-Za-z0-9_-]{0,79})/(list|read)', self.path)
                lengths = self.headers.get_all('Content-Length', [])
                if not match or self.headers.get('Transfer-Encoding') or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,5}', lengths[0]) or not 0 < int(lengths[0]) <= MAX_REQUEST or self.headers.get('Content-Type') != 'application/json':
                    raise PolicyError('Only bounded fixed JSON operations are supported')
                body = self.rfile.read(int(lengths[0]))
                if len(body) != int(lengths[0]):
                    raise PolicyError('A complete bounded JSON request is required')
                path = request_scope(config, match[1], match[2], json_object(body))
                self.reply(200, getattr(reader, match[2])(path))
            except (PolicyError, UnicodeError, ValueError, OSError):
                self.reply(403, {'error': 'Scope unavailable, unsupported entry or bounded operation failed'})

    return Handler


def main():
    config = validate_config(json_object(Path(os.environ['CONNECTOR_CONFIG_FILE']).read_bytes()))
    token = Path(os.environ['CONNECTOR_TOKEN_FILE']).read_text().strip()
    if not TOKEN.fullmatch(token):
        raise PolicyError('A scoped 256-bit bearer token is required')
    reader = RootReader()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(os.environ['CONNECTOR_TLS_CERT_FILE'], os.environ['CONNECTOR_TLS_KEY_FILE'])
    class SecureServer(HTTPServer):
        request_queue_size = 8

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            try:
                return tls.wrap_socket(connection, server_side=True), address
            except BaseException:
                connection.close()
                raise

    server = SecureServer(('0.0.0.0', 8443), handler(config, token, reader))
    try:
        server.serve_forever()
    finally:
        reader.close()
        server.server_close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Filesystem adapter failed closed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
