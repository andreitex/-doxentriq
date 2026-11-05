"""Policy/kernel unit checks; these do not qualify a deployed runsc source mount."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
from http.server import HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('filesystem', Path(__file__).with_name('filesystem.py'))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def config():
    return {'schemaVersion': 1, 'appId': 'app-one', 'connectionId': 'files-one', 'sourceRootId': 'import-one', 'root': 'documents', 'expiresAt': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(), 'sourceEvidenceHash': 'a' * 64, 'templateSourceHash': 'b' * 64, 'capabilities': ['files.list', 'files.read']}


class PolicyTests(unittest.TestCase):
    def test_configuration_has_no_paths_destinations_or_write_caps(self):
        sealed = config()
        self.assertEqual(adapter.validate_config(sealed), sealed)
        for change in [{'sourcePath': '/etc'}, {'capabilities': ['files.read', 'files.write']}, {'root': '..'}, {'sourceRootId': '../other'}, {'templateSourceHash': 'unknown'}, {'expiresAt': (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}, {'expiresAt': (datetime.now(timezone.utc) + timedelta(days=91)).isoformat()}]:
            with self.assertRaises(adapter.PolicyError):
                adapter.validate_config({**config(), **change})

    def test_traversal_encoded_paths_streams_and_ambiguous_names(self):
        self.assertEqual(adapter.relative_path('folder/report.pdf'), 'folder/report.pdf')
        for value in ['../outside', '/etc/passwd', 'folder//name', '.', './name', 'folder/../name', '%2e%2e/outside', 'C:\\secret', 'file:stream', 'name\0', ' bad', 'bad.', 'a/' * 25 + 'x', 'a' * 241, '']:
            with self.assertRaises(adapter.PolicyError, msg=value):
                adapter.relative_path(value, False)

    def test_exact_app_connection_root_and_operation(self):
        body = {'appId': 'app-one', 'root': 'documents', 'path': ''}
        self.assertEqual(adapter.request_scope(config(), 'files-one', 'list', body), '')
        for connection, operation, value in [('other', 'list', body), ('files-one', 'write', body), ('files-one', 'list', {**body, 'appId': 'other'}), ('files-one', 'list', {**body, 'root': 'other'}), ('files-one', 'list', {**body, 'url': 'https://example.test'}), ('files-one', 'read', body)]:
            with self.assertRaises(adapter.PolicyError):
                adapter.request_scope(config(), connection, operation, value)

    def test_duplicate_json_and_nonobject_requests(self):
        for raw in [b'{"appId":"one","appId":"two"}', b'[]', b'null']:
            with self.assertRaises(adapter.PolicyError):
                adapter.json_object(raw)

    def test_http_denies_cross_app_write_unknown_urls_and_bearer_missing(self):
        class Reader:
            def list(self, path):
                return {'entries': []}
        server = HTTPServer(('127.0.0.1', 0), adapter.handler(config(), 's' * 43, Reader()))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for url, token, body in [('/v1/connections/files-one/list', '', {'appId': 'app-one', 'root': 'documents', 'path': ''}), ('/v1/connections/files-one/list', 's' * 43, {'appId': 'other', 'root': 'documents', 'path': ''}), ('/v1/connections/files-one/write', 's' * 43, {}), ('/v1/connections/files-one/list?url=https://example.test', 's' * 43, {})]:
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                connection.request('POST', url, json.dumps(body), {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                self.assertNotIn('other', response.read().decode())
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


@unittest.skipUnless(sys.platform == 'linux' and os.uname().machine in {'x86_64', 'amd64'}, 'Linux amd64 kernel checks unavailable; not a runsc qualification')
class KernelTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def reader(self):
        # Unit tests run on a writable synthetic temporary directory. Production
        # always checks the actual read-only mount; runtime qualification does too.
        with patch.object(adapter, 'readonly_mount', return_value=True):
            return adapter.RootReader(str(self.root))

    def test_kernel_contained_list_and_bounded_read(self):
        (self.root / 'folder').mkdir()
        content = b'Synthetic document only'
        (self.root / 'folder' / 'document.txt').write_bytes(content)
        reader = self.reader()
        try:
            self.assertEqual(reader.list(''), {'entries': [{'name': 'folder', 'kind': 'directory', 'size': 0}]})
            result = reader.read('folder/document.txt')
            self.assertEqual(base64.b64decode(result['contentBase64']), content)
            self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
        finally:
            reader.close()

    def test_kernel_rejects_symlink_hardlink_fifo_and_oversized_file(self):
        (self.root / 'ordinary').write_bytes(b'synthetic')
        os.symlink('/etc/passwd', self.root / 'escape')
        os.link(self.root / 'ordinary', self.root / 'hardlink')
        os.mkfifo(self.root / 'pipe')
        with (self.root / 'large').open('wb') as stream:
            stream.truncate(adapter.MAX_FILE + 1)
        reader = self.reader()
        try:
            for name in ['escape', 'hardlink', 'ordinary', 'pipe', 'large']:
                with self.assertRaises(adapter.PolicyError, msg=name):
                    reader.read(name)
            with self.assertRaises(adapter.PolicyError):
                reader.list('')
        finally:
            reader.close()

    def test_startup_refuses_writable_mount(self):
        with self.assertRaises(adapter.PolicyError):
            adapter.RootReader(str(self.root))

    def test_openat2_failure_has_no_fallback_to_ordinary_open(self):
        with patch.object(adapter.ctypes, 'CDLL') as library:
            library.return_value.syscall.return_value = -1
            with patch.object(adapter.ctypes, 'get_errno', return_value=adapter.errno.ENOSYS):
                with self.assertRaisesRegex(adapter.PolicyError, 'containment is unavailable'):
                    self.reader()


if __name__ == '__main__':
    unittest.main()
