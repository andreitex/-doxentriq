#!/usr/bin/env python3
"""Request/protocol policy tests for the company Samba connector (no real SMB claim)."""
import base64
from collections import deque
from datetime import datetime, timedelta, timezone
import http.client
from http.server import HTTPServer
import importlib.util
import json
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/'deploy/connectors/samba.py'
if not SOURCE.exists():
    SOURCE = Path(__file__).with_name('samba.py')
spec = importlib.util.spec_from_file_location('scoped_samba', SOURCE)
samba = importlib.util.module_from_spec(spec)
spec.loader.exec_module(samba)
TOKEN = 't'*43
CONFIG = dict(schemaVersion=1,appId='fixture-app',connectionId='fixture-connection',serverIp='10.23.23.99',expiresAt=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),root='documents',share='documents',relayHost='app-'+'a'*24+'.internal',relayServerName='app-'+'a'*24+'.internal',relayPort=8444,readonlyAclEvidenceSha256='b'*64)


class SambaPolicy(unittest.TestCase):
    def test_literal_fixed_target_no_special_or_rebinding_destinations(self):
        self.assertEqual(samba.server_ip('10.23.23.99'),'10.23.23.99')
        for value in ('localhost','share.example','127.0.0.1','169.254.169.254','0.0.0.0','224.0.0.1','255.255.255.255','::1','10.23.23.99:445','010.23.23.99'):
            with self.subTest(value=value), self.assertRaises(samba.PolicyError):
                samba.server_ip(value)

    def test_sealed_config_and_remote_readonly_record_required(self):
        samba.validate_config(CONFIG,'adapter')
        for change in ({'readonlyAclEvidenceSha256':''},{'share':'IPC$'},{'root':'../documents'},{'relayHost':'api.internal'},{'relayPort':445},{'serverIp':'localhost'},{'username':'leak'}):
            with self.subTest(change=change), self.assertRaises(samba.PolicyError):
                samba.validate_config({**CONFIG,**change},'adapter')

    def test_app_connection_and_root_are_exact_and_expire(self):
        body=dict(appId='fixture-app',root='documents',path='folder/file.txt')
        self.assertEqual(samba.request_scope(CONFIG,'fixture-connection','read',body),'folder/file.txt')
        for connection,operation,change in [('other','read',{}),('fixture-connection','write',{}),('fixture-connection','read',{'appId':'other'}),('fixture-connection','read',{'root':'other'}),('fixture-connection','read',{'server':'evil'}),('fixture-connection','read',{'path':''})]:
            with self.subTest(change=change), self.assertRaises(samba.PolicyError):
                samba.request_scope(CONFIG,connection,operation,{**body,**change})
        with self.assertRaises(samba.PolicyError):
            samba.request_scope({**CONFIG,'expiresAt':'2020-01-01T00:00:00Z'},'fixture-connection','read',body)

    def test_paths_cannot_traverse_alias_encode_or_open_streams(self):
        self.assertEqual(samba.relative_path('folder/report.pdf'),'folder/report.pdf')
        for value in ('../secret','folder/../secret','/secret','folder//file','file:secret','file%2fsecret','file\\secret','file\x00secret','.','folder/.','folder/','trailing.','trailing ','*','file?','a/'*25+'file'):
            with self.subTest(value=value), self.assertRaises(samba.PolicyError):
                samba.relative_path(value)

    def test_no_ambiguous_json_fields(self):
        with self.assertRaises(samba.PolicyError):
            samba.json_object('{"appId":"a","appId":"b"}')
        with self.assertRaises(samba.PolicyError):
            samba.json_object('[]')

    def test_relay_is_exact_protocol_without_request_target(self):
        header=samba.relay_header(TOKEN)
        self.assertTrue(samba.valid_relay_header(header,TOKEN))
        for candidate in (header.replace(b'/smb',b'evil:445'),header.replace(TOKEN.encode(),b'x'*43),header.replace(b'\r\n\r\n',b'\r\nHost: evil\r\n\r\n'),header+b'payload'):
            self.assertFalse(samba.valid_relay_header(candidate,TOKEN))
        left,right=socket.socketpair()
        try:
            left.sendall(header+b'SMB packet')
            self.assertEqual(samba.read_header(right),header)
            self.assertEqual(right.recv(10),b'SMB packet')
        finally:
            left.close();right.close()

    def test_relay_dials_only_sealed_445_after_authorization(self):
        class TLS:
            def wrap_socket(self, connection, **options):
                return connection
        relay=samba.BoundedTCPServer(('127.0.0.1',0),samba.RelayHandler)
        relay.tls=TLS();relay.token=TOKEN;relay.config=CONFIG
        thread=threading.Thread(target=relay.serve_forever,daemon=True);thread.start()
        try:
            with patch.object(samba.socket,'create_connection',side_effect=OSError('fixture upstream unavailable')) as dial:
                connection=socket.socket();connection.connect(relay.server_address)
                connection.sendall(samba.relay_header('x'*43))
                self.assertIn(b'403',connection.recv(1024));connection.close()
                dial.assert_not_called()
                connection=socket.socket();connection.connect(relay.server_address)
                connection.sendall(samba.relay_header(TOKEN));connection.recv(1024);connection.close()
                dial.assert_called_once_with(('10.23.23.99',445),timeout=2)
        finally:
            relay.shutdown();relay.server_close();thread.join(2)

    def test_tunnel_transfer_has_a_hard_byte_limit(self):
        left,client=socket.socketpair();right,upstream=socket.socketpair()
        try:
            client.sendall(b'large')
            with patch.object(samba,'MAX_TUNNEL_BYTES',4), self.assertRaises(samba.PolicyError):
                samba.pump(left,right)
        finally:
            for item in (left,client,right,upstream):item.close()

    def test_http_interface_rejects_scope_before_calling_reader(self):
        class Reader:
            def __init__(self):self.calls=[]
            def operation(self,operation,path):
                self.calls.append((operation,path))
                return {'entries':[{'name':'report.txt','kind':'file'}]} if operation=='list' else {'contentBase64':base64.b64encode(b'fixture').decode()}
        server=HTTPServer(('127.0.0.1',0),samba.AdapterHandler)
        server.config=CONFIG;server.token=TOKEN;server.requests=deque();server.reader=Reader()
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(path,body,token=TOKEN):
            connection=http.client.HTTPConnection(*server.server_address,timeout=2)
            connection.request('POST',path,json.dumps(body),headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
            response=connection.getresponse();result=(response.status,json.loads(response.read()));connection.close();return result
        try:
            self.assertEqual(request('/v1/connections/fixture-connection/list',dict(appId='fixture-app',root='documents',path=''))[0],200)
            self.assertEqual(server.reader.calls,[('list','')])
            for path,body,token in [('/v1/connections/fixture-connection/read',dict(appId='fixture-app',root='documents',path='../secret'),TOKEN),('/v1/connections/fixture-connection/write',dict(appId='fixture-app',root='documents',path='report.txt'),TOKEN),('/v1/connections/other/read',dict(appId='fixture-app',root='documents',path='report.txt'),TOKEN),('/v1/connections/fixture-connection/read',dict(appId='other',root='documents',path='report.txt'),TOKEN),('/v1/connections/fixture-connection/read',dict(appId='fixture-app',root='documents',path='report.txt'),'x'*43)]:
                self.assertIn(request(path,body,token)[0],(400,403))
            self.assertEqual(server.reader.calls,[('list','')])
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_real_sdk_readonly_constants_available_in_company_image(self):
        try:
            from smbprotocol.file_info import FileAttributes,FileInformationClass
            from smbprotocol.open import CreateOptions,CreateDisposition,DirectoryAccessMask,FilePipePrinterAccessMask
            from smbprotocol.connection import Connection
        except ModuleNotFoundError:
            self.skipTest('Live SDK installed only in company connector image; local checks do not qualify SMB')
        self.assertEqual(CreateDisposition.FILE_OPEN,1)
        self.assertEqual(CreateOptions.FILE_OPEN_REPARSE_POINT,0x00200000)
        self.assertEqual(DirectoryAccessMask.FILE_LIST_DIRECTORY,FilePipePrinterAccessMask.FILE_READ_DATA)
        self.assertEqual(FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT,0x400)
        self.assertTrue(hasattr(FileInformationClass,'FILE_DIRECTORY_INFORMATION'))


if __name__=='__main__':
    unittest.main()
