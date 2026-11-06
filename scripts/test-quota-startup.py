"""Readiness, shutdown and unit wiring controls; not native reboot acceptance."""
import ast
from contextlib import contextmanager
import errno
import importlib.util
import os
from pathlib import Path
import socket
import socketserver
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
import uuid
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent

def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

Q=module('quota_startup_helper',HERE/'quota-helper.py')
B=module('quota_startup_bootstrap',HERE/'bootstrap.py')
INSTALLATION='894f90fe-9323-4c38-a8b7-e588cbd6689c'

@contextmanager
def working_directory(path):
    before=Path.cwd();os.chdir(path)
    try:yield
    finally:os.chdir(before)


class Tests(unittest.TestCase):
    def test_readiness_requires_existing_open_matching_allocation_and_mount(self):
        events=[]
        class Inspection:
            def __init__(self,name):self.name=name
            @contextmanager
            def inspect_initialized(self,identity,**kwargs):
                self_test.assertEqual(identity,INSTALLATION)
                self_test.assertEqual(kwargs['timeout'],10)
                if self.name=='allocation':self_test.assertIs(kwargs['read_state'],Q._runtime.load_state)
                events.append(self.name+' enter')
                yield {}
                events.append(self.name+' leave')
        self_test=self
        data=Path('/synthetic-encrypted')
        with patch.object(Q,'mount_proof',side_effect=lambda path:events.append('mount')) as mount, \
             patch.object(Q._runtime,'checkpoint_gate',return_value=Inspection('gate')), \
             patch.object(Q._runtime,'allocation_store',return_value=Inspection('allocation')):
            Q.verify_startup(data,INSTALLATION)
            self.assertEqual(mount.call_count,2)
        self.assertEqual(events,['mount','gate enter','allocation enter','mount','allocation leave','gate leave'])

    def test_uncertain_initialization_never_becomes_readiness_or_initialization(self):
        class Refused:
            @contextmanager
            def inspect_initialized(self,*args,**kwargs):
                raise ValueError('Synthetic retained pending state')
                yield
        for stage in ('mount','gate','allocation'):
            events=[]
            @contextmanager
            def allowed(*args,**kwargs):yield {}
            gate=type('Gate',(),{'inspect_initialized':staticmethod(allowed)})()
            allocation=type('Allocation',(),{'inspect_initialized':staticmethod(allowed)})()
            with patch.object(Q,'mount_proof',side_effect=ValueError('Synthetic wrong mount') if stage=='mount' else None), \
                 patch.object(Q._runtime,'checkpoint_gate',return_value=Refused() if stage=='gate' else gate), \
                 patch.object(Q._runtime,'allocation_store',return_value=Refused() if stage=='allocation' else allocation), \
                 patch.object(Q._runtime,'initialize_allocation',side_effect=lambda *a:events.append('initialize')):
                with self.assertRaises(ValueError):Q.verify_startup(Path('/synthetic-encrypted'),INSTALLATION)
            self.assertEqual(events,[])
        with patch.object(Q,'mount_proof') as mount:
            for value in (None,True,'not-an-id',INSTALLATION.upper()):
                with self.assertRaises((ValueError,AttributeError)):Q.verify_startup(Path('/synthetic-encrypted'),value)
            mount.assert_not_called()

    def test_listener_signals_ready_before_requests_and_stopping_on_drain(self):
        events=[];stopping=threading.Event()
        class Listener:
            def handle_request(self):events.append('request');stopping.set()
        listener=Listener()
        Q.serve_ready(listener,stopping,'/synthetic-notify',notify=lambda address,message:events.append(message))
        self.assertEqual(events,['READY=1','request','STOPPING=1'])
        self.assertEqual(listener.timeout,.25)
        events.clear()
        Q.serve_ready(listener,stopping,None,notify=lambda *args:events.append(args))
        self.assertEqual(events,[])

    def test_no_requests_are_accepted_if_ready_notification_fails(self):
        class Listener:
            def handle_request(self):raise AssertionError('Request was dispatched before readiness')
        def failed(*args):raise OSError('Synthetic notification failure')
        with self.assertRaises(OSError):Q.serve_ready(Listener(),threading.Event(),'/synthetic',notify=failed)

    def test_notification_uses_bounded_unix_datagram_and_rejects_other_authority(self):
        class Datagram:
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def settimeout(self,value):self.timeout=value
            def sendto(self,body,target):self.message=(body,target);return len(body)
        client=Datagram()
        family=getattr(socket,'AF_UNIX',object())
        with patch.object(Q.socket,'AF_UNIX',family,create=True), patch.object(Q.socket,'socket',return_value=client) as create:
            Q.notify_service('@synthetic-notify','READY=1')
            self.assertEqual(client.message,(b'READY=1','\0synthetic-notify'))
            self.assertEqual(client.timeout,2)
            create.assert_called_once_with(socket.AF_UNIX,socket.SOCK_DGRAM)
            create.reset_mock()
            for address in ('127.0.0.1:9000','relative','/', '@', '/bad\npath', '/bad\0path','/'+'x'*108):
                with self.assertRaises(ValueError):Q.notify_service(address,'READY=1')
            with self.assertRaises(ValueError):Q.notify_service('/synthetic','READY=1\nSTATUS=arbitrary')
            Q.notify_service(None,'READY=1')
            create.assert_not_called()

    def test_only_proven_stale_company_socket_survives_systemd_group_transition(self):
        events=[]
        identity=types.SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=0)
        class PathValue:
            def lstat(self):return identity
            def unlink(self):events.append('unlink')
            def __str__(self):return '/run/autosoft/quota.sock'
        class Probe:
            error=errno.ECONNREFUSED
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def settimeout(self,value):self.timeout=value
            def connect(self,path):
                if self.error:raise OSError(self.error,'Synthetic socket outcome')
        probe=Probe();family=getattr(socket,'AF_UNIX',object())
        with patch.object(Q.os.path,'lexists',return_value=True), patch.object(Q.socket,'AF_UNIX',family,create=True), patch.object(Q.socket,'socket',return_value=probe):
            for group in (0,10001):
                identity.st_gid=group;events.clear();Q.stale_socket(PathValue())
                self.assertEqual(events,['unlink'])
            for uid,group,mode,error in ((10001,10001,0o660,errno.ECONNREFUSED),(0,77,0o660,errno.ECONNREFUSED),(0,0,0o666,errno.ECONNREFUSED),(0,0,0o660,errno.EACCES),(0,0,0o660,0)):
                identity.st_uid=uid;identity.st_gid=group;identity.st_mode=stat.S_IFSOCK|mode;probe.error=error;events.clear()
                with self.assertRaises(ValueError):Q.stale_socket(PathValue())
                self.assertEqual(events,[])

    @unittest.skipUnless(os.name=='posix' and hasattr(socket,'AF_UNIX') and getattr(os,'geteuid',lambda:1)()==0,'Native root socket ownership transition is qualified on Linux')
    def test_native_stale_socket_recovery_accepts_root_group_but_keeps_active_listener(self):
        with tempfile.TemporaryDirectory(prefix='doxentriq-quota-owner-') as temp, working_directory(temp):
            directory=Path(temp);lock=Q.service_lock(directory);path=Path('quota.sock');inode=directory.stat().st_ino
            try:
                for group in (10001,0):
                    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    listener.bind(str(path));listener.listen(1);os.chmod(path,0o660);os.chown(path,0,group)
                    with self.assertRaises(ValueError):Q.stale_socket(path)
                    self.assertTrue(path.is_socket())
                    listener.close();Q.stale_socket(path)
                    self.assertFalse(path.exists());self.assertEqual(directory.stat().st_ino,inode)
            finally:os.close(lock)

    @unittest.skipUnless(sys.platform=='linux' and hasattr(socket,'AF_UNIX'),'Native Unix socket lifecycle is qualified on Linux')
    def test_native_systemd_datagram_format(self):
        # Abstract systemd sockets avoid depending on the test-artifact root's
        # path length; the protocol also supports filesystem-addressed sockets.
        address='doxentriq-test-'+uuid.uuid4().hex
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as receiver:
            receiver.bind('\0'+address);receiver.settimeout(2)
            Q.notify_service('@'+address,'READY=1')
            self.assertEqual(receiver.recv(128),b'READY=1')

    @unittest.skipUnless(os.name=='posix' and hasattr(socket,'AF_UNIX'),'Native Unix socket lifecycle is qualified on Linux')
    def test_close_drains_existing_request_and_rebind_keeps_directory_inode(self):
        with tempfile.TemporaryDirectory(prefix='doxentriq-quota-startup-') as temp, working_directory(temp):
            directory=Path(temp);path=directory/'quota.sock';before=directory.stat().st_ino
            entered=threading.Event();release=threading.Event();closed=threading.Event()
            class Handler(socketserver.BaseRequestHandler):
                def handle(self):entered.set();release.wait(5)
            server=Q.Server('quota.sock',Handler)
            client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.connect('quota.sock')
            server.handle_request();self.assertTrue(entered.wait(2))
            closer=threading.Thread(target=lambda:(server.server_close(),closed.set()))
            closer.start();self.assertFalse(closed.wait(.05))
            release.set();closer.join(2);client.close();self.assertTrue(closed.is_set())
            # A closed listener leaves a stale socket in the retained directory;
            # native privileged stale_socket permission checks have their own tests.
            path.unlink()
            with Q.Server('quota.sock',Handler):self.assertEqual(directory.stat().st_ino,before)
            path.unlink()

    def test_production_unit_waits_for_notification_and_preserves_mount_directory(self):
        unit=B.quota_service_unit('/srv/doxentriq','/opt/doxentriq')
        for line in ('Type=notify','NotifyAccess=main','RuntimeDirectoryPreserve=yes',
                     'RequiresMountsFor=/srv/doxentriq','Before=docker.service autosoft.service',
                     'ExecStartPre=/bin/bash /opt/doxentriq/scripts/storage-guard.sh',
                     'ExecStart=/usr/bin/python3 -I -B /opt/doxentriq/scripts/quota-helper.py',
                     'KillMode=mixed','SendSIGKILL=no','RestrictAddressFamilies=AF_UNIX'):
            self.assertIn(line+'\n',unit)
        for invalid in ('/', '/srv/../tmp', '/srv//data', '/srv/%n', '/srv/data\nAfter=evil', '/srv/data with space', 'relative'):
            with self.assertRaises(ValueError):B.quota_service_unit(invalid,'/opt/doxentriq')

    def test_full_unit_wiring_preserves_existing_encrypted_guard(self):
        tree=ast.parse((HERE/'bootstrap.py').read_bytes())
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='systemd')
        calls=[node for node in ast.walk(function) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='write']
        text=ast.unparse(function)
        self.assertNotIn('docker.service.d/autosoft-storage.conf',text)
        self.assertIn('docker.service.d/autosoft-quota.conf',text)
        self.assertIn('Requires=autosoft-quota.service {builds_mount}\\nAfter=autosoft-quota.service {builds_mount}',text)
        self.assertTrue(calls)
        source=(HERE/'quota-helper.py').read_text()
        self.assertLess(source.index('verify_startup(DATA,'),source.index('path=directory/\'quota.sock\''))
        self.assertFalse(Q.Server.daemon_threads)
        self.assertTrue(Q.Server.block_on_close)

    def test_full_generated_docker_dependency_orders_both_quota_and_bounded_build_mount(self):
        class SyntheticConfig:
            def read_text(self):return '{"timezone":"UTC"}'
        class SyntheticData:
            def __str__(self):return '/srv/doxentriq'
            def __truediv__(self,name):
                return SyntheticConfig() if name=='config/installation.json' else Path('/srv/doxentriq')/name
        captured={};mount='srv-doxentriq-runtime-builds.mount'
        with patch.object(B.subprocess,'check_output',return_value=mount+'\n'), patch.object(B,'write',side_effect=lambda path,value,*args:captured.__setitem__(str(path).replace('\\','/'),value)):
            B.systemd(SyntheticData(),'/opt/doxentriq')
        dropin=captured['/etc/systemd/system/docker.service.d/autosoft-quota.conf']
        self.assertIn('Requires=autosoft-quota.service '+mount+'\n',dropin)
        self.assertIn('After=autosoft-quota.service '+mount+'\n',dropin)
        mounted=captured['/etc/systemd/system/'+mount]
        self.assertIn('Where=/srv/doxentriq/runtime/builds\n',mounted)
        self.assertIn('Type=tmpfs\n',mounted)
        self.assertIn('size=2G,mode=0700,uid=10001,gid=10001,nosuid,nodev',mounted)
        self.assertNotIn('/etc/systemd/system/docker.service.d/autosoft-storage.conf',captured)


if __name__=='__main__':unittest.main(verbosity=2)
