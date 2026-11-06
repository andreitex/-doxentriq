"""Synthetic Docker responses test the original fixed transport decisions."""
import importlib.util
import json
import stat
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('render_commands',ROOT/'deploy/installer/company_render_commands.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)


class Simulated(C.NativeCommands):
    def __init__(self,*,volumes=False,fail_start=False,foreign_mount=False):
        self.name='doxentriq-render-'+'a'*32;self.image='caddy@sha256:'+'b'*64;self.image_id='sha256:'+'c'*64
        self.identifier='d'*64;self.container=None;self.failed=False;self.tools={};self.selinux=False
        self.calls=[];self.labels=[];self.started=False;self.fail_start=fail_start;self.foreign_mount=foreign_mount
        self.io=SimpleNamespace(root='/protected/data',readonly=False,caddy_label=lambda *args,**kwargs:self.labels.append((args,kwargs)))
        self.tmpfs={n:'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700' for n in ('/data','/config')} if volumes else {}
    def _docker(self,args):
        self.calls.append(args)
        if args[:2]==['container','create']:return (self.identifier+'\n').encode()
        if args[:2]==['container','inspect']:
            row=dict(Id=self.identifier,Name='/'+self.name,Image=self.image_id,
                Config=dict(Image=self.image,User='10001:10001',Cmd=['caddy','adapt','--config','/etc/caddy/Caddyfile'],Labels={'com.doxentriq.render':self.name}),
                HostConfig=dict(Privileged=False,ReadonlyRootfs=True,NetworkMode='none',Memory=134217728,PidsLimit=64,
                    CapDrop=['ALL'],CapAdd=['NET_BIND_SERVICE'],SecurityOpt=['no-new-privileges'],Tmpfs=self.tmpfs,
                    Binds=['/protected/data/config/Caddyfile:/etc/caddy/Caddyfile:ro'],PortBindings={},LogConfig={'Type':'none'},RestartPolicy={'Name':'no'}),
                State=dict(Status='exited' if self.started else 'created',ExitCode=0,Pid=0,OOMKilled=False,Error=''),
                Mounts=[dict(Type='bind',Source='/protected/data/config/Caddyfile',Destination='/etc/caddy/Caddyfile',RW=False)])
            if self.foreign_mount:row['Mounts'].append(dict(Type='volume',Source='/foreign',Destination='/data',RW=True))
            return json.dumps([row]).encode()
        if args[:2]==['container','start']:
            if self.fail_start:raise TimeoutError('synthetic unknown client outcome')
            self.started=True;return b'{"apps":{"http":{"servers":{"srv0":{"routes":[]}}}}}'
        if args[:2]==['container','rm']:return (self.identifier+'\n').encode()
        if args==['container','ls','--all','--quiet']:return b''
        raise AssertionError(args)
    def original(self):
        return ['docker','run','--rm','--network=none','--read-only','--user=10001:10001','--cap-drop=ALL',
            '--cap-add=NET_BIND_SERVICE','--security-opt=no-new-privileges','--memory=128m','--pids-limit=64',
            '--volume','/protected/data/config/Caddyfile:/etc/caddy/Caddyfile:ro,z',self.image,'caddy','adapt','--config','/etc/caddy/Caddyfile']


class Commands(unittest.TestCase):
    def test_docker_hub_normalization_preserves_exact_registry_repository_and_digest(self):
        suffix='@sha256:'+'a'*64
        for name in ('caddy','library/caddy','docker.io/caddy','docker.io/library/caddy'):
            with self.subTest(name=name):
                self.assertTrue(C.pinned_reference_present('docker.io/library/caddy'+suffix,[name+suffix]))
        self.assertTrue(C.pinned_reference_present('docker.io/company/caddy'+suffix,['company/caddy'+suffix]))
        self.assertTrue(C.pinned_reference_present('localhost:5000/team/caddy'+suffix,['localhost:5000/team/caddy'+suffix]))
        for name in ('evil.example/library/caddy'+suffix,'ghcr.io/library/caddy'+suffix,
                'company/caddy'+suffix,'docker.io/library/other'+suffix,'caddy@sha256:'+'b'*64):
            with self.subTest(name=name):
                self.assertFalse(C.pinned_reference_present('docker.io/library/caddy'+suffix,[name]))
        for name in ('caddy:latest'+suffix,'docker.io//caddy'+suffix,'docker.io/../caddy'+suffix,'caddy:latest'):
            with self.subTest(name=name),self.assertRaises(ValueError):C.canonical_digest_reference(name)

    def test_preflight_accepts_normalized_digest_but_still_refuses_active_engine(self):
        class Preflight(C.NativeCommands):
            def __init__(self,*,active=False,reference=None):
                self.tools={};self.image='docker.io/library/caddy@sha256:'+'b'*64
                self.io=SimpleNamespace(readonly=False);self.calls=[];self.active=active
                self.reference=reference or 'caddy@sha256:'+'b'*64
            def _tool(self,name):self.tools[name]=None
            def _check(self):pass
            def _docker(self,args):
                self.calls.append(args)
                if args[:2]==['image','inspect']:
                    return json.dumps([dict(Id='sha256:'+'c'*64,Os='linux',Architecture='amd64',
                        RepoDigests=[self.reference],Config={'Entrypoint':None,'Volumes':None})]).encode()
                if args==['container','ls','--all','--quiet']:return b'owned-or-foreign\n' if self.active else b''
                raise AssertionError(args)
        socket=SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=0,
            st_nlink=1,st_size=0,st_mtime_ns=3,st_ctime_ns=3)
        with patch.object(C.os,'stat',return_value=socket),patch.object(C.os.path,'exists',return_value=False):
            c=Preflight();c.preflight();self.assertEqual(c.image_id,'sha256:'+'c'*64)
            c=Preflight(active=True)
            with self.assertRaisesRegex(ValueError,'inactive container engine'):c.preflight()
            c=Preflight(reference='evil.example/library/caddy@sha256:'+'b'*64)
            with self.assertRaises(ValueError):c.preflight()
            self.assertEqual(c.calls,[['image','inspect',c.image]])

    def test_no_pull_no_network_owned_container_confirmed_then_removed(self):
        c=Simulated();c.check_output(c.original(),text=True)
        create=c.calls[0]
        self.assertIn('--pull=never',create);self.assertIn('--network=none',create)
        self.assertNotIn('--rm',create);self.assertIn('/protected/data/config/Caddyfile:/etc/caddy/Caddyfile:ro',create)
        self.assertFalse(any(value.endswith(':ro,z') for value in create))
        self.assertEqual(c.labels,[((False,),{'mutate':True})])
        self.assertEqual([v[:2] for v in c.calls],[['container','create'],['container','inspect'],['container','start'],['container','inspect'],['container','rm'],['container','ls']])
        self.assertIsNone(c.container)
    def test_only_declared_writable_paths_receive_bounded_tmpfs(self):
        c=Simulated(volumes=True);c.check_output(c.original(),text=True);create=c.calls[0]
        self.assertEqual(create.count('--tmpfs'),2)
        for name,value in c.tmpfs.items():self.assertIn(name+':'+value,create)
    def test_unknown_start_preserves_container_and_never_retries_or_removes(self):
        c=Simulated(fail_start=True)
        with self.assertRaises(TimeoutError):c.check_output(c.original(),text=True)
        self.assertEqual(c.container,c.identifier)
        self.assertEqual(sum(call[:2]==['container','start'] for call in c.calls),1)
        self.assertFalse(any(call[:2]==['container','rm'] for call in c.calls))
        with self.assertRaises(ValueError):c.close()
    def test_unexpected_anonymous_mount_refuses_before_start(self):
        c=Simulated(foreign_mount=True)
        with self.assertRaises(ValueError):c.check_output(c.original(),text=True)
        self.assertFalse(any(call[:2] in (['container','start'],['container','rm']) for call in c.calls))
    def test_altered_image_or_mount_request_never_runs_docker(self):
        c=Simulated();args=c.original();args[12]='/foreign:/etc/caddy/Caddyfile:ro'
        with self.assertRaises(ValueError):c.check_output(args,text=True)
        self.assertEqual(c.calls,[])
    def test_close_failure_still_attempts_every_owned_tool(self):
        c=Simulated();c.tools={'a':(71,()),'b':(72,()),'c':(73,())};closed=[]
        def close(fd):
            closed.append(fd)
            if fd==71:raise OSError('synthetic close failure')
        with patch.object(C.os,'close',close):
            with self.assertRaises(OSError):c.close()
        self.assertEqual(closed,[71,72,73])


if __name__=='__main__':unittest.main(verbosity=2)
