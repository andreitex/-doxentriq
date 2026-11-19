"""Exact Source terminal filename through the real backend and original IO.

Portable cases use the existing RAM syscall fixture. Linux cases use actual
root-owned exclusive files, fsync, getdents and descriptor closure in an explicit
private test root. Neither form claims signed Store/Source stage qualification.
"""
import ctypes
import importlib.util
import os
from pathlib import Path
import platform
import stat
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('source_terminal_fixture',ROOT/'tests/test_company_seed_backend.py')
T=importlib.util.module_from_spec(spec);sys.modules[spec.name]=T;spec.loader.exec_module(T)
SB,BK,Source=T.SB,T.BK,T.Source
TERMINAL='bytes-verified.json'
RAW=b'{"fixture":"terminal-source-record"}\n'


def close_backend(backend):
    for fd in reversed(tuple(backend._fds)):
        if fd not in backend._attempted:backend.close(fd)
    backend.require_released()


def create_source(backend):
    """Original SourceFiles writes, inventories, seals and rechecks its output."""
    io=Source.SourceFiles(SB,backend,clock=time.monotonic)
    try:
        parent=io.hold(backend.source_parent,mode=0o700)
        root=io.create(parent,backend.request['releaseSha256'])
        io.create(root,'intent.json',b'{"fixture":"intent"}\n')
        source=io.create(root,'source')
        io.create(source,'example.txt',b'synthetic source bytes\n')
        io.inventory(source,['example.txt']);io.seal_directory(source)
        io.create(root,TERMINAL,RAW)
        io.inventory(root,[TERMINAL,'intent.json','source'])
        io.seal_directory(root);io.check(readback=True)
        return Path(root)
    finally:
        io.close();backend.require_released()


class SourceTerminalPortableTests(unittest.TestCase):
    def test_original_source_io_can_write_exact_terminal(self):
        ram=T.RAM();backend=ram.adapter(clock=time.monotonic)
        root=create_source(backend)
        self.assertEqual(ram.nodes[(root/TERMINAL).as_posix()]['raw'],RAW)
        self.assertNotIn((root/'verified.json').as_posix(),ram.nodes)
        self.assertFalse(ram.fds)

    def test_legacy_name_is_not_an_allowed_source_record(self):
        for method in ('read','write'):
            with self.subTest(method=method):
                ram=T.RAM();backend=ram.adapter(clock=time.monotonic)
                parent=backend.open(backend.source_parent,'directory')
                root=backend.mkdir(parent,backend.request['releaseSha256'],0,0,0o700)
                path=backend.source_root+'/verified.json'
                try:
                    with self.assertRaises(SB.SeedBackendUnavailable):
                        if method=='read':backend.open(path,'file')
                        else:backend.create(root,'verified.json',0,0,0o400)
                    self.assertNotIn(path,ram.nodes)
                finally:close_backend(backend)


NATIVE=sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0 and bool(os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT'))


@unittest.skipUnless(NATIVE,'requires Linux root and an explicit protected test root')
class SourceTerminalNativeTests(unittest.TestCase):
    def setUp(self):
        base=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])
        info=base.lstat()
        if not str(base).startswith('/srv/') or not base.is_absolute() or base.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('protected-native-test-root-required')
        self.temporary=tempfile.TemporaryDirectory(prefix='source-terminal-',dir=base)
        self.root=Path(self.temporary.name)
        self.request=T.request();self.request['dataDir']=str(self.root)
        (self.root/'company/source-releases').mkdir(parents=True,mode=0o700)
        (self.root/'company').chmod(0o700)
        self.before=set(os.listdir('/proc/self/fd'))

    def tearDown(self):
        self.assertEqual(set(os.listdir('/proc/self/fd')),self.before)
        # Only this test's already-resolved fresh child is removed.
        for path in self.root.rglob('*'):
            if path.is_dir():path.chmod(0o700)
        self.temporary.cleanup()

    def backend(self):
        dents=BK.LinuxAMD64Getdents64(ctypes_module=ctypes,libc=ctypes.CDLL(None,use_errno=True),
            sys_module=sys,machine_module=platform)
        return SB.SeedBackend(request_value=self.request,budget=T.budget(),os_module=os,
            sys_module=sys,read_backend_module=BK,getdents64=dents,clock=time.monotonic)

    def test_original_terminal_has_native_write_sync_seal_and_fresh_readback(self):
        root=create_source(self.backend())
        self.assertEqual((root/TERMINAL).read_bytes(),RAW)
        self.assertEqual(stat.S_IMODE((root/TERMINAL).stat().st_mode),0o400)
        self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o500)
        backend=self.backend();io=Source.SourceFiles(SB,backend,clock=time.monotonic)
        try:
            io.hold(str(root/TERMINAL),directory=False,mode=0o400,raw=RAW)
            io.check(readback=True)
        finally:io.close();backend.require_released()
        self.assertFalse((root/'verified.json').exists())

    def test_legacy_source_write_is_refused_without_file(self):
        backend=self.backend();parent=backend.open(backend.source_parent,'directory')
        root=backend.mkdir(parent,self.request['releaseSha256'],0,0,0o700)
        try:
            with self.assertRaises(SB.SeedBackendUnavailable):backend.create(root,'verified.json',0,0,0o400)
            self.assertFalse((Path(backend.source_root)/'verified.json').exists())
        finally:close_backend(backend)

    def test_preexisting_legacy_source_read_is_refused(self):
        root=self.root/'company/source-releases'/self.request['releaseSha256']
        root.mkdir(mode=0o700);legacy=root/'verified.json';legacy.write_bytes(RAW);legacy.chmod(0o400)
        backend=self.backend()
        try:
            with self.assertRaises(SB.SeedBackendUnavailable):backend.open(str(legacy),'file')
            self.assertEqual(legacy.read_bytes(),RAW)
        finally:close_backend(backend)


if __name__=='__main__':unittest.main(verbosity=2)
