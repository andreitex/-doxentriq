"""Actual installed OpenSSL with inherited, exclusive native file descriptors.

Socket/Docker/bcrypt behavior is not exercised. The test-only subclass overrides
those preflight checks while retaining original transport, grammar and file IO.
"""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
F=load('render_filesystem_fixture','tests/test_company_render_io_native.py')
C=F.C


class ActualOpenSSL(C.NativeCommands):
    def __init__(self,io):super().__init__(io,'a'*32)
    def preflight(self):self._tool('openssl');self._check()
    def _check(self):
        C.require(not self.failed);self.io.check()
        for name,(fd,before) in self.tools.items():
            C.require(name=='openssl' and C.ident(os.fstat(fd))==before
                and C.ident(os.stat(C.TOOLS[name],follow_symlinks=False))==before)


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux root and installed OpenSSL required')
class OpenSSL(unittest.TestCase):
    def setUp(self):
        self.fixture=F.Native('test_missing_image_refuses_before_outputs');self.fixture.setUp()
        self.io=self.fixture.open(process_factory=ActualOpenSSL);self.process=self.io.process
    def tearDown(self):self.fixture.tearDown()
    def call(self,args):return self.process.run(['openssl',*args],check=True,capture_output=True,text=True).stdout
    def ca(self):
        d=self.io.root;self.call(['req','-x509','-newkey','rsa:4096','-nodes','-days','3650','-subj','/CN=Doxentriq Installation CA',
            '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
            '-keyout',d+'/tls/ca.key','-out',d+'/tls/ca.crt'])
        self.call(['verify','-x509_strict','-CAfile',d+'/tls/ca.crt',d+'/tls/ca.crt'])
    def test_actual_ca_issuer_fd_signing_and_public_key_match(self):
        self.ca();d=self.io.root
        self.io.write(self.io.data/'tls/app-issuer.cnf','basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        self.call(['req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=Autosoft Application Issuer',
            '-keyout',d+'/secrets/runtime/app-issuer.key','-out',d+'/tls/app-issuer.csr'])
        self.call(['x509','-req','-in',d+'/tls/app-issuer.csr','-CA',d+'/tls/ca.crt','-CAkey',d+'/tls/ca.key',
            '-CAcreateserial','-days','1825','-extfile',d+'/tls/app-issuer.cnf','-out',d+'/secrets/runtime/app-issuer.crt'])
        self.assertFalse((self.fixture.base/'tls/ca.srl').exists())
        self.call(['verify','-x509_strict','-CAfile',d+'/tls/ca.crt',d+'/secrets/runtime/app-issuer.crt'])
        public=self.call(['pkey','-in',d+'/secrets/runtime/app-issuer.key','-pubout'])
        self.assertTrue(public.startswith('-----BEGIN PUBLIC KEY-----'))
        self.assertEqual(public,self.call(['x509','-in',d+'/secrets/runtime/app-issuer.crt','-pubkey','-noout']))
        self.assertFalse(self.io.pending);self.io.check()
    def test_actual_invalid_csr_preserves_partial_output_and_ca(self):
        self.ca();d=self.io.root;before=(self.fixture.base/'tls/ca.key').read_bytes()
        self.io.write(self.io.data/'tls/app-issuer.csr','synthetic invalid csr')
        self.io.write(self.io.data/'tls/app-issuer.cnf','basicConstraints=critical,CA:true,pathlen:0\n')
        with self.assertRaises(ValueError):
            self.call(['x509','-req','-in',d+'/tls/app-issuer.csr','-CA',d+'/tls/ca.crt','-CAkey',d+'/tls/ca.key',
                '-CAcreateserial','-days','1825','-extfile',d+'/tls/app-issuer.cnf','-out',d+'/secrets/runtime/app-issuer.crt'])
        self.assertEqual(before,(self.fixture.base/'tls/ca.key').read_bytes())
        self.assertTrue((self.fixture.base/'secrets/runtime/app-issuer.crt').exists())
        self.assertTrue(self.io.poisoned)
    def test_actual_certificate_wrong_hostname_refused(self):
        self.ca();d=self.io.root;directory=self.io.data/'tls/mysql';directory.mkdir()
        self.io.write(directory/'extensions.cnf','basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:wrong-host\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n')
        self.call(['req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=mysql','-keyout',d+'/tls/mysql/mysql.key','-out',d+'/tls/mysql/request.csr'])
        self.call(['x509','-req','-in',d+'/tls/mysql/request.csr','-CA',d+'/tls/ca.crt','-CAkey',d+'/tls/ca.key',
            '-CAcreateserial','-days','365','-extfile',d+'/tls/mysql/extensions.cnf','-out',d+'/tls/mysql/mysql.crt'])
        with self.assertRaises(ValueError):
            self.call(['verify','-x509_strict','-CAfile',d+'/tls/ca.crt','-purpose','sslserver','-verify_hostname','mysql',d+'/tls/mysql/mysql.crt'])
        self.io.check()
    def test_arbitrary_command_refused_before_execution(self):
        before=set(self.fixture.base.rglob('*'))
        with self.assertRaises(ValueError):self.process.run(['openssl','version'],check=True)
        self.assertEqual(before,set(self.fixture.base.rglob('*')))
    def test_selector_allocation_failure_reaps_owned_child_and_closes_pipes(self):
        real=C.subprocess.Popen;children=[]
        def spawn(*args,**kwargs):
            child=real(*args,**kwargs);children.append(child);return child
        with patch.object(C.subprocess,'Popen',spawn),patch.object(C.selectors,'DefaultSelector',side_effect=OSError('synthetic selector allocation failure')):
            with self.assertRaises(OSError):self.process._execute('openssl',['version'])
        self.assertEqual(len(children),1);child=children[0]
        self.assertIsNotNone(child.poll())
        self.assertTrue(all(stream.closed for stream in (child.stdin,child.stdout,child.stderr)))
        self.assertTrue(self.process.failed)
        # The failed transport must refuse closure success while still releasing
        # every descriptor; the fixture removes no real host state.
        with self.assertRaises(ValueError):self.io.close(check=False)


if __name__=='__main__':unittest.main(verbosity=2)
