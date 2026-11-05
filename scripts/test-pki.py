#!/usr/bin/env python3
"""Real company bootstrap PKI and legacy-profile rejection on an encrypted fixture."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('autosoft_bootstrap',ROOT/'bootstrap.py')
bootstrap=importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:-1)()==0,'Root Linux encrypted fixture required')
class BootstrapPKI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup=json.loads(Path('/etc/autosoft/installation.json').read_text())
        data=Path(setup['data_dir']).resolve()
        cls.temporary=tempfile.TemporaryDirectory(prefix='pki-fixture-',dir=data/'validation')
        cls.data=Path(cls.temporary.name)
        for name in ('tls','public-tls','secrets/runtime'):(cls.data/name).mkdir(parents=True,exist_ok=True)
        cls.config=dict(certificate_mode='selfsigned',admin_origin='https://admin.fixture.internal',apps_base_url='https://apps.fixture.internal',auth_origin='https://identity.fixture.internal')
        bootstrap.certificates(cls.data,cls.config)

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def test_complete_chain_and_idempotent_keys(self):
        keys={str(p.relative_to(self.data)):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.data.rglob('*.key')}
        bootstrap.certificates(self.data,self.config)
        self.assertEqual(keys,{str(p.relative_to(self.data)):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.data.rglob('*.key')})
        for service in ('mysql','redis','rabbitmq','keycloak','registry','control','broker','packager','prometheus','loki','grafana','otel'):
            self.assertEqual(subprocess.run(['openssl','verify','-x509_strict','-purpose','sslserver','-verify_hostname',service,'-CAfile',str(self.data/'tls/ca.crt'),str(self.data/f'tls/{service}/{service}.crt')],capture_output=True).returncode,0)

    def test_existing_wrong_service_identity_is_preserved_and_rejected(self):
        path=self.data/'tls/control/control.crt';original=path.read_bytes()
        wrong=(self.data/'tls/mysql/mysql.crt').read_bytes();path.write_bytes(wrong)
        try:
            with self.assertRaisesRegex(ValueError,'strict chain/identity'):bootstrap.certificates(self.data,self.config)
            self.assertEqual(path.read_bytes(),wrong)
        finally:path.write_bytes(original)

    def test_legacy_ca_missing_key_usage_is_preserved_and_rejected(self):
        with tempfile.TemporaryDirectory(prefix='legacy-',dir=self.data) as temporary:
            data=Path(temporary);(data/'tls').mkdir()
            key,crt=data/'tls/ca.key',data/'tls/ca.crt'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config','/dev/null','-subj','/CN=Legacy fixture CA','-addext','basicConstraints=critical,CA:TRUE','-keyout',str(key),'-out',str(crt)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            before=(key.read_bytes(),crt.read_bytes())
            with self.assertRaisesRegex(ValueError,'installation CA fails strict'):bootstrap.certificates(data,self.config)
            self.assertEqual(before,(key.read_bytes(),crt.read_bytes()))
            self.assertFalse((data/'secrets/runtime/app-issuer.key').exists())


if __name__=='__main__':unittest.main()
