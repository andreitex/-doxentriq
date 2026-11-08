"""Actual private package and entry assembly; no installed authority or effects."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value);return value
B=load('infrastructure_package_builder_test','deploy/installer/build-native-retention-package.py')
H=load('infrastructure_profile_test','deploy/installer/company_host_tool_profiles.py')

@contextmanager
def clean_modules():
    before=set(sys.modules)
    try:yield
    finally:
        for name in set(sys.modules)-before:sys.modules.pop(name,None)

def fixture():
    return dict(schemaVersion=1,scope='COMPANY_HOST_TOOL_PROFILES',profiles=[dict(platform=dict(osId='rocky',versionId='10.2',architecture='x86_64'),
        qualificationReportSha256='d'*64,tools={name:dict(path=H.PATHS[name][0],bytes=1024,sha256=H.digest(('synthetic '+name).encode()),
            package=dict(name=package,version='5.7.0-1.synthetic',architecture='x86_64',archiveSha256='a'*64,repositoryMetadataSha256='b'*64))
            for name,package in H.PACKAGES.items()})])

class Package(unittest.TestCase):
    def package(self,catalog=None):
        with clean_modules():
            return B.assemble(ROOT,'a'*64,reader=lambda path,limit:path.read_bytes(),host_tool_catalog=catalog)

    def test_real_package_has_all_finite_components_and_keeps_catalog_refusal(self):
        with clean_modules():
            raw=self.package();worker=type(sys)('private_package_test');exec(compile(raw,'<private worker>','exec'),worker.__dict__)
            modules,delivery,auth=worker.load_package()
            self.assertEqual(set(modules),set(B.PROGRAMS));self.assertLess(len(raw),B.MAX_WORKER)
            with self.assertRaises(ValueError):worker.host_tool_binding(modules,dict(osId='rocky',versionId='10.2',architecture='x86_64'))
            self.assertEqual(modules['infrastructure_worker'].STAGE,'company-private-infrastructure')

    def test_companion_embeds_original_retention_loop_and_five_stage_tail(self):
        entry=B.assemble_entry(ROOT,b'# synthetic worker\n',reader=lambda path,limit:path.read_bytes(),infrastructure=True)
        text=entry.decode();self.assertEqual(text.count('install_lock_complete "$session"'),1)
        self.assertLess(text.index('verify-render --request'),text.index('initialize-private-infrastructure --request'))
        self.assertLess(text.index('verify-private-infrastructure --request'),text.index('install_lock_complete "$session"'))
        self.assertIn('infrastructure-ready --request',text);self.assertLess(len(entry),32768)
        result=subprocess.run(['/bin/bash','--noprofile','--norc','-n'],input=entry,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_entry_flags_cannot_ambiguously_select_successor(self):
        with self.assertRaises(ValueError):B.assemble_entry(ROOT,b'fixture',reader=lambda path,limit:path.read_bytes(),render=True,infrastructure=True)

    def test_actual_emitted_worker_binds_catalog_to_exact_host_and_transport(self):
        catalog=H.canonical(fixture())
        with clean_modules():
            raw=self.package(catalog);worker=type(sys)('private_catalog_worker_test');exec(compile(raw,'<private worker>','exec'),worker.__dict__)
            modules,_,_=worker.load_package();observed=fixture()['profiles'][0]['platform']
            binding=worker.host_tool_binding(modules,observed)
            self.assertEqual(binding['catalogSha256'],H.digest(catalog))
            self.assertEqual(modules['infrastructure_policy'].tool_pins(binding),modules['host_tool_profiles'].transport_pins(binding))
            with self.assertRaises(ValueError):worker.host_tool_binding(modules,dict(observed,versionId='10.1'))


    def test_initialization_entry_keeps_separate_identity_readback_before_completion(self):
        worker=self.package()
        prepare=B.assemble_entry(ROOT,worker,reader=lambda path,limit:path.read_bytes(),preparation=True)
        entry=B.assemble_entry(ROOT,worker,reader=lambda path,limit:path.read_bytes(),initialization=True)
        text=entry.decode();self.assertLess(len(entry),32768)
        self.assertIn(__import__('hashlib').sha256(worker).hexdigest().encode(),prepare)
        self.assertIn(__import__('hashlib').sha256(worker).hexdigest().encode(),entry)
        self.assertLess(text.index('verify-private-infrastructure --request'),text.index('provision-initial-identity --request'))
        self.assertLess(text.index('provision-initial-identity --request'),text.index('verify-initial-identity --request'))
        self.assertLess(text.index('verify-initial-identity --request'),text.index('install_lock_complete "$session"'))
        self.assertEqual(text.count('install_lock_complete "$session"'),1)
        self.assertNotIn('installation.complete',text)
        result=subprocess.run(['/bin/bash','--noprofile','--norc','-n'],input=entry,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        for flag in ('preparation','infrastructure','render','continuation'):
            with self.assertRaises(ValueError):B.assemble_entry(ROOT,worker,reader=lambda p,n:p.read_bytes(),initialization=True,**{flag:True})

    def test_initialization_uses_current_schema2_engine_binding_without_legacy_projection(self):
        F=load('initialization_engine_fixture','tests/test_company_engine_native.py');f=F.fixture()
        with clean_modules():
            raw=B.assemble(ROOT,'a'*64,reader=lambda path,n:path.read_bytes(),engine_catalog=f.raw)
            worker=type(sys)('initialization_engine_package');exec(compile(raw,'<private worker>','exec'),worker.__dict__)
            modules,_,_=worker.load_package();binding=worker.host_tool_binding(modules,f.platform)
            context=modules['infrastructure_policy'].tool_context(binding)
            self.assertEqual(context['scope'],'COMPANY_ENGINE_TOOL_BINDING_V2_ONLY')
            self.assertEqual(context['sourceManifestSha256'],f.value['profiles'][0]['sourceManifestSha256'])
            self.assertEqual(set(modules['infrastructure_policy'].tool_pins(binding)),{'docker','compose'})
            self.assertEqual(modules['identity_worker'].STAGE,'company-initial-identity')
            with self.assertRaises(ValueError):worker.host_tool_binding(modules,dict(f.platform,versionId='10.1'))

if __name__=='__main__':unittest.main(verbosity=2)
