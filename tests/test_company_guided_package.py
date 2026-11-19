"""Real producer composition, with synthetic catalogs; no installation effects."""
from contextlib import contextmanager
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',str(ROOT)))

def source(relative):
    candidate=ROOT/relative
    return candidate if candidate.is_file()else BASE/relative

def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,source(relative));m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m

B=load('guided_builder_test','deploy/installer/build-guided-private-package.py')
C=load('guided_engine_catalog','deploy/installer/company_engine_packages.py')
reader=lambda path,maximum:source(Path(path).relative_to(ROOT)).read_bytes()

def catalog():
    packages=[]
    for role in C.ROLES:
        row=dict(role=role,name=C.NAMES[role],version='29.9.3-1.doxentriq.1.el10',architecture='x86_64',
            filename=C.NAMES[role]+'.rpm',bytes=16384,sha256='c'*64,
            executables=[dict(path=path,bytes=1024,sha256='d'*64,mode=0o755)for path in C.EXECUTABLES[role]])
        row.update({name:'e'*64 for name in C.EVIDENCE});packages.append(row)
    return C.canonical(dict(schemaVersion=2,scope='COMPANY_HOST_PACKAGE_CATALOG',profiles=[dict(
        platform=dict(osId='rocky',versionId='10.2',architecture='x86_64'),origin='doxentriq',releaseId='doxentriq-engine-20261106.1',
        qualificationReportSha256='a'*64,sourceManifestSha256='b'*64,distributionMetadataSha256='c'*64,
        packageSigningKey=dict(filename='doxentriq-engine.asc',bytes=1024,sha256='f'*64,fingerprint='A1'*20),packages=packages)]))

@contextmanager
def clean_modules():
    before=set(sys.modules)
    try:yield
    finally:
        for name in set(sys.modules)-before:sys.modules.pop(name,None)

class Package(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with clean_modules():cls.records=B.assemble(ROOT,'a'*64,reader=reader,host_catalogs={'engine':catalog()})

    def test_actual_producers_emit_original_children_and_common_native_worker(self):
        self.assertEqual(set(self.records),{'company-install.sh','company_install.py','company-native-retention.py','company-prepare.sh','company-private-quota.sh','company-guided-private.sh','installation-status.py'})
        foundation_hash=hashlib.sha256(self.records['company_install.py']).hexdigest().encode()
        native_hash=hashlib.sha256(self.records['company-native-retention.py']).hexdigest().encode()
        self.assertIn(foundation_hash,self.records['company-install.sh'])
        self.assertIn(native_hash,self.records['company-prepare.sh']);self.assertIn(native_hash,self.records['company-private-quota.sh'])
        self.assertIn(b'full_install_pending_signed_source_and_native_pair',self.records['company-install.sh'])
        self.assertIn(b'--recover-private-quota',self.records['company-private-quota.sh'])
        assignments={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(self.records['company-native-retention.py']).body
            if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PACKAGE','HOST_ENGINE_CATALOG')}
        captured=base64.b64decode(assignments['HOST_ENGINE_CATALOG']['base64'],validate=True)
        self.assertEqual(captured,catalog());C.decode(captured,expected_catalog_sha256=C.sha(captured))
        quota=assignments['PACKAGE']['programs']['quota_worker']
        self.assertEqual(base64.b64decode(quota['base64']),source('deploy/installer/company_quota_worker.py').read_bytes())

    def test_entry_binds_every_exact_emitted_file_and_status_source(self):
        entry=self.records['company-guided-private.sh']
        for name,raw in self.records.items():
            if name=='company-guided-private.sh':continue
            line=('  _gp_file '+name+' '+hashlib.sha256(raw).hexdigest()+' '+str(len(raw))).encode()
            self.assertIn(line,entry)
        self.assertEqual(self.records['installation-status.py'],source('scripts/installation-status.py').read_bytes())
        self.assertNotIn(b'@GUIDED_',entry)
        self.assertLessEqual(len(entry),B.MAX_GUIDED_ENTRY)

    def test_missing_or_mixed_catalogs_refuse_before_assembly(self):
        for catalogs in(None,{},dict(engine=catalog(),tools=b'{}')):
            with self.subTest(catalogs=bool(catalogs)),self.assertRaisesRegex(ValueError,'qualified-host-catalogs-required'):
                B.assemble(ROOT,'a'*64,reader=reader,host_catalogs=catalogs)

    def test_changed_source_during_real_assembly_refuses(self):
        counts={}
        def changed(path,maximum):
            raw=reader(path,maximum);counts[str(path)]=counts.get(str(path),0)+1
            if path.name=='company-guided-private.sh'and counts[str(path)]>1:return raw+b'\n'
            return raw
        with clean_modules(),self.assertRaisesRegex(ValueError,'company-source-changed-during-assembly'):
            B.assemble(ROOT,'a'*64,reader=changed,host_catalogs={'engine':catalog()})

    def test_component_set_cannot_add_a_command_or_omit_status(self):
        components={k:v for k,v in self.records.items()if k!='company-guided-private.sh'}
        bad=dict(components);bad.pop('installation-status.py')
        for value in(bad,dict(components,extra=b'echo unsafe')):
            with self.assertRaisesRegex(ValueError,'exact-guided-components-required'):B.entry(ROOT,value,reader=reader)

if __name__=='__main__':unittest.main(verbosity=2)
