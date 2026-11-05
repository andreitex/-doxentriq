import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('public_export',Path(__file__).with_name('public-release-export.py'))
exporter=importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'source'
        self.root.mkdir()
        self.output=Path(self.temp.name)/'output'

    def tearDown(self):
        self.temp.cleanup()

    def add(self,name,text):
        path=self.root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(text,encoding='utf-8')

    def test_explicit_source_roots_and_no_private_artifacts(self):
        self.add('README.md','# Example\n[receipt](deploy/verification/private.json)\n')
        self.add('apps/example.ts','export const value=1;')
        self.add('tests/example.test.ts','test("example",()=>{});')
        self.add('tests/fixtures/source.py','def fixture(): return True\n')
        self.add('templates/example/schema.sql','CREATE TABLE example(id INT);')
        self.add('deploy/verification/private.json','private installation data')
        self.add('customer-records.csv','private customer data')
        self.add('scripts/start-trial-access.ps1','private launcher')
        result=exporter.export(self.root,self.output)
        self.assertEqual(result['publicSourceCheck']['findingCounts'],{'license_missing':1})
        self.assertFalse((self.output/'deploy/verification').exists())
        self.assertFalse((self.output/'customer-records.csv').exists())
        self.assertFalse((self.output/'scripts/start-trial-access.ps1').exists())
        self.assertEqual((self.output/'tests/example.test.ts').read_bytes(),(self.root/'tests/example.test.ts').read_bytes())
        self.assertEqual((self.output/'tests/fixtures/source.py').read_bytes(),(self.root/'tests/fixtures/source.py').read_bytes())
        self.assertEqual((self.output/'templates/example/schema.sql').read_bytes(),(self.root/'templates/example/schema.sql').read_bytes())
        self.assertEqual(result['brokenDocumentationLinks'],[])
        self.assertNotIn('private installation data',(self.output/'PUBLIC-SOURCE.json').read_text())

    def test_original_source_and_existing_export_are_preserved(self):
        self.add('README.md','# Original')
        exporter.export(self.root,self.output)
        before=(self.output/'PUBLIC-SOURCE.json').read_bytes()
        with self.assertRaises(ValueError):exporter.export(self.root,self.output)
        self.assertEqual(before,(self.output/'PUBLIC-SOURCE.json').read_bytes())
        self.assertEqual((self.root/'README.md').read_text(),'# Original')

    def test_license_is_not_generated(self):
        self.add('README.md','# Example')
        result=exporter.export(self.root,self.output)
        self.assertFalse(result['licenseSelected'])
        self.assertFalse((self.output/'LICENSE').exists())

    def test_missing_links_are_reported(self):
        self.add('README.md','[Missing](docs/not-present.md)')
        result=exporter.export(self.root,self.output)
        self.assertEqual(result['brokenDocumentationLinks'],[{'path':'README.md','target':'docs/not-present.md'}])

    def test_link_parent_traversal_is_rejected(self):
        self.add('README.md','[Outside](../outside.md)')
        with self.assertRaises(ValueError):exporter.export(self.root,self.output)
        self.assertFalse(self.output.exists())

    def test_secret_is_reported_without_disclosing_it(self):
        secret='sk-'+'proj-'+'D'*40
        self.add('apps/unsafe.ts',secret)
        result=exporter.export(self.root,self.output)
        self.assertIn('provider_credential',result['publicSourceCheck']['findingCounts'])
        self.assertNotIn(secret,json.dumps(result))

    def test_historical_carrier_defaults_become_inert(self):
        name='scripts/company_seed_backend_native_client_v1.py'
        text="from pathlib import Path\nROOT=Path('/private/station')\nSESSION='private-session'\nHOSTKEY='private-host-key'\ndef dispatch_once(folder):\n return folder\n"
        self.add(name,text)
        result=exporter.export(self.root,self.output)
        public=(self.output/name).read_text()
        self.assertNotIn('private-session',public)
        self.assertNotIn('private-host-key',public)
        self.assertIn('need(bool(SESSION) and bool(HOSTKEY))',public)
        self.assertEqual((self.root/name).read_text(),text)
        self.assertTrue(result['files'][0]['transformations'])

    def test_symlink_is_not_followed(self):
        self.add('apps/safe.ts','safe')
        try:(self.root/'apps/link.ts').symlink_to(self.root/'apps/safe.ts')
        except OSError:self.skipTest('Host cannot create symlinks')
        with self.assertRaises(ValueError):exporter.export(self.root,self.output)
        self.assertFalse(self.output.exists())



if __name__=='__main__':unittest.main()
