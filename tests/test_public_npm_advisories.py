"""Public advisory privacy and failure controls. No network access."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('public_advisories',Path(__file__).resolve().parents[1]/'scripts/public-npm-advisories.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class Response:
    status=200
    def __init__(self,value,headers=None,url=M.ENDPOINT):
        self.raw=json.dumps(value).encode();self.headers=headers or {};self.url=url
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def geturl(self):return self.url
    def read(self,maximum):return self.raw[:maximum]


class Opener:
    def __init__(self,response):self.response=response;self.requests=[]
    def open(self,request,timeout):self.requests.append((request,timeout));return self.response


class Tests(unittest.TestCase):
    def fixture(self):
        row=dict(version='1.2.3',resolved='https://registry.npmjs.org/react/-/react-1.2.3.tgz',integrity='sha512-'+'a'*86+'==')
        return dict(lockfileVersion=3,name='private-customer-project',packages={'':{'name':'private-customer-project'},'node_modules/react':row,'node_modules/@private/internal':{'link':True,'resolved':'packages/private-internal'},'packages/private-internal':{'name':'@private/internal','version':'0.1.0'}}),dict(schemaVersion=2,publicPackages=['react'],localWorkspaces=[{'path':'packages/private-internal','name':'@private/internal'}])
    def advisory(self,severity='moderate'):
        return dict(name='react',id=123,url='https://github.com/advisories/GHSA-synthetic',title='Synthetic advisory',vulnerable_versions='<2',severity=severity)
    def test_exact_public_payload_contains_no_root_workspace_paths_or_private_names(self):
        lock,catalog=self.fixture(); selected,excluded=M.payload(lock,catalog)
        self.assertEqual(selected,{'react':['1.2.3']});self.assertEqual(excluded,3)
        self.assertNotIn('private',json.dumps(selected))
    def test_unreviewed_package_cannot_be_sent_even_if_resolution_uses_public_registry(self):
        lock,catalog=self.fixture();lock['packages']['node_modules/private-company-name']=lock['packages'].pop('node_modules/react')
        with self.assertRaises(ValueError):M.payload(lock,catalog)
    def test_foreign_encoded_or_credential_bearing_resolution_and_unpinned_integrity_refused(self):
        for changes in [dict(resolved='https://private.example/react.tgz'),dict(resolved='https://user:secret@registry.npmjs.org/react/-/react-1.2.3.tgz'),dict(resolved='https://registry.npmjs.org/other/-/other-1.2.3.tgz'),dict(resolved='https://registry.npmjs.org/react/-/react-1.2.3.tgz?token=private'),dict(integrity='sha1-weak'),dict(version='file:private')]:
            lock,catalog=self.fixture();lock['packages']['node_modules/react'].update(changes)
            with self.assertRaises(ValueError):M.payload(lock,catalog)
    def test_multiple_versions_are_deduplicated_without_parent_graph(self):
        lock,catalog=self.fixture();lock['packages']['node_modules/parent/node_modules/react']=deepcopy(lock['packages']['node_modules/react'])
        self.assertEqual(M.payload(lock,catalog)[0],{'react':['1.2.3']})
    def test_external_private_or_forged_workspace_markers_cannot_bypass_scanning(self):
        for changes in [dict(private=True),dict(link=True),dict(link=True,resolved='../private'),dict(link=True,resolved='https://private.example')]:
            lock,catalog=self.fixture();lock['packages']['node_modules/react'].update(changes)
            with self.assertRaises(ValueError):M.payload(lock,catalog)
    def test_fixed_bulk_endpoint_and_only_names_versions_with_no_auth_or_cli_metadata(self):
        opener=Opener(Response({}));M.query({'react':['1.2.3']},opener)
        self.assertEqual(len(opener.requests),1);request,timeout=opener.requests[0]
        self.assertEqual(request.full_url,M.ENDPOINT);self.assertEqual(request.method,'POST');self.assertEqual(timeout,30)
        self.assertEqual(json.loads(request.data),{'react':['1.2.3']});self.assertNotIn('Authorization',request.headers)
    def test_medium_high_critical_block_but_low_is_not_actionable(self):
        for severity,expected in [('moderate','medium'),('high','high'),('critical','critical')]:
            result=M.query({'react':['1.2.3']},Opener(Response({'react':[self.advisory(severity)]})))
            self.assertEqual(result['status'],'blocked');self.assertEqual(result['findings'][0]['severity'],expected)
        low=M.query({'react':['1.2.3']},Opener(Response({'react':[self.advisory('low')]})))
        self.assertEqual(low['findings'],[]);self.assertEqual(low['lowAdvisoriesIgnored'],1)
    def test_malformed_unknown_severity_foreign_scope_or_missing_evidence_cannot_pass(self):
        for value in [[],{'private':[]},{'react':{}},{'react':[self.advisory('unknown')]},{'react':[{'name':'react','severity':'high'}]},{'react':[{**self.advisory(),'name':'foreign'}]},{'react':[{**self.advisory(),'url':'javascript:unsafe'}]}]:
            with self.assertRaises(ValueError):M.query({'react':['1.2.3']},Opener(Response(value)))
    def test_grouped_advisories_without_redundant_name_are_classified_and_block(self):
        for severity,expected in [('moderate','medium'),('high','high'),('critical','critical')]:
            item=self.advisory(severity);del item['name']
            item.update(cvss={'score':7.5},cwe=['CWE-400'])
            result=M.query({'react':['1.2.3']},Opener(Response({'react':[item]})))
            self.assertEqual(result['status'],'blocked')
            self.assertEqual(result['findings'][0]['name'],'react')
            self.assertEqual(result['findings'][0]['severity'],expected)
            self.assertEqual(result['findings'][0]['id'],123)
        item=self.advisory('low');del item['name']
        result=M.query({'react':['1.2.3']},Opener(Response({'react':[item]})))
        self.assertEqual(result['findings'],[]);self.assertEqual(result['lowAdvisoriesIgnored'],1)
    def test_grouped_identity_cannot_override_conflicting_or_malformed_inner_name(self):
        for inner in ('foreign','',None,123,False,[],{}):
            with self.subTest(inner=inner):
                item={**self.advisory(),'name':inner}
                with self.assertRaises(ValueError):M.query({'react':['1.2.3']},Opener(Response({'react':[item]})))
        item=self.advisory();del item['name']
        with self.assertRaises(ValueError):M.query({'react':['1.2.3']},Opener(Response({'unreviewed':[item]})))
    def test_redirect_compression_and_incomplete_or_oversized_body_refused(self):
        for response in [Response({},url='https://evil.example'),Response({},headers={'Content-Encoding':'gzip'}),Response({},headers={'Content-Length':'8388609'}),Response({},headers={'Content-Length':'bad'}),Response({},headers={'Content-Length':'3'})]:
            with self.assertRaises(ValueError):M.query({'react':['1.2.3']},Opener(response))
        with self.assertRaises(ValueError):M.NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_workspace_identity_is_company_reviewed_and_cannot_hide_an_external_dependency(self):
        for mutation in ['missing_target','missing_link','foreign_link','external_target','unreviewed_workspace','duplicate_workspace']:
            lock,catalog=self.fixture()
            if mutation=='missing_target':del lock['packages']['packages/private-internal']
            elif mutation=='missing_link':del lock['packages']['node_modules/@private/internal']
            elif mutation=='foreign_link':lock['packages']['node_modules/@private/internal']['resolved']='packages/another'
            elif mutation=='external_target':lock['packages']['packages/private-internal']['resolved']='https://private.example/private.tgz'
            elif mutation=='unreviewed_workspace':catalog['localWorkspaces']=[]
            else:catalog['localWorkspaces']*=2
            with self.assertRaises(ValueError):M.payload(lock,catalog)
    def test_real_platform_workspace_is_excluded_without_exposing_its_identity(self):
        root=Path(__file__).resolve().parents[1]
        selected,excluded=M.payload(json.loads((root/'package-lock.json').read_text()),json.loads((root/'models/platform-reviewed-public-npm.json').read_text()))
        self.assertEqual(len(selected),279);self.assertEqual(excluded,3)
        self.assertNotIn('autosoft',json.dumps(selected));self.assertNotIn('packages/core',json.dumps(selected))
    def test_v1_catalog_cannot_silently_exclude_workspace_links(self):
        lock,catalog=self.fixture();catalog=dict(schemaVersion=1,publicPackages=['react'])
        with self.assertRaises(ValueError):M.payload(lock,catalog)
    def test_real_dms_lock_matches_reviewed_public_inventory(self):
        root=Path(__file__).resolve().parents[1]
        selected,excluded=M.payload(json.loads((root/'templates/dms/package-lock.json').read_text()),json.loads((root/'models/dms-reviewed-public-npm.json').read_text()))
        self.assertEqual(len(selected),85);self.assertEqual(excluded,1);self.assertFalse(any(name.startswith('@autosoft/') for name in selected))


if __name__=='__main__':unittest.main()
