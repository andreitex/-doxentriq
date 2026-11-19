"""Actual company producer and original request validators; no host effects."""
import base64
from contextlib import redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',str(ROOT)))


def source(relative):
    candidate=ROOT/relative
    return candidate if candidate.is_file() else BASE/relative


def load(name,relative):
    spec=importlib.util.spec_from_file_location(name,source(relative))
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


B=load('intake_actual_guided_producer','deploy/installer/build-guided-private-package.py')
I=load('intake_actual_template','deploy/installer/company_request_intake.py')
G=load('intake_original_catalog_fixture','tests/test_company_guided_package.py')
DER=bytes.fromhex('302a300506032b6570032100')+bytes(range(32))
PUBLIC=b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(DER)+b'\n-----END PUBLIC KEY-----\n'
FINGERPRINT=hashlib.sha256(DER).hexdigest()
DEFAULTS=I.canonical(dict(schemaVersion=1,scope='GUIDED_PRIVATE_REQUEST_DEFAULTS',
    foundation=dict(releaseSha256='a'*64,bundleRoot='/opt/autosoft-company/incoming/foundation/company-release',sourceRoot='/opt/autosoft-company/incoming/foundation'),
    platform=dict(releaseSha256='b'*64,bundleRoot='/opt/autosoft-company/incoming/platform/company-release',sourceRoot='/opt/autosoft-company/incoming/platform'),
    runscVersion='20261108.0',runscSha512='c'*128))
ANSWERS=dict(dataDir='/srv/doxentriq-data',backingFile='/var/lib/doxentriq.luks',capacityGiB=64)


def reader(path,maximum=131072):
    raw=source(Path(path).relative_to(ROOT)).read_bytes()
    assert 0<len(raw)<=maximum
    return raw


class RequestIntake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with G.clean_modules():
            cls.records=B.assemble(ROOT,FINGERPRINT,reader=reader,host_catalogs={'engine':G.catalog()},
                                   intake_defaults=DEFAULTS,public_key=PUBLIC)
        cls.helper=I.module('actual_packaged_helper',cls.records['company-request-intake.py'])
        cls.foundation,cls.request,cls.verifier=cls.helper.captured_modules(cls.helper.PACKAGED)
        cls.defaults=cls.helper.validate_defaults(DEFAULTS,cls.foundation,cls.request)

    def test_actual_delivery_producer_binds_exact_helper_defaults_key_and_entry(self):
        records=self.records
        self.assertEqual(set(records),set(I.FILES)|{'guided-delivery.txt'})
        delivered={name:raw for name,raw in records.items() if name!='guided-delivery.txt'}
        self.assertEqual(records['guided-delivery.txt'],I.delivery_receipt(delivered))
        self.assertIn(b"GP_INTAKE_AVAILABLE='true'",records['company-guided-private.sh'])
        for name in ('company-request-intake.py','guided-request-defaults.json','company-signing-public-key.pem'):
            self.assertIn(hashlib.sha256(records[name]).hexdigest().encode(),records['company-guided-private.sh'])
        self.assertEqual(records['guided-request-defaults.json'],DEFAULTS)
        self.assertEqual(records['company-signing-public-key.pem'],PUBLIC)
        for suffix in ('.json','.foundation.json'):
            self.assertEqual(self.helper.output_mode(self.helper.REQUESTS/('d'*32+suffix)),0o600)
        for name in ('intent.json','complete.json'):
            self.assertEqual(self.helper.output_mode(self.helper.INTAKE/name),0o400)
        for path in (self.helper.REQUESTS/'unexpected.json',self.helper.PACKAGE/'guided-delivery.txt'):
            with self.assertRaises(ValueError):self.helper.output_mode(path)
        self.assertIn(b'full_install_pending_signed_source_and_native_pair',records['company-install.sh'])
        self.assertLessEqual(len(records['company-guided-private.sh']),40*1024)
        self.assertLessEqual(sum(map(len,records.values())),4*1024**2)

    def test_generated_pair_passes_both_actual_original_validators(self):
        first,full=self.helper.request_pair(self.defaults,ANSWERS,'d'*32,self.foundation,self.request)
        self.assertEqual(self.foundation.validate(json.loads(first)),json.loads(first))
        self.assertEqual(self.request.validate_request(full,request_sha256=I.sha(full)),json.loads(full))
        self.assertEqual(json.loads(first)['mode'],'foundation-only')
        self.assertEqual(json.loads(full)['mode'],'full-installation')
        for name in ('operationId','dataDir','backingFile','capacityGiB','runscVersion','runscSha512','keyPath'):
            self.assertEqual(json.loads(first)[name],json.loads(full)[name])
        self.assertNotIn(b'password',first+full);self.assertNotIn(b'apiKey',first+full)

    def test_original_validators_reject_invalid_storage_capacity_and_extra_answers(self):
        values=[dict(ANSWERS,capacityGiB=31),dict(ANSWERS,capacityGiB=True),dict(ANSWERS,capacityGiB=4097),
            dict(ANSWERS,dataDir='/srv/autosoft-company'),dict(ANSWERS,backingFile='/srv/doxentriq-data/file'),
            dict(ANSWERS,backingFile='/opt/autosoft-company/bad'),dict(ANSWERS,dataDir='/srv/../elsewhere'),
            dict(ANSWERS,apiKey='not-accepted')]
        for answers in values:
            with self.subTest(answers=answers),self.assertRaises(ValueError):
                self.helper.request_pair(self.defaults,answers,'d'*32,self.foundation,self.request)

    def test_company_defaults_cannot_select_code_or_ambiguous_release_fields(self):
        original=json.loads(DEFAULTS)
        changes=[]
        for name,value in (('schemaVersion',True),('scope','arbitrary'),('runscSha512','x'*128)):
            row=copy.deepcopy(original);row[name]=value;changes.append(I.canonical(row))
        row=copy.deepcopy(original);row['platform']['command']='sh';changes.append(I.canonical(row))
        row=copy.deepcopy(original);row['platform']=row['foundation'];changes.append(I.canonical(row))
        changes.extend([DEFAULTS.replace(b'"schemaVersion":1',b'"schemaVersion":1,"schemaVersion":1'),DEFAULTS+b'\n'])
        for raw in changes:
            with self.subTest(digest=I.sha(raw)),self.assertRaises(ValueError):
                self.helper.validate_defaults(raw,self.foundation,self.request)

    def test_original_key_parser_rejects_another_company_identity(self):
        other=b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(DER[:-1]+b'\xff')+b'\n-----END PUBLIC KEY-----\n'
        with self.assertRaisesRegex(ValueError,'public key does not match'):
            I.build(source('deploy/installer/company_request_intake.py').read_bytes(),self.records['company_install.py'],
                    source('deploy/installer/company_full_cli_request.py').read_bytes(),DEFAULTS,other)

    def test_receipt_has_closed_names_and_bounded_exact_member_bytes(self):
        records={name:raw for name,raw in self.records.items() if name!='guided-delivery.txt'}
        for changed in ({**records,'extra.sh':b'bad'},{name:raw for name,raw in records.items() if name!='company-guided-private.sh'}):
            with self.assertRaisesRegex(ValueError,'exact intake package'):I.delivery_receipt(changed)
        changed=dict(records);changed['guided-request-defaults.json']=b'x'*4097
        with self.assertRaisesRegex(ValueError,'member exceeds'):I.delivery_receipt(changed)

    def test_saved_pair_is_bound_to_delivery_defaults_and_exact_shared_fields(self):
        first,full=self.helper.request_pair(self.defaults,ANSWERS,'d'*32,self.foundation,self.request)
        class Inputs:pass
        inputs=Inputs();inputs.expected='e'*64;inputs.defaults_raw=DEFAULTS;inputs.defaults=self.defaults
        inputs.foundation=self.foundation;inputs.request=self.request
        value=dict(schemaVersion=1,scope='GUIDED_PRIVATE_REQUEST_PAIR',deliverySha256=inputs.expected,
                   defaultsSha256=I.sha(DEFAULTS),foundation=json.loads(first),full=json.loads(full))
        self.assertEqual(self.helper.record_pair(inputs,value),(first,full))
        mutations=[]
        for name in ('deliverySha256','defaultsSha256'):
            changed=copy.deepcopy(value);changed[name]='f'*64;mutations.append(changed)
        changed=copy.deepcopy(value);changed['foundation']['operationId']='e'*32;mutations.append(changed)
        changed=copy.deepcopy(value);changed['full']['runscSha512']='f'*128;mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(ValueError):self.helper.record_pair(inputs,changed)

    def test_storage_prompt_rejects_out_of_range_capacity_before_request_creation(self):
        class Inputs:pass
        class State:
            def exists(self,path):return False
        inputs=Inputs();inputs.defaults=self.defaults;inputs.foundation=self.foundation
        inputs.request=self.request;inputs.state=State()
        for capacity in ('31','4097'):
            with self.subTest(capacity=capacity), redirect_stdout(io.StringIO()), \
                 patch('builtins.input',side_effect=[ANSWERS['dataDir'],ANSWERS['backingFile'],capacity]), \
                 patch.object(self.helper,'request_pair',side_effect=AssertionError('invalid prompt reached request creation')), \
                 self.assertRaisesRegex(ValueError,'Enter a whole capacity from 32 through 4096 GiB'):
                self.helper.collect(inputs)
        # Exact supported boundaries still pass the original request validators.
        for capacity in ('32','4096'):
            with self.subTest(capacity=capacity), redirect_stdout(io.StringIO()), \
                 patch('builtins.input',side_effect=[ANSWERS['dataDir'],ANSWERS['backingFile'],capacity]):
                first,full=self.helper.collect(inputs)
            self.assertEqual(json.loads(first)['capacityGiB'],int(capacity))
            self.assertEqual(json.loads(full)['capacityGiB'],int(capacity))

    def test_legacy_producer_profile_does_not_enable_unconfigured_intake(self):
        with G.clean_modules():records=B.assemble(ROOT,FINGERPRINT,reader=reader,host_catalogs={'engine':G.catalog()})
        self.assertEqual(len(records),7)
        self.assertIn(b"GP_INTAKE_AVAILABLE='false'",records['company-guided-private.sh'])
        self.assertNotIn('company-request-intake.py',records)
        for args in (dict(intake_defaults=DEFAULTS),dict(public_key=PUBLIC)):
            with self.assertRaisesRegex(ValueError,'complete-intake-delivery'):
                B.assemble(ROOT,FINGERPRINT,reader=reader,host_catalogs={'engine':G.catalog()},**args)


if __name__=='__main__':unittest.main(verbosity=2)
