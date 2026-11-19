"""Portable producer controls only; no shell, writes, packages or host execution."""
import hashlib
import ast
import contextlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',str(ROOT)))


def read(path,maximum=131072):
    relative=Path(path).relative_to(ROOT)
    candidate=ROOT/relative
    raw=(candidate if candidate.is_file()else BASE/relative).read_bytes()
    if not 0<len(raw)<=maximum:raise ValueError('fixture-source-size')
    return raw


def load(name,relative):
    raw=read(ROOT/relative)
    from types import ModuleType
    value=ModuleType(name);value.__file__=str(ROOT/relative);sys.modules[name]=value
    exec(compile(raw,value.__file__,'exec'),value.__dict__);return value


B=load('placement_actual_guided_producer','deploy/installer/build-guided-private-package.py')
I=load('placement_original_intake_contract','deploy/installer/company_request_intake.py')
P=load('placement_candidate_producer','deploy/installer/company_guided_placement.py')


def records():
    # Synthetic bytes exercise delivery binding; they are never executed.
    value={name:('synthetic '+name+'\n').encode()for name in I.FILES}
    value['guided-delivery.txt']=I.delivery_receipt(value)
    return value


class PlacementProducer(unittest.TestCase):
    def test_actual_producer_binds_all_original_members_and_receipt(self):
        value=records();calls=[]
        def reader(path,maximum=131072):calls.append(str(path));return read(path,maximum)
        output=B.placement(ROOT,value,reader=reader)
        self.assertEqual(set(output),{'doxentriq-place-guided.sh'})
        raw=output['doxentriq-place-guided.sh']
        for name,data in value.items():
            self.assertIn(('  "$1" '+name+' '+str(len(data))+' '+hashlib.sha256(data).hexdigest()).encode(),raw)
        self.assertIn(read(ROOT/'scripts/install-lock.sh'),raw)
        self.assertIn(("BP_RECEIPT='"+hashlib.sha256(value['guided-delivery.txt']).hexdigest()+"'").encode(),raw)
        self.assertEqual(len(calls),8);self.assertEqual(len(set(calls)),4)
        self.assertLessEqual(len(raw),40*1024)

    def test_payload_change_cannot_reuse_original_receipt(self):
        value=records();value['company_install.py']+=b'changed'
        with self.assertRaisesRegex(ValueError,'receipt-binding'):B.placement(ROOT,value,reader=read)

    def test_missing_extra_and_legacy_members_refuse(self):
        for change in ('missing','extra','legacy'):
            value=records()
            if change=='missing':del value['company-guided-private.sh']
            elif change=='extra':value['unexpected.sh']=b'not executed'
            else:
                for name in ('company-request-intake.py','guided-request-defaults.json','company-signing-public-key.pem','guided-delivery.txt'):del value[name]
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'exact-package'):B.placement(ROOT,value,reader=read)

    def test_source_change_during_assembly_refuses(self):
        calls={}
        def reader(path,maximum=131072):
            key=str(path);calls[key]=calls.get(key,0)+1;raw=read(path,maximum)
            return raw+b'changed'if calls[key]==2 else raw
        with self.assertRaisesRegex(ValueError,'source-changed'):B.placement(ROOT,records(),reader=reader)

    def test_duplicate_or_missing_template_marker_refuses(self):
        template=read(ROOT/'deploy/installer/company-place-guided.sh');lock=read(ROOT/'scripts/install-lock.sh')
        for value in (template+b'\n# @EMBED_INSTALL_LOCK@',template.replace(b'@BOOTSTRAP_TOTAL_BYTES@',b'0')):
            with self.assertRaisesRegex(ValueError,'template-marker'):P.build(value,lock,records(),intake=I)

    def test_original_member_limit_is_enforced_before_emission(self):
        value=records();value['company-native-retention.py']=b'x'*(I.FILES['company-native-retention.py']+1)
        with self.assertRaises(ValueError):
            value['guided-delivery.txt']=I.delivery_receipt({name:value[name]for name in I.FILES})
            B.placement(ROOT,value,reader=read)


class ProducerMainPreflight(unittest.TestCase):
    """Run real main/admission against a closed in-memory filesystem.

    Source assembly and writes are fakes: these tests establish ordering and
    checks, not POSIX ownership enforcement or native emission behavior.
    """
    def exercise(self,*,placement='/review/placement',bad_parent=None,remove_pair_preflight=False):
        source=read(ROOT/'deploy/installer/build-guided-private-package.py')
        tree=ast.parse(source)
        if remove_pair_preflight:
            class RemovePairPreflight(ast.NodeTransformer):
                removed=0
                def visit_FunctionDef(self,node):
                    return self.generic_visit(node)if node.name=='main'else node
                def visit_Expr(self,node):
                    if isinstance(node.value,ast.Call)and isinstance(node.value.func,ast.Name)and node.value.func.id=='validate_output_destination':
                        self.removed+=1;return None
                    return node
            mutation=RemovePairPreflight();tree=mutation.visit(tree)
            self.assertEqual(mutation.removed,2)
            ast.fix_missing_locations(tree)
        producer=ModuleType('placement_main_mutation'if remove_pair_preflight else'placement_main_candidate')
        exec(compile(tree,'<controlled main candidate>','exec'),producer.__dict__)
        directory=lambda mode=0o700,uid=0,gid=0:SimpleNamespace(st_mode=stat.S_IFDIR|mode,st_uid=uid,st_gid=gid)
        state={'/':directory(0o755),'/review':directory(),'/review/source':directory(),
               '/review/catalog.json':SimpleNamespace(st_mode=stat.S_IFREG|0o400,st_uid=0,st_gid=0)}
        if bad_parent=='unsafe':state['/review/unsafe']=directory(0o777)
        elif bad_parent=='foreign':state['/review/foreign']=directory(uid=1000)
        elif bad_parent=='nondirectory':state['/review/nondirectory']=SimpleNamespace(st_mode=stat.S_IFREG|0o400,st_uid=0,st_gid=0)
        elif bad_parent=='symlink':state['/review/symlink']=SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0,st_gid=0)
        class VirtualPath(PurePosixPath):
            def lstat(self):
                if str(self)not in state:raise FileNotFoundError(str(self))
                return state[str(self)]
            def resolve(self,strict=False):
                if strict:self.lstat()
                return self
        input_bytes={
            '/review/catalog.json':b'controlled-catalog',
            '/review/defaults.json':b'controlled-defaults',
            '/review/public.pem':b'controlled-public-key',
        }
        guided={'company-guided-private.sh':b'controlled-guided-entry',
                'guided-delivery.txt':b'controlled-receipt'}
        placer={'doxentriq-place-guided.sh':b'controlled-placer'}
        emitted=[]
        def fake_emit(destination,records):
            destination=producer.validate_output_destination(destination)
            state[str(destination)]=directory()
            emitted.append(dict(path=str(destination),records=dict(records)))
            return {name:producer.pin(raw)for name,raw in records.items()}
        args=['/review/source','/review/delivery','--fingerprint','a'*64,
              '--engine-catalog','/review/catalog.json','--engine-catalog-sha256',producer.pin(input_bytes['/review/catalog.json'])['sha256']]
        if placement is not None:
            args+=['--placement-destination',placement,'--request-defaults','/review/defaults.json',
                   '--request-defaults-sha256',producer.pin(input_bytes['/review/defaults.json'])['sha256'],
                   '--public-key','/review/public.pem']
        output=io.StringIO();failure=None
        with patch.object(producer,'Path',VirtualPath),patch.object(producer.os,'name','posix'),\
             patch.object(producer.os,'geteuid',return_value=0,create=True),\
             patch.object(producer.os,'getegid',return_value=0,create=True),\
             patch.object(producer.os.path,'lexists',side_effect=lambda path:str(path)in state),\
             patch.object(producer,'protected_read',side_effect=lambda path,limit:input_bytes[str(path)]),\
             patch.object(producer,'assemble',return_value=guided)as assemble,\
             patch.object(producer,'placement',return_value=placer)as build_placement,\
             patch.object(producer,'emit',side_effect=fake_emit),contextlib.redirect_stdout(output):
            try:producer.main(args)
            except (ValueError,FileNotFoundError)as error:failure=error
        return dict(failure=failure,emitted=emitted,state=state,stdout=output.getvalue(),
                    assembleCalls=assemble.call_count,placementCalls=build_placement.call_count,
                    guided=guided,placer=placer)

    def test_main_missing_placement_parent_refuses_before_either_output(self):
        result=self.exercise(placement='/review/missing/placement')
        self.assertIsInstance(result['failure'],FileNotFoundError)
        self.assertEqual(result['emitted'],[]);self.assertNotIn('/review/delivery',result['state'])
        self.assertEqual(result['stdout'],'');self.assertEqual(result['assembleCalls'],0)

    def test_main_unsafe_placement_parents_refuse_before_either_output(self):
        for kind in('unsafe','foreign','nondirectory','symlink'):
            with self.subTest(kind=kind):
                result=self.exercise(placement='/review/'+kind+'/placement',bad_parent=kind)
                self.assertIsInstance(result['failure'],ValueError)
                self.assertEqual(str(result['failure']),'protected-output-ancestor-required')
                self.assertEqual(result['emitted'],[]);self.assertNotIn('/review/delivery',result['state'])
                self.assertEqual(result['assembleCalls'],0)

    def test_removing_pair_preflight_reproduces_partial_output(self):
        result=self.exercise(placement='/review/missing/placement',remove_pair_preflight=True)
        self.assertIsInstance(result['failure'],FileNotFoundError)
        self.assertEqual([row['path']for row in result['emitted']],['/review/delivery'])
        self.assertIn('/review/delivery',result['state']);self.assertEqual(result['stdout'],'')

    def test_main_valid_pair_emits_both_and_preserves_receipt_summary(self):
        result=self.exercise();self.assertIsNone(result['failure'])
        self.assertEqual([row['path']for row in result['emitted']],['/review/delivery','/review/placement'])
        summary=json.loads(result['stdout'])
        self.assertEqual(summary['files'],{name:B.pin(raw)for name,raw in result['guided'].items()})
        self.assertEqual(summary['placementFiles'],{name:B.pin(raw)for name,raw in result['placer'].items()})
        self.assertEqual(summary['deliveryReceiptSha256'],B.pin(result['guided']['guided-delivery.txt'])['sha256'])
        self.assertIs(summary['fullInstallerAvailable'],False);self.assertIs(summary['publicStartupAvailable'],False)
        self.assertEqual(result['assembleCalls'],1);self.assertEqual(result['placementCalls'],1)

    def test_legacy_single_output_is_unchanged_without_pair_preflight(self):
        actual=self.exercise(placement=None)
        prior_order=self.exercise(placement=None,remove_pair_preflight=True)
        for result in(actual,prior_order):
            self.assertIsNone(result['failure']);self.assertEqual(result['placementCalls'],0)
            self.assertEqual([row['path']for row in result['emitted']],['/review/delivery'])
            self.assertNotIn('placementFiles',json.loads(result['stdout']))
        self.assertEqual(actual['emitted'],prior_order['emitted']);self.assertEqual(actual['stdout'],prior_order['stdout'])


if __name__=='__main__':unittest.main(verbosity=2)
