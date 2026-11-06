"""Closed record projections from the original CLI flow; no host effects."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


R=load('retention_records_tests','deploy/installer/company_retention_records.py')
T=load('retention_records_original_flow','tests/test_company_full_cli.py')
B=load('retention_records_package','deploy/installer/build-native-retention-package.py')


class OriginalRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        f=T.Fixture()
        try:
            with f.context(genuine=True) as cli: planning=f.dispatch(cli,'plan-stage')
            cls.planned=planning.completed_record()
            cls.plan=base64.b64decode(json.loads(cls.planned)['planBase64'])
            cls.request_raw=f.request_raw;cls.request=json.loads(cls.request_raw)
            cls.stage='company-platform-store'
            with f.context(genuine=True) as cli:
                action=json.loads(cls.plan)['actionSha256']
                f.system.add(f.session+'/'+cls.stage+'.intent',f.system.stage(cls.stage,action))
                execution=f.dispatch(cli,'execute-stage',cls.plan)
            cls.executed=execution.completed_record();outcome=json.loads(cls.executed)['outcomeSha256']
            with f.context(genuine=True) as cli: verification=f.dispatch(cli,'verify-stage',cls.plan,execution,outcome)
            cls.verified=verification.completed_record()
            cls.parent=json.loads(f.invocation('execute-stage',cls.plan))['parent']
            cls.identity=json.loads(cls.executed)['deliveryIdentitySha256']
        finally:f.clean()

    def complete(self,**changes):
        arguments=dict(executed_raw=self.executed,verified_raw=self.verified,plan_raw=self.plan,
            request=self.request,request_raw=self.request_raw,stage=self.stage,parent=self.parent,identity=self.identity)
        arguments.update(changes)
        return R.completion(**arguments)

    def test_original_closed_plan_and_fresh_verification_are_exactly_bound(self):
        plan,action=R.planning_record(self.planned,self.request,self.request_raw,self.stage,self.identity)
        self.assertEqual(plan,self.plan);self.assertEqual(action,self.parent[-1])
        marker=self.complete()
        self.assertTrue(marker.startswith(b'retention-verified-v1\n'))
        self.assertIn(('\nrequest='+R.sha(self.request_raw)+'\n').encode(),marker)
        self.assertIn(('\nverification='+R.sha(self.verified)+'\n').encode(),marker)

    def test_changed_parent_session_action_request_and_identity_refuse(self):
        for index,value in ((3,'s-Zzz123Def456'),(4,'a'*64),(5,'company-source-materialize'),(6,'a'*64)):
            parent=list(self.parent);parent[index]=value
            with self.subTest(index=index),self.assertRaises(ValueError):self.complete(parent=parent)
        with self.assertRaises(ValueError):self.complete(identity='0'*64)
        with self.assertRaises(ValueError):self.complete(request_raw=self.request_raw+b' ')

    def test_stale_plan_or_missing_actual_reread_cannot_be_confirmed(self):
        plan=json.loads(self.plan);plan['actionSha256']='f'*64
        with self.assertRaises(ValueError):self.complete(plan_raw=R.canonical(plan))
        for field in ('exactEffectsReread','ownedReadHandlesKnownReleased','outerContextsRequireClosure'):
            verified=json.loads(self.verified);verified['result']['retainedEffectsObservation'][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):self.complete(verified_raw=R.canonical(verified))
        verified=json.loads(self.verified);verified['result']['ownedResourcesKnownReleased']=False
        with self.assertRaises(ValueError):self.complete(verified_raw=R.canonical(verified))

    def test_result_or_record_command_substitution_refuses(self):
        verified=json.loads(self.verified);verified['result']['operationResult']['unexpected']='changed'
        with self.assertRaises(ValueError):self.complete(verified_raw=R.canonical(verified))
        with self.assertRaises(ValueError):self.complete(verified_raw=self.executed)
        planned=json.loads(self.planned);planned['binding']['planSha256']='f'*64
        with self.assertRaises(ValueError):R.planning_record(R.canonical(planned),self.request,self.request_raw,self.stage,self.identity)

    def test_packaged_bash_embeds_original_lock_and_exact_worker_digest(self):
        worker=b'trusted fixture worker\n'
        entry=B.assemble_entry(ROOT,worker,reader=lambda path,maximum:path.read_bytes())
        self.assertIn((ROOT/'scripts/install-lock.sh').read_bytes(),entry)
        self.assertIn(R.sha(worker).encode(),entry)
        self.assertNotIn(b'@WORKER_SHA256@',entry)
        self.assertNotIn(b'@EMBED_INSTALL_LOCK@',entry)
        self.assertIn(b'if ! install_lock_stage',entry)
        self.assertLess(entry.index(b'if ! install_lock_stage'),entry.index(b'    install_lock_confirm_stage'))


if __name__=='__main__':unittest.main()
