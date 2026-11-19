"""Actual seven-stage Bash parent; effect workers are explicit synthetic fixtures."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('quota_original_entry_fixture',ROOT/'tests/test_company_initialization_entry_native.py')
O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)

def worker(mode):
    raw=O.worker(mode).decode()
    raw=raw.replace("'company-initial-identity':'6'*64}","'company-initial-identity':'6'*64,'company-private-quota':'8'*64}")
    raw=raw.replace("'company-initial-identity':'7'*64}","'company-initial-identity':'7'*64,'company-private-quota':'9'*64}")
    raw=raw.replace("stage=a.stage or (", "stage=a.stage or ('company-private-quota' if 'quota' in a.command else ")
    raw=raw.replace("'identity-action'):","'identity-action','quota-action'):")
    raw=raw.replace("'provision-initial-identity'):","'provision-initial-identity','activate-private-quota'):")
    raw=raw.replace("'company-private-infrastructure','company-initial-identity'):","'company-private-infrastructure','company-initial-identity','company-private-quota'):")
    raw=raw.replace(" if MODE=='identity-child-failure'", " if MODE=='quota-child-failure' and stage=='company-private-quota':raise SystemExit(23)\n if MODE=='identity-child-failure'")
    raw=raw.replace(" if MODE=='identity-verifier-failure'", " if MODE=='quota-verifier-failure' and stage=='company-private-quota':raise SystemExit(24)\n if MODE=='identity-verifier-failure'")
    raw=raw.replace(" session='s-XXXXXXXXXXXX'", " session='s-XXXXXXXXXXXX' if MODE=='stale-quota-confirmation' and stage=='company-private-quota' else 's-XXXXXXXXXXXX'")
    raw=raw.replace(" magic='initial-identity-verified-v1'", " magic='private-quota-verified-v1' if stage=='company-private-quota' else 'initial-identity-verified-v1'")
    compile(raw,'<synthetic quota entry worker>','exec')
    return raw.encode()

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'actual Linux root required')
class QuotaEntry(unittest.TestCase):
    def run_case(self,mode):
        case=Path(os.environ['DOXENTRIQ_NATIVE_TEST_ROOT'])/uuid.uuid4().hex;case.mkdir(mode=0o700)
        done=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',__file__,'--fixture',mode,str(case)],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=210)
        self.assertEqual(done.returncode,0,done.stderr.decode());return json.loads((case/'report.json').read_text())
    def test_seven_confirmations_share_original_live_parent(self):
        r=self.run_case('success');self.assertEqual(r['exitCode'],0,r['stderr'])
        self.assertEqual((r['sessions'],r['confirmed'],r['completed'],r['executed']),(1,7,1,7))
        self.assertEqual(len(r['effectSessions']),1);self.assertIn('Public services, operational timers',r['stdout'])
    def test_identity_failure_cannot_start_quota(self):
        r=self.run_case('identity-verifier-failure');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['confirmed'],r['completed'],r['executed']),(5,0,6))
    def test_uncertain_quota_start_preserved_without_replay(self):
        r=self.run_case('quota-child-failure');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['confirmed'],r['completed'],r['executed']),(6,0,7))
        self.assertNotEqual(r['retryExit'],0);self.assertEqual((r['retrySessions'],r['retryEffects']),(1,7))
    def test_quota_verification_failure_cannot_complete(self):
        r=self.run_case('quota-verifier-failure');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['confirmed'],r['completed'],r['executed']),(6,0,7))
    def test_stale_quota_confirmation_cannot_complete(self):
        r=self.run_case('stale-quota-confirmation');self.assertNotEqual(r['exitCode'],0)
        self.assertEqual((r['confirmed'],r['completed'],r['executed']),(6,0,7))

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--fixture':O.fixture(sys.argv[2],sys.argv[3],worker_factory=worker,quota=True)
    else:unittest.main(verbosity=2)
