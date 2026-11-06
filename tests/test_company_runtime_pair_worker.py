"""Closed-result pair remeasurement against original injected fixtures.

These are source/control regressions, not native encrypted installation proof.
"""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value


W=load('native_pair_worker_controls','deploy/installer/company_runtime_pair_worker.py')
T=load('native_pair_original_fixtures','scripts/test-runtime-pair-init.py')
R=T.P


def inspect(f):
    transport=T.F.Transport(f.files)
    def fixture_path(value):
        R.C.require(type(value) is str and Path(value).is_absolute() and str(Path(value))==value);return value
    def layout(data,files):return R.S.L.verify(data,files=files,build_mount=lambda _:dict(f.placement.mount))
    inputs=dict(host_directory=f.host,files=f.files,command=T.F.forbidden,mount=f.mount,layout=layout,
        gate_factory=f.gate,allocation_factory=f.allocation,read_state=f.read,clock=f.clock.time,timeout=10)
    with patch.object(R.S.I,'path_value',fixture_path),patch.object(R,'os',transport),patch.object(R.S,'os',transport),\
         patch.object(R.S.L,'os',transport),patch.object(f.files,'descriptor',transport.descriptor):
        result=W.inspect_completed(R,f.data,f.root,authority=T.Authority(),inputs=inputs)
    assert not transport.handles and not transport.real and not f.locks.held
    return result


class PairVerificationTests(unittest.TestCase):
    def test_completed_result_is_remeasured_without_writes(self):
        f=T.Fixture();before=f.call();f.files.events.clear()
        after,digest=inspect(f)
        self.assertEqual(before,after);self.assertFalse(after['nativeAuthorized']);self.assertEqual(len(digest),64)
        self.assertFalse(any(row[0] in ('write','mkdir','permission','replace-file') for row in f.files.events))
    def test_historical_gate_record_changes_are_detected_by_closed_execute_binding(self):
        f=T.Fixture();f.call();_,before=inspect(f)
        path=f.stage/'gate-confirmed.json';changed=f.files.read(path);changed['gateSha256']='0'*64;f.rewrite(path,changed)
        _,after=inspect(f)
        self.assertNotEqual(before,after) # The worker requires the complete closed execute summary to be identical.
    def test_native_authorization_claim_is_never_adopted(self):
        f=T.Fixture();f.call();path=f.stage/'confirmed.json';changed=f.files.read(path);changed['nativeAuthorized']=True;f.rewrite(path,changed)
        with self.assertRaises(ValueError):inspect(f)
    def test_missing_partial_record_is_not_reinitialized(self):
        f=T.Fixture();f.call();(f.stage/'allocation-confirmed.json').unlink();f.files.events.clear()
        with self.assertRaises(ValueError):inspect(f)
        self.assertFalse(any(row[0] in ('write','mkdir') for row in f.files.events))
    def test_exact_result_replacement_changes_immutable_record_binding(self):
        f=T.Fixture();f.call();_,before=inspect(f)
        path=f.stage/'gate-confirmed.json';value=path.read_bytes();path.rename(path.with_name('old-gate'))
        path.write_bytes(value);(f.stage/'old-gate').unlink()
        _,after=inspect(f);self.assertNotEqual(before,after)
    def test_unknown_admission_outcome_blocks_independent_confirmation(self):
        f=T.Fixture();f.call();base=next((f.gate().base/'operations').iterdir())
        f.files.write(base/'uncertain.json',dict(intentSha256=R.C.digest(f.files.read(base/'intent.json')),stage='completion'))
        with self.assertRaises(ValueError):inspect(f)
    def test_action_binds_worker_request_and_exact_storage_proof(self):
        proof=dict(installationId=T.INSTALLATION,dataRootSha256='d'*64,extra='bound')
        pair=W.proposal(R,proof);first=W.action(R,b'original','a'*64,pair)
        for body,worker,request in ((b'changed','a'*64,pair),(b'original','b'*64,pair),
            (b'original','a'*64,W.proposal(R,dict(proof,extra='changed')))):
            self.assertNotEqual(first,W.action(R,body,worker,request))


if __name__=='__main__':unittest.main(verbosity=2)
