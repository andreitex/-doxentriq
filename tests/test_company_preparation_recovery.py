"""Real Bash journals with explicitly injected Windows native primitives.

These controls do not qualify Linux flock, root permissions or actual install
effects. The separate native entry suite exercises the original HeldParent.
"""
import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(os.environ.get('DOXENTRIQ_BASE_SOURCE', ROOT if (ROOT/'scripts/installer_parent.py').exists() else ROOT.parents[2]))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module


L = load('preparation_original_lock_tests', BASE / 'scripts/test-install-lock.py')
L.SOURCE = ROOT / 'scripts/install-lock.sh'
L.ARTIFACT_ROOT = ROOT.parent
ENTRY = (ROOT / 'deploy/installer/company-prepare.sh').read_text()
INVENTORY = ENTRY[ENTRY.index('_cp_inventory()'):ENTRY.index('company_prepare_entry()')]


class RecoveryJournal(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='recovery-journal-', dir=ROOT.parent))
    def run_shell(self, body):
        return subprocess.run([L.BASH, '-c', L.HARNESS + INVENTORY + body, 'test',
            L.shell_path(L.SOURCE), L.shell_path(self.root), L.REQUEST, L.ACTION, L.OUTCOME, L.FINAL],
            capture_output=True, timeout=40)
    def ok(self, body):
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); return result
    def refused(self, body, reason):
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 74, result.stderr.decode())
        self.assertIn(reason.encode(), result.stderr)
    def initial(self, stage='company-configuration'):
        self.ok('install_lock_initialize "$base"\ninstall_lock_acquire "$base" "$request" 1\n'
                'printf "%s" "$IL_SESSION" > "$test_root/session"\n'
                f'install_lock_stage "$IL_SESSION" {stage} "$action" /usr/bin/true\n'
                'install_lock_release\n')
    def recover(self):
        return 'session=$(cat "$test_root/session")\ninstall_lock_recover "$base" "$request" 1 "$session"\n'
    def snapshot(self):
        return {p.relative_to(self.root).as_posix():(p.read_bytes(),p.stat().st_mtime_ns)
            for p in (self.root/'admission').rglob('*') if p.is_file()}
    def test_reattach_retains_session_and_all_records_without_replay(self):
        self.initial(); before=self.snapshot()
        result=self.ok(self.recover()+'_cp_inventory "$action"\n[[ "$CP_PENDING" = company-configuration && "$CP_ACTION" = "$action" && ${#CP_CONFIRMED[@]} = 0 ]]\ninstall_lock_release\n')
        self.assertEqual(before,self.snapshot())
    def test_changed_request_refused(self):
        self.initial()
        self.refused('request='+('9'*64)+'\n'+self.recover(), 'session_request_mismatch')
    def test_completed_session_cannot_be_recovered(self):
        self.initial()
        self.ok(self.recover()+'install_lock_confirm_stage "$session" company-configuration "$action" "$outcome"\ninstall_lock_complete "$session" "$final"\ninstall_lock_release\n')
        self.refused(self.recover(),'already_completed')
    def test_other_unresolved_session_blocks_recovery(self):
        self.initial()
        original=(self.root/'session').read_text()
        self.ok(self.recover()+'install_lock_confirm_stage "$session" company-configuration "$action" "$outcome"\ninstall_lock_complete "$session" "$final"\ninstall_lock_release\ninstall_lock_acquire "$base" "$request" 1\ninstall_lock_stage "$IL_SESSION" company-configuration "$action" /usr/bin/true\ninstall_lock_release\n')
        self.refused(self.recover(),'unresolved_stage')
        self.assertEqual((self.root/'session').read_text(),original)
    def test_unknown_stage_cannot_enter_preparation_recovery(self):
        self.initial('company-render')
        self.refused(self.recover()+'_cp_inventory "$action"\n','preparation_unexpected_record_preserved')
    def test_out_of_order_pending_stage_refused(self):
        self.initial('repository-seed')
        self.refused(self.recover()+'_cp_inventory "$action"\n','preparation_stage_order')
    def test_confirmed_prefix_then_pending_stage_keeps_exact_outcomes(self):
        self.initial()
        self.ok(self.recover()+'install_lock_confirm_stage "$session" company-configuration "$action" "$outcome"\ninstall_lock_stage "$session" repository-seed "$action" /usr/bin/true\n_cp_inventory "$action"\n[[ ${#CP_CONFIRMED[@]} = 1 && "${CP_CONFIRMED[0]}" = "$outcome" && "$CP_PENDING" = repository-seed ]]\ninstall_lock_release\n')
    def test_changed_packaged_configuration_action_refused(self):
        self.initial()
        self.refused(self.recover()+'_cp_inventory '+('9'*64)+'\n','preparation_worker_changed')
    def test_unknown_session_does_not_create_new_session(self):
        self.initial(); before=self.snapshot()
        result=self.run_shell('install_lock_recover "$base" "$request" 1 s-000000000000\n')
        self.assertNotEqual(result.returncode,0); self.assertEqual(before,self.snapshot())


class PreparationPackage(unittest.TestCase):
    def test_real_builder_embeds_fixed_entry_lock_and_worker_hash(self):
        B=load('preparation_package_builder',ROOT/'deploy/installer/build-native-retention-package.py')
        worker=b'print("synthetic package bytes")\n'
        def reader(path,maximum):
            selected=ROOT/path.relative_to(BASE)
            return (selected if selected.exists() else path).read_bytes()
        entry=B.assemble_entry(BASE,worker,reader=reader,preparation=True)
        self.assertIn(B.pin(worker)['sha256'].encode(),entry)
        self.assertNotIn(b'@EMBED_',entry);self.assertNotIn(b'@WORKER_',entry)
        self.assertIn(b'install_lock_recover()',entry)
        result=subprocess.run([L.BASH,'-n'],input=entry,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        with self.assertRaisesRegex(ValueError,'exact-companion-entry'):
            B.assemble_entry(BASE,worker,reader=reader,preparation=True,render=True)
        self.assertLess(len(entry),32768)
    def test_help_needs_no_root_worker_or_journal(self):
        result=subprocess.run([L.BASH,L.shell_path(ROOT/'deploy/installer/company-prepare.sh'),'--help'],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertIn(b'--recover-preparation REQUEST SESSION',result.stdout)


class ObservationRecords(unittest.TestCase):
    def setUp(self):
        self.W=load('preparation_observation_worker',ROOT/'deploy/installer/company_configuration_worker.py')
        self.saved=b'fresh independently measured bytes\n';self.writes=[];self.checks=[]
        def require(value):
            if value is not True:raise ValueError('refused')
        @contextmanager
        def directory(path):yield 91,lambda:self.checks.append(True)
        self.R=SimpleNamespace(require=require,directory=directory)
        self.S=SimpleNamespace(read_protected=lambda path,limit:self.saved)
        self.info=SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o100400,st_uid=0,st_gid=0,st_nlink=1,
            st_size=len(self.saved),st_mtime_ns=3,st_ctime_ns=4)
    def observe(self,**kwargs):
        with mock.patch.object(self.W.os.path,'lexists',return_value=True),mock.patch.object(self.W.os,'stat',return_value=self.info),mock.patch.object(self.W,'write',side_effect=lambda *a,**k:self.writes.append(a)):
            self.W.write_observation(self.R,self.S,'/protected','verified.json',kwargs.get('raw',self.saved))
    def test_exact_existing_remeasurement_is_read_only(self):
        self.observe();self.assertEqual(self.writes,[]);self.assertTrue(self.checks)
    def test_different_prior_bytes_preserved_and_refused(self):
        with self.assertRaises(ValueError):self.observe(raw=b'changed')
        self.assertEqual(self.writes,[])
    def test_link_or_foreign_owner_or_wrong_mode_refused(self):
        for field,value in [('st_nlink',2),('st_uid',1),('st_mode',0o120777),('st_mode',0o100600)]:
            prior=getattr(self.info,field);setattr(self.info,field,value)
            with self.assertRaises(ValueError):self.observe()
            setattr(self.info,field,prior)
    def test_execute_evidence_can_never_be_adopted(self):
        with self.assertRaises(ValueError):
            self.W.write_observation(self.R,self.S,'/protected','executed.json',self.saved)
    def test_metadata_drift_during_observation_refused(self):
        after=SimpleNamespace(**vars(self.info));after.st_ino+=1
        with mock.patch.object(self.W.os.path,'lexists',return_value=True),mock.patch.object(self.W.os,'stat',side_effect=[self.info,after]):
            with self.assertRaises(ValueError):self.W.write_observation(self.R,self.S,'/protected','verified.json',self.saved)


if __name__=='__main__':unittest.main(verbosity=2)
