#!/usr/bin/env python3
"""Local filesystem/function controls; no package manager or systemd is run.

Ownership/mode metadata, require_root and systemctl are stubbed on every OS.
Actual file type, content, hard-link counts and inode-preserving moves are local
filesystem observations. Native startup/reboot, Linux ownership and the
clean-install distribution matrix require separate acceptance.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).with_name('install-runtime-gate.sh').resolve()
BASH = r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' else '/bin/bash'

def shell_path(path):
    value = Path(path).resolve().as_posix()
    return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value

class RuntimeGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='runtime-gate-', dir=Path(__file__).resolve().parents[1] / '.local' if os.name == 'nt' else None)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'config'; self.config.mkdir()
        self.units = self.root / 'units'; self.units.mkdir()
        self.guard = self.root / 'guard.sh'
        self.guard.write_text('#!/bin/bash\nprintf "checked\\n" >> "$(dirname -- "$0")/guard-calls"\nexit 0\n', encoding='utf8', newline='\n')
    def tearDown(self):
        self.temporary.cleanup()
    def run_shell(self, body):
        program = '''set -Eeuo pipefail
die() { printf '%s\\n' "$*" >&2; exit 1; }
require_root() { :; }
source "$1"
config=$2; units=$3; guard=$4; test_root=$5; data=/synthetic-encrypted
# The actual protection predicates execute with synthetic root/mode inputs.
stat() {
  local format=$2 path=${@: -1}
  if [[ "$format" = %u ]]; then
    if [[ "$path" = "${bad_owner:-}" ]]; then printf '10001\\n'; else printf '0\\n'; fi
  elif [[ "$format" = %a ]]; then
    if [[ "$path" = "${bad_mode:-}" ]]; then printf '0666\\n'; elif [[ -d "$path" ]]; then printf '700\\n'; else printf '600\\n'; fi
  else command stat "$@"; fi
}
systemctl() {
  printf '%s\\n' "$*" >> "$test_root/systemctl-calls"
  case "$1" in
    daemon-reload) [[ "${fault_reload:-no}" != yes ]] ;;
    stop) [[ "$2" != "${fault_stop:-}" ]] ;;
    show)
      if [[ "$2" = --property=LoadState ]]; then
        if [[ "${units_absent:-no}" = yes ]]; then printf 'not-found\\n'; else printf 'loaded\\n'; fi
      elif [[ "$2" = --property=ActiveState ]]; then
        if [[ "$4" = "${fault_active:-}" ]]; then printf 'active\\n'; else printf 'inactive\\n'; fi
      else return 1; fi ;;
    *) return 1 ;;
  esac
}
''' + body
        return subprocess.run([BASH, '-c', program, 'runtime-gate-control', shell_path(SOURCE), shell_path(self.config), shell_path(self.units), shell_path(self.guard), shell_path(self.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    def persistent_guards(self):
        for unit in ('docker.service', 'containerd.service'):
            directory = self.units / (unit + '.d'); directory.mkdir(exist_ok=True)
            (directory / 'autosoft-storage.conf').write_text('[Unit]\nRequiresMountsFor=/synthetic-encrypted\nRequires=var-log-journal.mount\nAfter=systemd-cryptsetup@autosoft\\x2ddata.service var-log-journal.mount\n[Service]\nExecStartPre=/bin/bash ' + shell_path(self.guard) + '\n', encoding='utf8', newline='\n')
    def prepare(self):
        result = self.run_shell('prepare_runtime_gate "$config" "$units"\n')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
    def test_package_start_is_gated_for_all_three_units_before_storage_ready(self):
        self.prepare()
        self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
        for unit in ('docker.service', 'docker.socket', 'containerd.service'):
            self.assertEqual((self.units / (unit + '.d') / 'autosoft-bootstrap.conf').read_text(), '[Unit]\nConditionPathExists=' + shell_path(self.config) + '/runtime-bootstrap.ready\n')
        calls = (self.root / 'systemctl-calls').read_text().splitlines()
        self.assertEqual(calls[0], 'daemon-reload')
        self.assertEqual([call for call in calls if call.startswith('stop ')], ['stop docker.service', 'stop docker.socket', 'stop containerd.service'])
    def test_interrupted_prepare_and_rerun_preserve_existing_gates_and_no_ready_marker(self):
        self.prepare()
        files = list(self.units.glob('*/autosoft-bootstrap.conf'))
        before = {p:(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in files}
        self.prepare()
        self.assertEqual(before, {p:(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in files})
        self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
    def test_conflicting_existing_unit_gate_is_preserved_and_blocks_package_preparation(self):
        directory = self.units / 'docker.service.d'; directory.mkdir()
        gate = directory / 'autosoft-bootstrap.conf'; gate.write_bytes(b'[Unit]\nConditionPathExists=/foreign\n')
        result = self.run_shell('prepare_runtime_gate "$config" "$units"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(gate.read_bytes(), b'[Unit]\nConditionPathExists=/foreign\n')
        self.assertFalse((self.root / 'systemctl-calls').exists())
    def test_missing_persistent_storage_guard_cannot_publish_ready(self):
        self.prepare()
        result = self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
        self.assertFalse((self.root / 'guard-calls').exists())
    def test_failed_encrypted_mount_check_cannot_publish_ready_even_in_conditional_caller(self):
        self.prepare(); self.persistent_guards()
        self.guard.write_text('#!/bin/bash\nexit 1\n', encoding='utf8', newline='\n')
        result = self.run_shell('if complete_runtime_gate "$config" "$units" "$data" "$guard"; then printf "unsafe-ready"; fi\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
        self.assertNotIn(b'unsafe-ready', result.stdout)
    def test_only_guarded_completion_publishes_ready_and_rerun_preserves_it(self):
        self.prepare(); self.persistent_guards()
        result = self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        ready = self.config / 'runtime-bootstrap.ready'; before = (ready.read_bytes(), ready.stat().st_ino, ready.stat().st_mtime_ns)
        result = self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((ready.read_bytes(), ready.stat().st_ino, ready.stat().st_mtime_ns), before)
        self.assertEqual(ready.read_bytes(), b'encrypted-runtime-bootstrap-v1\n')
        self.assertEqual((self.root / 'guard-calls').read_text().splitlines(), ['checked', 'checked'])
    def test_existing_ready_marker_is_closed_even_when_storage_guard_is_now_missing(self):
        self.prepare(); self.persistent_guards()
        self.assertEqual(self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n').returncode, 0)
        (self.units / 'containerd.service.d/autosoft-storage.conf').unlink()
        before = (self.config / 'runtime-bootstrap.ready').read_bytes()
        result = self.run_shell('prepare_runtime_gate "$config" "$units"\n')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
        held = list(self.config.glob('runtime-bootstrap.closed.*/runtime-bootstrap.ready'))
        self.assertEqual(len(held), 1); self.assertEqual(held[0].read_bytes(), before)
        result = self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n')
        self.assertNotEqual(result.returncode, 0); self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
    def publish_ready(self):
        self.prepare(); self.persistent_guards()
        result = self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return self.config / 'runtime-bootstrap.ready'
    def test_fresh_uninstalled_units_are_confirmed_inactive_without_a_failed_stop(self):
        result = self.run_shell('units_absent=yes\nprepare_runtime_gate "$config" "$units"\n')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        calls = (self.root / 'systemctl-calls').read_text().splitlines()
        self.assertFalse(any(call.startswith('stop ') for call in calls))
        self.assertEqual(sum('--property=ActiveState' in call for call in calls), 3)
    def test_interruption_after_marker_move_leaves_gate_closed_and_preserves_inode_on_rerun(self):
        ready = self.publish_ready(); before = (ready.read_bytes(), ready.stat().st_ino)
        (self.units / 'containerd.service.d/autosoft-storage.conf').write_bytes(b'')
        result = self.run_shell('fault_reload=yes\nprepare_runtime_gate "$config" "$units"\nprintf "unsafe-package-work"\n')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(ready.exists()); self.assertNotIn(b'unsafe-package-work', result.stdout)
        preserved = list(self.config.glob('runtime-bootstrap.closed.*/runtime-bootstrap.ready')); self.assertEqual(len(preserved), 1)
        self.assertEqual((preserved[0].read_bytes(), preserved[0].stat().st_ino), before)
        self.prepare(); self.assertFalse(ready.exists()); self.assertEqual(list(self.config.glob('runtime-bootstrap.closed.*/runtime-bootstrap.ready')), preserved)
        result = self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(ready.exists())
    def test_failed_or_uncertain_stop_blocks_packages_without_restoring_marker(self):
        for fault in ('fault_stop=docker.service', 'fault_active=docker.service'):
            with self.subTest(fault=fault):
                ready = self.publish_ready()
                result = self.run_shell(fault + '\nprepare_runtime_gate "$config" "$units"\nprintf "unsafe-package-work"\n')
                self.assertNotEqual(result.returncode, 0); self.assertFalse(ready.exists()); self.assertNotIn(b'unsafe-package-work', result.stdout)
    def test_wrong_commented_appended_or_truncated_storage_guard_never_publishes_ready(self):
        self.prepare(); self.persistent_guards(); path = self.units / 'containerd.service.d/autosoft-storage.conf'; original = path.read_text()
        for content in (original.replace('/synthetic-encrypted', '/foreign'), original.replace('ExecStartPre=', '#ExecStartPre='), original.replace(shell_path(self.guard), '/foreign-guard.sh'), original + 'ExecStartPre=/bin/true\n', original[:30]):
            with self.subTest(content=content):
                path.write_text(content, encoding='utf8', newline='\n')
                result = self.run_shell('complete_runtime_gate "$config" "$units" "$data" "$guard"\n')
                self.assertNotEqual(result.returncode, 0); self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
        self.assertFalse((self.root / 'guard-calls').exists())
    def test_unprotected_ready_marker_is_never_moved_or_overwritten(self):
        for fault in ('bad_owner', 'bad_mode'):
            with self.subTest(fault=fault):
                ready = self.publish_ready(); before = (ready.read_bytes(), ready.stat().st_ino)
                prior_closures = list(self.config.glob('runtime-bootstrap.closed.*'))
                result = self.run_shell(f'{fault}="$config/runtime-bootstrap.ready"\nprepare_runtime_gate "$config" "$units"\n')
                self.assertNotEqual(result.returncode, 0); self.assertEqual((ready.read_bytes(), ready.stat().st_ino), before)
                self.assertEqual(list(self.config.glob('runtime-bootstrap.closed.*')), prior_closures)
    def test_hard_linked_ready_marker_cannot_be_moved_or_accepted(self):
        ready = self.publish_ready(); alias = self.root / 'ready-hardlink'; os.link(ready, alias)
        result = self.run_shell('prepare_runtime_gate "$config" "$units"\n')
        self.assertNotEqual(result.returncode, 0); self.assertTrue(ready.exists()); self.assertEqual(ready.read_bytes(), alias.read_bytes())
        self.assertEqual(list(self.config.glob('runtime-bootstrap.closed.*')), [])
    def test_unprotected_gate_storage_file_or_guard_script_blocks_completion(self):
        self.prepare(); self.persistent_guards()
        targets = ('$units/docker.service.d/autosoft-bootstrap.conf', '$units/containerd.service.d/autosoft-storage.conf', '$guard', '$test_root')
        for target in targets:
            for attribute in ('bad_owner', 'bad_mode'):
                with self.subTest(target=target, attribute=attribute):
                    result = self.run_shell(f'{attribute}="{target}"\ncomplete_runtime_gate "$config" "$units" "$data" "$guard"\n')
                    self.assertNotEqual(result.returncode, 0); self.assertFalse((self.config / 'runtime-bootstrap.ready').exists())
        self.assertFalse((self.root / 'guard-calls').exists())

if __name__ == '__main__':
    unittest.main(verbosity=2)
