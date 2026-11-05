#!/usr/bin/env python3
"""Retained local Bash controls. Native flock/root/filesystem/sync are injected.

Actual Bash parent descriptors, fork/exec descriptor closure, file contents,
types, local device/inode/link observations and journal retention are exercised.
No installer, packages, services, Linux native lock or remote action is run.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts' / 'install-lock.sh'
BASH = r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' else '/bin/bash'
ARTIFACT_ROOT = Path(os.environ.get('AUTOSOFT_TEST_ARTIFACT_ROOT', ROOT / '.local')).resolve()
REQUEST, ACTION, OUTCOME, FINAL = ('a' * 64, 'b' * 64, 'c' * 64, 'd' * 64)

def shell_path(path):
    value = Path(path).resolve().as_posix()
    return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value

HARNESS = r'''set -Eeuo pipefail
umask 077
source "$1"
test_root=$2; base="$test_root/admission"; request=$3; action=$4; outcome=$5; final=$6
_il_root() { [[ ${bad_root:-no} != yes ]] || _il_fail root_required; }
# Private adapter only in the test process. Native default implementations remain
# present in product source. Real stat dev/inode/link/size/timestamps are retained.
_il_tool() (
  _il_close_copies
  if [[ "$1" = test ]]; then [[ ${missing_utility:-no} != yes ]]; return; fi
  if [[ "$1" = sync ]]; then
    printf 'sync %s\n' "${@: -1}" >> "$test_root/order"
    [[ ${fault_sync:-} != "${@: -1}" && ${fault_all_sync:-no} != yes ]]
    return
  fi
  if [[ "$1" = stat && "$2" = -f ]]; then printf '%s\n' "${fake_filesystem:-xfs}"; return; fi
  if [[ "$1" = stat ]]; then
    path=${@: -1}
    raw=$(command stat "${@:2}") || exit 1
    IFS=: read -r dev ino bits uid gid mode links size modified changed <<< "$raw"
    # Directory/file protection is synthetic on Windows; identity continuity is real.
    if [[ -d "$path" ]]; then mode=700; bits=41c0; else mode=600; bits=8180; fi
    uid=0; gid=0
    [[ "$path" != "${bad_owner:-}" ]] || uid=10001
    [[ "$path" != "${bad_gid:-}" ]] || gid=10001
    [[ "$path" != "${bad_mode:-}" ]] || mode=777
    printf '%s:%s:%s:%s:%s:%s:%s:%s:%s:%s\n' "$dev" "$ino" "$bits" "$uid" "$gid" "$mode" "$links" "$size" "$modified" "$changed"
    return
  fi
  command "$@"
)
_il_take_lock() (
  # The actual two FDs are open. Only native flock acquisition is simulated.
  [[ -e "/proc/$IL_OWNER/fd/$IL_LOCK_FD" && -e "/proc/$IL_OWNER/fd/$IL_DIR_FD" ]] || exit 1
  printf 'flock %s\n' "$1" >> "$test_root/order"
  [[ ${busy_lock:-no} != yes ]]
)
'''

class InstallLockTests(unittest.TestCase):
    def setUp(self):
        if not ARTIFACT_ROOT.is_dir():
            raise RuntimeError('Company-controlled test artifact root must already exist')
        self.root = Path(tempfile.mkdtemp(prefix='install-lock-', dir=ARTIFACT_ROOT))
        self.base = self.root / 'admission'

    def run_shell(self, body):
        result = subprocess.run([BASH, '-c', HARNESS + body, 'install-lock-control',
                                 shell_path(SOURCE), shell_path(self.root), REQUEST,
                                 ACTION, OUTCOME, FINAL], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=40)
        # Keep complete raw outputs beside the exact synthetic fixture; no cleanup.
        index = len(list(self.root.glob('shell-*.stdout')))
        (self.root / f'shell-{index}.stdout').write_bytes(result.stdout)
        (self.root / f'shell-{index}.stderr').write_bytes(result.stderr)
        (self.root / f'shell-{index}.exit').write_text(str(result.returncode) + '\n')
        return result

    def ok(self, body):
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        return result

    def refused(self, body, code):
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 74, result.stderr.decode(errors='replace'))
        self.assertIn(code.encode(), result.stderr)
        return result

    def initialized(self):
        self.ok('install_lock_initialize "$base"\n')

    def completed_body(self):
        return '''install_lock_acquire "$base" "$request" 2
first=$IL_SESSION
install_lock_stage "$first" packages "$action" /bin/bash -c 'exit 0'
install_lock_confirm_stage "$first" packages "$action" "$outcome"
install_lock_complete "$first" "$final"
install_lock_release
'''

    def test_sourcing_has_no_filesystem_effect(self):
        self.ok(':\n')
        self.assertFalse(self.base.exists())

    def test_fresh_initialization_and_exact_persistent_lock(self):
        self.initialized()
        self.assertEqual(set(p.name for p in self.base.iterdir()), {'binding', 'install.lock', 'sessions'})
        self.assertEqual((self.base / 'install.lock').read_bytes(), b'')
        before = (self.base / 'install.lock').stat().st_ino
        self.ok(self.completed_body() + 'install_lock_acquire "$base" "$request" 1\ninstall_lock_release\n')
        self.assertEqual((self.base / 'install.lock').stat().st_ino, before)
        self.assertEqual(len(list((self.base / 'sessions').iterdir())), 2)

    def test_existing_empty_namespace_is_never_initialized_or_adopted(self):
        self.base.mkdir()
        self.refused('install_lock_initialize "$base"\n', 'existing_namespace')
        self.assertEqual(list(self.base.iterdir()), [])

    def test_missing_state_never_auto_initializes(self):
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'invalid_namespace')
        self.assertFalse(self.base.exists())

    def test_missing_binding_and_partial_initialization_are_preserved(self):
        self.base.mkdir(); (self.base / 'sessions').mkdir(); (self.base / 'install.lock').write_bytes(b'')
        before = sorted(p.name for p in self.base.iterdir())
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'incomplete_namespace')
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), before)

    def test_root_and_required_utility_fail_before_namespace_creation(self):
        self.refused('bad_root=yes; install_lock_initialize "$base"\n', 'root_required')
        self.refused('missing_utility=yes; install_lock_initialize "$base"\n', 'missing_utility')
        self.assertFalse(self.base.exists())

    def test_unsafe_ancestor_and_foreign_group_fail_closed(self):
        self.refused('bad_mode=$test_root; install_lock_initialize "$base"\n', 'unsafe_ancestor')
        self.refused('bad_gid=$test_root; install_lock_initialize "$base"\n', 'foreign_owner')
        self.assertFalse(self.base.exists())

    def test_unsupported_filesystem_leaves_refused_partial_namespace(self):
        self.refused('fake_filesystem=nfs; install_lock_initialize "$base"\n', 'unsupported_filesystem')
        self.assertTrue((self.base / 'install.lock').exists())
        self.refused('install_lock_initialize "$base"\n', 'existing_namespace')

    def test_lock_timeout_has_no_session_or_child(self):
        self.initialized()
        self.refused('busy_lock=yes; install_lock_acquire "$base" "$request" 3\n', 'lock_wait_unavailable')
        self.assertEqual(list((self.base / 'sessions').iterdir()), [])
        self.assertIn('flock 3', (self.root / 'order').read_text())

    def test_wait_and_request_are_exact_and_bounded(self):
        self.initialized()
        for wait in ('0', '31', '01', '1.0', '-1', 'inf'):
            self.refused(f'install_lock_acquire "$base" "$request" {wait}\n', 'invalid_acquisition')
        self.refused('install_lock_acquire "$base" bad 1\n', 'invalid_acquisition')

    def test_nonempty_hardlinked_and_replaced_lock_are_refused(self):
        self.initialized()
        lock = self.base / 'install.lock'
        lock.write_bytes(b'foreign')
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'nonempty_lock')
        lock.write_bytes(b'')
        os.link(lock, self.root / 'lock-link')
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'invalid_lock')

    def test_record_nul_and_unknown_namespace_object_are_refused(self):
        self.initialized()
        binding = self.base / 'binding'; binding.write_bytes(binding.read_bytes() + b'\x00')
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'malformed_record')

    def test_unknown_namespace_object_never_adopted(self):
        self.initialized(); (self.base / 'unexpected').write_bytes(b'preserve')
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'unknown_namespace_object')
        self.assertEqual((self.base / 'unexpected').read_bytes(), b'preserve')

    def test_session_intent_and_stage_sync_precede_child_effect(self):
        self.initialized()
        self.ok('''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c '[[ -f "$1/intent" && -f "$1/storage.intent" ]]; printf "child\\n" >> "$2"' _ "$base/sessions/$IL_SESSION" "$test_root/order"
install_lock_release
''')
        events = (self.root / 'order').read_text().splitlines()
        child = events.index('child')
        self.assertTrue(any('/intent' in event for event in events[:child]))
        self.assertTrue(any('/storage.intent' in event for event in events[:child]))
        self.assertTrue(events[child - 1].startswith('sync ') and '/sessions/s-' in events[child - 1])

    def test_children_receive_neither_owned_descriptor_parent_retains_both(self):
        self.initialized()
        self.ok('''install_lock_acquire "$base" "$request" 1
lock_fd=$IL_LOCK_FD; dir_fd=$IL_DIR_FD
install_lock_stage "$IL_SESSION" packages "$action" /bin/bash -c '[[ ! -e /proc/$BASHPID/fd/$1 && ! -e /proc/$BASHPID/fd/$2 ]]' _ "$lock_fd" "$dir_fd"
[[ -e /proc/$BASHPID/fd/$lock_fd && -e /proc/$BASHPID/fd/$dir_fd ]]
install_lock_release
''')

    def test_zero_child_exit_and_process_exit_never_complete(self):
        self.initialized()
        self.ok('install_lock_acquire "$base" "$request" 1\ninstall_lock_stage "$IL_SESSION" packages "$action" /bin/bash -c "exit 0"\n')
        session = next((self.base / 'sessions').iterdir())
        self.assertFalse((session / 'complete').exists())
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'unresolved_stage')
        self.assertEqual(len(list((self.base / 'sessions').iterdir())), 1)

    def test_release_without_stage_leaves_durable_unknown_session(self):
        self.initialized()
        self.ok('install_lock_acquire "$base" "$request" 1\ninstall_lock_release\n')
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'no_confirmed_stage')

    def test_child_failure_retains_intent_and_actual_status(self):
        self.initialized()
        self.ok('''install_lock_acquire "$base" "$request" 1
if install_lock_stage "$IL_SESSION" render "$action" /bin/bash -c 'exit 19'; then exit 99; else [[ $? = 19 ]]; fi
install_lock_release
''')
        session = next((self.base / 'sessions').iterdir())
        self.assertTrue((session / 'render.intent').exists())
        self.assertFalse((session / 'render.confirmed').exists())

    def test_stage_sync_failure_never_dispatches_child(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
fault_sync="$base/sessions/$IL_SESSION/storage.intent"
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c 'touch "$1"' _ "$test_root/effect"
''', 'record_sync_unavailable')
        self.assertFalse((self.root / 'effect').exists())
        self.assertTrue(next((self.base / 'sessions').iterdir()).joinpath('storage.intent').exists())

    def test_wrong_stage_action_or_session_cannot_confirm(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" packages "$action" /bin/bash -c 'exit 0'
install_lock_confirm_stage "$IL_SESSION" packages "$outcome" "$final"
''', 'stage_binding_mismatch')
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'unresolved_stage')

    def test_stale_subshell_and_released_scope_are_refused(self):
        self.initialized()
        self.refused('install_lock_acquire "$base" "$request" 1\n(install_lock_release)\n', 'foreign_or_released_session')

    def test_released_api_cannot_complete_even_with_exact_saved_session(self):
        self.initialized()
        self.refused('install_lock_acquire "$base" "$request" 1\nsaved=$IL_SESSION\ninstall_lock_release\ninstall_lock_complete "$saved" "$final"\n', 'foreign_or_released_session')

    def test_path_lock_replacement_before_stage_never_dispatches(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
mv "$base/install.lock" "$test_root/original-lock"; : > "$base/install.lock"
install_lock_stage "$IL_SESSION" packages "$action" /bin/bash -c 'touch "$1"' _ "$test_root/effect"
''', 'namespace_binding_mismatch')
        self.assertFalse((self.root / 'effect').exists())

    def test_namespace_directory_replacement_preserves_and_refuses_history(self):
        self.initialized()
        self.ok('install_lock_acquire "$base" "$request" 1\ninstall_lock_release\n')
        self.refused('mv "$base/sessions" "$test_root/original-sessions"\nmkdir "$base/sessions"\ninstall_lock_acquire "$base" "$request" 1\n', 'namespace_binding_mismatch')
        self.assertTrue(any((self.root / 'original-sessions').iterdir()))

    def test_complete_requires_all_exact_confirmations_and_retains_manifest(self):
        self.initialized()
        self.ok(self.completed_body())
        session = next((self.base / 'sessions').iterdir())
        self.assertIn(b'independently_confirmed=true\n', (session / 'complete').read_bytes())
        self.assertIn(b'manifest=', (session / 'complete').read_bytes())
        confirmation = session / 'packages.confirmed'
        confirmation.write_bytes(confirmation.read_bytes().replace(OUTCOME.encode(), FINAL.encode()))
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'completion_binding_mismatch')

    def test_completed_record_lost_ack_is_terminal_only_with_valid_exact_evidence(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" packages "$action" /bin/bash -c 'exit 0'
install_lock_confirm_stage "$IL_SESSION" packages "$action" "$outcome"
fault_sync="$base/sessions/$IL_SESSION/complete"
install_lock_complete "$IL_SESSION" "$final"
''', 'record_sync_unavailable')
        # A surviving valid terminal assertion is not undone by failed acknowledgement.
        self.ok('install_lock_acquire "$base" "$request" 1\ninstall_lock_release\n')

    def test_held_lock_aba_descriptor_cannot_use_restored_original_path(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
mv "$base/install.lock" "$test_root/original-lock"; : > "$base/install.lock"
exec {IL_LOCK_FD}<&-; exec {IL_LOCK_FD}<"$base/install.lock"
mv "$base/install.lock" "$test_root/replacement-lock"; mv "$test_root/original-lock" "$base/install.lock"
# Renames change ctime. Rebind every persistent correspondence in this controlled
# root fixture so only the wrong actually-held inode can reject before dispatch.
_il_read "$base/binding"; original_binding=$IL_TEXT
printf '%s' "$original_binding" > "$test_root/binding-before-aba"
original_lock=${original_binding#*$'\\n'lock=}; original_lock=${original_lock%%$'\\n'*}
current_lock=$(_il_identity "$base/install.lock" file)
updated_binding=${original_binding/"lock=$original_lock"/"lock=$current_lock"}
printf '%s' "$updated_binding" > "$base/binding"
updated_digest=$(_il_hash "$updated_binding"); updated_digest=${updated_digest%% *}
_il_read "$base/sessions/$IL_SESSION/intent"; original_intent=$IL_TEXT
printf '%s' "$original_intent" > "$test_root/intent-before-aba"
printf '%s' "${original_intent/"binding=$IL_BINDING"/"binding=$updated_digest"}" > "$base/sessions/$IL_SESSION/intent"
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c 'touch "$1"' _ "$test_root/effect"
''', 'held_scope_mismatch')
        self.assertFalse((self.root / 'effect').exists())

    def test_changed_lock_after_child_effect_is_unknown_not_completed(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c 'touch "$2"; mv "$1/install.lock" "$1/original-lock"; : > "$1/install.lock"' _ "$base" "$test_root/effect"
''', 'unknown_namespace_object')
        self.assertTrue((self.root / 'effect').exists())
        session = next((self.base / 'sessions').iterdir())
        self.assertFalse((session / 'storage.confirmed').exists())
        self.assertFalse((session / 'complete').exists())

    def test_unconfirmed_stage_refuses_later_stage_dispatch(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" packages "$action" /bin/bash -c 'exit 0'
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c 'touch "$1"' _ "$test_root/effect"
''', 'unresolved_stage')
        self.assertFalse((self.root / 'effect').exists())

    def test_exact_true_assertion_and_partial_confirmation_fail_closed(self):
        self.initialized()
        self.ok(self.completed_body())
        session = next((self.base / 'sessions').iterdir())
        complete = session / 'complete'
        complete.write_bytes(complete.read_bytes().replace(b'independently_confirmed=true', b'independently_confirmed=1'))
        self.refused('install_lock_acquire "$base" "$request" 1\n', 'completion_binding_mismatch')

    def test_stage_inventory_limit_precedes_child_dispatch(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
for ((number=0;number<64;number++)); do : > "$base/sessions/$IL_SESSION/stage-$number.intent"; : > "$base/sessions/$IL_SESSION/stage-$number.confirmed"; done
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c 'touch "$1"' _ "$test_root/effect"
''', 'stage_inventory_limit')
        self.assertFalse((self.root / 'effect').exists())

    def test_metadata_children_also_close_both_owned_descriptors(self):
        self.initialized()
        self.ok('''install_lock_acquire "$base" "$request" 1
_il_tool /bin/bash -c '[[ ! -e /proc/$BASHPID/fd/$1 && ! -e /proc/$BASHPID/fd/$2 ]]' _ "$IL_LOCK_FD" "$IL_DIR_FD"
[[ -e /proc/$BASHPID/fd/$IL_LOCK_FD && -e /proc/$BASHPID/fd/$IL_DIR_FD ]]
install_lock_release
''')

    def test_orphan_confirmation_refuses_first_stage_dispatch(self):
        self.initialized()
        self.refused('''install_lock_acquire "$base" "$request" 1
printf 'orphan preserved\\n' > "$base/sessions/$IL_SESSION/orphan.confirmed"
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c 'touch "$1"' _ "$test_root/effect"
''', 'unresolved_stage')
        self.assertFalse((self.root / 'effect').exists())
        self.assertEqual(next((self.base / 'sessions').iterdir()).joinpath('orphan.confirmed').read_bytes(), b'orphan preserved\n')

if __name__ == '__main__':
    unittest.main(verbosity=2)
