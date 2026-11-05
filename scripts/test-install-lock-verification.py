#!/usr/bin/env python3
"""Focused local verification-wrapper controls; native protection/flock is injected.

The original 33 controls are imported only as a retained fixture adapter. They
are neither inherited nor rerun. Actual local Bash exec/environment/descriptors
and record replacement are exercised in company-controlled retained fixtures.
No installer, native Linux acquisition, VM, package or service action is run.
"""
import importlib.util
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'retained_install_lock_fixture', ROOT / 'scripts' / 'test-install-lock.py')
OLD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(OLD)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = OLD.InstallLockTests('test_sourcing_has_no_filesystem_effect')
        self.fixture.setUp()
        self.root, self.base = self.fixture.root, self.fixture.base

    def ok(self, body):
        return self.fixture.ok(body)

    def refused(self, body, code):
        return self.fixture.refused(body, code)

    def initialized(self):
        self.fixture.initialized()

    def session(self):
        return next((self.base / 'sessions').iterdir())

    def assert_fixed_environment(self, path):
        expected = {'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C', 'LANG=C', 'HOME=/', 'TZ=UTC'}
        if os.name == 'nt':
            # MSYS reconstructs these three platform bootstrap entries after
            # env -i. No other inherited export is accepted. Linux stays exact.
            expected |= {'MSYSTEM=MINGW64', 'SYSTEMROOT=' + os.environ['SYSTEMROOT'].upper(),
                         'WINDIR=' + os.environ['WINDIR'].upper()}
        self.assertEqual(set(path.read_text().splitlines()), expected)

    def test_real_child_closes_three_owned_fds_parent_retains_original_scope(self):
        self.initialized()
        result = self.ok(r'''install_lock_acquire "$base" "$request" 1
install_lock_verify "$IL_SESSION" /bin/bash -c '
  parent=$1; lock=$2; directory=$3; intent=$4; count=0
  [[ -e /proc/$parent/fd/$lock && -e /proc/$parent/fd/$directory ]]
  [[ ! -e /proc/$BASHPID/fd/$lock && ! -e /proc/$BASHPID/fd/$directory ]]
  for descriptor in /proc/$parent/fd/*; do
    if [[ "$descriptor" -ef "$intent" ]]; then
      ((count+=1)); number=${descriptor##*/}
      [[ ! -e /proc/$BASHPID/fd/$number ]] || exit 91
    fi
  done
  [[ "$count" = 1 ]] || exit 92
  printf "three-owned-copies-closed\n"
' _ "$BASHPID" "$IL_LOCK_FD" "$IL_DIR_FD" "$base/sessions/$IL_SESSION/intent"
[[ -e /proc/$BASHPID/fd/$IL_LOCK_FD && -e /proc/$BASHPID/fd/$IL_DIR_FD && -z ${IL_RECORD_FD:-} ]]
_il_live "$IL_SESSION"
install_lock_release
''')
        self.assertEqual(result.stdout, b'three-owned-copies-closed\n')
        self.assertEqual(set(p.name for p in self.session().iterdir()), {'intent'})

    def test_fixed_environment_removes_exports_and_language_startup_injection(self):
        self.initialized()
        self.ok(r'''install_lock_acquire "$base" "$request" 1
printf 'printf injected > "$1"\n' > "$test_root/startup"
export IL_ACTIVE IL_OWNER IL_BASE IL_SESSION IL_REQUEST IL_LOCK_FD IL_DIR_FD
export BASH_ENV="$test_root/startup" ENV="$test_root/startup"
export PYTHONPATH=/untrusted PYTHONHOME=/untrusted NODE_OPTIONS=--untrusted
export COMPANY_SECRET=do-not-forward CDPATH=/untrusted GCONV_PATH=/untrusted
injected_function() { printf unexpected; }; export -f injected_function
install_lock_verify "$IL_SESSION" /usr/bin/env > "$test_root/child-environment"
install_lock_verify "$IL_SESSION" /bin/bash -c '
 [[ "$PWD" = / && "$LC_ALL" = C && "$LANG" = C && "$HOME" = / && "$TZ" = UTC ]]
 [[ -z ${BASH_ENV+x} && -z ${ENV+x} && -z ${IL_ACTIVE+x} && -z ${IL_RECORD_FD+x} ]]
 [[ -z ${LD_PRELOAD+x} && -z ${PYTHONPATH+x} && -z ${NODE_OPTIONS+x} && -z ${COMPANY_SECRET+x} ]]
 ! declare -F injected_function >/dev/null
' _ "$test_root/injected"
[[ ! -e "$test_root/injected" ]]
install_lock_release
''')
        self.assert_fixed_environment(self.root / 'child-environment')
        self.assertFalse((self.root / 'injected').exists())

    def test_actual_child_clears_loader_environment_before_loading_env_launcher(self):
        # Inject only at the pre-exec boundary: Windows Git Bash's loader also
        # reads LD_PRELOAD while forking unchanged parent metadata helpers.
        # The actual helper body is retained; one export line is inserted after
        # cd and before its original exec -c. This isolates that exec contract.
        source = OLD.SOURCE.read_text()
        start = source.index('_il_verification_child() (\n')
        end = source.index('install_lock_verify() {\n', start)
        actual = source[start:end]
        needle = '  cd / || exit 74\n'
        self.assertEqual(actual.count(needle), 1)
        insertion = ('  export LD_PRELOAD=/nonexistent-loader-injection '
                     'LD_LIBRARY_PATH=/untrusted\n')
        instrumented = actual.replace(needle, needle + insertion)
        self.assertEqual(instrumented.replace(insertion, ''), actual)
        (self.root / 'actual-child-before-loader-injection.sh').write_text(actual)
        (self.root / 'actual-child-loader-control.sh').write_text(instrumented)
        self.initialized()
        self.ok(r'''source "$test_root/actual-child-loader-control.sh"
install_lock_acquire "$base" "$request" 1
install_lock_verify "$IL_SESSION" /usr/bin/env > "$test_root/loader-child-environment"
_il_live "$IL_SESSION"
install_lock_release
''')
        self.assert_fixed_environment(self.root / 'loader-child-environment')

    def test_zero_result_preserves_unknown_stage_and_cannot_complete_it(self):
        self.initialized()
        self.refused(r'''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" packages "$action" /bin/bash -c 'exit 0'
_il_read "$base/sessions/$IL_SESSION/packages.intent"; before=$IL_TEXT
install_lock_verify "$IL_SESSION" /bin/bash -c 'exit 0'
_il_read "$base/sessions/$IL_SESSION/packages.intent"; after=$IL_TEXT
[[ "$before" = "$after" ]]
install_lock_complete "$IL_SESSION" "$final"
''', 'unresolved_stage')
        self.assertEqual(set(p.name for p in self.session().iterdir()), {'intent', 'packages.intent'})

    def test_nonzero_result_and_missing_executable_preserve_status_and_scope(self):
        self.initialized()
        self.ok(r'''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" render "$action" /bin/bash -c 'exit 0'
if install_lock_verify "$IL_SESSION" /bin/bash -c 'exit 19'; then exit 91; else [[ $? = 19 ]]; fi
_il_live "$IL_SESSION"
if install_lock_verify "$IL_SESSION" /nonexistent/company-verifier; then exit 92; else [[ $? = 127 ]]; fi
_il_live "$IL_SESSION"
install_lock_release
''')
        self.assertEqual(set(p.name for p in self.session().iterdir()), {'intent', 'render.intent'})

    def test_exact_same_content_intent_replacement_after_zero_result_is_refused(self):
        self.initialized()
        self.refused(r'''install_lock_acquire "$base" "$request" 1
install_lock_stage "$IL_SESSION" storage "$action" /bin/bash -c 'exit 0'
install_lock_verify "$IL_SESSION" /bin/bash -c '
 cp "$1/intent" "$2/original-content"; mv "$1/intent" "$2/original-intent"
 (umask 077; cat "$2/original-content" > "$1/intent")
 exit 0
' _ "$base/sessions/$IL_SESSION" "$test_root"
printf unexpected > "$test_root/after-verify"
''', 'verification_record_replaced')
        self.assertEqual((self.root / 'original-intent').read_bytes(), (self.session() / 'intent').read_bytes())
        self.assertFalse((self.root / 'after-verify').exists())
        self.assertFalse((self.session() / 'storage.confirmed').exists())
        self.assertFalse((self.session() / 'complete').exists())

    def test_postcheck_refuses_replaced_lock_even_after_nonzero_result(self):
        self.initialized()
        self.refused(r'''install_lock_acquire "$base" "$request" 1
install_lock_verify "$IL_SESSION" /bin/bash -c '
 mv "$1/install.lock" "$2/original-lock"; : > "$1/install.lock"; exit 19
' _ "$base" "$test_root"
printf unexpected > "$test_root/after-verify"
''', 'namespace_binding_mismatch')
        self.assertTrue((self.root / 'original-lock').exists())
        self.assertFalse((self.root / 'after-verify').exists())
        self.assertEqual(set(p.name for p in self.session().iterdir()), {'intent'})

    def test_invalid_session_cannot_dispatch_even_valid_command(self):
        self.initialized()
        self.refused(r'''install_lock_acquire "$base" "$request" 1
install_lock_verify s-AAAAAAAAAAAA /bin/bash -c 'printf unexpected > "$1"' _ "$test_root/effect"
''', 'foreign_or_released_session')
        self.assertFalse((self.root / 'effect').exists())

    def test_subshell_and_released_parent_cannot_dispatch(self):
        self.initialized()
        self.refused(r'''install_lock_acquire "$base" "$request" 1
(install_lock_verify "$IL_SESSION" /bin/bash -c 'printf unexpected > "$1"' _ "$test_root/effect")
''', 'foreign_or_released_session')
        self.assertFalse((self.root / 'effect').exists())
        # A different retained fixture avoids pretending the unknown prior session reopened.
        other = OLD.InstallLockTests('test_sourcing_has_no_filesystem_effect')
        other.setUp(); other.initialized()
        other.refused(r'''install_lock_acquire "$base" "$request" 1
saved=$IL_SESSION; install_lock_release
install_lock_verify "$saved" /bin/bash -c 'printf unexpected > "$1"' _ "$test_root/effect"
''', 'foreign_or_released_session')
        self.assertFalse((other.root / 'effect').exists())

    def test_argc_path_and_byte_limits_refuse_before_live_scope_or_dispatch(self):
        cases = [
            ('install_lock_verify\n', 'invalid_verification_argv'),
            ('install_lock_verify session\n', 'invalid_verification_argv'),
            ('set --; for ((n=0;n<33;n++)); do set -- "$@" x; done; install_lock_verify session /bin/bash "$@"\n', 'invalid_verification_argv'),
            ('install_lock_verify session relative\n', 'invalid_path'),
            ('install_lock_verify session /bin/../bin/bash\n', 'invalid_path'),
            ('printf -v long "%4097s" x; install_lock_verify session /bin/bash "$long"\n', 'verification_argument_limit'),
            ('printf -v long "%4096s" x; set --; for ((n=0;n<16;n++)); do set -- "$@" "$long"; done; install_lock_verify session /bin/bash "$@"\n', 'verification_argv_limit'),
            ('printf -v bytes "%4094s" x; bytes+=$\'\\xc3\\xa9\\xc3\\xa9\'; install_lock_verify session /bin/bash "$bytes"\n', 'verification_argument_limit'),
        ]
        for body, code in cases:
            with self.subTest(code=code, body=body):
                self.refused(body, code)
        self.assertFalse(self.base.exists())

    def test_literal_argv_and_valid_argument_boundary_are_preserved(self):
        self.initialized()
        result = self.ok(r'''install_lock_acquire "$base" "$request" 1
printf -v boundary '%4096s' x
literal='$(printf injected); `printf injected`; * ? [x]'
install_lock_verify "$IL_SESSION" /bin/bash -c '
 [[ ${#1} = 4096 && "$2" = '\''$(printf injected); `printf injected`; * ? [x]'\'' && "$3" = $'\''two\nlines'\'' ]]
 printf "literal-argv-preserved\n"
' _ "$boundary" "$literal" $'two\nlines'
install_lock_release
''')
        self.assertEqual(result.stdout, b'literal-argv-preserved\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
