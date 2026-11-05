# Standalone installer admission

`scripts/install-lock.sh` is a company-only Bash library. It is not wired into
the installer. Source qualification is not installation or backup readiness.

The intended parent installer calls `install_lock_initialize BASE` exactly once
for a wholly absent protected namespace, then `install_lock_acquire BASE
REQUEST_SHA256 WAIT_SECONDS`. Acquisition accepts integer waits from 1 to 30
seconds and retains its exact directory and permanent, read-only-opened lock
descriptors in the original Bash process. Root ownership, root group, private
0700 directories, single-link 0600 records, canonical protected ancestors and
local ext2/ext3, XFS or Btrfs placement are required. Missing tools, unknown
objects, changed bindings and partial initialization fail closed. Nothing is
deleted, reset, replaced, repaired or automatically adopted.

Acquisition writes an immutable `closed=true` session intent before returning.
`install_lock_stage SESSION LABEL ACTION_SHA256 COMMAND ARGS...` writes,
synchronizes and reads back its immutable stage intent before executing the
quoted argv. Both owned descriptors are closed in the child, while the original
parent retains its lock. A zero child exit merely returns zero. Failure, process
death, lock release and elapsed time never confirm installation effects.
Later stages are refused until every earlier admitted stage is confirmed.

Only a trusted company caller that independently checked the exact session,
stage, requested action and resulting artifacts may call
`install_lock_confirm_stage SESSION LABEL ACTION_SHA256 OUTCOME_SHA256`.
After all stages are confirmed, that caller must independently verify the final
installation evidence before calling `install_lock_complete SESSION FINAL_SHA256`.
The terminal record binds the request and the exact confirmed stage manifest.
The helper checks the bindings and hash shapes; opaque hashes alone do not prove
package, storage or daemon outcomes. It does not generate this independent
evidence or interpret a subprocess status as evidence. A surviving valid durable
terminal assertion can be recognized after its return acknowledgement failed.
Missing or partial terminal records remain unresolved.

`install_lock_release` invalidates the live scope and closes the parent
descriptors. It does not complete the session. Every later acquisition inventories
retained history under the exclusive lock. Any unfinished session or malformed
evidence blocks new installation work, even after a crash freed the kernel lock.
No replay, resume, abort or reconciliation API is provided in this first slice.
Future installer wiring must cover completed-installation fast paths, package
actions, resume, storage, render and initialization with this same parent scope.

GNU `sync -f` is used for each exact new record and its parent. Its success and
readback are required before stage dispatch. Actual Linux durability, filesystem
behavior, distribution utility availability and power-loss recovery require
native qualification. The 30-second limit bounds the `flock` acquisition wait,
not arbitrary filesystem, synchronization or child execution time. Shell glob
inventories are count-limited to 1,024 sessions and 64 stages; glob materialization
occurs before those checks. The private namespace assumes a trusted host root.
This is not a hostile-root or arbitrary shell path-race guarantee.
The original parent owns the private `IL_*` state and descriptors. The company
caller must not close, duplicate, reassign or export them outside this API; the
helper does not detect arbitrary caller manipulation of an open file description.

Closing descriptors in child wrappers protects live-parent serialization. It
does not cancel descendants or prove they stopped if the parent dies. The
unresolved durable session prevents fresh acquisition in that situation. No
process-group termination, reaping or universal kernel I/O deadline is claimed.

The retained local suite injects root/protection/filesystem/synchronization and
native lock acquisition. It exercises actual local Bash descriptors, fork/exec
closure, file contents, types, inode/link continuity and retained journals. Use an
already existing company-controlled `AUTOSOFT_TEST_ARTIFACT_ROOT`; the default is
the repository `.local`. Fixtures and raw per-process outputs are retained.
Native Debian/Rocky flock, reboot, root DAC and utility presence are unqualified.

Primary API references: [util-linux flock](https://man7.org/linux/man-pages/man1/flock.1.html),
[Bash redirections](https://www.gnu.org/s/bash/manual/html_node/Redirections.html),
[GNU stat](https://www.gnu.org/s/coreutils/manual/html_node/stat-invocation.html),
[GNU sync](https://www.gnu.org/s/coreutils/manual/html_node/sync-invocation.html).

## Company verification commands

`install_lock_verify SESSION ABSOLUTE_COMMAND [ARGS...]` is a separate company
inspection wrapper. It checks the original live parent session before dispatch,
holds the exact protected session-intent descriptor during the command, checks
its unchanged path and descriptor identity afterward, closes that descriptor,
and checks the live parent session again before returning the command status.
The child closes its copies of the namespace, lock and intent descriptors; the
parent retains the original two admission descriptors throughout inspection.
This wrapper writes no session, stage, confirmation or completion records. Exit
zero is an inspection result, never independently confirmed installation evidence.
Nonzero status or post-command uncertainty leaves existing stage records intact.

The command must have a canonical absolute lexical path. The call accepts at
most 32 additional arguments, at most 4,096 bytes per argument (including the
session and command), and at most 65,536 bytes including argv separators. Quoted
argv is passed literally. The child starts in `/` with only fixed `PATH`,
`LC_ALL`, `LANG`, `HOME` and `TZ`; Bash `exec -c` clears the inherited environment
before loading the fixed `/usr/bin/env` launcher. Exported admission variables,
loader settings, language startup settings and exported functions are not passed
through. The original parent remains a trusted company Bash process: the caller
must authenticate the verifier and its source, use only nonsecret argv, and
avoid tracing or hostile startup configuration. Existing parent metadata helpers
retain their original trusted-parent contract.

This wrapper cannot prove that an arbitrary executable is read-only, independently
validate its reported findings, or bound arbitrary child/kernel I/O and descendant
lifetimes. Only authenticated company verification code is authorized for this
API. A future caller must provide its own reviewed runtime supervision and check
the exact artifact evidence before the separate confirmation API. No installer
wiring, reconciliation, cancellation or new readiness guarantee is introduced.
The separate focused local verification suite reuses the injected fixture by
composition; it does not rerun or modify the original 33 controls. Linux native
DAC, flock, utility availability and durability remain separately unqualified.

On the Windows control host, MSYS reconstructs `MSYSTEM`, `SYSTEMROOT` and
`WINDIR` after environment clearing. The local assertion permits exactly those
three platform bootstrap values in addition to the five fixed entries. This is
not Linux environment qualification. The loader-variable control inserts one
export into an otherwise exact actual verification-child body immediately before
its original `exec -c`, because exporting a nonexistent loader library into the
Windows parent prevents its existing metadata-helper forks from starting.
