# Held installer parent evidence

`installer_parent.py` is a separate read-only evidence core. It is not wired to
the installer, runtime initializer, service startup or company pipelines. Its
output has scope `HELD_INSTALLER_PARENT_EVIDENCE_ONLY` and always keeps
`nativeAuthorized`, `effectsConfirmed` and `backupReady` false. Authenticating the
company release, binding the caller and independently confirming effects remain
separate integration work. A copied session string or successful inspection is
not permission to initialize anything.

The input is exactly seven explicit nonsecret argv fields: the original direct
Bash parent PID, its admission-directory FD index, its admission-lock FD index,
the `s-[A-Za-z0-9]{12}` session, installation request SHA256, stage label and action
SHA256. Inputs are typed and bounded; environment variables carry no authority.
The only admitted namespace is `/etc/autosoft-install-admission`. Installation
UUIDs stay distinct from Bash session identifiers.

The native backend requires Linux amd64, root credentials, the original direct
parent, root-owned Bash executable metadata, unchanged boot/start identity,
matching PID and mount namespaces, and an available live CLOEXEC pidfd. Its own
pidfd has immutable fstat/flags/inode and exact kernel `Pid`/`NSpid` bindings,
checked before and after use; the initial host profile refuses unknown/nested
procfs PID views. Parent
identity is sampled before and after pidfd acquisition and every checked use.
Pidfd polling reports termination; it does not report effect completion.
[Linux pidfd documentation](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
[Kernel pidfd fdinfo implementation](https://github.com/torvalds/linux/blob/v6.12/fs/pidfs.c)

The core holds its own nofollow read-only directory and record descriptors. It
checks root ownership, protected modes, file type, one-link records and finite
sizes; checks the immutable binding, session and current stage bytes; and checks
exact path/FD continuity throughout use. Immutable file metadata includes device,
inode, type/mode, UID/GID, link count, size and nanosecond modification/change
times. Directory continuity uses device, inode, type/mode and UID/GID, permitting
unrelated ancestor directory contents to change. Active namespace membership and
held records must remain unchanged. An existing current-stage confirmation or
terminal record is refused. Prior stages need exact intent/confirmation pairs.

The native backend verifies actual procfs and local ext/XFS/btrfs filesystem
types. It reads at most 4 KiB per record/fdinfo, 16 KiB per process record, 1,024
session names and 129 active-stage entries, with at most 64 stages. These bounds
admit at most 130 held files, six held directories and one pidfd. All owned
handles are CLOEXEC, close on success/failure, and every close is attempted even
when another close fails. Failed cleanup keeps the result unavailable.

The original parent FD targets are inspected with stat/readlink only. Its lock
fdinfo must contain one exact `FLOCK ADVISORY WRITE` whole-file row matching the
protected device/inode. The acquiring helper PID need not equal the Bash parent;
it is retained as part of observed row continuity, not treated as authority.
Parent and independently opened anchor mount IDs must correspond. Shared,
waiting, POSIX, ambiguous, unknown or changed rows are denied. No global lock
listing or blocked probe substitutes for the descriptor association. The kernel
documents that fdinfo includes locks associated with that descriptor.
[Kernel proc documentation](https://docs.kernel.org/filesystems/proc.html#proc-pid-fdinfo-fd-information-about-opened-file)

An entry check rejects inherited admission-inode copies. The core never opens
`/proc/PID/fd/LOCK_FD`, duplicates that FD, uses `pidfd_getfd`, takes a new lock,
signals a parent/process tree, or launches another parent. The flock lock follows
an open file description; inheriting or duplicating it could retain or release
the original lock. Independent read-only path opens do not adopt that OFD.
[Linux flock documentation](https://man7.org/linux/man-pages/man2/flock.2.html)

`hold_parent(input)` checks before entering and after leaving its context.
`held.use()` checks around an individual caller operation; `held.check()` makes
another observation. Any failed check invalidates the held scope and closes its
own handles. The core creates no records, stage confirmation or completion.
Parent death or an observed change around an operation leaves effects uncertain.
An effect and a parent/lock observation are not atomic. Transient changes entirely
between observations cannot be ruled out; no general OFD ABA detection,
syscall/IO deadline, parent/source authenticity, descendant cancellation or
external-effect cancellation guarantee is introduced. The original root company
parent and loaded core remain trusted pending signed-release caller binding.

The tests use virtual protected storage/process evidence and managed mocks of
the actual Linux syscall seams. They execute byte parsers, scope lifetime and
cleanup behavior, not a native installer parent, flock, namespace or pidfd.
Injected systems are always labelled `INJECTED_PARENT_EVIDENCE_UNQUALIFIED`;
even native-backend observations remain `LINUX_PARENT_EVIDENCE_UNQUALIFIED`.
Debian/Rocky live parent semantics, native DAC/mount/locking, durability, reboot,
installer activation and runtime-pair adapter integration remain unqualified.
