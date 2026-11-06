# Runtime archive verification

The foundation verifier checks the complete pinned gVisor archive against the
installed files before running its version command. Current releases include
companion executables beneath `gvisor-bin`; checking only `runsc` and the
containerd shim is insufficient. See the [gVisor installation guide](https://gvisor.dev/docs/user_guide/install/).

The verifier accepts three exact layouts: the two primary executables alone,
the previous layout with five companion files, and the current layout with six
companions. The current layout adds `gvisor-bin/gvisor-proc-umounter`, present in
the official [20261102.0 release](https://github.com/google/gvisor/releases/tag/release-20261102.0).
A legacy two-file archive is accepted only when there is no installed companion
directory. Unknown archive members, incomplete layouts,
links, unexpected installed companion files, writable or privileged executable
modes, and content changes are rejected. A changed vendor layout requires a
reviewed verifier update.

The verifier opens the archive beneath protected directories and checks the
expected SHA512 while copying it into a sealed in-memory file. The decoder reads
that immutable copy. Original archive descriptors remain held and their bytes
and metadata are checked again before confirmation. Installed executable
descriptors remain held through final verification, including a second content
measurement. Descriptor cleanup failure prevents confirmation.

Native regression tests cover real Linux files, all three layouts, changed or missing
companions, traversal, links, permissions, late content changes, archive
replacement, digest mismatch, sealing and decoder failure. They run through the
public Linux controls workflow and company test runner.

On November 6, 2026, the original 17 native cases passed on Rocky Linux 10.2 and
Ubuntu 24.04 under WSL. After adding the current layout, all 23 native cases
passed under WSL, with no skips; the 61 foundation controls also passed. The
actual checksum-pinned 20261005.0 and 20261102.0 archives passed seven-file and
eight-file verification respectively in private Linux fixtures. The latter
archive was fully checked before extraction and independently measured afterward.
The expanded suite has not yet been run on Rocky Linux.

No gVisor executable was run by these checks. A separate fresh-feed scan of the
20261102.0 binaries reported 15 High and eight Medium package findings, plus
eight findings with unknown severity, across 18 distinct advisory identifiers.
That runtime candidate remains blocked; supporting its archive layout does not
approve its deployment. These results establish archive-verifier behavior;
they do not establish sandbox operation, vulnerability eligibility, complete
installation or reboot recovery.
