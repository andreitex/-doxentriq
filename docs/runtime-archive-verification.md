# Runtime archive verification

The foundation verifier checks the complete pinned gVisor archive against the
installed files before running its version command. Current releases include
companion executables beneath `gvisor-bin`; checking only `runsc` and the
containerd shim is insufficient. See the [gVisor installation guide](https://gvisor.dev/docs/user_guide/install/).

The supported current layout contains the two primary executables and five
companion files. A legacy two-file archive is accepted only when there is no
installed companion directory. Unknown archive members, incomplete layouts,
links, unexpected installed companion files, writable or privileged executable
modes, and content changes are rejected. A changed vendor layout requires a
reviewed verifier update.

The verifier opens the archive beneath protected directories and checks the
expected SHA512 while copying it into a sealed in-memory file. The decoder reads
that immutable copy. Original archive descriptors remain held and their bytes
and metadata are checked again before confirmation. Installed executable
descriptors remain held through final verification, including a second content
measurement. Descriptor cleanup failure prevents confirmation.

Native regression tests cover real Linux files, both layouts, changed or missing
companions, traversal, links, permissions, late content changes, archive
replacement, digest mismatch, sealing and decoder failure. They run through the
public Linux controls workflow and company test runner.

On November 6, 2026, the 17 native cases passed on Rocky Linux 10.2 and Ubuntu
24.04 under WSL. The actual checksum-pinned gVisor 20261005.0 archive also passed
seven-file verification in a private Linux fixture. No gVisor executable was
run by these checks. These results establish archive-verifier behavior; they
do not establish sandbox operation, vulnerability eligibility, complete
installation or reboot recovery.
