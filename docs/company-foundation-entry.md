# Trusted company foundation entry

This source slice implements the company foundation worker and the producer for
its two-file trusted package. The reviewed phase definitions are now integrated
in the public `scripts/install.sh`, following explicit user approval. The
original installer and approval-review failures remain preserved in local
evidence. All 116 focused controls pass against the public script: 61 foundation,
28 installation-wiring and 27 source-catalog controls, with no skips. Both
company pipelines register the foundation suite. This establishes source
integration; the trusted entry has not run as a native Linux installer.
The public integration receipt (private installation record; not distributed)
records exact source pins, test counts, retained failures and independent review.

The company distributes `company-install.sh` and `company_install.py` through an
independently trusted channel, together with the package hashes and the company
public-key fingerprint. `deploy/installer/build-package.py` produces those two
files; it does not sign a company release or install anything. Its native
producer requires Linux root, root-owned protected source ancestry and files,
exclusive output, bounded writes, readback and directory synchronization. Source
reads retain all nine metadata fields independently for each path and descriptor;
the cross-view comparison excludes ctime. Producer ancestor checks use stable
path observations, not a held descriptor for every ancestor. Native race and
close behavior has not been qualified by the portable controls.

The company prepares a protected, quiet `/opt/autosoft-company` tree before
dispatch: `bootstrap`, `incoming`, `staging` and `evidence` are real root:root
directories with mode 0700. The package and independent public key reside in
`bootstrap`; the schema3 release bundle and matching source tree reside beneath
`incoming`. Files are never imported from candidate siblings. The emitted worker
embeds and hash-checks the trusted verifier, materializer and original-parent
observer before opening candidate data. The emitted entry embeds the original
installer lock and pins the worker. Trusted package provenance is a distribution
prerequisite; root ownership alone does not establish it.

The entry accepts exactly `--foundation-only` and a canonical JSON request file.
The request names `schemaVersion` 1, `mode` `foundation-only`, a fresh 32-character
hexadecimal `operationId`, the exact `releaseSha256`, protected `bundleRoot` and
`sourceRoot`, a `keyPath` beneath `bootstrap`, a `/srv` data mount, an external
`backingFile`, integer `capacityGiB` from 32 through 4096, an immutable
`runscVersion`, and the approved archive `runscSha512`. There are no callbacks,
model credentials or arbitrary commands. The packaged fingerprint is independent
of the request. Existing storage evidence, output trees or admission uncertainty
are preserved and refused by fresh setup.

The original Bash process keeps the exclusive installer lock. Only the trusted
fixed Python/OpenSSL prerequisite stage can run before release authentication,
for a base VM lacking those tools. It uses a fixed OS package command and timeout
and validates actual executable availability; failure leaves its stage unresolved.
That timeout is not proof of remote or external effects being canceled. The
foundation worker is the direct child of that Bash parent and holds the parent
observer and complete schema3 authentication context across its effects. Each
Python phase runs with `-I -B`, captured sibling files and a cleared environment.

Packages run from captured authenticated Bash bytes before materialization.
This prevents package-induced ancestor metadata changes from being silently
rebased. Storage and preparation run from a fresh private staging tree. The
preparation phase creates the finite encrypted data skeleton and finishes all
direct-child changes before materializing the final execution root at
`DATA_DIR/company/host-releases/install-OPERATION`. Host records, storage guards
and service references persist that final root, never the temporary stage. The
runtime archive lives under `DATA_DIR/company/work`. The canonical storage
drop-in is preserved; build mount dependencies use a separate
`autosoft-builds.conf` drop-in.

Both materializers keep full-nine ancestor guards through caller use. A quiet
namespace is required: unrelated changes to `/opt`, the selected `/srv` ancestry,
or other guarded ancestors cause refusal. Neither the worker nor this design
authorizes blanket metadata refresh. Materialization or phase failure retains
partial trees and stage evidence. There is no automatic reconciliation or retry.

The worker independently observes the installation identity/receipt, backing and
LUKS mapping, exact encrypted XFS mount, Docker/containerd roots and health,
storage/build drop-ins, bounded build tmpfs, encrypted journal, swap absence,
retention policy, runtime archive and installed binary hashes, and all 62 captured
source/template/config/provenance leaves. The runtime hash probe intentionally
supports only the two regular root archive members `runsc` and
`containerd-shim-runsc-v1`; other archive shapes remain unsupported. It does not
unpack arbitrary runtime members. A second worker invocation remeasures those
effects and the persisted tree before returning the independent acknowledgement.
Child exit zero is insufficient. Uncertain held closes prevent completion.

The worker owns a second finite read-only guard for persisted output. Both fresh
measurement and separate verification keep all 62 leaf descriptors, the five
tree directories and every ancestor open, with full-nine path/descriptor
continuity. Directory enumeration uses those held descriptors with bounded
counts, and content is compared to the exact closed captured catalogs. The
guard is rechecked across measurement and fully released before acknowledgement;
any unknown close retains its owner reference and denies completion. This is a
new worker responsibility, not a change to the frozen materializer or catalogs.
Its 60-second logical budget applies separately to acquisition and each recheck,
not to time spent by the caller between checks. Native Linux FD/listdir behavior
remains unqualified by the synthetic filesystem controls.

The native runner is a single-thread, sole-reaper owner with default SIGCHLD,
pidfd and `waitid(WNOWAIT)`, sanitized environment, at most 48 commands, a
3600-second logical outer deadline and 4 MiB per output stream. It terminates
the owned group before reaping the leader, observes group absence afterward,
drains streams and retains uncertain resources. Logical deadlines do not bound
every potentially stalled kernel I/O. These POSIX mechanisms and real host
effects remain untested here. Tests inject process and host observations; they
never launch packages, daemons or installers.

Focused tests default to the actual public `scripts/install.sh`. Earlier
proposal-mode results remain separate historical evidence. Both company gates
explicitly clear `AUTOSOFT_FOUNDATION_TEST_PROPOSAL` before running the new suite,
so a private candidate cannot substitute for the public installer. The Linux
foundation checkpoint registered 42 modules and 18 fixture selectors. Subsequent
complete-source schema4 registration raises those counts to 44 and 20. Gate
registration and Bash syntax passed; neither a complete Linux pipeline nor an
image build ran for these integrations.

Full platform installation is explicitly pending. This slice does not initialize
the global checkpoint/allocation pair, activate applications, provision models or
identity, start backups, or assert production readiness. The [complete-source
schema4 APIs](company-platform-source.md) are now implemented and locally
checked; an actual signed artifact and safe seeding integration remain required.
The 44 host sources and 10 templates do not cover the complete platform source.
The original broad unsigned seed path remains unreachable in the public full-mode
function. A real native pair adapter and installer integration remain required.
