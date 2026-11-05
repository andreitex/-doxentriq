# Host quota admission boundary

Quota provisioning validates its request and encrypted XFS mount before taking a
checkpoint shared activity lease. It then takes the independent protected
`quota/allocation/allocation.lock` exclusively. The lock's permanent inode and
the quota, runtime, storage, allocation and commit directories are bound by the
explicit initialization record. Another process must use the same allocation
lock; the quota helper's existing thread lock is only an additional restriction.
Each allocation lease is live only inside its owning process/thread's scope,
with bounded call serialization. Scope exit invalidates it before unlock/close;
a released object cannot borrow a later lease through descriptor-number reuse.

The leases remain held through the projects read, pending reservation, directory
and native quota writes, verification, directory sync, exact active state and
final native path/ownership/size/limit readback. A possible-effect record precedes
the pending commit. An admitted operation may finish while the checkpoint is
CLOSED; new operations cannot enter. Neither the broker nor a parent caller
takes a second checkpoint lease. Parent/child delegated admission is unsupported.

`projects.json` must already exist. Its semantic hash and next ID are bound to a
durable allocation pointer and retained monotonically numbered commit intents.
Missing/malformed state, replacement of a bound directory or lock, a reset
projects table, an older pointer, or an incomplete commit fails closed. Existing
IDs, sizes and records cannot be deleted or reassigned. No partial commit or
unknown native result is automatically replayed, adopted, repaired or pruned.

The company must explicitly initialize the checkpoint Gate, then call
`quota_runtime.initialize_allocation(data, installation_id)` after validating the
intended mount. That source interface independently validates the mount, admits
the initializer, and accepts only absent allocation/projects metadata and empty
storage. Interrupted initialization is retained; it cannot restart implicitly.
No installer/startup/service wiring or installed VM initialization is included
in this slice. Existing populated installations require separately reviewed
migration/recovery rather than treating missing metadata as fresh storage.

An exception before any effect marker or completion attempt can be recorded as
an abort before business effects. Errors after marking and before independently
confirmed terminal evidence retain uncertainty.
Completion asserts only an independently verified local quota outcome. If the
valid durable terminal assertion was written but its acknowledgement is lost,
it remains confirmed; a client disconnect or failed HTTP write cannot undo it.
No PID, timeout, lost response or released lock proves an external effect ended.

This boundary covers the quota writer only: **HOST_QUOTA_ONLY**. It does not
coordinate registry, daemon, image, database, broker, backup or recovery writers.
Checkpoint readiness remains **PRIMITIVE_ONLY** with `backupReady: false`.
Allocation lock waits are bounded to ten seconds; filesystem and native command
durability are not universally bounded under stalled kernel IO. Commit inventory
is count-bounded to 20,000 commits; no automatic evidence cleanup is provided.

Local controls exercise actual Gate and allocation code with retained synthetic
files and injected Windows ownership/directory-sync/flock policies. They do not
qualify native Linux flock, XFS, encryption, reboot, power loss or installed
helper behavior. Run the new controls with `python3 scripts/test-quota-admission.py`;
the company-only `AUTOSOFT_TEST_ARTIFACT_ROOT` selects an existing protected test
artifact directory, defaulting to the repository's `.local`. Legacy quota
controls retain their native/journal assertions with fixture-only admission
adapters. Company pipeline registration and clean-install qualification remain
separate work.
