# Application storage quotas

The trusted host helper allocates one XFS project per application storage name.
Its authenticated local socket accepts only an application UUID, a bounded name
and a size in MiB. Generated applications receive neither this socket nor its
credential. Existing allocation sizes cannot be changed through this API.

A pending journal record is committed before directories or quota commands are
created. An interrupted or uncertain allocation keeps that record and its data;
another request for the same name cannot replay it. Company review and independent
native readback are required to recover such an allocation. Automatic recovery
and resizing are unavailable. Existing active allocations are checked using
read-only commands and are never reconfigured as part of a retry.

The helper checks the encrypted XFS mount, active project accounting/enforcement,
the directory's kernel project ID and inheritance flag, an independent installed
tool result, and the exact byte and inode hard limits. New directories remain root
owned until those checks pass, then receive the application owner. Directory and
journal metadata are synced before the active record is returned.

Commands have fixed argument lists, a ten-second execution limit and at most
32 KiB of stdout. Failure triggers bounded process termination and reaping. Client
reads time out after five seconds and the header/body admission has a ten-second
total deadline; at most four clients are served concurrently.
Journal files require root ownership, private permissions, a single link and
stable file identity. Journal replacement uses a fresh exclusive sibling file,
file sync and parent-directory sync. A process lock prevents a second helper
from replacing a working service socket.

Local tests exercise request/state validation, uncertain dispatch, failed commits,
failed directory sync, readback parsers, bounded subprocesses and retry behavior.
Filesystem ownership and quota operations are injected in these tests. Native XFS
enforcement, Unix-socket operation, power-loss behavior and quota-fill containment
remain unqualified. The test VM's installed helper remains its retained earlier
version; the source changes have not been installed or restarted there. Company
image/release qualification and native testing are required before rollout.

The current local receipt (private installation record; not distributed)
records two independent twenty-test runs, three syntax checks and the existing
deployment validation caller. The helper resolves its company-managed sibling
module without modifying Python's search path, retains the foundation call API,
and handles the protected root-group directory created by systemd. Earlier
receipts remain evidence for their earlier source.

The original failed metadata attempt (private installation record; not distributed) and retained-evidence readback (private installation record; not distributed) are preserved. Their partial read and unavailable private retention do not uniquely establish the historical exception cause. The writer correction (private installation record; not distributed) passed sixteen new controls; the corrected transport (private installation record; not distributed) passed fourteen new controls before one native dispatch. The completed observation and independent root review (private installation record; not distributed) verify eight installed files with 110,440,994 bytes read and hashed, exact release confirmations and all initial/final preservation guards. Root independently verified 129 stable local evidence files and exact wire/public, stdin and quoted-argument correspondence. Metadata qualification does not execute the observed tools. ABI compatibility, allocator exclusion, pending-map state and gVisor quota enforcement remain unqualified; no helper deployment or restart occurred.
