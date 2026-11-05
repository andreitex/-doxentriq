# Runtime image scanner capacity

The OS feed member `trivy/db/trivy.db` admits sizes from 1 byte through
2 GiB (2,147,483,648 bytes). The retained October 13 observation reported an
OS database of 1,607,704,576 bytes; this fits the size policy. Java remains
limited to 512 MiB, and each metadata file remains limited to 64 KiB.
Only the existing four exact feed-member paths receive a limit. Unknown
paths, aliases, empty files and oversized files remain unavailable.

The production reader applies this size admission before opening a feed
member. Its existing 64 KiB streaming buffer, incremental hash, context
cancellation, total-byte ceiling and file/ancestor continuity checks are
preserved. Size admission does not establish database validity or feed
provenance. The new boundary tests do not create or hash multi-GiB fixtures.
The existing `oversized_db` control now exercises the production admission
helper directly instead of creating a large sparse file; its remaining
variants still exercise the existing feed reader.

The image-scanner container requests exactly 3 GiB of memory and 3 GiB for
Docker's combined memory/swap ceiling. Both inspector fields must match
3,221,225,472 bytes before start and during cleanup. An old 1 GiB profile,
different swap limit or post-seal resource drift blocks start or leaves
cleanup unconfirmed. The CPU, network, PID, 128 MiB tmpfs, credentials,
mounts, environment and cleanup rules retain their previous policy.

Local tests qualify size-policy and injected lifecycle enforcement only.
They do not establish that 3 GiB is sufficient for this database, open a
real Trivy database, launch a scanner container, activate a feed, or grant
production security eligibility. Linux-only file/link/synchronization
controls and native scanner acceptance remain separate requirements.
