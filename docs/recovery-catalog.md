# Combined recovery catalog

Nightly and incremental maintenance now use one protected recovery catalog at
`<encrypted-data>/backups/recovery-catalog`. A numbered immutable generation holds
both the binary-log/document cursor and the archive index. Its hash-bound current
pointer is published only after the generation is fsynced and read back. A durable
confirmation binds the exact intent, generation and pointer. No separately
truncated cursor or index remains authoritative.

This is **RECOVERY_CATALOG_ONLY**. The recorded boundary identifies the original
containers selected by `QuiescedContainers`, with `globalWritersQuiesced: false`.
It does not coordinate every registry/daemon/quota/maintenance writer or prove a
complete backup, external-system consistency, restoration or production readiness.
The catalog's returned `backupReady` is always false.

The permanent exclusive catalog lock is acquired before capture intent and held
through archive creation and combined commit. Maintenance holds its existing
maintenance lock first, then the catalog lock, then the original-container
boundary; no checkpoint Gate shared lease is acquired. Both capture paths commit
inside that boundary before its final confirmation and original-only resumption.
Encryption or catalog failures retain their intent and output; the existing
boundary still attempts only the original containers' resumption. An unsuccessful
capture never reports a successful recovery checkpoint.

Native access checks bind the canonical data root, private root-owned same-device
directories, permanent lock inode and held directory/file descriptors. Records
have exact schemas and bounded reads. Each capture streams, hashes and fsyncs the
exact protected ciphertext before publication and verifies it again before the
terminal record. Current history validates generation, parent/base, cursor/index
and operation-directory hash/identity correspondence; referenced retained files
must match their recorded metadata. It does not reread every historical archive's
ciphertext on every metadata read. Pruning rehashes every selected original before
its intent and exact removal.

## Explicit fresh initialization

The company must first independently verify the encrypted mount, canonical
installation identity and protected placement. The root-only maintenance parser
has a concrete standalone route:

```sh
python3 <installation-root>/scripts/maintenance.py initialize-recovery-catalog
```

Maintenance validates the configured encrypted mount and obtains its existing
maintenance lock. The initializer accepts only absent catalog state and empty
archive directories. Either legacy `binlog-cursor.json` or `recovery-index.json`,
prior archives, partial initialization, pending capture/pruning, unknown records,
missing metadata or mismatched hashes are preserved and refused. Backup never
initializes or adopts state. Existing installations require a separately reviewed
company migration; this change provides no migration, reset or automatic replay.
The `autosoft` convenience CLI and installation wiring are separate work.

## Pruning and uncertainty

Pruning uses the same exclusive lock and combined generation. It retains every
base required by a checkpoint newer than the 30-day cutoff and the current cursor,
removing an eligible base only with all its descendants. The new projection stops
referencing selected files before exact deletion; a terminal confirmation is
written only after those removals are confirmed. A failed removal or commit keeps
pending evidence and blocks later captures; absence alone is not completion or
permission to retry. Historical catalog generations and operation records remain.

A valid durable terminal assertion follows independently checked ciphertext and
metadata. Losing its return acknowledgement can leave that valid catalog commit
readable, while the maintenance call still fails. Failure before that assertion
retains uncertainty. Neither a lock becoming free nor process death, expiry or a
successful subprocess exit creates a catalog confirmation.

## Finite, unqualified capacity

This first catalog has no scalable epoch compaction. Limits are 4,096 committed
mutations, 4,096 current archives, 50,000 document hashes per cursor, 8 MiB per
metadata record, 512 MiB of retained generation/operation records, and 256 GiB per
encrypted archive. It reserves 24 MiB for the next intent/generation/confirmation
before admitting an effect. Count, index or retained-byte exhaustion refuses
capture before container stops or encryption and requests company maintenance.
A new manifest exceeding its record/document bound is retained as an unresolved
capture rather than advanced or silently truncated.

At one nightly plus 96 daily incrementals, 4,096 mutations alone last about 42
days; pruning also consumes mutations. Large document inventories can exhaust
retained bytes much sooner. Full snapshot history validation includes bounded
parent-chain walks and can be expensive. These bounds and throughput are
**UNQUALIFIED for production and for a 30-day scalable retention guarantee**.
The 30-day cutoff is an archive eligibility policy, not a capacity promise.
Filesystem I/O/fsync duration is not bounded by the finite (at most 30-second)
lock-acquisition deadline. Company compaction/migration and Linux/power-loss
qualification are future work; there is no automatic history deletion here.

## Local controls

`scripts/test-recovery-catalog.py` retains synthetic fixtures under
`AUTOSOFT_TEST_ARTIFACT_ROOT` (default the repository's `.local`). It exercises
actual catalog and maintenance/QuiescedContainers methods with every container,
GPG and external-copy sink injected. Synthetic pruning moves fixture bytes to a
retained directory and never deletes an actual backup. Windows tests inject root
policy, flock, directory descriptors/fsync, held-file replacement and read-only
descriptor fsync; maintenance inventory names receive POSIX normalization only
in that fixture. These passes do not qualify native Linux locks, encryption,
container actions, encrypted mounts, restoration or global writer coordination.
