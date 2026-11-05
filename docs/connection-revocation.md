# Explicit filesystem connection withdrawal

The protected Connections view supports permanent withdrawal of one retained filesystem connection for one application. Only the configured permanent local owner with MFA can review and authorize it. This is separate from registry metadata edits, source-catalog monitoring and app release rollback. Samba withdrawal is unavailable for historical receipts that do not retain original immutable container IDs; no name-based stop is offered.

The review binds the original approved scope, current registry hash, exact plain-language impact hash and complete independently inspected sidecar inventory. It includes retained preview and published candidates. Container IDs and stable configuration/mount profile hashes are shown; host source paths and credentials are excluded. The review expires five minutes after inventory observation. Any changed inventory or scope requires a fresh review before first execution.

The control API consumes the exact approval and persists an operation intent in MySQL before one signed broker dispatch. The broker independently verifies the original encrypted approval/candidate/network/live receipts and complete all-container inventory under the app lock. It writes an encrypted app/connection tombstone, synchronizes the file and all containing directories, and reads back the exact payload before stopping any container. A failed synchronization never authorizes a stop. A boot/timer retry must successfully synchronize and read back the retained intent again before continuing.

Retention remains beneath the trusted configured absolute runtime-data mount. The runtime checks that this root and its descendants are directories without symlinks or group/other write access; synchronization terminates at the normalized mount root. It does not introduce an ownership policy for ancestors outside that trusted mount.

Only original full Docker IDs with matching retained source, image, scope, mounts, sealed configuration and private-network provenance can be stopped. The implementation does not remove containers, volumes, documents, credentials, application records or databases. Partial independently confirmed stop receipts are preserved. Unknown IDs, replacements, changed profiles, unavailable inventories and uncertain stop outcomes remain pending with the permanent tombstone retained. A completed status requires a fresh final independent stopped-state check for every exact target. Missing/stale/unavailable current runtime readback demotes cached completion to pending, preserving prior stop evidence and denying access.

Runtime status inspection never sends a stop request; it can persist current readback evidence. Bounded broker startup and sixty-second reconciliation passes finish only the already-authorized original stop intent. Busy app locks and unavailable provenance can delay completion. The older filesystem source watcher evaluates catalog/inode/expiry/qualification independently and does not use an unsynchronized explicit-withdrawal file as stop authority.

Both adapter admission entry points and provisioning replay branches deny access when the app/connection tombstone is present. Corrupt, linked, unreadable or unsupported tombstones also deny admission. The control API excludes pending/withdrawn app scopes from generation context, rechecks withdrawal after asynchronous broker evidence, and blocks provisioning. Other apps authorized for the same registry connection remain independent. App code rollback cannot restore a withdrawn grant; regrant requires a new registry connection ID and new scope approval. Rolling back the company platform to an older version unaware of tombstones is outside this guarantee and must not be used as a regrant mechanism.

Expired/disabled registrations, archived apps and withdrawn source catalogs can still be explicitly withdrawn when their original immutable provenance is retained. These stop rights do not grant new access. Lost approval/dispatch responses are inspected without blind replay. An unused approved review must expire before a fresh attempt; a dispatched uncertain operation remains pending for inspection and company reconciliation.

## API boundaries

- `GET /api/v1/connections/:id/revocation?appId=...`: protected current operation inspection.
- `POST /api/v1/connections/:id/revocation/approval`: prepare exact review for `{appId}`.
- `POST /api/v1/connection-revocations/approvals/:id/approve`: approve `{artifactHash}`.
- `POST /api/v1/connections/:id/revoke`: consume `{approvalId}` and send the single signed intent.
- Internal broker: `/v1/connectors/revocation/snapshot`, `/v1/connectors/revoke`, `/v1/connectors/revocation/status`.

Local injected protocol tests cover owner/MFA and hash binding, inventory changes, durability-before-stop ordering, partial recovery, response loss, stale/current status, duplicate dispatch, app isolation and generation races. Linux file/directory synchronization has a separate native test that is skipped on Windows. These source tests are not a live deployment or image qualification. Frozen 1726/2003 archives and their VM evidence remain unchanged and do not claim this new behavior.
