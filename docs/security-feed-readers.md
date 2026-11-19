# Shared security feed readers

This component coordinates individual feed reads by the maintenance scanner,
broker image scanner and broker source scanner, and binds their combined reports
and approval decisions to one observed snapshot. It does not enable feed refresh,
database promotion, public startup or clean-install eligibility.

Each Linux reader opens two existing zero-length regular files beneath the
protected `security-cache` directory: `.feed-admission.lock` and
`.feed-readers.lock`. Both must have one link, owner `root`, group `10001` and
mode `0440`. Readers never create, replace, repair or adopt these files. Missing
or changed protection makes scanning unavailable. Provisioning these permanent
lock files remains part of the future reviewed writer/initialization stage.

A reader takes an exclusive nonblocking admission lock, then a shared
nonblocking readers lock, and releases admission. The readers lock stays held
through the scanner call, existing cleanup and terminal feed validation. The
maintenance scanner takes its existing scanner lock first; the image scanner
takes its existing serialization slot first. A future writer must hold
admission exclusively while draining the readers lock, and must not acquire a
scanner lock in that scope. This prevents new readers from bypassing an
already-admitted writer. Busy readers fail closed without spinning or waiting
indefinitely; no fairness guarantee is claimed before writer admission.

The same file hashes, file/directory identities and lock inodes must survive the
read. Only the fixed OS database and optional complete Java database are
admitted. Metadata is bounded, duplicate-free UTF-8 JSON with the exact fields
`Version`, `UpdatedAt`, `NextUpdate` and `DownloadedAt`. OS schema is 2; optional
Java schema is 1. Timestamps use UTC with up to nine fractional digits. Maximum
age remains 24 hours with at most 60 seconds of future skew; `NextUpdate` must
be strictly later than both `UpdatedAt` and the actual current time. Equality at
expiry is refused, including at the terminal check. Download time must be
credible relative to publication and the current clock.

Python hashing checks a 60-second monotonic snapshot deadline between bounded
reads and again before returning. Go hashing imposes its own 60-second context
and retains any shorter caller deadline.
The cached status reader has a 30-second context. Database size ceilings and
existing scanner-image/version contracts remain independent controls; a hash
and a lock do not establish a valid vulnerability database or sufficient scan
coverage.

The existing feed-refresh refusal and initial gate's unavailable third-party
runtime-advisory coverage remain unchanged. No upstream signature or provenance
claim is invented by this component.

A report-local scope now captures one validated snapshot, releases its initial
lease, and requires every later reader and the final acceptance check to match
its database bytes, sizes and filesystem identities. Equal publication timestamps
alone are insufficient. The scope has at most 30 minutes to complete and inherits
an earlier cancellation deadline. It holds no outer lock between scans, packaging
or application work, so a writer can proceed between readers; a changed snapshot
makes the pending result unavailable. This is an acceptance deadline, not a new
time limit on existing image acquisition commands.

The VM report ends its scope before requesting application reports. Each app
report has a separate scope. Verification, connector approvals and live receipts,
publication and recovery use the same binding; nested connector work inherits its
caller's scope. Previously obtained findings survive later unavailable coverage.
The control API requires complete passed coverage before clearing older findings,
including when a partial report has status `failed` because it found a vulnerability.
No report schema or historical receipt is rewritten.

Before a writer can be enabled, these concrete integrations are still required:

- The source scanner now uses the image scanner's recorded create/inspect/start/
  stop/remove lifecycle, with its own fixed read-only workspace, no-network and
  1 GiB profile. Unknown create outcomes and unconfirmed cleanup retain a shared
  blocker and preserve the exact owned build workspace. Image journal v1 bytes
  remain compatible; source v2 records carry an explicit source path and the
  actual built-in no-network ID. This implementation still needs live scanner
  qualification. Process death releases locks but does not establish container
  absence; a future writer must independently establish scanner quiescence.
- Bounded acquisition, authenticated provenance, tested scanner compatibility,
  interrupted promotion recovery and genuine host-runtime advisory coverage
  remain required. Lock provisioning alone cannot satisfy them.

The original feed-reader qualification passed 85 Python cases and 10 Go
top-level tests without skips. These include actual root-owned Linux fixtures, Python/Go cross-process
reader/writer contention, current-time expiry without byte changes,
replacement/link/ownership refusals and real scan callers using controlled
transports. The Go test binary was compiled as UID65534, then run separately as
UID0 with only `CAP_CHOWN` added, no network, a read-only root and input, and a
bounded temporary filesystem. Both private test containers were removed.

A later source-scanner lifecycle run passed 38 top-level cases plus one
synthetic child-process fixture, with zero skips. The same compiled binary
separately passed 17 existing source-binding, verification-wire and pipeline
regressions without skips or recompilation. Coverage includes unchanged v1
journal bytes and canonical hashes, exact owned-container cleanup, cancellation,
unknown outcomes, panic-time workspace preservation and feed checks through
cleanup. Container API responses are controlled test inputs; these results do
not qualify a live scanner. The initial failed compilation and its diagnostics
remain preserved separately.

The later report-binding component run passed 76 substantive Go cases plus one
synthetic child-process fixture and a separate UID/GID 10001 case with no added
capabilities. It also passed 104 Linux Python cases without skips. These cover
writer admission between reads, changed bytes with unchanged timestamps, identity
and Java-membership drift, cancellation, expiry, final lease-close failure,
retained findings, and refusal before connector or publication acceptance. A local
control API regression separately confirmed that incomplete failed reports retain
prior findings and block approval until complete coherent coverage is received.
The initial Python preservation-check failure is retained; its corrected test
projects only the exact new additions before checking the unchanged original
security boundaries. No production scanner behavior was relaxed to pass it.

Ordinary unprivileged or non-Linux test runs skip
only the fixtures that require real root-owned Linux locks; they do not replace
the production lock with an in-process success path. Native component tests and
live scanner/feed qualification are distinct; no VM or clean-install acceptance
is claimed here.
