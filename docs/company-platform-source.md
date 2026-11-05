# Complete company source artifacts

Schema4 adds complete platform source authentication as an explicit API. It does
not enable full installation, initialize the runtime pair or seed the shared
repository. The schema2/3 APIs, fixed 44 host sources, ten deployment templates
and 62-file foundation output retain their existing contracts.

The local acceptance record (private installation record; not distributed)
retains 35 source-format controls, 32 schema4 controls and 71 unchanged
compatibility controls, all passing without skips. Independent module, release
and gate reviews passed. Both company gates register these suites, bringing the
Linux registry at that checkpoint to 44 modules and 20 fixture selectors; five embedded Python
blocks and Bash syntax passed. No complete Linux pipeline, image build, company
signing operation or native installation ran for this checkpoint. Earlier failed
fixtures and evidence-reader attempts remain preserved.

The subsequent authenticated source and repository initializer checkpoint (private installation record; not distributed)
passed 23 issuance controls, 32 schema4 controls and 51 initializer controls,
without skips. Independent issuer, initializer and gate reviews passed; root
verified 74 stable inputs. The current company gates register 46 modules and 22
fixture selectors. Earlier repeated runs are historical evidence and do not add
to these 106 distinct latest passes. See [repository initialization](company-repository-seed.md)
for its separate authority, storage and native qualification requirements.

The signed release names exactly seven inputs: `images.lock.json`,
`runtime-manifest.json`, `approved-mirrors.json`, `company-sources.json`,
`company-deployment.json`, `platform-sources.json` and
`platform-sources.tar.gz`. The release signature, independent public-key
fingerprint and architecture are verified before loading a source helper.

`authenticated_platform_source` requires an explicit protected source root. It
reads `scripts/platform_source.py` through protected original handles and binds
its exact bytes, size and Git mode to the authenticated full-source manifest
before execution. It does not import a candidate sibling. The archive is hashed
before parsing; all captured members and both independent host/template catalogs
must match. The returned capability carries immutable source bytes, modes,
configuration and raw signature provenance. Access and context exit recheck
original inputs; a failed check expires the capability. Uncertain closes block
completion. Native crypto and filesystem behavior need separate qualification.
The verifier privately registers the exact capability issued by its authenticated
context. `require_platform_source` checks exact type, registered identity, live
original-input rechecks and known handle disposal before and after access;
constructor flags or copied maps cannot issue a capability. This is an API
provenance control inside trusted company code. It does not isolate hostile code
running inside the same Python process.

The guarded `archive_bytes` getter retains the original authenticated compressed
bytes and validates their signed length and hash. Consumers must not recompress
the source or reopen a mutable bundle to reconstruct that artifact. Metadata
also retains the independently checked `signingKeyFingerprint`. Both are needed
by the separate company-owned storage operation.
Read-only schema4 bundle, key, helper, archive and signing-station inputs use a
separate full-nine directory guard. The earlier small `Snapshot` and schema2/3
policies stay intact. Fresh signing outputs retain the existing five-field
directory identity for intentional writes, with exact eight-name inventory and
held file-content readback during and after creation.

The producer `prepare_platform_payload` uses one live `capture_git_revision`
context to derive the full archive and both smaller catalogs. The caller supplies
an independently selected Git SHA1 revision and a trusted bounded Git adapter.
It verifies the committed tree and stage-zero index, refuses untracked or ignored
files, and compares every tracked file's raw bytes and mode with that tree.
Configured clean filters are not used to compare working files. Replacement and
lazy object fetching are disabled. Git blob/tree identities are recomputed from
captured bytes; signed SHA256 values separately bind every member and archive.
The command interface follows [Git index listings](https://git-scm.com/docs/git-ls-files)
and [Git replacement/fetch controls](https://git-scm.com/docs/git). Availability
on the supported OS/tool versions remains a native qualification requirement.

The fixed source policy includes company administration/control code, packages,
services, database, models, deployment inputs, scripts, tests, documentation,
templates, tools and the declared root build files. Every tracked path must
satisfy that policy. Secrets, generated applications, reports, caches, links,
submodules and unknown roots cause refusal rather than silent omission.
Artifacts and signing scratch space must be outside the clean producer tree.
A consumer verifies the signed inventory; only the producer's independent Git
capture establishes that the inventory includes the chosen complete tree.

The versioned manifest records the source revision/tree, file count, total
bytes, archive hash/size and each path's length, SHA256 and `100644` or `100755`
mode. Paths are canonical ASCII, sorted and unique, including directory case
aliases. The archive contains deterministic regular USTAR members in manifest
order and one gzip stream. Validation accepts no extra members, links, devices,
PAX/GNU extensions, sparse records, noncanonical headers, concatenated gzip
streams or trailing data. Nothing calls `extractall`.

Initial capacity limits are 2,048 files, 512 derived directories, 256-byte paths,
8 MiB per member, 64 MiB of source data, a 1 MiB manifest, a 32 MiB compressed
archive and 96 MiB of expanded tar data. These are refusal limits, not native
capacity or performance qualifications. Input admission and archive checks
precede builder output. Output uses exclusive creation; partial output survives
failure and prevents automatic replay.

The offline signer has an explicit `--complete-platform-source SOURCE_ROOT`
selector. Its unsigned snapshot API requires independently trusted station
code, captured separately from candidate inputs; root ownership alone does not
establish that trust. Existing signing selectors retain their earlier behavior.
The schema4 producer is an explicit callable API; the image-build wrapper still
produces schema3 and does not infer a native Git runner or complete-source pass.

The [producer Git runner](company-git-runner.md) now has independently reviewed
source and 42 passing injected controls. It retains the fixed seven-command
protocol and requires a dedicated sole-reaper caller. Native Linux capture and
complete producer qualification remain pending.

The reviewed customer-repository API constructs and verifies exact Git objects,
tree, commit and index, retains installation provenance and preserves unknown or
interrupted repositories. The historical mutable `rsync` initializer now refuses
execution. Separate encrypted company-owned artifact storage and native caller
assembly remain required before installation can use these APIs. Actual signed
artifacts, original-parent/runtime-pair integration, security eligibility and the
supported clean-install matrix remain required.
