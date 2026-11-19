# Source scanner coverage candidate

Native component checks passed for this source: 68 main cases, one synthetic
process fixture, and a separate UID/GID 10001 permissions case, with no skips.
These checks cover code contracts and filesystem behavior in fixed local test
profiles. They do not qualify live Trivy scanning, runsc or SELinux.

The maintained deployment source names Trivy 0.75.0. Its report structures define
schema 2, artifact type `filesystem`, optional Results, and a `Trivy.Version`
field. Secret results omit Type. Misconfiguration results use Class `config`
with separate status/summary fields. The private 0.76.2 physical-binary scans
do not qualify this source contract; this candidate rejects that version.

Confirmed source paths:

- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/types/report.go
- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/scan/local/service.go
- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/result/filter.go
- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/fanal/analyzer/analyzer.go
- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/fanal/analyzer/language/python/pip/pip.go
- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/dependency/parser/nodejs/npm/parse.go
- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/flag/package_flags.go
- https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/flag/report_flags.go

Observed gaps in the original maintained path:

- Schema >=2 plus absent/null/empty Results can yield zero findings and a source
  security pass without artifact, analyzer, target or package evidence.
- Ordinary Go struct decoding accepts duplicate/case-aliased fields; a later
  Results array can overwrite an earlier result containing a blocking finding.
- Python acquisition uses requirements.lock. The default pip analyzer selects
  requirements.txt, so an immutable retained lock alone is not positive coverage.
- Development dependencies are installed and used by builds; Trivy excludes
  them by default unless include-dev-deps is set.
- An inaccessible imported or historical snapshot must not yield a clean scan.
  The intended runtime layout uses UID/GID10001 with0700 directories and0600
  files, matching the scanner. A root-owned negative fixture does not establish
  a deployment defect. Actual scanner skip/error behavior still needs a live
  probe; neither behavior authorizes a clean scan.

The explicit list-all-pkgs flag is not a fix for a disabled default: 0.75.0
already defaults it to true. Pinning it makes the intended contract reviewable.

The proposed finite contract supports one authoritative root npm v2/v3 lock or
hash-pinned pip lock. It captures inventory from caller-bound immutable source,
never from the scanner report. Npm includes all lock entries, including dev and
transitive packages, with exact-name/version deduplication matching the source
parser. Explicit npm names must equal their node_modules-derived identity and
resolved URLs must be the exact canonical registry tarball for that name/version;
aliases or inconsistent URLs are unavailable. All85 entries in the maintained
DMS v3 lock match this contract, including69 dev and53 optional entries. The
component test binds the two actual manifest files and all85 expected identities.
Pip supports exact pinned lines with one or more SHA256 hashes and
backslash continuations. Unsupported dialects, alternate/nested source lock
authorities, recursive requirements, markers, ranges, workspace links and
unrecognized evidence are unavailable. Package identifiers in extra recognized
scan results are validated and all their findings retained, but those results
cannot replace root-lock coverage. Valid independently empty locks may have no
dependency result; this is not inferred from empty Results.

The scanner command adds explicit list-all-pkgs, include-dev-deps, disabled
secret-config loading and the fixed analyzer pattern `pip:^requirements\.lock$`.
The original source filenames, historical releases, scanner image, UID, network,
resources, feed locks and owned-container cleanup remain unchanged. Caller input
includes the existing source-binding version, template and trusted source hash.
Verification captures the final lock-bearing source hash before custom commands.
Daily/rollback paths use the existing receipt hash. Original input files must
still match the scan tree before/after; additional generated outputs are allowed.

Configuration checks mean recognized IaC checks, not validation of arbitrary
application JSON or all business/security logic. Secret findings are necessarily
sparse; absence is not a positive file-by-file scan inventory. This candidate
does not manufacture secret/config results for empty projects. Native
qualification must establish the exact tool behavior and preserve those limits.

Required bounded live qualification, using public synthetic fixtures only:

1. Exact company-approved image digest/version, same runsc/UID10001/no-network
   profile and pinned fresh DB/check inputs. A new version requires a separately
   reviewed source contract; do not change the maintained image implicitly.
2. Npm v2/v3 fixtures with scoped, nested/transitive, dev-only and duplicate
   name/version packages. Include installed node_modules with bundled example
   locks. Compare exact reported targets/package identities, not only counts.
3. Python hashed requirements.lock with continuations and a requirements.txt
   control. Demonstrate the fixed file pattern actually selects the .lock file,
   preserves normalized names/versions and detects a known Medium+ advisory.
4. Known vulnerable/fixed npm and Python package pairs, plus independent valid
   zero-dependency controls. Confirm omissions/null shapes and tool version.
5. Synthetic recognizable secret and safe control; recognized IaC fail/pass
   pair; malformed/unreadable inputs and unsupported dialects. Confirm JSON
   Type omission, summaries, status values and ordinary exit behavior.
6. Feed replacement/staleness, cancellation, output truncation and source drift
   must remain unavailable, with confirmed exact-ID cleanup or preserved owned
   input if uncertain. Component tests cover logic; live runs cover the actual
   tool/runtime boundary. No fixture result establishes complete vulnerability
   coverage or permission to publish.

Permission qualification uses the intended same-user layout: compose declares
the broker user10001:10001, bootstrap creates its build tmpfs with that ownership,
and runtime_layout.py assigns and checks sources/builds ownership10001:10001.
The runtime's ownership() call is self-ownership for these files; cap_dropALL
alone is not evidence of failure. A separate component test runs as10001:10001
with all capabilities dropped and no-new-privileges, calls the actual ownership()
and coverage checks on0700/0600 build and retained-source inputs, and verifies
unchanged identities/modes without scanner or host commands. This does not
qualify Trivy, runsc or SELinux. Root-owned inaccessible fixtures remain negative
controls only. A copied scan view is needed only if a supported real deployment
is shown to retain inaccessible source; this candidate neither changes original
permissions nor adds that currently unproven requirement.

Recorded component checks used Go 1.27.3 and covered report ambiguity,
version/artifact/target mismatch, exact package coverage, zero dependencies,
threshold findings, supported extra results, lock dialects, caller/source drift,
post-cleanup drift and immutable permissions. The actual DMS manifests and all
85 dependency identities were included. Selected lifecycle, image, feed, caller
and recovery cases passed on the same binary. The separate permissions case ran
as UID/GID 10001 with no capabilities and no-new-privileges. All three owned test
containers were removed; source, SDK and DMS inputs were preserved. The earlier
test-source compilation failure remains recorded separately. No live scanner or
end-to-end publication qualification is inferred from these component results.
