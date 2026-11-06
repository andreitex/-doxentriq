# Public repository secret audit

Audited **November 6, 2026**. No live credentials were found in the public
material described below. This is an evidence-based result for a specific
snapshot, not a guarantee about every possible secret format or external copy.

## Snapshot and coverage

Repository: [andreitex/-doxentriq](https://github.com/andreitex/-doxentriq).
Audited main commit: `1ff9302f1a67582568514088882fd89fa195df13`.

| Surface | Result |
|---|---|
| Advertised public Git refs | One branch, no tags or pull requests; all four reachable commits inspected in an independent bare mirror. |
| Reachable Git objects | 647 distinct blobs, 57 trees and four commits; 8,751,994 bytes inventoried. Both history diffs and complete non-tree object contents were scanned, including files removed from the current tree. |
| Generated GitHub source ZIP | All 632 files matched the audited Git tree byte for byte. The archive was also scanned. |
| GitHub Actions logs | All three available workflow-run log archives, containing 12 log files, were downloaded and scanned. No findings in these logs. |
| Release assets and Actions artifacts | No releases, tags or uploaded Actions artifacts existed at the time of the audit. |
| GitHub secret-scanning alerts | Zero open alerts and zero resolved alerts. Native secret scanning and push protection were enabled. |
| Known installation credentials | A read-only comparison ran inside the installation against 33 scoped files: 44 configured mounted references plus the explicitly named OpenAI, Anthropic and Google configuration files. None of the 48 extracted credential representations matched the 92,384 public literal/token fingerprints from Git and Actions logs. |

The installation comparison exported neither credential values nor unmatched
credential hashes. Credentials were not submitted to external providers for
validation, rotated, or changed. Repository history was not rewritten.

## Detector and reviewed matches

[Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) was
obtained from its official release. The archive matched both the published
checksum and the GitHub release asset digest. Output was fully redacted, and
repository-specific ignore rules and inline allow comments were disabled.

Seven detections were reviewed against exact source bytes:

- Two deterministic Stripe signing-secret fixtures used by isolated UI tests.
- A synthetic provider-header marker used with a replaced test fetch function.
- A UUID fixture used to test credential redaction from request identifiers.
- A deliberately fabricated canary in a model-safety evaluation prompt.
- A test-helper source-integrity SHA-256 pin.
- A public Go module-integrity checksum.

The complete-object pass examines blobs without filename-based exclusions; this
also brought the Go checksum into review. No unresolved detections remained.
The narrow reviews are recorded in
[public-history-reviewed-fixtures.json](../scripts/public-history-reviewed-fixtures.json).
Each binds the path, complete blob SHA-256, rule and line. Changing the file
invalidates its review; an entire test directory is never excluded.

## Repeat before publication

Use a fresh mirror or a complete fetch of the public refs. A shallow checkout is
not sufficient. Obtain a verified Gitleaks executable for the current operating
system, then run the offline gate:

```sh
python3 -I -B scripts/public-history-audit.py \
  --repo /path/to/complete/repository \
  --gitleaks /path/to/verified/gitleaks \
  --gitleaks-sha256 VERIFIED_EXECUTABLE_SHA256 \
  --reviewed-fixtures scripts/public-history-reviewed-fixtures.json \
  --report /private/audit/history-report.json
```

The gate disables Git replacement objects and lazy fetching, isolates inherited
Git configuration, and disables hooks, filesystem monitors, external diff and
text conversion. It refuses shallow history, grafts, alternate object stores,
Git LFS pointers, submodules, unavailable scanners, unredacted scanner reports,
oversized inventories and refs that change during the scan. LFS objects and
submodules need separately scoped audits before publication.

The automated regressions include an actual scanner test with a fake token
removed from the latest tree and another hidden behind a Git replacement. The
original credential-shaped bytes must still be detected, without appearing in
the report. Configure the two `DOXENTRIQ_GITLEAKS_TEST_*` variables with the same
verified tool to run these integration checks; otherwise they are explicitly
reported as skipped.

A history gate complements the current-file
[publication checker](../scripts/public-release-check.py). Hosted Actions logs,
release assets, package registries and known installation credential comparisons
remain separate checks because a Git-only scanner cannot inspect them.

## Limits and incident handling

This audit covers the advertised refs, artifacts and credentials available at
the recorded snapshot. Deleted or inaccessible refs, previous credentials no
longer available for comparison, forks, external caches and copies held by
other people cannot be ruled out by this result. Encoded, split or unusual
credential formats can also escape pattern and exact-value comparisons.

If a real credential is found later, preserve redacted evidence and identify
its owner. Revoke or rotate it through the responsible provider, then review
history and hosted-artifact removal as a separate action. Deleting a Git commit
alone does not revoke the credential or remove external copies.
