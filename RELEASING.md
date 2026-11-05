# Preparing the first public release

Public source availability and production installation readiness are separate
milestones. Describe a source preview as pre-release until the full installation,
recovery, security and user acceptance criteria pass.

## Owner decisions

The owner selected [Apache-2.0](LICENSE) and
[andreitex/-doxentriq](https://github.com/andreitex/-doxentriq). Preserve third-party
notices and confirm contributed code can be distributed under its stated terms.
Private vulnerability reporting is enabled for that repository; the verified
reporting route is in [SECURITY](SECURITY.md). Keep it working and designate
maintainers for incoming reports. Do not describe this development preview as a
production-supported release.

## Source review

Run the offline current-tree audit from the repository root:

```sh
python3 -I -B scripts/public-release-check.test.py
python3 -I -B scripts/public-release-check.py --report .local/public-release-report.json
```

Create `.local` first if it does not exist. The command reports filenames, finding
categories and line numbers, never the matching secret value. It exits nonzero for
missing licensing, credential patterns, deployment artifacts, operator paths,
trial endpoints and unreviewable files. It reads tracked files plus unignored
untracked files; ignored local work and dependency trees are not traversed.

Resolve each finding in a separate publication candidate. Preserve private
installation records in their existing protected location. Do not delete or
sanitize the only recovery evidence to make a public-source check pass. Replace
customer examples with synthetic examples and correct documentation links when
private verification records are excluded.

Prepare an explicit source-only candidate without modifying the working tree:

```sh
python3 -I -B scripts/public-release-export.test.py
python3 -I -B scripts/public-release-export.py --output .local/public-source-candidate
```

The output directory must be new. The exporter includes only maintained source
roots and root project files; it excludes installation receipts and personal
trial launchers. It replaces installation chronology with public procedures,
removes links to excluded private records, and leaves historical diagnostic
carriers without a configured SSH station. `PUBLIC-SOURCE.json` records every
included file's original/export hash, transformation and remaining blocker.
Tests and templates are retained. Review and test the exported candidate itself.
The exporter copies the owner-selected license without generating or changing
license terms. Missing licensing or a failed source check makes the command exit
nonzero. A source-hygiene pass does not establish production readiness.

The narrow `scripts/public-release-reviewed-fixtures.json` review list covers
known synthetic credential-URL tests and runtime URL templates by exact file hash.
A changed file invalidates its review. Provider credentials and private keys can
never be waived by that list. New or changed exceptions require source review.

The audit is a bounded heuristic check, not a complete secret or personal-data
detector. Independently review the entire staged diff, binary assets, generated
files, dependency provenance and license obligations. If Git history will be
published, scan that history as well. Revoke any real exposed credential before
publishing, even if it was subsequently removed.

## Build and acceptance

Run the TypeScript, UI, Go and affected installer tests described in CONTRIBUTING.
Build locked, digest-pinned images; scan the current dependencies and images with
fresh feeds. Retain SBOMs, license notices, signed release artifacts and verifiable
checksums. Review [dependency license metadata](docs/third-party-licenses.md);
source-only distribution does not discharge obligations for later binary images. Historical scans are not evidence that a new release is currently clear.

Complete clean install, rerun, interrupted install, reboot and failed encrypted
mount checks for every OS advertised as supported. Verify restore and rollback
with preserved business data. Publish only the OS/runtime combinations actually
tested, and document the single-VM availability limits.

Ask a person unfamiliar with the implementation to complete first login, app
creation, clarification, preview, publication, invitation and recovery from an
actionable failure using only the product and user guide. Record where help was
needed and resolve those usability failures before claiming nontechnical operation.

The manual **Public source readiness** workflow runs this audit on tracked files
and a separate source build with Node.js 24, locked dependency installation,
TypeScript/UI checks, and Go tests/vet using the declared compiler. Installation
lifecycle scripts and npm audit are disabled for that dependency installation.
The separate reviewed-public-package client checks current platform and DMS
advisories; unavailable results and Medium-or-higher findings fail the job.
Actions are pinned to reviewed official release commits. This is a workflow
definition; a green local run does not claim that hosted CI has executed.

The publication audit deliberately fails until blockers are resolved. The workflow
does not publish source, deploy software, access a customer environment or call a
model provider. Full native installer/recovery acceptance remains a separate lane.
