# Host remediation proposals

The internal planner in `scripts/host_remediation.py` produces an exact proposal from an installed-package inventory, supported running-kernel identity, complete fresh scan, authenticated vendor candidate metadata and a bounded package-manager simulation. It handles only known Medium, High and Critical findings. Missing coverage, ambiguous identities, stale feeds or unavailable vendor evidence leave the proposal unavailable.

Repository authentication is a typed result from trusted verification code. It cannot be accepted from a JSON field claiming that metadata is signed. The maintained live signature-chain verifier and package-manager query adapters still require integration and qualification.

The planner also has an explicit DNF 4.20.0 pending-transaction `0.0` parser, separate from the stored-transaction `1.0` parser. It requires a typed `Dnf4PendingEvidence` result from trusted native adapter code: exact document, inventory and repository bindings; complete native replacement pairs with positive RPM version comparisons; and explicit install-only classification. Hash strings alone are insufficient, and this type must never be constructed from administrator-supplied JSON. Native `unknown` reasons remain unknown. The parser rejects removals, downgrades, reinstalls, unpaired replacements and unsupported group operations.

The new local DNF4 parser receipt (private installation record; not distributed) records 49 passing checks. Its saved native fixture contains 121 rows from an actual isolated offline DNF solve: 58 upgrades and five kernel additions, preserving the existing kernel packages. This proves parsing of that output, not complete live planner integration or an applied update. Rocky package and scan parsing now handle alphabetic versions and the caret operator using a separate bounded [RPM version grammar](https://rpm.org/docs/6.0.x/man/rpm-version.7); Debian parsing is unchanged. Repository trust, source-epoch projection, complete security coverage, a qualified live adapter, recovery rehearsal and approval remain separate requirements.

The planner reconciles all APT or DNF simulated additions, upgrades and removals against the original inventory. It refuses essential or running-kernel removal. Kernel updates preserve the installed running kernel and require a reboot; installing a kernel does not prove that the machine is running its fixed version. Vendor advisory resolution determines candidate applicability; a scanner's fixed-version string is insufficient.

Every proposal reports `tested:false` and `applyAuthorized:false`, with recovery checkpoint and approved maintenance window required. This source does not execute queries, install packages, reboot, provide an apply command or claim that a fix has been tested.

The local planner receipt (private installation record; not distributed) binds the source, root and independent 38-test runs, and two syntax checks. Tests use synthetic inventories, vendor proofs and transaction outputs; they do not qualify native APT/DNF versions or signature verification.

The separate internal `scripts/host_queries.py` adapter queries a new protected
copy of the installed-package database with fixed dpkg/RPM arguments. It retains
bounded private output and checks the original metadata, copied files, executable
identity and two decoded results. Its local receipt (private installation record; not distributed)
records nineteen tests in each independent run. Native database/configuration and
signature verification remain unqualified; repository evidence and simulation
methods refuse before dispatch. The first RPM decoder also refuses nonzero
epochs because the source RPM filename does not establish a source epoch. It
therefore does not claim complete native Rocky inventory coverage yet.
