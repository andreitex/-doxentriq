# Host remediation proposals

The internal planner in `scripts/host_remediation.py` produces an exact proposal from an installed-package inventory, supported running-kernel identity, complete fresh scan, authenticated vendor candidate metadata and a bounded package-manager simulation. It handles only known Medium, High and Critical findings. Missing coverage, ambiguous identities, stale feeds or unavailable vendor evidence leave the proposal unavailable.

Repository authentication is a typed result from trusted verification code. It cannot be accepted from a JSON field claiming that metadata is signed. The native signature-chain verifier and package-manager query adapters still require implementation and qualification.

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
