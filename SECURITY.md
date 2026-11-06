# Security policy

Doxentriq is pre-release software. No production-supported release or response-time
commitment has been announced. A passing source test does not certify an installed
system, its dependencies, a generated application or a third-party connection.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/andreitex/-doxentriq/security/advisories/new)
for [andreitex/-doxentriq](https://github.com/andreitex/-doxentriq). Sign into GitHub
if prompted. The repository feature was enabled and confirmed through GitHub's
API on November 5, 2026.

Do not post credentials, customer records, invitation links, complete logs or
exploit details in public issues or chat. If a customer installation requires
urgent assistance, also contact the company representative who supplied it.
This policy does not promise a response-time service level.

A useful report includes the affected version, a minimal reproduction using
synthetic data, expected and observed behavior, and the scope of the impact.
Retain original evidence privately. If a credential was exposed, tell the affected
operator promptly so it can be revoked; removing it from a later commit does not
make the exposed credential safe.

## Maintainer handling

Triage reports privately, record affected versions, reproduce with synthetic data,
prepare a fix and regression test, and coordinate a release and advisory with the
reporter. Medium, High and Critical known findings block ordinary publication under
the platform policy. Lower-severity findings may still be tracked and corrected.

Never request a customer's model keys or passwords in an issue. Production access,
destructive changes, permission changes and recovery operations must use the
platform's applicable approval and audit controls.
