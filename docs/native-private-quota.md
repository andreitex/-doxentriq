# Private quota activation continuation

The company package producer's `--quota-entry` option emits
`company-private-quota.sh`. From a fresh prepared request, its
`--retain-render-initialize-and-start-quota REQUEST` command runs the six
[private initialization stages](native-private-initialization.md), then starts
and independently verifies the quota helper. All seven stages use the same
authenticated worker, original live Bash parent, request and installer lock.
Preparation and this companion must be produced with the same worker digest.

Choose this combined command instead of the six-stage initializer. It is not a
post-install command for a request whose earlier initialization already finished.
Completed and uncertain steps are not replayed. A failure preserves its files,
process observations and stage records for company review; explicit recovery for
private infrastructure, identity and quota is still required.

Before any quota effect, the worker reauthenticates the signed source and
configuration, original parent confirmations, encrypted-storage placement,
current private infrastructure and both closed identity helper workspaces. It
installs exactly two previously absent files: `autosoft-quota.service` and
`docker.service.d/autosoft-quota.conf`. The existing build-mount dependency is
preserved. Existing or partially written quota files are refused, not overwritten
or adopted. Only the declared quota dependency may change in Docker's observed
unit configuration.

The bounded supervisor reloads systemd and starts this one service. Every polling
cycle retains the original source/parent checks and checks the exact installed
unit and identity evidence. Changed evidence stops the operation and preserves
the uncertain outcome. Read-only process checks use the original held authority;
temporary effect checks are removed when their scope ends.

The startup verifier briefly releases its initialized journal locks while the
real helper acquires those locks itself. Protected storage, key and source
checks remain held, and the original verifier must confirm unchanged journals
afterward. This prevents the installer from deadlocking the helper at readiness.
Independent verification binds the service state, live PID, exact command line,
Python executable, Unix peer credentials, socket and signed operational files.

This stage does not enable units, start public services or timers, create an
installation-complete marker, establish browser MFA, or grant backup readiness.
It remains a company companion, not the supported one-command public installer.

## Component evidence and remaining acceptance

On November 8, 2026, 112 Linux cases passed without skips: 36 new quota/closed
identity cases and 76 affected package, host-supervisor, identity-evidence,
retention and initialization cases. The new cases exercised exclusive fixture
files, the original seven-stage Bash parent, real separate-process journal locks,
PID/socket observations, changed-unit and changed-identity rejection during the
actual supervisor loop, and preservation after interrupted or uncertain steps.

Mount-namespace fixtures used synthetic mount proof and harmless processes.
Docker/Keycloak, signing authority and selected parent/storage collaborators
were synthetic. No Docker command, VM operation, actual systemd service start,
encrypted unlock or signing action ran. Source inputs and the parent mount
namespace were unchanged. CI includes these cases alongside the existing suites.

Remaining work is to connect intake, foundation, preparation and this companion
into one guided command with explicit interrupted-stage recovery; qualify signed
artifacts and actual quota activation; gate public service startup; verify owner
password/TOTP and the first backup/restore; then enable operational timers.
Clean installation, safe rerun, reboot and failed-unlock acceptance remain open
on every supported operating system.
