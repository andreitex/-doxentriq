# Private infrastructure and initial identity continuation

This company companion connects the signed retained-source and rendering stages
to the five private infrastructure services and an independently verified initial
identity policy. It does **not** complete or publicly activate an installation.
The public installer continues to support foundation-only deployment.

The company package producer can emit `--preparation-entry` and
`--initialization-entry` together with the **same** `company-native-retention.py`.
The initializer embeds that exact worker digest. Preparation and initialization
use the same protected request and authenticated release. Preparing with one
worker and substituting a differently assembled worker is refused.
The existing full-request contract requires original bundle/source inputs under
`/opt/autosoft-company/incoming` and the key under its protected `bootstrap`
directory. The initializer reauthenticates those original inputs while changing
identity workspaces. Retained-source reconstruction closes before that change;
substituting a retained data-volume path for an original request path is rejected.

The intended IT sequence, after company foundation setup and request preparation,
is:

1. Run the packaged `company-prepare.sh --prepare-foundation REQUEST` and retain
   its evidence. The existing explicit preparation recovery command may verify
   a recorded interrupted step before continuing; incomplete effects stay blocked.
2. Run the packaged `company-initialize.sh
   --retain-render-and-initialize-private REQUEST`.
3. Preserve the request, package and all evidence if a step fails. Do not delete
   evidence, rerun provisioning, or manually remove an uncertain helper. Identity
   initialization currently needs company review after interruption; automatic
   resume or adoption is not implemented.

`REQUEST` must be the exact protected
`/opt/autosoft-company/requests/<operation-id>.json` already prepared by the company.
These are companion commands, not a standalone copy-and-run public installer.

For a fresh prepared request that also needs private quota activation, the
producer can instead emit the combined [seven-stage quota companion](native-private-quota.md).
Choose that companion instead of this six-stage command. Running it after a
completed six-stage initialization would attempt the earlier stages again and
is refused; existing completed or interrupted requests require company review.

The initializer admits six steps under one live parent and one installer lock:
platform retention, source materialization, stored-startup verification,
configuration rendering, private infrastructure, and initial identity. Each step
has independent confirmation before the next. Source, configuration, runtime,
storage and host checks remain active. Infrastructure checks bind the actual
five container IDs, images, networks, configuration, readiness and encrypted
Docker/containerd/journal placement. Current company-engine schema2 provenance is
preserved separately from legacy distribution profiles.

Identity provisioning uses the signed helper source and existing protected
rendered secrets. Credentials travel through helper stdin and are not included
in evidence or command arguments. The helper has no published port, Docker socket
or host shell. A separate temporary helper verifies the resulting policy and
owner identifier. Exact Docker executable bytes must match the captured catalog.
Host observations close before the declared identity workspace creation, reopen
afterward, and must match before and after helper execution; directory checks
are not globally refreshed to conceal that change. An uncertain helper outcome
is preserved and never blindly retried.

Required before actual execution:

- Authenticated company delivery and signing-key fingerprint, signed source and
  release/configuration/image locks covering the exact source tree.
- Qualified company host-engine packages/catalog, all runtime archives, required
  image digests and their independently reviewed security/qualification evidence.
- Genuine foundation, encrypted-mount, configuration, repository and runtime
  preparation confirmations; protected full request and matching package.
- Correct DNS/certificate and identity configuration from IT intake.

Still required for one complete guided installation: connect intake, foundation,
preparation and this initializer in the supported entry command; define explicit
recovery for interrupted private infrastructure/identity; provision public
service units only from genuine infrastructure and identity confirmation; verify
owner password/TOTP in the browser; take and restore a first backup checkpoint;
enable operational timers; and demonstrate reboot, failed-unlock recovery and
clean-install/rerun on every supported OS. No `installation.complete` marker,
public-start permission, browser-MFA acceptance or backup readiness is emitted by
this companion.

On November 8, 2026, this composition passed 115 Linux fixture cases without
skips across 11 suites. The checks include the original live Bash parent,
six-stage interruption and confirmation rules, current engine-catalog packaging,
real protected identity files, separate policy readback and combined source,
infrastructure and storage ancestry checks. Source and storage drift prevented
success. The input source and parent mount namespace remained unchanged.

The public-source CI runs the nine new suites alongside its existing engine and
retention suites. Fixture signatures, Docker/Keycloak, mount proof and some
journal admission collaborators are synthetic. This evidence does not establish
genuine signed execution, an encrypted-volume installation, public startup,
browser MFA, backups, reboot recovery or complete VM acceptance.

The maintained Keycloak helper and packaged worker contract were subsequently
checked together: 39 cases passed without skips using Node 22.19 and Python
3.12. The actual packaged worker supplies the configured admin URL and SSO
aliases to the real helper. Controlled HTTP responses cover initial-policy
readback, TLS readiness on the infrastructure profile's port 9000, rejected
policy drift and existing provisioning/recovery transport. These checks make
no live Keycloak calls and do not establish Node 24 image, browser MFA or signed
installation acceptance.

The captured configuration validator was then tested without a permissive test
replacement. Four identity predicates now pass literal booleans to its existing
strict `require` function. The current contract passed 18 Linux cases (15 worker
and three ancestry cases) plus 14 Node helper cases, with zero skips. These 32
cases cover the actual packaged validator and worker payload; they supersede the
earlier worker fixtures within the 39-case result above. The unchanged 13
transport tests remain separate. None of these controlled-transport checks
qualifies live Keycloak or browser MFA.
