# Guided private installation companion

This company-produced companion connects the existing foundation, preparation
and seven private initialization/quota stages. It is a development component,
not a completed public installer. Public services and operational timers remain
gated. It creates no `installation.complete` marker.

The trusted company producer runs `deploy/installer/build-guided-private-package.py`
against protected source, an independently approved engine catalog and signing
fingerprint. It reuses the existing foundation and native-retention producers,
captures one common preparation/quota worker, and includes the read-only status
checker. All emitted entries and workers are root-owned mode 0400; the guided
entry checks each exact file's size, hash, ownership, link count and ancestry.
Source changes during assembly refuse the package. The package neither signs
itself nor authenticates its initial delivery; IT must independently authenticate
the company delivery before executing it.

An optional company delivery profile provides [setup input preparation](guided-request-intake.md)
to create the immutable request pair from storage prompts. It also verifies and
redisplays completed inputs on a rerun without repeating prompts or operations.
The existing protected configuration questionnaire still collects administrator
settings and credentials later.

## Optional authenticated delivery placement

The company producer can also emit a separate Bash placement entry. On the
trusted company build machine, add `--placement-destination` to the producer
invocation alongside the setup-input profile:

```sh
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /usr/bin/python3 -I -B /absolute/protected-source/deploy/installer/build-guided-private-package.py \
  /absolute/protected-source /absolute/delivery \
  --fingerprint APPROVED_SIGNING_FINGERPRINT \
  --engine-catalog /absolute/approved-engine-catalog.json \
  --engine-catalog-sha256 APPROVED_CATALOG_SHA256 \
  --request-defaults /absolute/request-defaults.json \
  --request-defaults-sha256 APPROVED_DEFAULTS_SHA256 \
  --public-key /absolute/company-signing-public-key.pem \
  --placement-destination /absolute/placement
```

Replace the example paths and approved values. Both output directories must be
fresh, separate, and under existing root-owned parents that are not writable by
other users. The producer checks both destinations before emitting either one.
The original guided package stays in `delivery`; the separate output contains
`doxentriq-place-guided.sh`. The JSON result includes each output's hashes and
`deliveryReceiptSha256` for `guided-delivery.txt`.

Before executing the placer on the target VM, IT must independently authenticate
that executable and obtain the approved delivery receipt hash through a trusted
company channel. A hash or receipt supplied only by the same unverified delivery
does not establish trust. Keep the delivered directory root-owned mode 0700,
its eleven files root-owned mode 0400, and its ancestry protected. Use absolute
paths without spaces, outside `/opt/autosoft-company`:

```sh
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /bin/bash --noprofile --norc /absolute/placement/doxentriq-place-guided.sh \
  --place /absolute/delivery INDEPENDENT_DELIVERY_RECEIPT_SHA256

sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /bin/bash --noprofile --norc /absolute/placement/doxentriq-place-guided.sh \
  --status /absolute/delivery INDEPENDENT_DELIVERY_RECEIPT_SHA256
```

Placement verifies and copies the fixed package into
`/opt/autosoft-company/bootstrap`, creates the required private directories,
and records its intent and completion. A completed rerun verifies the same
source path, receipt and installed package without replacing files. `--status`
does not create a missing destination. An existing incomplete, changed or
unrelated destination is preserved and refused; IT must reconcile it before any
further placement. Do not delete the retained directory or repeat an uncertain
operation to force progress.

This is delivery placement only. It installs no packages or Python, runs no
foundation prerequisites, and starts no platform services. The setup-input
wizard still needs Python 3; signed source bundles and approved host-package
files still need separate authenticated delivery. The complete installer and
native clean-install/reboot/failed-unlock acceptance remain unfinished. Portable
producer checks do not establish native placement qualification.

## Private installation after delivery

After delivery and immutable paired requests are prepared, the new command is:

```sh
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /bin/bash --noprofile --norc /opt/autosoft-company/bootstrap/company-guided-private.sh \
  --install-private FOUNDATION_REQUEST FULL_REQUEST
```

The original foundation request remains separate from the canonical full request
at `/opt/autosoft-company/requests/<operation-id>.json`. Their operation, storage,
capacity, gVisor and key identities must agree. The foundation and full signed
release inputs may differ: the existing configuration worker independently
verifies the corresponding schema3 foundation bytes against schema4 full source.
The guided preflight accepts only the original closed, canonical, credential-free
request envelopes. Credentials are collected later by the existing protected
configuration questionnaire, with stdin and terminal handling preserved.

The command runs the original foundation entry, preparation companion, then
private quota companion. Each child acquires its own original installer admission
lock and retains its own live Bash parent and independent verification. The
guided command holds no outer admission lock. It rechecks the exact package and
both request bytes before every child and after the last child.

A durable exclusive guided intent prevents a second fresh invocation from
replaying the same operation. Existing operation evidence or a matching retained
admission session also refuses fresh execution before a child is launched. Any
failure preserves requests, records, effects and artifacts. Use the same package:

```sh
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /bin/bash --noprofile --norc /opt/autosoft-company/bootstrap/company-guided-private.sh \
  --private-status FOUNDATION_REQUEST FULL_REQUEST
```

Status is read-only and advisory. It invokes the existing pinned status checker
and reports the original request/session for `--recover-preparation` or
`--recover-private-quota` when the retained stage is attributable. Those existing
commands perform their own verification; printing a command grants no recovery
authority. Partial or unknown effects stay blocked. An interrupted foundation
still requires IT reconciliation. If the original foundation session completed
and preparation never began, IT can explicitly continue the same delivered
package and requests:

```sh
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /bin/bash --noprofile --norc /opt/autosoft-company/bootstrap/company-guided-private.sh \
  --continue-after-foundation FOUNDATION_REQUEST FULL_REQUEST FOUNDATION_SESSION
```

This command checks the exact completed predecessor and starts a new, separate
read-only handoff session. It independently measures the existing signed source,
host package state, encrypted storage and installed runtimes twice before the
original preparation/private children run. It never rewrites the old session or
foundation evidence or repeats foundation installation. Changed package/request
bindings, begun preparation and an existing handoff refuse continuation. If the
handoff itself stops, preserve its records for IT reconciliation.

After the original preparation session completes, the same explicit approach
can verify its three finished stages before continuing to the private companion:

```sh
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC \
  /bin/bash --noprofile --norc /opt/autosoft-company/bootstrap/company-guided-private.sh \
  --continue-after-preparation FOUNDATION_REQUEST FULL_REQUEST PREPARATION_SESSION
```

This uses a fresh `preparation-handoff` session. The old completed journal,
configuration/secret digests, signed source, initial Git tree and initialized
runtime pair must agree with independent current observations. It preserves all
old records and never repeats the questionnaire, repository seed or runtime
initialization. Any begun private stage, previous handoff or missing completion
refuses. A stopped handoff needs IT reconciliation; there is no automatic replay.
The status command offers only the next unbegun phase or the actual unfinished
phase. Earlier completed sessions remain listed as evidence. Its guidance is
advisory; the verifiers make the admission decision each time.

The preparation handoff passed 72 distinct Linux component cases across the
retained runs: 63 in the earlier run and nine in the corrected fixture run. The
original failed fixture report is retained. These tests use genuine Bash parent
handling and the original record/effect readers; signed-source acquisition and
host effects remain modeled. They do not qualify a real signed installation,
reboot, public startup or later private-phase continuation.
The guided entry's emitted size bound is now 40 KiB; the template and embedded
lock inputs retain their 32 KiB bounds, the whole package retains 4 MiB and the
native worker retains 2 MiB. The measured candidate entry is 35,526 bytes. This accommodates readable handoff/recovery guidance;
no record format or historical authority changes. New emitted bytes have new
independently delivered hashes, and cannot adopt an old package's guided intent.

Remaining work includes base-VM prerequisites and native qualification of authenticated delivery placement;
genuine signed-VM reconciliation and foundation recovery; signed package and image
qualification; fresh security feeds and runtime advisory coverage; public service
startup; owner browser password/TOTP enrollment; first backup and isolated
restoration; timer enablement; and clean-install/reboot/failed-unlock acceptance
on every supported OS. The source/package and synthetic-effect component tests
do not establish any of that native acceptance.
