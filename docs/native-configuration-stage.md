# Configuration before signed source retention

This is an executable company installation stage, not a completed public
installer. The ordinary full-install entry still refuses activation. The new
stage has local source/control tests; its actual signed fresh-VM execution and
power-loss behavior have **not** been qualified yet.

The Store/Source implementation requires a real configuration and confirmed
runtime placement. A foundation-only result does not create these inputs. The
supported next sequence is: independently confirmed foundation, company
configuration and placement, signed Store, signed Source, then the still-pending
repository seed, runtime pair, authenticated service startup and operations
activation. Do not manufacture layout or configuration receipts to skip a step.

## Exact source and company delivery

The trusted company image pipeline can now capture a reviewed clean Git revision
as schema4 by setting `COMPLETE_PLATFORM_REVISION` to its exact commit. Its output
must be outside that checkout. The existing build and scan gates still run; this
selector does not bypass them. Signing remains a separate company trust action.
Run the [Git producer prerequisite check](git-producer-prerequisites.md) first;
an older distribution Git is not silently accepted by dropping the no-fetch guard.

For three already reviewed image configuration files in a fresh protected bundle
directory, the producer can instead prepare unsigned complete source explicitly:

```sh
python3 -I -B scripts/release-manifest.py --complete-platform-source \
  /protected/bundle /protected/clean-source EXACT_40_HEX_COMMIT VERSION
bash scripts/sign-company-release.sh /protected/bundle /protected/offline-key.pem \
  --complete-platform-source /protected/clean-source
```

Prepare the prerequisite foundation bundle from the same frozen source and an
exact copy of those three catalog files in a separate fresh protected directory:

```sh
python3 -I -B scripts/release-manifest.py --complete-deployment-source \
  /protected/foundation-bundle /protected/clean-source VERSION
bash scripts/sign-company-release.sh /protected/foundation-bundle \
  /protected/offline-key.pem --complete-deployment
```

This emits the original schema3 source binding; it does not build images or
qualify catalog provenance. Preserve its own release digest in the foundation
request, and the schema4 digest in the subsequent full request.

The input files are `images.lock.json`, `runtime-manifest.json` and
`approved-mirrors.json`. Schema4 complete-source capture checks the actual clean
Git revision and raw worktree bytes. Schema3 binds the 54 reviewed source/template
byte streams and must use the same frozen source. Preparing source alone makes no claim about image safety,
dependency checks or the provenance of those three configuration files. Retain
the real image pipeline evidence. Never sign a fixture as a production release.

From the same trusted company source, build the independently delivered entries:

```sh
python3 -I -B deploy/installer/build-native-retention-package.py \
  /protected/clean-source /protected/delivery/company-native-retention.py \
  --entry /protected/delivery/company-retention.sh \
  --configuration-entry /protected/delivery/company-configure.sh \
  --fingerprint INDEPENDENT_COMPANY_ED25519_SPKI_SHA256
```

Authenticate the emitted bootstrap files independently. Their printed digests do
not authenticate their initial download. Existing delivery files are never
overwritten. The previously retained r6 validation bundle remains unchanged;
changed source requires a new capture, package and signed release.

## Fresh-foundation binding and execution

The existing foundation entry consumes schema3. The configuration stage reads
its actual protected `intent.json`, `result.json` and `verified` evidence. It
authenticates the installed schema3 bundle using the original verifier and
requires its 54 host/template files and five configuration catalogs to equal the
corresponding schema4 bytes. It also binds the operation ID, installation ID,
host records, storage paths/capacity, gVisor selection, key path and measured
foundation source inventory. A different fixture or merely existing directory
cannot substitute for that foundation.

The canonical full request at
`/opt/autosoft-company/requests/OPERATION_ID.json` uses the existing
`company_full_cli_request.py` schema. It has mode `full-installation`, the same
operation/storage/runtime identity as the foundation, and the genuine schema4
bundle/source paths and release SHA256. Keep the original foundation request and
evidence separately; do not overwrite them with the full request.

After independent bootstrap authentication, the IT operator runs:

```sh
bash --noprofile --norc /protected/delivery/company-configure.sh \
  --configure-foundation /opt/autosoft-company/requests/OPERATION_ID.json
bash --noprofile --norc /protected/delivery/company-retention.sh \
  --retention-only /opt/autosoft-company/requests/OPERATION_ID.json
```

The company questionnaire collects strictly bounded answers in memory before
opening bounded source/native contexts. Credentials use non-echoing prompts; an
unavailable protected terminal refuses instead of writing an input file or
falling back to visible input. The signed wizard consumes the complete answer
set without prompting again. Original signature, source, parent, encrypted
mount and quiet-host checks still precede customer configuration writes. Native
read-command deadlines are unchanged.

Set the approved spending limits during setup. When restoring an installation,
preserve its spending ledger and any separately accounted uncertain reservations.
Installation qualification does not authorize model calls or reset accounting.

The stage writes actual configuration and runtime placement through their
original captured implementations. It preserves the exact three signed catalog
byte streams. The model catalog remains an operator-supplied input at this stage;
later model qualification and price-freshness checks remain compulsory.

A bounded output digest covers the model catalog, both provider-key files, DNS
credentials, optional registry/SMTP credentials and selected SSO credentials.
Native checks reject links, hardlinks, unexpected files, wrong ownership and
permissions; Keycloak's UID1000 files are distinguished from root-owned secrets.
Files and their parent directories are fsynced before execution evidence. Only
the aggregate output digest enters protected stage evidence; values and
individual credential digests are never printed. A separate worker invocation
remeasures the actual files, signed catalogs, layout and foundation binding.
The Bash parent confirms only after both direct children exit successfully.

Service units require inactive service PID/cgroup evidence. Timer units require
their actual inactive timer properties; nonexistent service PID fields are not
invented for timers. Every existing Docker container, including stopped ones,
refuses this fresh stage. Nothing is stopped or adopted automatically.

Interruptions leave all written secrets, configuration, layout and admission
records intact. A rerun refuses the prior attempt; general reconciliation is
still pending. This stage starts no application containers, initializes no quota
journals, enables no timers, and marks no full installation complete.

## Qualification still required

Run the new configuration/output and foundation-entry native tests on Linux, then
run the real sequence against a genuine signed release on a fresh Rocky VM.
The foundation-entry regression uses a private mount namespace and an invalid
synthetic admission object: it proves the protected request read reaches the
next real refusal without touching live services. Output tests use synthetic
credentials and actual fsync/mode/digest checks. Neither suite replaces the
complete signed transaction, interruption, reboot or failed-unlock acceptance.

After real Store/Source success, implement and qualify authenticated repository
seeding, runtime-pair initialization, immutable-source service paths and reboot
verification before replacing the full-install refusal.
