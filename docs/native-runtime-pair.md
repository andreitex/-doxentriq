# Native runtime-pair stage

This companion initializes the fresh runtime admission gate and quota allocation
journal using the original signed installer modules. It does not render or start
services, initialize identity, claim backup readiness, or complete installation.

The independently authenticated native package can include a companion entry:

```sh
python3 -I -B deploy/installer/build-native-retention-package.py \
  /protected/company/source /protected/output/company-native-retention.py \
  --fingerprint COMPANY_KEY_FINGERPRINT \
  --runtime-pair-entry /protected/output/company-runtime-pair.sh
```

After the actual encrypted foundation and configuration/runtime layout exist,
IT can run the company-delivered entry with its canonical full request:

```sh
bash --noprofile --norc /protected/output/company-runtime-pair.sh \
  --initialize-runtime-pair /opt/autosoft-company/requests/OPERATION_ID.json
```

The action command authenticates the complete source, checks the stopped host
writers, verifies encrypted storage and build tmpfs, and requires fresh empty
quota/storage plus absent pair-stage records before creating an admission session.
The action binds the full request, exact worker bytes, installation identity,
data-root identity and actual storage proof. The execute child rechecks these
conditions under the genuine held Bash parent. The separately packaged
`company_runtime_pair_parent` issues the original one-use authority; its default
constructor remains unusable. All `nativeAuthorized` fields remain **false**.

The worker calls original `runtime_pair_init.initialize` with actual `NativeFiles`,
`Gate`, `Allocation`, and quota state readers/writers. All host and build-mount
queries explicitly use the restricted native command runner; there is no silent
fallback to the general command helper. The stage writes its durable intent,
initializes the admission gate, performs the single admitted empty allocation,
and verifies the exact initial pair. Existing or partial journals are preserved
and refused, including after a lost acknowledgement.

The four original stage records are measured with exact bytes and nine-field
file identities. After all original source/parent/adapter contexts close, the
execute child writes its immutable observation. A distinct read-only child then
uses original pair/startup inspections and checks the same record aggregate.
The earlier gate-only digest remains bound to the closed execute observation;
verification does not pretend the completed allocation history is absent.
Only successful verification-child exit and the exact request/session/action/
outcome marker allow Bash to confirm this stage.

The storage guard treats only the specifically authenticated backing file's
mtime/ctime as mutable: ciphertext changes during legitimate volume writes.
Its device, inode, mode, owner, group, link count and size remain fixed, as do
the actual mapper/backing/LUKS UUID checks. Key, configuration and receipt files
retain full identity checks. The backing path cannot alias the unlock key.
Neither backing contents nor key contents are read by this guard.

## Verification limits

Source tests cover the original pair/parent contracts, immutable record binding,
separate verification, changed storage metadata, partial outcomes and refusal of
authorization claims. Linux component fixtures exercise real root-owned files,
fsync, flock, pair initialization and read-only inspection. Those fixtures use
explicitly synthetic storage and parent evidence. Separate private-namespace
Bash tests exercise the actual admission parent with synthetic trusted effects.

These tests do not establish a complete signed-source-to-encrypted-foundation
native installation, encryption or XFS quota enforcement, power-loss behavior,
reboot recovery, or full activation. The remaining stored-startup handoff still
requires authenticated Store/Source outcomes in the required parent session;
this separate companion does not bypass that requirement.
