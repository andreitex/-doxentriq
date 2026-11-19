# Native retained-source startup inspection

The company package can emit `company-continue.sh` with
`build-native-retention-package.py --continuation-entry PATH`. Its supported
invocation is:

```sh
bash --noprofile --norc /protected/company-continue.sh \
  --retain-and-inspect-startup /opt/autosoft-company/requests/OPERATION_ID.json
```

This is a fresh continuation after foundation, configuration, repository seeding
and runtime-pair initialization. It is not full installation. A read-only check
authenticates the incoming signed source and current configured storage/runtime
pair before creating a durable session. It also matches the configured signing
fingerprint and the three active deployment catalogs to that release. This
check does not independently reverify the repository seed.
Configuration now creates the two fixed empty root-owned `0700` parents under
`DATA/company`: `platform-releases` and `source-releases`. It refuses either
existing name before configuration writes and independently records their
directory identities. Continuation preflight only verifies both protected empty
parents; it creates neither and refuses missing or conflicting state before
opening its admission session.

The producer embeds the exact Store/Source stage loop from the unchanged
retention-only entry. This companion keeps both confirmations in its live Bash
session, then admits `company-stored-startup`. It reauthenticates retained signed
artifacts, holds the complete physical source through the original read-only
backend and source guard, and binds the original captured assembly to that guard.
The original `StoredStartup` capability verifies exact prior outcomes from this
same live parent session; saved JSON or an earlier completed session is
insufficient.

The worker inspects the independently initialized runtime pair without creating
or repairing it. All source, storage, parent and descriptor scopes close before
the worker publishes its observation. Another child performs the same read-only
inspection and must produce an identical result. Bash confirms only after the
successful child exits and an exact request/session/action/result marker.

Failures preserve partial source, journal and session evidence. There is no
automatic resume, adoption of old sessions, or retry of an unknown effect. Do
not run the retention-only command first for the same operation: it completes
a separate two-stage session, which this fresh continuation cannot reuse.

Rendering, identity provisioning and service activation are still separate
unfinished stages. This command does not call them, enable timers, mark the
installation complete, claim native authorization, or establish backup readiness.
The read-only storage/source scopes must not be reused around later rendering
writes; those writes require a separately reviewed mutation boundary.

Original-API control tests and private-namespace Bash tests cover this handoff.
Synthetic Bash effects do not qualify actual signed Store/Source execution.
A complete native run on the encrypted foundation and reboot/failure recovery
acceptance remain pending.
