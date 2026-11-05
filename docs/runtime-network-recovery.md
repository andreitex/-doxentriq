# Runtime network diagnosis and recovery design

## Implemented behavior

The runtime supplies gVisor applications with independently verified addresses for their private company services. Docker can assign different service addresses after a restart; an existing application's saved host mappings do not change with them.

When an exact published release fails its health observation, the broker now checks those mappings against the current, digest-pinned company services on that application's derived private network. The check verifies the application container identity and configuration again after inspecting the services. It reads no database credentials and performs no container or data mutations.

Confirmed infrastructure drift produces an `unavailable` observation with an explanation for the administrator to contact the platform operator. It does not count as an application-code failure toward automatic rollback. The observation retains its release identity and normal immutable evidence hash. Retrying its observation ID returns the original evidence.

This diagnostic covers MySQL, Redis, RabbitMQ and, when enabled for a protected app, the directory authorization service. Connector mappings have separate scope checks; this diagnosis does not certify them. Healthy applications do not incur these extra inspections. Missing, changed or unverified evidence does not establish a network-drift cause.

## Recovery still to implement

Active-container replacement remains an operator recovery operation. The existing guard against deleting or recreating an active container remains in place. Automatic startup recovery is not implemented by this change.

A future recovery executor needs a durable, app-locked workflow with these requirements:

1. Verify the completed publication, immutable source, schema compatibility, actual route, current image security eligibility and the entire expected runtime contract. A label or old successful build alone cannot authorize a replacement.
2. Resolve every new infrastructure address independently. Preserve the approved image, data mounts, credentials, resource limits, sandbox, routes and access policy. Do not reprovision credentials or replay application actions.
3. Bind the recovery journal to the old immutable container ID and record each step before it can take effect. Retain the old stopped container and its volumes; do not remove business data.
4. Resolve interrupted TLS and signing-key maintenance against the old container before replacement. These records bind to immutable container IDs. Preserve their original bytes and link any archival to the recovery journal; never rewrite them to claim that an earlier operation acted on the new container.
5. Recreate from a validated company runtime specification and record the actual new immutable ID. Independently verify its mounts, isolation, image, current service mappings, served certificate and health before completing recovery.
6. On an interruption or ambiguous Docker result, inspect both exact identities and reconcile the recorded step. Do not repeat a mutation solely because its caller timed out. A failed new instance must not start an older instance with stale service mappings.

Acceptance must cover interruption at each step, stale or missing identity records, infrastructure movement during recovery, a concurrent publication, stopped apps, sidecars, and document preservation. A known vulnerable image or unverifiable state must produce an actionable blocked recovery rather than bypassing release controls.
