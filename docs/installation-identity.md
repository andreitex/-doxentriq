# Host installation identity

`scripts/installation_identity.py` supplies protected host records for a future fresh installer. It does not create storage, keys, mounts, Gate state or allocation state, and is not yet wired into installation or startup.

Fresh setup commits one canonical installation UUID with the exact data mount, company source directory, backing file and capacity before the caller performs any backing-file, key or LUKS action. The record is exclusive, private, synced and read back. Existing keys, host metadata, pending metadata, intents and backing files prevent fresh creation. Failure preserves any evidence already written. A lost acknowledgement cannot generate a replacement UUID on retry.

Read-only verification checks the protected host directory binding, the closed intent schema, canonical paths and UUID, and exact pending or final host metadata. Client configuration must refer to the same persisted UUID. Legacy, missing, conflicting, malformed, linked or replaced evidence requires company review; this module never migrates or repairs it. It cannot itself establish that LUKS formatting, filesystem creation or mounts completed safely.

Local controls use the existing injected Windows root and directory-sync policy while retaining real exclusive file creation, file fsync, typed parsing and readback. Native Linux permissions, directory fsync, interrupted storage stages, full installer reruns and supported operating-system qualification remain separate work.
