# Source context for app improvements

An improvement starts from the application's saved source and current release.
After requirements are clarified, the platform selects complete files using the
request, answers and acceptance criteria. Requested files come first, followed
by small application contracts, relevant files and import neighbours. The
current context limit is 48,000 UTF-8 bytes; an oversized requested file pauses
the request with an explanation instead of sending a partial file.

The selection records the original source hashes, selected and omitted paths,
selection reasons, byte counts and the release baseline. It is saved once in the
encrypted generation context alongside paid model checkpoints. Recovery reuses
that same selection and completed outputs. A changed request, baseline or
selection cannot silently replace the context of an interrupted job.

Before independent review or merge, the platform checks the complete proposed
artifact, including structured manifests, pipelines, migrations and deletions.
A model cannot change a file that was omitted from its source context. If an
omitted JSON contract is semantically unchanged, the platform preserves its
original bytes rather than reformatting it. Unchanged omitted files remain in
the application.

Dependency changes that would delete an omitted package lock currently pause.
They require a separately verified dependency acquisition and lock-generation
step before this workflow can support them. Retaining a stale lock or deleting
it without context is not an accepted fallback. Administrators receive an
actionable clarification; these controls do not authorize a release.

Local tests cover request-directed frontend selection, context limits, encrypted
selection persistence, replay without another paid call, omitted contract
changes and lock deletion. They use injected providers. Live model generation,
the DMS publication/improvement/rollback demonstration and provider qualification
remain separate acceptance work. See [implementation status](implementation-status.md).

The accepted local evidence (private installation record; not distributed)
records 58 passing controls, zero skips, the backend TypeScript check and
independent/root verification of thirty stable files.
