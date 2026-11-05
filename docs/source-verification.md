# Source verification and preview recovery

Each new verification request binds the submitted files and pipeline before the runtime runs a generated command. Version 1 uses the runtime's existing source digest: sort project paths by UTF-8 bytes, hash each file's UTF-8 contents, serialize the ordered `{path,hash}` records with Go-compatible JSON escaping, and hash that JSON. File enumeration order does not change the digest. NUL inside a file cannot masquerade as another file.

The canonical input hash rejects exact duplicate paths, malformed UTF-8 paths and traversal before writing the workspace. Additional protected-path and case-alias checks during writing can leave a partial tree, which remains preserved. Source content is hashed from the UTF-8 bytes written to disk. Pipeline commands must round-trip through UTF-8 and contain no NUL; an isolated UTF-16 surrogate is refused before either workspace creation or broker submission. Direct `BrokerClient.verify` calls apply the same command check before opening the transport.

The runtime checks the actual workspace digest and captured `autosoft.pipeline.json` against the request. It creates fresh source and build directories, then checks both copied trees independently. A pre-existing partial directory is preserved for reconciliation and prevents reuse of that attempt. Generated commands receive the distinct build tree.

The receipt retains two source hashes and a pipeline hash:

| Field | Binds |
| --- | --- |
| `sourceBindingVersion: 1`, `filesHash`, `inputSourceHash` | The submitted source bytes |
| `pipelineHash` | The parsed pipeline, including ordered stages, commands and timeouts |
| `sourceHash` | The final retained source after trusted dependency-lock generation |

Migration capture uses the final `sourceHash`, with a fresh 120-second context derived from the verification request. It does not reuse a completed dependency or test context. Parent cancellation makes capture evidence unavailable; physical process interruption remains separately qualified. This change does not authorize destructive migrations or establish compatibility for an existing database with unapplied migrations.

Verification replay requires matching versioned input, app, attempt, pipeline, template, final retained source and migration binding. An older receipt without the versioned input contract is preserved and refused for verification replay. Reading historical verified source remains possible when the actual returned file bytes match its recorded final source hash. A changed source tree cannot be returned as verified context for an improvement request.

The accepted source receipt (private installation record; not distributed) records 79 focused Node passes without skips and backend TypeScript success. It separately retains 57 named Go passes, including 21 top-level tests, and vet success against unchanged Go source. Independent and root review verified 38 stable files. The first review's direct-client finding and the original failed preparations remain preserved; the correction adds three direct rejection cases with zero transport calls.

These checks cover shared Unicode/NUL vectors, forged input, pipeline differences, partial-directory preservation, lock-generated final hashes, capture cancellation, receipt conflicts and returned-source tampering. They use synthetic data and injected runtime operations. They do not establish a live model-generated DMS, native Linux deployment, publication or backup acceptance.
