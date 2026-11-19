# Captured installer materialization

The externally trusted installer worker calls this helper inside its active
`authenticated_deployment` context. It receives no permission from this helper
to execute an installer or change the host. The trusted verifier, key fingerprint,
interpreter and original installer-parent lock remain the caller's obligations.

```python
with trusted_verifier.authenticated_deployment(...) as held:
    with installer_materialize.materialized_deployment(
        held, protected_parent, 'install-' + operation_id,
    ) as tree:
        tree.recheck()
        captured_install_path = tree.root / 'scripts/install.sh'
```

The independent finite catalogs require 44 script leaves, ten deployment
templates, five signed configurations and three raw provenance leaves. Scripts
and templates retain their relative paths; configurations and provenance go
under `company-release/`. The tree has exactly 62 files and five directories.
There is no ambient directory copy, repository seed, candidate import or dispatch.
The active held API is supplied by trusted code; accepting its interface cannot
authenticate a counterfeit object supplied by an untrusted caller.

The native backend requires POSIX root UID/GID, a pre-existing root-owned0700
parent and protected root-owned ancestors. It uses held nofollow/CLOEXEC openat
handles, exclusive mkdir/file creation, bounded writes, fsync and exact readback.
Written files become0400 and are reopened read-only; the completed tree's
directories become0500. Parent contents and the exact output inventory are
checked. File and directory identities include all nine metadata fields between
effects. Only the exact directory changed by our exclusive mkdir/file creation
gets a new observation, requiring the original identity/ownership/mode and the
expected link-count change. Sealing permits only the intended mode/ctime change.
Unrelated ancestors are never rebased. Completed observations remain held and
unchanged across caller work.

Source/template bytes jointly cap at16MiB, templates at4MiB, each ordinary leaf
at1MiB. Configuration and provenance caps match the held verifier; aggregate
output caps at19MiB plus61504 bytes. Parent inventory caps at1024 entries and
ancestor depth at32. Preparation and each recheck have a60-second cooperative deadline;
chunk writes/reads cap at64KiB. It does not set host resource limits, attest an
encrypted mount, or guarantee interruption of blocked kernel calls. A worker
must provide its own overall process, caller-work and installation-stage supervision.

The helper checks held inputs before filesystem effects, before yield and after
caller work. Explicit `tree.recheck()` also checks original provenance, content,
metadata and inventory. Any failed recheck expires tree access.
Output path, hash-map and release-hash getters recheck the materialized output
before returning, rather than waiting until caller exit to discover drift.
The held verifier must remain active for all use; saved paths or hashes are historical afterward.
Every owned close is attempted. Failed closes retain exact backend/FD references
in a sticky unknown latch and deny another materialization; they are not retried
by numeric descriptor. Files and partial trees are preserved after every failure,
including a lost mkdir/write/fsync acknowledgement. No adoption, overwrite,
deletion, permission repair or completion marker exists.

This source slice is not wired into install.sh/lib.sh/bootstrap.py. It leaves
their ambient-path and unsigned broad repository-copy issues outstanding. Local
controls use real small retained fixture bytes with injected POSIX ownership,
directory handles and fsync behavior on Windows; native Linux materialization,
installer recovery, production activation and the OS matrix remain unqualified.

Schema4 callers use the distinct `materialized_platform_foundation` API:

```python
with original_verifier.authenticated_platform_source(...) as held:
    with installer_materialize.materialized_platform_foundation(
        held, quiet_protected_parent, 'install-' + operation_id,
        verifier=original_verifier, files=explicit_trusted_backend,
    ) as tree:
        tree.recheck()
```

The company must separately authenticate the original verifier and backend. This
route requires genuine private issuance in that verifier before reading source
maps and throughout materialization. It independently matches the 44/10 catalogs,
signed selected hashes and logical Git modes. It adds `platform-sources.json` to
the five configurations and the separately declared `scripts/installation-status.py`
from the signed platform manifest, producing exactly 64 files. The legacy
44-file host catalog remains unchanged, and the existing aggregate limits are
preserved. The temporary adapter retains the same original held source and
expires on failure or exit; it never presents a schema3 capability.

This foundation projection omits `platform-sources.tar.gz` and is not a complete
schema4 bundle. Store and the original verifier retain the archive separately.
The full worker must use that original context and avoid the legacy schema3-only
complete-deployment path. The local receipt (private installation record; not distributed)
records twelve new passes and all 37 existing materializer regressions without
skips. The later installed-status projection passed 113 Linux component cases
across seven suites, including two real copied-CLI cases in private mount
namespaces and rejection of missing or changed signed diagnostic rows. The
original signing and filesystem-ownership collaborators remain synthetic.
Native installation remains separate acceptance work.

The foundation materializer registration made this suite mandatory in both
Docker and host company gates, with 58 suites and 34 temporary fixture selectors
at that checkpoint. The later full-component registration (private installation record; not distributed)
increased those counts to 62 and 38. Both registrations ran only Bash syntax and
five embedded Python checks, preserving earlier commands and required coverage
rules. They did not rerun the suites, build an image or execute the company Linux
pipeline.

The stored-startup borrowed route (private installation record; not distributed)
can reuse the caller's original issued and physically bound fresh assembly,
preserving bootstrap/Store/Source identities without recompilation. Ten new
controls and three existing regressions passed; the earlier combined timeout
remains separate. The original source, assembly and guard must stay live through
caller use and closure. An actual full worker consuming this schema4 projection,
native storage and runtime-pair adapters, and full service activation still
require integration and acceptance.
