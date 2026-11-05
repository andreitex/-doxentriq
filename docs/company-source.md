# Company source byte manifest

`company_source.py` creates and compares source byte records. It neither signs
them nor establishes company trust. No installer, release-builder, verifier or
service caller is wired to it in this slice. An independently pinned bootstrap
verifier must authenticate the company signature and manifest hash before
loading the sources it describes. Self-verification cannot supply that trust.

`create(root, paths=INSTALLER_RUNTIME_SOURCES)` returns a closed manifest with
`schemaVersion:1`, scope `COMPANY_SOURCE_BYTES_ONLY`, and sorted records containing
only canonical relative path, integer byte count and SHA256. `encode` emits exact
ASCII canonical JSON with one terminal LF; `decode` accepts only those exact
bytes and rejects duplicate keys, nonfinite values, extra fields, traversal,
unsorted/duplicate records and missing or extra catalog paths.

`verify(root, manifest, paths=INSTALLER_RUNTIME_SOURCES)` accepts a validated dict
or bounded canonical bytes. Coverage comes from the independently selected
company catalog, never from the received manifest. Custom catalogs are explicit
trusted-caller inputs; they do not qualify the default installer coverage.
The fixed catalog includes this module, installer/lock/identity/layout/pair and
quota/checkpoint siblings, host recovery/scanner/maintenance modules, their
wrappers, and company release scripts, including `verify-release.py`: 44 explicit
paths. It never recursively walks `scripts` or test fixtures. The local suite
checks Python sibling imports plus literal `scripts/` and shell `SCRIPT_DIR`
references, `with_name` paths and explicit `_sibling`/importlib loader filenames.
It verifies the actual install/bootstrap release-verifier calls and rejects the
previous 43-path catalog. These are bounded syntax checks; computed filenames,
command aliases and arbitrary dynamic loading require separate company review.
No command or catalog module executes during those checks. Container-contained
TS/Go/runtime dependencies remain a separate signed
immutable-image boundary; this manifest is not all-platform executable coverage.

The native backend opens canonical absolute roots and every ancestor/directory
with read-only nofollow/CLOEXEC `openat`, then holds independently opened regular
single-link source files. It requires protected modes and exact configured
UID/GID. Installer verification defaults to root/root. A trusted nonroot company
builder may explicitly select its own expected UID/GID; ancestors may then be
root/root or that exact owner, never group/world writable. Source files are
nonempty, at most 1 MiB each; limits are 128 files, 16 MiB total, 64 held
directories, eight relative components, 128 ASCII path bytes and 32 KiB canonical
manifest bytes. No output-file, mkdir, chmod, chown, import, execution, signature,
key, credential or network operation is provided.

Directory device/inode/type/mode/owner bindings remain exact through the call.
Each file's nine metadata fields and pathname/held-FD identity remain exact;
its contents are hashed once during admission and reread through the held FD
before return. Nonblocking file opens keep an unexpected FIFO replacement from
blocking the opener. Actual kernel/filesystem behavior and transient changes
entirely between checks are not universally attested. All owned closes are
attempted. Failed closure keeps the exact backend/FD reference and an unknown
latch; later calls refuse rather than retrying a potentially reused FD. Existing
sources are never modified, removed or repaired on failure.

Success is observation only: `changed`, `companyTrustEstablished`,
`signatureVerified`, `nativeAuthorized` and `backupReady` are false. It describes
the checked invocation, not future source imports after handles are released.
Later integration must hold authenticated sources through use or provide its
own reviewed continuity boundary, add the canonical manifest hash to a signed
release v2, and check exact expected catalog coverage before installer activation.
The current image-only release v1 format is unchanged.

The focused suite reads actual retained source bytes and performs local file
replacement, hardlink, content-drift and parser controls. Linux DAC, directory-FD
transport and Windows path/FD ctime are injected on the Windows control host;
the production native verifier has no Windows metadata relaxation. Tests do not
import the catalog's old production modules, sign releases, launch a native
installer or qualify Debian/Rocky mount/flock/source-loading behavior. Fixtures
remain beneath the existing company-controlled `AUTOSOFT_TEST_ARTIFACT_ROOT`
(default `.local`); no cleanup or broad fixture discovery is performed.
