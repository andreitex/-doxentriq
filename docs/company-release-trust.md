# Schema2 company release bytes

The compatible `prepare_payload` API prepares schema2 metadata. It binds `images.lock.json`,
`runtime-manifest.json`, `approved-mirrors.json` and canonical
`company-sources.json` by exact byte length and SHA256. The independent source
catalog contains 44 explicit installer/runtime scripts, including
`verify-release.py`. Source manifests retain their own schema1 byte-catalog
format; runtime manifests also retain their existing schema1 format.

The trusted company builder loads its reviewed `company_source.py` and
`registry_manifest.py` siblings from captured bytes rather than ambient Python
imports. It creates source/release metadata exclusively. Existing or partial
metadata is preserved and blocks rerun; this slice has no reset, migration or
automatic recovery operation. The company build tree must be independently
trusted and quiescent. Creating hashes does not establish signature trust.

The default verifier accepts only canonical schema2 release metadata. It
requires an independently supplied SHA256 of the Ed25519 public key's DER
SubjectPublicKeyInfo, and an explicit expected architecture (`x86_64`). Use an
independently authenticated verifier and Python standard-library runtime:

```sh
/usr/bin/python3 -I -B scripts/verify-release.py BUNDLE PUBLIC_KEY FINGERPRINT --expected-architecture x86_64
```

It first captures bounded public-key, signature and release bytes through
protected held descriptors. It checks the external fingerprint and verifies the
signature over those same captured release bytes before parsing candidate JSON.
It then validates closed types/roles, canonical JSON, config hashes, exact source
coverage and all actual source hashes. Only after all 44 sources match does it
execute the captured `resolve-images.py` bytes to validate the image lock. It
never imports an ambient registry/helper module or reparses a resolver path.
Held paths, descriptors and contents are rechecked before a successful return.

Native verification is Linux only. It uses nofollow/CLOEXEC descriptor reads and
sealed memfd message/signature/public-key inputs to fixed `/usr/bin/openssl`.
Only those three descriptors are passed to the verifier process, with a fixed
environment and a 15-second subprocess timeout. Unsupported memfd/seal/procfs
facilities deny verification. All owned close attempts are made; uncertain close
outcomes latch future acquisition closed without retrying a numeric descriptor.
The fixed system OpenSSL, interpreter and standard library are external trust
dependencies. Local injected controls and a synthetic fixture OpenSSL signature
test do not qualify Linux DAC, memfd, reboot or power-loss behavior. A subprocess
timeout does not prove all possible descendant effects or universal I/O
cancellation.

Caps are 16 KiB release JSON, 4 KiB public PEM, exactly 64 signature bytes, 32 KiB
source manifest, 1 MiB per source/config, 16 MiB source aggregate, 128 records per
snapshot and 80 held directory records. Native regular files require one link,
the caller's explicit owner UID/GID and no group/world write permissions;
ancestors permit root or that owner. Full native file identities include ctime.
The Windows test profile explicitly injects Linux ownership and normalizes its
birth-time/FD-time distinction. No production identity check is weakened.

`inspect_legacy_images` (CLI `--inspect-legacy-images`) is the separately named,
signature-checked schema1 image-bundle inspection API. It never executes company
source and returns `sourceAuthenticated=false` and `productionAuthorized=false`.
Default schema2 verification never falls back to it. Old schema1 bundles are
preserved; malformed or partial schema2 metadata must be handled by the company,
not silently adopted. Existing schema1 bundle UTC timestamps remain inspectable.

`sign-company-release.sh` remains an explicit trusted offline station operation.
Before key use it asks the isolated verifier to capture/check an unsigned
schema2 snapshot in an owned private station directory, signs that captured
release file, and writes signature/public-key outputs exclusively. Signing does
not overwrite partial outputs. Only public metadata and a public key enter its
private scratch directory; the signing private key remains in the station's
protected key path. The station must separately protect its tools, tree, key,
scratch filesystem and environment. Scratch defaults beneath the protected
bundle; `COMPANY_SIGNING_SCRATCH` may select another protected parent. The helper
retains the exact private directory descriptor, checks empty inventory, creates
the finite snapshots exclusively through it, fsyncs and rereads the written
files, and rejects path replacement. Native station writing remains unqualified
by these local tests. No actual release was signed by these tests.

A successful API result means `SCHEMA2_SOURCE_AND_IMAGE_BYTES_AUTHENTICATED` at
this completed read boundary. It explicitly returns `productionAuthorized`,
`nativeAuthorized`, `installerActivated` and `trustContinuesAfterReturn` as false.
Compose/templates and other host activation inputs are outside this 44-script
catalog. An externally authenticated pre-effect bootstrap and retained
source/activation authority are still required. Current install/bootstrap/build
wrapper call sites are not updated in this slice; old verifier CLI calls lack
the mandatory architecture/isolated flags and deliberately deny. These results
must not be used to activate the current installer automatically.

# Schema3 complete deployment byte coverage

The native `release-manifest.py` entry now prepares schema3. The separate
`prepare_deployment_payload` API measures the same 44 scripts and exactly ten
deployment inputs together through the existing protected source snapshot. It
adds canonical `company-deployment.json`, whose own schema1 byte catalog uses
scope `COMPANY_DEPLOYMENT_BYTES_ONLY`. The ten independent paths are:

- `deploy/compose.yaml`
- `deploy/config/grafana-datasources.yml`
- `deploy/config/loki.yml`
- `deploy/config/mysql.cnf`
- `deploy/config/otel.yml`
- `deploy/config/prometheus-web.yml`
- `deploy/config/prometheus.yml`
- `deploy/config/rabbitmq.conf`
- `deploy/config/redis.conf`
- `deploy/config/squid.conf`

Schema3 `release.json` binds that manifest, `company-sources.json` and the three
existing deployment JSON configurations by exact size and SHA256. The existing
Ed25519 `release.sig` therefore authenticates both catalogs and all their
declared inputs. A candidate cannot choose its own coverage: the verifier checks
the independent fixed ten-path catalog, rejecting omissions, extras, duplicates,
traversal, reordered entries, booleans/floats, bad hashes and noncanonical JSON.
An unrelated file physically present in the checkout is not declared or consumed
by this API; later rendering must also use the closed catalog rather than directory
discovery. Creating byte catalogs alone establishes no company trust.

Use the explicitly selected schema3 verifier API `verify_deployment`, or:

```sh
/usr/bin/python3 -I -B TRUSTED_VERIFY_RELEASE BUNDLE PUBLIC_KEY FINGERPRINT --expected-architecture x86_64 --complete-deployment --source-root AUTHENTICATED_CANDIDATE_TREE
```

The expected key fingerprint and initial verifier/interpreter/crypto tools must
be authenticated independently of the candidate artifact. The verifier checks
the signature over the captured release bytes before parsing candidate JSON,
then reads and rechecks all 44 script and ten template bytes through held
descriptors before executing the captured image resolver. It rechecks source,
template, key and bundle bytes again after that resolver returns. Source count
remains 44; deployment count is ten. The new result status is
`SCHEMA3_SOURCE_DEPLOYMENT_AND_IMAGE_BYTES_AUTHENTICATED`, with
`deploymentAuthenticated=true`. All existing activation/native/production flags
and `trustContinuesAfterReturn` remain false. A successful return closes the
read context; callers cannot then treat mutable pathname copies as authenticated.

The template manifest cap is 8 KiB, each declared template is at most 1 MiB,
templates together are at most 4 MiB, and the combined 54 script/template inputs
are at most 16 MiB. Other key, signature, release, configuration, file and
directory caps remain unchanged. Verification does not parse YAML, run Compose,
prove safe semantics, or attest the memory requirements of any service. It
authenticates exact input bytes. Generated configurations, such as the Grafana
template after the installation CA is substituted, require a separately bound
rendering context; their bytes are not the original signed template.

Offline signing selects the complete schema explicitly:

```sh
scripts/sign-company-release.sh BUNDLE PRIVATE_KEY --complete-deployment
```

The verifier CLI combines `--snapshot-for-signing DIRECTORY` with
`--complete-deployment` to select `deployment_signing_snapshot`. It validates
closed schema3 manifests and all five captured payload hashes before writing
exactly six snapshot files, including `release.json`, exclusively through a
held private directory, with fsync and full readback. A partial write or directory
replacement fails and retains the partial output, blocking a fresh rerun. This
unsigned snapshot operation does not read or execute the candidate source tree,
verify a signature, or establish the provenance of the builder's measurements.
The offline station must trust the builder and its own tools before signing.
The original `signing_snapshot`, `inspect_unsigned_schema2`, `verify` and
`prepare_payload` APIs keep their schema2 behavior. Default verifier and signer
selection remains schema2; no schema fallback grants complete coverage.

Local controls preserve the previous 34 test bodies and add schema3 coverage,
tampering, signature ordering/binding, typed catalog/cap checks, mid-read and
post-resolver changes, protection/close uncertainty, exact signing snapshots,
partial-state preservation, and explicit producer/CLI/signer selection. Their
POSIX identity and filesystem behavior is injected on Windows; they do not
qualify native Linux descriptors, actual offline signing, or installation.

Installer, startup and rendering call sites are deliberately unchanged in this
source slice. The company build wrapper is separately owned; schema3 signing
requires its explicit `--complete-deployment` selection. Passing schema3 to the
default schema2 signer fails closed. Early external artifact authentication,
holding authenticated bytes through execution/rendering, complete provenance
retention and real held-parent/storage/runtime ordering are the next integration
work. No signature, child exit or source-only evidence here authorizes host or
service effects.

# Held schema3 authentication context

`authenticated_deployment` supplies the concrete held read boundary for a future
externally trusted installer caller. It accepts the same independently supplied
bundle, key, fingerprint, expected architecture and source root as
`verify_deployment`. It preserves signature-before-parse ordering, the independent
44-script and ten-template catalogs, exact captured hashes and sizes, and resolver
execution only after complete capture. The bundle, key and source `Snapshot`
handles stay open through the caller's entire `with` body.

```python
with trusted_verifier.authenticated_deployment(
    bundle, public_key, fingerprint,
    expected_architecture='x86_64', source_root=candidate_tree,
) as held:
    held.recheck()
    install_source = held.sources['scripts/install.sh']
    compose_template = held.templates['deploy/compose.yaml']
    image_config = held.configs['images.lock.json']
```

`sources`, `templates` and `configs` are closed read-only maps containing immutable
captured `bytes`. `configs` contains all five signed JSON payloads, including the
two byte catalogs. `metadata` is deeply immutable, including the release's nested
file records. No view exposes a mutable alias of the parsed release or captured
maps. Callers must use these byte values rather than reread mutable source paths,
discover ambient templates, or take the example as an installer activation flow.

The context rechecks every held input before yielding and after caller work,
including when the caller raises. Explicit `held.recheck()` has the same boundary;
its failure expires the view even if a caller catches the error and restores a
file. Every context exit expires view access and recheck. Previously obtained
byte values remain immutable historical snapshots; retaining them does not retain
held trust after return. Close failures propagate and keep the existing exact
unknown-handle latch, blocking subsequent acquisition without retry. All owned
snapshot releases are attempted. Recheck, caller or release failure supplies no
completion or activation assertion; effects already performed by a future caller
would require separately retained reconciliation evidence.

The existing `verify_deployment` and schema2/legacy/signing APIs are unchanged.
Their return and `trustContinuesAfterReturn:false` contracts remain unchanged.
The held context's metadata also keeps production, native and installer activation
flags false. It performs byte authentication rather than authorizing host effects.
No entry, install/lib/bootstrap call, company gate, deployment or signing workflow
is wired by this slice. Local controls preserve all49 prior bodies and exercise
held lifetime, immutable maps, post-caller content/metadata changes, errors and
unknown closes. Their POSIX descriptor ownership remains injected; native Linux
installer qualification is still separate.

The held view also exposes `provenance`, a closed read-only map with the exact
keys `release.json`, `release.sig` and `company-signing-public-key.pem`. Values
come directly from the already authenticated bundle and key snapshot records;
exporting the map opens no additional file and does not reread a pathname.
The canonical output key name does not normalize or reserialize the PEM bytes,
signature or release. The exported release is the original signed canonical JSON
object; its hash equals `metadata['releaseSha256']`. The PEM's Ed25519 DER
fingerprint is checked against the caller's independently trusted fingerprint.

An installer can copy these byte values as retained provenance while the context
remains active. Map and byte values are immutable, and view access expires with
the other held maps after return, caller failure or failed recheck. Previously
obtained values remain historical copies. Original release, signature and key
continuity is still checked after caller work; export cannot hide tampering or
authorize effects. The context keeps all 62 existing file handles and their
protected ancestors held, without new capture or release semantics. This narrow
addition wires no installer entry, host lock, template materialization or native
deployment, and does not extend the signed 44-source/10-template catalog.
