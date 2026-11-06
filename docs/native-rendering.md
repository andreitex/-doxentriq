# Native rendering stage

The experimental company installer can now retain signed source, inspect its
initialized runtime and render platform configuration in one admission session.
This is an executable component, **not a completed or independently qualified
clean-VM installer**. Identity provisioning, service activation and recovery
acceptance remain separate work.

The company package producer's `--render-entry` option emits `company-render.sh`
beside the authenticated native worker. After configuration, repository seeding
and runtime-pair initialization, IT can use the separately authenticated entry:

```sh
bash --noprofile --norc /protected/company-render.sh \
  --retain-inspect-and-render /opt/autosoft-company/requests/OPERATION.json
```

The entry requires empty retention parents and a quiet foundation. Existing
retention-only commands remain available. Partial sessions or previously
rendered files are preserved and refused; this command does not resume them.

## Controls implemented

- The original signed-source verifier, captured assembly and live Bash parent
  remain authoritative. Store, Source and startup confirmations must belong to
  that same session. Retained physical source is rechecked in separate closed
  scopes before and after writes; its ancestor identity guard is not weakened.
- A finite descriptor-based output plan controls configuration, secrets, PKI,
  permissions and directory changes. Creation is exclusive. Provider credential
  bytes stay unchanged through explicitly permitted ownership transitions.
- Tool and local digest-pinned Caddy-image checks run before admission and
  credential creation. OpenSSL writes through exclusive inherited file
  descriptors; bcrypt passwords use stdin. Processes have finite time/output
  limits and owned-child cleanup, including failed resource acquisition.
- The temporary Caddy container uses `--pull=never`, no network, a read-only
  root, restricted capabilities and resource limits. Only its exact confirmed
  identity can be removed. Unknown outcomes are retained without blind retry.
  Its Caddyfile has an explicit verified SELinux label transition when needed;
  Docker does not implicitly relabel it. SELinux remains enabled.
- A separate read-only child verifies the exact output inventory, hashes and
  permissions, credential relationships, realm policy, image bindings and TLS
  chains, key pairs and hostnames. Bash acknowledges only after successful
  execute and verification exits and an exact bound confirmation.

## Component evidence and limits

On November 6, 2026, the reviewed isolated implementation passed **36 distinct
component tests with zero skips**:

| Cases | Evidence |
|---:|---|
| 16 | Actual Linux files, descriptors, ownership and fsync; the original complete renderer and independent readback, using synthetic crypto/container commands. |
| 5 | Actual OpenSSL signing and verification through held FDs, wrong-host/invalid-CSR refusal, arbitrary-command refusal and selector-failure cleanup. Docker/socket preflight was explicitly injected. |
| 6 | Synthetic Docker responses checking the fixed profile, bounded tmpfs, unknown-outcome preservation and cleanup. |
| 3 | Actual package assembly/module loading, original parent-record parsing and entry composition. |
| 6 | Original Bash admission and HeldParent in private mount namespaces, with synthetic effects; four-stage success and failure/stale/preflight/rerun controls. |

These tests did not execute the complete signed native worker on an encrypted
VM or execute Caddy/Docker. Native Rocky SELinux labeling, actual Caddy output,
all source/parent/storage contexts together, and failed-unlock/reboot recovery
still need acceptance. Source integration preserves the newer identity
provisioning controls; it does not make those remaining checks pass by inference.

The real host needs trusted OpenSSL, `htpasswd`, Docker and the already-local
approved Caddy image. Installer dependency delivery must demonstrate these
prerequisites. A company-produced matching source catalog, signed artifacts and
authenticated bootstrap are also required; a source checkout supplies none of
those trust decisions by itself.

Native tests use a fresh root-owned mode0700 `DOXENTRIQ_NATIVE_TEST_ROOT` supplied
by CI. Namespace fixtures bind synthetic `/etc` and `/opt` only inside private
child mount namespaces. They do not modify host services. See
[installation readiness](installation-readiness.md) for the complete milestone.
