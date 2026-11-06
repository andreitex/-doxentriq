# Installation readiness

Reviewed November 6, 2026. The repository is a development preview. It does
**not yet provide a complete installer that an independent IT operator can run
on a clean VM**. The existing trial must not be described as clean-install
acceptance for a public release.

## What currently works in the source

The foundation code prepares dependencies, a new LUKS2 backing file, encrypted
Docker/containerd storage and journals, gVisor, resource checks, and startup
guards. Existing backing files and partial installation records are preserved.
The configuration wizard collects separate admin, app and identity URLs,
certificate/SSO settings, model credentials, budgets, timezone and backup options.
The maintenance CLI has read-only help and installation-status commands:

```sh
bash scripts/install.sh --help
bash scripts/autosoft.sh --help
sudo bash scripts/install.sh --status
sudo bash scripts/install.sh --status --json
# After the maintenance command has been installed:
sudo autosoft installation-status
```

These commands do not install anything. Status works from the source checkout
before a bootstrap or full installation exists. It reports retained sessions,
stages with an intent but no confirmation, inconsistent records, and missing
bootstrap prerequisites. It checks only the presence of protected configuration
and the volume key; it never reads their contents. The result is advisory: it
does not authenticate installation effects, authorize recovery, or report a
foundation-only installation as complete. Preserve pending records and storage
and have IT reconcile the reported stage before continuing. Other maintenance
commands require an existing installation and root access.
Everyday application management belongs in the administration website.

## Release blockers

| Requirement | Current evidence and missing work |
|---|---|
| Install from a public release | `scripts/install.sh` delegates to `/opt/autosoft-company/bootstrap/company-install.sh`. A checkout does not supply that trusted installed entry. Publish a verified bootstrap and signed source/image bundle with a documented trust fingerprint. |
| Complete platform setup | `deploy/installer/company-install.sh` accepts only `--foundation-only`. `scripts/install.sh` explicitly stops the retained full-install function before service deployment. Experimental companions now cover [configuration and placement](native-configuration-stage.md), [repository seeding](native-repository-seed.md), [runtime initialization](native-runtime-pair.md), [retained-source startup inspection](native-stored-startup.md) and [native rendering](native-rendering.md). Rendering now has an executable same-session successor and independent output verification, with component evidence only. Actual signed execution on a fresh encrypted VM, Caddy/SELinux qualification, identity, service activation and recovery still need one complete accepted installer. |
| Safe rerun and interruption recovery | Read-only `--status` now reports retained stages and missing confirmation through the normal installer/maintenance entry points. Partial records remain preserved. The foundation command is not a general resume command: native stage reconciliation and continuation still need implementation and disposable-VM acceptance. Do not delete records to make a rerun succeed. |
| Clean-install OS matrix | Debian 12/13 and Rocky Linux 9/10 are source targets. Retained Rocky 10.2 foundation and reboot reports cover a limited earlier configuration. They do not establish complete clean-install, rerun, or failed-unlock recovery on any of the four targets. |
| Usable first sign-in | A new installation must reach the admin URL, force owner password change and TOTP enrollment, and explain how to recover access. Test real DNS/certificate configuration, including the identity hostname and application subdomains, without trial-only browser mappings. |
| Routine operations | [Quota startup controls](quota-service-startup.md) now order Docker after the ready quota service and bounded build mount, preserve the socket directory and drain admitted requests during shutdown. Linux helper tests and systemd syntax/dependency validation passed; actual installation and reboot remain unqualified. Demonstrate certificate renewal, fresh security feeds, scheduled backups and isolated restoration using the released installer. |

Source locations: [foundation phases](../scripts/install.sh),
[company shell entry](../deploy/installer/company-install.sh),
[full CLI](../deploy/installer/company_full_cli.py),
[source-owned execution](../deploy/installer/company_source_owned_execute.py),
[configuration and verification](../scripts/bootstrap.py),
[maintenance commands](../scripts/autosoft.sh).

## Next executable milestone

Finish **one complete signed installation on a fresh Rocky Linux 10 VM** using
the same published artifacts an external IT operator receives. Use a disposable
VM or an explicitly authorized reset target with a verified recovery copy. Removing
application files from an existing host is not a clean operating-system install.
Record the installer commands and versions,
then verify these outcomes:

1. One guided command completes and reports working admin/apps/identity URLs,
   protected owner credentials, certificate trust steps and recovery instructions.
2. A rerun preserves configuration, accounts and data; an interrupted run gives
   a precise recovery action without requiring source edits.
3. Reboot restores services. A failed encrypted-volume unlock leaves container
   services stopped; restoring the key restores access without formatting.
4. A nontechnical administrator creates and publishes an app, invites a local
   user, requests an update and understands any required approval or failure.
5. Backup restoration into an isolated target preserves documents and app state.

After this passes, repeat the same artifact on the other three OS targets. Do
not replace a failing safety check with a bypass to complete this milestone.

## Checks run during this review

A fresh Rocky Linux 10.2 VM passed 42 network-control tests (162 including
subtests), 11 native installer-source cases and five shell syntax checks. Three
Git-dependent source cases were skipped because Git was not installed on the
base VM. After the current archive-layout update, the
[runtime archive verifier](runtime-archive-verification.md) passed all 23 native
cases on that VM. The [storage fault harness](storage-fault-qualification.md)
also passed all 12 component cases, including four private mount-namespace
fixtures using the original guard and library. These 35 cases had no skips;
SELinux remained enforcing, and the host mount table was unchanged. They used
synthetic configuration, executed no runtime binary or cryptsetup operation,
and did not install the platform, create its encrypted volume or qualify reboot
recovery. The remaining release and activation blockers above still apply.

The five existing installation-budget controls passed locally. They verify
finite positive limits and reject malformed/zero/infinite inputs before secrets
are written. Bash syntax and both new help paths passed on Windows Git Bash;
the missing-bootstrap path returned a clear error before performing any install
action. These checks do not qualify native Linux installation or reboot.

Nine installation-status tests cover fresh and partial state, retained foundation
completion, inconsistent confirmations, unreadable/linked/oversized records,
secret exclusion, no filesystem changes, and early shell dispatch. Complete-source
archive tests preserve Apache/public metadata and CI workflows byte-for-byte and
continue to reject credential paths. Native installation acceptance remains open.

Further component checks exercise the actual Source terminal journal filename,
the initialized runtime pair, and the captured owner identity dependency. The
source terminal fix passed five native cases plus 50 backend controls; the pair
passed ten native filesystem/Bash cases using synthetic authority or host state.
[Captured identity checks](captured-owner-identity.md) cover the full dependency
chain. These results do not substitute for a signed installation, live owner
login or VM reboot test.

[Native rendering](native-rendering.md) adds 36 reviewed component cases covering
the original renderer's actual file writes and independent readback, real
OpenSSL, fixed synthetic Docker responses, package assembly and genuine Bash
admission with synthetic effects. They do not establish complete signed-worker,
actual Caddy/SELinux or encrypted-VM acceptance.
