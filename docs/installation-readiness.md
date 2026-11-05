# Installation readiness

Reviewed November 5, 2026. The repository is a development preview. It does
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
| Complete platform setup | `deploy/installer/company-install.sh` accepts only `--foundation-only`. `scripts/install.sh` explicitly stops the retained full-install function before service deployment. `company_full_cli.py` and `company_source_owned_execute.py` retain refusing default entry points. Finish and qualify the native full entry before advertising installation. |
| Safe rerun and interruption recovery | Read-only `--status` now reports retained stages and missing confirmation through the normal installer/maintenance entry points. Partial records remain preserved. The foundation command is not a general resume command: native stage reconciliation and continuation still need implementation and disposable-VM acceptance. Do not delete records to make a rerun succeed. |
| Clean-install OS matrix | Debian 12/13 and Rocky Linux 9/10 are source targets. Retained Rocky 10.2 foundation and reboot reports cover a limited earlier configuration. They do not establish complete clean-install, rerun, or failed-unlock recovery on any of the four targets. |
| Usable first sign-in | A new installation must reach the admin URL, force owner password change and TOTP enrollment, and explain how to recover access. Test real DNS/certificate configuration, including the identity hostname and application subdomains, without trial-only browser mappings. |
| Routine operations | Demonstrate service restart after reboot, certificate renewal, fresh security feeds, scheduled backups and isolated restoration using the released installer. Existing helper tests or a manually assembled trial do not establish those outcomes. |

Source locations: [foundation phases](../scripts/install.sh),
[company shell entry](../deploy/installer/company-install.sh),
[full CLI](../deploy/installer/company_full_cli.py),
[source-owned execution](../deploy/installer/company_source_owned_execute.py),
[configuration and verification](../scripts/bootstrap.py),
[maintenance commands](../scripts/autosoft.sh).

## Next executable milestone

Finish **one complete signed installation on a fresh Rocky Linux 10 VM** using
the same published artifacts an external IT operator receives. Keep the current
trial VM and its documents intact. Record the installer commands and versions,
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
