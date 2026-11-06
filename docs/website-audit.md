# Doxentriq website accuracy audit

Reviewed **6 November 2026** (Europe/Bucharest) against public source commit
`1ff9302f1a67582568514088882fd89fa195df13`, the current administrator and
installation guides, and retained trial verification. This is a factual product
and documentation review, not a certification of production readiness or a legal
review of the website policies. No website content was changed or published.

The site already identifies Doxentriq as early access and explicitly says it is
not production ready. Those disclosures are useful. Several specific feature
and installation statements nevertheless imply more completeness or stronger
guarantees than the evidence supports. These are overstatements and stale
information; the audit does not establish an intent to mislead.

## Scope and capture

Read the live [homepage](https://doxentriq.com/),
[privacy policy](https://doxentriq.com/privacy-policy.html),
[terms](https://doxentriq.com/terms.html), and
[cookie policy](https://doxentriq.com/cookie-policy.html), plus the public
JavaScript, stylesheet, robots file, sitemap and homepage response headers.
All four pages returned HTTP 200 over certificate-verified HTTPS. The homepage
capture SHA-256 is
`cbe833dc30409baf7c1480123bf09016562628c580935ebdf39ce825e2303c15`.
Original responses and a capture manifest are retained privately.

A separately located local website source was subsequently found. Its homepage
bytes match the live capture hash above exactly. Corrected homepage copy and a
unified patch have been prepared privately for review; the live website and its
source files have not been changed. The draft replaces unsupported category
comparisons with an evaluation checklist and keeps installation limitations
visible beside the setup instructions.

The reviewed page is a static site. Its fetched HTML, JavaScript and stylesheet
contain no configured external analytics loader, remote font import or tracking
request. Theme and consent preferences use browser local storage. This supports
the narrow description of the delivered static assets; it does not independently
verify hosting logs, infrastructure access, retention periods, subprocessors,
future deployments or the company's contractual practices.

## Corrections to prioritize

| Priority | Location and claim, paraphrased | Finding | Recommended correction |
|---|---|---|---|
| High | [Install](https://doxentriq.com/#install): cloning the repository and running the installer provisions a hardened, encrypted server. | Incorrect for the published checkout. The entry requires a separately trusted company bootstrap; the full CLI/source execution entries still refuse installation. The example also invokes `npm` on a fresh base VM without installing Node or the locked dependencies. | Replace the server-install recipe with an explicit development-preview notice and link to [installation readiness](installation-readiness.md). Show only the harmless help/status commands until the independently installable signed artifact passes acceptance. |
| High | [Features](https://doxentriq.com/#features): the platform is complete. | Contradicts the early-access disclosure and documented installation, migration and recovery blockers. | Describe it as a platform under active development, with tested components and an explicit readiness matrix. |
| High | [Comparison](https://doxentriq.com/#compare): the whole system runs on the customer's infrastructure. | Misleading without a nearby exception: configured OpenAI or Anthropic services perform model inference externally. Source code, specifications, chat and redacted diagnostics can leave the VM. | Say that the application runtime and storage are self-hosted, while configured model providers process development context. Do not imply offline or on-premises model inference is currently supported. |
| High | [Security](https://doxentriq.com/#security), [comparison footnote](https://doxentriq.com/#compare) and [FAQ](https://doxentriq.com/#faq): endpoints and business records can never enter model context. | The code redacts known credentials and recognized secret patterns; it does not semantically recognize every confidential record or endpoint in arbitrary chat, specifications or application source. `job.request`, answers and selected source are passed to providers after redaction. | Explain what is sent, that registry credentials are kept out of prompts, and that administrators must not paste secrets or confidential business records into chat. Do not promise universal content exclusion. |
| High | [Security](https://doxentriq.com/#security): generated code never receives production credentials. | Accurate only for generation/build/test isolation. Published app runtimes intentionally receive their own restricted database, Redis and RabbitMQ credentials through scoped files. | Separate build-time isolation from runtime access. State that builds receive no production credentials and deployed apps receive only their approved, app-specific credentials. |
| High | [Backup feature](https://doxentriq.com/#features) and [architecture](https://doxentriq.com/#architecture): nightly/15-minute backups are generally restore-tested. | Overstates the demonstrated scope and omits outages. Synthetic isolated MySQL/document-chain restoration has passed; complete platform recovery and production data replacement remain unavailable. Nightly cold checkpoints stop platform/app containers; incrementals briefly stop writers. | State the actual schedule design, interruption cost, limited restoration evidence and unfinished whole-platform/off-VM recovery. Link to [operations](operations.md). |
| High | [Workflow](https://doxentriq.com/#how) and [rollback FAQ](https://doxentriq.com/#faq): migrations and rollback broadly guarantee preserved data. | Supported publication checks must pass, but existing-data migration rehearsal, schema epochs and compatible end-to-end rollback remain unfinished. `migration_rehearsal.go` deliberately leaves imported snapshots ineligible for publication until the remaining contract is established. Retaining code versions is not proof that every rollback is compatible. | Say that compatible code rollback normally retains business data; incompatible schemas block publication/rollback. Database restoration is a separate approved action and can lose newer writes. Never imply that rollback reverses payments, invoices or emails. |
| Medium | [Model FAQ](https://doxentriq.com/#faq): every bundled model is initially unqualified. | Factually stale. The audited public `models/catalog.json` contains four `qualified: true` entries and two `false` entries. A catalog flag is not itself a fresh per-installation/provider qualification result. | Describe selection from the maintained catalog and the additional configured qualification/budget requirements. Remove the blanket claim about all bundled flags. Revisit the public defaults separately if unqualified-by-default is the intended product policy. |
| Medium | [App portal feature](https://doxentriq.com/#features): the directory is only for public apps, with protected apps shared only by direct link. | Out of date. Protected apps can now be listed by an exact owner/MFA review of their metadata and link, while retaining app sign-in and permissions. | Explain that owners can list either public or protected apps; protected listings still require sign-in. Listing does not grant access. |
| Medium | [Status](https://doxentriq.com/#status): all claims have published machine-readable proof and all gaps are listed. | Too broad. Some private trial evidence is intentionally not public; local tests, historical receipts and live qualification prove different things. The status card omits the full installer entry and permanent quota/service-address reboot recovery as immediate blockers. | Publish a dated, version-bound status table with evidence scope, open blockers and explicit private-evidence summaries. Link to current CI and installation readiness. Do not claim universal proof coverage. |
| Medium | [Status](https://doxentriq.com/#status): live invitations and webhook deduplication are wholly future work. | Stale categorization. Local invitation workflows and local DMS accounts exist; Google/Microsoft live qualification remains separate. Stripe signed metadata ingress and deduplication helpers exist and are locally tested, while outbound payment execution and production ingress qualification do not. | Split each capability into implemented source, live-tested scope and missing qualification. Keep outbound email/payment/invoice adapters on the roadmap. |
| Medium | [Comparison](https://doxentriq.com/#compare): Doxentriq is as easy as hosted builders, and broad categories lack competing controls. | No first-time nontechnical usability study or versioned competitor evidence supports these comparisons. Category-level yes/no/rarely judgments hide material differences between products and configurations. | Replace the table with a buyer checklist, or name and date specific independently verified comparisons. Present nontechnical usability as a design goal until observed testing supports it. |
| Medium | [Budget feature and cost FAQ](https://doxentriq.com/#faq): hard caps and only VM/model costs. | The platform can control requests it initiates and reserve estimated cost; it cannot cap other use of the same provider key/account or guarantee an external provider invoice. Optional storage, backups, DNS, integrations and support can also cost money. | Describe Doxentriq request/monthly controls, uncertain-charge reconciliation and separate provider/account limits. Say operating costs depend on infrastructure, model use and selected services. |
| Medium | [Security](https://doxentriq.com/#security): absolute fail-closed and proof guarantees. | These are engineering policies and tested controls, not evidence that every implementation path is defect-free. Signature-enforcement source and digest pins also do not establish a publicly shipped, signed install release. | Describe the enforced checks and tested scope. State that known Medium-or-higher findings block ordinary release, unavailable scanning blocks approval, and ongoing monitoring is needed for new findings. Tie any signature claim to an actual distributed artifact. |
| Low | [DNS/TLS requirement](https://doxentriq.com/#install): certificates come from DNS providers. | Route53, Cloud DNS and WHM/cPanel provide DNS validation, not the public certificate issuer in this design. | Say that Let's Encrypt uses DNS-01 validation through those providers, or that the installation can use a private CA. Mark provider-specific clean-install acceptance as pending. |
| Low | Hero mock interface. | Its ARIA label identifies an example, but sighted readers are shown synthetic test counts, a passing migration and a ready release without a prominent visible qualification. | Add a visible caption explaining that it is an illustrative workflow using synthetic data, not a recorded acceptance result. |

## Missing information that matters to users

1. **IT installation versus everyday use.** Say explicitly that IT handles DNS,
   TLS, provider credentials, budgets, encrypted storage, maintenance and recovery.
   Customer administrators describe business needs, review previews and approve
   changes. Link directly to the [administrator guide](admin-guide.md).
2. **Current installation boundary.** Prominently identify the public download as
   a development preview. Debian 12/13 and Rocky 9/10 are target environments;
   a complete supported clean-install/reboot/failed-unlock matrix is pending.
3. **Local application accounts.** Explain that platform administration and app
   accounts are separate, app-local invitations work without Google/Microsoft,
   and SSO login is separate from API consent and directory-group authorization.
   Link to [local DMS accounts](dms-local-accounts.md). Invitation delivery is
   currently manual; the platform does not automatically email the link.
4. **One-VM limits.** One VM supplies no high availability. A VM-local unlock key
   does not protect against theft of the whole VM. Recovery from complete VM loss
   requires independently retained backups and recovery material. These belong
   beside encryption/backup claims, not only in repository documentation.
5. **Security and privacy boundaries.** Explain external model processing near
   the main proposition, the scope of app secrets, scan coverage/freshness, and
   separate approval for destructive actions, data restore and access-policy
   changes. Code rollback does not roll back access policy.
6. **Evidence and releases.** Add a last-reviewed date, tested commit, CI link,
   release notes and clear separation of source publication from a supported
   binary/image release. Avoid fixed test-count marketing unless generated from
   the exact CI run with skipped/live tests explained.
7. **Private security reporting.** Link directly to
   [GitHub private vulnerability reporting](https://github.com/andreitex/-doxentriq/security/advisories/new),
   matching [SECURITY.md](../SECURITY.md). Email can remain an additional company
   contact; this audit did not test mailbox delivery or response commitments.
8. **Naming.** The website already uses Doxentriq consistently. The audited public
   README, security policy and administration text still use AutoSoft. Change
   public-facing branding deliberately; internal storage paths, service IDs,
   cookie names, token issuers and migration-sensitive identifiers need a
   compatibility plan instead of a global replacement.

## Suggested replacement copy

### Hero and readiness notice

> Build and improve business apps through chat.
>
> Doxentriq is an Apache-2.0 platform under active development. IT operates the
> installation; administrators describe business needs, follow progress, review
> previews and approve exact releases. Applications and storage run on your
> infrastructure. Your configured AI provider processes development prompts and
> selected, redacted context.
>
> Development preview. The complete installer, supported operating-system matrix
> and end-to-end recovery acceptance are still being finished. Explore the source
> or try the local development interface with synthetic data. See installation
> readiness before planning a server deployment.

### Server-install panel, until the full installer is qualified

> Independent server installation is not available from this checkout yet. The
> current entry requires a trusted company bootstrap, and full installation is
> deliberately blocked while its safety and recovery checks are completed.

```sh
git clone https://github.com/andreitex/-doxentriq.git doxentriq
cd doxentriq
bash scripts/install.sh --help
```

> This displays help; it does not install the platform. IT operators should follow
> the installation-readiness document and use a disposable VM for development.

### Data and credentials FAQ

> Application databases and documents are stored on the infrastructure you
> operate. Doxentriq sends your configured AI provider chat, specifications,
> selected application source and redacted diagnostic context. Protected
> connection credentials are kept out of model prompts. Redaction is a safety
> control, not a guarantee that arbitrary confidential text will be recognized;
> use synthetic examples and never paste secrets or business records into chat.
> Configured SSO, DNS, certificate, backup and integration providers have their
> own processing boundaries. There is no default usage-telemetry service operated
> by FirstIT in the reviewed application configuration.

### Build isolation and runtime access

> Untrusted builds and tests run in restricted gVisor sandboxes without production
> credentials or a Docker socket. Deployed applications receive only their
> provisioned app credentials and approved connection capabilities. Dependency,
> test, security and approval checks must pass for a supported release to publish.

### Backup and recovery

> Encrypted backup tooling supports nightly cold checkpoints and 15-minute
> incremental archival. The current implementation can interrupt services or
> writers. Isolated MySQL/document recovery has passed synthetic-data tests;
> complete platform restoration, off-VM recovery and installation-wide reboot
> acceptance remain in progress. Compatible code rollback normally preserves
> current business data. Restoring a database is a separate approved operation
> that can discard newer writes.

### Portal and user access

> Owners can choose which apps appear in the portal. Protected apps still require
> sign-in and their approved roles when listed. Each app can use invitation-based
> local accounts independently of platform administration; Microsoft or Google
> sign-in is optional when configured and qualified.

## Policy and website observations

The terms correctly separate the Apache-2.0 source license from website terms
and acknowledge early-access limits. The privacy policy correctly distinguishes
the static website from customer installations and mentions configured AI and
other external providers. Its absolute no-company-access statement should start
with a default-deployment qualification, consistent with the following paid
support/hosting exception.

The reviewed static assets support the statement that no analytics tool is
currently configured. A consent UI for a hypothetical future analytics tool adds
complexity without activating analytics; simplify it if the site will continue
to use only local preference storage. Any future analytics deployment must be
reviewed against its actual documented configuration rather than treating an old
generic choice as evidence for a new tool.

Company facts and operational promises still need confirmation from their
owners: the business registration/address, experience claim, support offerings,
hosting/email providers, access-log retention, correspondence retention and data
protection arrangements. Client-side source cannot establish them. This audit
does not decide legal bases, statutory obligations or enforceability.

The sampled HTTPS response did not advertise Content-Security-Policy,
Strict-Transport-Security, X-Content-Type-Options or Referrer-Policy headers.
That is a separate web-hardening opportunity, not proof of a product claim being
false. Any CSP must account for the current inline theme/bootstrap and structured
data scripts; do not deploy a blanket policy without a browser regression check.

## Evidence references

- [Installation readiness](installation-readiness.md),
  [installer entry](../scripts/install.sh),
  [company installer](../deploy/installer/company-install.sh),
  [full CLI](../deploy/installer/company_full_cli.py), and
  [source-owned executor](../deploy/installer/company_source_owned_execute.py).
- [Provider context construction](../packages/core/src/models.ts),
  [redaction](../packages/core/src/security.ts),
  [app credential environment](../services/runtime/deploy.go), and
  [public model catalog](../models/catalog.json).
- [Operations and backup limitations](operations.md),
  [migration rehearsal contract](../services/runtime/migration_rehearsal.go), and
  [network/reboot recovery limitations](runtime-network-recovery.md).
- [Administrator guide](admin-guide.md), [local accounts](dms-local-accounts.md),
  [external integration scope](external-integrations.md), and
  [public-source CI for the audited commit](https://github.com/andreitex/-doxentriq/actions/runs/42119999051).

The audit also found that the public commit's `docs/operations.md` portal
paragraph still described public apps only. The newer administrator guide and
implementation allow explicit protected-app listings. That paragraph has now
been corrected in the working source; include the correction in the next public
update so the website and its linked documentation agree.
