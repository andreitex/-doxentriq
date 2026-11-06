# Doxentriq

Build and improve applications by describing what you need in chat. An IT
operator installs and maintains one instance for an organization. Administrators
then use the website to request changes, review previews, invite app users and
approve releases.

**Development preview — not yet ready for independent customer installation.**
The full installer, operating-system matrix and end-to-end recovery acceptance
remain unfinished. A running trial does not establish those results. Read
[installation readiness](docs/installation-readiness.md) before deployment and
[release requirements](RELEASING.md) before distributing source or images.
The project is licensed under [Apache-2.0](LICENSE). The public source destination
is [andreitex/-doxentriq](https://github.com/andreitex/-doxentriq).
The [public secret audit](docs/public-security-audit.md) records its exact
history, artifact and credential-comparison coverage. The
[website claims review](docs/website-audit.md) distinguishes implemented controls
from remaining installation and recovery acceptance.

## Everyday administration

1. Describe the app or improvement: who uses it, what they need to do and who may view or change information.
2. Answer business questions. The system selects technical approaches and configured models within spending limits.
3. Follow recorded progress and test results, then try the preview.
4. Review the proposed changes and approve the exact release to publish it.
5. Set app roles, invite users and request the next improvement through chat.

The [administrator guide](docs/admin-guide.md) explains these tasks, connections,
directory listings, errors and rollback. Platform administration and app accounts
have separate permissions. Listing an app does not remove sign-in requirements.
Passwords and API keys belong in protected forms, never chat.

## Repository components

| Area | Implementation |
|---|---|
| Administration and app directory | React and TypeScript |
| Control API and durable workflows | Fastify, MySQL, RabbitMQ and Redis |
| Identity | Keycloak, local accounts, TOTP and SSO integration code |
| App execution and packaging | Go broker, gVisor and private OCI registry |
| Templates | Node.js browser apps, APIs, workers, DMS and MCPs; Python integration support |
| Operations | Encrypted storage, telemetry, security scanning and backup/recovery tooling |

Implementation is not production acceptance. Major remaining gaps include the
complete reproducible installer, existing-database migration rehearsal and
compatible rollback, fresh security qualification, backup restoration and
first-time administrator usability validation. Several integrations need
provider-specific implementation or live qualification; see
[integration scope](docs/external-integrations.md).

## For IT operators

Deployment targets one amd64 Debian 12/13 or Rocky Linux 9/10 VM. The planned
minimum is 4 vCPU and 16 GiB RAM; the production recommendation is 8 vCPU and
32 GiB RAM. These are target configurations, not a completed support matrix.
IT handles DNS, certificates, encrypted storage, credentials, SSO, budgets and
recovery material. Routine application management belongs in the website.

The current installer requires a company-provisioned trusted bootstrap; a
checkout alone cannot complete installation. Inspect help without installing:

```sh
bash scripts/install.sh --help
bash scripts/autosoft.sh --help
```

Use a disposable VM for installation development and preserve existing trial
data. One VM provides no high availability. A VM-local unlock key does not protect
against theft of the complete VM. Off-VM recovery requires separately configured
backups and exported recovery material.

## Local development

Node.js 24 LTS is the production target; Node 22.19 or newer runs the local
development interface. Use the checked-in lock:

```sh
npm ci
AUTH_MODE=development PUBLIC_ORIGIN=http://127.0.0.1:5173 npm run dev
```

For PowerShell, set the variables before starting the API:

```powershell
$env:AUTH_MODE = 'development'
$env:PUBLIC_ORIGIN = 'http://127.0.0.1:5173'
npm run dev
```

In another terminal run `npm run dev:ui`, then open
`http://127.0.0.1:5173`. Development authentication accepts loopback clients only.
This setup does not install sandbox infrastructure or configure model providers.
Requests pause with setup guidance when a required service is absent.

```sh
npm run typecheck
npm test
npm run build
cd services/runtime
go test ./...
go vet ./...
```

The Go toolchain is declared in `services/runtime/go.mod`. Local tests use
injected providers and do not require paid model calls. Installation, storage
and recovery acceptance requires the separately documented Linux VM environment.

## Contributing and release status

Read [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md) and
[RELEASING](RELEASING.md). Keep customer installations, credentials, private test
receipts and generated business applications out of public commits. The source
checker reports potential disclosures without printing matching secrets.
Historical engineering evidence is retained separately from the publication
candidate. Source publication and production readiness have separate release
checks. See [third-party licensing](docs/third-party-licenses.md) before
distributing compiled bundles, containers or dependency source.
