# Contributing

AutoSoft source is licensed under [Apache-2.0](LICENSE). The project repository
is [andreitex/-doxentriq](https://github.com/andreitex/-doxentriq). Contributions
intended for inclusion are submitted under that license. Do not submit company
or customer code without permission to distribute it under those terms.
Production acceptance and the release checks remain separate requirements.

Describe the user-visible problem, expected behavior and steps to reproduce it.
Use synthetic records, example domains and fake credentials in issues and tests.
Keep customer documents, production logs, database dumps, invitation links,
private keys and deployment evidence out of contributions.

## Development

Use the toolchain versions declared in `package.json` and `services/runtime/go.mod`.
The installation runtime targets Node.js 24 LTS. Follow the local development
instructions in [README](README.md); production authentication and storage are
separate from local development mode.

Run the checks affected by your change:

```sh
npm run typecheck
npm test
npm run build
(cd services/runtime && go test ./... && go vet ./...)
python3 -I -B scripts/public-release-check.test.py
python3 -I -B scripts/public-release-export.test.py
python3 -I -B scripts/test-seed-backend-history.py
python3 -I -B tests/test_company_seed_backend.py
```

Installer, encryption, reboot, sandbox and recovery changes also require their
native Linux acceptance checks. Tests with simulated providers do not establish
working customer installation or real provider behavior. Do not use real model
credentials in CI or make paid requests from pull requests.

Public source checks run on pull requests and updates to `main`, and can also
be started manually. They check source hygiene, build and tests, public package
advisories, and the Go runtime. Passing CI does not qualify VM installation,
container images or recovery behavior.

Run the historical backend controls through their
[documented runner](docs/backend-history-tests.md), which supplies each original
test with its exact pinned source fixture. Directly running an old test against
today's backend can correctly reject a mismatched historical source. The current
backend suite remains a separate check.

For dependency changes, preserve independent application locks and use the
reviewed public-package advisory workflow described in
[public dependency advisories](docs/public-dependency-advisories.md).
Never send private package names or customer source to an advisory service.

Keep changes scoped. Explain behavior, relevant tests and any remaining limits
in the pull request. Security-sensitive changes need review of backend permission
checks, request retries, data preservation and approval behavior.

Preserve exact bytes of pinned source inputs and reviewed fixtures. The repository
disables Git's automatic newline conversion because changing CRLF/LF can invalidate
integrity hashes. Prefer LF for new files, but do not bulk-normalize existing files.
An intentional byte change must update the applicable reviewed pins and checks.

Report suspected security vulnerabilities using [SECURITY](SECURITY.md), without
putting exploit details or credentials in a public issue.
