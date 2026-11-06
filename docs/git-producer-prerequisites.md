# Git prerequisites for company source production

Before preparing a complete source release, run this on the trusted Linux
builder:

```sh
python3 -I -B scripts/release-manifest.py --producer-preflight
```

The command checks only `/usr/bin/git`, reads no repository, creates no release
files and installs nothing. Complete-source production calls the same check
before capture; the company image pipeline calls it before creating its output
or downloading/building images when `COMPLETE_PLATFORM_REVISION` is selected.

The current policy requires Git **2.45.1 or newer**, plus a successful actual
`--no-lazy-fetch --version` probe. This is a functional prerequisite, not a
vulnerability clearance. Use a maintained package and retain the company's
independent tool provenance and security checks.

Git introduced the command-line option in 2.45.0. The 2.45.1 source also checks
the no-fetch environment setting in the direct promisor-fetch path before
starting a fetch child. That path lacks the guard in 2.45.0. This is why accepting
the option alone is insufficient. See the [2.45 release notes](https://raw.githubusercontent.com/git/git/v2.45.0/Documentation/RelNotes/2.45.0.txt),
the [2.45.0 implementation](https://raw.githubusercontent.com/git/git/v2.45.0/promisor-remote.c)
and the [2.45.1 implementation](https://raw.githubusercontent.com/git/git/v2.45.1/promisor-remote.c).

The current query protocol retains both `--no-lazy-fetch` and
`GIT_NO_LAZY_FETCH=1`. It never retries a repository read without the option.
Some older maintained releases backport the environment guard without adding
the option; for example, the [2.39.4 source](https://raw.githubusercontent.com/git/git/v2.39.4/promisor-remote.c)
contains that guard. An older version string or an accepted environment variable
does not establish equivalent behavior. Supporting an environment-only protocol
would require a separately reviewed adapter and native missing-object/helper
containment tests. No such fallback is implemented.

As checked on 2026-11-06, the official package listings show:

| Distribution | Listed Git | Current option policy |
|---|---|---|
| [Debian 12](https://packages.debian.org/bookworm/git) | 2.39.5 | Does not satisfy the current producer requirement |
| [Debian 13](https://packages.debian.org/trixie/git) | 2.47.3 | Version meets the requirement; probe the installed tool |
| [Rocky 9](https://download.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/g/) | 2.52.0 | Version meets the requirement; probe the installed tool |
| [Rocky 10](https://download.rockylinux.org/pub/rocky/10/AppStream/x86_64/os/Packages/g/) | 2.52.0 | Version meets the requirement; probe the installed tool |

These listings are not an installation receipt, a security approval or proof of
the package selected by a customer's configured repositories. If the actual
tool fails, use an approved Linux builder or supply a company-reviewed Git
package built for that exact OS. Do not mix distribution packages, replace a
system binary with an unverified download or remove the guard to continue.
A separately signed, maintained package and its lifecycle for Debian 12 have
not yet been implemented or qualified.

The same Git option is used by later host repository-seed operations. Their
capability check and supported-package delivery must be integrated before full
Debian 12 installation can be accepted. The source producer preflight does not
mark those later stages complete.

Basic bounded Git transport tests can pass with Git 2.43 even though it cannot
run the protected complete-source capture protocol. Those tests must not be
reported as schema4 capture acceptance. Actual capture still
requires the eligible tool, a clean protected Git checkout, the exact reviewed
revision and the real source/cross-catalog verification.
