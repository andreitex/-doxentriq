# Public dependency advisory checks

`scripts/public-npm-advisories.py` checks the exact public dependency names and
versions in a version 3 lockfile against npm's fixed Bulk Advisory endpoint.
Every name must already appear in a separately reviewed company catalog. The
checker requires the exact public-registry tarball URL and pinned SHA512
integrity. Unknown names, foreign registries, credentials in URLs and missing
integrity stop the request. Root and valid local workspace links are excluded;
their code requires separate source scanning. A private external dependency or
a forged link marker blocks this check rather than silently reducing coverage.

The checked-in `models/dms-reviewed-public-npm.json` covers the 85 known public
packages in the DMS reference lock. It grants no package execution, connection
or release approval. Generated applications cannot extend this company list.
Review new SDK provenance and public visibility before extending it.

Run a no-network preview first:

```sh
python3 -I -B scripts/public-npm-advisories.py \
  --lock templates/dms/package-lock.json \
  --reviewed-public-packages models/dms-reviewed-public-npm.json --dry-run
```

Omit `--dry-run` to make one fixed HTTPS request. `--report` saves the result.
No npm CLI, `.npmrc`, credentials, proxy configuration, source code, project
name or full dependency tree is sent. Redirects are refused and there is no
Quick Audit fallback. The protocol is documented by [npm](https://docs.npmjs.com/cli/v11/commands/npm-audit/).

The [registry API response](https://api-docs.npmjs.com/#tag/Audit) groups advisory
arrays under the public package name and may omit the redundant inner `name`.
The checker derives identity from that already-validated outer key. An explicit
inner name must match; absent identity never permits an unrequested package.
This also matches the [npm CLI's advisory processing](https://github.com/npm/cli/blob/latest/workspaces/arborist/lib/audit-report.js).

HTTP/protocol errors, unexpected package names, unknown severities, malformed
advisories and oversized or incomplete responses cannot produce a pass.
Moderate maps to Medium; Medium, High and Critical findings block this check.
Low findings are counted but excluded from actionable findings. Returned
advisory text is untrusted data, never a command or automatic fix.

On November 5, fifteen offline controls passed. The first corrected platform
scan reported eight Medium/High advisory entries across five packages. Updated
Fastify static, Zod and their affected transitive dependencies resolved those
findings. The final platform query covered 279 reviewed public package names,
returned no Medium-or-higher advisories and counted one Low advisory. A separate
fresh DMS query returned no advisories for its 85 public packages. This establishes only that
advisory result at retrieval time. It does not certify package provenance beyond
the reviewed URL/integrity bindings, private code, source vulnerabilities,
container/OS packages, feed completeness or release eligibility. Runtime image
scans and the remaining release gates are still mandatory.

The earlier ordinary `npm audit` attempt remains recorded as rejected before
execution because it could disclose private workspace metadata. This checker
is a separate implementation with an explicit public-only payload. It does not
authorize that original command or grant private-metadata egress.
