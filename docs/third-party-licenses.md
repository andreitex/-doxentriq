# Project and third-party licensing

AutoSoft source is licensed under [Apache-2.0](../LICENSE), selected by the
project owner. The license file preserves the existing repository copy of the
standard license text from its original Git blob, verified against the
[Apache Software Foundation text](https://www.apache.org/licenses/LICENSE-2.0.txt)
with only the leading blank line omitted.
The repository destination is
[andreitex/-doxentriq](https://github.com/andreitex/-doxentriq).

Dependencies keep their own licenses. Apache-2.0 in the root package metadata
does not replace a dependency's terms or notices. The source export excludes
installed npm packages, Go's module cache, compiled browser assets and container
layers. Customer data and private generated applications are also excluded.

## Source dependency inventory

The [locked dependency inventory](dependency-license-inventory.json) records
package/version/license metadata and exact lock hashes reviewed on November 5,
2026. Counts include optional platform packages and multiple installed versions;
they are not counts of unique package names.

| Declared npm license | Platform lock instances | DMS lock instances |
|---|---:|---:|
| MIT | 223 | 68 |
| Apache-2.0 | 27 | 2 |
| ISC | 9 | 2 |
| BSD-3-Clause | 5 | 1 |
| BSD-2-Clause | 1 | 0 |
| BlueOak-1.0.0 | 6 | 0 |
| MPL-2.0 | 12 | 12 |
| **Total** | **283** | **85** |

Every npm instance in these two locks has a declared license. This metadata
review does not independently prove upstream ownership or the completeness of
every package's notices. The MPL entries are Lightning CSS and its optional
native platform packages. Preserve their own license/source information when
shipping those tools in a distribution.

The Go manifest declares twelve module versions. The inventory records license
and notice file hashes for the eleven cached modules and the official exact-tag
license source for `gotest.tools/v3`. The MySQL driver uses MPL-2.0; the other
reviewed module texts include Apache-2.0, MIT and BSD-style licenses. Docker CLI
also supplies a `NOTICE` file. Keep those files with any redistribution that
requires them; do not replace them with this summary.

## Before distributing built releases

For each exact binary, browser bundle or image release:

1. Produce an SBOM from what is actually included, including base images and OS
   packages, rather than relying only on development dependency manifests.
2. Collect the applicable license, copyright, attribution and NOTICE texts from
   those exact versions. Preserve upstream notices and identify modifications.
3. Review source-availability and other distribution requirements for components
   with their own terms, including database and observability images. Container
   references in this repository are not a license review of their full contents.
4. Include the corresponding notices and any required source material or source
   offer in the release artifact before distributing it.

This inventory qualifies source-release preparation only. Binary/image notice
bundles and their distribution review remain release work, alongside the
[installation acceptance requirements](installation-readiness.md).
