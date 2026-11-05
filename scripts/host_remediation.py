#!/usr/bin/env python3
"""Internal, read-only host remediation planning from bounded evidence.

This module never starts a process, accesses a host file, downloads a package,
or authorizes a transaction. RepositoryAuthentication is evidence supplied by
a TRUSTED verifier adapter, not a JSON 'signed' flag. No such live adapter is
implemented here. Its future implementation must authenticate the original
vendor metadata and the exact normalized candidate projection together.

APT's documented simulation operations and DNF's stored resolved transaction
are parsed strictly. Native manager/version/configuration qualification and
signature verification remain separate acceptance work; injected tests do not
qualify them. A simulation is not a transaction test or a checkpoint.

Primary contracts:
https://manpages.debian.org/trixie/apt/apt-get.8.en.html
https://manpages.debian.org/trixie/apt/apt-secure.8.en.html
https://dnf.readthedocs.io/en/stable/transaction_json.html
https://dnf.readthedocs.io/en/latest/api_transaction.html
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Literal

MAX_PACKAGES = 10000
MAX_FINDINGS = 10000
MAX_OPERATIONS = 2048
MAX_SIMULATION_BYTES = 2 * 1024**2
HEX = re.compile(r"[a-f0-9]{64}")
FINGERPRINT = re.compile(r"[A-F0-9]{40}|[A-F0-9]{64}")
NAME = re.compile(r"[a-z0-9][a-z0-9+_.-]{0,159}")
VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~_-]{0,199}")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}")
ADVISORY = re.compile(r"[A-Z0-9][A-Z0-9:._-]{0,99}")
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class PlanningUnavailable(ValueError):
    """Only fixed internal reason codes are permitted in public results."""


def require(value, reason):
    if not value:
        raise PlanningUnavailable(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, keys, reason):
    require(type(value) is dict and set(value) == set(keys), reason)


def text(value, pattern, reason):
    require(type(value) is str and pattern.fullmatch(value) is not None, reason)
    return value


def timestamp(value):
    require(type(value) is str and len(value) <= 40, "invalid-evidence-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise PlanningUnavailable("invalid-evidence-time") from None
    require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0), "invalid-evidence-time")
    return parsed


def fresh(value, now, maximum):
    parsed = timestamp(value)
    require(timedelta(0) <= now - parsed <= maximum, "stale-or-future-evidence")
    return parsed


def document(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, "evidence-size-limit")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-evidence-field")
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(PlanningUnavailable("invalid-evidence-json")))
    except PlanningUnavailable:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise PlanningUnavailable("invalid-evidence-json") from None
    pending, count = [(result, 0)], 0
    while pending:
        value, depth = pending.pop(); count += 1
        require(depth <= 16 and count <= 250000, "evidence-structure-limit")
        if type(value) is dict:
            pending.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in value)
    return result


@dataclass(frozen=True)
class Distribution:
    family: Literal["debian", "rocky"]
    version: str


def distribution(value):
    exact(value, {"family", "version"}, "invalid-distribution")
    family, version = value["family"], value["version"]
    require(type(family) is str and type(version) is str and
            (family == "debian" and version in {"12", "13"} or
             family == "rocky" and re.fullmatch(r"(?:9|10)(?:\.[0-9]{1,2})?", version)), "unsupported-distribution")
    return Distribution(family, version)


@dataclass(frozen=True, order=True)
class Package:
    name: str
    version: str
    arch: str
    source: str
    source_version: str
    essential: bool

    @property
    def identity(self):
        return sha(canonical(asdict(self)))


def kernel_package(value):
    return (value.source == "kernel" and value.name.startswith("kernel-") or
            value.source in {"linux", "linux-signed-amd64"} and
            re.fullmatch(r"linux-image-[0-9][A-Za-z0-9.+_~-]*-(?:cloud-|rt-)?amd64(?:-unsigned)?", value.name) is not None)


def kernel_flavor(value):
    if value.source == "kernel":return "rocky"
    name = value.name.removesuffix("-unsigned")
    return "cloud" if name.endswith("-cloud-amd64") else "rt" if name.endswith("-rt-amd64") else "normal"


def package(value, distro):
    exact(value, {"name", "version", "arch", "source", "source_version", "essential"}, "invalid-package")
    text(value["name"], NAME, "invalid-package"); text(value["source"], NAME, "invalid-package")
    text(value["version"], VERSION, "invalid-package"); text(value["source_version"], VERSION, "invalid-package")
    require(type(value["arch"]) is str and value["arch"] in
            ({"amd64", "all"} if distro.family == "debian" else {"x86_64", "noarch"})
            and type(value["essential"]) is bool, "invalid-package")
    return Package(**value)


def package_set(values, distro):
    require(type(values) is list and 0 < len(values) <= MAX_PACKAGES, "incomplete-package-inventory")
    result = tuple(sorted(package(item, distro) for item in values))
    require(len({p.identity for p in result}) == len(result) and
            len({(p.name, p.version, p.arch) for p in result}) == len(result), "ambiguous-package-inventory")
    return result


@dataclass(frozen=True)
class InstalledInventory:
    distribution: Distribution
    packages: tuple[Package, ...]
    metadata_sha256: str
    captured_at: datetime
    identity: str


def parse_inventory(raw, now):
    value = document(raw, 4 * 1024**2)
    exact(value, {"schemaVersion", "distribution", "packages", "metadataSha256", "capturedAt"}, "invalid-installed-inventory")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "invalid-installed-inventory")
    distro = distribution(value["distribution"]); packages = package_set(value["packages"], distro)
    pin = text(value["metadataSha256"], HEX, "invalid-installed-inventory")
    captured = fresh(value["capturedAt"], now, timedelta(minutes=30))
    identity = sha(canonical({"distribution": asdict(distro), "metadataSha256": pin,
                              "packages": [asdict(p) for p in packages]}))
    return InstalledInventory(distro, packages, pin, captured, identity)


@dataclass(frozen=True)
class ScanContext:
    inventory_sha256: str
    feed_sha256: str
    feed_updated_at: str
    checked_at: str
    # These are the existing host coverage names/statuses, not a clean-host flag.
    coverage: tuple[tuple[str, str], ...]
    # From the separately verified running-source query, not FixedVersion.
    # Package identities refer back to this exact installed inventory.
    kernel_findings: tuple[Finding, ...] = ()


@dataclass(frozen=True, order=True)
class Finding:
    id: str
    severity: str
    package_identity: str


def formatted_version(value, prefix=""):
    version = text(value.get(prefix + "Version"), VERSION, "invalid-scanned-package")
    epoch, release = value.get(prefix + "Epoch", 0), value.get(prefix + "Release", "")
    require(type(epoch) is int and 0 <= epoch < 10**8 and type(release) is str, "invalid-scanned-package")
    if release: text(release, VERSION, "invalid-scanned-package")
    return (str(epoch) + ":" if epoch else "") + version + ("-" + release if release else "")


def parse_scan(raw, context, inventory, now):
    require(type(context) is ScanContext and context.inventory_sha256 == inventory.identity,
            "scan-inventory-mismatch")
    text(context.feed_sha256, HEX, "invalid-scan-context")
    fresh(context.feed_updated_at, now, timedelta(hours=24))
    fresh(context.checked_at, now, timedelta(minutes=30))
    require(type(context.coverage) is tuple and len(context.coverage) == 2 and
            {name for name, _ in context.coverage} == {"host-os-packages", "host-running-kernel-vendor-advisories"}
            and all(status in {"passed", "failed"} for _, status in context.coverage), "incomplete-host-coverage")
    value = document(raw, 16 * 1024**2)
    require(type(value) is dict and type(value.get("Metadata")) is dict, "invalid-scan-report")
    os = value["Metadata"].get("OS")
    require(type(os) is dict and os.get("Family") == inventory.distribution.family and
            os.get("Name") == inventory.distribution.version and os.get("EOSL") is False, "scan-distribution-mismatch")
    results = value.get("Results")
    require(type(results) is list and 0 < len(results) <= 100 and all(type(row) is dict for row in results), "invalid-scan-report")
    os_results = [row for row in results if row.get("Class") == "os-pkgs"]
    require(len(os_results) == 1 and os_results[0].get("Type") == inventory.distribution.family, "incomplete-host-coverage")
    result = os_results[0]; rows = result.get("Packages")
    require(type(rows) is list and 0 < len(rows) <= MAX_PACKAGES, "incomplete-package-inventory")
    installed = {(p.name, p.version, p.arch): p for p in inventory.packages}
    scanned, identities = {}, set()
    for row in rows:
        require(type(row) is dict and type(row.get("ID")) is str and 0 < len(row["ID"]) <= 500
                and row["ID"] not in scanned, "ambiguous-scanned-package")
        key = (row.get("Name"), formatted_version(row), row.get("Arch"))
        require(key in installed, "scan-inventory-mismatch")
        target = installed[key]
        require(row.get("SrcName") == target.source and formatted_version(row, "Src") == target.source_version
                and type(row.get("Repository")) is dict and row["Repository"].get("Class") == "official", "non-vendor-scanned-package")
        require(target.identity not in identities, "ambiguous-scanned-package")
        identities.add(target.identity); scanned[row["ID"]] = target
    require(identities == {p.identity for p in inventory.packages}, "scan-inventory-mismatch")
    vulns = result.get("Vulnerabilities", [])
    require(type(vulns) is list and len(vulns) <= MAX_FINDINGS, "invalid-scan-findings")
    findings, seen = [], set()
    for row in vulns:
        require(type(row) is dict and row.get("Severity") in SEVERITIES, "unclassified-advisory")
        require(type(row.get("DataSource")) is dict and row["DataSource"].get("ID") == inventory.distribution.family,
                "non-vendor-advisory")
        identity = row.get("PkgID")
        require(type(identity) is str and identity in scanned and row.get("PkgName") == scanned[identity].name
                and row.get("InstalledVersion") == scanned[identity].version, "finding-inventory-mismatch")
        identifier = text(row.get("VulnerabilityID"), ADVISORY, "invalid-advisory")
        key = (identifier, scanned[identity].identity)
        require(key not in seen, "duplicate-advisory"); seen.add(key)
        if row["Severity"] != "LOW":findings.append(Finding(identifier, row["Severity"], scanned[identity].identity))
    status = dict(context.coverage)
    require((status["host-os-packages"] == "failed") == bool(findings), "scan-coverage-finding-mismatch")
    require(type(context.kernel_findings) is tuple and len(context.kernel_findings) <= MAX_FINDINGS,
            "incomplete-running-kernel-advisories")
    packages_by_id = {p.identity: p for p in inventory.packages}
    combined = {(row.id, row.package_identity): row for row in findings}
    for row in context.kernel_findings:
        require(type(row) is Finding and row.severity in SEVERITIES - {"LOW"}
                and type(row.package_identity) is str and row.package_identity in packages_by_id
                and kernel_package(packages_by_id[row.package_identity]), "incomplete-running-kernel-advisories")
        text(row.id, ADVISORY, "invalid-advisory")
        key = (row.id, row.package_identity)
        require(key not in combined or combined[key] == row, "conflicting-running-kernel-advisory")
        combined[key] = row
    kernel_findings = [row for row in combined.values() if kernel_package(packages_by_id[row.package_identity])]
    require((status["host-running-kernel-vendor-advisories"] == "failed") == bool(kernel_findings),
            "incomplete-running-kernel-advisories")
    return tuple(sorted(combined.values()))


@dataclass(frozen=True)
class RepositoryAuthentication:
    """Trusted adapter output; never deserialize this proof from user JSON.

    payload_sha256 binds the normalized candidates; signed_metadata_sha256
    binds original vendor metadata whose authenticated projection it represents.
    Native adapter/keyring/package-archive acceptance remains unimplemented.
    """
    payload_sha256: str
    signed_metadata_sha256: str
    method: Literal["debian-release-chain", "rocky-repomd-signature"]
    signer_fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class Candidate:
    package: Package
    repository: str
    archive_sha256: str
    fixes: tuple[tuple[str, str], ...]  # exact advisory and installed identity


def parse_repository(raw, authentication, trusted_fingerprints, inventory, now):
    require(type(authentication) is RepositoryAuthentication, "repository-authentication-unavailable")
    expected_method = "debian-release-chain" if inventory.distribution.family == "debian" else "rocky-repomd-signature"
    require(authentication.method == expected_method and authentication.payload_sha256 == sha(raw), "repository-authentication-mismatch")
    text(authentication.signed_metadata_sha256, HEX, "repository-authentication-unavailable")
    require(type(trusted_fingerprints) is tuple and 0 < len(trusted_fingerprints) <= 16
            and len(set(trusted_fingerprints)) == len(trusted_fingerprints), "repository-trust-unavailable")
    for key in trusted_fingerprints:text(key, FINGERPRINT, "repository-trust-unavailable")
    keys = authentication.signer_fingerprints
    require(type(keys) is tuple and 0 < len(keys) <= 4 and len(set(keys)) == len(keys)
            and all(type(key) is str and key in trusted_fingerprints for key in keys), "repository-trust-unavailable")
    value = document(raw, 8 * 1024**2)
    exact(value, {"schemaVersion", "distribution", "generatedAt", "validUntil", "repositories", "candidates"}, "invalid-repository-metadata")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and distribution(value["distribution"]) == inventory.distribution,
            "repository-distribution-mismatch")
    generated = fresh(value["generatedAt"], now, timedelta(hours=24)); expires = timestamp(value["validUntil"])
    require(generated < expires and now < expires, "stale-or-future-evidence")
    repos = value["repositories"]
    require(type(repos) is list and 0 < len(repos) <= 16, "invalid-repository-metadata")
    for repo in repos:text(repo, REPO, "invalid-repository-metadata")
    require(len(set(repos)) == len(repos), "invalid-repository-metadata")
    rows = value["candidates"]
    require(type(rows) is list and len(rows) <= MAX_PACKAGES, "invalid-repository-metadata")
    result, seen = {}, set()
    installed_by_id = {p.identity: p for p in inventory.packages}
    for row in rows:
        exact(row, {"package", "repository", "archiveSha256", "fixes"}, "invalid-repository-candidate")
        target = package(row["package"], inventory.distribution)
        require(type(row["repository"]) is str and row["repository"] in repos and target.identity not in result,
                "ambiguous-repository-candidate")
        pin = text(row["archiveSha256"], HEX, "invalid-repository-candidate")
        fixes = row["fixes"]; require(type(fixes) is list and len(fixes) <= MAX_FINDINGS, "invalid-vendor-fix-binding")
        bound = set()
        for fix in fixes:
            exact(fix, {"id", "installedIdentity"}, "invalid-vendor-fix-binding")
            identifier = text(fix["id"], ADVISORY, "invalid-vendor-fix-binding")
            installed_id = text(fix["installedIdentity"], HEX, "invalid-vendor-fix-binding")
            require(installed_id in installed_by_id, "invalid-vendor-fix-binding")
            old = installed_by_id[installed_id]
            matching_name = old.name == target.name or kernel_package(old) and kernel_package(target) and kernel_flavor(old) == kernel_flavor(target)
            require(matching_name and old.arch == target.arch and old.source == target.source
                    and old.version != target.version, "invalid-vendor-fix-binding")
            require((identifier, installed_id) not in bound, "invalid-vendor-fix-binding")
            bound.add((identifier, installed_id))
        # Same NEVRA with conflicting source/essential flags cannot hide as two candidates.
        key = (target.name, target.version, target.arch)
        require(key not in seen, "ambiguous-repository-candidate"); seen.add(key)
        result[target.identity] = Candidate(target, row["repository"], pin, tuple(sorted(bound)))
    return result


@dataclass(frozen=True)
class SimulationContext:
    manager: Literal["apt-get", "dnf"]
    manager_version: str
    inventory_before_sha256: str
    inventory_after_sha256: str
    repository_sha256: str
    stdout_sha256: str
    requested_candidates: tuple[str, ...]
    checked_at: str
    duration_millis: int
    return_code: int


@dataclass(frozen=True)
class Change:
    action: Literal["add", "change", "remove"]
    before: Package | None
    after: Package | None
    repository: str | None
    archive_sha256: str | None


def _candidate(name, version, arch, repo, candidates):
    found = [row for row in candidates.values() if (row.package.name, row.package.version, row.package.arch, row.repository) == (name, version, arch, repo)]
    require(len(found) == 1, "simulation-candidate-not-authenticated")
    return found[0]


def parse_apt_simulation(raw, inventory, candidates):
    """Strict documented Inst/Conf/Remv subset with a reconciled totals footer.

    Wrapped/localized/broken-package/multi-origin/unsupported output fails closed.
    A future actual apt adapter must qualify exact options/version and pin origin
    labels to authenticated repository IDs. No apt command is executed here.
    """
    try:lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError:raise PlanningUnavailable("invalid-simulation-output") from None
    old = {(p.name, p.arch): p for p in inventory.packages}
    require(len(old) == len(inventory.packages), "apt-multiversion-inventory-unavailable")
    operations, configured, summary = [], set(), None
    header = {"Reading package lists... Done", "Building dependency tree... Done", "Reading state information... Done", "Calculating upgrade... Done"}
    for line in lines:
        if not line or line in header:continue
        match = re.fullmatch(r"([0-9]+) upgraded, ([0-9]+) newly installed, ([0-9]+) to remove and ([0-9]+) not upgraded\.", line)
        if match:
            require(summary is None and all(len(item) <= 5 for item in match.groups()), "invalid-simulation-summary")
            summary = tuple(int(item) for item in match.groups());continue
        match = re.fullmatch(r"Inst ([a-z0-9][a-z0-9+_.-]{0,159})(?::(amd64|all))?(?: \[([^\[\] ]+)\])? \(([^ ()]+) ([A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}) \[(amd64|all)\]\)", line)
        if match:
            name, explicit_arch, before_version, version, repo, arch = match.groups()
            require(explicit_arch is None or explicit_arch == arch, "invalid-simulation-operation")
            candidate = _candidate(name, version, arch, repo, candidates); prior = old.get((name, arch))
            require((prior is None and before_version is None) or prior is not None and prior.version == before_version,
                    "simulation-inventory-mismatch")
            operations.append(Change("change" if prior else "add", prior, candidate.package, repo, candidate.archive_sha256));continue
        match = re.fullmatch(r"Conf ([a-z0-9][a-z0-9+_.-]{0,159})(?::(amd64|all))? \(([^ ()]+) ([A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}) \[(amd64|all)\]\)", line)
        if match:
            name, explicit_arch, version, repo, arch = match.groups(); candidate = _candidate(name, version, arch, repo, candidates)
            require((explicit_arch is None or explicit_arch == arch) and candidate.package.identity not in configured, "invalid-simulation-operation")
            configured.add(candidate.package.identity);continue
        match = re.fullmatch(r"Remv ([a-z0-9][a-z0-9+_.-]{0,159})(?::(amd64|all))? \[([^\[\] ]+)\]", line)
        if match:
            name, arch, version = match.groups(); found = [p for p in inventory.packages if p.name == name and p.version == version and (arch is None or p.arch == arch)]
            require(len(found) == 1, "simulation-inventory-mismatch");operations.append(Change("remove", found[0], None, None, None));continue
        raise PlanningUnavailable("unsupported-apt-simulation-output")
    require(summary is not None and tuple(sum(row.action == action for row in operations) for action in ("change", "add", "remove")) == summary[:3]
            and configured == {row.after.identity for row in operations if row.after is not None}, "incomplete-simulation")
    return tuple(operations)


def parse_dnf_transaction(raw, inventory, candidates):
    """DNF stored resolved transaction 1.0; unsupported actions are unavailable.

    DNF documents this format as unstable. Live adapter/version acceptance and
    complete resolve capture are still required; this is never replayed.
    """
    value = document(raw, MAX_SIMULATION_BYTES)
    exact(value, {"version", "rpms", "groups", "environments"}, "invalid-dnf-transaction")
    require(value["version"] == "1.0" and value["groups"] == [] and value["environments"] == []
            and type(value["rpms"]) is list and len(value["rpms"]) <= MAX_OPERATIONS * 2, "unsupported-dnf-transaction")
    old = {f"{p.name}-{p.version if ':' in p.version else '0:' + p.version}.{p.arch}": p for p in inventory.packages}
    require(len(old) == len(inventory.packages), "ambiguous-package-inventory")
    available = {f"{p.package.name}-{p.package.version if ':' in p.package.version else '0:' + p.package.version}.{p.package.arch}": p for p in candidates.values()}
    added, retired, upgrades, seen = [], [], [], set()
    for row in value["rpms"]:
        exact(row, {"action", "nevra", "reason", "repo_id"}, "invalid-dnf-transaction")
        require(type(row["nevra"]) is str and row["nevra"] not in seen and row["reason"] in
                {"dependency", "clean", "group", "user", "weak-dependency"}, "invalid-dnf-transaction")
        seen.add(row["nevra"])
        if row["action"] in {"Upgrade", "Install"}:
            require(row["nevra"] in available and row["repo_id"] == available[row["nevra"]].repository, "simulation-candidate-not-authenticated")
            target = available[row["nevra"]]
            (upgrades if row["action"] == "Upgrade" else added).append(target)
        elif row["action"] in {"Upgraded", "Removed"}:
            require(row["nevra"] in old and row["repo_id"] == "@System", "simulation-inventory-mismatch")
            retired.append((row["action"], old[row["nevra"]]))
        else:raise PlanningUnavailable("unsupported-dnf-transaction")
    operations = [Change("add", None, row.package, row.repository, row.archive_sha256) for row in added]
    used = set()
    for target in upgrades:
        found = [p for action, p in retired if action == "Upgraded" and (p.name, p.arch) == (target.package.name, target.package.arch)]
        require(len(found) == 1 and found[0].identity not in used, "incomplete-simulation")
        used.add(found[0].identity);operations.append(Change("change", found[0], target.package, target.repository, target.archive_sha256))
    require(used == {p.identity for action, p in retired if action == "Upgraded"}, "incomplete-simulation")
    operations.extend(Change("remove", p, None, None, None) for action, p in retired if action == "Removed")
    return tuple(operations)


def parse_simulation(raw, context, inventory, repository_raw, candidates, now):
    require(type(raw) is bytes and len(raw) <= MAX_SIMULATION_BYTES and type(context) is SimulationContext, "invalid-simulation-context")
    manager = "apt-get" if inventory.distribution.family == "debian" else "dnf"
    require(context.manager == manager and context.inventory_before_sha256 == context.inventory_after_sha256 == inventory.identity
            and context.repository_sha256 == sha(repository_raw) and context.stdout_sha256 == sha(raw), "simulation-binding-mismatch")
    text(context.manager_version, VERSION, "invalid-simulation-context")
    require(type(context.duration_millis) is int and 0 <= context.duration_millis <= 30000
            and type(context.return_code) is int and context.return_code == 0, "simulation-query-unavailable")
    fresh(context.checked_at, now, timedelta(minutes=30))
    requested = context.requested_candidates
    require(type(requested) is tuple and len(requested) <= MAX_OPERATIONS and len(set(requested)) == len(requested)
            and all(type(pin) is str and pin in candidates for pin in requested), "invalid-simulation-request")
    operations = parse_apt_simulation(raw, inventory, candidates) if manager == "apt-get" else parse_dnf_transaction(raw, inventory, candidates)
    require(len(operations) <= MAX_OPERATIONS, "simulation-operation-limit")
    before, after = set(), set()
    installed = {p.identity: p for p in inventory.packages}
    for operation in operations:
        if operation.before:
            require(operation.before.identity in installed and operation.before.identity not in before, "duplicate-simulation-operation")
            before.add(operation.before.identity)
        if operation.after:
            require(operation.after.identity not in installed and operation.after.identity not in after, "duplicate-simulation-operation")
            after.add(operation.after.identity)
    require(set(requested) <= after, "incomplete-simulation")
    result = {**{pin: p for pin, p in installed.items() if pin not in before},
              **{operation.after.identity: operation.after for operation in operations if operation.after}}
    require(0 < len(result) <= MAX_PACKAGES and len({(p.name, p.version, p.arch) for p in result.values()}) == len(result), "incomplete-simulation")
    return tuple(sorted(operations, key=lambda row: (row.after or row.before).identity)), tuple(sorted(result.values()))


@dataclass(frozen=True)
class RunningKernel:
    installed_package_identity: str
    release: str
    runtime_source_version: str
    reboot_already_needed: bool
    # Exact Built-Using linux (= version) already checked by HostProbe for a
    # signing wrapper. Its source package version is NOT the running linux build.
    debian_linux_version: str | None = None


@dataclass(frozen=True)
class RemediationPlan:
    status: Literal["proposed_untested", "blocked_unresolved", "no_medium_plus_actions", "unavailable"]
    reason: str
    changes: tuple[Change, ...] = ()
    findings: tuple[Finding, ...] = ()
    unresolved: tuple[Finding, ...] = ()
    resulting_inventory_sha256: str | None = None
    kernel_reboot_required: bool | None = None
    input_evidence_sha256: tuple[tuple[str, str], ...] = ()
    tested: bool = False
    checkpoint_required: bool = True
    approved_maintenance_window_required: bool = True
    apply_authorized: bool = False
    live_query_adapters_available: bool = False
    limitations: tuple[str, ...] = (
        "Injected verifier and package-manager evidence require native adapter qualification.",
        "Package availability and candidate fix bindings do not establish tested remediation.",
        "Service restarts, configuration/scriptlet effects and post-reboot health require rehearsal.",
        "Third-party advisories, loaded kernel bytes, live patches, firmware and hardening are outside this scope.",
    )

    def as_dict(self):
        return asdict(self)


def plan_host_remediation(*, inventory_before: bytes, inventory_after: bytes,
                          scan_report: bytes, scan_context: ScanContext,
                          repository_metadata: bytes, repository_authentication: RepositoryAuthentication | None,
                          trusted_fingerprints: tuple[str, ...], simulation_output: bytes,
                          simulation_context: SimulationContext, running_kernel: RunningKernel,
                          now: datetime | None = None) -> RemediationPlan:
    """Plan exact vendor package changes; never infer a fix from FixedVersion.

    Inputs are retained read-only snapshots/outputs from trusted caller adapters.
    No query is run here. Missing live adapters keep execution/integration disabled.
    The before/after inventories must span the simulation and agree in full.
    """
    try:
        now = now or datetime.now(timezone.utc)
        require(type(now) is datetime and now.tzinfo is not None and now.utcoffset() == timedelta(0), "invalid-evidence-time")
        before, after = parse_inventory(inventory_before, now), parse_inventory(inventory_after, now)
        require(before.identity == after.identity and before.captured_at <= after.captured_at, "installed-inventory-changed")
        findings = parse_scan(scan_report, scan_context, before, now)
        candidates = parse_repository(repository_metadata, repository_authentication, trusted_fingerprints, before, now)
        operations, final_packages = parse_simulation(simulation_output, simulation_context, before, repository_metadata, candidates, now)
        simulated_at = timestamp(simulation_context.checked_at)
        require(before.captured_at <= simulated_at <= after.captured_at, "simulation-not-bracketed-by-inventory")
        require(type(running_kernel) is RunningKernel and type(running_kernel.reboot_already_needed) is bool,
                "running-kernel-evidence-unavailable")
        active = [p for p in before.packages if p.identity == running_kernel.installed_package_identity]
        require(len(active) == 1 and kernel_package(active[0])
                and type(running_kernel.release) is str and re.fullmatch(r"[0-9][A-Za-z0-9.+_~-]{0,180}", running_kernel.release),
                "running-kernel-evidence-unavailable")
        underlying = active[0].source_version
        if active[0].source == "linux-signed-amd64":
            underlying = text(running_kernel.debian_linux_version, VERSION, "running-kernel-evidence-unavailable")
            require(underlying == active[0].version, "running-kernel-evidence-unavailable")
        else:require(running_kernel.debian_linux_version is None, "running-kernel-evidence-unavailable")
        require(underlying == running_kernel.runtime_source_version, "running-kernel-evidence-unavailable")
        removed = {row.before.identity for row in operations if row.before}
        fixes = {fix for row in operations if row.after for fix in candidates[row.after.identity].fixes}
        unresolved = tuple(finding for finding in findings if (finding.id, finding.package_identity) not in fixes
                           or finding.package_identity not in removed and not any(row.after and kernel_package(row.after)
                               and row.after.source == active[0].source and kernel_flavor(row.after) == kernel_flavor(active[0])
                               and finding.package_identity == active[0].identity for row in operations))
        # RPM install-only kernel additions retain the currently running package;
        # they are proposed reboot targets, never a claim the fix is running now.
        kernel_changed = any((row.before and kernel_package(row.before)) or
                             (row.after and kernel_package(row.after)) for row in operations)
        unsafe_remove = any(row.action == "remove" and (row.before.essential or row.before.identity == active[0].identity) for row in operations)
        require(not unsafe_remove, "protected-package-removal")
        requested = set(simulation_context.requested_candidates)
        known_findings = {(finding.id, finding.package_identity) for finding in findings}
        require(all(set(candidates[pin].fixes) & known_findings for pin in requested), "request-without-vendor-fix-binding")
        require(not operations or requested, "unrequested-maintenance-changes")
        status = "blocked_unresolved" if unresolved else "proposed_untested" if findings else "no_medium_plus_actions"
        # A scan without Medium+ findings cannot smuggle unrelated maintenance.
        require(findings or not operations, "unrequested-maintenance-changes")
        evidence = tuple(sorted((name, sha(raw)) for name, raw in (
            ("inventory_before", inventory_before), ("inventory_after", inventory_after),
            ("scan_report", scan_report), ("repository_metadata", repository_metadata), ("simulation_output", simulation_output))))
        return RemediationPlan(status, "vendor-plan-needs-testing" if status == "proposed_untested" else
                               "vendor-fixes-incomplete" if unresolved else "no-medium-plus-vendor-findings",
                               operations, findings, unresolved, sha(canonical([asdict(p) for p in final_packages])),
                               kernel_changed or running_kernel.reboot_already_needed, evidence)
    except PlanningUnavailable as error:
        return RemediationPlan("unavailable", error.args[0])
    except Exception:
        return RemediationPlan("unavailable", "invalid-or-incomplete-planning-evidence")
