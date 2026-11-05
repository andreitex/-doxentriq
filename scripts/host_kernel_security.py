#!/usr/bin/env python3
"""Read-only distribution advisory coverage for the kernel actually running.

The caller supplies the company-controlled, fresh Trivy OS report and scanner.
Debian signed kernels are explicitly queried against their exact Built-Using
linux source, rather than the signing wrapper's source. No upstream version
heuristic, package install, live patch discount, or automatic reboot is used.

Primary contracts:
https://kernel-team.pages.debian.net/kernel-handbook/ch-versions.html
https://www.debian.org/doc/debian-policy/ch-relationships.html#s-built-using
https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html
https://docs.rockylinux.org/teams/rel_eng/errata/
https://rpm.org/docs/4.20.x/manual/lua
https://trivy.dev/docs/latest/guide/coverage/os/debian/
https://trivy.dev/docs/latest/guide/coverage/os/rocky/
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time

MAX_QUERY_BYTES = 128 * 1024
MAX_KERNELS = 64
DEBIAN_MAINTAINER = "Debian Kernel Team <debian-kernel@lists.debian.org>"
ROCKY_VENDOR = "Rocky Enterprise Software Foundation"
RELEASE = re.compile(r"[0-9][A-Za-z0-9.+_~-]{0,180}")
VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~_-]{0,199}")
DEB_NAME = re.compile(r"linux-image-(?P<release>[0-9][A-Za-z0-9.+_~-]*-(?:cloud-|rt-)?amd64)(?:-unsigned)?")
DEB_FORMAT = "${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\t${source:Version}\t${Built-Using}\t${Maintainer}\\n"
RPM_FORMAT = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\\n"


class CoverageUnavailable(ValueError):
    """A fixed, credential-free coverage reason; command stderr is not exposed."""


def require(condition, reason):
    if not condition:
        raise CoverageUnavailable(reason)


def token(value, pattern=VERSION):
    require(isinstance(value, str) and pattern.fullmatch(value), "invalid-package-identity")
    return value


def _allowed_query(argv):
    require(isinstance(argv, list) and all(isinstance(arg, str) for arg in argv), "unsupported-query-command")
    if len(argv) == 2 and argv[0] == "/usr/bin/uname" and argv[1] in {"-r", "-v", "-m"}:
        return
    if argv == ["/usr/bin/dpkg-query", "-W", "-f=" + DEB_FORMAT, "linux-image-*"] or argv == ["/usr/bin/rpm", "-q", "kernel-core", "--qf", RPM_FORMAT]:
        return
    if len(argv) == 3 and argv[:2] == ["/usr/bin/dpkg-query", "-S"]:
        require(argv[2].startswith("/boot/vmlinuz-") and RELEASE.fullmatch(argv[2][len("/boot/vmlinuz-"):]), "unsupported-query-command")
        return
    if len(argv) == 5 and argv[:2] == ["/usr/bin/rpm", "-qf"] and argv[3:] == ["--qf", RPM_FORMAT]:
        require(argv[2].startswith("/boot/vmlinuz-") and RELEASE.fullmatch(argv[2][len("/boot/vmlinuz-"):]), "unsupported-query-command")
        return
    if len(argv) == 5 and argv[:2] == ["/usr/bin/dpkg", "--compare-versions"] and argv[3] == "gt":
        token(argv[2]); token(argv[4]); return
    if len(argv) == 3 and argv[:2] == ["/usr/bin/rpm", "--eval"]:
        match = re.fullmatch(r"%\{lua:print\(rpm\.vercmp\('([0-9][A-Za-z0-9.+:~_-]{0,199})','([0-9][A-Za-z0-9.+:~_-]{0,199})'\)\)\}", argv[2])
        require(match is not None, "unsupported-query-command")
        return
    raise CoverageUnavailable("unsupported-query-command")


def _bounded_query(argv, deadline):
    """Fixed read-only commands only; bounded output/time, no shell or network."""
    _allowed_query(argv)
    remaining = min(10.0, deadline - time.monotonic())
    require(remaining > 0, "package-query-timeout")
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, shell=False,
                               env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C", "HOME": "/nonexistent"})
    output = bytearray()
    end = time.monotonic() + remaining
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < end, "package-query-timeout")
                for key, _ in selector.select(min(.1, max(0, end - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        require(len(output) <= MAX_QUERY_BYTES, "package-query-output-limit")
        code = process.wait(timeout=max(.001, end - time.monotonic()))
        return code, output.decode("utf-8", errors="strict")
    except Exception:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        raise
    finally:
        process.stdout.close()


def _ordinary_file(path, maximum, *, content=False):
    """Never follow a supplied kernel path or writable/unowned package file."""
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), "invalid-evidence-path")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= maximum, "untrusted-evidence-file")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mode,
                                  value.st_uid, value.st_gid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(after) and len(raw) <= maximum, "evidence-file-changed")
    require(identity(path.lstat()) == identity(after), "evidence-path-changed")
    if content:
        return raw.decode("utf-8", errors="strict")
    return {"device": before.st_dev, "inode": before.st_ino, "size": before.st_size,
            "sha256": hashlib.sha256(raw).hexdigest()}


def parse_os_release(raw):
    require(isinstance(raw, str) and len(raw) <= 16384, "invalid-os-release")
    fields = {}
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        require("=" in line, "invalid-os-release")
        key, value = line.split("=", 1)
        require(re.fullmatch(r"[A-Z_]+", key) and key not in fields, "invalid-os-release")
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        require(not any(ord(c) < 32 for c in value), "invalid-os-release")
        fields[key] = value
    family, version = fields.get("ID"), fields.get("VERSION_ID", "")
    require((family == "debian" and version in {"12", "13"}) or
            (family == "rocky" and re.fullmatch(r"(?:9|10)(?:\.[0-9]{1,2})?", version)), "unsupported-host-distribution")
    return {"family": family, "version": version}


def parse_debian_packages(raw):
    rows = []
    require(isinstance(raw, str) and len(raw) <= MAX_QUERY_BYTES, "invalid-package-query")
    for line in raw.splitlines():
        fields = line.split("\t")
        require(len(fields) == 8, "invalid-debian-package-row")
        name, version, arch, status, source, source_version, built_using, maintainer = fields
        if status != "install ok installed":
            continue
        match = DEB_NAME.fullmatch(name)
        # Metapackages, debug symbols and another CPU architecture aren't boot images.
        if not match or arch != "amd64":
            continue
        token(version); token(source_version); token(match["release"], RELEASE)
        require(maintainer == DEBIAN_MAINTAINER and source in {"linux", "linux-signed-amd64"}, "non-vendor-kernel-package")
        if source == "linux":
            linux_version = source_version
        else:
            match_built = re.fullmatch(r"linux \(= ([0-9][A-Za-z0-9.+:~_-]{0,199})\)", built_using)
            require(match_built is not None, "missing-exact-linux-built-using")
            linux_version = match_built[1]
        require(linux_version == version, "kernel-binary-source-version-mismatch")
        rows.append(dict(name=name, version=version, arch=arch, source=source,
                         sourceVersion=source_version, linuxVersion=linux_version, release=match["release"]))
    require(0 < len(rows) <= MAX_KERNELS and len({row["name"] for row in rows}) == len(rows), "missing-or-ambiguous-kernel-packages")
    return rows


def parse_rocky_packages(raw):
    rows = []
    require(isinstance(raw, str) and len(raw) <= MAX_QUERY_BYTES, "invalid-package-query")
    for line in raw.splitlines():
        fields = line.split("\t")
        require(len(fields) == 7, "invalid-rocky-package-row")
        name, epoch, version, release, arch, source, vendor = fields
        require(name == "kernel-core" and arch == "x86_64" and vendor == ROCKY_VENDOR, "non-vendor-kernel-package")
        require(re.fullmatch(r"[0-9]{1,8}", epoch) is not None, "invalid-package-epoch")
        token(version); token(release)
        require(source == f"kernel-{version}-{release}.src.rpm", "kernel-source-rpm-mismatch")
        evr = (epoch + ":" if int(epoch) else "") + version + "-" + release
        rows.append(dict(name=name, version=evr, arch=arch, source="kernel", sourceVersion=evr,
                         linuxVersion=evr, release=version + "-" + release + "." + arch))
    require(0 < len(rows) <= MAX_KERNELS and len({row["version"] for row in rows}) == len(rows), "missing-or-ambiguous-kernel-packages")
    return rows


class HostProbe:
    """Bounded host-only metadata. Injectable I/O exists solely for unit tests."""
    def __init__(self, query=None, file_read=None):
        self.deadline = time.monotonic() + 30
        self.query = query or (lambda argv: _bounded_query(argv, self.deadline))
        self.file_read = file_read or _ordinary_file

    def checked(self, argv):
        code, raw = self.query(argv)
        require(type(code) is int and code == 0, "package-query-failed")
        require(isinstance(raw, str) and len(raw) <= MAX_QUERY_BYTES, "invalid-package-query")
        return raw

    def compare(self, family, a, b):
        token(a); token(b)
        if family == "debian":
            code, raw = self.query(["/usr/bin/dpkg", "--compare-versions", a, "gt", b])
            require(type(code) is int and code in {0, 1} and raw == "", "package-version-comparison-unavailable")
            return code == 0
        # Official RPM Lua vercmp implements full EVR on RPM >=4.16 (Rocky 9/10).
        # Restricted version tokens cannot inject Lua, a macro, or a shell command.
        raw = self.checked(["/usr/bin/rpm", "--eval", "%{lua:print(rpm.vercmp('" + a + "','" + b + "'))}"])
        require(raw in {"-1\n", "0\n", "1\n"}, "package-version-comparison-unavailable")
        return raw == "1\n"

    def collect(self):
        # The scanner runs between snapshots and has a separate lifecycle.
        # Each host snapshot gets a fresh aggregate query budget; a slow valid
        # scan must not consume the post-scan snapshot's entire allowance.
        self.deadline = time.monotonic() + 30
        os_path = Path("/etc/os-release")
        if os_path.is_symlink():
            require(os_path.resolve() == Path("/usr/lib/os-release"), "unexpected-os-release-link")
            os_path = Path("/usr/lib/os-release")
        distribution = parse_os_release(self.file_read(os_path, 16384, content=True))
        release = self.checked(["/usr/bin/uname", "-r"]).rstrip("\n")
        build = self.checked(["/usr/bin/uname", "-v"]).rstrip("\n")
        require(RELEASE.fullmatch(release) and 0 < len(build) <= 512 and not any(ord(c) < 32 for c in build), "invalid-running-kernel-identity")
        require(self.checked(["/usr/bin/uname", "-m"]) == "x86_64\n", "unsupported-kernel-architecture")
        image_path = "/boot/vmlinuz-" + release
        image = self.file_read(image_path, 256 * 1024**2)
        if distribution["family"] == "debian":
            rows = parse_debian_packages(self.checked(["/usr/bin/dpkg-query", "-W", "-f=" + DEB_FORMAT, "linux-image-*"]))
            owner_raw = self.checked(["/usr/bin/dpkg-query", "-S", image_path])
            owners = owner_raw.splitlines()
            require(len(owners) == 1 and owners[0].endswith(": " + image_path), "ambiguous-kernel-file-owner")
            owner = owners[0][:-len(": " + image_path)]
            require(DEB_NAME.fullmatch(owner) is not None, "unexpected-kernel-file-owner")
            active = [row for row in rows if row["name"] == owner and row["release"] == release]
            require(len(active) == 1, "running-kernel-package-missing")
            build_matches = re.findall(r"\bDebian ([0-9][A-Za-z0-9.+:~_-]{0,199})(?= |$)", build)
            require(len(build_matches) == 1, "unknown-debian-running-build")
            runtime_version = build_matches[0]
        else:
            rows = parse_rocky_packages(self.checked(["/usr/bin/rpm", "-q", "kernel-core", "--qf", RPM_FORMAT]))
            owner_rows = parse_rocky_packages(self.checked(["/usr/bin/rpm", "-qf", image_path, "--qf", RPM_FORMAT]))
            active = [row for row in rows if row["release"] == release]
            require(len(active) == 1 and owner_rows == active, "running-kernel-package-missing")
            runtime_version = active[0]["linuxVersion"]
        active = active[0]
        suffix = "-cloud-amd64" if release.endswith("-cloud-amd64") else "-rt-amd64" if release.endswith("-rt-amd64") else "-amd64"
        candidates = [row for row in rows if distribution["family"] == "rocky" or row["release"].endswith(suffix)
                      and (suffix != "-amd64" or not row["release"].endswith(("-cloud-amd64", "-rt-amd64")))]
        newest = active
        for row in candidates:
            if self.compare(distribution["family"], row["linuxVersion"], newest["linuxVersion"]):
                newest = row
        return dict(distribution=distribution, release=release, build=build, image=image, package=active,
                    runtimeVersion=runtime_version, installedKernels=rows, newestInstalled=newest,
                    rebootNeeded=runtime_version != active["linuxVersion"] or newest != active)


def debian_source_inventory(snapshot):
    """Explicit advisory query, not a claim that this synthetic status is installed."""
    distro, package = snapshot["distribution"], snapshot["package"]
    require(distro["family"] == "debian" and snapshot["runtimeVersion"] == package["linuxVersion"], "running-installed-build-mismatch")
    # Source linux comes only from the checked source/Built-Using relation.
    fields = {"Package": package["name"], "Status": "install ok installed", "Architecture": "amd64",
              "Version": package["version"], "Source": "linux (" + package["linuxVersion"] + ")",
              "Maintainer": DEBIAN_MAINTAINER}
    return {"etc/os-release": f'ID=debian\nVERSION_ID="{distro["version"]}"\n',
            "var/lib/dpkg/status": "".join(key + ": " + value + "\n" for key, value in fields.items()) + "\n"}


def _formatted_version(package, source=False):
    prefix = "Src" if source else ""
    version = token(package.get(prefix + "Version"))
    epoch = package.get(prefix + "Epoch", 0)
    release = package.get(prefix + "Release", "")
    require(type(epoch) is int and 0 <= epoch < 10**8 and isinstance(release, str), "invalid-scanned-package-version")
    if release:
        token(release)
    return (str(epoch) + ":" if epoch else "") + version + ("-" + release if release else "")


def kernel_advisories(report, snapshot):
    distro, active = snapshot["distribution"], snapshot["package"]
    require(isinstance(report, dict), "invalid-kernel-advisory-report")
    metadata = report.get("Metadata", {}).get("OS", {})
    require(metadata.get("Family") == distro["family"] and metadata.get("Name") == distro["version"]
            and (metadata.get("EOSL") is None or metadata.get("EOSL") is False), "kernel-advisory-os-mismatch")
    results = report.get("Results")
    require(isinstance(results, list) and 0 < len(results) <= 100, "missing-kernel-advisory-results")
    os_results = [result for result in results if isinstance(result, dict) and result.get("Class") == "os-pkgs"
                  and result.get("Type") == distro["family"]]
    require(len(os_results) == 1, "ambiguous-kernel-advisory-results")
    result = os_results[0]
    packages = result.get("Packages")
    require(isinstance(packages, list) and 0 < len(packages) <= 100000, "missing-scanned-kernel-packages")
    matched = []
    for package in packages:
        require(isinstance(package, dict), "invalid-scanned-package")
        if package.get("Name") != active["name"]:
            continue
        if _formatted_version(package) != active["version"]:
            continue
        source_name = "linux" if distro["family"] == "debian" else "kernel"
        require(package.get("Arch") == active["arch"] and package.get("SrcName") == source_name, "scanned-kernel-source-mismatch")
        require(_formatted_version(package, source=True) == active["linuxVersion"]
                and package.get("Repository", {}).get("Class") != "third-party", "scanned-kernel-source-mismatch")
        matched.append(package)
    require(len(matched) == 1, "exact-running-kernel-not-scanned")
    selected = matched[0]
    vulns = result.get("Vulnerabilities") or []
    require(isinstance(vulns, list) and len(vulns) <= 100000, "invalid-kernel-advisories")
    findings, incomplete = [], False
    seen = set()
    for finding in vulns:
        require(isinstance(finding, dict), "invalid-kernel-advisory")
        if finding.get("PkgName") != active["name"]:
            continue
        require(isinstance(finding.get("InstalledVersion"), str), "kernel-advisory-version-missing")
        if finding["InstalledVersion"] != active["version"]:
            continue
        require(not finding.get("PkgID") or finding["PkgID"] == selected.get("ID"), "kernel-advisory-package-mismatch")
        require(finding.get("DataSource", {}).get("ID") == distro["family"], "non-vendor-kernel-advisory")
        severity = finding.get("Severity")
        if severity in {None, "UNKNOWN"}:
            incomplete = True
            continue
        require(severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}, "invalid-kernel-advisory-severity")
        if severity == "LOW":
            continue
        identifier = finding.get("VulnerabilityID")
        require(isinstance(identifier, str) and re.fullmatch(r"[A-Z0-9:._-]{1,100}", identifier), "invalid-kernel-advisory-id")
        require(identifier not in seen, "duplicate-kernel-advisory")
        seen.add(identifier)
        findings.append(dict(id=identifier, severity=severity, package=active["name"],
                             installedVersion=active["version"], fixedVersion=str(finding.get("FixedVersion", ""))[:200],
                             source=str(finding.get("PrimaryURL") or finding.get("DataSource", {}).get("URL", ""))[:500],
                             description=str(finding.get("Title") or identifier)[:5000]))
    return findings, incomplete


def check_running_kernel(host_report, feed_updated_at, scan_debian_source=None, *, probe=None, now=None):
    """Return coverage/findings/actual-vs-installed metadata; never remediate.

    `scan_debian_source` receives exactly the two fixed relative paths returned
    by debian_source_inventory, and must use the same validated offline feed.
    The callback's result is a Trivy JSON object with --list-all-pkgs enabled.
    The caller must freshly create its query directory, never reuse stale data.
    """
    fixed_now = now
    now = now or datetime.now(timezone.utc)
    evidence = None
    try:
        require(isinstance(feed_updated_at, str), "kernel-advisory-feed-unavailable")
        feed = datetime.fromisoformat(feed_updated_at.replace("Z", "+00:00"))
        require(feed.tzinfo is not None and now.tzinfo is not None
                and timedelta(0) <= now - feed <= timedelta(hours=24), "kernel-advisory-feed-stale")
        probe = probe or HostProbe()
        before = probe.collect()
        evidence = dict(release=before["release"], runtimeVersion=before["runtimeVersion"],
                        installedPackage=before["package"], newestInstalled=before["newestInstalled"],
                        installedKernelCount=len(before["installedKernels"]), rebootNeeded=before["rebootNeeded"],
                        loadedBinaryAttested=False, livePatchesEvaluated=False)
        require(before["runtimeVersion"] == before["package"]["linuxVersion"], "running-installed-build-mismatch")
        if before["distribution"]["family"] == "debian":
            require(callable(scan_debian_source), "kernel-source-advisory-scan-unavailable")
            report = scan_debian_source(debian_source_inventory(before))
        else:
            report = host_report
        findings, incomplete = kernel_advisories(report, before)
        require(probe.collect() == before, "kernel-evidence-changed-during-scan")
        finished = fixed_now or datetime.now(timezone.utc)
        require(timedelta(0) <= finished - feed <= timedelta(hours=24), "kernel-advisory-feed-stale")
        status = "failed" if findings else "unavailable" if incomplete else "passed"
        detail = f"Running distribution kernel {before['release']} matched its exact source/package version against the fresh vendor advisory feed: {len(findings)} Medium or higher findings."
        if before["distribution"]["family"] == "rocky":
            detail += " Rocky feed coverage is limited to vendor-published advisories with a released fix; unfixed issues are not promised covered."
        if incomplete:
            detail += " Advisory severity classification is incomplete."
        if before["rebootNeeded"]:
            target = before["newestInstalled"]
            detail += f" A newer kernel is installed but is not running: {target['release']} (build {target['linuxVersion']}). Review this target and reboot during an approved maintenance window."
        detail += " In-memory binary attestation, live patches, firmware and host hardening are not evaluated."
        return dict(coverage=dict(name="host-running-kernel-vendor-advisories", status=status, detail=detail),
                    findings=findings, runningKernel=evidence)
    except Exception as error:
        reason = str(error) if isinstance(error, CoverageUnavailable) else "kernel-evidence-or-advisory-query-unavailable"
        detail = "Running-kernel vendor advisory coverage is unavailable (" + reason + "). Installed package results do not establish that a kernel fix is running."
        if evidence and evidence["rebootNeeded"]:
            target = evidence["newestInstalled"]
            detail += f" Installed and running kernel evidence differs; installed target {target['release']} (build {target['linuxVersion']}) needs maintenance review before considering the fix active."
        return dict(coverage=dict(name="host-running-kernel-vendor-advisories", status="unavailable", detail=detail),
                    findings=[], runningKernel=evidence)
