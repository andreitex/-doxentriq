#!/usr/bin/env python3
"""Running-kernel/advisory binding; synthetic protocol tests, no VM commands."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("host_kernel_security", HERE / "host_kernel_security.py")
K = importlib.util.module_from_spec(spec)
spec.loader.exec_module(K)
NOW = datetime(2026, 10, 11, 1, 0, tzinfo=timezone.utc)
FRESH = (NOW - timedelta(hours=1)).isoformat()
DEB_RELEASE = "6.1.0-37-amd64"
DEB_VERSION = "6.1.140-1"
RPM_RELEASE = "6.12.0-124.61.1.el10_1.x86_64"
RPM_VERSION = "6.12.0-124.61.1.el10_1"


def deb_row(release=DEB_RELEASE, version=DEB_VERSION, source="linux-signed-amd64", built=None, maintainer=K.DEBIAN_MAINTAINER, status="install ok installed"):
    source_version = version if source == "linux" else version.split("-", 1)[0] + "+1"
    built = f"linux (= {version})" if built is None else built
    return "\t".join(("linux-image-" + release, version, "amd64", status, source, source_version, built, maintainer)) + "\n"


def rpm_row(version="6.12.0", release="124.61.1.el10_1", epoch="0", vendor=K.ROCKY_VENDOR, source=None):
    source = f"kernel-{version}-{release}.src.rpm" if source is None else source
    return "\t".join(("kernel-core", epoch, version, release, "x86_64", source, vendor)) + "\n"


def snapshot(family="debian", reboot=False):
    package = K.parse_debian_packages(deb_row())[0] if family == "debian" else K.parse_rocky_packages(rpm_row())[0]
    return dict(distribution=dict(family=family, version="12" if family == "debian" else "10.1"),
                release=package["release"], build="#1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22)" if family == "debian" else "#1 SMP PREEMPT_DYNAMIC", image=dict(device=1, inode=2, size=42, sha256="a"*64),
                package=package, runtimeVersion=package["linuxVersion"], installedKernels=[package],
                newestInstalled=package, rebootNeeded=reboot)


def report(snap, severities=()):
    active = snap["package"]
    version, release = active["version"].rsplit("-", 1)
    package = dict(ID=active["name"] + "@" + active["version"], Name=active["name"], Version=version,
                   Release=release, Arch=active["arch"], SrcName="linux" if snap["distribution"]["family"] == "debian" else "kernel",
                   SrcVersion=version, SrcRelease=release, Repository={"Class": "official"})
    vulns = [dict(VulnerabilityID=f"CVE-2026-{1000+i}", PkgName=active["name"], PkgID=package["ID"], InstalledVersion=active["version"],
                  FixedVersion="6.1.150-1" if snap["distribution"]["family"] == "debian" else "6.12.0-124.62.1.el10_1",
                  Severity=severity, DataSource={"ID": snap["distribution"]["family"], "URL": "https://security-tracker.debian.org/tracker/"},
                  PrimaryURL="https://security-tracker.debian.org/tracker/CVE-2026-1000", Title="Synthetic kernel advisory") for i, severity in enumerate(severities)]
    return dict(Metadata={"OS": {"Family": snap["distribution"]["family"], "Name": snap["distribution"]["version"], "EOSL": False}},
                Results=[dict(Class="os-pkgs", Type=snap["distribution"]["family"], Packages=[package], Vulnerabilities=vulns)])


class Probe:
    def __init__(self, before=None, after=None):
        self.before = before or snapshot()
        self.after = after or self.before
        self.calls = 0

    def collect(self):
        self.calls += 1
        return deepcopy(self.before if self.calls == 1 else self.after)


class Assessment(unittest.TestCase):
    def check(self, snap=None, scanned=None, **kwargs):
        snap = snap or snapshot()
        scanned = scanned or report(snap)
        return K.check_running_kernel(scanned, FRESH, lambda files: scanned,
                                      probe=kwargs.pop("probe", Probe(snap)), now=NOW, **kwargs)

    def test_debian_signed_source_query_uses_exact_linux_built_using(self):
        snap = snapshot()
        calls = []
        def scanner(files):
            calls.append(files)
            self.assertEqual(set(files), {"etc/os-release", "var/lib/dpkg/status"})
            self.assertIn("Source: linux (6.1.140-1)\n", files["var/lib/dpkg/status"])
            self.assertNotIn("linux-signed-amd64", files["var/lib/dpkg/status"])
            return report(snap, ["MEDIUM"])
        result = K.check_running_kernel(None, FRESH, scanner, probe=Probe(snap), now=NOW)
        self.assertEqual(result["coverage"]["status"], "failed")
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["findings"][0]["id"], "CVE-2026-1000")
        self.assertEqual(set(result["findings"][0]), {"id", "severity", "package", "installedVersion", "fixedVersion", "source", "description"})

    def test_rocky_exact_active_version_not_newest_installed_version(self):
        snap = snapshot("rocky", reboot=True)
        newer = K.parse_rocky_packages(rpm_row(release="124.62.1.el10_1"))[0]
        snap["newestInstalled"] = newer; snap["installedKernels"].append(newer)
        scanned = report(snap, ["HIGH"])
        extra = deepcopy(scanned["Results"][0]["Packages"][0])
        extra.update(ID="new", Release="124.62.1.el10_1", SrcRelease="124.62.1.el10_1")
        scanned["Results"][0]["Packages"].append(extra)
        result = self.check(snap, scanned)
        self.assertEqual(result["coverage"]["status"], "failed")
        self.assertEqual(result["findings"][0]["installedVersion"], RPM_VERSION)
        self.assertTrue(result["runningKernel"]["rebootNeeded"])
        self.assertIn("newer kernel is installed", result["coverage"]["detail"])
        self.assertIn("unfixed issues are not promised covered", result["coverage"]["detail"])

    def test_low_only_clean_published_advisory_scope_does_not_claim_live_patch_attestation(self):
        result = self.check(scanned=report(snapshot(), ["LOW"]))
        self.assertEqual(result["coverage"]["status"], "passed")
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["runningKernel"]["loadedBinaryAttested"])
        self.assertFalse(result["runningKernel"]["livePatchesEvaluated"])

    def test_unknown_or_missing_severity_is_unavailable_and_known_findings_remain(self):
        for severities, expected in [(["UNKNOWN"], "unavailable"), ([None], "unavailable"), (["HIGH", "UNKNOWN"], "failed")]:
            with self.subTest(severities=severities):
                result = self.check(scanned=report(snapshot(), severities))
                self.assertEqual(result["coverage"]["status"], expected)
                self.assertIn("classification is incomplete", result["coverage"]["detail"])

    def test_stale_future_naive_or_missing_feed_never_calls_probe_or_scanner(self):
        for feed in [None, "garbage", (NOW-timedelta(hours=24, seconds=1)).isoformat(), (NOW+timedelta(seconds=1)).isoformat(), "2026-10-11T00:00:00"]:
            with self.subTest(feed=feed):
                probe = Probe()
                result = K.check_running_kernel(None, feed, lambda _: self.fail("scanner called"), probe=probe, now=NOW)
                self.assertEqual(result["coverage"]["status"], "unavailable")
                self.assertEqual(probe.calls, 0)

    def test_feed_expiring_during_scanner_callback_cannot_pass(self):
        clock = SimpleNamespace(fromisoformat=datetime.fromisoformat,
                                now=MagicMock(side_effect=[NOW, NOW + timedelta(hours=24)]))
        calls = []
        with patch.object(K, "datetime", clock):
            result = K.check_running_kernel(None, FRESH, lambda files: calls.append(files) or report(snapshot()),
                                            probe=Probe())
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["coverage"]["status"], "unavailable")
        self.assertEqual(result["findings"], [])
        self.assertIn("kernel-advisory-feed-stale", result["coverage"]["detail"])

    def test_slow_scanner_gets_independent_bounded_before_and_after_snapshots(self):
        clock, deadlines = [0], []
        def query(argv, deadline):
            K.require(deadline > clock[0], "package-query-timeout")
            deadlines.append((clock[0], deadline))
            if argv[0].endswith("uname"):
                return 0, {"-r": DEB_RELEASE+"\n", "-v": "#1 SMP Debian 6.1.140-1\n", "-m": "x86_64\n"}[argv[1]]
            if argv[0].endswith("dpkg-query"):
                return 0, deb_row() if argv[1] == "-W" else "linux-image-"+DEB_RELEASE+": /boot/vmlinuz-"+DEB_RELEASE+"\n"
            return 1, ""
        def scan(_):
            clock[0] = 120
            return report(snapshot())
        with patch.object(K.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(K, "_bounded_query", side_effect=query), \
             patch.object(Path, "is_symlink", return_value=False):
            probe = K.HostProbe(file_read=lambda _, limit, content=False: "ID=debian\nVERSION_ID=12\n" if content else {"sha256": "a"*64})
            result = K.check_running_kernel(None, FRESH, scan, probe=probe, now=NOW)
        self.assertEqual(result["coverage"]["status"], "passed")
        self.assertEqual(set(deadlines), {(0, 30), (120, 150)})

    def test_same_abi_installed_package_replaced_while_old_build_running_requires_reboot(self):
        snap = snapshot(); snap["runtimeVersion"] = "6.1.139-1"; snap["rebootNeeded"] = True
        result = K.check_running_kernel(None, FRESH, lambda _: self.fail("cannot infer old source"), probe=Probe(snap), now=NOW)
        self.assertEqual(result["coverage"]["status"], "unavailable")
        self.assertEqual(result["runningKernel"]["runtimeVersion"], "6.1.139-1")
        self.assertTrue(result["runningKernel"]["rebootNeeded"])
        self.assertIn("running-installed-build-mismatch", result["coverage"]["detail"])

    def test_scan_race_kernel_package_or_image_drift_cannot_pass(self):
        for key in ["release", "runtimeVersion", "image", "installedKernels"]:
            with self.subTest(key=key):
                before = snapshot(); after = deepcopy(before)
                after[key] = "changed" if key in {"release", "runtimeVersion"} else {}
                result = self.check(probe=Probe(before, after))
                self.assertEqual(result["coverage"]["status"], "unavailable")
                self.assertIn("changed-during-scan", result["coverage"]["detail"])

    def test_exact_package_source_arch_and_os_presence_are_mandatory(self):
        changes = [("os", "Family", "ubuntu"), ("os", "Name", "13"), ("os", "EOSL", True), ("os", "EOSL", 1),
                   ("pkg", "Name", "linux-image-other"), ("pkg", "Arch", "arm64"), ("pkg", "Version", "6.1.141"),
                   ("pkg", "SrcName", "linux-signed-amd64"), ("pkg", "SrcRelease", "2"), ("pkg", "Epoch", True),
                   ("pkg", "Repository", {"Class": "third-party"})]
        for kind, key, value in changes:
            with self.subTest(kind=kind, key=key, value=value):
                scanned = report(snapshot())
                target = scanned["Metadata"]["OS"] if kind == "os" else scanned["Results"][0]["Packages"][0]
                target[key] = value
                self.assertEqual(self.check(scanned=scanned)["coverage"]["status"], "unavailable")

    def test_missing_duplicate_package_or_multiple_os_results_are_unavailable(self):
        for mutation in [lambda r: r["Results"][0].pop("Packages"),
                         lambda r: r["Results"][0]["Packages"].append(deepcopy(r["Results"][0]["Packages"][0])),
                         lambda r: r["Results"].append(deepcopy(r["Results"][0]))]:
            scanned = report(snapshot()); mutation(scanned)
            self.assertEqual(self.check(scanned=scanned)["coverage"]["status"], "unavailable")

    def test_nonvendor_package_advisory_and_duplicate_ids_are_unavailable(self):
        for mutation in [lambda v: v[0].update(DataSource={"ID": "nvd"}), lambda v: v[0].update(PkgID="foreign"),
                         lambda v: v[0].pop("InstalledVersion"), lambda v: v[0].update(Severity="MODERATE"),
                         lambda v: v.append(deepcopy(v[0]))]:
            scanned = report(snapshot(), ["HIGH"]); mutation(scanned["Results"][0]["Vulnerabilities"])
            self.assertEqual(self.check(scanned=scanned)["coverage"]["status"], "unavailable")

    def test_debian_callback_failure_and_host_query_failure_remain_unavailable_no_raw_errors(self):
        result = K.check_running_kernel({}, FRESH, lambda _: (_ for _ in ()).throw(RuntimeError("synthetic-secret")), probe=Probe(), now=NOW)
        self.assertEqual(result["coverage"]["status"], "unavailable"); self.assertNotIn("synthetic-secret", str(result))
        result = K.check_running_kernel({}, FRESH, probe=SimpleNamespace(collect=lambda: (_ for _ in ()).throw(RuntimeError("raw host error"))), now=NOW)
        self.assertNotIn("raw host error", str(result))


class PackageEvidence(unittest.TestCase):
    def test_debian_signed_and_unsigned_exact_source_mapping(self):
        for source in ["linux", "linux-signed-amd64"]:
            self.assertEqual(K.parse_debian_packages(deb_row(source=source))[0]["linuxVersion"], DEB_VERSION)

    def test_debian_no_inferred_or_ambiguous_built_using(self):
        for built in ["", "linux (>= 6.1.140-1)", "linux (= 6.1.140-2)", "linux (= 6.1.140-1), linux (= 6.1.140-1)", "linux-signed (= 6.1.140-1)"]:
            with self.subTest(built=built), self.assertRaises(K.CoverageUnavailable):
                K.parse_debian_packages(deb_row(built=built))
        for raw in [deb_row(maintainer="Third Party"), deb_row(source="custom-linux"), deb_row()*2, deb_row(status="deinstall ok config-files")]:
            with self.assertRaises(K.CoverageUnavailable): K.parse_debian_packages(raw)

    def test_rocky_vendor_source_arch_epoch_and_duplicate_guards(self):
        self.assertEqual(K.parse_rocky_packages(rpm_row(epoch="1"))[0]["version"], "1:" + RPM_VERSION)
        for raw in [rpm_row(vendor="CentOS"), rpm_row(source="custom.src.rpm"), rpm_row(epoch="(none)"), rpm_row()*2,
                    rpm_row().replace("x86_64", "aarch64"), rpm_row(version="6.12.0');os.execute('bad")]:
            with self.subTest(raw=raw), self.assertRaises(K.CoverageUnavailable): K.parse_rocky_packages(raw)

    def test_supported_os_release_is_not_shell_evaluated(self):
        for raw in ['ID=debian\nVERSION_ID="12"\n', 'ID="rocky"\nVERSION_ID="10.2"\n']:
            self.assertIn(K.parse_os_release(raw)["family"], {"debian", "rocky"})
        for raw in ["ID=rocky\nID=debian\nVERSION_ID=12\n", "ID=ubuntu\nVERSION_ID=24.04\n", "ID=debian\nVERSION_ID=11\n", "ID=$(bad)\nVERSION_ID=12\n"]:
            with self.assertRaises(K.CoverageUnavailable): K.parse_os_release(raw)

    def test_version_queries_are_native_readonly_and_reject_lua_injection_before_dispatch(self):
        calls = []
        probe = K.HostProbe(query=lambda argv: (calls.append(argv) or (0, "1\n")))
        self.assertTrue(probe.compare("rocky", RPM_VERSION, "6.12.0-124.60.1.el10_1"))
        self.assertEqual(calls[0][0:2], ["/usr/bin/rpm", "--eval"])
        self.assertNotIn("os.execute", calls[0][2])
        before = len(calls)
        with self.assertRaises(K.CoverageUnavailable): probe.compare("rocky", "1');os.execute('bad", RPM_VERSION)
        self.assertEqual(len(calls), before)
        calls.clear(); probe.query = lambda argv: (calls.append(argv) or (1, ""))
        self.assertFalse(probe.compare("debian", DEB_VERSION, "6.1.141-1"))
        self.assertEqual(calls[0], ["/usr/bin/dpkg", "--compare-versions", DEB_VERSION, "gt", "6.1.141-1"])

    def test_default_runner_rejects_mutation_network_or_arbitrary_macro_before_process(self):
        forbidden = [["/usr/bin/rpm", "-e", "kernel-core"], ["/usr/bin/dpkg", "--install", "file.deb"],
                     ["/usr/bin/rpm", "--eval", "%{lua:os.execute('bad')}"],
                     ["/usr/bin/rpm", "-qf", "https://example.invalid/pkg.rpm", "--qf", K.RPM_FORMAT],
                     ["/usr/bin/dpkg-query", "-S", "/boot/vmlinuz-../../etc/passwd"],
                     ["/usr/bin/uname", "-a"], ["/bin/sh", "-c", "true"]]
        with patch.object(K.subprocess, "Popen", side_effect=AssertionError("must not launch")):
            for argv in forbidden:
                with self.subTest(argv=argv), self.assertRaises(K.CoverageUnavailable):
                    K._bounded_query(argv, 1)
        K._allowed_query(["/usr/bin/rpm", "--eval", "%{lua:print(rpm.vercmp('" + RPM_VERSION + "','" + RPM_VERSION + "'))}"])
        K._allowed_query(["/usr/bin/dpkg", "--compare-versions", DEB_VERSION, "gt", DEB_VERSION])

    def test_package_query_output_limit_kills_process_and_discards_batch(self):
        process = MagicMock()
        process.poll.return_value = None
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {1: object()}
        selector.select.return_value = [(SimpleNamespace(fileobj=process.stdout), 1)]
        with patch.object(K.subprocess, "Popen", return_value=process), \
             patch.object(K.selectors, "DefaultSelector", return_value=selector), \
             patch.object(K.time, "monotonic", return_value=0), \
             patch.object(K.os, "read", return_value=b"012345678"), \
             patch.object(K, "MAX_QUERY_BYTES", 8), \
             self.assertRaisesRegex(K.CoverageUnavailable, "package-query-output-limit"):
            K._bounded_query(["/usr/bin/uname", "-r"], 30)
        process.kill.assert_called_once_with()
        process.stdout.close.assert_called_once_with()

    def test_package_query_deadline_kills_process_without_reusing_partial_output(self):
        process = MagicMock()
        process.poll.return_value = None
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {1: object()}
        with patch.object(K.subprocess, "Popen", return_value=process), \
             patch.object(K.selectors, "DefaultSelector", return_value=selector), \
             patch.object(K.time, "monotonic", side_effect=[0, 0, 11]), \
             self.assertRaisesRegex(K.CoverageUnavailable, "package-query-timeout"):
            K._bounded_query(["/usr/bin/uname", "-r"], 30)
        process.kill.assert_called_once_with()
        selector.select.assert_not_called()
        process.stdout.close.assert_called_once_with()

    def test_runtime_debian_collector_matches_build_owner_and_only_same_flavor_alternatives(self):
        calls = []
        rows = deb_row() + deb_row("6.1.0-38-amd64", "6.1.141-1") + deb_row("6.1.0-40-cloud-amd64", "6.1.145-1")
        def query(argv):
            calls.append(argv)
            if argv[0].endswith("uname"):
                return 0, {"-r": DEB_RELEASE+"\n", "-v": "#1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22)\n", "-m": "x86_64\n"}[argv[1]]
            if argv[0].endswith("dpkg-query"):
                return 0, rows if argv[1] == "-W" else "linux-image-"+DEB_RELEASE+": /boot/vmlinuz-"+DEB_RELEASE+"\n"
            return (0 if argv[2] > argv[4] else 1), ""
        def file_read(path, _, content=False):
            return "ID=debian\nVERSION_ID=12\n" if content else dict(sha256="a"*64)
        with patch.object(Path, "is_symlink", return_value=False):
            result = K.HostProbe(query=query, file_read=file_read).collect()
        self.assertTrue(result["rebootNeeded"])
        self.assertEqual(result["newestInstalled"]["version"], "6.1.141-1")
        self.assertEqual(result["runtimeVersion"], DEB_VERSION)
        self.assertTrue(all(argv[0] in {"/usr/bin/uname", "/usr/bin/dpkg-query", "/usr/bin/dpkg"} for argv in calls))

    def test_runtime_rocky_collector_keeps_old_running_kernel_when_newer_installed(self):
        current = rpm_row(); newer = rpm_row(release="124.62.1.el10_1")
        def query(argv):
            if argv[0].endswith("uname"):
                return 0, {"-r": RPM_RELEASE+"\n", "-v": "#1 SMP PREEMPT_DYNAMIC\n", "-m": "x86_64\n"}[argv[1]]
            if argv[1] == "--eval": return 0, "1\n" if "124.62" in argv[2] else "0\n"
            return 0, current if argv[1] == "-qf" else current+newer
        with patch.object(Path, "is_symlink", return_value=False):
            result = K.HostProbe(query=query, file_read=lambda p, n, content=False: "ID=rocky\nVERSION_ID=10.1\n" if content else {}).collect()
        self.assertTrue(result["rebootNeeded"])
        self.assertEqual(result["package"]["version"], RPM_VERSION)

    def test_missing_or_ambiguous_running_owner_never_infers_newest(self):
        snap = snapshot(); raw = deb_row()
        def query(argv):
            if argv[0].endswith("uname"):
                return 0, {"-r": DEB_RELEASE+"\n", "-v": "#1 SMP Debian 6.1.140-1\n", "-m": "x86_64\n"}[argv[1]]
            return 0, raw if argv[1] == "-W" else "foreign: /boot/vmlinuz-"+DEB_RELEASE+"\n"
        with patch.object(Path, "is_symlink", return_value=False), self.assertRaises(K.CoverageUnavailable):
            K.HostProbe(query=query, file_read=lambda p, n, content=False: "ID=debian\nVERSION_ID=12\n" if content else {}).collect()


class FileIdentity(unittest.TestCase):
    def test_read_atime_can_change_but_stable_write_identity_must_not(self):
        folder = HERE.parent / ".local" if os.name == "nt" else None
        with tempfile.TemporaryDirectory(dir=folder) as temporary:
            path = Path(temporary) / "evidence"; path.write_bytes(b"synthetic evidence")
            native = path.stat()
            fields = {key: getattr(native, key) for key in ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_gid", "st_nlink", "st_mtime_ns", "st_ctime_ns", "st_atime_ns")}
            fields.update(st_uid=0, st_mode=stat.S_IFREG|0o644, st_nlink=1)
            before = SimpleNamespace(**fields); fields["st_atime_ns"] += 10**9; after = SimpleNamespace(**fields)
            with patch.object(os, "O_NOFOLLOW", 0, create=True), patch.object(os, "O_NONBLOCK", 0, create=True), patch.object(os, "fstat", side_effect=[before, after]), patch.object(Path, "lstat", return_value=after):
                self.assertEqual(K._ordinary_file(path, 1024, content=True), "synthetic evidence")
            changed = SimpleNamespace(**{**fields, "st_mtime_ns": fields["st_mtime_ns"]+1})
            with patch.object(os, "O_NOFOLLOW", 0, create=True), patch.object(os, "O_NONBLOCK", 0, create=True), patch.object(os, "fstat", side_effect=[before, changed]), patch.object(Path, "lstat", return_value=changed), self.assertRaises(K.CoverageUnavailable):
                K._ordinary_file(path, 1024)


if __name__ == "__main__":
    unittest.main()
