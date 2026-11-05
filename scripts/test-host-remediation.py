#!/usr/bin/env python3
"""Injected planning evidence only; no host query, repository or transaction."""
import ast
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("host_remediation", HERE / "host_remediation.py")
R = importlib.util.module_from_spec(spec);sys.modules[spec.name] = R;spec.loader.exec_module(R)
NOW = datetime(2026, 10, 11, 15, 0, tzinfo=timezone.utc)
KEY = "A" * 40


def raw(value):return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
def moment(seconds):return (NOW - timedelta(seconds=seconds)).isoformat()
def pkg(name, version, arch="amd64", source=None, essential=False):
    return dict(name=name, version=version, arch=arch, source=source or name,
                source_version=version, essential=essential)
def identity(value):return R.Package(**value).identity


class Fixture:
    def __init__(self, family="debian"):
        self.family = family;self.arch = "amd64" if family == "debian" else "x86_64"
        self.distro = dict(family=family, version="13" if family == "debian" else "10.2")
        kernel_name = "linux-image-6.12.0-1-amd64" if family == "debian" else "kernel-core"
        self.kernel = pkg(kernel_name, "6.12.0-1", self.arch, "linux" if family == "debian" else "kernel")
        self.zlib = pkg("zlib", "1.3.2-1", self.arch)
        self.abi = pkg("libabi", "1.0-1", self.arch)
        self.installed = [self.kernel, self.zlib, self.abi]
        self.inventory = dict(schemaVersion=1, distribution=self.distro, packages=self.installed,
                              metadataSha256="b" * 64, capturedAt=moment(60))
        self.before = raw(self.inventory);self.after = raw(dict(self.inventory, capturedAt=moment(15)))
        self.parsed = R.parse_inventory(self.before, NOW)
        self.target = pkg("zlib", "1.3.2-2", self.arch)
        self.repo = "Debian:13/stable" if family == "debian" else "baseos"
        self.repository = dict(schemaVersion=1, distribution=self.distro, generatedAt=moment(3600),
                               validUntil=(NOW + timedelta(hours=2)).isoformat(), repositories=[self.repo],
                               candidates=[self.candidate(self.target, [dict(id="CVE-2026-1001", installedIdentity=identity(self.zlib))])])
        self.scan = dict(Metadata={"OS": dict(Family=family, Name=self.distro["version"], EOSL=False)},
                         Results=[dict(Class="os-pkgs", Type=family, Packages=[self.scan_package(p) for p in self.installed],
                                       Vulnerabilities=[self.finding(self.zlib)])])
        self.scan_context = R.ScanContext(self.parsed.identity, "c" * 64, moment(3600), moment(40),
                                         (("host-os-packages", "failed"), ("host-running-kernel-vendor-advisories", "passed")))
        self.kernel_context = R.RunningKernel(identity(self.kernel), "6.12.0-1-amd64" if family == "debian" else "6.12.0-1.x86_64", self.kernel["source_version"], False)
        self.requested = (identity(self.target),)
        self.simulation = self.apt([self.target], []) if family == "debian" else self.dnf([("Upgrade", self.target, self.repo), ("Upgraded", self.zlib, "@System")])

    def candidate(self, target, fixes=()):
        return dict(package=target, repository=self.repo, archiveSha256=R.sha(raw(target)), fixes=list(fixes))

    def scan_package(self, p):
        return dict(ID=identity(p), Name=p["name"], Version=p["version"], Arch=p["arch"],
                    SrcName=p["source"], SrcVersion=p["source_version"], Repository={"Class": "official"})

    def finding(self, p, identifier="CVE-2026-1001", severity="HIGH", fixed="9999-99"):
        return dict(VulnerabilityID=identifier, Severity=severity, PkgID=identity(p), PkgName=p["name"],
                    InstalledVersion=p["version"], FixedVersion=fixed, DataSource={"ID": self.family},
                    Title="synthetic", PrimaryURL="https://vendor.invalid/public")

    def apt(self, installs, removes):
        old = {(p["name"], p["arch"]): p for p in self.installed};lines=[];changes=0;adds=0
        for p in installs:
            prior = old.get((p["name"], p["arch"]));bracket = " [" + prior["version"] + "]" if prior else ""
            changes += int(prior is not None);adds += int(prior is None)
            lines.append(f'Inst {p["name"]}{bracket} ({p["version"]} {self.repo} [{p["arch"]}])')
        for p in removes:lines.append(f'Remv {p["name"]} [{p["version"]}]')
        for p in installs:lines.append(f'Conf {p["name"]} ({p["version"]} {self.repo} [{p["arch"]}])')
        lines.append(f'{changes} upgraded, {adds} newly installed, {len(removes)} to remove and 0 not upgraded.')
        return ("\n".join(lines) + "\n").encode()

    def dnf(self, operations):
        return raw(dict(version="1.0", groups=[], environments=[], rpms=[dict(action=action,
                   nevra=p["name"] + "-" + (p["version"] if ":" in p["version"] else "0:" + p["version"]) + "." + p["arch"],
                   repo_id=repo, reason="user" if p["name"] == "zlib" else "dependency") for action, p, repo in operations]))

    def arguments(self):
        repo_raw = raw(self.repository)
        return dict(inventory_before=self.before, inventory_after=self.after, scan_report=raw(self.scan), scan_context=self.scan_context,
                    repository_metadata=repo_raw, repository_authentication=R.RepositoryAuthentication(R.sha(repo_raw), "d" * 64,
                    "debian-release-chain" if self.family == "debian" else "rocky-repomd-signature", (KEY,)), trusted_fingerprints=(KEY,),
                    simulation_output=self.simulation, simulation_context=R.SimulationContext("apt-get" if self.family == "debian" else "dnf", "3.0.3" if self.family == "debian" else "4.22.0",
                    self.parsed.identity, self.parsed.identity, R.sha(repo_raw), R.sha(self.simulation), self.requested, moment(30), 25, 0),
                    running_kernel=self.kernel_context, now=NOW)

    def plan(self, **changes):return R.plan_host_remediation(**(self.arguments() | changes))


class Tests(unittest.TestCase):
    def test_debian_candidate_requires_explicit_vendor_fix_not_fixed_version(self):
        f=Fixture();result=f.plan()
        self.assertEqual(result.status,"proposed_untested");self.assertEqual(len(result.changes),1)
        self.assertEqual(result.changes[0].after.version,"1.3.2-2")
        self.assertNotEqual(result.changes[0].after.version,f.scan["Results"][0]["Vulnerabilities"][0]["FixedVersion"])
        self.assertFalse(result.tested);self.assertFalse(result.apply_authorized);self.assertFalse(result.live_query_adapters_available)
        self.assertTrue(result.checkpoint_required);self.assertTrue(result.approved_maintenance_window_required)

    def test_rocky_resolved_native_transaction_pair(self):
        result=Fixture("rocky").plan();self.assertEqual(result.status,"proposed_untested")
        self.assertEqual([(p.action,p.before.version,p.after.version) for p in result.changes],[("change","1.3.2-1","1.3.2-2")])

    def test_dependency_addition_change_and_removal_all_exposed(self):
        for family in ("debian","rocky"):
            f=Fixture(family);added=pkg("libnew","2.0-1",f.arch);abi=pkg("libabi","1.0-2",f.arch)
            f.repository["candidates"] += [f.candidate(added),f.candidate(abi)]
            removed=pkg("obsolete","1.0-1",f.arch);f.installed.append(removed)
            f.inventory["packages"]=f.installed;f.before=raw(f.inventory);f.after=raw(dict(f.inventory,capturedAt=moment(15)))
            f.parsed=R.parse_inventory(f.before,NOW);f.scan_context=replace(f.scan_context,inventory_sha256=f.parsed.identity)
            f.scan["Results"][0]["Packages"]=[f.scan_package(p) for p in f.installed]
            f.simulation=f.apt([f.target,abi,added],[removed]) if family=="debian" else f.dnf([
                ("Upgrade",f.target,f.repo),("Upgraded",f.zlib,"@System"),("Upgrade",abi,f.repo),("Upgraded",f.abi,"@System"),
                ("Install",added,f.repo),("Removed",removed,"@System")])
            result=f.plan();self.assertEqual(result.status,"proposed_untested",result.reason)
            self.assertEqual(sorted(p.action for p in result.changes),["add","change","change","remove"])
            self.assertTrue(all(p.archive_sha256 is not None for p in result.changes if p.after))

    def test_fixed_version_without_vendor_fix_binding_remains_blocked(self):
        f=Fixture();f.repository["candidates"][0]["fixes"]=[]
        self.assertEqual(f.plan().reason,"request-without-vendor-fix-binding")

    def test_unresolved_findings_are_retained_without_clean_claim(self):
        f=Fixture();f.scan["Results"][0]["Vulnerabilities"].append(f.finding(f.abi,"CVE-2026-1002","MEDIUM"))
        result=f.plan();self.assertEqual(result.status,"blocked_unresolved")
        self.assertEqual([p.id for p in result.unresolved],["CVE-2026-1002"]);self.assertEqual(len(result.changes),1)

    def test_low_findings_do_not_authorize_maintenance(self):
        f=Fixture();f.scan["Results"][0]["Vulnerabilities"][0]["Severity"]="LOW"
        self.assertEqual(f.plan().status,"unavailable")
        f.simulation=f.apt([],[]);f.requested=()
        f.scan_context=replace(f.scan_context,coverage=(("host-os-packages","passed"),("host-running-kernel-vendor-advisories","passed")))
        result=f.plan();self.assertEqual(result.status,"no_medium_plus_actions");self.assertEqual(result.changes,())

    def test_missing_or_unknown_severity_is_unavailable(self):
        for severity in (None,"UNKNOWN","UNRATED","",True):
            f=Fixture();f.scan["Results"][0]["Vulnerabilities"][0]["Severity"]=severity
            self.assertEqual(f.plan().reason,"unclassified-advisory")
        f=Fixture();del f.scan["Results"][0]["Vulnerabilities"][0]["Severity"]
        self.assertEqual(f.plan().reason,"unclassified-advisory")

    def test_scan_list_all_packages_must_exactly_match_inventory(self):
        f=Fixture();f.scan["Results"][0]["Packages"].pop();self.assertEqual(f.plan().reason,"scan-inventory-mismatch")
        f=Fixture();f.scan["Results"][0]["Packages"].append(f.scan_package(pkg("foreign","1.0-1")))
        self.assertEqual(f.plan().reason,"scan-inventory-mismatch")

    def test_source_version_arch_and_vendor_mismatch_rejected(self):
        for field,value in (("SrcVersion","1.0-99"),("Arch","arm64"),("Repository",{"Class":"third-party"})):
            f=Fixture();f.scan["Results"][0]["Packages"][0][field]=value
            self.assertEqual(f.plan().status,"unavailable")

    def test_cross_distribution_and_eosl_rejected(self):
        f=Fixture();f.scan["Metadata"]["OS"]["Family"]="rocky";self.assertEqual(f.plan().reason,"scan-distribution-mismatch")
        for value in (True,None,0):
            f=Fixture();f.scan["Metadata"]["OS"]["EOSL"]=value;self.assertEqual(f.plan().reason,"scan-distribution-mismatch")

    def test_vendor_advisory_and_exact_package_binding(self):
        for field,value in (("PkgID","other"),("InstalledVersion","1.3.2-99"),("DataSource",{"ID":"nvd"})):
            f=Fixture();f.scan["Results"][0]["Vulnerabilities"][0][field]=value
            self.assertEqual(f.plan().status,"unavailable")

    def test_duplicate_package_and_advisory_rejected(self):
        f=Fixture();f.scan["Results"][0]["Packages"].append(deepcopy(f.scan["Results"][0]["Packages"][0]))
        self.assertEqual(f.plan().reason,"ambiguous-scanned-package")
        f=Fixture();f.scan["Results"][0]["Vulnerabilities"].append(deepcopy(f.scan["Results"][0]["Vulnerabilities"][0]))
        self.assertEqual(f.plan().reason,"duplicate-advisory")

    def test_incomplete_coverage_cannot_yield_plan(self):
        f=Fixture()
        for coverage in ((),(("host-os-packages","passed"),),(("host-os-packages","failed"),("host-running-kernel-vendor-advisories","unavailable"))):
            self.assertEqual(f.plan(scan_context=replace(f.scan_context,coverage=coverage)).reason,"incomplete-host-coverage")

    def test_inventory_race_and_simulation_bracketing(self):
        f=Fixture();after=deepcopy(f.inventory);after["packages"][1]["version"]="1.3.2-3"
        self.assertEqual(f.plan(inventory_after=raw(after)).reason,"installed-inventory-changed")
        f=Fixture();ctx=f.arguments()["simulation_context"]
        self.assertEqual(f.plan(simulation_context=replace(ctx,checked_at=moment(5))).reason,"simulation-not-bracketed-by-inventory")

    def test_stale_feed_repository_and_inventory_rejected(self):
        f=Fixture();self.assertEqual(f.plan(scan_context=replace(f.scan_context,feed_updated_at=moment(86401))).reason,"stale-or-future-evidence")
        f.repository["generatedAt"]=moment(86401);self.assertEqual(f.plan().reason,"stale-or-future-evidence")
        f=Fixture();f.inventory["capturedAt"]=moment(1801);self.assertEqual(f.plan(inventory_before=raw(f.inventory)).reason,"stale-or-future-evidence")

    def test_expired_repository_and_future_metadata_rejected(self):
        for field,value in (("validUntil",NOW.isoformat()),("generatedAt",(NOW+timedelta(seconds=1)).isoformat())):
            f=Fixture();f.repository[field]=value;self.assertEqual(f.plan().reason,"stale-or-future-evidence")

    def test_authentication_is_typed_and_binds_payload_chain_and_trust(self):
        f=Fixture();args=f.arguments();auth=args["repository_authentication"]
        for value in (None,True,{"signed":True},replace(auth,payload_sha256="0"*64),replace(auth,method="rocky-repomd-signature"),replace(auth,signer_fingerprints=("B"*40,)),replace(auth,signed_metadata_sha256="missing")):
            self.assertEqual(f.plan(repository_authentication=value).status,"unavailable")
        self.assertEqual(f.plan(trusted_fingerprints=()).reason,"repository-trust-unavailable")

    def test_authenticated_candidate_cannot_claim_foreign_installed_fix(self):
        f=Fixture();f.repository["candidates"][0]["fixes"][0]["installedIdentity"]="0"*64
        self.assertEqual(f.plan().reason,"invalid-vendor-fix-binding")
        f=Fixture();f.repository["candidates"][0]["package"]["source"]="foreign"
        self.assertEqual(f.plan().reason,"invalid-vendor-fix-binding")

    def test_simulation_cannot_use_unsigned_dependency_or_unknown_repository(self):
        for family in ("debian","rocky"):
            f=Fixture(family);foreign=pkg("unbound","1.0-1",f.arch)
            f.simulation=f.apt([f.target,foreign],[]) if family=="debian" else f.dnf([("Upgrade",f.target,f.repo),("Upgraded",f.zlib,"@System"),("Install",foreign,f.repo)])
            self.assertEqual(f.plan().reason,"simulation-candidate-not-authenticated")
        f=Fixture();f.simulation=f.simulation.replace(f.repo.encode(),b"foreign")
        self.assertEqual(f.plan().reason,"simulation-candidate-not-authenticated")

    def test_simulation_receipt_bindings_and_bounded_failure(self):
        f=Fixture();ctx=f.arguments()["simulation_context"]
        for changes in (dict(stdout_sha256="0"*64),dict(repository_sha256="0"*64),dict(inventory_after_sha256="0"*64),dict(manager="dnf"),dict(return_code=1),dict(return_code=False),dict(duration_millis=30001),dict(duration_millis=True)):
            self.assertEqual(f.plan(simulation_context=replace(ctx,**changes)).status,"unavailable")

    def test_apt_missing_configuration_or_totals_rejected(self):
        f=Fixture()
        for output in (f.simulation.replace(b"1 upgraded",b"2 upgraded"),b"\n".join(line for line in f.simulation.splitlines() if not line.startswith(b"Conf")),b"\n".join(line for line in f.simulation.splitlines() if b"upgraded," not in line)):
            self.assertEqual(f.plan(simulation_output=output,simulation_context=replace(f.arguments()["simulation_context"],stdout_sha256=R.sha(output))).reason,"incomplete-simulation")

    def test_apt_localized_or_broken_or_extra_operation_never_ignored(self):
        for extra in (b"W: held packages\n",b"Inst zlib Broken\n",b"The following packages will be upgraded:\n",b"ERROR credential-canary\n"):
            f=Fixture();f.simulation+=extra;result=f.plan();self.assertEqual(result.reason,"unsupported-apt-simulation-output")
            self.assertNotIn("credential-canary",json.dumps(result.as_dict()))

    def test_duplicate_simulation_and_wrong_installed_version_rejected(self):
        f=Fixture();f.simulation=f.apt([f.target,f.target],[]);self.assertEqual(f.plan().status,"unavailable")
        f=Fixture();f.simulation=f.simulation.replace(b"[1.3.2-1]",b"[1.3.2-99]")
        self.assertEqual(f.plan().reason,"simulation-inventory-mismatch")

    def test_dnf_omitted_old_pair_and_unknown_action_rejected(self):
        f=Fixture("rocky");f.simulation=f.dnf([("Upgrade",f.target,f.repo)])
        self.assertEqual(f.plan().reason,"incomplete-simulation")
        for action in ("Downgrade","Reinstall","Obsoleted","Reason Change"):
            f=Fixture("rocky");f.simulation=f.dnf([(action,f.target,f.repo)])
            self.assertEqual(f.plan().reason,"unsupported-dnf-transaction")

    def test_dnf_format_groups_and_extra_fields_rejected(self):
        for change in (lambda v:v.update(version="2.0"),lambda v:v.update(groups=[{}]),lambda v:v.update(extra=True)):
            f=Fixture("rocky");value=json.loads(f.simulation);change(value);f.simulation=raw(value)
            self.assertEqual(f.plan().status,"unavailable")

    def test_essential_or_running_kernel_removal_blocked(self):
        f=Fixture();f.abi["essential"]=True;f.inventory["packages"]=f.installed
        f.before=raw(f.inventory);f.after=raw(dict(f.inventory,capturedAt=moment(15)));f.parsed=R.parse_inventory(f.before,NOW)
        f.scan_context=replace(f.scan_context,inventory_sha256=f.parsed.identity);f.scan["Results"][0]["Packages"]=[f.scan_package(p) for p in f.installed]
        f.simulation=f.apt([f.target],[f.abi]);self.assertEqual(f.plan().reason,"protected-package-removal")
        f=Fixture();f.simulation=f.apt([f.target],[f.kernel]);self.assertEqual(f.plan().reason,"protected-package-removal")

    def test_kernel_installonly_target_retains_running_kernel_and_requires_reboot(self):
        f=Fixture("rocky");target=pkg("kernel-core","6.12.0-2",f.arch,"kernel")
        f.scan["Results"][0]["Vulnerabilities"].append(f.finding(f.kernel,"CVE-2026-1002","CRITICAL"))
        f.scan_context=replace(f.scan_context,coverage=(("host-os-packages","failed"),("host-running-kernel-vendor-advisories","failed")))
        f.repository["candidates"].append(f.candidate(target,[dict(id="CVE-2026-1002",installedIdentity=identity(f.kernel))]))
        f.requested+=(identity(target),);f.simulation=f.dnf([("Upgrade",f.target,f.repo),("Upgraded",f.zlib,"@System"),("Install",target,f.repo)])
        result=f.plan();self.assertEqual(result.status,"proposed_untested",result.reason);self.assertTrue(result.kernel_reboot_required)
        self.assertFalse(result.tested);self.assertTrue(any(row.action=="add" and row.after.name=="kernel-core" for row in result.changes))

    def test_existing_reboot_need_and_bad_runtime_identity(self):
        f=Fixture();result=f.plan(running_kernel=replace(f.kernel_context,reboot_already_needed=True));self.assertTrue(result.kernel_reboot_required)
        for kernel in (None,replace(f.kernel_context,installed_package_identity="0"*64),replace(f.kernel_context,runtime_source_version="6.12.0-99"),replace(f.kernel_context,reboot_already_needed=1)):
            self.assertEqual(f.plan(running_kernel=kernel).reason,"running-kernel-evidence-unavailable")

    def test_failed_running_kernel_scope_requires_actual_bound_findings(self):
        f=Fixture();ctx=replace(f.scan_context,coverage=(("host-os-packages","failed"),("host-running-kernel-vendor-advisories","failed")))
        self.assertEqual(f.plan(scan_context=ctx).reason,"incomplete-running-kernel-advisories")
        kernel=R.Finding("CVE-2026-1002","HIGH",identity(f.kernel));ctx=replace(ctx,kernel_findings=(kernel,))
        result=f.plan(scan_context=ctx);self.assertEqual(result.status,"blocked_unresolved")
        self.assertEqual(result.unresolved,(kernel,))

    def test_running_kernel_advisories_deduplicate_but_cannot_change_severity(self):
        f=Fixture();f.scan["Results"][0]["Vulnerabilities"].append(f.finding(f.kernel,"CVE-2026-1002","HIGH"))
        ctx=replace(f.scan_context,coverage=(("host-os-packages","failed"),("host-running-kernel-vendor-advisories","failed")),kernel_findings=(R.Finding("CVE-2026-1002","HIGH",identity(f.kernel)),))
        self.assertEqual(len(f.plan(scan_context=ctx).findings),2)
        ctx=replace(ctx,kernel_findings=(R.Finding("CVE-2026-1002","CRITICAL",identity(f.kernel)),))
        self.assertEqual(f.plan(scan_context=ctx).reason,"conflicting-running-kernel-advisory")

    def test_signed_debian_kernel_new_name_exact_built_using_and_reboot(self):
        f=Fixture();f.kernel["source"]="linux-signed-amd64";f.kernel["source_version"]="6.12.0+1"
        f.before=raw(f.inventory);f.after=raw(dict(f.inventory,capturedAt=moment(15)));f.parsed=R.parse_inventory(f.before,NOW)
        f.scan["Results"][0]["Packages"]=[f.scan_package(p) for p in f.installed]
        target=pkg("linux-image-6.12.0-2-amd64","6.12.0-2",f.arch,"linux-signed-amd64");target["source_version"]="6.12.0+2"
        f.repository["candidates"].append(f.candidate(target,[dict(id="CVE-2026-1002",installedIdentity=identity(f.kernel))]))
        f.scan_context=replace(f.scan_context,inventory_sha256=f.parsed.identity,coverage=(("host-os-packages","failed"),("host-running-kernel-vendor-advisories","failed")),kernel_findings=(R.Finding("CVE-2026-1002","HIGH",identity(f.kernel)),))
        f.kernel_context=R.RunningKernel(identity(f.kernel),"6.12.0-1-amd64",f.kernel["version"],False,f.kernel["version"])
        f.requested+=(identity(target),);f.simulation=f.apt([f.target,target],[])
        result=f.plan();self.assertEqual(result.status,"proposed_untested",result.reason);self.assertTrue(result.kernel_reboot_required)
        self.assertEqual(f.plan(running_kernel=replace(f.kernel_context,debian_linux_version=None)).reason,"running-kernel-evidence-unavailable")

    def test_debian_kernel_flavor_cannot_be_substituted(self):
        f=Fixture();target=pkg("linux-image-6.12.0-2-cloud-amd64","6.12.0-2",f.arch,"linux")
        f.repository["candidates"].append(f.candidate(target,[dict(id="CVE-2026-1002",installedIdentity=identity(f.kernel))]))
        self.assertEqual(f.plan().reason,"invalid-vendor-fix-binding")

    def test_host_failed_scope_cannot_silently_become_empty_plan(self):
        f=Fixture();f.scan["Results"][0]["Vulnerabilities"]=[];f.requested=();f.simulation=f.apt([],[])
        self.assertEqual(f.plan().reason,"scan-coverage-finding-mismatch")

    def test_raw_error_fields_and_payloads_not_exported(self):
        f=Fixture();f.scan["Results"][0]["Vulnerabilities"][0].update(Title="secret-canary",PrimaryURL="https://secret:token@invalid")
        result=f.plan();encoded=json.dumps(result.as_dict());self.assertNotIn("secret-canary",encoded);self.assertNotIn("token@",encoded)
        self.assertEqual(len(result.input_evidence_sha256),5)

    def test_output_is_detached_from_mutable_input_documents(self):
        f=Fixture();result=f.plan();before=result.as_dict();f.target["version"]="99-99";f.scan.clear();f.repository.clear()
        self.assertEqual(result.as_dict(),before)

    def test_input_size_duplicate_fields_utf8_and_boolean_versions(self):
        for value in (b"\xff",b'{"a":1,"a":2}',b"{"+b"x"*(4*1024**2)+b"}"):
            f=Fixture();self.assertEqual(f.plan(inventory_before=value).status,"unavailable")
        f=Fixture();f.inventory["schemaVersion"]=True;self.assertEqual(f.plan(inventory_before=raw(f.inventory)).reason,"invalid-installed-inventory")

    def test_unrequested_solver_output_and_unbound_request_denied(self):
        f=Fixture();f.requested=();self.assertEqual(f.plan().reason,"unrequested-maintenance-changes")
        f=Fixture();f.requested=("0"*64,);self.assertEqual(f.plan().reason,"invalid-simulation-request")

    def test_no_process_file_network_or_apply_entry_points(self):
        tree=ast.parse((HERE/"host_remediation.py").read_bytes())
        imports={alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node,(ast.Import,ast.ImportFrom)) for alias in (node.names if isinstance(node,ast.Import) else [])}
        self.assertTrue(imports <= {"hashlib","json","re"})
        functions={node.name for node in tree.body if isinstance(node,ast.FunctionDef)}
        self.assertNotIn("main",functions);self.assertFalse(any(name.startswith(("apply","execute","install","reboot")) for name in functions))


if __name__=="__main__":unittest.main(verbosity=2)
