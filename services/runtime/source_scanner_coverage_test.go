package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const sourceCoverageFixtureManifest = `{"dependencies":{"fixture":"1.0.0"}}`
const sourceCoverageFixtureLock = `{"lockfileVersion":3,"packages":{"":{"dependencies":{"fixture":"1.0.0"}},"node_modules/fixture":{"version":"1.0.0","resolved":"https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz","integrity":"sha512-fixture"}}}`

func sourceCoverageExpectedFixture() sourceScannerCoverage {
	return sourceScannerCoverage{target: "package-lock.json", kind: "npm", packages: map[string]bool{"fixture\x001.0.0": true}}
}

func sourceCoverageReportFixture() map[string]any {
	return map[string]any{"SchemaVersion": 2, "Trivy": map[string]any{"Version": sourceScannerVersion}, "ArtifactName": "/workspace", "ArtifactType": "filesystem", "Results": []any{map[string]any{"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Packages": []any{map[string]any{"Name": "fixture", "Version": "1.0.0"}}}}}
}

func sourceCoverageReportBytes(t *testing.T, report map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSourceScannerCoverageRejectsMissingOrAmbiguousEvidence(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"future_schema":         func(r map[string]any) { r["SchemaVersion"] = 3 },
		"no_version":            func(r map[string]any) { delete(r, "Trivy") },
		"other_private_version": func(r map[string]any) { r["Trivy"] = map[string]any{"Version": "0.76.2"} },
		"wrong_artifact":        func(r map[string]any) { r["ArtifactType"] = "container_image" },
		"wrong_workspace":       func(r map[string]any) { r["ArtifactName"] = "/other" },
		"missing_results":       func(r map[string]any) { delete(r, "Results") },
		"null_results":          func(r map[string]any) { r["Results"] = nil },
		"empty_results":         func(r map[string]any) { r["Results"] = []any{} },
		"null_result":           func(r map[string]any) { r["Results"] = []any{nil} },
		"unknown_root_field":    func(r map[string]any) { r["Errors"] = []any{"partial scan"} },
		"unknown_class":         func(r map[string]any) { r["Results"].([]any)[0].(map[string]any)["Class"] = "custom" },
		"unknown_analyzer":      func(r map[string]any) { r["Results"].([]any)[0].(map[string]any)["Type"] = "other" },
		"wrong_target":          func(r map[string]any) { r["Results"].([]any)[0].(map[string]any)["Target"] = "other/package-lock.json" },
		"missing_inventory":     func(r map[string]any) { delete(r["Results"].([]any)[0].(map[string]any), "Packages") },
		"wrong_package": func(r map[string]any) {
			r["Results"].([]any)[0].(map[string]any)["Packages"] = []any{map[string]any{"Name": "fixture", "Version": "2.0.0"}}
		},
		"finding_alias": func(r map[string]any) { r["Results"].([]any)[0].(map[string]any)["vulnerabilities"] = []any{} },
		"modified_findings": func(r map[string]any) {
			r["Results"].([]any)[0].(map[string]any)["ExperimentalModifiedFindings"] = []any{map[string]any{"Status": "ignored"}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			report := sourceCoverageReportFixture()
			mutate(report)
			if findings, err := sourceScannerFindings(sourceCoverageReportBytes(t, report), sourceCoverageExpectedFixture()); err == nil || findings != nil {
				t.Fatal("incomplete source report became a clean scan")
			}
		})
	}
	valid := string(sourceCoverageReportBytes(t, sourceCoverageReportFixture()))
	for _, changed := range []string{strings.TrimSuffix(valid, "}") + `,"Results":[]}`, strings.TrimSuffix(valid, "}") + `,"results":[]}`} {
		if _, err := sourceScannerFindings([]byte(changed), sourceCoverageExpectedFixture()); err == nil {
			t.Fatal("a duplicate result field erased scanner evidence")
		}
	}
}

func TestSourceScannerCoverageZeroDependenciesAreExplicit(t *testing.T) {
	expected := sourceCoverageExpectedFixture()
	expected.packages = map[string]bool{}
	for _, include := range []bool{false, true} {
		report := sourceCoverageReportFixture()
		delete(report, "Results")
		if include {
			report["Results"] = []any{}
		}
		if findings, err := sourceScannerFindings(sourceCoverageReportBytes(t, report), expected); err != nil || len(findings) != 0 {
			t.Fatal("valid independently established zero dependencies were refused")
		}
		if _, err := sourceScannerFindings(sourceCoverageReportBytes(t, report), sourceCoverageExpectedFixture()); err == nil {
			t.Fatal("report-derived zero dependencies were accepted")
		}
	}
}

func TestSourceScannerCoverageRetainsBlockingFindings(t *testing.T) {
	report := sourceCoverageReportFixture()
	result := report["Results"].([]any)[0].(map[string]any)
	result["Vulnerabilities"] = []any{map[string]any{"VulnerabilityID": "CVE-fixture", "Severity": "UNKNOWN", "PkgName": "fixture", "InstalledVersion": "1.0.0"}}
	report["Results"] = append(report["Results"].([]any),
		map[string]any{"Target": "src/settings.js", "Class": "secret", "Secrets": []any{map[string]any{"RuleID": "synthetic-secret", "Severity": "HIGH", "Title": "Synthetic value"}}},
		map[string]any{"Target": "infra/main.tf", "Class": "config", "Type": "terraform", "MisconfSummary": map[string]any{"Successes": 1, "Failures": 1}, "Misconfigurations": []any{map[string]any{"ID": "AVD-fixture", "Severity": "MEDIUM", "Status": "FAIL"}}})
	findings, err := sourceScannerFindings(sourceCoverageReportBytes(t, report), sourceCoverageExpectedFixture())
	if err != nil || len(findings) != 3 {
		t.Fatalf("findings lost: %v", err)
	}
	for _, finding := range findings {
		if !blockedSeverity(finding.Severity) {
			t.Fatal("unknown or Medium+ evidence no longer blocks")
		}
	}
	result["Vulnerabilities"].([]any)[0].(map[string]any)["Severity"] = "unrecognized"
	if _, err := sourceScannerFindings(sourceCoverageReportBytes(t, report), sourceCoverageExpectedFixture()); err == nil {
		t.Fatal("malformed severity accepted")
	}
}

func TestSourceScannerNpmInventoryIncludesDevAndTransitivePackages(t *testing.T) {
	manifest := []byte(`{"dependencies":{"fixture":"1.0.0"},"devDependencies":{"@scope/dev":"2.0.0"}}`)
	lock := []byte(`{"lockfileVersion":3,"packages":{"":{"dependencies":{"fixture":"1.0.0"},"devDependencies":{"@scope/dev":"2.0.0"}},"node_modules/fixture":{"version":"1.0.0","resolved":"https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz","integrity":"sha512-fixture"},"node_modules/@scope/dev":{"name":"@scope/dev","version":"2.0.0","dev":true,"resolved":"https://registry.npmjs.org/@scope/dev/-/dev-2.0.0.tgz","integrity":"sha512-fixture"},"node_modules/fixture/node_modules/transitive":{"version":"3.0.0","optional":true,"resolved":"https://registry.npmjs.org/transitive/-/transitive-3.0.0.tgz","integrity":"sha512-fixture"}}}`)
	got, err := sourceNpmPackages(manifest, lock)
	want := map[string]bool{"fixture\x001.0.0": true, "@scope/dev\x002.0.0": true, "transitive\x003.0.0": true}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("independent lock inventory is incomplete: %v", err)
	}
	for _, change := range []string{
		strings.Replace(string(lock), `"lockfileVersion":3`, `"lockfileVersion":1`, 1),
		strings.Replace(string(lock), `"version":"3.0.0"`, `"version":"3.0.0","link":true`, 1),
		strings.Replace(string(lock), `"packages":`, `"Packages":`, 1),
		strings.Replace(string(lock), `"name":"@scope/dev"`, `"name":"apparently-clean"`, 1),
		strings.Replace(string(lock), `registry.npmjs.org/transitive/-/transitive-3.0.0.tgz`, `registry.npmjs.org/other/-/other-3.0.0.tgz`, 1),
		strings.Replace(string(lock), `registry.npmjs.org/fixture/-/fixture-1.0.0.tgz`, `registry.npmjs.org/fixture/-/fixture-0.1.0.tgz`, 1),
	} {
		if _, err := sourceNpmPackages(manifest, []byte(change)); err == nil {
			t.Fatal("unsupported lock dialect/link or misleading registry identity admitted")
		}
	}
	if got, err := sourceNpmPackages([]byte(`{}`), []byte(`{"lockfileVersion":3,"packages":{"":{}}}`)); err != nil || len(got) != 0 {
		t.Fatal("valid empty npm lock is not explicitly represented")
	}
}

func TestSourceScannerNpmInventoryAcceptsMaintainedDMSLock(t *testing.T) {
	root := os.Getenv("DOXENTRIQ_DMS_FIXTURE_DIR")
	if root == "" {
		root = filepath.Join("..", "..", "templates", "dms")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name, digest string, size int64) []byte {
		t.Helper()
		b, err := sourceScannerReadFileLimit(root, name, size)
		if err != nil || int64(len(b)) != size || hashBytes(b) != digest {
			t.Fatalf("maintained DMS %s fixture missing or changed: %v", name, err)
		}
		return b
	}
	manifest := read("package.json", "9de12ec3a564b113cc161d58844f6581aac68164c7de233ff51f37f5252b5261", 410)
	lock := read("package-lock.json", "22ff55bb47da40b379c90c595b8c57216a396fa548043658dc50869a80f203e5", 46697)
	got, err := sourceNpmPackages(manifest, lock)
	if err != nil {
		t.Fatalf("maintained DMS lock dialect refused: %v", err)
	}
	keys := make([]string, 0, len(got))
	for key := range got {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// Independently captured from this exact maintained lock, including all
	// 69 development and 53 optional entries, not the scanner's report.
	if len(keys) != 85 || hashBytes([]byte(strings.Join(keys, "\n")+"\n")) != "4c97269a9e63287de238fdc032d00b0fa9a39a08e687fbddcee22ddb53dcca7d" {
		t.Fatal("maintained DMS dependency identities were dropped or relabeled")
	}
	for _, key := range []string{"jose\x006.2.12", "vite\x008.3.4", "@rolldown/binding-linux-x64-gnu\x001.2.13", "lightningcss-linux-x64-gnu\x001.33.0"} {
		if !got[key] {
			t.Fatal("maintained direct/dev/optional/transitive dependency disappeared")
		}
	}
}

func TestSourceCoverageIntendedRuntimeIdentity(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 10001 || os.Geteuid() != 10001 || os.Getgid() != 10001 || os.Getegid() != 10001 {
		t.Skip("requires the separately qualified capability-free UID/GID10001 profile")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if fields[name] != "0000000000000000" {
			t.Fatalf("unexpected %s in intended runtime fixture", name)
		}
	}
	if fields["NoNewPrivs"] != "1" {
		t.Fatal("no-new-privileges missing")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s := &server{data: root, hostRuntime: root,
		runner: func(context.Context, string, ...string) (string, error) {
			t.Fatal("unexpected host runner")
			return "", nil
		},
		imageScannerDocker: func(context.Context, []string, int64) (imageScannerCommandResult, error) {
			t.Fatal("unexpected scanner call")
			return imageScannerCommandResult{}, nil
		},
	}
	before := map[string]os.FileInfo{}
	for _, area := range []string{"sources", "builds"} {
		dir := filepath.Join(root, area, "attempt1")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "app.manifest.json"), []byte(`{"template":"node-api"}`), 0600); err != nil {
			t.Fatal(err)
		}
		sourceScannerFixtureLocks(t, dir, false)
	}
	if err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err == nil {
			before[p] = info
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := ownership(filepath.Join(root, "builds", "attempt1")); err != nil {
		t.Fatalf("self-ownership failed without capabilities: %v", err)
	}
	input := sourceScannerFixtureInput(t, s)
	for _, area := range []string{"builds", "sources"} {
		coverage, err := s.sourceScannerCoverage(filepath.Join(root, area, "attempt1"), input)
		if err != nil || coverage.check() != nil || len(coverage.packages) != 1 {
			t.Fatalf("intended private %s permissions were rejected: %v", area, err)
		}
	}
	for p, original := range before {
		current, err := os.Lstat(p)
		if err != nil || !os.SameFile(original, current) || current.Mode() != original.Mode() || !sourceScannerReadable(current) {
			t.Fatal("intended source/build identity or private permissions changed")
		}
		owner := reflect.Indirect(reflect.ValueOf(current.Sys()))
		if owner.FieldByName("Uid").Uint() != 10001 || owner.FieldByName("Gid").Uint() != 10001 {
			t.Fatal("intended source/build ownership changed")
		}
	}
}

func TestSourceScannerPipInventoryKeepsHashPinnedRequirements(t *testing.T) {
	hash := "--hash=sha256:" + strings.Repeat("a", 64)
	input := "# approved wheel inventory\nExample_Pkg==1.2.3 \\\n    " + hash + " \\\n    " + hash + "\nsecond==2.0 " + hash + "\n"
	got, err := sourcePipPackages([]byte(input))
	if err != nil || !reflect.DeepEqual(got, map[string]bool{"example-pkg\x001.2.3": true, "second\x002.0": true}) {
		t.Fatalf("hashed continuation inventory failed: %v", err)
	}
	for _, bad := range []string{"thing>=1 " + hash, "thing==1", "-r other.lock", "thing==1 " + hash + "; python_version<'3'", "thing==1 " + hash + "\nTHING==1 " + hash, "thing==1 " + hash + " \\\n"} {
		if _, err := sourcePipPackages([]byte(bad)); err == nil {
			t.Fatal("unsupported Python dependency syntax became covered")
		}
	}
	if empty, err := sourcePipPackages([]byte("# No third-party dependencies\n")); err != nil || len(empty) != 0 {
		t.Fatal("explicit empty Python inventory refused")
	}
}

func sourceScannerFixtureLocks(t *testing.T, root string, readable bool) {
	t.Helper()
	for name, text := range map[string]string{"package.json": sourceCoverageFixtureManifest, "package-lock.json": sourceCoverageFixtureLock} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if readable && runtime.GOOS == "linux" {
		// Readable synthetic input without expanding the CHOWN-only test profile.
		// Production originals are never chmodded by coverage code.
		if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			mode := os.FileMode(0644)
			if d.IsDir() {
				mode = 0755
			}
			return os.Chmod(p, mode)
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func sourceScannerFixtureInput(t *testing.T, s *server) sourceScannerInput {
	t.Helper()
	hash, err := sourceDigest(filepath.Join(s.data, "sources", "attempt1"))
	if err != nil {
		t.Fatal(err)
	}
	return sourceScannerInput{"node-api", hash, sourceBindingVersion}
}

func TestSourceScannerCoverageRejectsLockDriftBeforeEffects(t *testing.T) {
	for _, mutation := range []string{"source", "build", "caller_hash", "caller_version", "caller_template", "unreadable", "source_file"} {
		t.Run(mutation, func(t *testing.T) {
			s, scanner, workspace := sourceScannerServerFixture(t)
			input := sourceScannerFixtureInput(t, s)
			switch mutation {
			case "source", "build":
				root := workspace
				if mutation == "source" {
					root = filepath.Join(s.data, "sources", "attempt1")
				}
				if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{}}}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "source_file":
				if err := os.WriteFile(filepath.Join(workspace, "app.manifest.json"), []byte(`{"template":"node-web"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "caller_hash":
				input.SourceHash = strings.Repeat("0", 64)
			case "caller_version":
				input.BindingVersion = 0
			case "caller_template":
				input.Template = "python-api"
			case "unreadable":
				if err := os.Chmod(filepath.Join(workspace, "package.json"), 0000); err != nil {
					t.Fatal(err)
				}
			}
			if findings, feed, err := s.scan(context.Background(), workspace, input); err == nil || findings != nil || feed != "" || len(scanner.calls) != 0 {
				t.Fatal("unbound/unreadable source reached the scanner")
			}
		})
	}
}

func TestSourceScannerCoverageProtectsHistoricalPermissions(t *testing.T) {
	s, scanner, _ := sourceScannerServerFixture(t)
	source := filepath.Join(s.data, "sources", "attempt1")
	before, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	input := sourceScannerFixtureInput(t, s)
	if findings, feed, err := s.scan(context.Background(), source, input); err == nil || findings != nil || feed != "" || len(scanner.calls) != 0 {
		t.Fatal("root-private source was falsely treated as readable by scanner UID10001")
	}
	after, err := os.Stat(source)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("historical permissions or identity were modified")
	}
	for _, field := range []string{"Uid", "Gid"} {
		if reflect.Indirect(reflect.ValueOf(before.Sys())).FieldByName(field).Uint() != reflect.Indirect(reflect.ValueOf(after.Sys())).FieldByName(field).Uint() {
			t.Fatal("historical owner changed")
		}
	}
}

func TestSourceScannerCoverageRejectsDriftAfterScannerCleanup(t *testing.T) {
	s, scanner, workspace := sourceScannerServerFixture(t)
	input := sourceScannerFixtureInput(t, s)
	original := s.imageScannerDocker
	s.imageScannerDocker = func(ctx context.Context, args []string, limit int64) (imageScannerCommandResult, error) {
		result, err := original(ctx, args, limit)
		if args[4] == "rm" {
			if err := os.WriteFile(filepath.Join(workspace, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return result, err
	}
	findings, feed, err := s.scan(context.Background(), workspace, input)
	if err == nil || findings != nil || feed != "" || !scanner.removed || scanner.count("start") != 1 || imageScannerPriorClear(s.data) != nil {
		t.Fatal("post-scan drift escaped or confirmed cleanup was lost")
	}
}

func TestSourceScannerCoverageUnknownLocksAreUnavailable(t *testing.T) {
	s, scanner, workspace := sourceScannerServerFixture(t)
	for _, root := range []string{filepath.Join(s.data, "sources", "attempt1"), workspace} {
		file := filepath.Join(root, "yarn.lock")
		if err := os.WriteFile(file, []byte("# unsupported second dependency authority\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if root == workspace {
			if err := os.Chmod(file, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	input := sourceScannerFixtureInput(t, s)
	if _, _, err := s.scan(context.Background(), workspace, input); err == nil || len(scanner.calls) != 0 {
		t.Fatal("unsupported lock became covered")
	}
}

func TestSourceScannerCoveragePreservesFindingsFromAdditionalKnownTargets(t *testing.T) {
	report := sourceCoverageReportFixture()
	report["Results"] = append(report["Results"].([]any), map[string]any{"Target": "node_modules/example/package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Packages": []any{map[string]any{"Name": "nested", "Version": "2.0.0"}}, "Vulnerabilities": []any{map[string]any{"VulnerabilityID": "CVE-nested", "Severity": "MEDIUM", "PkgName": "nested", "InstalledVersion": "2.0.0"}}})
	findings, err := sourceScannerFindings(sourceCoverageReportBytes(t, report), sourceCoverageExpectedFixture())
	if err != nil || len(findings) != 1 || findings[0].ID != "CVE-nested" || !blockedSeverity(findings[0].Severity) {
		t.Fatal("additional supported result findings disappeared")
	}
	report["Results"] = report["Results"].([]any)[1:]
	if _, err := sourceScannerFindings(sourceCoverageReportBytes(t, report), sourceCoverageExpectedFixture()); err == nil {
		t.Fatal("additional target substituted for authoritative root lock")
	}
}
