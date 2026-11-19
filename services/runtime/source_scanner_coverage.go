package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
)

// This is the reviewed source-report contract, not a claim that a scanner image
// is security eligible. Other versions require their own behavior qualification.
const sourceScannerVersion = "0.75.0"

type sourceScannerInput struct {
	Template, SourceHash string
	BindingVersion       int
}

type sourceScannerCoverage struct {
	source, scanned, sourceHash, template, target, kind string
	locks                                               map[string]string
	packages                                            map[string]bool
}

var sourceNpmName = regexp.MustCompile(`^(?:@[a-z0-9_-]+/)?[a-z0-9._-]+$`)
var sourceNpmPath = regexp.MustCompile(`^node_modules/(?:@[a-z0-9_-]+/)?[a-z0-9._-]+(?:/node_modules/(?:@[a-z0-9_-]+/)?[a-z0-9._-]+)*$`)
var sourceNpmVersion = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?(?:\+[a-zA-Z0-9.-]+)?$`)
var sourcePipRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.!+_-]*)$`)
var sourcePipNameParts = regexp.MustCompile(`[-_.]+`)
var sourcePipHash = regexp.MustCompile(`^--hash=sha256:[a-fA-F0-9]{64}$`)

func sourcePackageKey(name, version, kind string) string {
	if kind == "pip" || kind == "python-pkg" {
		name = sourcePipNameParts.ReplaceAllString(strings.ToLower(name), "-")
	}
	return name + "\x00" + version
}

// Intentionally a finite lock dialect: no workspace links, Git/URL aliases,
// legacy v1 locks, recursive requirements, version ranges or environment markers.
// Unrecognized input is unavailable, never a zero-package inventory.
func sourceNpmPackages(manifest, lock []byte) (map[string]bool, error) {
	pkg, err := imageScannerJSON(manifest)
	if err != nil {
		return nil, imageScannerUnavailable
	}
	l, err := imageScannerJSON(lock)
	if err != nil || (!scannerNumber(l["lockfileVersion"], 2) && !scannerNumber(l["lockfileVersion"], 3)) {
		return nil, imageScannerUnavailable
	}
	entries := scannerMap(l["packages"])
	root := scannerMap(entries[""])
	if entries != nil && len(entries) == 0 {
		root = map[string]any{}
	}
	if entries == nil || root == nil || len(entries) > 10000 {
		return nil, imageScannerUnavailable
	}
	for _, object := range []map[string]any{pkg, root} {
		if sourceScannerCaseAliases(object, "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "workspaces") {
			return nil, imageScannerUnavailable
		}
		for _, field := range []string{"bundledDependencies", "bundleDependencies"} {
			if value, present := object[field]; present && !scannerEmpty(value) {
				return nil, imageScannerUnavailable
			}
		}
		if value, present := object["workspaces"]; present && !scannerEmpty(value) {
			return nil, imageScannerUnavailable
		}
	}
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		a, aok := pkg[field]
		b, bok := root[field]
		if !aok {
			a = map[string]any{}
		}
		if !bok {
			b = map[string]any{}
		}
		if scannerMap(a) == nil || scannerMap(b) == nil || !reflect.DeepEqual(a, b) {
			return nil, imageScannerUnavailable
		}
		for name, value := range scannerMap(a) {
			version, ok := value.(string)
			entry := scannerMap(entries["node_modules/"+name])
			if !ok || !sourceNpmName.MatchString(name) || !sourceNpmVersion.MatchString(version) || entry == nil || entry["version"] != version {
				return nil, imageScannerUnavailable
			}
		}
	}
	packages := map[string]bool{}
	for location, value := range entries {
		if location == "" {
			continue
		}
		entry := scannerMap(value)
		if !sourceNpmPath.MatchString(location) || entry == nil {
			return nil, imageScannerUnavailable
		}
		if link, present := entry["link"]; present && !scannerBool(link, false) {
			return nil, imageScannerUnavailable
		}
		name := strings.Split(location, "node_modules/")
		packageName := name[len(name)-1]
		if declared, present := entry["name"]; present {
			// Trivy prefers an explicit name. Do not let a lock alias relabel a
			// different registry package as an unrelated, apparently clean one.
			if scannerString(declared) != packageName {
				return nil, imageScannerUnavailable
			}
		}
		version := scannerString(entry["version"])
		resolved := "https://registry.npmjs.org/" + packageName + "/-/" + path.Base(packageName) + "-" + version + ".tgz"
		if !sourceNpmName.MatchString(packageName) || !sourceNpmVersion.MatchString(version) ||
			scannerString(entry["resolved"]) != resolved ||
			!strings.HasPrefix(scannerString(entry["integrity"]), "sha512-") {
			return nil, imageScannerUnavailable
		}
		packages[sourcePackageKey(packageName, version, "npm")] = true
	}
	return packages, nil
}

func sourcePipPackages(lock []byte) (map[string]bool, error) {
	if len(lock) > 2<<20 || bytes.IndexByte(lock, 0) >= 0 {
		return nil, imageScannerUnavailable
	}
	packages := map[string]bool{}
	names := map[string]bool{}
	continued := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(lock), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			if continued != "" {
				return nil, imageScannerUnavailable
			}
			continue
		}
		continued += line
		if strings.HasSuffix(continued, "\\") {
			continued = strings.TrimSuffix(continued, "\\") + " "
			continue
		}
		fields := strings.Fields(continued)
		continued = ""
		if len(fields) < 2 || len(fields) > 512 {
			return nil, imageScannerUnavailable
		}
		match := sourcePipRequirement.FindStringSubmatch(fields[0])
		if match == nil {
			return nil, imageScannerUnavailable
		}
		name := sourcePipNameParts.ReplaceAllString(strings.ToLower(match[1]), "-")
		if names[name] || len(names) >= 10000 {
			return nil, imageScannerUnavailable
		}
		names[name] = true
		for _, hash := range fields[1:] {
			if !sourcePipHash.MatchString(hash) {
				return nil, imageScannerUnavailable
			}
		}
		packages[sourcePackageKey(name, match[2], "pip")] = true
	}
	if continued != "" {
		return nil, imageScannerUnavailable
	}
	return packages, nil
}

func sourceScannerReadFile(root, name string) ([]byte, error) {
	return sourceScannerReadFileLimit(root, name, 2<<20)
}

func sourceScannerReadFileLimit(root, name string, limit int64) ([]byte, error) {
	if !sourceScannerTarget(filepath.ToSlash(name)) || withdrawalAncestors(root, filepath.Dir(filepath.Join(root, name)), false) != nil {
		return nil, imageScannerUnavailable
	}
	p := filepath.Join(root, name)
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, imageScannerUnavailable
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, imageScannerUnavailable
	}
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(info, held) || !held.Mode().IsRegular() {
		return nil, imageScannerUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	after, statErr := os.Lstat(p)
	if err != nil || closeErr != nil || statErr != nil || int64(len(b)) > limit || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, imageScannerUnavailable
	}
	return b, nil
}

// Runtime-created snapshots use the same UID/GID10001 as the scanner. A read-only
// bind still cannot make an inaccessible imported/historical snapshot readable;
// refuse that input without changing its ownership or permissions.
func sourceScannerReadable(info os.FileInfo) bool {
	if runtime.GOOS != "linux" || info == nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		return false
	}
	owner := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !owner.IsValid() || owner.Kind() != reflect.Struct {
		return false
	}
	uid, gid := owner.FieldByName("Uid"), owner.FieldByName("Gid")
	if !uid.IsValid() || !gid.IsValid() || !uid.CanUint() || !gid.CanUint() {
		return false
	}
	mode := info.Mode().Perm()
	switch {
	case uid.Uint() == 10001:
		mode >>= 6
	case gid.Uint() == 10001:
		mode >>= 3
	}
	required := os.FileMode(4)
	if info.IsDir() {
		required = 5
	}
	return mode&required == required
}

func sourceScannerReadability(root string) error {
	count, total := 0, int64(0)
	return filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return imageScannerUnavailable
		}
		count++
		if count > 100000 {
			return imageScannerUnavailable
		}
		info, err := os.Lstat(p)
		if err != nil {
			return imageScannerUnavailable
		}
		if info.Mode()&os.ModeSymlink != 0 {
			actual, err := filepath.EvalSymlinks(p)
			if err != nil {
				return imageScannerUnavailable
			}
			rel, err := filepath.Rel(root, actual)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				return imageScannerUnavailable
			}
			info, err = os.Stat(actual)
			if err != nil || !info.Mode().IsRegular() {
				return imageScannerUnavailable
			}
		}
		if !sourceScannerReadable(info) {
			return imageScannerUnavailable
		}
		if info.Mode().IsRegular() {
			total += info.Size()
			if total > 512<<20 {
				return imageScannerUnavailable
			}
		}
		return nil
	})
}

func (s *server) sourceScannerCoverage(hostBuild string, input sourceScannerInput) (sourceScannerCoverage, error) {
	c := sourceScannerCoverage{locks: map[string]string{}}
	if input.BindingVersion != sourceBindingVersion || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(input.SourceHash) || !sourceScannerWorkspace(s.hostRuntime, hostBuild) || !filepath.IsAbs(s.data) || filepath.Clean(s.data) != s.data {
		return c, imageScannerUnavailable
	}
	attempt := filepath.Base(hostBuild)
	c.source = filepath.Join(s.data, "sources", attempt)
	c.scanned = filepath.Join(s.data, filepath.Base(filepath.Dir(hostBuild)), attempt)
	var err error
	c.sourceHash, err = sourceDigest(c.source)
	if err != nil || c.sourceHash != input.SourceHash {
		return c, imageScannerUnavailable
	}
	manifest, err := sourceScannerReadFile(c.source, "app.manifest.json")
	if err != nil {
		return c, err
	}
	m, err := imageScannerJSON(manifest)
	if err != nil {
		return c, err
	}
	c.template = scannerString(m["template"])
	if c.template != input.Template {
		return c, imageScannerUnavailable
	}
	switch c.template {
	case "node-web", "node-api", "node-worker", "node-mcp":
		c.target, c.kind = "package-lock.json", "npm"
		pkg, e := sourceScannerReadFile(c.source, "package.json")
		lock, e2 := sourceScannerReadFile(c.source, c.target)
		if e != nil || e2 != nil {
			return c, imageScannerUnavailable
		}
		c.packages, err = sourceNpmPackages(pkg, lock)
		c.locks["package.json"] = hashBytes(pkg)
		c.locks[c.target] = hashBytes(lock)
	case "python-api":
		c.target, c.kind = "requirements.lock", "pip"
		lock, e := sourceScannerReadFile(c.source, c.target)
		if e != nil {
			return c, imageScannerUnavailable
		}
		c.packages, err = sourcePipPackages(lock)
		c.locks[c.target] = hashBytes(lock)
	default:
		return c, imageScannerUnavailable
	}
	if err != nil || sourceScannerLockScope(c.source, c.target, c.kind) != nil || c.check() != nil {
		return c, imageScannerUnavailable
	}
	return c, nil
}

func (c sourceScannerCoverage) check() error {
	digest, err := sourceDigest(c.source)
	if err != nil || digest != c.sourceHash || len(c.locks) == 0 || c.packages == nil {
		return imageScannerUnavailable
	}
	if sourceScannerReadability(c.scanned) != nil || sourceScannerOriginalFilesMatch(c.source, c.scanned) != nil {
		return imageScannerUnavailable
	}
	for name, expected := range c.locks {
		for _, root := range []string{c.source, c.scanned} {
			b, err := sourceScannerReadFile(root, name)
			if err != nil || hashBytes(b) != expected {
				return imageScannerUnavailable
			}
		}
	}
	return nil
}

func sourceScannerTarget(value any) bool {
	s, ok := value.(string)
	return ok && scannerText(s, 8192, false) && !strings.Contains(s, "\\") && !path.IsAbs(s) && path.Clean(s) == s && s != "." && s != ".." && !strings.HasPrefix(s, "../")
}

func sourceScannerSeverity(value any) bool {
	s, ok := value.(string)
	return ok && (s == "UNKNOWN" || s == "LOW" || s == "MEDIUM" || s == "HIGH" || s == "CRITICAL")
}

func sourceScannerFindings(out []byte, expected sourceScannerCoverage) ([]Finding, error) {
	report, err := imageScannerJSON(out)
	if err != nil || !scannerNumber(report["SchemaVersion"], 2) || report["ArtifactType"] != "filesystem" || report["ArtifactName"] != "/workspace" || scannerMap(report["Trivy"])["Version"] != sourceScannerVersion || expected.packages == nil || expected.target == "" || (expected.kind != "npm" && expected.kind != "pip") {
		return nil, imageScannerUnavailable
	}
	if !sourceScannerFields(report, "SchemaVersion", "Trivy", "ReportID", "CreatedAt", "ArtifactID", "ArtifactName", "ArtifactType", "Metadata", "Results") {
		return nil, imageScannerUnavailable
	}
	var results []any
	if value, present := report["Results"]; present {
		var ok bool
		results, ok = value.([]any)
		if !ok || len(results) > 4096 {
			return nil, imageScannerUnavailable
		}
	}
	covered := len(expected.packages) == 0
	seen := map[string]bool{}
	findings := []Finding{}
	packageCount := 0
	for _, value := range results {
		result := scannerMap(value)
		class, kind, target := scannerString(result["Class"]), scannerString(result["Type"]), scannerString(result["Target"])
		if result == nil || !scannerText(result["Target"], 8192, false) || seen[class+"\x00"+kind+"\x00"+target] {
			return nil, imageScannerUnavailable
		}
		seen[class+"\x00"+kind+"\x00"+target] = true
		if !sourceScannerFields(result, "Target", "Class", "Type", "Packages", "Vulnerabilities", "MisconfSummary", "Misconfigurations", "Secrets", "Licenses", "CryptoAssets", "CustomResources", "ExperimentalModifiedFindings") {
			return nil, imageScannerUnavailable
		}
		for _, unsupported := range []string{"ExperimentalModifiedFindings", "Licenses", "CryptoAssets", "CustomResources"} {
			if value, present := result[unsupported]; present && !scannerEmpty(value) {
				return nil, imageScannerUnavailable
			}
		}
		switch class {
		case "lang-pkgs":
			if kind != "npm" && kind != "pip" && kind != "node-pkg" && kind != "python-pkg" {
				return nil, imageScannerUnavailable
			}
			if (kind == "npm" || kind == "pip") && !sourceScannerTarget(result["Target"]) {
				return nil, imageScannerUnavailable
			}
			pkgs, ok := result["Packages"].([]any)
			if !ok || len(pkgs) == 0 {
				return nil, imageScannerUnavailable
			}
			packageCount += len(pkgs)
			if packageCount > 50000 {
				return nil, imageScannerUnavailable
			}
			actual := map[string]bool{}
			for _, value := range pkgs {
				pkg := scannerMap(value)
				if !scannerText(pkg["Name"], 1024, false) || !scannerText(pkg["Version"], 4096, false) {
					return nil, imageScannerUnavailable
				}
				key := sourcePackageKey(scannerString(pkg["Name"]), scannerString(pkg["Version"]), kind)
				actual[key] = true
			}
			if target == expected.target {
				if kind != expected.kind || !reflect.DeepEqual(actual, expected.packages) {
					return nil, imageScannerUnavailable
				}
				covered = true
			}
			if _, present := result["Misconfigurations"]; present {
				return nil, imageScannerUnavailable
			}
			if _, present := result["Secrets"]; present {
				return nil, imageScannerUnavailable
			}
		case "config":
			if !sourceScannerTarget(result["Target"]) {
				return nil, imageScannerUnavailable
			}
			switch kind {
			case "dockerfile", "terraform", "terraformplan", "cloudformation", "kubernetes", "helm", "azure-arm", "ansible":
			default:
				return nil, imageScannerUnavailable
			}
			if _, present := result["Vulnerabilities"]; present {
				return nil, imageScannerUnavailable
			}
			if _, present := result["Secrets"]; present {
				return nil, imageScannerUnavailable
			}
			summary := scannerMap(result["MisconfSummary"])
			failures, ok := result["Misconfigurations"].([]any)
			if !ok {
				if _, present := result["Misconfigurations"]; present {
					return nil, imageScannerUnavailable
				}
			}
			if summary == nil || !scannerNumber(summary["Failures"], int64(len(failures))) || !sourceScannerNonnegative(summary["Successes"]) || (len(failures) == 0 && scannerNumber(summary["Successes"], 0)) {
				return nil, imageScannerUnavailable
			}
		case "secret":
			if _, present := result["Type"]; present {
				return nil, imageScannerUnavailable
			}
			if !sourceScannerTarget(result["Target"]) {
				return nil, imageScannerUnavailable
			}
			if _, present := result["Vulnerabilities"]; present {
				return nil, imageScannerUnavailable
			}
			if _, present := result["Misconfigurations"]; present {
				return nil, imageScannerUnavailable
			}
			if secrets, ok := result["Secrets"].([]any); !ok || len(secrets) == 0 {
				return nil, imageScannerUnavailable
			}
		default:
			return nil, imageScannerUnavailable
		}
		for _, field := range []string{"Vulnerabilities", "Misconfigurations", "Secrets"} {
			value, present := result[field]
			if !present {
				continue
			}
			list, ok := value.([]any)
			if !ok || len(list)+len(findings) > 50000 {
				return nil, imageScannerUnavailable
			}
			for _, value := range list {
				f := scannerMap(value)
				if sourceScannerCaseAliases(f, "VulnerabilityID", "RuleID", "ID", "Severity", "Status", "PkgName", "InstalledVersion", "FixedVersion", "Title") {
					return nil, imageScannerUnavailable
				}
				id, source := "VulnerabilityID", "trivy"
				if field == "Misconfigurations" {
					id, source = "ID", "trivy-config"
					if f["Status"] != "FAIL" {
						return nil, imageScannerUnavailable
					}
				} else if field == "Secrets" {
					id, source = "RuleID", "trivy-secret"
				}
				if !scannerText(f[id], 1024, false) || !sourceScannerSeverity(f["Severity"]) {
					return nil, imageScannerUnavailable
				}
				for _, optional := range []string{"Title", "FixedVersion"} {
					if text, exists := f[optional]; exists && !scannerText(text, 8192, true) {
						return nil, imageScannerUnavailable
					}
				}
				if field == "Vulnerabilities" && (!scannerText(f["PkgName"], 1024, false) || !scannerText(f["InstalledVersion"], 4096, false)) {
					return nil, imageScannerUnavailable
				}
				findings = append(findings, Finding{scannerString(f[id]), scannerString(f["Severity"]), scannerString(f["PkgName"]), scannerString(f["InstalledVersion"]), scannerString(f["FixedVersion"]), source, scannerString(f["Title"])})
			}
		}
	}
	if !covered {
		return nil, imageScannerUnavailable
	}
	return findings, nil
}

func sourceScannerFields(value map[string]any, keys ...string) bool {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func sourceScannerCaseAliases(value map[string]any, keys ...string) bool {
	for key := range value {
		for _, expected := range keys {
			if key != expected && strings.EqualFold(key, expected) {
				return true
			}
		}
	}
	return false
}

func sourceScannerNonnegative(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	n, err := number.Int64()
	return err == nil && n >= 0 && n <= 50000 && scannerNumber(value, n)
}

// The first contract supports one root dependency manifest. Extra lock dialects
// must not disappear into an apparently empty or partial source report.
func sourceScannerLockScope(root, target, kind string) error {
	names := map[string]bool{"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "bun.lock": true, "requirements.lock": true, "requirements.txt": true, "uv.lock": true, "poetry.lock": true, "Pipfile.lock": true, "pylock.toml": true, "pyproject.toml": true, "setup.py": true, "setup.cfg": true, "Cargo.lock": true, "go.mod": true, "composer.lock": true, "Gemfile.lock": true}
	count := 0
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		count++
		if count > 1200 {
			return imageScannerUnavailable
		}
		if e != nil {
			return imageScannerUnavailable
		}
		if d.IsDir() || !names[d.Name()] {
			return nil
		}
		rel, e := filepath.Rel(root, p)
		if e != nil || (rel != target && !(kind == "npm" && rel == "package.json")) {
			return imageScannerUnavailable
		}
		return nil
	})
}

// Build commands may add outputs, but may not hide or replace the original
// source that the receipt will commit and daily scanning will later revisit.
func sourceScannerOriginalFilesMatch(source, scanned string) error {
	count, total := 0, int64(0)
	return filepath.WalkDir(source, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return imageScannerUnavailable
		}
		if d.IsDir() {
			return nil
		}
		count++
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() || count > 600 {
			return imageScannerUnavailable
		}
		total += info.Size()
		if total > 20<<20 {
			return imageScannerUnavailable
		}
		rel, e := filepath.Rel(source, p)
		if e != nil {
			return imageScannerUnavailable
		}
		before, e := sourceScannerReadFileLimit(source, rel, 20<<20)
		actual, e2 := sourceScannerReadFileLimit(scanned, rel, 20<<20)
		if e != nil || e2 != nil || !bytes.Equal(before, actual) {
			return imageScannerUnavailable
		}
		return nil
	})
}
