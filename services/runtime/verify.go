package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func validatePipeline(p Pipeline, m RuntimeManifest) error {
	if p.Version != 1 {
		return errors.New("Unsupported pipeline version")
	}
	if _, ok := m.Templates[p.Template]; !ok {
		return errors.New("A company-maintained template is required")
	}
	if len(p.Stages) != len(mandatoryStages) {
		return errors.New("Every mandatory stage must be present")
	}
	counts := map[string]int{}
	for _, stage := range p.Stages {
		if stage.Name != "build" && stage.Name != "application_tests" && stage.Name != "acceptance" && len(stage.Commands) != 0 {
			return fmt.Errorf("%s is company-managed and cannot contain ignored custom commands", stage.Name)
		}
		if stage.Timeout < 1 || stage.Timeout > 1800 || len(stage.Commands) > 16 {
			return errors.New("Stage exceeds execution limits")
		}
		for _, command := range stage.Commands {
			if len(command) == 0 || len(command) > 4096 || strings.IndexByte(command, 0) >= 0 {
				return errors.New("Invalid sandbox command")
			}
		}
		counts[stage.Name]++
	}
	for _, name := range mandatoryStages {
		if counts[name] != 1 {
			return fmt.Errorf("Missing or duplicated %s stage", name)
		}
	}
	return nil
}
func validateApp(m AppManifest, appID string, template string) error {
	if m.Version != 1 || m.ID != appID || m.Template != template || !regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`).MatchString(m.Slug) || strings.HasPrefix(m.Slug, "preview-") {
		return errors.New("Invalid application identity or template")
	}
	for _, slug := range []string{"admin", "auth", "api", "registry", "metrics", "preview"} {
		if m.Slug == slug {
			return errors.New("Reserved application hostname")
		}
	}
	if m.Resources.CPU < .1 || m.Resources.CPU > 4 || m.Resources.Memory < 64 || m.Resources.Memory > 8192 || m.Resources.Pids < 16 || m.Resources.Pids > 512 || m.Health.Port != 8080 || !regexp.MustCompile(`^/[a-zA-Z0-9/_-]*$`).MatchString(m.Health.Path) {
		return errors.New("Invalid resource or health policy")
	}
	if m.Auth != "public" && m.Auth != "sso" && m.Auth != "local" {
		return errors.New("An explicit access policy is required")
	}
	if (m.Kind == "mcp" || m.Template == "node-mcp") && m.Auth == "public" {
		return errors.New("Hosted MCP servers require authenticated access")
	}
	if len(m.Storage) > 1 {
		return errors.New("Current template supports one quota-controlled storage volume")
	}
	for _, storage := range m.Storage {
		if !identity.MatchString(storage.Name) || storage.MaxMB < 1 || storage.MaxMB > 32768 {
			return errors.New("Invalid storage quota")
		}
	}
	return nil
}
func copyTree(src, dst string, maxBytes int64, maxFiles int) (string, error) {
	type entry struct {
		Path string `json:"path"`
		Hash string `json:"hash"`
	}
	items := []entry{}
	var size int64
	count := 0
	e := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(src, p)
		if e != nil {
			return e
		}
		if rel == "." {
			return os.MkdirAll(dst, 0700)
		}
		if strings.Contains(rel, "\\") && filepath.Separator != '\\' {
			return errors.New("Backslash filenames are forbidden")
		}
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if part == ".git" || part == ".env" || strings.HasPrefix(part, ".env.") || part == ".npmrc" || part == ".agents" || part == ".codex" || part == "Dockerfile" {
				return errors.New("Protected infrastructure files are forbidden")
			}
		}
		if maxFiles > 1000 && d.IsDir() && (d.Name() == ".cache" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			if maxFiles <= 1000 {
				return errors.New("Symbolic links are forbidden")
			}
			actual, e := filepath.EvalSymlinks(p)
			if e != nil {
				return e
			}
			inside, e := filepath.Rel(src, actual)
			if e != nil || strings.HasPrefix(inside, "..") || filepath.IsAbs(inside) {
				return errors.New("Artifact link escapes its authorized root")
			}
			info, e := os.Stat(actual)
			if e != nil || !info.Mode().IsRegular() {
				return errors.New("Only internal links to regular package files are permitted")
			}
			size += info.Size()
			count++
			if size > maxBytes || count > maxFiles {
				return errors.New("Artifact size limit exceeded")
			}
			b, e := os.ReadFile(actual)
			if e != nil {
				return e
			}
			items = append(items, entry{filepath.ToSlash(rel), hashBytes(b)})
			return os.WriteFile(filepath.Join(dst, rel), b, 0600)
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("Only regular source files are accepted")
		}
		size += info.Size()
		count++
		if size > maxBytes || count > maxFiles {
			return errors.New("Source or artifact size limit exceeded")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		items = append(items, entry{filepath.ToSlash(rel), hashBytes(b)})
		return os.WriteFile(target, b, 0600)
	})
	if e != nil {
		return "", e
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	b, _ := json.Marshal(items)
	return hashBytes(b), nil
}
func (s *server) sandbox(ctx context.Context, name, hostDir string, t Template, command []string, dependency bool, readOnlyWorkspace ...bool) (string, error) {
	if !identity.MatchString(name) || !filepath.IsAbs(hostDir) {
		return "", errors.New("Invalid sandbox mount")
	}
	network := "none"
	if dependency {
		network = env("DEPENDENCY_NETWORK", "autosoft_dependency")
	}
	workspaceMount := "type=bind,src=" + hostDir + ",dst=/workspace"
	cache := "/workspace/.cache/npm"
	if len(readOnlyWorkspace) > 0 && readOnlyWorkspace[0] {
		workspaceMount += ",readonly"
		cache = "/tmp/npm-cache"
	}
	args := []string{"run", "--rm", "--name", name, "--label", "io.autosoft.build=true", "--runtime", env("RUNSC_RUNTIME", "runsc"), "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "1g", "--cpus", "2", "--network", network, "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777", "--mount", workspaceMount, "--workdir", "/workspace", "--env", "HOME=/tmp", "--env", "npm_config_cache=" + cache, "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONPATH=/workspace/vendor", "--env", "npm_config_ignore_scripts=true"}
	if dependency {
		proxy := env("DEPENDENCY_PROXY_URL", s.manifest.DependencyProxy)
		if proxy == "" {
			return "", errors.New("Restricted dependency proxy is required")
		}
		hosts, err := s.trustedServiceHosts(ctx, network, []string{"dependency-proxy"})
		if err != nil {
			return "", err
		}
		args = append(args, hosts...)
		args = append(args, "--env", "HTTPS_PROXY="+proxy, "--env", "HTTP_PROXY="+proxy, "--env", "https_proxy="+proxy, "--env", "http_proxy="+proxy)
	}
	args = append(args, t.ToolchainImage)
	args = append(args, command...)
	out, e := s.runner(ctx, "docker", args...)
	if ctx.Err() != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = s.runner(cleanup, "docker", "rm", "-f", name)
	}
	return out, e
}
func ownership(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if e = os.Chmod(p, func() fs.FileMode {
			if d.IsDir() {
				return 0700
			}
			return 0600
		}()); e != nil {
			return e
		}
		return os.Chown(p, 10001, 10001)
	})
}
func dependencyCommand(root, template string) ([]string, error) {
	if template == "python-api" {
		b, e := os.ReadFile(filepath.Join(root, "requirements.lock"))
		if e != nil {
			return nil, errors.New("Python requires a hash-pinned requirements.lock")
		}
		if !strings.Contains(string(b), "--hash=sha256:") || strings.Contains(string(b), "git+") || strings.Contains(string(b), "--extra-index") {
			return nil, errors.New("Python dependencies must use approved hashed wheels")
		}
		return []string{"python", "-m", "pip", "install", "--require-hashes", "--only-binary=:all:", "--no-deps", "--target", "/workspace/vendor", "-r", "requirements.lock"}, nil
	}
	b, e := os.ReadFile(filepath.Join(root, "package.json"))
	if e != nil {
		return nil, e
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if e = json.Unmarshal(b, &pkg); e != nil {
		return nil, e
	}
	exact := regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$`)
	for _, set := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, version := range set {
			if !regexp.MustCompile(`^(?:@[a-z0-9_-]+/)?[a-z0-9._-]+$`).MatchString(name) || !exact.MatchString(version) {
				return nil, errors.New("Dependencies require exact registry package versions")
			}
		}
	}
	if lock, e := os.ReadFile(filepath.Join(root, "package-lock.json")); e == nil {
		var manifest struct {
			Packages map[string]struct {
				Resolved  string `json:"resolved"`
				Integrity string `json:"integrity"`
				Link      bool   `json:"link"`
			} `json:"packages"`
		}
		if e = json.Unmarshal(lock, &manifest); e != nil {
			return nil, e
		}
		for path, p := range manifest.Packages {
			if path == "" {
				continue
			}
			if p.Link || !strings.HasPrefix(p.Resolved, "https://registry.npmjs.org/") || !strings.HasPrefix(p.Integrity, "sha512-") {
				return nil, errors.New("Lockfile contains an unapproved source or missing integrity")
			}
		}
		return []string{"npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org"}, nil
	}
	return []string{"npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", "--registry=https://registry.npmjs.org"}, nil
}
func (s *server) commitSource(ctx context.Context, appID, source string) (string, error) {
	unlock := s.lock("repository")
	defer unlock()
	repo := env("REPOSITORY_ROOT", filepath.Join(s.data, "repository"))
	if e := os.MkdirAll(repo, 0700); e != nil {
		return "", e
	}
	if _, e := os.Stat(filepath.Join(repo, ".git")); os.IsNotExist(e) {
		if _, e = s.runner(ctx, "git", "-c", "core.hooksPath=/dev/null", "init", repo); e != nil {
			return "", e
		}
	}
	dst := filepath.Join(repo, "apps", appID)
	if _, e := os.Stat(dst); e == nil {
		archive := dst + ".previous-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if e = os.Rename(dst, archive); e != nil {
			return "", e
		}
	}
	if _, e := copyTree(source, dst, 20<<20, 600); e != nil {
		return "", e
	}
	args := []string{"-C", repo, "-c", "core.hooksPath=/dev/null", "-c", "user.name=AutoSoft", "-c", "user.email=platform@localhost"}
	if _, e := s.runner(ctx, "git", append(args, "add", "--", "apps/"+appID)...); e != nil {
		return "", e
	}
	if _, e := s.runner(ctx, "git", append(args, "commit", "--allow-empty", "-m", "Verified candidate for "+appID)...); e != nil {
		return "", e
	}
	v, e := s.runner(ctx, "git", append(args, "rev-parse", "HEAD")...)
	return strings.TrimSpace(v), e
}
func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	var in verificationInput
	if !decode(w, r, &in) {
		return
	}
	if e := validatePipeline(in.Pipeline, s.manifest); e != nil {
		fail(w, 400, e)
		return
	}
	workspace, e := safePath(s.workspace, in.AppID, in.JobID, in.AttemptID)
	if e != nil {
		fail(w, 400, e)
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	inputHash, e := verificationSourceInput(workspace, in)
	if e != nil {
		fail(w, 409, e)
		return
	}
	if e = s.acceptFence(in.AppID, in.JobID, in.AttemptID, in.Fence); e != nil {
		fail(w, 409, e)
		return
	}
	receipt := filepath.Join(s.data, "receipts", in.AttemptID+".json")
	if b, e := os.ReadFile(receipt); e == nil {
		var v Verification
		if json.Unmarshal(b, &v) == nil && verificationReplayBinding(v, in, inputHash, filepath.Join(s.data, "sources", in.AttemptID)) && s.snapshotContext(v.MigrationSnapshot.Binding) == nil {
			retained, re := s.readSnapshot(v.MigrationSnapshot.Binding)
			if re != nil || !reflect.DeepEqual(retained.Receipt, *v.MigrationSnapshot) || s.verifySnapshotStream(r.Context(), retained) != nil || s.retainSnapshot(retained) != nil || r.Context().Err() != nil {
				fail(w, 409, snapshotUnavailable)
				return
			}
			respond(w, v)
			return
		}
		fail(w, 409, errors.New("Verification identity was already used"))
		return
	} else if !os.IsNotExist(e) {
		fail(w, 409, errors.New("Previous verification outcome is unavailable; preserve it for company reconciliation"))
		return
	}
	select {
	case s.buildSlot <- struct{}{}:
		defer func() { <-s.buildSlot }()
	case <-r.Context().Done():
		return
	}
	// The trusted snapshot is immutable; generated stages only receive the distinct build workspace.
	source := filepath.Join(s.data, "sources", in.AttemptID)
	build := filepath.Join(s.data, "builds", in.AttemptID)
	sourceHash, buildOwned, e := createVerificationSnapshots(workspace, source, build, in)
	if buildOwned {
		defer os.RemoveAll(build)
	}
	if e != nil {
		fail(w, 400, e)
		return
	}
	var manifest AppManifest
	b, e := os.ReadFile(filepath.Join(source, "app.manifest.json"))
	if e != nil || json.Unmarshal(b, &manifest) != nil {
		fail(w, 400, errors.New("Validated app.manifest.json is required"))
		return
	}
	if e = validateApp(manifest, in.AppID, in.Pipeline.Template); e != nil {
		fail(w, 400, e)
		return
	}
	if e = s.validateConnectorRefs(manifest); e != nil {
		fail(w, 409, e)
		return
	}
	t := s.manifest.Templates[in.Pipeline.Template]
	v := Verification{Evidence: Evidence{Status: "failed", CheckedAt: time.Now().UTC().Format(time.RFC3339), FeedUpdatedAt: "", Findings: []Finding{}, Checks: []Check{}}, Images: []string{}, Migrations: []Migration{}, AppID: in.AppID, AttemptID: in.AttemptID, FilesHash: in.FilesHash, InputSourceHash: sourceHash, SourceBindingVersion: sourceBindingVersion, PipelineHash: pipelineDefinitionHash(in.Pipeline), SourceHash: sourceHash, Template: in.Pipeline.Template, Schema: 1, SchemaMin: 1, SchemaMax: 1}
	if feed, e := cachedFeed(); e == nil {
		v.Evidence.FeedUpdatedAt = feed
	}
	hostBuild := filepath.Join(s.hostRuntime, "builds", in.AttemptID)
	abort := func(stage string, e error) {
		v.Evidence.Checks = append(v.Evidence.Checks, Check{stage, false, e.Error()})
		_ = atomicJSON(receipt, v)
		respond(w, v)
	}
	if e = ownership(build); e != nil {
		abort("dependencies", e)
		return
	}
	command, e := dependencyCommand(build, in.Pipeline.Template)
	if e != nil {
		abort("dependencies", e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	_, e = s.sandbox(ctx, "as-deps-"+in.AttemptID, hostBuild, t, command, true)
	cancel()
	if e != nil {
		abort("dependencies", errors.New("Locked dependency acquisition failed inside sandbox"))
		return
	}
	v.Evidence.Checks = append(v.Evidence.Checks, Check{"dependencies", true, "Approved registry packages acquired with lifecycle scripts disabled"})
	if in.Pipeline.Template != "python-api" {
		b, e := os.ReadFile(filepath.Join(build, "package-lock.json"))
		if e != nil {
			abort("dependencies", errors.New("Trusted dependency acquisition did not produce a lockfile"))
			return
		}
		if _, e = dependencyCommand(build, in.Pipeline.Template); e != nil {
			abort("dependencies", e)
			return
		}
		if e = os.WriteFile(filepath.Join(source, "package-lock.json"), b, 0600); e != nil {
			abort("dependencies", e)
			return
		}
	}
	for _, name := range []string{"build", "application_tests"} {
		stageDetail := "Offline gVisor stage completed within enforced limits"
		var stage Stage
		for _, p := range in.Pipeline.Stages {
			if p.Name == name {
				stage = p
			}
		}
		if name == "build" && len(stage.Commands) == 0 {
			abort(name, errors.New("Application build command is required"))
			return
		}
		for _, command := range stage.Commands {
			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(stage.Timeout)*time.Second)
			output, stageError := s.sandbox(ctx, "as-stage-"+in.AttemptID, hostBuild, t, []string{"/bin/sh", "-lc", command}, false)
			cancel()
			if stageError != nil {
				abort(name, fmt.Errorf("Custom %s command failed in the isolated sandbox: %s", name, diagnosticOutput(output)))
				return
			}
		}
		if name == "application_tests" {
			files := []string{}
			_ = filepath.WalkDir(build, func(p string, d fs.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "vendor" || d.Name() == ".cache") {
					return filepath.SkipDir
				}
				if !d.IsDir() && ((in.Pipeline.Template == "python-api" && strings.HasSuffix(p, "_test.py")) || (in.Pipeline.Template != "python-api" && (strings.HasSuffix(p, ".test.mjs") || strings.HasSuffix(p, ".test.js")))) {
					rel, _ := filepath.Rel(build, p)
					files = append(files, filepath.ToSlash(rel))
				}
				return nil
			})
			if len(files) == 0 {
				abort(name, errors.New("Executable independent test files are required"))
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
			command := append([]string{"node", "--test", "--test-reporter=tap"}, files...)
			if in.Pipeline.Template == "python-api" {
				command = []string{"python", "-m", "unittest", "discover", "-s", ".", "-p", "*_test.py", "-v"}
			}
			out, e := s.sandbox(ctx, "as-tests-"+in.AttemptID, hostBuild, t, command, false)
			cancel()
			confirmed := regexp.MustCompile(`(?m)^# tests [1-9][0-9]*$`).MatchString(out) && strings.Contains(out, "# fail 0")
			if in.Pipeline.Template == "python-api" {
				confirmed = regexp.MustCompile(`(?m)^Ran [1-9][0-9]* tests? in `).MatchString(out) && regexp.MustCompile(`(?m)^OK\s*$`).MatchString(out)
			}
			if e != nil || !confirmed {
				abort(name, fmt.Errorf("Mandatory test runner did not confirm successful executed tests: %s", diagnosticOutput(out)))
				return
			}
			countPattern := regexp.MustCompile(`(?m)^# tests ([1-9][0-9]*)$`)
			if in.Pipeline.Template == "python-api" {
				countPattern = regexp.MustCompile(`(?m)^Ran ([1-9][0-9]*) tests? in `)
			}
			count := countPattern.FindStringSubmatch(out)
			stageDetail = "Mandatory independent runner confirmed " + count[1] + " executed tests with no failures; custom test commands also passed offline"
		}
		v.Evidence.Checks = append(v.Evidence.Checks, Check{name, true, stageDetail})
	}
	findings, feed, e := s.scan(r.Context(), hostBuild)
	v.Evidence.Findings = findings
	if feed != "" {
		v.Evidence.FeedUpdatedAt = feed
	}
	if e != nil {
		abort("security", e)
		return
	}
	for _, f := range findings {
		if blockedSeverity(f.Severity) {
			abort("security", errors.New("Medium-or-higher or unclassified security finding blocks release"))
			return
		}
	}
	if e = staticPolicy(build); e != nil {
		abort("security", e)
		return
	}
	v.Evidence.Checks = append(v.Evidence.Checks, Check{"security", true, "Dependencies, configuration, secrets and high-risk source patterns scanned; fresh advisory database verified"})
	artifact := filepath.Join(s.data, "artifacts", in.AttemptID)
	if _, e = copyTree(build, artifact, 512<<20, 100000); e != nil {
		abort("image_packaging", e)
		return
	}
	image, e := s.requestPackage(r.Context(), in.AppID, in.AttemptID, in.Pipeline.Template)
	if e != nil {
		abort("image_packaging", e)
		return
	}
	v.Images = []string{image}
	imageFindings, e := s.scanImage(r.Context(), image)
	if e != nil {
		abort("image_packaging", e)
		return
	}
	v.Evidence.Findings = append(v.Evidence.Findings, imageFindings...)
	for _, finding := range imageFindings {
		if blockedSeverity(finding.Severity) {
			abort("security", errors.New("Packaged image has a Medium-or-higher or unclassified vulnerability"))
			return
		}
	}
	v.Evidence.Checks = append(v.Evidence.Checks, Check{"image_packaging", true, "Validated files appended to digest-pinned template without executing a Dockerfile"})
	if e = bindFinalVerificationSource(&v, source); e != nil {
		abort("image_packaging", e)
		return
	}
	if v.Commit, e = s.commitSource(r.Context(), in.AppID, source); e != nil {
		abort("image_packaging", e)
		return
	}
	migrations, e := readMigrations(source)
	if e != nil {
		abort("migration_rehearsal", e)
		return
	}
	v.Migrations = migrations
	q := verifiedMigrationRequest(in, v, migrations)
	if in.BaseReleaseID != nil {
		var current activeDeployment
		if readBoundedJSON(filepath.Join(s.data, "active", in.AppID+".json"), &current) != nil || current.ReleaseID != *in.BaseReleaseID {
			v.Evidence.Status = "unavailable"
			abort("migration_rehearsal", snapshotUnavailable)
			return
		}
		q.BaseHash, q.BaseImage = current.Hash, current.Image
	}
	snapshot, captureError := captureVerificationMigration(r.Context(), q, migrations, s.captureMigrationSnapshot)
	v.MigrationSnapshot = &snapshot
	if captureError != nil || snapshot.Status != "captured" && snapshot.Status != "no_previous_release" || len(snapshot.Unapplied) > 0 {
		v.Evidence.Status = "unavailable"
		abort("migration_rehearsal", errors.New("Protected capture does not establish record preservation or previous-release compatibility; existing unapplied migrations are blocked before live DDL"))
		return
	}
	v.Schema, v.SchemaMin, v.SchemaMax = snapshot.SchemaEpoch, snapshot.SchemaEpoch, snapshot.SchemaEpoch
	previewResources, e := s.provision(r.Context(), in.AppID+"_preview", manifest, true)
	if e != nil {
		abort("migration_rehearsal", e)
		return
	}
	if e = s.rehearse(r.Context(), previewResources, migrations); e != nil {
		abort("migration_rehearsal", e)
		return
	}
	v.Evidence.Checks = append(v.Evidence.Checks, Check{"migration_rehearsal", true, "Additive statements applied to an isolated preview database"})
	previewName := "as-preview-" + in.AppID
	previewCandidate := previewName + "-" + hashBytes([]byte(in.AttemptID))[:8]
	previewResources, e = s.stageAppConnectors(r.Context(), manifest, previewResources, true, previewCandidate)
	if e != nil {
		abort("preview", e)
		return
	}
	if e = s.checkRetirableAppConnectors(r.Context(), in.AppID, previewResources.AppID, previewCandidate); e != nil {
		abort("preview", e)
		return
	}
	e = s.startApp(r.Context(), previewName, image, manifest, previewResources, true)
	if e != nil {
		abort("preview", e)
		return
	}
	host := "preview-" + manifest.Slug + "." + s.appsHost()
	if e = s.route(r.Context(), "preview-"+in.AppID, host, previewName, 8080, true); e != nil {
		abort("preview", e)
		return
	}
	if e = s.retireAppConnectors(r.Context(), in.AppID, previewResources.AppID, previewCandidate); e != nil {
		abort("preview", errors.New("Exact previous preview connector retirement requires reconciliation"))
		return
	}
	v.PreviewURL = "https://" + host
	v.Evidence.Checks = append(v.Evidence.Checks, Check{"preview", true, "Isolated preview responds to its health check; MFA required at preview gateway"})
	if e = s.runAcceptance(r.Context(), in.AttemptID, hostBuild, t, in.Pipeline); e != nil {
		abort("acceptance", e)
		return
	}
	v.Evidence.Checks = append(v.Evidence.Checks, Check{"acceptance", true, "Custom acceptance commands executed offline with read-only artifacts; tests, healthy preview, image digest and migration rehearsal are recorded"})
	v.Evidence.Status = "passed"
	v.Evidence.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	if e = atomicJSON(receipt, v); e != nil {
		fail(w, 500, e)
		return
	}
	respond(w, v)
}

func (s *server) scanImage(ctx context.Context, image string) ([]Finding, error) {
	return s.scanImageSafely(ctx, image)
}
func blockedSeverity(s string) bool {
	return s != "LOW"
}
func diagnosticOutput(output string) string {
	if len(output) > 8192 {
		output = output[len(output)-8192:]
	}
	output = regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9._~+/-]+`).ReplaceAllString(output, "Bearer [REDACTED]")
	return regexp.MustCompile(`(?i)(password|api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`).ReplaceAllString(output, "$1=[REDACTED]")
}

func cachedFeed() (string, error) {
	b, e := os.ReadFile(filepath.Join(env("SECURITY_CACHE_DIR", "/data/security-cache"), "trivy", "db", "metadata.json"))
	if e != nil {
		return "", errors.New("Vulnerability feed is unavailable")
	}
	var m struct {
		Updated time.Time `json:"UpdatedAt"`
	}
	if json.Unmarshal(b, &m) != nil || m.Updated.IsZero() || time.Since(m.Updated) > 24*time.Hour || m.Updated.After(time.Now().Add(time.Minute)) {
		return "", errors.New("Vulnerability feed is stale")
	}
	return m.Updated.UTC().Format(time.RFC3339), nil
}
func staticPolicy(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "vendor" || d.Name() == ".cache") {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".py") {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			if regexp.MustCompile(`(?m)(child_process|node:vm|\beval\s*\(|\bexecSync\s*\(|\bsubprocess\.|pickle\.loads|yaml\.load\()`).Match(b) {
				return errors.New("Source uses a restricted dynamic execution capability; company review and template required")
			}
		}
		return nil
	})
}
func (s *server) scan(ctx context.Context, hostBuild string) ([]Finding, string, error) {
	if !digestImage.MatchString(s.manifest.ScannerImage) {
		return nil, "", errors.New("Pinned scanner is unavailable")
	}
	cache := env("HOST_SECURITY_CACHE_DIR", filepath.Join(env("HOST_DATA_DIR", ""), "security-cache"))
	localCache := env("SECURITY_CACHE_DIR", "/data/security-cache")
	b, e := os.ReadFile(filepath.Join(localCache, "trivy", "db", "metadata.json"))
	if e != nil {
		return nil, "", errors.New("Vulnerability feed unavailable; release is blocked")
	}
	var metadata struct {
		UpdatedAt time.Time `json:"UpdatedAt"`
	}
	if json.Unmarshal(b, &metadata) != nil || time.Since(metadata.UpdatedAt) > 24*time.Hour || metadata.UpdatedAt.After(time.Now().Add(time.Minute)) {
		return nil, "", errors.New("Vulnerability feed is stale or invalid")
	}
	// The bounded trusted runner combines stdout and stderr. Suppress scanner
	// progress/log messages so only its JSON report reaches the protocol parser.
	out, e := s.runner(ctx, "docker", "run", "--rm", "--runtime", env("RUNSC_RUNTIME", "runsc"), "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--memory", "1g", "--pids-limit", "128", "--tmpfs", "/tmp:size=128m,mode=1777", "--mount", "type=bind,src="+hostBuild+",dst=/workspace,readonly", "--mount", "type=bind,src="+cache+",dst=/cache,readonly", s.manifest.ScannerImage, "fs", "--quiet", "--config=", "--ignorefile=", "--cache-dir", "/cache/trivy", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln,misconfig,secret", "--format", "json", "/workspace")
	if e != nil {
		return nil, "", errors.New("Security scanner failed; publication is blocked")
	}
	var report struct {
		SchemaVersion int `json:"SchemaVersion"`
		Results       []struct {
			Vulnerabilities []struct {
				ID        string `json:"VulnerabilityID"`
				Severity  string
				Pkg       string `json:"PkgName"`
				Installed string `json:"InstalledVersion"`
				Fixed     string `json:"FixedVersion"`
				Title     string
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID       string
				Severity string
				Title    string
			} `json:"Misconfigurations"`
			Secrets []struct {
				ID       string `json:"RuleID"`
				Severity string
				Title    string
			} `json:"Secrets"`
		} `json:"Results"`
	}
	if json.Unmarshal([]byte(out), &report) != nil || report.SchemaVersion < 2 {
		return nil, "", errors.New("Scanner returned invalid evidence")
	}
	findings := []Finding{}
	for _, result := range report.Results {
		for _, f := range result.Vulnerabilities {
			findings = append(findings, Finding{f.ID, f.Severity, f.Pkg, f.Installed, f.Fixed, "trivy", f.Title})
		}
		for _, f := range result.Misconfigurations {
			findings = append(findings, Finding{ID: f.ID, Severity: f.Severity, Source: "trivy-config", Description: f.Title})
		}
		for _, f := range result.Secrets {
			findings = append(findings, Finding{ID: f.ID, Severity: f.Severity, Source: "trivy-secret", Description: f.Title})
		}
	}
	return findings, metadata.UpdatedAt.UTC().Format(time.RFC3339), nil
}
func readMigrations(root string) ([]Migration, error) {
	b, e := os.ReadFile(filepath.Join(root, "migrations.json"))
	if os.IsNotExist(e) {
		return []Migration{}, nil
	}
	if e != nil {
		return nil, e
	}
	var ms []Migration
	if e = json.Unmarshal(b, &ms); e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for i := range ms {
		m := &ms[i]
		if !identity.MatchString(m.ID) || seen[m.ID] || m.Destructive {
			return nil, errors.New("Destructive or invalid migrations require a separately verified recovery checkpoint and exact impact approval")
		}
		seen[m.ID] = true
		if e = validateSQL(m.SQL); e != nil {
			return nil, e
		}
		m.Checksum = hashBytes([]byte(m.SQL))
	}
	return ms, nil
}
func validateSQL(sql string) error {
	// Only the explicit enabling form is allowed. A generated statement cannot disable
	// encryption or choose another storage engine/location behind an additive prefix.
	policySQL := regexp.MustCompile(`(?i)\bENCRYPTION\s*=\s*'Y'`).ReplaceAllString(sql, "")
	blocked := regexp.MustCompile(`(?i)\b(DROP|TRUNCATE|DELETE|UPDATE|SELECT|RENAME|REPLACE|GRANT|REVOKE|LOAD|OUTFILE|INFILE|PROCEDURE|TRIGGER|EVENT|FUNCTION|DATABASE|USER|MODIFY|CHANGE|CONVERT|CHARSET|COLLATE|COLLATION|PARTITION|PARTITIONS|REORGANIZE|COALESCE|EXCHANGE|DISCARD|IMPORT|ENGINE|TABLESPACE|DIRECTORY|ENCRYPTION|DISABLE|ENABLE|FORCE|ALGORITHM|LOCK|SECONDARY_ENGINE|_AUTOSOFT_MIGRATIONS)\b|\bCHARACTER\s+SET\b`)
	if len(sql) == 0 || len(sql) > 100000 || strings.IndexByte(sql, 0) >= 0 || strings.Contains(sql, "--") || strings.Contains(sql, "/*") || strings.Contains(sql, "#") || blocked.MatchString(policySQL) || regexp.MustCompile("[a-zA-Z_`][a-zA-Z0-9_`]*\\s*\\.\\s*[a-zA-Z_`]").MatchString(sql) {
		return errors.New("Only reviewed additive schema statements are supported")
	}
	count := 0
	for _, statement := range strings.Split(sql, ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		count++
		alter := regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+[a-zA-Z0-9_` + "`" + `]+\s+ADD\s+`)
		isAlter := alter.MatchString(statement)
		if !isAlter && !regexp.MustCompile(`(?i)^CREATE\s+(TABLE|INDEX)\s+`).MatchString(statement) {
			return errors.New("Migration is outside the additive schema policy")
		}
		if isAlter && regexp.MustCompile(`(?i)\b(NOT\s+NULL|UNIQUE|PRIMARY|FOREIGN|REFERENCES|CONSTRAINT|CHECK|AUTO_INCREMENT|FIRST|AFTER)\b`).MatchString(statement) {
			return errors.New("Existing-table additions must remain nullable and cannot impose new write constraints or reorder columns; explicit compatibility verification is required")
		}
		// ALTER accepts exactly one ADD clause. Commas in column definitions or
		// index expressions remain valid; top-level commas could append a second
		// operation and are refused independently of the capability blacklist.
		depth := 0
		var quote byte
		for i := 0; i < len(statement); i++ {
			c := statement[i]
			if quote != 0 {
				if c == '\\' && quote != '`' {
					i++
					continue
				}
				if c == quote {
					if i+1 < len(statement) && statement[i+1] == quote {
						i++
					} else {
						quote = 0
					}
				}
				continue
			}
			switch c {
			case '\'', '"', '`':
				quote = c
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					return errors.New("Unbalanced migration expression")
				}
			case ',':
				if isAlter && depth == 0 {
					return errors.New("Each ALTER statement may contain only one additive clause")
				}
			}
		}
		if quote != 0 || depth != 0 {
			return errors.New("Unbalanced or unterminated migration expression")
		}
	}
	if count == 0 {
		return errors.New("An additive migration statement is required")
	}
	return nil
}

func (s *server) source(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AppID  string `json:"appId"`
		Commit string `json:"commit"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !identity.MatchString(in.AppID) || !regexp.MustCompile(`^[a-f0-9]{40,64}$`).MatchString(in.Commit) {
		fail(w, 400, errors.New("Exact scoped source revision is required"))
		return
	}
	entries, e := os.ReadDir(filepath.Join(s.data, "receipts"))
	if e != nil {
		fail(w, 404, errors.New("Verified source is unavailable"))
		return
	}
	var v Verification
	found := false
	for _, entry := range entries {
		b, e := os.ReadFile(filepath.Join(s.data, "receipts", entry.Name()))
		if e == nil && json.Unmarshal(b, &v) == nil && v.AppID == in.AppID && v.Commit == in.Commit && v.Evidence.Status == "passed" {
			found = true
			break
		}
	}
	if !found {
		fail(w, 404, errors.New("Verified source revision does not belong to this application"))
		return
	}
	if !identity.MatchString(v.AttemptID) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(v.SourceHash) {
		fail(w, 409, errors.New("Verified source identity is unavailable"))
		return
	}
	root := filepath.Join(s.data, "sources", v.AttemptID)
	files := []capturedSourceFile{}
	total := 0
	e = filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() || d.Type()&os.ModeSymlink != 0 {
			return errors.New("Verified source contains an invalid file")
		}
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		held, e := f.Stat()
		if e != nil || !held.Mode().IsRegular() || !os.SameFile(info, held) {
			f.Close()
			return errors.New("Verified source changed during capture")
		}
		b, e := io.ReadAll(io.LimitReader(f, int64((20<<20)-total+1)))
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return errors.New("Verified source capture is unavailable")
		}
		total += len(b)
		if total > 20<<20 || len(files) >= 600 {
			return errors.New("Source context exceeds the approved limit")
		}
		rel, _ := filepath.Rel(root, p)
		files = append(files, capturedSourceFile{filepath.ToSlash(rel), string(b)})
		return nil
	})
	if e != nil {
		fail(w, 500, e)
		return
	}
	actual, e := capturedSourceDigest(files)
	if e != nil || actual != v.SourceHash {
		fail(w, 409, errors.New("Returned source bytes differ from the verified final source"))
		return
	}
	respond(w, map[string]any{"files": files})
}
func (s *server) requestPackage(ctx context.Context, app, attempt, template string) (string, error) {
	b, _ := json.Marshal(map[string]string{"appId": app, "attemptId": attempt, "template": template})
	request, e := http.NewRequestWithContext(ctx, "POST", env("PACKAGER_URL", "http://packager:8091")+"/v1/package", strings.NewReader(string(b)))
	if e != nil {
		return "", e
	}
	token, e := secret("PACKAGER_TOKEN")
	if e != nil {
		return "", e
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, e := s.client.Do(request)
	if e != nil {
		return "", e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", errors.New("Trusted image packager rejected artifacts")
	}
	var result struct {
		Image string `json:"image"`
	}
	if e = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result); e != nil || !digestImage.MatchString(result.Image) {
		return "", errors.New("Image packager did not return a verified digest")
	}
	return result.Image, nil
}
