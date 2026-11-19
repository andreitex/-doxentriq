package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// A source scan is limited to one current build or retained receipt snapshot.
// This path binding supplements the caller's source authorization and digest
// checks; it does not replace them or claim that generated build bytes are a
// verified immutable source snapshot.
func sourceScannerPath(path string) bool {
	area := filepath.Base(filepath.Dir(path))
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, ",\x00\r\n") && identity.MatchString(filepath.Base(path)) &&
		(area == "builds" || area == "sources")
}

func sourceScannerWorkspace(root, path string) bool {
	return filepath.IsAbs(root) && filepath.Clean(root) == root && sourceScannerPath(path) &&
		filepath.Dir(filepath.Dir(path)) == root
}

// Only the current scanner execution can return this binding. A journal with
// an unrelated or malformed marker is not authority to remove a workspace.
type sourceScannerUnresolved struct{ workspace string }

func (e *sourceScannerUnresolved) Error() string { return imageScannerUnavailable.Error() }
func (e *sourceScannerUnresolved) Unwrap() error { return imageScannerUnavailable }

func sourceScannerPreservesWorkspace(err error, workspace string) bool {
	var unresolved *sourceScannerUnresolved
	return errors.As(err, &unresolved) && sourceScannerPath(workspace) && unresolved.workspace == workspace
}

func cleanupVerificationBuild(build, hostBuild string, scanErr error) {
	// Both paths were derived from the same accepted attempt by verification.
	// Reject aliases or a different attempt before the existing owned-tree cleanup.
	if !sourceScannerPath(build) || filepath.Base(filepath.Dir(build)) != "builds" ||
		!sourceScannerPath(hostBuild) || filepath.Base(filepath.Dir(hostBuild)) != "builds" ||
		filepath.Base(build) != filepath.Base(hostBuild) || sourceScannerPreservesWorkspace(scanErr, hostBuild) {
		return
	}
	_ = os.RemoveAll(build)
}

func (s *server) scanVerificationSource(ctx context.Context, hostBuild string, input sourceScannerInput, pending *error) ([]Finding, string, error) {
	// net/http can recover a panic while owned-container effects remain unknown.
	// Install the exact workspace binding before entering the scanner, and clear
	// or replace it only on a normal return. Verification's defer reads it later.
	*pending = &sourceScannerUnresolved{workspace: hostBuild}
	findings, updated, err := s.scan(ctx, hostBuild, input)
	*pending = err
	return findings, updated, err
}

func scannerRecordTargetValid(record imageScannerRecord) bool {
	switch record.Version {
	case 1:
		return record.ScanKind == "" && record.SourceWorkspace == "" && record.NetworkMode == "" && digestImage.MatchString(record.Image)
	case 2:
		return record.ScanKind == "source" && record.Image == "" && record.NetworkMode == "none" && sourceScannerPath(record.SourceWorkspace)
	default:
		return false
	}
}

func sourceScannerCommand() []string {
	return []string{"fs", "--quiet", "--config=", "--ignorefile=", "--cache-dir", "/cache/trivy", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln,misconfig,secret", "--list-all-pkgs", "--include-dev-deps", "--file-patterns", `pip:^requirements\.lock$`, "--secret-config=", "--format", "json", "/workspace"}
}

func (x *imageScannerExecution) sourceProfileValid() bool {
	return x.r.Version == 2 && scannerRecordTargetValid(x.r) && x.r.SourceWorkspace == x.spec.workspace &&
		x.spec.name == "as-source-scan-"+x.r.OperationID && x.spec.image == x.r.Scanner &&
		digestImage.MatchString(x.spec.image) && x.spec.runtime == "runsc" && x.spec.network == "none" &&
		exactDockerID.MatchString(x.r.NetworkID) && x.spec.ca == "" && x.spec.envFile == "" &&
		len(x.spec.hosts) == 0 && len(x.spec.environment) == 0 && reflect.DeepEqual(x.spec.command, sourceScannerCommand())
}

func (s imageScannerSpec) sourceCreate() []string {
	args := []string{"create", "--name", s.name, "--hostname", s.name,
		"--label", "io.autosoft.runtime-source-scan=" + strings.TrimPrefix(s.name, "as-source-scan-"),
		"--runtime", "runsc", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--user", "10001:10001", "--workdir", "/",
		"--cpus", "1", "--memory", "1g", "--memory-swap", "1g", "--pids-limit", "128",
		"--restart", "no", "--log-driver", "none", "--no-healthcheck", "--stop-signal", "SIGTERM",
		"--tmpfs", "/tmp:size=128m,mode=1777",
		"--mount", "type=bind,src=" + s.workspace + ",dst=/workspace,readonly",
		"--mount", "type=bind,src=" + s.cache + ",dst=/cache,readonly", s.image}
	return append(args, s.command...)
}

// Inspect the built-in no-network driver; its real immutable ID is journaled.
// There is no registry resolver, credential file, extra host or network attach.
func sourceScannerNetwork(out []byte) (string, error) {
	n, err := imageScannerJSON(out)
	if err != nil || n["Name"] != "none" || n["Driver"] != "null" || n["Scope"] != "local" ||
		!exactDockerID.MatchString(scannerString(n["Id"])) || !scannerBool(n["Internal"], false) ||
		!scannerBool(n["Attachable"], false) || !scannerBool(n["Ingress"], false) ||
		!scannerEmpty(scannerMap(n["IPAM"])["Config"]) || !scannerEmpty(n["Options"]) {
		return "", imageScannerUnavailable
	}
	return scannerString(n["Id"]), nil
}

func sourceScannerNetworkState(networks, state map[string]any, id string) bool {
	if len(networks) != 1 || !exactDockerID.MatchString(id) {
		return false
	}
	endpoint := scannerMap(networks["none"])
	if endpoint == nil {
		return false
	}
	if endpoint["NetworkID"] != id {
		if endpoint["NetworkID"] != "" || state["Status"] != "created" ||
			!scannerNumber(state["Pid"], 0) || state["StartedAt"] != "0001-01-01T00:00:00Z" {
			return false
		}
	}
	for _, key := range []string{"Gateway", "IPAddress", "MacAddress", "IPv6Gateway", "GlobalIPv6Address"} {
		if value, ok := endpoint[key].(string); !ok || value != "" {
			return false
		}
	}
	for _, key := range []string{"IPPrefixLen", "GlobalIPv6PrefixLen"} {
		if !scannerNumber(endpoint[key], 0) {
			return false
		}
	}
	for _, key := range []string{"IPAMConfig", "Links", "Aliases", "DriverOpts", "DNSNames"} {
		if value, present := endpoint[key]; !present || !scannerEmpty(value) {
			return false
		}
	}
	return true
}

func (s *server) scanSourceSafely(ctx context.Context, hostBuild string, input sourceScannerInput) (findings []Finding, updated string, err error) {
	if !digestImage.MatchString(s.manifest.ScannerImage) || !filepath.IsAbs(s.data) ||
		env("RUNSC_RUNTIME", "runsc") != "runsc" || !sourceScannerWorkspace(s.hostRuntime, hostBuild) {
		return nil, "", imageScannerUnavailable
	}
	coverage, coverageError := s.sourceScannerCoverage(hostBuild, input)
	if coverageError != nil {
		return nil, "", imageScannerUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, imageScannerSeconds*time.Second)
	defer cancel()
	select {
	case imageScannerSerial <- struct{}{}:
		defer func() { <-imageScannerSerial }()
	case <-ctx.Done():
		return nil, "", imageScannerUnavailable
	}
	if imageScannerPriorClear(s.data) != nil {
		return nil, "", imageScannerUnavailable
	}
	hostData := env("HOST_DATA_DIR", "")
	cache := env("HOST_SECURITY_CACHE_DIR", filepath.Join(hostData, "security-cache"))
	if !filepath.IsAbs(hostData) || cache != filepath.Join(hostData, "security-cache") {
		return nil, "", imageScannerUnavailable
	}
	feedLease, e := holdSecurityFeed(ctx, s.data, env("SECURITY_CACHE_DIR", "/data/security-cache"))
	if e != nil {
		return nil, "", imageScannerUnavailable
	}
	defer func() {
		if feedLease.Close() != nil {
			findings, updated = nil, ""
			if !sourceScannerPreservesWorkspace(err, hostBuild) {
				err = imageScannerUnavailable
			}
		}
	}()
	op := randomSecret()[:32]
	dir := filepath.Join(s.data, "security", "runtime-image-scans", op)
	docker := s.imageScannerDocker
	if docker == nil {
		docker = imageScannerCommand
	}
	x := imageScannerExecution{
		d:   imageScannerDependencies{docker: docker, retain: func(path string, value any) error { return retainImageScannerFile(s.data, path, value) }},
		r:   imageScannerRecord{Version: 2, OperationID: op, Scanner: s.manifest.ScannerImage, ScanKind: "source", SourceWorkspace: hostBuild, NetworkMode: "none", Status: "intent", FeedHash: accessHash(feedLease.before)},
		dir: dir, config: filepath.Join(dir, "docker-config"),
	}
	if x.retain() != nil || x.d.retain(filepath.Join(dir, "feed-before.enc"), feedLease.before) != nil {
		return nil, "", imageScannerUnavailable
	}
	lease, e := claimImageScanner(s.data, x.r, x.d.retain)
	if e != nil {
		return nil, "", imageScannerUnavailable
	}
	defer func() {
		if !x.r.CleanupConfirmed {
			findings, updated, err = nil, "", &sourceScannerUnresolved{workspace: hostBuild}
			return
		}
		if err != nil {
			x.r.Status = "unavailable"
		}
		if x.retain() != nil || lease.release(x.r) != nil {
			findings, updated, err = nil, "", imageScannerUnavailable
		}
	}()
	if withdrawalAncestors(s.data, x.config, true) != nil {
		return nil, "", imageScannerUnavailable
	}
	config := filepath.Join(x.config, "config.json")
	if os.WriteFile(config, []byte("{}\n"), 0600) != nil {
		return nil, "", imageScannerUnavailable
	}
	x.inputGuard = func() error {
		info, e := os.Lstat(config)
		if e != nil || !withdrawalOrdinary(info) || info.Size() != 3 {
			return imageScannerUnavailable
		}
		data, e := os.ReadFile(config)
		if e != nil || !bytes.Equal(data, []byte("{}\n")) {
			return imageScannerUnavailable
		}
		return nil
	}
	r, e := x.call(ctx, 4<<20, "network", "inspect", "--format", "{{json .}}", "none")
	if e != nil {
		return nil, "", imageScannerUnavailable
	}
	x.r.NetworkID, e = sourceScannerNetwork(r.Stdout)
	if e != nil {
		return nil, "", imageScannerUnavailable
	}
	x.spec = imageScannerSpec{name: "as-source-scan-" + op, image: s.manifest.ScannerImage, runtime: "runsc", network: "none", workspace: hostBuild, cache: cache, command: sourceScannerCommand()}
	out, e := x.execute(ctx)
	if e != nil {
		return nil, "", imageScannerUnavailable
	}
	after, e := feedLease.Check(ctx)
	if e != nil || accessHash(after) != accessHash(feedLease.before) || x.d.retain(filepath.Join(dir, "feed-after.enc"), after) != nil {
		return nil, "", imageScannerUnavailable
	}
	if coverage.check() != nil {
		return nil, "", imageScannerUnavailable
	}
	if x.d.retain(filepath.Join(dir, "source-coverage.enc"), map[string]any{"sourceHash": coverage.sourceHash, "template": coverage.template, "target": coverage.target, "kind": coverage.kind, "locks": coverage.locks, "packages": coverage.packages}) != nil {
		return nil, "", imageScannerUnavailable
	}
	findings, e = sourceScannerFindings(out, coverage)
	if e != nil {
		return nil, "", e
	}
	return findings, after.UpdatedAt, nil
}
