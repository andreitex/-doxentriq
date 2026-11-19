package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func sourceScannerFixtureNetwork(id string) map[string]any {
	return map[string]any{"Id": id, "Name": "none", "Driver": "null", "Scope": "local", "Internal": false, "Attachable": false, "Ingress": false, "Options": nil, "IPAM": map[string]any{"Config": nil}}
}

func sourceScannerFixtureEndpoint(id string) map[string]any {
	return map[string]any{"NetworkID": id, "EndpointID": "", "Gateway": "", "IPAddress": "", "MacAddress": "", "IPv6Gateway": "", "GlobalIPv6Address": "", "IPPrefixLen": 0, "GlobalIPv6PrefixLen": 0, "IPAMConfig": nil, "Links": nil, "Aliases": nil, "DriverOpts": nil, "DNSNames": nil}
}

func newSourceScannerFixture(t *testing.T) *imageScannerFixture {
	f := newImageScannerFixture(t)
	f.x.spec = imageScannerSpec{name: "as-source-scan-" + f.x.r.OperationID, image: f.x.r.Scanner, runtime: "runsc", network: "none", cache: "/host/security-cache", workspace: "/host/runtime/builds/attempt1", command: sourceScannerCommand()}
	f.x.r.Version, f.x.r.Image, f.x.r.ScanKind = 2, "", "source"
	f.x.r.SourceWorkspace, f.x.r.NetworkMode = f.x.spec.workspace, "none"
	f.createHook = func() { sourceScannerFixtureContainer(f) }
	return f
}

func sourceScannerFixtureContainer(f *imageScannerFixture) {
	spec := f.x.spec
	host := scannerFixtureMap(f.container, "HostConfig")
	host["Memory"], host["MemorySwap"] = 1<<30, 1<<30
	config := scannerFixtureMap(f.container, "Config")
	config["Labels"] = map[string]string{"company": "scanner", "io.autosoft.runtime-source-scan": strings.TrimPrefix(spec.name, "as-source-scan-")}
	f.container["Mounts"] = []map[string]any{{"Type": "bind", "Source": spec.workspace, "Destination": "/workspace", "RW": false}, {"Type": "bind", "Source": spec.cache, "Destination": "/cache", "RW": false}}
	f.container["NetworkSettings"] = map[string]any{"Networks": map[string]any{"none": sourceScannerFixtureEndpoint(f.x.r.NetworkID)}, "Ports": nil}
}

// Can coexist with the image fixture: only exact configs first observed in a
// source's built-in-none inspection are handled here. No production Docker runs.
func installSourceScannerServerFixture(t *testing.T, s *server, hostData string) *imageScannerFixture {
	t.Helper()
	f := newSourceScannerFixture(t)
	f.x.spec.image = s.manifest.ScannerImage
	f.x.spec.cache = filepath.Join(hostData, "security-cache")
	previous := s.imageScannerDocker
	configs := map[string]bool{}
	s.imageScannerDocker = func(ctx context.Context, args []string, limit int64) (imageScannerCommandResult, error) {
		if len(args) < 5 {
			t.Fatal("missing explicit Docker arguments")
		}
		command := args[4:]
		if reflect.DeepEqual(command, []string{"network", "inspect", "--format", "{{json .}}", "none"}) {
			configs[args[3]] = true
			f.calls = append(f.calls, append([]string{}, command...))
			data, _ := json.Marshal(sourceScannerFixtureNetwork(f.x.r.NetworkID))
			return imageScannerCommandResult{Stdout: data, Reaped: true}, nil
		}
		if !configs[args[3]] {
			if previous == nil {
				t.Fatal("unexpected non-source Docker operation")
			}
			return previous(ctx, args, limit)
		}
		if command[0] == "create" {
			for i := 1; i+1 < len(command); i++ {
				switch command[i] {
				case "--name":
					f.x.spec.name = command[i+1]
				case "--mount":
					mount := command[i+1]
					if strings.HasSuffix(mount, ",dst=/workspace,readonly") {
						f.x.spec.workspace = strings.TrimSuffix(strings.TrimPrefix(mount, "type=bind,src="), ",dst=/workspace,readonly")
					}
				}
			}
		}
		result, err := f.docker(ctx, args, limit)
		if command[0] == "start" && err == nil {
			report := sourceCoverageReportFixture()
			report["Results"].([]any)[0].(map[string]any)["Vulnerabilities"] = []any{map[string]any{"VulnerabilityID": "CVE-fixture", "Severity": "MEDIUM", "PkgName": "fixture", "InstalledVersion": "1.0.0"}}
			result.Stdout = sourceCoverageReportBytes(t, report)
		}
		return result, err
	}
	return f
}

func sourceScannerServerFixture(t *testing.T) (*server, *imageScannerFixture, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("durable Linux scanner journal required")
	}
	root, cache := scannerFixtureFeed(t)
	fixtureProtectedFeedLocks(t, cache)
	t.Setenv("BROKER_VAULT_KEY_FILE", "")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("HOST_DATA_DIR", filepath.Dir(root))
	t.Setenv("HOST_SECURITY_CACHE_DIR", cache)
	t.Setenv("SECURITY_CACHE_DIR", cache)
	s := &server{data: root, hostRuntime: root, manifest: testManifest()}
	s.manifest.ScannerImage = "registry:5000/scanner@sha256:" + strings.Repeat("c", 64)
	for _, area := range []string{"sources", "builds"} {
		dir := filepath.Join(root, area, "attempt1")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "app.manifest.json"), []byte(`{"template":"node-api"}`), 0600); err != nil {
			t.Fatal(err)
		}
		sourceScannerFixtureLocks(t, dir, area == "builds")
	}
	f := installSourceScannerServerFixture(t, s, filepath.Dir(root))
	return s, f, filepath.Join(root, "builds", "attempt1")
}

func TestSourceScannerLifecycleCancellationAndUnknownOutcomes(t *testing.T) {
	for _, kind := range []string{"success", "cancel_running", "cancel_create_with_id", "lost_create_id", "cleanup_unconfirmed", "lost_remove_response", "prestart_profile_drift"} {
		t.Run(kind, func(t *testing.T) {
			s, f, workspace := sourceScannerServerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "cancel_running":
				f.startHook = cancel
			case "cancel_create_with_id":
				f.createHook = func() { sourceScannerFixtureContainer(f); cancel() }
			case "lost_create_id":
				f.lostID = true
			case "cleanup_unconfirmed":
				f.startHook = cancel
				f.stopFault = true
			case "lost_remove_response":
				f.removeFault = true
			case "prestart_profile_drift":
				f.driftAt = 2
			}
			findings, feed, err := s.scan(ctx, workspace, sourceScannerFixtureInput(t, s))
			pass := kind == "success" || kind == "lost_remove_response"
			if (err == nil) != pass || pass && (len(findings) != 1 || feed == "") || !pass && (findings != nil || feed != "") {
				t.Fatalf("unexpected outcome for %s: %v", kind, err)
			}
			unresolved := kind == "lost_create_id" || kind == "cleanup_unconfirmed" || kind == "prestart_profile_drift"
			if sourceScannerPreservesWorkspace(err, workspace) != unresolved || f.removed == unresolved {
				t.Fatal("unresolved source workspace/cleanup binding was lost")
			}
			if sourceScannerPreservesWorkspace(err, filepath.Join(s.hostRuntime, "builds", "other")) || sourceScannerPreservesWorkspace(errors.New("unconfirmed"), workspace) {
				t.Fatal("unrelated error or workspace obtained preservation authority")
			}
			if (imageScannerPriorClear(s.data) != nil) != unresolved {
				t.Fatal("durable source outcome disagrees with independent cleanup")
			}
			if unresolved {
				count := len(f.calls)
				if _, _, e := s.scan(context.Background(), workspace, sourceScannerFixtureInput(t, s)); e == nil || len(f.calls) != count {
					t.Fatal("source scan retried unknown container")
				}
				if _, e := s.scanImageSafely(context.Background(), "registry:5000/app@sha256:"+strings.Repeat("a", 64)); e == nil || len(f.calls) != count {
					t.Fatal("image scan bypassed source uncertainty")
				}
			}
			if (kind == "lost_create_id" || kind == "cancel_create_with_id" || kind == "prestart_profile_drift") && f.count("start") != 0 {
				t.Fatal("unknown/cancelled/changed container was started")
			}
			for _, command := range f.calls {
				if command[0] == "run" {
					t.Fatal("legacy auto-remove path used")
				}
			}
		})
	}
}

func TestSourceScannerFixedProfileAndAuthorizedPaths(t *testing.T) {
	f := newSourceScannerFixture(t)
	args := strings.Join(f.x.spec.create(), " ")
	for _, want := range []string{"--network none", "--memory 1g", "--memory-swap 1g", "--read-only", "--user 10001:10001", "--cap-drop ALL", "--security-opt no-new-privileges", "--restart no", "--log-driver none", "dst=/workspace,readonly", "dst=/cache,readonly", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--quiet", "--config=", "--ignorefile="} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing fixed source profile: %s", want)
		}
	}
	for _, forbidden := range []string{"--rm", "--env", "--add-host", "docker.sock", "ca.crt"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("source scan leaked broader authority: %s", forbidden)
		}
	}
	root := filepath.Join(t.TempDir(), "runtime")
	for _, area := range []string{"builds", "sources"} {
		if !sourceScannerWorkspace(root, filepath.Join(root, area, "attempt1")) {
			t.Fatal("authorized snapshot rejected")
		}
	}
	for _, path := range []string{filepath.Join(root, "other", "attempt1"), filepath.Join(root, "builds", "nested", "attempt1"), filepath.Join(filepath.Dir(root), "foreign", "builds", "attempt1"), filepath.Join(root, "builds", "attempt,bind"), root + string(filepath.Separator) + "builds" + string(filepath.Separator) + ".." + string(filepath.Separator) + "attempt1"} {
		if sourceScannerWorkspace(root, path) {
			t.Fatalf("unbound workspace admitted: %s", path)
		}
	}
}

func TestSourceScannerNetworkRefusesEgressAndProfileChanges(t *testing.T) {
	for _, field := range []string{"Driver", "Scope", "Name", "Id", "Internal", "Attachable", "Ingress", "Options"} {
		n := sourceScannerFixtureNetwork(strings.Repeat("b", 64))
		n[field] = "unexpected"
		data, _ := json.Marshal(n)
		if _, err := sourceScannerNetwork(data); err == nil {
			t.Fatalf("network field bypass: %s", field)
		}
	}
	for _, kind := range []string{"address", "gateway", "network", "extra_network", "writable_workspace", "foreign_workspace", "memory", "credentials"} {
		t.Run(kind, func(t *testing.T) {
			f := newSourceScannerFixture(t)
			f.createHook = func() {
				sourceScannerFixtureContainer(f)
				networks := scannerFixtureMap(scannerFixtureMap(f.container, "NetworkSettings"), "Networks")
				endpoint := scannerFixtureMap(networks, "none")
				switch kind {
				case "address":
					endpoint["IPAddress"] = "192.0.2.1"
				case "gateway":
					endpoint["Gateway"] = "192.0.2.254"
				case "network":
					endpoint["NetworkID"] = strings.Repeat("f", 64)
				case "extra_network":
					networks["bridge"] = sourceScannerFixtureEndpoint(strings.Repeat("e", 64))
				case "writable_workspace":
					f.container["Mounts"].([]map[string]any)[0]["RW"] = true
				case "foreign_workspace":
					f.container["Mounts"].([]map[string]any)[0]["Source"] = "/foreign"
				case "memory":
					scannerFixtureMap(f.container, "HostConfig")["Memory"] = 3 << 30
				case "credentials":
					scannerFixtureMap(f.container, "Config")["Env"] = []string{"PATH=/usr/local/bin:/usr/bin", "TRIVY_PASSWORD=forbidden"}
				}
			}
			if out, err := f.x.execute(context.Background()); err == nil || out != nil || f.count("start") != 0 || f.removed {
				t.Fatal("unproven source profile executed or was removed")
			}
		})
	}
}

func TestScannerJournalV1ExactBytesRemainCompatible(t *testing.T) {
	// Retained v1 field spelling/order: adding source fields must not change the
	// encrypted marker's recorded hash when an old image record is read back.
	original := `{"schemaVersion":1,"operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Image":"registry:5000/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","Scanner":"registry:5000/scanner@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","NetworkID":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","Status":"completed","ContainerID":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","ProfileHash":"1111111111111111111111111111111111111111111111111111111111111111","RawPrestartHash":"2222222222222222222222222222222222222222222222222222222222222222","FeedHash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","CleanupConfirmed":true,"CheckedAt":"2026-01-01T00:00:00Z"}`
	var record imageScannerRecord
	if json.Unmarshal([]byte(original), &record) != nil || !scannerRecordTargetValid(record) {
		t.Fatal("retained v1 format refused")
	}
	encoded, err := json.Marshal(record)
	if err != nil || string(encoded) != original || accessHash(record) != "5c59ba5cb25b09f3ca0cd736eb1a19a4ee643e977c24cfe5aa8b5c1aad162454" {
		t.Fatal("v1 journal hash changed")
	}
	record.ScanKind = "source"
	if scannerRecordTargetValid(record) {
		t.Fatal("mixed v1/source record admitted")
	}
}

func TestSourceScannerJournalBindsExplicitTarget(t *testing.T) {
	record := scannerFixtureCompletedRecord()
	record.Version, record.Image, record.ScanKind, record.NetworkMode = 2, "", "source", "none"
	record.SourceWorkspace = filepath.Join(t.TempDir(), "runtime", "sources", "attempt1")
	if !scannerRecordTargetValid(record) {
		t.Fatal("source record refused")
	}
	for _, kind := range []string{"image", "mode", "kind", "version", "source"} {
		bad := record
		switch kind {
		case "image":
			bad.Image = bad.Scanner
		case "mode":
			bad.NetworkMode = "bridge"
		case "kind":
			bad.ScanKind = "image"
		case "version":
			bad.Version = 1
		case "source":
			bad.SourceWorkspace = filepath.Join(t.TempDir(), "secrets", "file")
		}
		if scannerRecordTargetValid(bad) {
			t.Fatalf("mixed source record admitted: %s", kind)
		}
	}
}

func TestSourceScannerWorkspacePreservationKeepsOwnedFailure(t *testing.T) {
	s, f, workspace := sourceScannerServerFixture(t)
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(workspace, "retained.txt")
	if err := os.WriteFile(file, []byte("source evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	f.lostID = true
	_, _, scanErr := s.scan(context.Background(), workspace, sourceScannerFixtureInput(t, s))
	if !sourceScannerPreservesWorkspace(scanErr, workspace) {
		t.Fatal("unknown-create source lost its preservation binding")
	}
	cleanupVerificationBuild(workspace, workspace, scanErr)
	if data, err := os.ReadFile(file); err != nil || string(data) != "source evidence" {
		t.Fatal("unknown outcome damaged source")
	}
	if sourceScannerPreservesWorkspace(nil, workspace) || sourceScannerPreservesWorkspace(imageScannerUnavailable, workspace) {
		t.Fatal("ordinary successful/unrelated cleanup was disabled")
	}
	cleanupVerificationBuild(workspace, filepath.Join(s.hostRuntime, "builds", "different"), nil)
	if _, err := os.Stat(file); err != nil {
		t.Fatal("mismatched attempt authorized deletion")
	}
	cleanupVerificationBuild(workspace, workspace, nil)
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatal("confirmed ordinary build cleanup was disabled")
	}
}

func TestSourceScannerCallerPanicPreservesOwnedWorkspace(t *testing.T) {
	for _, phase := range []string{"create", "inspection", "normal_return"} {
		t.Run(phase, func(t *testing.T) {
			s, scanner, workspace := sourceScannerServerFixture(t)
			if err := os.MkdirAll(workspace, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(workspace, "retained.txt")
			if err := os.WriteFile(file, []byte("owned source evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, 0644); err != nil {
				t.Fatal(err)
			}
			if phase == "create" {
				scanner.createHook = func() { sourceScannerFixtureContainer(scanner); panic("injected-source-create") }
			} else if phase == "inspection" {
				original := s.imageScannerDocker
				s.imageScannerDocker = func(ctx context.Context, args []string, limit int64) (imageScannerCommandResult, error) {
					if args[4] == "inspect" {
						panic("injected-source-inspection")
					}
					return original(ctx, args, limit)
				}
			}
			var recovered any
			var pending error
			func() {
				defer func() { recovered = recover() }()
				defer func() { cleanupVerificationBuild(workspace, workspace, pending) }()
				_, _, _ = s.scanVerificationSource(context.Background(), workspace, sourceScannerFixtureInput(t, s), &pending)
			}()
			if phase == "normal_return" {
				if recovered != nil || pending != nil || !scanner.removed {
					t.Fatal("normal scanner return did not clear pending ownership")
				}
				if _, err := os.Stat(workspace); !os.IsNotExist(err) {
					t.Fatal("ordinary cleanup was disabled")
				}
			} else {
				if recovered == nil || !scanner.created || scanner.removed || scanner.count("start") != 0 || !sourceScannerPreservesWorkspace(pending, workspace) {
					t.Fatal("panic escaped without exact unresolved workspace binding")
				}
				if data, err := os.ReadFile(file); err != nil || string(data) != "owned source evidence" {
					t.Fatal("caller unwind deleted unresolved source")
				}
				if imageScannerPriorClear(s.data) == nil {
					t.Fatal("caller panic cleared unresolved scanner journal")
				}
			}
		})
	}
}
