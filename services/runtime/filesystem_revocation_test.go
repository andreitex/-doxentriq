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
	"strings"
	"sync"
	"testing"
	"time"
)

type filesystemRevocationFixture struct {
	server    *server
	state     filesystemConnectorState
	index     connectorCandidate
	resource  resources
	receipt   filesystemLiveReceipt
	expected  filesystemContainerExpected
	container map[string]any
	stops     []string
	stopError bool
	keepAlive bool
	listed    string
}

func newFilesystemRevocationFixture(t *testing.T, preview bool) *filesystemRevocationFixture {
	t.Helper()
	t.Setenv("OWNER_SUBJECT", "owner-one")
	t.Setenv("BROKER_VAULT_KEY_FILE", "")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
	t.Setenv("RUNSC_RUNTIME", "runsc")
	base := t.TempDir()
	t.Setenv("HOST_DATA_DIR", filepath.Join(base, "host-data"))
	f := &filesystemRevocationFixture{server: &server{data: filepath.Join(base, "runtime"), hostRuntime: filepath.Join(base, "host-runtime")}}
	in := filesystemRequestFixture()
	prepared := time.Now().Add(-2 * time.Hour).UTC()
	in.ApprovedAt = prepared.Format(time.RFC3339)
	in.Scope.AccessExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	in.Scope.ExpiresAt = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	in.ArtifactHash = filesystemArtifactHash(in.Scope)
	template := filesystemTemplate{Image: in.Scope.Image, SourceHash: in.Scope.TemplateSourceHash}
	template.Qualification.Status, template.Qualification.Scope = "passed", "synthetic-readonly-filesystem-runsc"
	template.Qualification.ReportHash, template.Qualification.CheckedAt = in.Scope.QualificationHash, prepared.Format(time.RFC3339)
	f.state = filesystemConnectorState{in, in.ArtifactHash, template, prepared.Format(time.RFC3339)}
	owner, candidate := in.Scope.AppID, "as-app-"+in.Scope.AppID+"-deadbeef"
	if preview {
		owner, candidate = owner+"_preview", "as-preview-"+in.Scope.AppID+"-deadbeef"
	}
	network := "autosoft_app_" + hashBytes([]byte(owner))[:24]
	f.resource = resources{AppID: owner, Network: network, Secrets: filepath.Join(f.server.data, "secrets", owner)}
	f.index = connectorCandidate{AppID: in.Scope.AppID, ResourceID: candidate, OwnerResourceID: owner, Network: network, Connections: []string{in.Scope.ConnectionID}}
	v := f.resource
	v.AppID = candidate
	var err error
	f.expected, err = f.server.expectedFilesystemContainer(f.state, v)
	if err != nil {
		t.Fatal(err)
	}
	f.container = filesystemContainerFixture(f.expected)
	f.container["NetworkSettings"] = map[string]any{"Networks": map[string]any{network: map[string]any{"NetworkID": strings.Repeat("9", 64), "IPAddress": "172.30.1.2"}}}
	f.container["State"] = map[string]any{"Running": true, "Paused": false, "Restarting": false, "Status": "running"}
	id := f.container["Id"].(string)
	f.listed = id
	f.receipt = filesystemLiveReceipt{AppID: in.Scope.AppID, ResourceID: candidate, ConnectionID: in.Scope.ConnectionID, ScopeHash: f.state.ScopeHash, Image: template.Image, SourceHash: template.SourceHash, Adapter: f.expected.Name, ContainerID: id, CheckedAt: prepared.Add(time.Minute).Format(time.RFC3339), FeedUpdatedAt: prepared.Format(time.RFC3339), ExpiresAt: in.Scope.AccessExpiresAt, Status: "passed"}
	f.write(t)
	f.server.runner = func(ctx context.Context, name string, args ...string) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if name != "docker" {
			t.Fatal("Unapproved executable", name)
		}
		if reflect.DeepEqual(args, []string{"ps", "--all", "--no-trunc", "--filter", "label=io.autosoft.managed=true", "--filter", "label=io.autosoft.connector.type=filesystem", "--format", "{{.ID}}"}) {
			return f.listed, nil
		}
		if reflect.DeepEqual(args, []string{"network", "inspect", "--format", "{{json .}}", network}) {
			b, _ := json.Marshal(map[string]any{"Id": strings.Repeat("9", 64), "Name": network, "Driver": "bridge", "Internal": true, "Labels": map[string]string{"io.autosoft.managed": "true"}, "IPAM": map[string]any{"Config": []map[string]string{{"Subnet": "172.30.1.0/24"}}}, "Containers": map[string]any{id: map[string]string{"IPv4Address": "172.30.1.2/24"}}})
			return string(b), nil
		}
		if reflect.DeepEqual(args, []string{"inspect", "--format", "{{json .}}", id}) {
			b, _ := json.Marshal(f.container)
			return string(b), nil
		}
		if reflect.DeepEqual(args, []string{"stop", "--time", "10", id}) {
			f.stops = append(f.stops, id)
			if !f.keepAlive {
				f.container["State"] = map[string]any{"Running": false, "Paused": false, "Restarting": false, "Status": "exited"}
			}
			if f.stopError {
				return "", errors.New("Synthetic lost stop response")
			}
			return id, nil
		}
		t.Fatalf("Unexpected host command: %s %v", name, args)
		return "", errors.New("Unapproved fixture operation")
	}
	return f
}

func (f *filesystemRevocationFixture) write(t *testing.T) {
	t.Helper()
	for file, value := range map[string]any{f.server.filesystemStatePath(f.state.Input.Scope.AppID, f.state.Input.Scope.ConnectionID): f.state, filepath.Join(f.server.data, "connectors", "candidates", f.index.ResourceID+".enc"): f.index, filepath.Join(f.server.data, "resources", f.resource.AppID+".enc"): f.resource} {
		if err := writeEncrypted(file, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := atomicJSON(filepath.Join(f.server.data, "connectors", "filesystem-live", f.index.ResourceID, f.state.Input.Scope.ConnectionID+".json"), f.receipt); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemRevocationStopsOriginalExpiredPublishedAndPreviewWithoutDeletingData(t *testing.T) {
	for _, preview := range []bool{false, true} {
		f := newFilesystemRevocationFixture(t, preview)
		result := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, f.server.loadApprovedFilesystem)
		if result.Status != "stopped" || len(f.stops) != 1 || f.stops[0] != f.receipt.ContainerID {
			t.Fatal("Expired exact original adapter was not stopped", result, f.stops)
		}
		if _, err := os.Stat(f.server.filesystemStatePath(f.state.Input.Scope.AppID, f.state.Input.Scope.ConnectionID)); err != nil {
			t.Fatal("Approval was deleted", err)
		}
		f.state.Input.Scope.AccessExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		// Stopped adapters are never restarted, even when policy becomes current.
		current := func(string, string) (filesystemConnectorState, error) { return f.state, nil }
		if repeated := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, current); repeated.Status != "current" || len(f.stops) != 1 {
			t.Fatal("Reconciliation restarted or re-stopped a current/manual stopped adapter", repeated)
		}
	}
}

func TestFilesystemRevocationPreservesForeignReplacementMountAndEncryptedOwnershipDrift(t *testing.T) {
	mutations := map[string]func(*filesystemRevocationFixture){
		"replacement": func(f *filesystemRevocationFixture) { f.container["Id"] = strings.Repeat("1", 64) },
		"foreign-app": func(f *filesystemRevocationFixture) {
			f.container["Config"].(map[string]any)["Labels"].(map[string]string)["io.autosoft.connector.app"] = "other-app"
		},
		"image": func(f *filesystemRevocationFixture) {
			f.container["Config"].(map[string]any)["Image"] = "unapproved:latest"
		},
		"writable": func(f *filesystemRevocationFixture) { f.container["Mounts"].([]map[string]any)[0]["RW"] = true },
		"duplicate-sealed-env": func(f *filesystemRevocationFixture) {
			config := f.container["Config"].(map[string]any)
			config["Env"] = append(config["Env"].([]string), "CONNECTOR_CONFIG_FILE=/foreign")
		},
		"host-source":          func(f *filesystemRevocationFixture) { f.container["Mounts"].([]map[string]any)[0]["Source"] = "/etc" },
		"candidate-owner":      func(f *filesystemRevocationFixture) { f.index.OwnerResourceID = "other-app" },
		"candidate-membership": func(f *filesystemRevocationFixture) { f.index.Connections = []string{"other-connection"} },
		"resource-network":     func(f *filesystemRevocationFixture) { f.resource.Network = "foreign" },
		"network-id": func(f *filesystemRevocationFixture) {
			f.container["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)[f.expected.Network].(map[string]any)["NetworkID"] = strings.Repeat("8", 64)
		},
		"network-ip": func(f *filesystemRevocationFixture) {
			f.container["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)[f.expected.Network].(map[string]any)["IPAddress"] = "172.30.1.3"
		},
		"source-origin":       func(f *filesystemRevocationFixture) { f.state.Template.SourceHash = strings.Repeat("1", 64) },
		"original-live-id":    func(f *filesystemRevocationFixture) { f.receipt.ContainerID = strings.Repeat("1", 64) },
		"original-live-image": func(f *filesystemRevocationFixture) { f.receipt.Image = "unapproved:latest" },
	}
	for label, mutate := range mutations {
		t.Run(label, func(t *testing.T) {
			f := newFilesystemRevocationFixture(t, false)
			id := f.receipt.ContainerID
			mutate(f)
			f.write(t)
			result := f.server.reconcileFilesystemRevocationTarget(context.Background(), id, f.server.loadApprovedFilesystem)
			if result.Status != "unavailable" || len(f.stops) != 0 {
				t.Fatal("Foreign or drifted scope was mutated", result, f.stops)
			}
		})
	}
}

func TestFilesystemRevocationRequiresIndependentStopConfirmationAndRetriesBusyApps(t *testing.T) {
	for _, item := range []struct {
		lostResponse, running bool
		expected              string
	}{{false, false, "stopped"}, {true, false, "stopped"}, {true, true, "unavailable"}, {false, true, "unavailable"}} {
		f := newFilesystemRevocationFixture(t, false)
		f.stopError, f.keepAlive = item.lostResponse, item.running
		result := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, f.server.loadApprovedFilesystem)
		if result.Status != item.expected || len(f.stops) != 1 {
			t.Fatal("Stop response substituted for independent runtime evidence", result, f.stops)
		}
	}
	f := newFilesystemRevocationFixture(t, false)
	lock, _ := f.server.locks.LoadOrStore("app-"+f.index.AppID, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	result := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, f.server.loadApprovedFilesystem)
	lock.(*sync.Mutex).Unlock()
	if result.Status != "unavailable" || len(f.stops) != 0 || !strings.Contains(result.Detail, "busy") {
		t.Fatal("Busy app mutation was not deferred", result)
	}
	if result = f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, f.server.loadApprovedFilesystem); result.Status != "stopped" {
		t.Fatal("Safe deferred retry did not stop the exact original adapter", result)
	}
}

func TestFilesystemRevocationRechecksExactContainerBeforeStopAndDoesNotRestartManuallyStoppedAdapters(t *testing.T) {
	f := newFilesystemRevocationFixture(t, false)
	calls := 0
	withdrawn := func(string, string) (filesystemConnectorState, error) {
		calls++
		if calls == 2 {
			f.container["Mounts"].([]map[string]any)[0]["Source"] = "/foreign"
		}
		return filesystemConnectorState{}, errors.New("Synthetic catalog withdrawal")
	}
	if result := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, withdrawn); result.Status != "unavailable" || len(f.stops) != 0 {
		t.Fatal("Changed mount after initial proof was stopped", result)
	}
	f = newFilesystemRevocationFixture(t, false)
	f.container["State"] = map[string]any{"Running": false, "Paused": false, "Restarting": false, "Status": "exited"}
	if result := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, f.server.loadApprovedFilesystem); result.Status != "stopped" || len(f.stops) != 0 {
		t.Fatal("Manual stop was not preserved", result)
	}
}

func TestFilesystemRevocationPassBoundsInventoryAndPersistsUnavailableReport(t *testing.T) {
	for _, invalid := range []string{"short-id", strings.Repeat("f", 64) + "\n" + strings.Repeat("f", 64), strings.Repeat(strings.Repeat("f", 64)+"\n", 257)} {
		f := newFilesystemRevocationFixture(t, false)
		f.listed = invalid
		results := f.server.reconcileFilesystemRevocations(context.Background())
		if len(results) != 1 || results[0].Status != "unavailable" || len(f.stops) != 0 {
			t.Fatal("Unbounded or ambiguous discovery allowed a stop", results)
		}
		var report struct {
			RegistryRevocationSupported bool
			Results                     []filesystemRevocationResult
		}
		if readBoundedJSON(filepath.Join(f.server.data, "reports", "filesystem-revocation-report.json"), &report) != nil || report.RegistryRevocationSupported || len(report.Results) != 1 {
			t.Fatal("Unavailable proof was not accurately persisted")
		}
	}
	f := newFilesystemRevocationFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := f.server.reconcileFilesystemRevocationTarget(ctx, f.receipt.ContainerID, f.server.loadApprovedFilesystem); result.Status != "unavailable" || len(f.stops) != 0 {
		t.Fatal("Canceled reconciliation mutated an adapter", result)
	}
}

func TestFilesystemRevocationTelemetryReportsOnlyFreshBoundedFixedSummary(t *testing.T) {
	s := &server{data: t.TempDir()}
	file := filepath.Join(s.data, "reports", "filesystem-revocation-report.json")
	if s.filesystemRevocationTelemetry()["status"] != "unavailable" {
		t.Fatal("Missing evidence implied health")
	}
	write := func(value any) {
		t.Helper()
		if err := atomicJSON(file, value); err != nil {
			t.Fatal(err)
		}
	}
	base := func() map[string]any {
		return map[string]any{"checkedAt": time.Now().UTC().Format(time.RFC3339), "checkIntervalSeconds": 60, "registryRevocationSupported": false, "results": []filesystemRevocationResult{}}
	}
	write(base())
	if s.filesystemRevocationTelemetry()["status"] != "healthy" {
		t.Fatal("Fresh completed empty inventory rejected")
	}
	for _, status := range []string{"current", "stopped", "unavailable"} {
		r := base()
		r["results"] = []filesystemRevocationResult{{AppID: "app-one", ConnectionID: "connection-one", ResourceID: "as-app-app-one-deadbeef", ContainerID: strings.Repeat("f", 64), Status: status, Detail: "must-not-leak /private/root synthetic-secret", CheckedAt: r["checkedAt"].(string)}}
		write(r)
		result := s.filesystemRevocationTelemetry()
		want := "degraded"
		if status == "current" {
			want = "healthy"
		}
		encoded, _ := json.Marshal(result)
		if result["status"] != want || len(result) != 3 || strings.Contains(string(encoded), "/private/root") || strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(string(encoded), "app-one") || strings.Contains(string(encoded), strings.Repeat("f", 64)) {
			t.Fatal("Telemetry status or fixed redacted summary is incorrect", result)
		}
	}
	for _, mutate := range []func(map[string]any){
		func(r map[string]any) { r["checkedAt"] = time.Now().Add(time.Second).UTC().Format(time.RFC3339) },
		func(r map[string]any) { r["checkedAt"] = time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339) },
		func(r map[string]any) { r["checkedAt"] = "malformed" },
		func(r map[string]any) { r["checkIntervalSeconds"] = 0 },
		func(r map[string]any) { delete(r, "registryRevocationSupported") },
		func(r map[string]any) { r["registryRevocationSupported"] = true },
		func(r map[string]any) { r["results"] = nil },
		func(r map[string]any) { r["results"] = make([]filesystemRevocationResult, 258) },
		func(r map[string]any) {
			r["results"] = []filesystemRevocationResult{{Status: "healthy", CheckedAt: r["checkedAt"].(string)}}
		},
		func(r map[string]any) {
			r["results"] = []filesystemRevocationResult{{Status: "current", CheckedAt: r["checkedAt"].(string)}}
		},
		func(r map[string]any) {
			r["results"] = []filesystemRevocationResult{{Status: "unavailable", CheckedAt: time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339)}}
		},
		func(r map[string]any) {
			r["results"] = []filesystemRevocationResult{{Status: "unavailable", CheckedAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}}
		},
		func(r map[string]any) {
			r["results"] = []filesystemRevocationResult{{Status: "unavailable", CheckedAt: r["checkedAt"].(string), ContainerID: "short-id"}}
		},
	} {
		r := base()
		mutate(r)
		write(r)
		if result := s.filesystemRevocationTelemetry(); result["status"] != "unavailable" {
			t.Fatal("Malformed or stale report implied a verified status", result)
		}
	}
	if err := os.WriteFile(file, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if s.filesystemRevocationTelemetry()["status"] != "unavailable" {
		t.Fatal("Malformed report implied health")
	}
}
