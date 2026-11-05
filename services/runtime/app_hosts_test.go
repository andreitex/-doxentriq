package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type appHostsFixture struct {
	observation                      *observationFixture
	name, resource, id, desiredImage string
	target                           tlsContainer
	hosts                            []string
	expected                         []string
	absent                           bool
	removed                          [][]string
	inspectIDChanged                 bool
	refuseRemoval                    bool
}

func newAppHostsFixture(t *testing.T, preview bool) *appHostsFixture {
	t.Helper()
	o := newObservationFixture(t, "local")
	var receipt Verification
	receiptPath := filepath.Join(o.server.data, "receipts", "attempt1.json")
	if readBoundedJSON(receiptPath, &receipt) != nil {
		t.Fatal("Immutable fixture receipt unavailable")
	}
	for _, name := range mandatoryStages {
		receipt.Evidence.Checks = append(receipt.Evidence.Checks, Check{Name: name, Passed: true, Detail: "Synthetic independently completed stage"})
	}
	if atomicJSON(receiptPath, receipt) != nil {
		t.Fatal("Immutable fixture receipt could not retain stage evidence")
	}
	f := &appHostsFixture{observation: o, name: "as-app-app1-previous001", resource: "app1", id: strings.Repeat("d", 64), desiredImage: o.current.Image, hosts: []string{"mysql:172.30.2.2", "redis:172.30.2.3", "rabbitmq:172.30.2.4"}, expected: []string{"--add-host", "mysql:172.30.2.2", "--add-host", "redis:172.30.2.3", "--add-host", "rabbitmq:172.30.2.4"}}
	f.target = o.inspected
	f.target.ID, f.target.Name, f.target.State.Running = f.id, "/"+f.name, false
	if preview {
		f.name, f.resource = "as-preview-app1", "app1_preview"
		f.target.Name, f.target.State.Running = "/"+f.name, true
		f.target.Mounts[0].Source = filepath.Join(o.server.hostRuntime, "secrets", f.resource)
		f.desiredImage = "registry.internal/apps/app1@sha256:" + strings.Repeat("e", 64)
	}
	o.server.runner = func(_ context.Context, executable string, args ...string) (string, error) {
		if executable != "docker" || len(args) == 0 {
			t.Fatalf("Unexpected host action: %s %v", executable, args)
		}
		switch args[0] {
		case "ps":
			want := []string{"ps", "--all", "--no-trunc", "--filter", "name=^/" + f.name + "$", "--format", "{{.ID}}"}
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("Container discovery escaped exact name: %v", args)
			}
			if f.absent {
				return "", nil
			}
			return f.id, nil
		case "inspect":
			if len(args) != 4 || args[1] != "--format" || args[2] != "{{json .}}" || (args[3] != f.name && args[3] != f.id) {
				t.Fatalf("Unscoped inspect: %v", args)
			}
			b, _ := json.Marshal(f.target)
			var value map[string]any
			_ = json.Unmarshal(b, &value)
			value["HostConfig"] = map[string]any{"ExtraHosts": f.hosts}
			if args[3] == f.id && f.inspectIDChanged {
				value["Id"] = strings.Repeat("f", 64)
				delete(value, "ID")
			}
			b, _ = json.Marshal(value)
			return string(b), nil
		case "rm":
			f.removed = append(f.removed, append([]string(nil), args...))
			if f.refuseRemoval {
				return "", errors.New("Synthetic running-container race")
			}
			f.absent = true
			return "", nil
		}
		t.Fatalf("Unexpected container mutation: %v", args)
		return "", nil
	}
	return f
}

func (f *appHostsFixture) reconcile(preview bool) (bool, bool, error) {
	return f.observation.server.reconcileExistingAppHosts(context.Background(), f.name, "app1", f.resource, f.desiredImage, f.expected, preview)
}

func TestExistingAppHostsReuseExactMappingsWithoutDeletingOrStarting(t *testing.T) {
	f := newAppHostsFixture(t, false)
	f.hosts = []string{"rabbitmq:172.30.2.4", "mysql:172.30.2.2", "redis:172.30.2.3"}
	exists, removed, err := f.reconcile(false)
	if err != nil || !exists || removed || len(f.removed) != 0 {
		t.Fatalf("Exact unordered host mappings were not retained: %v %v %v", exists, removed, err)
	}
	f.absent = true
	exists, removed, err = f.reconcile(false)
	if err != nil || exists || removed {
		t.Fatalf("Independently absent container was not a fresh start: %v %v %v", exists, removed, err)
	}
}

func TestExistingAppHostsRecreateOnlyStoppedInactiveExactContainerWithoutVolumes(t *testing.T) {
	f := newAppHostsFixture(t, false)
	f.hosts[0] = "mysql:172.30.2.9"
	businessFile := filepath.Join(f.observation.server.data, "documents", "business-record")
	if err := os.MkdirAll(filepath.Dir(businessFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(businessFile, []byte("preserve-document"), 0600); err != nil {
		t.Fatal(err)
	}
	exists, removed, err := f.reconcile(false)
	if err != nil || !exists || !removed || !reflect.DeepEqual(f.removed, [][]string{{"rm", f.id}}) {
		t.Fatalf("Stopped inactive container not recreated by immutable ID: %v %v %v %v", exists, removed, err, f.removed)
	}
	if value, err := os.ReadFile(businessFile); err != nil || string(value) != "preserve-document" {
		t.Fatal("Application data was removed during container reconciliation")
	}
	var active activeDeployment
	if readBoundedJSON(filepath.Join(f.observation.server.data, "active", "app1.json"), &active) != nil || active.Container != f.observation.current.Container {
		t.Fatal("Current publication was changed")
	}
}

func TestExistingAppHostsKeepRunningActiveAmbiguousOrUnverifiedContainers(t *testing.T) {
	for _, mutation := range []string{"running", "active", "route", "missing_active", "source", "image", "mount", "identity", "inspect_race", "extra_mapping", "duplicate_mapping"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAppHostsFixture(t, false)
			f.hosts[0] = "mysql:172.30.2.9"
			switch mutation {
			case "running":
				f.target.State.Running = true
			case "active":
				f.observation.current.Container = f.name
				_ = atomicJSON(filepath.Join(f.observation.server.data, "active", "app1.json"), f.observation.current)
			case "route":
				f.observation.routed = false
			case "missing_active":
				_ = os.Remove(filepath.Join(f.observation.server.data, "active", "app1.json"))
			case "source":
				_ = os.WriteFile(filepath.Join(f.observation.server.data, "sources", "attempt1", "unreviewed.mjs"), []byte("changed"), 0600)
			case "image":
				f.target.Config.Image = "registry.internal/other@sha256:" + strings.Repeat("f", 64)
			case "mount":
				f.target.Mounts[0].RW = true
			case "identity":
				f.target.Config.Labels["io.autosoft.app"] = "other-app"
			case "inspect_race":
				f.inspectIDChanged = true
			case "extra_mapping":
				f.target.State.Running = true
				f.hosts = append(f.hosts, "metadata.google.internal:169.254.169.254")
			case "duplicate_mapping":
				f.target.State.Running = true
				f.hosts = append(f.hosts, f.hosts[0])
			}
			exists, removed, err := f.reconcile(false)
			if err == nil || !exists || removed || len(f.removed) != 0 {
				t.Fatalf("Unsafe container was removed/reused: %v %v %v %v", exists, removed, err, f.removed)
			}
		})
	}
}

func TestExistingAppHostsReplaceOnlyIndependentlyVerifiedOwnedPreviewImage(t *testing.T) {
	f := newAppHostsFixture(t, true)
	exists, removed, err := f.reconcile(true)
	if err != nil || !exists || !removed || !reflect.DeepEqual(f.removed, [][]string{{"rm", "--force", f.id}}) {
		t.Fatalf("Owned prior preview could not be replaced with a new image: %v %v %v %v", exists, removed, err, f.removed)
	}
	for _, mutation := range []string{"source", "receipt", "ownership", "public_resource"} {
		f := newAppHostsFixture(t, true)
		switch mutation {
		case "source":
			_ = os.WriteFile(filepath.Join(f.observation.server.data, "sources", "attempt1", "extra-file"), []byte("unverified"), 0600)
		case "receipt":
			_ = os.Remove(filepath.Join(f.observation.server.data, "receipts", "attempt1.json"))
		case "ownership":
			f.target.Config.Labels["io.autosoft.app"] = "other-app"
		case "public_resource":
			f.resource = "app1"
		}
		_, removed, err := f.reconcile(true)
		if err == nil || removed || len(f.removed) != 0 {
			t.Fatalf("Unverified preview was removed: %s", mutation)
		}
	}
}

func TestExistingAppHostsRejectMalformedExpectedMappingsAndStopOnRemovalRace(t *testing.T) {
	for _, args := range [][]string{nil, {"--network", "host"}, {"--add-host", "mysql:127.0.0.11"}, {"--add-host", "mysql:172.30.2.2", "--add-host", "mysql:172.30.2.3"}, {"--add-host", "mysql=172.30.2.2"}} {
		f := newAppHostsFixture(t, false)
		f.expected = args
		if _, _, err := f.reconcile(false); err == nil || len(f.removed) != 0 {
			t.Fatal("Untrusted expected mapping entered reconciliation")
		}
	}
	f := newAppHostsFixture(t, false)
	f.hosts[0] = "mysql:172.30.2.9"
	f.refuseRemoval = true
	_, removed, err := f.reconcile(false)
	if err == nil || removed || !reflect.DeepEqual(f.removed, [][]string{{"rm", f.id}}) {
		t.Fatal("Stopped-to-running race was forcefully removed or treated as success")
	}
}

func TestExistingPreviewDeletionAllowsPackagedFailedAcceptanceWithoutGrantingExecution(t *testing.T) {
	for _, failedStage := range []string{"preview", "acceptance"} {
		f := newAppHostsFixture(t, true)
		path := filepath.Join(f.observation.server.data, "receipts", "attempt1.json")
		var receipt Verification
		if readBoundedJSON(path, &receipt) != nil {
			t.Fatal("Receipt unavailable")
		}
		receipt.Evidence.Status = "failed"
		for index := range receipt.Evidence.Checks {
			if receipt.Evidence.Checks[index].Name == failedStage {
				receipt.Evidence.Checks[index].Passed = false
			}
		}
		if atomicJSON(path, receipt) != nil {
			t.Fatal("Failed receipt unavailable")
		}
		if _, err := f.observation.server.tlsManifest("app1", f.target.Config.Image); err == nil {
			t.Fatal("Failed preview obtained execution/certificate reconciliation provenance")
		}
		_, removed, err := f.reconcile(true)
		if err != nil || !removed || !reflect.DeepEqual(f.removed, [][]string{{"rm", "--force", f.id}}) {
			t.Fatalf("Exact packaged failed preview could not be cleaned for repair: %s %v", failedStage, err)
		}
		var preserved Verification
		if readBoundedJSON(path, &preserved) != nil || !reflect.DeepEqual(preserved, receipt) {
			t.Fatal("Failed evidence was changed or promoted")
		}
	}
	for _, missingStage := range []string{"dependencies", "build", "application_tests", "security", "image_packaging"} {
		f := newAppHostsFixture(t, true)
		path := filepath.Join(f.observation.server.data, "receipts", "attempt1.json")
		var receipt Verification
		_ = readBoundedJSON(path, &receipt)
		receipt.Evidence.Status = "failed"
		for index := range receipt.Evidence.Checks {
			if receipt.Evidence.Checks[index].Name == missingStage {
				receipt.Evidence.Checks[index].Passed = false
			}
		}
		_ = atomicJSON(path, receipt)
		if _, removed, err := f.reconcile(true); err == nil || removed || len(f.removed) != 0 {
			t.Fatalf("Missing package/source/security provenance allowed cleanup: %s", missingStage)
		}
	}
}

func TestTLSManifestRejectsSourceTamperingAndMissingSourceHashes(t *testing.T) {
	f := newTLSRotationFixture(t, false, 90)
	if _, err := f.server.tlsManifest(f.appID, f.image); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.server.data, "receipts", "attempt1.json")
	var receipt Verification
	_ = readBoundedJSON(path, &receipt)
	receipt.SourceHash = ""
	_ = atomicJSON(path, receipt)
	if _, err := f.server.tlsManifest(f.appID, f.image); err == nil {
		t.Fatal("Missing source hash obtained manifest authority")
	}
	receipt.SourceHash, _ = sourceDigest(filepath.Join(f.server.data, "sources", "attempt1"))
	_ = atomicJSON(path, receipt)
	_ = os.WriteFile(filepath.Join(f.server.data, "sources", "attempt1", "unverified-change"), []byte("tampered"), 0600)
	if _, err := f.server.tlsManifest(f.appID, f.image); err == nil {
		t.Fatal("Changed preserved source obtained manifest authority")
	}
}
