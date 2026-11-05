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

type retirementFixture struct {
	observation            *observationFixture
	previous               activeDeployment
	container              tlsContainer
	receipt                deployReceipt
	discovered             string
	confirmStop            bool
	stopCount              int
	changePointerOnInspect bool
}

func newRetirementFixture(t *testing.T) *retirementFixture {
	t.Helper()
	o := newObservationFixture(t, "local")
	f := &retirementFixture{observation: o, discovered: strings.Repeat("e", 64), confirmStop: true}
	f.previous = activeDeployment{Hash: strings.Repeat("f", 64), OperationID: "publication-prior", ReleaseID: "previous001", Container: "as-app-app1-previous1", Image: "registry.internal/apps/app1@sha256:" + strings.Repeat("d", 64), Schema: 1, URL: o.current.URL}
	var manifest AppManifest
	if err := readBoundedJSON(filepath.Join(o.server.data, "sources", "attempt1", "app.manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Kind = "worker"
	source := filepath.Join(o.server.data, "sources", "attempt-prior")
	if err := atomicJSON(filepath.Join(source, "app.manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := sourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	verified := Verification{AppID: "app1", AttemptID: "attempt-prior", Template: "node-web", Images: []string{f.previous.Image}, SourceHash: digest, Schema: 1, SchemaMin: 1, SchemaMax: 1, Evidence: Evidence{Status: "passed"}}
	if err = atomicJSON(filepath.Join(o.server.data, "receipts", "attempt-prior.json"), verified); err != nil {
		t.Fatal(err)
	}
	prior := deployReceipt{OperationID: f.previous.OperationID, Hash: f.previous.Hash, ApprovalID: "approval-prior", Healthy: true, Phase: "completed", AppID: "app1", ReleaseID: f.previous.ReleaseID, AttemptID: "attempt-prior", Schema: 1}
	if err = atomicJSON(filepath.Join(o.server.data, "operations", prior.OperationID+".json"), prior); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(o.inspected)
	if err = json.Unmarshal(b, &f.container); err != nil {
		t.Fatal(err)
	}
	f.container.ID, f.container.Name, f.container.Config.Image = f.discovered, "/"+f.previous.Container, f.previous.Image
	o.current.Previous = &f.previous
	if err = atomicJSON(filepath.Join(o.server.data, "active", "app1.json"), o.current); err != nil {
		t.Fatal(err)
	}
	f.receipt = deployReceipt{OperationID: o.current.OperationID, Hash: o.current.Hash, ApprovalID: "approval1", Phase: "started", AppID: "app1", ReleaseID: o.current.ReleaseID, AttemptID: "attempt1", PreviousRuntime: &retirementBinding{ID: f.container.ID, Name: f.previous.Container, Image: f.previous.Image, ReleaseID: f.previous.ReleaseID, Hash: f.previous.Hash, OperationID: f.previous.OperationID}}
	o.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
		if command != "docker" || len(args) == 0 {
			t.Fatal("Unexpected retirement command")
		}
		switch args[0] {
		case "ps":
			if !reflect.DeepEqual(args, []string{"ps", "--all", "--no-trunc", "--filter", "name=^/" + f.previous.Container + "$", "--format", "{{.ID}}"}) {
				t.Fatal("Retirement discovery escaped original name")
			}
			return f.discovered, nil
		case "inspect":
			if len(args) != 4 {
				t.Fatal("Unexpected inspect")
			}
			if args[3] == o.current.Container {
				b, _ := json.Marshal(o.inspected)
				return string(b), nil
			}
			if args[3] != f.previous.Container && args[3] != f.container.ID {
				t.Fatal("Retirement inspection escaped original identity")
			}
			if f.changePointerOnInspect {
				next := o.current
				next.OperationID = "different-operation"
				_ = atomicJSON(filepath.Join(o.server.data, "active", "app1.json"), next)
			}
			b, _ := json.Marshal(f.container)
			return string(b), nil
		case "stop":
			if ctx.Err() != nil || !reflect.DeepEqual(args, []string{"stop", "--time", "15", strings.Repeat("e", 64)}) {
				t.Fatal("Retirement used cancellation or mutable/replacement identity")
			}
			f.stopCount++
			if f.confirmStop {
				f.container.State.Running = false
			}
			return "", errors.New("Synthetic lost Docker response")
		case "exec":
			if args[1] != o.inspected.ID {
				t.Fatal("Retirement probed an unrelated runtime")
			}
			return "AUTOSOFT_HEALTHY", nil
		}
		t.Fatalf("Retirement performed an unapproved action: %v", args)
		return "", nil
	}
	return f
}

func TestRetirementConfirmsOnlyOriginalStoppedRuntimeAndPreservesData(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(map[bool]string{true: "running", false: "already_stopped"}[running], func(t *testing.T) {
			f := newRetirementFixture(t)
			f.container.State.Running = running
			file := filepath.Join(f.observation.server.data, "documents", "business-record")
			if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("preserved-current-data"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := f.observation.server.retirePreviousRuntime(ctx, f.receipt, f.observation.current); err != nil {
				t.Fatal(err)
			}
			if f.container.State.Running || f.stopCount != map[bool]int{true: 1, false: 0}[running] {
				t.Fatal("Original stop was not independently confirmed")
			}
			if b, err := os.ReadFile(file); err != nil || string(b) != "preserved-current-data" {
				t.Fatal("Retirement changed business data")
			}
		})
	}
}

func TestRetirementPreservesMissingReplacedForeignAndChangedState(t *testing.T) {
	for _, changed := range []string{"missing_binding", "binding_hash", "binding_image", "binding_operation", "binding_release", "binding_name", "invalid_id", "same_candidate", "missing_original", "replacement", "inspected_identity", "foreign_owner", "mount", "source", "schema", "publication_schema", "url", "active_pointer", "pointer_during_inspect"} {
		t.Run(changed, func(t *testing.T) {
			f := newRetirementFixture(t)
			o := f.observation
			switch changed {
			case "missing_binding":
				f.receipt.PreviousRuntime = nil
			case "binding_hash":
				f.receipt.PreviousRuntime.Hash = strings.Repeat("a", 64)
			case "binding_image":
				f.receipt.PreviousRuntime.Image = o.current.Image
			case "binding_operation":
				f.receipt.PreviousRuntime.OperationID = "another-operation"
			case "binding_release":
				f.receipt.PreviousRuntime.ReleaseID = "another-release"
			case "binding_name":
				f.receipt.PreviousRuntime.Name = "as-app-app1-another"
			case "invalid_id":
				f.receipt.PreviousRuntime.ID = "mutable-name"
			case "same_candidate":
				f.previous.Container = o.current.Container
				f.receipt.PreviousRuntime.Name = o.current.Container
			case "missing_original":
				f.discovered = ""
			case "replacement":
				f.discovered = strings.Repeat("9", 64)
			case "inspected_identity":
				f.container.ID = strings.Repeat("9", 64)
			case "foreign_owner":
				f.container.Config.Labels["io.autosoft.app"] = "foreign-app"
			case "mount":
				f.container.Mounts[0].RW = true
			case "source":
				if err := os.WriteFile(filepath.Join(o.server.data, "sources", "attempt-prior", "changed.txt"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "schema":
				f.previous.Schema = 2
			case "publication_schema":
				var p deployReceipt
				path := filepath.Join(o.server.data, "operations", f.previous.OperationID+".json")
				_ = readBoundedJSON(path, &p)
				p.Schema = 2
				_ = atomicJSON(path, p)
			case "url":
				f.previous.URL = "https://foreign.apps.test.internal"
			case "active_pointer":
				next := o.current
				next.OperationID = "another-operation"
				_ = atomicJSON(filepath.Join(o.server.data, "active", "app1.json"), next)
			case "pointer_during_inspect":
				f.changePointerOnInspect = true
			}
			if err := o.server.retirePreviousRuntime(context.Background(), f.receipt, o.current); err == nil {
				t.Fatal("Untrusted retirement was accepted")
			}
			if f.stopCount != 0 || !f.container.State.Running {
				t.Fatal("Missing/replaced/foreign runtime was changed")
			}
		})
	}
}

func TestUnconfirmedRetirementCannotCompleteHealthyCandidate(t *testing.T) {
	for _, changed := range []string{"running", "missing_binding", "replacement"} {
		t.Run(changed, func(t *testing.T) {
			f := newRetirementFixture(t)
			f.confirmStop = false
			if changed == "missing_binding" {
				f.receipt.PreviousRuntime = nil
			}
			if changed == "replacement" {
				f.discovered = strings.Repeat("9", 64)
			}
			if _, complete := f.observation.server.reconcileHealthyOperation(context.Background(), f.receipt); complete {
				t.Fatal("Healthy candidate bypassed previous retirement")
			}
			if !f.container.State.Running {
				t.Fatal("Unconfirmed previous runtime state changed")
			}
		})
	}
	f := newRetirementFixture(t)
	if _, complete := f.observation.server.reconcileHealthyOperation(context.Background(), f.receipt); !complete || f.container.State.Running || f.stopCount != 1 {
		t.Fatal("Confirmed previous retirement did not release completion")
	}
}

func TestFirstPublicationRequiresNoPreviousRetirementBinding(t *testing.T) {
	f := newRetirementFixture(t)
	f.observation.current.Previous = nil
	if err := f.observation.server.retirePreviousRuntime(context.Background(), f.receipt, f.observation.current); err == nil {
		t.Fatal("Unexpected retirement authority accepted on first deployment")
	}
	f.receipt.PreviousRuntime = nil
	if err := f.observation.server.retirePreviousRuntime(context.Background(), f.receipt, f.observation.current); err != nil {
		t.Fatal(err)
	}
	if f.stopCount != 0 {
		t.Fatal("First deployment retired a runtime")
	}
}
