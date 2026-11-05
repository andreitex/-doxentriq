package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func candidateStopFixture(t *testing.T, stopConfirmed bool) (*appHostsFixture, *[][]string) {
	t.Helper()
	f := newAppHostsFixture(t, false)
	f.target.State.Running = true
	original := f.observation.server.runner
	calls := [][]string{}
	f.observation.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
		calls = append(calls, append([]string{command}, args...))
		if len(args) > 0 && args[0] == "stop" {
			if ctx.Err() != nil || !reflect.DeepEqual(args, []string{"stop", "--time", "15", f.id}) {
				t.Fatal("Shutdown used a canceled request or mutable container name")
			}
			if stopConfirmed {
				f.target.State.Running = false
			}
			return "", errors.New("Synthetic ambiguous Docker response")
		}
		return original(ctx, command, args...)
	}
	return f, &calls
}

func TestFailedCandidateConfirmsExactShutdownBeforeWorkerRecovery(t *testing.T) {
	f, calls := candidateStopFixture(t, true)
	file := filepath.Join(f.observation.server.data, "documents", "business-record")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("preserve-current-data"), 0600); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("Synthetic candidate health failure")
	err := f.observation.server.failedCandidate(f.name, "app1", f.resource, f.desiredImage, cause)
	if err != cause || f.target.State.Running || candidateShutdownUncertain(err) {
		t.Fatalf("Confirmed stopped candidate did not retain its health failure: %v", err)
	}
	for _, call := range *calls {
		if strings.Contains(strings.Join(call, " "), " rm ") || strings.Contains(strings.Join(call, " "), " start ") {
			t.Fatal("Shutdown removed data or started a competing worker")
		}
	}
	if value, err := os.ReadFile(file); err != nil || string(value) != "preserve-current-data" {
		t.Fatal("Candidate failure changed business data")
	}
}

func TestFailedCandidateUnconfirmedShutdownRemainsPending(t *testing.T) {
	f, _ := candidateStopFixture(t, false)
	err := f.observation.server.failedCandidate(f.name, "app1", f.resource, f.desiredImage, errors.New("Synthetic health failure"))
	if !candidateShutdownUncertain(err) || !f.target.State.Running {
		t.Fatal("Running candidate permitted recovery of a competing previous worker")
	}
}

func TestFailedCandidatePreservesChangedOwnershipAndIdentity(t *testing.T) {
	for _, changed := range []string{"app", "image", "mount", "immutable_id"} {
		t.Run(changed, func(t *testing.T) {
			f, calls := candidateStopFixture(t, true)
			switch changed {
			case "app":
				f.target.Config.Labels["io.autosoft.app"] = "another-app"
			case "image":
				f.target.Config.Image = "registry.internal/apps/app1@sha256:" + strings.Repeat("f", 64)
			case "mount":
				f.target.Mounts[0].RW = true
			case "immutable_id":
				f.target.ID = strings.Repeat("e", 64)
			}
			if err := f.observation.server.stopFailedCandidate(f.name, "app1", f.resource, f.desiredImage); !candidateShutdownUncertain(err) {
				t.Fatal("Changed candidate identity qualified for shutdown")
			}
			for _, call := range *calls {
				if len(call) > 1 && call[1] == "stop" {
					t.Fatal("Changed candidate was stopped")
				}
			}
		})
	}
}

func TestRestartedHistoricalWorkerHealthFailureStopsCandidateDespiteCancellation(t *testing.T) {
	for _, confirmed := range []bool{true, false} {
		t.Run(map[bool]string{true: "confirmed", false: "unconfirmed"}[confirmed], func(t *testing.T) {
			f, calls := candidateStopFixture(t, confirmed)
			f.id, f.target.ID = strings.Repeat("7", 64), strings.Repeat("7", 64)
			services := newServiceHostsFixture(t)
			s := f.observation.server
			s.manifest.ServiceImages = services.server.manifest.ServiceImages
			original := s.runner
			s.runner = func(ctx context.Context, command string, args ...string) (string, error) {
				if len(args) > 0 && args[0] == "network" || len(args) > 1 && args[0] == "ps" && strings.Contains(strings.Join(args, " "), "label=com.docker.compose.service=") || len(args) == 4 && args[0] == "inspect" && args[3] != f.name && args[3] != f.id {
					return services.server.runner(ctx, command, args...)
				}
				if len(args) > 0 && args[0] == "start" {
					*calls = append(*calls, append([]string{command}, args...))
					f.target.State.Running = true
					return "", nil
				}
				if len(args) > 0 && args[0] == "exec" {
					return "", errors.New("Synthetic historical worker health failure")
				}
				return original(ctx, command, args...)
			}
			m := AppManifest{ID: "app1", Slug: "documents", Kind: "worker", Template: "node-web"}
			v := resources{AppID: "app1", Network: services.network.Name, Secrets: t.TempDir()}
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // No 90-second wait; cleanup must use its separate bounded context.
			err := s.startApp(ctx, f.name, f.desiredImage, m, v, false)
			if err == nil || candidateShutdownUncertain(err) == confirmed || f.target.State.Running == confirmed {
				t.Fatalf("Historical worker shutdown result was unsafe: %v, running=%v", err, f.target.State.Running)
			}
		})
	}
}
