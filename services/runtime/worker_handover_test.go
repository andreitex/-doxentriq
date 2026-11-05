package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type handoverFixture struct {
	observation       *observationFixture
	route, discovered string
	calls             [][]string
	writes            int
	routerUnavailable bool
}

func newHandoverFixture(t *testing.T) *handoverFixture {
	t.Helper()
	o := newObservationFixture(t, "local")
	f := &handoverFixture{observation: o, route: o.current.Container, discovered: o.inspected.ID}
	o.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
		f.calls = append(f.calls, append([]string{command}, args...))
		if command != "docker" || len(args) == 0 {
			t.Fatal("Unexpected host action")
		}
		switch args[0] {
		case "ps":
			if !reflect.DeepEqual(args, []string{"ps", "--all", "--no-trunc", "--filter", "name=^/" + o.current.Container + "$", "--format", "{{.ID}}"}) {
				t.Fatal("Previous discovery left exact owned name")
			}
			return f.discovered, nil
		case "inspect":
			if len(args) != 4 || (args[3] != o.current.Container && args[3] != o.inspected.ID) {
				t.Fatal("Previous inspect escaped its exact runtime")
			}
			b, _ := json.Marshal(o.inspected)
			return string(b), nil
		case "start", "stop", "exec":
			if ctx.Err() != nil {
				t.Fatal("Fallback inherited canceled request")
			}
			if args[0] == "start" && (len(args) != 2 || args[1] != o.inspected.ID) {
				t.Fatal("Previous restart used a mutable container name")
			}
			if args[0] == "stop" && !reflect.DeepEqual(args, []string{"stop", "--time", "15", o.inspected.ID}) {
				t.Fatal("Previous shutdown used a mutable identity")
			}
			if args[0] == "exec" && args[1] != o.inspected.ID {
				t.Fatal("Health probe used mutable identity")
			}
			if args[0] == "start" {
				o.inspected.State.Running = true
			}
			if args[0] == "stop" {
				o.inspected.State.Running = false
			}
			return "", nil
		}
		t.Fatalf("Unexpected Docker mutation: %v", args)
		return "", nil
	}
	o.server.routeProbe = func(_ context.Context, app, host, container string) (bool, error) {
		if app != "app1" || host != "documents.apps.test.internal" {
			t.Fatal("Fallback inspected another route")
		}
		if f.routerUnavailable {
			return false, errors.New("Synthetic router outage")
		}
		return f.route == container, nil
	}
	o.server.routeChange = func(ctx context.Context, app, host, container string, port int, preview bool) error {
		if ctx.Err() != nil || app != "app1" || host != "documents.apps.test.internal" || container != o.current.Container || port != 8080 || preview {
			t.Fatal("Fallback changed an unauthorized route")
		}
		f.writes++
		f.route = container
		return nil
	}
	return f
}

func TestPinnedPreviousRequiresPublishedSourceOwnershipAndActualRoute(t *testing.T) {
	for _, changed := range []string{"app", "image", "mount", "identity", "source", "route"} {
		t.Run(changed, func(t *testing.T) {
			f := newHandoverFixture(t)
			o := f.observation
			switch changed {
			case "app":
				o.inspected.Config.Labels["io.autosoft.app"] = "foreign"
			case "image":
				o.inspected.Config.Image = "registry.internal/foreign@sha256:" + strings.Repeat("f", 64)
			case "mount":
				o.inspected.Mounts[0].RW = true
			case "identity":
				f.discovered = strings.Repeat("d", 64)
			case "source":
				var m AppManifest
				path := filepath.Join(o.server.data, "sources", "attempt1", "app.manifest.json")
				_ = readBoundedJSON(path, &m)
				m.Slug = "changed"
				_ = atomicJSON(path, m)
			case "route":
				f.route = "foreign-runtime"
			}
			if p, err := o.server.pinPublishedRuntime(context.Background(), "app1", &o.current); err == nil || p != nil {
				t.Fatal("Changed previous runtime was pinned")
			}
			for _, call := range f.calls {
				if call[1] == "start" || call[1] == "stop" {
					t.Fatal("Invalid previous runtime mutated")
				}
			}
		})
	}
}

func TestPinnedFallbackRestoresActuallyChangedRouteAfterLostResponse(t *testing.T) {
	f := newHandoverFixture(t)
	o := f.observation
	p, err := o.server.pinPublishedRuntime(context.Background(), "app1", &o.current)
	if err != nil {
		t.Fatal(err)
	}
	o.inspected.State.Running = false
	f.route = "as-app-app1-candidate"
	if err = o.server.restorePinnedRuntime("app1", &o.current, p, f.route, true); err != nil {
		t.Fatal(err)
	}
	if !o.inspected.State.Running || f.route != o.current.Container || f.writes != 1 {
		t.Fatal("Previous owned healthy runtime/route was not confirmed restored")
	}
}

func TestPinnedFallbackPreservesUnexpectedStateAndManualStop(t *testing.T) {
	for _, changed := range []string{"foreign_route", "router_outage", "replacement", "mount", "active_pointer", "manual_stop"} {
		t.Run(changed, func(t *testing.T) {
			f := newHandoverFixture(t)
			o := f.observation
			if changed == "manual_stop" {
				o.inspected.State.Running = false
			}
			p, err := o.server.pinPublishedRuntime(context.Background(), "app1", &o.current)
			if err != nil {
				t.Fatal(err)
			}
			o.inspected.State.Running = false
			f.calls = nil
			switch changed {
			case "foreign_route":
				f.route = "another-published-runtime"
			case "router_outage":
				f.routerUnavailable = true
			case "replacement":
				f.discovered = strings.Repeat("d", 64)
			case "mount":
				o.inspected.Mounts[0].RW = true
			case "active_pointer":
				next := o.current
				next.ReleaseID = "other-release"
				_ = atomicJSON(filepath.Join(o.server.data, "active", "app1.json"), next)
			}
			err = o.server.restorePinnedRuntime("app1", &o.current, p, "as-app-app1-candidate", true)
			if (err == nil) != (changed == "manual_stop") {
				t.Fatalf("Unexpected fallback result: %v", err)
			}
			if o.inspected.State.Running || f.writes != 0 {
				t.Fatal("Unavailable/foreign/manual state was overridden")
			}
			for _, call := range f.calls {
				if call[1] == "start" {
					t.Fatal("Unsafe previous runtime restarted")
				}
			}
		})
	}
}

func TestPinnedPreviousShutdownRejectsReplacementBeforeMutation(t *testing.T) {
	f := newHandoverFixture(t)
	o := f.observation
	p, err := o.server.pinPublishedRuntime(context.Background(), "app1", &o.current)
	if err != nil {
		t.Fatal(err)
	}
	f.discovered = strings.Repeat("d", 64)
	f.calls = nil
	if err = o.server.stopRuntimeCandidate(p.Name, "app1", "app1", p.Image, p.ID); !candidateShutdownUncertain(err) {
		t.Fatal("Previous replacement could be stopped")
	}
	for _, call := range f.calls {
		if call[1] == "stop" {
			t.Fatal("Replaced previous runtime was stopped")
		}
	}
}
