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

type appHostDiagnosticsFixture struct {
	observation *observationFixture
	services    *serviceHostsFixture
	manifest    AppManifest
	hosts       []string
	network     string
	inspections int
	race        bool
}

func newAppHostDiagnosticsFixture(t *testing.T) *appHostDiagnosticsFixture {
	t.Helper()
	o := newObservationFixture(t, "local")
	o.inspected.ID = strings.Repeat("1", 64)
	h := newServiceHostsFixture(t)
	f := &appHostDiagnosticsFixture{observation: o, services: h, hosts: []string{"mysql:172.30.2.2", "redis:172.30.2.3", "rabbitmq:172.30.2.4"}}
	f.network = "autosoft_app_" + hashBytes([]byte("app1"))[:24]
	h.network.Name = f.network
	for name, service := range h.containers {
		endpoint := service.NetworkSettings.Networks["autosoft_app_1234"]
		delete(service.NetworkSettings.Networks, "autosoft_app_1234")
		service.NetworkSettings.Networks[f.network] = endpoint
		h.containers[name] = service
	}
	o.server.manifest = h.server.manifest
	if readBoundedJSON(filepath.Join(o.server.data, "sources", "attempt1", "app.manifest.json"), &f.manifest) != nil {
		t.Fatal("Fixture manifest missing")
	}
	base := o.server.runner
	o.server.runner = func(ctx context.Context, executable string, args ...string) (string, error) {
		if executable != "docker" || len(args) == 0 {
			t.Fatalf("Unexpected host action: %s %v", executable, args)
		}
		if args[0] == "inspect" && len(args) == 4 && (args[3] == o.current.Container || args[3] == o.inspected.ID) {
			if args[3] == o.inspected.ID {
				f.inspections++
			}
			encoded, _ := json.Marshal(o.inspected)
			var actual map[string]any
			_ = json.Unmarshal(encoded, &actual)
			actual["HostConfig"] = map[string]any{"NetworkMode": f.network, "ExtraHosts": f.hosts}
			if f.race && f.inspections == 2 {
				actual["Name"] = "/unexpected-replacement"
			}
			encoded, _ = json.Marshal(actual)
			return string(encoded), nil
		}
		if args[0] == "exec" {
			return base(ctx, executable, args...)
		}
		if args[0] != "network" && args[0] != "ps" && args[0] != "inspect" {
			t.Fatalf("Read-only diagnostic attempted a mutation: %v", args)
		}
		return h.server.runner(ctx, executable, args...)
	}
	return f
}

func TestHostDriftObservationExplainsInfrastructureFailureWithoutRequestingCodeRollback(t *testing.T) {
	f := newAppHostDiagnosticsFixture(t)
	f.hosts[0] = "mysql:172.30.2.9"
	f.observation.probe = "AUTOSOFT_UNHEALTHY"
	result := observeFixture(t, f.observation)
	if result.Status != "unavailable" || !strings.Contains(result.Detail, "mysql") || !strings.Contains(result.Detail, "platform operator") || strings.Contains(result.Detail, "172.30.") {
		t.Fatalf("Confirmed service drift was not reported safely: %+v", result)
	}
	if result.Hash != f.observation.current.Hash || result.ReleaseID != f.observation.current.ReleaseID || result.EvidenceHash == "" {
		t.Fatal("Network diagnosis changed the exact observed release identity")
	}
	calls := len(f.services.calls)
	inspections := f.inspections
	f.hosts[0] = "mysql:172.30.2.2"
	if replay := observeFixture(t, f.observation); !reflect.DeepEqual(replay, result) || len(f.services.calls) != calls || f.inspections != inspections {
		t.Fatal("Replaying an observation repeated diagnosis or changed retained evidence")
	}
}

func TestHostDriftDiagnosisDoesNotChangeHealthyOrUnrelatedAppFailure(t *testing.T) {
	f := newAppHostDiagnosticsFixture(t)
	f.hosts[0] = "mysql:172.30.2.9"
	if result := observeFixture(t, f.observation); result.Status != "healthy" || len(f.services.calls) != 0 || f.inspections != 0 {
		t.Fatal("Healthy observation unnecessarily inspected infrastructure")
	}
	f = newAppHostDiagnosticsFixture(t)
	f.observation.probe = "AUTOSOFT_UNHEALTHY"
	if result := observeFixture(t, f.observation); result.Status != "unhealthy" || strings.Contains(result.Detail, "saved network") {
		t.Fatal("Current infrastructure mappings hid a measured application failure")
	}
}

func TestHostDriftDiagnosisWorksForStoppedExactPublishedContainer(t *testing.T) {
	f := newAppHostDiagnosticsFixture(t)
	f.observation.inspected.State.Running = false
	f.hosts[1] = "redis:172.30.2.9"
	result := observeFixture(t, f.observation)
	if result.Status != "unavailable" || !strings.Contains(result.Detail, "redis") {
		t.Fatalf("Stopped published app's stale service binding was not diagnosed: %+v", result)
	}
}

func TestHostDriftDiagnosisNeverTrustsUnqualifiedOrAmbiguousEvidence(t *testing.T) {
	for _, mutation := range []string{"wrong_network", "duplicate_host", "invalid_host", "missing_service", "service_image", "service_ownership", "service_membership", "service_down", "container_race", "container_image", "manifest_scope"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAppHostDiagnosticsFixture(t)
			f.hosts[0] = "mysql:172.30.2.9"
			container := f.observation.inspected
			service := f.services.containers["mysql"]
			switch mutation {
			case "wrong_network":
				f.network = "autosoft_app_another"
			case "duplicate_host":
				f.hosts = append(f.hosts, "mysql:172.30.2.2")
			case "invalid_host":
				f.hosts[0] = "mysql:127.0.0.1"
			case "missing_service":
				delete(f.observation.server.manifest.ServiceImages, "mysql")
			case "service_image":
				service.Config.Image = "mysql:latest"
			case "service_ownership":
				service.Config.Labels["io.autosoft.managed"] = "false"
			case "service_membership":
				delete(f.services.network.Containers, service.ID)
			case "service_down":
				service.State.Running = false
			case "container_race":
				f.race = true
			case "container_image":
				container.Config.Image = "registry.internal/app@sha256:" + strings.Repeat("e", 64)
			case "manifest_scope":
				f.manifest.ID = "another-app"
			}
			f.services.containers["mysql"] = service
			changed, err := f.observation.server.publishedServiceHostDrift(context.Background(), "app1", container, f.manifest)
			if err == nil || len(changed) != 0 {
				t.Fatalf("Uncertain evidence claimed verified drift: %v %v", changed, err)
			}
		})
	}
}

func TestHostDriftDiagnosisHandlesMissingRequiredMappingAndScopedExtraAliases(t *testing.T) {
	f := newAppHostDiagnosticsFixture(t)
	f.hosts = []string{"redis:172.30.2.3", "rabbitmq:172.30.2.4", "connector-app1.internal:172.30.2.20"}
	changed, err := f.observation.server.publishedServiceHostDrift(context.Background(), "app1", f.observation.inspected, f.manifest)
	if err != nil || len(changed) != 1 || changed[0] != "mysql" {
		t.Fatalf("Missing infrastructure mapping was not independently diagnosed: %v %v", changed, err)
	}
	f.hosts = nil
	changed, err = f.observation.server.publishedServiceHostDrift(context.Background(), "app1", f.observation.inspected, f.manifest)
	if err != nil || !reflect.DeepEqual(changed, []string{"mysql", "redis", "rabbitmq"}) {
		t.Fatalf("Missing complete infrastructure mappings were not diagnosed: %v %v", changed, err)
	}
}

func TestHostDriftDiagnosisIncludesDirectoryServiceOnlyForProtectedApps(t *testing.T) {
	t.Setenv("APP_DIRECTORY_AUTHORIZATION_ENABLED", "1")
	f := newAppHostDiagnosticsFixture(t)
	service := f.services.containers["mysql"]
	service.ID, service.Name = strings.Repeat("6", 64), "/autosoft-control-1"
	labels := map[string]string{}
	for key, value := range service.Config.Labels {
		labels[key] = value
	}
	labels["com.docker.compose.service"] = "control"
	service.Config.Labels = labels
	service.NetworkSettings.Networks = map[string]struct{ IPAddress, NetworkID string }{f.network: {IPAddress: "172.30.2.8", NetworkID: f.services.network.ID}}
	f.services.containers["control"], f.services.results["control"] = service, service.ID
	f.observation.server.manifest.ServiceImages["control"] = service.Config.Image
	f.services.network.Containers[service.ID] = struct{ IPv4Address string }{"172.30.2.8/24"}
	f.hosts = append(f.hosts, "control:172.30.2.9")
	changed, err := f.observation.server.publishedServiceHostDrift(context.Background(), "app1", f.observation.inspected, f.manifest)
	if err != nil || !reflect.DeepEqual(changed, []string{"control"}) {
		t.Fatalf("Protected directory service drift was not diagnosed: %v %v", changed, err)
	}
	f.manifest.Auth = "public"
	changed, err = f.observation.server.publishedServiceHostDrift(context.Background(), "app1", f.observation.inspected, f.manifest)
	if err != nil || len(changed) != 0 {
		t.Fatal("Public app was diagnosed against an unused directory service")
	}
}

func TestHostDriftDiagnosisDoesNotInventCauseWhenDockerIsUnavailable(t *testing.T) {
	f := newAppHostDiagnosticsFixture(t)
	f.observation.probeError = errors.New("Synthetic unavailable runtime")
	base := f.observation.server.runner
	f.observation.server.runner = func(ctx context.Context, executable string, args ...string) (string, error) {
		if args[0] == "network" {
			return "", errors.New("Synthetic unavailable inspection")
		}
		return base(ctx, executable, args...)
	}
	result := observeFixture(t, f.observation)
	if result.Status != "unavailable" || strings.Contains(result.Detail, "saved network") {
		t.Fatal("Unavailable infrastructure evidence became a confirmed network cause")
	}
}
