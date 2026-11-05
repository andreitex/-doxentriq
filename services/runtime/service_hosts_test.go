package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func qualifiedServiceCatalog() RuntimeManifest {
	images := map[string]string{}
	for _, name := range []string{"mysql", "redis", "rabbitmq", "registry", "dependency-proxy", "keycloak", "control", "worker", "broker", "packager", "caddy", "prometheus", "loki", "grafana", "otel"} {
		images[name] = "registry:5000/company/" + name + "@sha256:" + strings.Repeat("a", 64)
	}
	images["worker"] = images["control"]
	images["packager"] = images["broker"]
	return RuntimeManifest{ServiceImages: images}
}

func TestValidateServiceCatalogAcceptsCompanyAliasesAndSharedImages(t *testing.T) {
	m := qualifiedServiceCatalog()
	if err := validateServiceCatalog(m); err != nil {
		t.Fatalf("Qualified company catalog rejected: %v", err)
	}
	minimum := RuntimeManifest{ServiceImages: map[string]string{}}
	for _, required := range []string{"mysql", "redis", "rabbitmq", "registry", "dependency-proxy"} {
		minimum.ServiceImages[required] = m.ServiceImages[required]
	}
	if err := validateServiceCatalog(minimum); err != nil {
		t.Fatalf("All required pinned infrastructure aliases rejected: %v", err)
	}
}

func TestValidateServiceCatalogRequiresEveryInfrastructureImage(t *testing.T) {
	for _, required := range []string{"mysql", "redis", "rabbitmq", "registry", "dependency-proxy"} {
		t.Run(required, func(t *testing.T) {
			m := qualifiedServiceCatalog()
			delete(m.ServiceImages, required)
			if err := validateServiceCatalog(m); err == nil {
				t.Fatal("Incomplete infrastructure catalog can start")
			}
		})
	}
	if err := validateServiceCatalog(RuntimeManifest{}); err == nil {
		t.Fatal("Missing company catalog can start")
	}
}

func TestValidateServiceCatalogRejectsUnqualifiedAndUnboundedReferences(t *testing.T) {
	for name, image := range map[string]string{
		"empty": "", "tag": "mysql:8.4", "short_digest": "mysql@sha256:abcd",
		"uppercase_digest": "mysql@sha256:" + strings.Repeat("A", 64),
		"whitespace":       "mysql@sha256:" + strings.Repeat("a", 64) + "\n",
		"shell_text":       "mysql@sha256:" + strings.Repeat("a", 64) + "; echo secret",
		"oversized":        strings.Repeat("a", 513) + "@sha256:" + strings.Repeat("a", 64),
	} {
		t.Run(name, func(t *testing.T) {
			m := qualifiedServiceCatalog()
			m.ServiceImages["mysql"] = image
			if err := validateServiceCatalog(m); err == nil {
				t.Fatal("Invalid company service image accepted")
			}
		})
	}
}

func TestValidateServiceCatalogRejectsArbitraryServiceAliases(t *testing.T) {
	for _, name := range []string{"generated-app", "metadata", "dependency_proxy", "MySQL", "mysql:127.0.0.1", "mysql\n", strings.Repeat("a", 64)} {
		t.Run(name, func(t *testing.T) {
			m := qualifiedServiceCatalog()
			m.ServiceImages[name] = m.ServiceImages["mysql"]
			if err := validateServiceCatalog(m); err == nil {
				t.Fatal("Arbitrary service alias entered company catalog")
			}
		})
	}
	m := qualifiedServiceCatalog()
	for len(m.ServiceImages) <= 32 {
		m.ServiceImages["extra-"+strings.Repeat("a", len(m.ServiceImages))] = m.ServiceImages["mysql"]
	}
	if err := validateServiceCatalog(m); err == nil {
		t.Fatal("Oversized service catalog accepted")
	}
}

type serviceHostsFixture struct {
	server     *server
	network    serviceNetworkInspection
	containers map[string]serviceContainerInspection
	results    map[string]string
	calls      [][]string
}

func newServiceHostsFixture(t *testing.T) *serviceHostsFixture {
	t.Helper()
	f := &serviceHostsFixture{containers: map[string]serviceContainerInspection{}, results: map[string]string{}}
	f.network.ID, f.network.Name, f.network.Driver, f.network.Internal = strings.Repeat("a", 64), "autosoft_app_1234", "bridge", true
	f.network.Labels = map[string]string{"io.autosoft.managed": "true"}
	f.network.IPAM.Config = []struct{ Subnet string }{{Subnet: "172.30.2.0/24"}}
	f.network.Containers = map[string]struct{ IPv4Address string }{}
	f.server = &server{manifest: RuntimeManifest{ServiceImages: map[string]string{}}}
	for index, name := range []string{"mysql", "redis", "rabbitmq"} {
		id := strings.Repeat(string(rune('b'+index)), 64)
		image := "registry:5000/" + name + "@sha256:" + strings.Repeat(string(rune('d'+index)), 64)
		address := []string{"172.30.2.2", "172.30.2.3", "172.30.2.4"}[index]
		c := serviceContainerInspection{ID: id, Name: "/autosoft-" + name + "-1"}
		c.State.Running = true
		c.Config.Image = image
		c.Config.Labels = map[string]string{"com.docker.compose.project": "autosoft", "com.docker.compose.service": name, "com.docker.compose.oneoff": "False", "com.docker.compose.container-number": "1", "io.autosoft.managed": "true"}
		c.HostConfig.NetworkMode = "autosoft_database"
		c.NetworkSettings.Networks = map[string]struct{ IPAddress, NetworkID string }{f.network.Name: {IPAddress: address, NetworkID: f.network.ID}, "autosoft_database": {IPAddress: "172.31.0.2", NetworkID: strings.Repeat("f", 64)}}
		f.containers[name], f.results[name], f.server.manifest.ServiceImages[name] = c, id, image
		f.network.Containers[id] = struct{ IPv4Address string }{address + "/24"}
	}
	f.server.runner = func(_ context.Context, command string, args ...string) (string, error) {
		f.calls = append(f.calls, append([]string{command}, args...))
		if command != "docker" {
			t.Fatalf("Unexpected host command %s", command)
		}
		if len(args) == 5 && reflect.DeepEqual(args[:4], []string{"network", "inspect", "--format", "{{json .}}"}) && args[4] == f.network.Name {
			encoded, _ := json.Marshal(f.network)
			return string(encoded), nil
		}
		if len(args) > 1 && args[0] == "ps" {
			joined := strings.Join(args, " ")
			for name, result := range f.results {
				if strings.Contains(joined, "label=com.docker.compose.service="+name+" ") {
					for _, required := range []string{"--no-trunc", "status=running", "label=com.docker.compose.project=autosoft", "label=io.autosoft.managed=true", "--format {{.ID}}"} {
						if !strings.Contains(joined, required) {
							t.Fatalf("Service query omits %s", required)
						}
					}
					return result, nil
				}
			}
		}
		if len(args) == 4 && reflect.DeepEqual(args[:3], []string{"inspect", "--format", "{{json .}}"}) {
			for _, c := range f.containers {
				if c.ID == args[3] {
					encoded, _ := json.Marshal(c)
					return string(encoded), nil
				}
			}
		}
		return "", errors.New("Synthetic independent inspection unavailable")
	}
	return f
}

// Scanner/application tests still use their own actual command assertions. This
// wrapper supplies only the independently inspected company networking evidence
// introduced by the trusted resolver; it never bypasses production validation.
func installTrustedServiceTestFixture(t *testing.T, s *server, networkName, service string) {
	t.Helper()
	f := newServiceHostsFixture(t)
	f.network.Name = networkName
	f.network.Containers = map[string]struct{ IPv4Address string }{}
	id := strings.Repeat("9", 64)
	image := "registry:5000/" + service + "@sha256:" + strings.Repeat("8", 64)
	c := f.containers["mysql"]
	c.ID, c.Name, c.Config.Image = id, "/autosoft-"+service+"-1", image
	c.Config.Labels["com.docker.compose.service"] = service
	c.HostConfig.NetworkMode = networkName
	c.NetworkSettings.Networks = map[string]struct{ IPAddress, NetworkID string }{networkName: {IPAddress: "172.30.2.2", NetworkID: f.network.ID}}
	f.containers = map[string]serviceContainerInspection{service: c}
	f.results = map[string]string{service: id}
	f.network.Containers[id] = struct{ IPv4Address string }{"172.30.2.2/24"}
	if s.manifest.ServiceImages == nil {
		s.manifest.ServiceImages = map[string]string{}
	}
	s.manifest.ServiceImages[service] = image
	original := s.runner
	s.runner = func(ctx context.Context, executable string, args ...string) (string, error) {
		if executable == "docker" && ((len(args) >= 2 && args[0] == "network" && args[1] == "inspect") || (len(args) > 0 && (args[0] == "ps" || args[0] == "inspect"))) {
			return f.server.runner(ctx, executable, args...)
		}
		return original(ctx, executable, args...)
	}
}

func TestTrustedServiceHostsExactQualifiedPrivateAddresses(t *testing.T) {
	f := newServiceHostsFixture(t)
	args, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql", "redis", "rabbitmq"})
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"--add-host", "mysql:172.30.2.2", "--add-host", "redis:172.30.2.3", "--add-host", "rabbitmq:172.30.2.4"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("Unexpected mapping: %v", args)
	}
	if len(f.calls) != 7 {
		t.Fatalf("Each infrastructure address needs independent container and network inspection: %v", f.calls)
	}
	// A shared infrastructure container may also join its company network and
	// other app networks. Only its exact requested subnet is mapped into runsc.
	if strings.Contains(strings.Join(args, " "), "172.31") {
		t.Fatal("Another network address entered the sandbox mapping")
	}
}

func TestTrustedServiceHostsRejectUnsafeRequestedNamesBeforeInspection(t *testing.T) {
	for _, tc := range []struct {
		network string
		names   []string
	}{{"host", []string{"mysql"}}, {"none", []string{"mysql"}}, {"bridge", []string{"mysql"}}, {"private --network=host", []string{"mysql"}}, {"autosoft_app_1234", nil}, {"autosoft_app_1234", []string{"mysql", "mysql"}}, {"autosoft_app_1234", []string{"mysql:127.0.0.1"}}, {"autosoft_app_1234", []string{"metadata.google.internal"}}, {"autosoft_app_1234", []string{"unqualified"}}} {
		f := newServiceHostsFixture(t)
		if args, err := f.server.trustedServiceHosts(context.Background(), tc.network, tc.names); err == nil || args != nil || len(f.calls) != 0 {
			t.Fatalf("Unsafe request reached Docker: %#v, %v, %v", tc, args, err)
		}
	}
	f := newServiceHostsFixture(t)
	f.server.manifest.ServiceImages["mysql"] = "mysql:latest"
	if _, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql"}); err == nil || len(f.calls) != 0 {
		t.Fatal("Tag-only company service image accepted")
	}
}

func TestTrustedServiceHostsRejectChangedContainerProvenance(t *testing.T) {
	mutations := map[string]func(*serviceContainerInspection){
		"project": func(c *serviceContainerInspection) { c.Config.Labels["com.docker.compose.project"] = "other" },
		"service": func(c *serviceContainerInspection) { c.Config.Labels["com.docker.compose.service"] = "redis" },
		"managed": func(c *serviceContainerInspection) { delete(c.Config.Labels, "io.autosoft.managed") },
		"oneoff":  func(c *serviceContainerInspection) { c.Config.Labels["com.docker.compose.oneoff"] = "True" },
		"replica": func(c *serviceContainerInspection) { c.Config.Labels["com.docker.compose.container-number"] = "2" },
		"name":    func(c *serviceContainerInspection) { c.Name = "/untrusted-mysql" },
		"image": func(c *serviceContainerInspection) {
			c.Config.Image = "registry:5000/mysql@sha256:" + strings.Repeat("f", 64)
		},
		"stopped":             func(c *serviceContainerInspection) { c.State.Running = false },
		"paused":              func(c *serviceContainerInspection) { c.State.Paused = true },
		"restarting":          func(c *serviceContainerInspection) { c.State.Restarting = true },
		"host":                func(c *serviceContainerInspection) { c.HostConfig.NetworkMode = "host" },
		"container_namespace": func(c *serviceContainerInspection) { c.HostConfig.NetworkMode = "container:other" },
		"missing_membership":  func(c *serviceContainerInspection) { delete(c.NetworkSettings.Networks, "autosoft_app_1234") },
		"different_network_id": func(c *serviceContainerInspection) {
			endpoint := c.NetworkSettings.Networks["autosoft_app_1234"]
			endpoint.NetworkID = strings.Repeat("f", 64)
			c.NetworkSettings.Networks["autosoft_app_1234"] = endpoint
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newServiceHostsFixture(t)
			c := f.containers["mysql"]
			mutate(&c)
			f.containers["mysql"] = c
			if args, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql"}); err == nil || args != nil {
				t.Fatal("Changed service provenance produced a host mapping")
			}
		})
	}
}

func TestTrustedServiceHostsRejectUnverifiedNetworkAndAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.11", "169.254.169.254", "0.0.0.0", "0.2.3.4", "224.0.0.1", "255.255.255.255", "172.30.3.2", "::1", "::ffff:172.30.2.2", "172.030.2.2", "172.30.2.2:3306"} {
		f := newServiceHostsFixture(t)
		c := f.containers["mysql"]
		endpoint := c.NetworkSettings.Networks[f.network.Name]
		endpoint.IPAddress = address
		c.NetworkSettings.Networks[f.network.Name] = endpoint
		f.containers["mysql"] = c
		if args, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql"}); err == nil || args != nil {
			t.Fatalf("Unsafe address accepted: %s", address)
		}
	}
	for _, mutation := range []string{"not_internal", "driver", "ownership", "network_id", "subnet", "network_member"} {
		f := newServiceHostsFixture(t)
		switch mutation {
		case "not_internal":
			f.network.Internal = false
		case "driver":
			f.network.Driver = "host"
		case "ownership":
			f.network.Labels = map[string]string{"com.docker.compose.project": "other"}
		case "network_id":
			f.network.ID = "short"
		case "subnet":
			f.network.IPAM.Config[0].Subnet = "172.31.0.0/24"
		case "network_member":
			delete(f.network.Containers, f.containers["mysql"].ID)
		}
		if args, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql"}); err == nil || args != nil {
			t.Fatalf("Unverified network produced a host mapping: %s", mutation)
		}
	}
}

func TestTrustedServiceHostsRejectDuplicateCandidatesAndAddresses(t *testing.T) {
	for _, ids := range []string{"", strings.Repeat("b", 12), strings.Repeat("b", 64) + "\n" + strings.Repeat("c", 64)} {
		f := newServiceHostsFixture(t)
		f.results["mysql"] = ids
		if args, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql"}); err == nil || args != nil {
			t.Fatal("Missing, truncated or duplicate service identity accepted")
		}
	}
	f := newServiceHostsFixture(t)
	c := f.containers["redis"]
	endpoint := c.NetworkSettings.Networks[f.network.Name]
	endpoint.IPAddress = "172.30.2.2"
	c.NetworkSettings.Networks[f.network.Name] = endpoint
	f.containers["redis"] = c
	f.network.Containers[c.ID] = struct{ IPv4Address string }{"172.30.2.2/24"}
	if args, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql", "redis"}); err == nil || args != nil {
		t.Fatal("Two distinct service aliases mapped the same address")
	}
}

func TestTrustedServiceHostsNeverReturnsRawDockerDiagnostics(t *testing.T) {
	f := newServiceHostsFixture(t)
	f.server.runner = func(context.Context, string, ...string) (string, error) {
		return "password=synthetic-sensitive-value", errors.New("password=synthetic-sensitive-value")
	}
	args, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"mysql"})
	if args != nil || err == nil || strings.Contains(err.Error(), "synthetic-sensitive-value") {
		t.Fatal("Unverified Docker error escaped the trusted host boundary")
	}
}
