package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func directoryNetworkFixture(t *testing.T, attached bool) (*serviceHostsFixture, *int) {
	t.Helper()
	f := newServiceHostsFixture(t)
	c := f.containers["mysql"]
	c.ID, c.Name = strings.Repeat("8", 64), "/autosoft-control-1"
	c.Config.Image = "registry:5000/control@sha256:" + strings.Repeat("7", 64)
	c.Config.Labels = map[string]string{"com.docker.compose.project": "autosoft", "com.docker.compose.service": "control", "com.docker.compose.oneoff": "False", "com.docker.compose.container-number": "1", "io.autosoft.managed": "true"}
	c.NetworkSettings.Networks = map[string]struct{ IPAddress, NetworkID string }{}
	f.containers["control"], f.results["control"], f.server.manifest.ServiceImages["control"] = c, c.ID, c.Config.Image
	attach := func() {
		c := f.containers["control"]
		c.NetworkSettings.Networks[f.network.Name] = struct{ IPAddress, NetworkID string }{"172.30.2.5", f.network.ID}
		f.containers["control"] = c
		f.network.Containers[c.ID] = struct{ IPv4Address string }{"172.30.2.5/24"}
	}
	if attached {
		attach()
	}
	original, connects := f.server.runner, new(int)
	f.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
		if len(args) > 1 && args[0] == "network" && args[1] == "connect" {
			*connects++
			if command != "docker" || !reflect.DeepEqual(args, []string{"network", "connect", "--alias", "control", f.network.Name, c.ID}) {
				return "", errors.New("Directory attachment attempted an unverified container")
			}
			attach()
			return "", nil
		}
		return original(ctx, command, args...)
	}
	return f, connects
}

func TestDirectoryControlUsesExactQualifiedPrivateCompanyContainer(t *testing.T) {
	t.Setenv("APP_DIRECTORY_AUTHORIZATION_ENABLED", "1")
	for _, attached := range []bool{false, true} {
		f, connects := directoryNetworkFixture(t, attached)
		if err := f.server.attachDirectoryControl(context.Background(), f.network.Name); err != nil {
			t.Fatal(err)
		}
		expected := 1
		if attached {
			expected = 0
		}
		if *connects != expected {
			t.Fatal("Directory attachment was repeated or omitted")
		}
		hosts, err := f.server.trustedServiceHosts(context.Background(), f.network.Name, []string{"control"})
		if err != nil || !reflect.DeepEqual(hosts, []string{"--add-host", "control:172.30.2.5"}) {
			t.Fatal("Directory control has no verified fixed private address")
		}
	}
}

func TestDirectoryControlDisabledRequiresNoHostOperations(t *testing.T) {
	t.Setenv("APP_DIRECTORY_AUTHORIZATION_ENABLED", "0")
	f, _ := directoryNetworkFixture(t, false)
	if err := f.server.attachDirectoryControl(context.Background(), "host"); err != nil || len(f.calls) != 0 {
		t.Fatal("Disabled directory service changed host networking")
	}
}

func TestDirectoryControlDeniesChangedOwnershipImageAndMissingReadback(t *testing.T) {
	t.Setenv("APP_DIRECTORY_AUTHORIZATION_ENABLED", "1")
	for _, mutation := range []string{"multiple", "short_id", "tag", "image", "owner", "stopped", "oneoff", "public_network", "missing_readback"} {
		t.Run(mutation, func(t *testing.T) {
			f, connects := directoryNetworkFixture(t, false)
			c := f.containers["control"]
			switch mutation {
			case "multiple":
				f.results["control"] += "\n" + strings.Repeat("9", 64)
			case "short_id":
				f.results["control"] = c.ID[:12]
			case "tag":
				f.server.manifest.ServiceImages["control"] = "control:latest"
			case "image":
				c.Config.Image = f.server.manifest.ServiceImages["mysql"]
			case "owner":
				c.Config.Labels["com.docker.compose.project"] = "customer"
			case "stopped":
				c.State.Running = false
			case "oneoff":
				c.Config.Labels["com.docker.compose.oneoff"] = "True"
			case "public_network":
				f.network.Internal = false
			case "missing_readback":
				original := f.server.runner
				f.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
					if len(args) > 1 && args[0] == "network" && args[1] == "connect" {
						return "", nil
					}
					return original(ctx, command, args...)
				}
			}
			f.containers["control"] = c
			if err := f.server.attachDirectoryControl(context.Background(), f.network.Name); err == nil {
				t.Fatal("Unverified directory attachment accepted")
			}
			if *connects != 0 {
				t.Fatal("Unverified company identity reached network mutation")
			}
		})
	}
}
