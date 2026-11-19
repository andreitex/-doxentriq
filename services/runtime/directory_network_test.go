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

func TestDirectoryControlRefusesLegacyDynamicConnections(t *testing.T) {
	t.Setenv("APP_DIRECTORY_AUTHORIZATION_ENABLED", "1")
	for _, attached := range []bool{false, true} {
		f, connects := directoryNetworkFixture(t, attached)
		if err := f.server.attachDirectoryControl(context.Background(), f.network.Name); err == nil || *connects != 0 {
			t.Fatal("Legacy directory network was adopted or mutated")
		}
	}
}

func TestDirectoryControlVerifiesReservedConnectionWithoutMutation(t *testing.T) {
	f := newAssignedNetworkFixture(t)
	if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err != nil {
		t.Fatal(err)
	}
	before := f.connects
	if err := f.server.attachDirectoryControl(context.Background(), f.value.Network); err != nil || f.connects != before {
		t.Fatal("Directory verification changed network", err)
	}
	delete(f.containers["control"]["NetworkSettings"].(map[string]any)["Networks"].(map[string]any), f.value.Network)
	if err := f.server.attachDirectoryControl(context.Background(), f.value.Network); err == nil || f.connects != before {
		t.Fatal("Missing reserved connection caused dynamic fallback")
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
			f := newAssignedNetworkFixture(t)
			if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err != nil {
				t.Fatal(err)
			}
			if err := f.server.attachDirectoryControl(context.Background(), f.value.Network); err != nil {
				t.Fatal("Valid reserved fixture must pass before mutation", err)
			}
			before := f.connects
			c := f.containers["control"]
			switch mutation {
			case "multiple", "short_id":
				original := f.server.runner
				f.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
					if len(args) > 0 && args[0] == "ps" {
						if mutation == "multiple" {
							return c["Id"].(string) + "\n" + strings.Repeat("9", 64), nil
						}
						return c["Id"].(string)[:12], nil
					}
					return original(ctx, command, args...)
				}
			case "tag":
				f.server.manifest.ServiceImages["control"] = "control:latest"
			case "image":
				c["Config"].(map[string]any)["Image"] = f.server.manifest.ServiceImages["mysql"]
			case "owner":
				c["Config"].(map[string]any)["Labels"].(map[string]string)["com.docker.compose.project"] = "customer"
			case "stopped":
				c["State"].(map[string]any)["Running"] = false
			case "oneoff":
				c["Config"].(map[string]any)["Labels"].(map[string]string)["com.docker.compose.oneoff"] = "True"
			case "public_network":
				f.network.Internal = false
			case "missing_readback":
				f.connected["control"] = false
			}
			if err := f.server.attachDirectoryControl(context.Background(), f.value.Network); err == nil {
				t.Fatal("Unverified directory attachment accepted")
			}
			if f.connects != before {
				t.Fatal("Unverified company identity reached network mutation")
			}
		})
	}
}
