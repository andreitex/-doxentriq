package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

type appHostInspection struct {
	ID, Name string
	Config   struct {
		Image  string
		Labels map[string]string
	}
	State      struct{ Running, Paused, Restarting bool }
	HostConfig struct {
		NetworkMode string
		ExtraHosts  []string
	}
}

// This is a read-only diagnosis, not authorization to start, replace or repair
// a container. The caller already holds the app lock and has verified the
// immutable publication, actual route and scoped credential mount. A positive
// diagnosis must bind to that same container and to independently inspected
// company services on the app's derived private network. No resource secrets
// need to be opened and no observed address is returned to the administrator.
func (s *server) publishedServiceHostDrift(ctx context.Context, appID string, container tlsContainer, manifest AppManifest) ([]string, error) {
	return s.appServiceHostDrift(ctx, appID, appID, container, manifest)
}

// Resource scope is explicit: a preview has a distinct name and private network.
// This check does not establish whether a preview is still authorized for use.
func (s *server) appServiceHostDrift(ctx context.Context, appID, resourceID string, container tlsContainer, manifest AppManifest) ([]string, error) {
	validName := resourceID == appID && strings.HasPrefix(container.Name, "/as-app-"+appID+"-")
	if resourceID == appID+"_preview" {
		validName = container.Name == "/as-preview-"+appID
	}
	if !identity.MatchString(appID) || manifest.ID != appID || !exactDockerID.MatchString(container.ID) || !digestImage.MatchString(container.Config.Image) || !validName {
		return nil, errors.New("Exact application and resource identity are required for network diagnosis")
	}
	network := "autosoft_app_" + hashBytes([]byte(resourceID))[:24]
	inspect := func() (appHostInspection, error) {
		var actual appHostInspection
		output, err := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", container.ID)
		if err != nil || len(output) > 2<<20 || json.Unmarshal([]byte(output), &actual) != nil || actual.ID != container.ID || actual.Name != container.Name || actual.Config.Image != container.Config.Image || actual.Config.Labels["io.autosoft.managed"] != "true" || actual.Config.Labels["io.autosoft.app"] != appID || actual.HostConfig.NetworkMode != network || actual.State.Paused || actual.State.Restarting || actual.State.Running != container.State.Running {
			return actual, errors.New("Exact application network configuration is unavailable")
		}
		return actual, nil
	}
	before, err := inspect()
	if err != nil {
		return nil, err
	}
	if len(before.HostConfig.ExtraHosts) > 48 {
		return nil, errors.New("Application host mapping inventory is unavailable or unbounded")
	}
	// Include connector aliases in structural validation without treating them
	// as qualified infrastructure. Their own scope and health checks are separate.
	args := make([]string, 0, len(before.HostConfig.ExtraHosts)*2)
	for _, host := range before.HostConfig.ExtraHosts {
		args = append(args, "--add-host", host)
	}
	actual := map[string]string{}
	if len(args) > 0 {
		actual, err = expectedAppHostSet(args)
		if err != nil {
			return nil, errors.New("Application host mappings are malformed or ambiguous")
		}
	}
	names := []string{"mysql", "redis", "rabbitmq"}
	if directoryAuthorizationEnabled() && manifest.Auth != "public" {
		names = append(names, "control")
	}
	expectedArgs, err := s.trustedServiceHosts(ctx, network, names)
	if err != nil {
		return nil, errors.New("Current company service addresses cannot be independently verified")
	}
	expected, err := expectedAppHostSet(expectedArgs)
	if err != nil {
		return nil, err
	}
	changed := []string{}
	for _, name := range names {
		if actual[name] != expected[name] {
			changed = append(changed, name)
		}
	}
	after, err := inspect()
	if err != nil || !reflect.DeepEqual(before, after) {
		return nil, errors.New("Application configuration changed during network diagnosis")
	}
	return changed, nil
}
