package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// This switch is protected company host configuration, never an app manifest.
func directoryAuthorizationEnabled() bool {
	return os.Getenv("APP_DIRECTORY_AUTHORIZATION_ENABLED") == "1"
}

func (s *server) attachDirectoryControl(ctx context.Context, networkName string) error {
	if !directoryAuthorizationEnabled() {
		return nil
	}
	if !trustedNetworkName.MatchString(networkName) || !digestImage.MatchString(s.manifest.ServiceImages["control"]) {
		return errors.New("Directory authorization requires a qualified control service")
	}
	text, err := s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", networkName)
	if err != nil {
		return errors.New("Private directory application network inspection unavailable")
	}
	if _, err = inspectServiceNetwork(text, networkName); err != nil {
		return err
	}
	text, err = s.runner(ctx, "docker", "ps", "--no-trunc", "--filter", "status=running", "--filter", "label=com.docker.compose.project=autosoft", "--filter", "label=com.docker.compose.service=control", "--filter", "label=io.autosoft.managed=true", "--format", "{{.ID}}")
	identifier := strings.TrimSpace(text)
	if err != nil || !exactDockerID.MatchString(identifier) {
		return errors.New("One exact running directory control service is required")
	}
	text, err = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", identifier)
	var value serviceContainerInspection
	if err != nil || json.Unmarshal([]byte(text), &value) != nil || value.ID != identifier || value.Name != "/autosoft-control-1" || !value.State.Running || value.State.Paused || value.State.Restarting || value.Config.Image != s.manifest.ServiceImages["control"] {
		return errors.New("Directory control immutable image/identity is unverified")
	}
	labels := value.Config.Labels
	if labels["com.docker.compose.project"] != "autosoft" || labels["com.docker.compose.service"] != "control" || labels["com.docker.compose.oneoff"] != "False" || labels["com.docker.compose.container-number"] != "1" || labels["io.autosoft.managed"] != "true" {
		return errors.New("Directory control company ownership is unverified")
	}
	if _, exists := value.NetworkSettings.Networks[networkName]; !exists {
		if _, err = s.runner(ctx, "docker", "network", "connect", "--alias", "control", networkName, identifier); err != nil {
			return errors.New("Directory control private attachment outcome is unavailable")
		}
	}
	// Independent network membership, private IP and company container readback
	// are required before the app gets its fixed control host or callback URL.
	_, err = s.trustedServiceHosts(ctx, networkName, []string{"control"})
	return err
}
