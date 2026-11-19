package main

import (
	"context"
	"errors"
	"os"
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
	network, err := inspectServiceNetwork(text, networkName)
	if err != nil {
		return err
	}
	if network.Labels["io.autosoft.network-version"] != "1" {
		return errors.New("Directory control requires a provisioned static app network; IT must migrate legacy networks")
	}
	// Attachments now happen exclusively through the persisted reservation in
	// ensureAssignedAppNetwork. This path only verifies; it cannot create a
	// dynamic connection as a fallback.
	_, err = s.trustedServiceHosts(ctx, networkName, []string{"control"})
	return err
}
