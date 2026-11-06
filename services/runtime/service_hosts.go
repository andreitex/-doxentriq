package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var trustedServiceName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var trustedNetworkName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var exactDockerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// This catalog is company release configuration, not a generated-app service
// registry. Keep the allowed aliases aligned with release-manifest.py. Multiple
// aliases intentionally share an image (control/worker and broker/packager).
func validateServiceCatalog(m RuntimeManifest) error {
	if len(m.ServiceImages) == 0 || len(m.ServiceImages) > 32 {
		return errors.New("Company service image catalog must contain at most 32 qualified entries")
	}
	for name, image := range m.ServiceImages {
		if !trustedServiceName.MatchString(name) {
			return errors.New("Company service image catalog contains an invalid service alias")
		}
		switch name {
		case "mysql", "redis", "rabbitmq", "keycloak", "registry", "dependency-proxy", "control", "worker", "broker", "packager", "caddy", "prometheus", "loki", "grafana", "otel":
		default:
			return errors.New("Company service image catalog contains an unsupported service alias")
		}
		if len(image) > 512 || !digestImage.MatchString(image) {
			return errors.New("Every company service image must be bounded and digest pinned")
		}
	}
	for _, name := range []string{"mysql", "redis", "rabbitmq", "registry", "dependency-proxy"} {
		if m.ServiceImages[name] == "" {
			return errors.New("Company service image catalog is missing required infrastructure")
		}
	}
	return nil
}

type serviceNetworkInspection struct {
	ID, Name, Driver string
	Internal         bool
	Labels           map[string]string
	IPAM             struct {
		Config []struct{ Subnet string }
	}
	Containers map[string]struct{ IPv4Address string }
}

type serviceContainerInspection struct {
	ID, Name string
	State    struct {
		Running, Paused, Restarting bool
	}
	Config struct {
		Image  string
		Labels map[string]string
	}
	HostConfig struct {
		NetworkMode string
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress, NetworkID string }
	}
}

func trustedServiceIPv4(value string) net.IP {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil || ip.String() != value || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return nil
	}
	v4 := ip.To4()
	if v4[0] == 0 || v4[0] >= 224 {
		return nil
	}
	return v4
}

func inspectServiceNetwork(output, name string) (serviceNetworkInspection, error) {
	var network serviceNetworkInspection
	if len(output) > 2<<20 || json.Unmarshal([]byte(output), &network) != nil || network.Name != name || !exactDockerID.MatchString(network.ID) || network.Driver != "bridge" || !network.Internal {
		return network, errors.New("The exact private service network is unavailable or not an internal bridge")
	}
	if network.Labels["io.autosoft.managed"] != "true" && network.Labels["com.docker.compose.project"] != "autosoft" {
		return network, errors.New("Private service network company ownership is unverified")
	}
	return network, nil
}

func serviceAddress(output, id, service, expectedImage string, network serviceNetworkInspection) (string, error) {
	var container serviceContainerInspection
	if len(output) > 2<<20 || json.Unmarshal([]byte(output), &container) != nil || container.ID != id || !exactDockerID.MatchString(container.ID) || container.Name != "/autosoft-"+service+"-1" || !container.State.Running || container.State.Paused || container.State.Restarting {
		return "", errors.New("The exact running company service container could not be verified")
	}
	labels := container.Config.Labels
	if labels["com.docker.compose.project"] != "autosoft" || labels["com.docker.compose.service"] != service || labels["com.docker.compose.oneoff"] != "False" || labels["com.docker.compose.container-number"] != "1" || labels["io.autosoft.managed"] != "true" || container.Config.Image != expectedImage || !digestImage.MatchString(container.Config.Image) {
		return "", errors.New("Company service labels or qualified digest do not match")
	}
	if !isolatedServiceNetworkMode(container.HostConfig.NetworkMode) {
		return "", errors.New("Company service network isolation is unverified")
	}
	endpoint, present := container.NetworkSettings.Networks[network.Name]
	if !present || endpoint.NetworkID != network.ID {
		return "", errors.New("Company service is not attached to the exact requested network")
	}
	if version := network.Labels["io.autosoft.network-version"]; version != "" {
		var pinned struct {
			NetworkSettings struct {
				Networks map[string]struct {
					IPAMConfig *struct {
						IPv4Address, IPv6Address string
						LinkLocalIPs             []string
					}
				}
			}
		}
		if version != "1" || json.Unmarshal([]byte(output), &pinned) != nil {
			return "", errors.New("Application network address policy is unsupported")
		}
		config := pinned.NetworkSettings.Networks[network.Name].IPAMConfig
		if config == nil || config.IPv4Address != endpoint.IPAddress || config.IPv6Address != "" || len(config.LinkLocalIPs) != 0 {
			return "", errors.New("Reserved service address lacks persisted static IPAM evidence")
		}
		if len(network.IPAM.Config) != 1 {
			return "", errors.New("Reserved service network subnet evidence is ambiguous")
		}
		subnet, err := netip.ParsePrefix(network.IPAM.Config[0].Subnet)
		index := -1
		for position, name := range appNetworkServices {
			if name == service {
				index = position
			}
		}
		if err != nil || !subnet.Addr().Is4() || subnet != subnet.Masked() || subnet.Bits() != appNetworkPrefix || index < 0 || endpoint.IPAddress != networkOffset(subnet.Addr(), index+2).String() {
			return "", errors.New("Service address differs from the static application network policy")
		}
	}
	ip := trustedServiceIPv4(endpoint.IPAddress)
	if ip == nil {
		return "", errors.New("Company service private IPv4 is invalid")
	}
	retained, exists := network.Containers[id]
	networkIP, assigned, err := net.ParseCIDR(retained.IPv4Address)
	if !exists || err != nil || networkIP.To4() == nil || !networkIP.Equal(ip) || assigned == nil {
		return "", errors.New("Independent network membership does not confirm the service IPv4")
	}
	inside := false
	for _, config := range network.IPAM.Config {
		_, subnet, err := net.ParseCIDR(config.Subnet)
		if err == nil && subnet.IP.To4() != nil && subnet.Contains(ip) {
			inside = true
		}
	}
	if !inside {
		return "", errors.New("Service IPv4 does not belong to the exact private network subnet")
	}
	return endpoint.IPAddress, nil
}

func isolatedServiceNetworkMode(mode string) bool {
	return mode != "" && mode != "host" && mode != "none" && mode != "default" && mode != "bridge" && !strings.HasPrefix(mode, "container:")
}

// Docker's embedded DNS address is not usable by every runsc networking mode.
// Supply only independently verified company service IPv4 addresses; never use
// host networking, a caller-supplied address, or a generated DNS/hosts entry.
// The returned values are complete Docker argument pairs, in requested order.
func (s *server) trustedServiceHosts(ctx context.Context, networkName string, names []string) ([]string, error) {
	if !trustedNetworkName.MatchString(networkName) || networkName == "host" || networkName == "none" || networkName == "bridge" || len(names) == 0 || len(names) > 16 {
		return nil, errors.New("Invalid bounded company service host request")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !trustedServiceName.MatchString(name) || seen[name] || !digestImage.MatchString(s.manifest.ServiceImages[name]) {
			return nil, errors.New("Every requested service needs a unique qualified company image")
		}
		seen[name] = true
	}
	output, err := s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", networkName)
	if err != nil {
		return nil, errors.New("The private company service network cannot be independently inspected")
	}
	network, err := inspectServiceNetwork(output, networkName)
	if err != nil {
		return nil, err
	}
	args, addresses := []string{}, map[string]bool{}
	for _, name := range names {
		output, err = s.runner(ctx, "docker", "ps", "--no-trunc", "--filter", "status=running", "--filter", "label=com.docker.compose.project=autosoft", "--filter", "label=com.docker.compose.service="+name, "--filter", "label=io.autosoft.managed=true", "--format", "{{.ID}}")
		id := strings.TrimSpace(output)
		if err != nil || !exactDockerID.MatchString(id) {
			return nil, errors.New("Exactly one running managed company service is required")
		}
		output, err = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
		if err != nil {
			return nil, errors.New("Company service immutable container inspection failed")
		}
		address, err := serviceAddress(output, id, name, s.manifest.ServiceImages[name], network)
		if err != nil {
			return nil, err
		}
		if addresses[address] {
			return nil, errors.New("Different company services cannot share a host mapping address")
		}
		addresses[address] = true
		args = append(args, "--add-host", name+":"+address)
	}
	return args, nil
}

func expectedAppHostSet(args []string) (map[string]string, error) {
	if len(args) == 0 || len(args)%2 != 0 || len(args) > 96 {
		return nil, errors.New("Application trusted host arguments are invalid")
	}
	result := map[string]string{}
	for index := 0; index < len(args); index += 2 {
		if args[index] != "--add-host" {
			return nil, errors.New("Only trusted host arguments can be reconciled")
		}
		parts := strings.Split(args[index+1], ":")
		if len(parts) != 2 || !trustedNetworkName.MatchString(parts[0]) || trustedServiceIPv4(parts[1]) == nil || result[parts[0]] != "" {
			return nil, errors.New("Application trusted host aliases must be unique exact IPv4 mappings")
		}
		result[parts[0]] = parts[1]
	}
	return result, nil
}

func sameAppHostSet(actual []string, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, mapping := range actual {
		parts := strings.Split(mapping, ":")
		if len(parts) != 2 || seen[parts[0]] || expected[parts[0]] != parts[1] {
			return false
		}
		seen[parts[0]] = true
	}
	return true
}

func (s *server) exactAppContainerID(ctx context.Context, name string) (string, error) {
	output, err := s.runner(ctx, "docker", "ps", "--all", "--no-trunc", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	id := strings.TrimSpace(output)
	if err != nil || (id != "" && !exactDockerID.MatchString(id)) {
		return "", errors.New("Exact application container discovery is unavailable or ambiguous")
	}
	return id, nil
}

func (s *server) independentlyVerifiedAppImage(appID, image string) error {
	entries, err := os.ReadDir(filepath.Join(s.data, "receipts"))
	if err != nil || len(entries) > 10000 {
		return errors.New("Owned preview verification inventory is unavailable")
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var receipt Verification
		if readBoundedJSON(filepath.Join(s.data, "receipts", entry.Name()), &receipt) != nil || receipt.AppID != appID || !previewRemovalProvenance(receipt.Evidence) || len(receipt.Images) != 1 || receipt.Images[0] != image || !identity.MatchString(receipt.AttemptID) || !exactDockerID.MatchString(receipt.SourceHash) {
			continue
		}
		source, err := safePath(filepath.Join(s.data, "sources"), receipt.AttemptID)
		if err != nil {
			continue
		}
		var manifest AppManifest
		if readBoundedJSON(filepath.Join(source, "app.manifest.json"), &manifest) != nil || validateApp(manifest, appID, receipt.Template) != nil {
			continue
		}
		actual, err := sourceDigest(source)
		if err == nil && actual == receipt.SourceHash {
			return nil
		}
	}
	return errors.New("The owned preview image lacks an exact immutable verification receipt")
}

func previewRemovalProvenance(evidence Evidence) bool {
	// This grants deletion of the exact owned preview container only. Failed
	// health/acceptance evidence remains failed and cannot authorize startup,
	// certificate reconciliation, publication or automatic recovery.
	if evidence.Status != "passed" && evidence.Status != "failed" {
		return false
	}
	requiredChecks := []string{"dependencies", "build", "application_tests", "security", "image_packaging"}
	if evidence.Status == "passed" {
		requiredChecks = mandatoryStages
		seen := map[string]bool{}
		for _, check := range evidence.Checks {
			if !check.Passed || seen[check.Name] {
				return false
			}
			seen[check.Name] = true
		}
	}
	for _, required := range requiredChecks {
		found := false
		for _, check := range evidence.Checks {
			if check.Name != required {
				continue
			}
			if found || !check.Passed {
				return false
			}
			found = true
		}
		if !found {
			return false
		}
	}
	return true
}

// Called inside the application lock, only from an already authorized
// publication/rollback or preview workflow. Docker restarts retain ExtraHosts;
// inactive previous containers need safe recreation when infrastructure moves.
// Removal never includes volumes and always uses the inspected immutable ID.
func (s *server) reconcileExistingAppHosts(ctx context.Context, name, appID, resourceID, image string, expectedArgs []string, preview bool) (exists bool, removed bool, err error) {
	if !identity.MatchString(name) || !identity.MatchString(appID) || !digestImage.MatchString(image) || (preview && (resourceID != appID+"_preview" || name != "as-preview-"+appID)) || (!preview && (resourceID != appID || !strings.HasPrefix(name, "as-app-"+appID+"-"))) {
		return false, false, errors.New("Exact application host reconciliation identity is required")
	}
	expected, err := expectedAppHostSet(expectedArgs)
	if err != nil {
		return false, false, err
	}
	id, err := s.exactAppContainerID(ctx, name)
	if err != nil || id == "" {
		return false, false, err
	}
	expectedImage := image
	if preview {
		expectedImage = "" // The independently verified prior preview may use an older image.
	}
	inspected, err := s.inspectTLSContainer(ctx, name, appID, resourceID, expectedImage)
	if err != nil || inspected.ID != id {
		return true, false, errors.New("Application ownership changed during host reconciliation")
	}
	if preview {
		if err = s.independentlyVerifiedAppImage(appID, inspected.Config.Image); err != nil {
			return true, false, err
		}
	}
	output, err := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
	var current struct {
		ID, Name   string
		State      struct{ Running bool }
		HostConfig struct{ ExtraHosts []string }
	}
	if err != nil || len(output) > 2<<20 || json.Unmarshal([]byte(output), &current) != nil || current.ID != id || current.Name != "/"+name || current.State.Running != inspected.State.Running {
		return true, false, errors.New("Application host configuration cannot be independently confirmed")
	}
	if !preview && sameAppHostSet(current.HostConfig.ExtraHosts, expected) {
		return true, false, nil
	}
	if !preview {
		if current.State.Running {
			return true, false, errors.New("Running application host mappings changed; company-approved recovery is required")
		}
		var active activeDeployment
		if readBoundedJSON(filepath.Join(s.data, "active", appID+".json"), &active) != nil || active.Container == name || !identity.MatchString(active.Container) || active.Schema < 1 {
			return true, false, errors.New("Only a stopped independently confirmed inactive application can be recreated")
		}
		request := observationRequest{ID: "host-reconciliation", AppID: appID, ReleaseID: active.ReleaseID, Hash: active.Hash, Images: []string{active.Image}, OperationID: active.OperationID}
		_, verified, manifest, proofErr := s.publicationReceipt(request)
		if proofErr != nil || active.URL != "https://"+manifest.Slug+"."+s.appsHost() || active.Schema < verified.SchemaMin || active.Schema > verified.SchemaMax {
			return true, false, errors.New("Current immutable publication evidence is unavailable; existing containers are preserved")
		}
		matched, routeErr := s.routeMatches(ctx, appID, manifest.Slug+"."+s.appsHost(), active.Container)
		if routeErr != nil || !matched {
			return true, false, errors.New("Current routing does not independently exclude the inactive container")
		}
	}
	args := []string{"rm"}
	if preview {
		args = append(args, "--force")
	}
	args = append(args, id)
	if _, err = s.runner(ctx, "docker", args...); err != nil {
		return true, false, errors.New("Exact inactive container recreation failed; application data mounts were retained")
	}
	remaining, err := s.exactAppContainerID(ctx, name)
	if err != nil || remaining != "" {
		return true, true, errors.New("Container replacement became ambiguous; fresh startup is blocked")
	}
	return true, true, nil
}
