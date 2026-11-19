package main

// Fresh app networks reserve infrastructure addresses outside Docker's dynamic
// range. Existing dynamic networks are never disconnected or silently adopted.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const appNetworkVersion = 1
const appNetworkPrefix = 26

var appNetworkServices = []string{"mysql", "redis", "rabbitmq", "caddy", "control"}
var networkInterface = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,64}$`)

type appNetworkAttachment struct {
	ContainerID string `json:"containerId"`
	State       string `json:"state"`
}

type appNetworkAssignment struct {
	Version      int                             `json:"version"`
	Pool         string                          `json:"pool"`
	Subnet       string                          `json:"subnet"`
	DynamicRange string                          `json:"dynamicRange"`
	Reservation  string                          `json:"reservation"`
	NetworkID    string                          `json:"networkId,omitempty"`
	State        string                          `json:"state"`
	Addresses    map[string]string               `json:"addresses"`
	Attaching    map[string]appNetworkAttachment `json:"attaching"`
}

type hostNetworkSnapshot struct {
	Schema     int    `json:"schema"`
	ObservedAt string `json:"observedAt"`
	Interfaces []struct {
		Name      string   `json:"name"`
		Addresses []string `json:"addresses"`
	} `json:"interfaces"`
	Routes []struct {
		Destination string `json:"destination"`
		Interface   string `json:"interface"`
		Type        string `json:"type"`
		Table       string `json:"table"`
	} `json:"routes"`
}

type assignedNetworkInspection struct {
	ID, Name, Driver, Scope string
	Internal, EnableIPv6    bool
	Labels, Options         map[string]string
	IPAM                    struct {
		Driver string
		Config []struct{ Subnet, IPRange, Gateway string }
	}
}

func appNetworkPool(value string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(value)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != value || p.Bits() < 16 || p.Bits() > 24 {
		return netip.Prefix{}, errors.New("IT must configure a canonical private IPv4 APP_NETWORK_POOL between /16 and /24")
	}
	for _, private := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if netip.MustParsePrefix(private).Contains(p.Addr()) {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("Application address pool must belong to an IT-approved RFC1918 range")
}

func networkOffset(address netip.Addr, count int) netip.Addr {
	for index := 0; index < count; index++ {
		address = address.Next()
	}
	return address
}

func newNetworkAssignment(pool, subnet netip.Prefix, reservation string) *appNetworkAssignment {
	addresses := map[string]string{}
	for index, service := range appNetworkServices {
		addresses[service] = networkOffset(subnet.Addr(), index+2).String()
	}
	return &appNetworkAssignment{Version: appNetworkVersion, Pool: pool.String(), Subnet: subnet.String(),
		DynamicRange: netip.PrefixFrom(networkOffset(subnet.Addr(), 32), 27).String(), Reservation: reservation,
		State: "reserved", Addresses: addresses, Attaching: map[string]appNetworkAttachment{}}
}

func validateNetworkAssignment(value *appNetworkAssignment) (netip.Prefix, error) {
	if value == nil || value.Version != appNetworkVersion {
		return netip.Prefix{}, errors.New("This application has legacy dynamic networking; IT must review migration before provisioning or changing connections")
	}
	pool, err := appNetworkPool(value.Pool)
	subnet, se := netip.ParsePrefix(value.Subnet)
	if err != nil || se != nil || !subnet.Addr().Is4() || subnet != subnet.Masked() || subnet.String() != value.Subnet || subnet.Bits() != appNetworkPrefix || !pool.Contains(subnet.Addr()) || !exactDockerID.MatchString(value.Reservation) {
		return netip.Prefix{}, errors.New("Persisted application address reservation is invalid")
	}
	expected := newNetworkAssignment(pool, subnet, value.Reservation)
	if value.DynamicRange != expected.DynamicRange || len(value.Addresses) != len(expected.Addresses) || value.Attaching == nil || len(value.Attaching) > len(appNetworkServices) {
		return netip.Prefix{}, errors.New("Persisted application address policy changed")
	}
	for service, address := range expected.Addresses {
		if value.Addresses[service] != address {
			return netip.Prefix{}, errors.New("Infrastructure address reservation changed")
		}
	}
	for service, attempted := range value.Attaching {
		if expected.Addresses[service] == "" || !exactDockerID.MatchString(attempted.ContainerID) || (attempted.State != "pending" && attempted.State != "verified") {
			return netip.Prefix{}, errors.New("Unrecognized network attachment intent")
		}
	}
	if (value.State != "reserved" && value.State != "create-intent" && value.State != "created") || (value.State == "created" && !exactDockerID.MatchString(value.NetworkID)) || (value.State != "created" && value.NetworkID != "") {
		return netip.Prefix{}, errors.New("Network creation outcome requires IT review")
	}
	if value.State != "created" && len(value.Attaching) != 0 {
		return netip.Prefix{}, errors.New("Service attachment intent precedes confirmed network creation")
	}
	return subnet, nil
}

func fetchHostNetworkSnapshot(ctx context.Context, client *http.Client, token string) (hostNetworkSnapshot, error) {
	var value hostNetworkSnapshot
	request, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/v1/network-snapshot", bytes.NewBufferString("{}"))
	if err != nil {
		return value, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return value, errors.New("Host network collision checks are unavailable")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (512<<10)+1))
	if err != nil || response.StatusCode != 200 || len(raw) > 512<<10 {
		return value, errors.New("Host network snapshot is unavailable or exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return value, errors.New("Host network snapshot is malformed")
	}
	if _, err = hostNetworkConflicts(value, time.Now(), netip.Prefix{}, ""); err != nil {
		return value, err
	}
	return value, nil
}

func (s *server) hostNetworkSnapshot(ctx context.Context) (hostNetworkSnapshot, error) {
	token, err := secret("QUOTA_HELPER_TOKEN")
	if err != nil {
		return hostNetworkSnapshot{}, errors.New("Authenticated host network inspection is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return fetchHostNetworkSnapshot(ctx, caddyClient(env("QUOTA_HELPER_SOCKET_FILE", "/run/autosoft/quota.sock")), token)
}

func hostNetworkConflicts(value hostNetworkSnapshot, now time.Time, own netip.Prefix, bridge string) ([]netip.Prefix, error) {
	observed, err := time.Parse(time.RFC3339Nano, value.ObservedAt)
	if err != nil || value.Schema != 1 || now.Sub(observed) > 30*time.Second || observed.Sub(now) > 5*time.Second || len(value.Interfaces) == 0 || len(value.Interfaces) > 512 || len(value.Routes) > 8192 {
		return nil, errors.New("A fresh bounded host network snapshot is required")
	}
	var blocked []netip.Prefix
	count := 0
	add := func(raw, device string, allowOwn bool) error {
		prefix, err := netip.ParsePrefix(raw)
		count++
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != raw || count > 16384 || (device != "" && !networkInterface.MatchString(device)) {
			return errors.New("Host route or interface evidence is invalid")
		}
		prefix = prefix.Masked()
		if allowOwn && bridge != "" && own.IsValid() && device == bridge && own.Bits() <= prefix.Bits() && own.Contains(prefix.Addr()) {
			return nil
		}
		blocked = append(blocked, prefix)
		return nil
	}
	seen := map[string]bool{}
	for _, device := range value.Interfaces {
		if !networkInterface.MatchString(device.Name) || seen[device.Name] || len(device.Addresses) > 256 {
			return nil, errors.New("Host interfaces are invalid or duplicated")
		}
		seen[device.Name] = true
		for _, address := range device.Addresses {
			if err = add(address, device.Name, true); err != nil {
				return nil, err
			}
		}
	}
	if !seen["lo"] {
		return nil, errors.New("Host loopback evidence is missing")
	}
	for _, route := range value.Routes {
		if route.Table == "" || len(route.Table) > 64 || route.Type == "" || len(route.Type) > 32 {
			return nil, errors.New("Host route table evidence is invalid")
		}
		if route.Destination == "0.0.0.0/0" {
			continue // Default routing is not an allocated subnet; broad VPN /1 routes still conflict.
		}
		if err = add(route.Destination, route.Interface, route.Type == "unicast" || route.Type == "local" || route.Type == "broadcast"); err != nil {
			return nil, err
		}
	}
	return blocked, nil
}

func overlapsAny(candidate netip.Prefix, blocked []netip.Prefix) bool {
	for _, other := range blocked {
		if candidate.Overlaps(other) {
			return true
		}
	}
	return false
}

func chooseAppSubnet(pool netip.Prefix, blocked []netip.Prefix) (netip.Prefix, error) {
	for address := pool.Addr(); pool.Contains(address); address = networkOffset(address, 64) {
		candidate := netip.PrefixFrom(address, appNetworkPrefix)
		if !overlapsAny(candidate, blocked) {
			return candidate, nil
		}
	}
	return netip.Prefix{}, errors.New("The IT-configured application address pool has no conflict-free subnet; no network was changed")
}

func (s *server) networkInventory(ctx context.Context) ([]assignedNetworkInspection, error) {
	text, err := s.runner(ctx, "docker", "network", "ls", "--no-trunc", "--format", "{{.ID}}")
	ids := strings.Fields(text)
	if err != nil || len(ids) == 0 || len(ids) > 512 {
		return nil, errors.New("Complete Docker network inventory is unavailable")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !exactDockerID.MatchString(id) || seen[id] {
			return nil, errors.New("Docker network identities are invalid")
		}
		seen[id] = true
	}
	text, err = s.runner(ctx, "docker", append([]string{"network", "inspect"}, ids...)...)
	var networks []assignedNetworkInspection
	if err != nil || len(text) > 2<<20 || json.Unmarshal([]byte(text), &networks) != nil || len(networks) != len(ids) {
		return nil, errors.New("Docker network subnet inventory is unavailable")
	}
	for _, network := range networks {
		if !seen[network.ID] || len(network.IPAM.Config) > 16 {
			return nil, errors.New("Docker network inventory changed")
		}
		delete(seen, network.ID)
		for _, entry := range network.IPAM.Config {
			if prefix, e := netip.ParsePrefix(entry.Subnet); e != nil || prefix != prefix.Masked() {
				return nil, errors.New("A Docker network has an unrecognized subnet")
			}
		}
	}
	return networks, nil
}

func (s *server) reserveAppNetwork(ctx context.Context, value *resources, persist func() error) error {
	unlock := s.lock("application-network-reservations")
	defer unlock()
	pool, err := appNetworkPool(os.Getenv("APP_NETWORK_POOL"))
	if err != nil {
		return err
	}
	snapshot, err := s.hostNetworkSnapshot(ctx)
	if err != nil {
		return err
	}
	blocked, err := hostNetworkConflicts(snapshot, time.Now(), netip.Prefix{}, "")
	if err != nil {
		return err
	}
	networks, err := s.networkInventory(ctx)
	if err != nil {
		return err
	}
	for _, network := range networks {
		if network.Name == value.Network {
			return errors.New("An existing network cannot be adopted as a fresh application reservation")
		}
		for _, entry := range network.IPAM.Config {
			prefix, _ := netip.ParsePrefix(entry.Subnet)
			if prefix.Addr().Is4() {
				blocked = append(blocked, prefix)
			}
		}
	}
	retained, err := s.retainedNetworkSubnets()
	if err != nil {
		return err
	}
	blocked = append(blocked, retained...)
	subnet, err := chooseAppSubnet(pool, blocked)
	if err != nil {
		return err
	}
	value.NetworkAssignment = newNetworkAssignment(pool, subnet, randomSecret())
	return persist() // Retain reservation before Docker or database effects; other apps see it under the same lock.
}

func (s *server) retainedNetworkSubnets() ([]netip.Prefix, error) {
	resourceStateFiles.RLock()
	defer resourceStateFiles.RUnlock()
	entries, err := os.ReadDir(filepath.Join(s.data, "resources"))
	if err != nil && !os.IsNotExist(err) || len(entries) > 512 {
		return nil, errors.New("Retained network reservations cannot be inventoried")
	}
	var retained []netip.Prefix
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".enc") || !applicationSQLResource.MatchString(strings.TrimSuffix(entry.Name(), ".enc")) {
			return nil, errors.New("Unrecognized or abandoned resource entry prevents network allocation; IT must review retained write evidence")
		}
		var existing resources
		if info, e := entry.Info(); e != nil || info.Size() > 1<<20 {
			return nil, errors.New("Retained resource state exceeds its bounded inventory")
		}
		if readEncrypted(filepath.Join(s.data, "resources", entry.Name()), &existing) != nil {
			return nil, errors.New("Retained network reservation cannot be decrypted")
		}
		if existing.NetworkAssignment != nil {
			prefix, e := validateNetworkAssignment(existing.NetworkAssignment)
			if e != nil {
				return nil, e
			}
			retained = append(retained, prefix)
		}
	}
	return retained, nil
}

func assignedBridge(network assignedNetworkInspection) (string, error) {
	name := network.Options["com.docker.network.bridge.name"]
	if name == "" && exactDockerID.MatchString(network.ID) {
		name = "br-" + network.ID[:12]
	}
	if !networkInterface.MatchString(name) {
		return "", errors.New("Owned network bridge interface cannot be identified")
	}
	return name, nil
}

func checkAssignedNetwork(network assignedNetworkInspection, value resources) error {
	a := value.NetworkAssignment
	if _, err := validateNetworkAssignment(a); err != nil {
		return err
	}
	if !exactDockerID.MatchString(network.ID) || network.Name != value.Network || network.Driver != "bridge" || network.Scope != "local" || !network.Internal || network.EnableIPv6 || network.IPAM.Driver != "default" || len(network.IPAM.Config) != 1 || network.Labels["io.autosoft.managed"] != "true" || network.Labels["io.autosoft.app-resource"] != value.AppID || network.Labels["io.autosoft.network-version"] != "1" || network.Labels["io.autosoft.network-reservation"] != a.Reservation || (a.NetworkID != "" && network.ID != a.NetworkID) {
		return errors.New("Application network identity or ownership differs; preserve the existing network for IT review")
	}
	config := network.IPAM.Config[0]
	subnet, _ := netip.ParsePrefix(a.Subnet)
	if config.Subnet != a.Subnet || config.IPRange != a.DynamicRange || config.Gateway != networkOffset(subnet.Addr(), 1).String() {
		return errors.New("Application network address policy differs from its saved reservation")
	}
	return nil
}

func (s *server) ensureAssignedAppNetwork(ctx context.Context, value *resources, persist func() error) error {
	a := value.NetworkAssignment
	subnet, err := validateNetworkAssignment(a)
	if err != nil {
		return err
	}
	if a.Pool != os.Getenv("APP_NETWORK_POOL") {
		return errors.New("The application address pool changed; IT migration review is required")
	}
	networks, err := s.networkInventory(ctx)
	if err != nil {
		return err
	}
	var found *assignedNetworkInspection
	for index := range networks {
		if networks[index].Name == value.Network {
			if found != nil {
				return errors.New("Application network name is ambiguous")
			}
			found = &networks[index]
		}
	}
	if found == nil && a.State != "reserved" {
		return errors.New("A previously attempted application network is missing; creation must not be blindly repeated")
	}
	bridge := ""
	if found != nil {
		if a.State == "reserved" {
			return errors.New("A network appeared before its saved creation intent; IT review is required")
		}
		if err = checkAssignedNetwork(*found, *value); err != nil {
			return err
		}
		bridge, err = assignedBridge(*found)
		if err != nil {
			return err
		}
	}
	snapshot, err := s.hostNetworkSnapshot(ctx)
	if err != nil {
		return err
	}
	blocked, err := hostNetworkConflicts(snapshot, time.Now(), subnet, bridge)
	if err != nil {
		return err
	}
	for _, network := range networks {
		if found != nil && network.ID == found.ID {
			continue
		}
		for _, config := range network.IPAM.Config {
			prefix, _ := netip.ParsePrefix(config.Subnet)
			if prefix.Addr().Is4() {
				blocked = append(blocked, prefix)
			}
		}
	}
	if overlapsAny(subnet, blocked) {
		return errors.New("Reserved application subnet now conflicts with a host route, interface or Docker network; no connection was changed")
	}
	if found == nil {
		a.State = "create-intent"
		if err = persist(); err != nil {
			return err
		}
		text, createErr := s.runner(ctx, "docker", "network", "create", "--internal", "--driver", "bridge", "--subnet", a.Subnet, "--ip-range", a.DynamicRange, "--gateway", networkOffset(subnet.Addr(), 1).String(), "--label", "io.autosoft.managed=true", "--label", "io.autosoft.app-resource="+value.AppID, "--label", "io.autosoft.network-version=1", "--label", "io.autosoft.network-reservation="+a.Reservation, value.Network)
		id := strings.TrimSpace(text)
		if createErr != nil || !exactDockerID.MatchString(id) {
			return errors.New("Application network creation outcome is uncertain; preserve its intent for exact readback")
		}
		text, err = s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", id)
		var created assignedNetworkInspection
		if err != nil || len(text) > 2<<20 || json.Unmarshal([]byte(text), &created) != nil || created.ID != id || checkAssignedNetwork(created, *value) != nil {
			return errors.New("Created network could not be independently matched to its saved reservation")
		}
		a.State, a.NetworkID = "created", id
		if err = persist(); err != nil {
			return err
		}
		return s.ensureAssignedAppNetwork(ctx, value, persist) // Fresh host/Docker readback before any service attachment.
	}
	if a.State != "created" {
		a.State, a.NetworkID = "created", found.ID
		if err = persist(); err != nil {
			return err
		}
	}
	services := []string{"mysql", "redis", "rabbitmq", "caddy"}
	if directoryAuthorizationEnabled() {
		services = append(services, "control")
	}
	for _, service := range services {
		if err = s.attachAssignedService(ctx, *value, service, persist); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) attachAssignedService(ctx context.Context, value resources, service string, persist func() error) error {
	a := value.NetworkAssignment
	image := s.manifest.ServiceImages[service]
	if a == nil || a.Addresses[service] == "" || !digestImage.MatchString(image) {
		return errors.New("A reserved address and qualified company service image are required")
	}
	text, err := s.runner(ctx, "docker", "ps", "--no-trunc", "--filter", "status=running", "--filter", "label=com.docker.compose.project=autosoft", "--filter", "label=com.docker.compose.service="+service, "--filter", "label=io.autosoft.managed=true", "--format", "{{.ID}}")
	id := strings.TrimSpace(text)
	if err != nil || !exactDockerID.MatchString(id) {
		return errors.New("Exactly one running managed company service is required before network attachment")
	}
	intent, attempted := a.Attaching[service]
	if attempted && intent.ContainerID != id {
		return errors.New("Company service container was replaced; IT must approve and verify its new reserved connection before provisioning")
	}
	inspect := func() (bool, error) {
		text, err := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
		var container serviceContainerInspection
		var endpoints struct {
			NetworkSettings struct {
				Networks map[string]struct {
					NetworkID, IPAddress string
					Aliases              []string
					IPAMConfig           *struct {
						IPv4Address, IPv6Address string
						LinkLocalIPs             []string
					}
				}
			}
		}
		if err != nil || len(text) > 2<<20 || json.Unmarshal([]byte(text), &container) != nil || json.Unmarshal([]byte(text), &endpoints) != nil || container.ID != id || container.Name != "/autosoft-"+service+"-1" || !container.State.Running || container.State.Paused || container.State.Restarting || container.Config.Image != image {
			return false, errors.New("Service immutable identity or qualified image is unavailable")
		}
		labels := container.Config.Labels
		if labels["com.docker.compose.project"] != "autosoft" || labels["com.docker.compose.service"] != service || labels["com.docker.compose.oneoff"] != "False" || labels["com.docker.compose.container-number"] != "1" || labels["io.autosoft.managed"] != "true" {
			return false, errors.New("Service ownership is unavailable")
		}
		if !isolatedServiceNetworkMode(container.HostConfig.NetworkMode) {
			return false, errors.New("Service network isolation is unverified before attachment")
		}
		endpoint, present := endpoints.NetworkSettings.Networks[value.Network]
		if !present {
			return false, nil
		}
		if !attempted {
			return false, errors.New("Existing service connection has no retained attachment intent; IT review is required")
		}
		aliases := append([]string(nil), endpoint.Aliases...)
		sort.Strings(aliases)
		if endpoint.NetworkID != a.NetworkID || endpoint.IPAddress != a.Addresses[service] || endpoint.IPAMConfig == nil || endpoint.IPAMConfig.IPv4Address != a.Addresses[service] || endpoint.IPAMConfig.IPv6Address != "" || len(endpoint.IPAMConfig.LinkLocalIPs) != 0 || !sortContains(aliases, service) {
			return false, errors.New("Existing service connection is dynamic or differs from its reservation; IT migration is required")
		}
		networkText, ne := s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", a.NetworkID)
		var actual assignedNetworkInspection
		if ne != nil || len(networkText) > 2<<20 || json.Unmarshal([]byte(networkText), &actual) != nil || checkAssignedNetwork(actual, value) != nil {
			return false, errors.New("Reserved service network changed")
		}
		network, ne := inspectServiceNetwork(networkText, value.Network)
		if ne != nil {
			return false, ne
		}
		_, ne = serviceAddress(text, id, service, image, network)
		return ne == nil, ne
	}
	attached, err := inspect()
	if err != nil {
		return err
	}
	if attached {
		if intent.State != "verified" {
			intent.State = "verified"
			a.Attaching[service] = intent
			return persist()
		}
		return nil
	}
	if attempted {
		if intent.State == "verified" {
			return errors.New("A previously verified company service connection is missing; IT must review maintenance recovery before reconnecting")
		}
		return errors.New("Previous service attachment outcome is uncertain; no automatic reconnect is permitted")
	}
	intent = appNetworkAttachment{ContainerID: id, State: "pending"}
	a.Attaching[service] = intent
	attempted = true
	if err = persist(); err != nil {
		return err
	}
	if _, err = s.runner(ctx, "docker", "network", "connect", "--ip", a.Addresses[service], "--alias", service, a.NetworkID, id); err != nil {
		return errors.New("Reserved service attachment outcome is uncertain; inspect its retained intent")
	}
	attached, err = inspect()
	if err != nil || !attached {
		return errors.New("Reserved service attachment did not pass independent address and ownership readback")
	}
	intent.State = "verified"
	a.Attaching[service] = intent
	return persist()
}

func sortContains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}
