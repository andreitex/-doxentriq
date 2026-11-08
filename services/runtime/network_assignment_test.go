package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func hostSnapshotFixture() hostNetworkSnapshot {
	var snapshot hostNetworkSnapshot
	_ = json.Unmarshal([]byte(`{"schema":1,"interfaces":[{"name":"lo","addresses":["127.0.0.0/8"]},{"name":"eth0","addresses":["192.168.1.0/24"]}],"routes":[{"destination":"0.0.0.0/0","interface":"eth0","type":"unicast","table":"main"}]}`), &snapshot)
	snapshot.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return snapshot
}

func TestAppNetworkRequiresExplicitPrivateCanonicalPool(t *testing.T) {
	for _, value := range []string{"", "10.1.1.1/16", "10.1.0.0/15", "10.1.0.0/25", "172.15.0.0/16", "192.169.0.0/16", "100.64.0.0/16", "2001:db8::/64", " 10.1.0.0/16"} {
		if _, err := appNetworkPool(value); err == nil {
			t.Fatalf("Unqualified pool accepted: %s", value)
		}
	}
	for _, value := range []string{"10.23.0.0/16", "172.20.12.0/24", "192.168.0.0/16"} {
		if _, err := appNetworkPool(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppSubnetAllocationPreservesHostDockerAndRetainedReservations(t *testing.T) {
	pool := netip.MustParsePrefix("10.90.0.0/24")
	blocked := []netip.Prefix{netip.MustParsePrefix("10.90.0.0/26"), netip.MustParsePrefix("10.90.0.80/32"), netip.MustParsePrefix("10.90.0.128/26")}
	chosen, err := chooseAppSubnet(pool, blocked)
	if err != nil || chosen.String() != "10.90.0.192/26" {
		t.Fatalf("Conflicting subnet selected: %v %v", chosen, err)
	}
	blocked = append(blocked, chosen)
	if _, err = chooseAppSubnet(pool, blocked); err == nil {
		t.Fatal("Exhausted pool silently reused")
	}
	if _, err = chooseAppSubnet(pool, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")}); err == nil {
		t.Fatal("Broad VPN route ignored")
	}
}

func TestAppNetworkStaticServicesRemainOutsideDynamicRange(t *testing.T) {
	a := newNetworkAssignment(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParsePrefix("10.90.0.64/26"), strings.Repeat("a", 64))
	if _, err := validateNetworkAssignment(a); err != nil {
		t.Fatal(err)
	}
	dynamic := netip.MustParsePrefix(a.DynamicRange)
	for index, service := range appNetworkServices {
		address := netip.MustParseAddr(a.Addresses[service])
		if dynamic.Contains(address) || a.Addresses[service] != fmt.Sprintf("10.90.0.%d", 66+index) {
			t.Fatal("Static infrastructure overlaps dynamic leases")
		}
	}
	for _, mutation := range []string{"legacy", "subnet", "range", "address", "state", "intent"} {
		t.Run(mutation, func(t *testing.T) {
			copy := newNetworkAssignment(netip.MustParsePrefix(a.Pool), netip.MustParsePrefix(a.Subnet), a.Reservation)
			switch mutation {
			case "legacy":
				copy = nil
			case "subnet":
				copy.Subnet = "10.90.1.0/26"
			case "range":
				copy.DynamicRange = "10.90.0.64/27"
			case "address":
				copy.Addresses["mysql"] = "10.90.0.99"
			case "state":
				copy.State = "created"
			case "intent":
				copy.Attaching["untrusted"] = appNetworkAttachment{ContainerID: strings.Repeat("a", 64), State: "pending"}
			}
			if _, err := validateNetworkAssignment(copy); err == nil {
				t.Fatal("Modified policy accepted")
			}
		})
	}
}

func TestHostSnapshotIgnoresOnlyDefaultAndVerifiedOwnBridge(t *testing.T) {
	snapshot := hostSnapshotFixture()
	own := netip.MustParsePrefix("10.90.0.0/26")
	add := func(destination, device, kind string) {
		raw, _ := json.Marshal(map[string]string{"destination": destination, "interface": device, "type": kind, "table": "100"})
		var route struct {
			Destination string `json:"destination"`
			Interface   string `json:"interface"`
			Type        string `json:"type"`
			Table       string `json:"table"`
		}
		_ = json.Unmarshal(raw, &route)
		snapshot.Routes = append(snapshot.Routes, route)
	}
	add(own.String(), "br-owned", "unicast")
	add("10.90.0.1/32", "br-owned", "local")
	add("10.90.0.63/32", "br-owned", "broadcast")
	blocked, err := hostNetworkConflicts(snapshot, time.Now(), own, "br-owned")
	if err != nil || overlapsAny(own, blocked) {
		t.Fatal("Verified own bridge falsely conflicts", err)
	}
	blocked, err = hostNetworkConflicts(snapshot, time.Now(), own, "")
	if err != nil || !overlapsAny(own, blocked) {
		t.Fatal("Missing bridge proof bypassed conflict")
	}
	add("10.90.0.2/32", "eth0", "local")
	blocked, err = hostNetworkConflicts(snapshot, time.Now(), own, "br-owned")
	if err != nil || !overlapsAny(own, blocked) {
		t.Fatal("Different interface route incorrectly exempted")
	}
	snapshot = hostSnapshotFixture()
	add("10.90.0.0/26", "", "unicast")
	blocked, err = hostNetworkConflicts(snapshot, time.Now(), own, "")
	if err != nil || !overlapsAny(own, blocked) {
		t.Fatal("Empty interface treated as owned bridge")
	}
	snapshot = hostSnapshotFixture()
	add("0.0.0.0/1", "tun0", "unicast")
	blocked, err = hostNetworkConflicts(snapshot, time.Now(), netip.Prefix{}, "")
	if err != nil || !overlapsAny(own, blocked) {
		t.Fatal("VPN policy route omitted")
	}
}

func TestHostSnapshotRejectsMissingStaleAndNonCanonicalEvidence(t *testing.T) {
	for _, mutation := range []string{"schema", "stale", "future", "missing_loopback", "duplicate", "host_bits", "ipv6", "unknown_interface"} {
		t.Run(mutation, func(t *testing.T) {
			snapshot := hostSnapshotFixture()
			switch mutation {
			case "schema":
				snapshot.Schema = 2
			case "stale":
				snapshot.ObservedAt = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
			case "future":
				snapshot.ObservedAt = time.Now().Add(time.Minute).Format(time.RFC3339Nano)
			case "missing_loopback":
				snapshot.Interfaces = snapshot.Interfaces[1:]
			case "duplicate":
				snapshot.Interfaces = append(snapshot.Interfaces, snapshot.Interfaces[0])
			case "host_bits":
				snapshot.Interfaces[1].Addresses = []string{"10.90.0.1/26"}
			case "ipv6":
				snapshot.Interfaces[1].Addresses = []string{"::1/128"}
			case "unknown_interface":
				snapshot.Interfaces[1].Name = "bad\nname"
			}
			if _, err := hostNetworkConflicts(snapshot, time.Now(), netip.Prefix{}, ""); err == nil {
				t.Fatal("Untrusted host snapshot accepted")
			}
		})
	}
}

func TestHostSnapshotWireFailsClosedOnUnavailableOrIncompleteEvidence(t *testing.T) {
	for _, mode := range []string{"valid", "unavailable", "unknown_field", "trailing_json", "oversized", "stale"} {
		t.Run(mode, func(t *testing.T) {
			snapshot := hostSnapshotFixture()
			if mode == "stale" {
				snapshot.ObservedAt = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
			}
			raw, _ := json.Marshal(snapshot)
			switch mode {
			case "unknown_field":
				raw = append([]byte(`{"extra":true,`), raw[1:]...)
			case "trailing_json":
				raw = append(raw, []byte(`{}`)...)
			case "oversized":
				raw = []byte(strings.Repeat(" ", (512<<10)+1))
			}
			client := &http.Client{Transport: telemetryTransport(func(request *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(request.Body)
				if request.Method != "POST" || request.URL.Path != "/v1/network-snapshot" || string(body) != "{}" || request.Header.Get("Authorization") != "Bearer fixture" {
					t.Fatal("Unexpected host authority contract")
				}
				status := 200
				if mode == "unavailable" {
					status = 503
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}
			_, err := fetchHostNetworkSnapshot(context.Background(), client, "fixture")
			if (err == nil) != (mode == "valid") {
				t.Fatalf("Incorrect wire acceptance %s: %v", mode, err)
			}
		})
	}
}

// This serves the actual authenticated Unix socket wire protocol; Docker is a
// strict deterministic fake. It cannot qualify a real daemon or VM reboot.
type assignedNetworkFixture struct {
	server                                                     *server
	value                                                      resources
	network                                                    *assignedNetworkInspection
	containers                                                 map[string]map[string]any
	connected                                                  map[string]bool
	creates, connects, saves                                   int
	createError, connectError, noCreateEffect, noConnectEffect bool
	hostConflict                                               bool
	lastSaved                                                  *appNetworkAssignment
	requests                                                   int
}

func newAssignedNetworkFixture(t *testing.T) *assignedNetworkFixture {
	t.Helper()
	t.Setenv("APP_NETWORK_POOL", "10.90.0.0/24")
	t.Setenv("APP_DIRECTORY_AUTHORIZATION_ENABLED", "1")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("BROKER_VAULT_KEY_FILE", "")
	t.Setenv("QUOTA_HELPER_TOKEN", randomSecret())
	t.Setenv("QUOTA_HELPER_TOKEN_FILE", "")
	f := &assignedNetworkFixture{containers: map[string]map[string]any{}, connected: map[string]bool{}}
	f.server = &server{data: t.TempDir(), manifest: qualifiedServiceCatalog()}
	f.value = resources{AppID: "test-app", Network: "autosoft_app_test", NetworkAssignment: newNetworkAssignment(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParsePrefix("10.90.0.0/26"), strings.Repeat("b", 64))}
	for index, service := range appNetworkServices {
		id := strings.Repeat(string(rune('a'+index)), 64)
		f.containers[service] = map[string]any{"Id": id, "Name": "/autosoft-" + service + "-1", "State": map[string]any{"Running": true}, "Config": map[string]any{"Image": f.server.manifest.ServiceImages[service], "Labels": map[string]string{"com.docker.compose.project": "autosoft", "com.docker.compose.service": service, "com.docker.compose.oneoff": "False", "com.docker.compose.container-number": "1", "io.autosoft.managed": "true"}}, "HostConfig": map[string]any{"NetworkMode": "autosoft_database"}, "NetworkSettings": map[string]any{"Networks": map[string]any{}}}
	}
	directory, err := os.MkdirTemp("", "as-net-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "host.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	api := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		if r.Method != "POST" || r.URL.Path != "/v1/network-snapshot" || string(body) != "{}" || r.Header.Get("Authorization") != "Bearer "+os.Getenv("QUOTA_HELPER_TOKEN") {
			t.Error("Host API requested outside exact authenticated contract")
			w.WriteHeader(403)
			return
		}
		f.requests++
		snapshot := hostSnapshotFixture()
		if f.network != nil {
			bridge, _ := assignedBridge(*f.network)
			snapshot.Interfaces = append(snapshot.Interfaces, struct {
				Name      string   `json:"name"`
				Addresses []string `json:"addresses"`
			}{bridge, []string{f.value.NetworkAssignment.Subnet}})
		}
		if f.hostConflict {
			snapshot.Interfaces[1].Addresses = append(snapshot.Interfaces[1].Addresses, "10.90.0.0/24")
		}
		_ = json.NewEncoder(w).Encode(snapshot)
	})}
	go func() { _ = api.Serve(listener) }()
	t.Cleanup(func() { _ = api.Close(); _ = os.RemoveAll(directory) })
	t.Setenv("QUOTA_HELPER_SOCKET_FILE", socket)
	f.server.runner = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "docker" {
			t.Fatal("Unapproved host command", command)
		}
		encode := func(value any) (string, error) { raw, err := json.Marshal(value); return string(raw), err }
		if len(args) > 1 && args[0] == "network" {
			switch args[1] {
			case "ls":
				ids := strings.Repeat("f", 64)
				if f.network != nil {
					ids += "\n" + f.network.ID
				}
				return ids, nil
			case "inspect":
				if len(args) == 5 && args[2] == "--format" {
					if f.network == nil || (args[4] != f.network.ID && args[4] != f.network.Name) {
						return "", errors.New("Missing network")
					}
					raw, _ := json.Marshal(f.network)
					var obj map[string]any
					_ = json.Unmarshal(raw, &obj)
					members := map[string]any{}
					for service, attached := range f.connected {
						if attached {
							members[f.containers[service]["Id"].(string)] = map[string]any{"IPv4Address": f.value.NetworkAssignment.Addresses[service] + "/26"}
						}
					}
					obj["Containers"] = members
					return encode(obj)
				}
				base := assignedNetworkInspection{ID: strings.Repeat("f", 64), Name: "host", Driver: "host", Scope: "local"}
				inventory := []assignedNetworkInspection{base}
				if f.network != nil {
					inventory = append(inventory, *f.network)
				}
				return encode(inventory)
			case "create":
				f.creates++
				if f.lastSaved == nil || f.lastSaved.State != "create-intent" {
					t.Fatal("Network created before retained intent")
				}
				a := f.value.NetworkAssignment
				expected := []string{"network", "create", "--internal", "--driver", "bridge", "--subnet", a.Subnet, "--ip-range", a.DynamicRange, "--gateway", "10.90.0.1", "--label", "io.autosoft.managed=true", "--label", "io.autosoft.app-resource=" + f.value.AppID, "--label", "io.autosoft.network-version=1", "--label", "io.autosoft.network-reservation=" + a.Reservation, f.value.Network}
				if !reflect.DeepEqual(args, expected) {
					t.Fatal("Unsafe or incomplete create arguments", args)
				}
				if !f.noCreateEffect {
					f.installNetwork()
				}
				if f.createError {
					return "", errors.New("Uncertain create response")
				}
				return f.network.ID, nil
			case "connect":
				f.connects++
				if len(args) != 8 || args[2] != "--ip" || args[4] != "--alias" {
					t.Fatal("Missing static address", args)
				}
				service := args[5]
				a := f.value.NetworkAssignment
				if f.lastSaved == nil || f.lastSaved.Attaching[service].ContainerID != args[7] || f.lastSaved.Attaching[service].State != "pending" || args[3] != a.Addresses[service] || args[6] != a.NetworkID || args[7] != f.containers[service]["Id"] {
					t.Fatal("Attachment outside saved exact reservation")
				}
				if !f.noConnectEffect {
					f.connect(service)
				}
				if f.connectError {
					return "", errors.New("Uncertain connect response")
				}
				return "", nil
			default:
				t.Fatal("Unexpected network mutation", args)
			}
		}
		if len(args) > 0 && args[0] == "ps" {
			for _, arg := range args {
				if strings.HasPrefix(arg, "label=com.docker.compose.service=") {
					service := strings.TrimPrefix(arg, "label=com.docker.compose.service=")
					return f.containers[service]["Id"].(string), nil
				}
			}
		}
		if len(args) == 4 && args[0] == "inspect" {
			for _, container := range f.containers {
				if container["Id"] == args[3] {
					return encode(container)
				}
			}
		}
		t.Fatal("Unexpected Docker command", args)
		return "", errors.New("Unexpected command")
	}
	return f
}

func (f *assignedNetworkFixture) installNetwork() {
	a := f.value.NetworkAssignment
	n := &assignedNetworkInspection{ID: strings.Repeat("9", 64), Name: f.value.Network, Driver: "bridge", Scope: "local", Internal: true, Labels: map[string]string{"io.autosoft.managed": "true", "io.autosoft.app-resource": f.value.AppID, "io.autosoft.network-version": "1", "io.autosoft.network-reservation": a.Reservation}}
	n.IPAM.Driver = "default"
	n.IPAM.Config = []struct{ Subnet, IPRange, Gateway string }{{a.Subnet, a.DynamicRange, "10.90.0.1"}}
	f.network = n
}

func (f *assignedNetworkFixture) connect(service string) {
	a := f.value.NetworkAssignment
	networks := f.containers[service]["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)
	networks[f.value.Network] = map[string]any{"IPAddress": a.Addresses[service], "NetworkID": a.NetworkID, "Aliases": []string{service}, "IPAMConfig": map[string]any{"IPv4Address": a.Addresses[service]}}
	f.connected[service] = true
}

func (f *assignedNetworkFixture) persist() error {
	f.saves++
	raw, _ := json.Marshal(f.value.NetworkAssignment)
	return json.Unmarshal(raw, &f.lastSaved)
}

func TestAppNetworkCreationAndStaticAttachmentAreReadBackAndIdempotent(t *testing.T) {
	f := newAssignedNetworkFixture(t)
	for attempt := 0; attempt < 2; attempt++ {
		if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err != nil {
			t.Fatal(err)
		}
	}
	if f.creates != 1 || f.connects != 5 || f.requests < 3 {
		t.Fatalf("Expected one create and five static attaches: %d %d", f.creates, f.connects)
	}
	for _, service := range appNetworkServices {
		hosts, err := f.server.trustedServiceHosts(context.Background(), f.value.Network, []string{service})
		if err != nil || !reflect.DeepEqual(hosts, []string{"--add-host", service + ":" + f.value.NetworkAssignment.Addresses[service]}) {
			t.Fatal("Trusted hosts did not preserve reserved address", err)
		}
	}
}

func TestAppNetworkUnknownCreateOutcomeNeverRepeatsCreation(t *testing.T) {
	for _, effect := range []bool{false, true} {
		t.Run(fmt.Sprint(effect), func(t *testing.T) {
			f := newAssignedNetworkFixture(t)
			f.createError = true
			f.noCreateEffect = !effect
			if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err == nil {
				t.Fatal("Unknown outcome accepted")
			}
			f.createError = false
			err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist)
			if (err == nil) != effect || f.creates != 1 {
				t.Fatal("Creation repeated or exact outcome not reconciled", err)
			}
		})
	}
}

func TestAppNetworkUnknownConnectOutcomeNeverBlindlyReconnects(t *testing.T) {
	for _, effect := range []bool{false, true} {
		t.Run(fmt.Sprint(effect), func(t *testing.T) {
			f := newAssignedNetworkFixture(t)
			f.connectError = true
			f.noConnectEffect = !effect
			if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err == nil {
				t.Fatal("Unknown outcome accepted")
			}
			f.connectError = false
			err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist)
			if (err == nil) != effect {
				t.Fatal("Unknown attachment outcome mishandled", err)
			}
			if (!effect && f.connects != 1) || (effect && f.connects != 5) {
				t.Fatal("Completed or uncertain connect repeated")
			}
		})
	}
}

func TestAppNetworkRefusesLegacyConflictsTamperingAndMissingIntentBeforeMutation(t *testing.T) {
	for _, mutation := range []string{"legacy", "pool_changed", "host_overlap", "adoption", "owner", "range", "network_id", "missing_created"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAssignedNetworkFixture(t)
			switch mutation {
			case "legacy":
				f.value.NetworkAssignment = nil
			case "pool_changed":
				t.Setenv("APP_NETWORK_POOL", "10.91.0.0/24")
			case "host_overlap":
				f.hostConflict = true
			case "missing_created":
				f.value.NetworkAssignment.State = "created"
				f.value.NetworkAssignment.NetworkID = strings.Repeat("9", 64)
			default:
				f.installNetwork()
				if mutation != "adoption" {
					f.value.NetworkAssignment.State = "create-intent"
				}
				switch mutation {
				case "owner":
					f.network.Labels["io.autosoft.app-resource"] = "another-app"
				case "range":
					f.network.IPAM.Config[0].IPRange = "10.90.0.0/27"
				case "network_id":
					f.network.ID = "short"
				}
			}
			if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err == nil {
				t.Fatal("Unsafe network accepted")
			}
			if f.creates != 0 || f.connects != 0 {
				t.Fatal("Unsafe network reached mutation")
			}
		})
	}
}

func TestAppNetworkRefusesDynamicOrUnsafeServiceBeforeConnect(t *testing.T) {
	for _, mutation := range []string{"dynamic", "wrong_ip", "missing_intent", "owner", "host_mode", "image"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAssignedNetworkFixture(t)
			f.installNetwork()
			a := f.value.NetworkAssignment
			a.State = "created"
			a.NetworkID = f.network.ID
			switch mutation {
			case "dynamic", "wrong_ip", "missing_intent":
				f.connect("mysql")
				if mutation != "missing_intent" {
					a.Attaching["mysql"] = appNetworkAttachment{ContainerID: f.containers["mysql"]["Id"].(string), State: "pending"}
				}
				endpoint := f.containers["mysql"]["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)[f.value.Network].(map[string]any)
				if mutation == "dynamic" {
					delete(endpoint, "IPAMConfig")
				} else if mutation == "wrong_ip" {
					endpoint["IPAddress"] = "10.90.0.33"
				}
			case "host_mode":
				f.containers["mysql"]["HostConfig"].(map[string]any)["NetworkMode"] = "host"
			case "owner":
				f.containers["mysql"]["Config"].(map[string]any)["Labels"].(map[string]string)["com.docker.compose.project"] = "customer"
			case "image":
				f.containers["mysql"]["Config"].(map[string]any)["Image"] = "mysql:latest"
			}
			if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err == nil || f.connects != 0 {
				t.Fatal("Unsafe service attached", err)
			}
		})
	}
}

func TestAppNetworkReservationIsSerializedAndRetainedBeforeEffects(t *testing.T) {
	f := newAssignedNetworkFixture(t)
	var group sync.WaitGroup
	results := make(chan string, 4)
	failures := make(chan error, 4)
	for index := 0; index < 4; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			value := resources{AppID: fmt.Sprintf("app-%d", index), Network: fmt.Sprintf("autosoft_app_%d", index)}
			err := f.server.reserveAppNetwork(context.Background(), &value, func() error {
				return writeEncrypted(filepath.Join(f.server.data, "resources", value.AppID+".enc"), value)
			})
			if err != nil {
				failures <- err
				return
			}
			results <- value.NetworkAssignment.Subnet
		}(index)
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for subnet := range results {
		if seen[subnet] {
			t.Fatal("Concurrent reservation reused subnet")
		}
		seen[subnet] = true
	}
	if len(seen) != 4 || f.creates != 0 || f.connects != 0 {
		t.Fatal("Reservation mutated Docker or lost an app")
	}
	extra := resources{AppID: "app-5", Network: "autosoft_app_5"}
	if err := f.server.reserveAppNetwork(context.Background(), &extra, func() error { t.Fatal("Exhausted reservation persisted"); return nil }); err == nil {
		t.Fatal("Retained reservations ignored")
	}
}

func TestAppNetworkProvisioningPreservesLegacyCredentialsAndDataBeforeSQL(t *testing.T) {
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("BROKER_VAULT_KEY_FILE", "")
	appID := "legacy-app"
	name := "app_" + hashBytes([]byte(appID))[:24]
	value := resources{AppID: appID, Database: name, User: name, Password: randomSecret(), RedisPassword: randomSecret(), RabbitPassword: randomSecret(), Network: "autosoft_app_legacy", Schema: 4}
	s := &server{data: t.TempDir(), runner: func(context.Context, string, ...string) (string, error) {
		t.Fatal("Legacy network reached host mutation")
		return "", nil
	}}
	file := filepath.Join(s.data, "resources", appID+".enc")
	if err := writeEncrypted(file, value); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(file)
	actual, err := s.provision(context.Background(), appID, AppManifest{}, false)
	after, _ := os.ReadFile(file)
	if err == nil || !strings.Contains(err.Error(), "legacy dynamic networking") || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(value, actual) {
		t.Fatal("Legacy provisioning changed retained resources or entered SQL", err)
	}
}

func TestAppNetworkCompletedAttachmentCannotBeReplacedOrSilentlyReconnected(t *testing.T) {
	for _, mutation := range []string{"missing_endpoint", "replacement_without_endpoint", "replacement_with_exact_endpoint"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAssignedNetworkFixture(t)
			if err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist); err != nil {
				t.Fatal(err)
			}
			before := f.connects
			if f.lastSaved.Attaching["mysql"].State != "verified" {
				t.Fatal("Completed attachment not retained")
			}
			if mutation != "missing_endpoint" {
				f.containers["mysql"]["Id"] = strings.Repeat("7", 64)
			}
			if mutation != "replacement_with_exact_endpoint" {
				delete(f.containers["mysql"]["NetworkSettings"].(map[string]any)["Networks"].(map[string]any), f.value.Network)
				f.connected["mysql"] = false
			}
			err := f.server.ensureAssignedAppNetwork(context.Background(), &f.value, f.persist)
			if err == nil || !strings.Contains(err.Error(), "IT must") || f.connects != before {
				t.Fatal("Changed completed attachment was adopted or automatically reconnected", err)
			}
		})
	}
}

type heldResourceWrite struct {
	value            resources
	entered, release chan struct{}
}

func (value heldResourceWrite) MarshalJSON() ([]byte, error) {
	close(value.entered)
	<-value.release
	return json.Marshal(value.value)
}

func TestAppNetworkInventoryWaitsForActiveResourceWriterButRejectsAbandonedTemporary(t *testing.T) {
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("BROKER_VAULT_KEY_FILE", "")
	s := &server{data: t.TempDir()}
	value := resources{AppID: "app-1", NetworkAssignment: newNetworkAssignment(netip.MustParsePrefix("10.90.0.0/24"), netip.MustParsePrefix("10.90.0.0/26"), strings.Repeat("a", 64))}
	file := filepath.Join(s.data, "resources", "app-1.enc")
	if err := writeEncrypted(file, value); err != nil {
		t.Fatal(err)
	}
	held := heldResourceWrite{value: value, entered: make(chan struct{}), release: make(chan struct{})}
	written := make(chan error, 1)
	go func() { written <- writeEncrypted(file, held) }()
	<-held.entered
	started := make(chan struct{})
	read := make(chan error, 1)
	go func() {
		close(started)
		subnets, err := s.retainedNetworkSubnets()
		if err == nil && (len(subnets) != 1 || subnets[0].String() != value.NetworkAssignment.Subnet) {
			err = errors.New("Committed reservation lost")
		}
		read <- err
	}()
	<-started
	premature := false
	select {
	case <-read:
		premature = true
	case <-time.After(30 * time.Millisecond):
	}
	close(held.release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if premature {
		t.Fatal("Inventory raced an identified active resource writer")
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".new", []byte("retained incomplete encrypted write"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.retainedNetworkSubnets(); err == nil {
		t.Fatal("Unowned pending resource evidence silently ignored")
	}
}
