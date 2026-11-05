package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const scannerCreatedNetworkFixture = `{"State":{"Status":"created","Running":false,"Pid":0,"StartedAt":"0001-01-01T00:00:00Z"},"Networks":{"autosoft_artifact":{"IPAMConfig":null,"Links":null,"Aliases":null,"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null}}}`

func TestScannerDocker29UnstartedEndpointAdmission(t *testing.T) {
	networkID := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		change  func(map[string]any, map[string]any, map[string]any)
		allowed bool
	}{
		{"native-created-empty", func(_, _, _ map[string]any) {}, true},
		{"native-exited-attached", func(_ map[string]any, s, n map[string]any) { s["Status"] = "exited"; n["NetworkID"] = networkID }, true},
		{"running-empty", func(_ map[string]any, s, _ map[string]any) { s["Status"] = "running"; s["Running"] = true }, false},
		{"exited-empty", func(_ map[string]any, s, _ map[string]any) { s["Status"] = "exited" }, false},
		{"created-foreign-network", func(_, _ map[string]any, n map[string]any) { n["NetworkID"] = strings.Repeat("b", 64) }, false},
		{"created-missing-id", func(_, _ map[string]any, n map[string]any) { delete(n, "NetworkID") }, false},
		{"created-with-process", func(_ map[string]any, s, _ map[string]any) { s["Pid"] = json.Number("12") }, false},
		{"created-previously-started", func(_ map[string]any, s, _ map[string]any) { s["StartedAt"] = "2026-10-15T00:00:00Z" }, false},
		{"created-with-address", func(_, _ map[string]any, n map[string]any) { n["IPAddress"] = "172.20.0.9" }, false},
		{"created-with-endpoint", func(_, _ map[string]any, n map[string]any) { n["EndpointID"] = strings.Repeat("b", 64) }, false},
		{"created-missing-endpoint", func(_, _ map[string]any, n map[string]any) { delete(n, "EndpointID") }, false},
		{"created-static-ipam", func(_, _ map[string]any, n map[string]any) {
			n["IPAMConfig"] = map[string]any{"IPv4Address": "172.20.0.9"}
		}, false},
		{"created-with-alias", func(_, _ map[string]any, n map[string]any) { n["Aliases"] = []any{"other"} }, false},
		{"created-other-name", func(networks, _, _ map[string]any) {
			networks["other"] = networks["autosoft_artifact"]
			delete(networks, "autosoft_artifact")
		}, false},
		{"created-extra-network", func(networks, _, _ map[string]any) { networks["other"] = map[string]any{} }, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture, err := imageScannerJSON([]byte(scannerCreatedNetworkFixture))
			if err != nil {
				t.Fatal(err)
			}
			networks, state := scannerMap(fixture["Networks"]), scannerMap(fixture["State"])
			test.change(networks, state, scannerMap(networks["autosoft_artifact"]))
			if imageScannerNetworkState(networks, state, networkID) != test.allowed {
				t.Fatal("Incorrect native lifecycle admission")
			}
		})
	}
}
