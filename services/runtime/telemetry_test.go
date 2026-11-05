package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type telemetryTransport func(*http.Request) (*http.Response, error)

func (t telemetryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }

func TestMeasuredTelemetryContainsOwnedContainersAndActualMetrics(t *testing.T) {
	rows, e := containerTelemetry(`{"Names":"autosoft-mysql-1","State":"running","Status":"Up2minutes(healthy)","Labels":"com.docker.compose.project=autosoft"}
{"Names":"as-preview-app1","State":"running","Status":"Up1minute(unhealthy)","Labels":"io.autosoft.managed=true"}
{"Names":"other","State":"running","Status":"Up1minute","Labels":""}`, `{"Name":"autosoft-mysql-1","CPUPerc":"2.3%","MemUsage":"145MiB/1GiB","MemPerc":"14%","NetIO":"1kB / 2kB","BlockIO":"0B / 3MB","PIDs":"12"}`)
	if e != nil || len(rows) != 2 || rows[0]["cpuPercent"] != "2.3%" || rows[0]["name"] != "autosoft-mysql-1" || rows[1]["status"] != "degraded" {
		t.Fatalf("Measured services invalid: %+v %v", rows, e)
	}
	if _, e = containerTelemetry("malformed", ""); e == nil {
		t.Fatal("Unavailable Docker data passed")
	}
}

func TestDocker29TelemetryIgnoresUnrelatedStructuredMetadata(t *testing.T) {
	// Docker29's real ps formatter adds Platform as an object, not a string.
	containers := `{"ID":"d66c2e850fd8","Image":"registry.internal/mysql@sha256:fixture","Command":"docker-entrypoint.sh","CreatedAt":"2026-10-10 17:01:02 +0000 UTC","RunningFor":"2 minutes","Ports":"3306/tcp","Names":"autosoft-mysql-1","State":"running","Status":"Up 2 minutes (healthy)","Size":"0B","Labels":"com.docker.compose.project=autosoft,com.docker.compose.service=mysql,io.autosoft.managed=true","Mounts":"autosoft-mysql","Networks":"autosoft_private","LocalVolumes":"1","Platform":{"architecture":"amd64","os":"linux"}}
{"Names":"foreign-service","State":"running","Status":"Up 1 minute","Labels":"com.docker.compose.project=other","Platform":{"architecture":"amd64","os":"linux"}}
{"Names":"as-app-stopped","State":"exited","Status":"Exited (0) 1 minute ago","Labels":"io.autosoft.managed=true","Platform":{"architecture":"amd64","os":"linux"}}`
	stats := `{"Name":"autosoft-mysql-1","ID":"d66c2e850fd8","Container":"d66c2e850fd8","CPUPerc":"2.30%","MemUsage":"145MiB / 1GiB","MemPerc":"14.16%","NetIO":"1.2kB / 3.4kB","BlockIO":"0B / 8.19kB","PIDs":"12","Platform":{"architecture":"amd64","os":"linux"},"AdditionalMetadata":[1,false,null]}`
	rows, err := containerTelemetry(containers, stats)
	if err != nil || len(rows) != 2 {
		t.Fatalf("Docker29 metadata made actual measurements unavailable: %+v %v", rows, err)
	}
	for field, expected := range map[string]string{"name": "autosoft-mysql-1", "status": "running", "cpuPercent": "2.30%", "memoryUsage": "145MiB / 1GiB", "memoryPercent": "14.16%", "networkIO": "1.2kB / 3.4kB", "blockIO": "0B / 8.19kB", "pids": "12"} {
		if rows[0][field] != expected {
			t.Fatalf("Required measured field %s changed: %+v", field, rows[0])
		}
	}
	if rows[1]["status"] != "stopped" || rows[1]["cpuPercent"] != nil {
		t.Fatalf("Stopped service acquired invented measurements: %+v", rows[1])
	}
	if _, copied := rows[0]["Platform"]; copied {
		t.Fatal("Unrelated Docker metadata entered the telemetry contract")
	}
}

func TestDockerTelemetryRejectsMalformedRequiredServiceFields(t *testing.T) {
	base := map[string]any{"Names": "autosoft-mysql-1", "State": "running", "Status": "Up 2 minutes (healthy)", "Labels": "com.docker.compose.project=autosoft", "Platform": map[string]string{"architecture": "amd64", "os": "linux"}}
	for _, field := range []string{"Names", "State", "Status", "Labels"} {
		for _, value := range []any{nil, 29, true, map[string]string{"unexpected": "object"}, []string{"unexpected"}, "bad\nvalue"} {
			t.Run(fmt.Sprintf("%s/%T", field, value), func(t *testing.T) {
				row := make(map[string]any, len(base))
				for key, item := range base {
					row[key] = item
				}
				row[field] = value
				encoded, _ := json.Marshal(row)
				if _, err := containerTelemetry(string(encoded), ""); err == nil {
					t.Fatalf("Malformed required %s passed as measured service state", field)
				}
			})
		}
		row := make(map[string]any, len(base))
		for key, item := range base {
			if key != field {
				row[key] = item
			}
		}
		encoded, _ := json.Marshal(row)
		if _, err := containerTelemetry(string(encoded), ""); err == nil {
			t.Fatalf("Missing required %s passed", field)
		}
	}
	for _, field := range []string{"Names", "State", "Status"} {
		for _, value := range []string{"", "   "} {
			encoded, _ := json.Marshal(map[string]any{"Names": "owned", "State": "running", "Status": "Up", "Labels": "io.autosoft.managed=true", field: value})
			if _, err := containerTelemetry(string(encoded), ""); err == nil {
				t.Fatalf("Empty required %s passed", field)
			}
		}
	}
	if _, err := containerTelemetry(`{"Names":"owned","State":"unknown","Status":"Up","Labels":"io.autosoft.managed=true"}`, ""); err == nil {
		t.Fatal("Unknown container state silently became stopped")
	}
}

func TestDockerTelemetryRejectsMalformedRequiredMeasurements(t *testing.T) {
	containers := `{"Names":"autosoft-mysql-1","State":"running","Status":"Up 2 minutes","Labels":"com.docker.compose.project=autosoft"}`
	base := map[string]any{"Name": "autosoft-mysql-1", "CPUPerc": "2.30%", "MemUsage": "145MiB / 1GiB", "MemPerc": "14.16%", "NetIO": "0B / 0B", "BlockIO": "0B / 0B", "PIDs": "12", "Platform": map[string]string{"architecture": "amd64", "os": "linux"}}
	for _, field := range []string{"Name", "CPUPerc", "MemUsage", "MemPerc", "NetIO", "BlockIO", "PIDs"} {
		for _, value := range []any{nil, 29, true, map[string]string{"unexpected": "object"}, []string{"unexpected"}, "", "   ", "bad\nvalue", strings.Repeat("x", 301)} {
			t.Run(fmt.Sprintf("%s/%T", field, value), func(t *testing.T) {
				row := make(map[string]any, len(base))
				for key, item := range base {
					row[key] = item
				}
				row[field] = value
				encoded, _ := json.Marshal(row)
				if _, err := containerTelemetry(containers, string(encoded)); err == nil {
					t.Fatalf("Malformed required measurement %s passed", field)
				}
			})
		}
		row := make(map[string]any, len(base))
		for key, item := range base {
			if key != field {
				row[key] = item
			}
		}
		encoded, _ := json.Marshal(row)
		if _, err := containerTelemetry(containers, string(encoded)); err == nil {
			t.Fatalf("Missing required measurement %s passed", field)
		}
	}
}

func TestDockerTelemetryRejectsDuplicateMeasuredIdentities(t *testing.T) {
	container := `{"Names":"autosoft-mysql-1","State":"running","Status":"Up 2 minutes","Labels":"com.docker.compose.project=autosoft"}`
	stats := `{"Name":"autosoft-mysql-1","CPUPerc":"2.30%","MemUsage":"145MiB / 1GiB","MemPerc":"14.16%","NetIO":"0B / 0B","BlockIO":"0B / 0B","PIDs":"12"}`
	if _, err := containerTelemetry(container+"\n"+container, stats); err == nil {
		t.Fatal("Duplicate owned service identity passed")
	}
	if _, err := containerTelemetry(container, stats+"\n"+stats); err == nil {
		t.Fatal("Duplicate measurement silently overwrote prior evidence")
	}
}

func TestHostTelemetryAuthenticatesAndRequiresValidStorageMeasurements(t *testing.T) {
	response := `{"host":{"name":"vm","status":"healthy","detail":"Measured","cpuCount":4,"loadAverage":[0.1,0.2,0.3],"memoryTotalBytes":16000,"memoryAvailableBytes":12000,"diskTotalBytes":128000,"diskFreeBytes":120000,"uptimeSeconds":200,"encryptedDataMounted":true}}`
	client := &http.Client{Transport: telemetryTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Path != "/v1/telemetry" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Fatal("Host telemetry request was not scoped/authenticated")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response))}, nil
	})}
	h, e := fetchHostTelemetry(context.Background(), client, "fixture")
	if e != nil || h.CPUCount != 4 || h.DiskFreeBytes != 120000 {
		t.Fatalf("Actual host metrics unavailable: %+v %v", h, e)
	}
	response = strings.ReplaceAll(response, `"encryptedDataMounted":true`, `"encryptedDataMounted":false`)
	h, e = fetchHostTelemetry(context.Background(), client, "fixture")
	if e != nil || h.Status != "degraded" {
		t.Fatal("Failed mount displayed as healthy")
	}
	response = strings.ReplaceAll(response, `"memoryAvailableBytes":12000`, `"memoryAvailableBytes":20000`)
	if _, e = fetchHostTelemetry(context.Background(), client, "fixture"); e == nil {
		t.Fatal("Invalid measurements passed")
	}
}
