package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type hostTelemetry struct {
	Name                 string    `json:"name"`
	Status               string    `json:"status"`
	Detail               string    `json:"detail"`
	CPUCount             int       `json:"cpuCount"`
	LoadAverage          []float64 `json:"loadAverage"`
	MemoryTotalBytes     uint64    `json:"memoryTotalBytes"`
	MemoryAvailableBytes uint64    `json:"memoryAvailableBytes"`
	DiskTotalBytes       uint64    `json:"diskTotalBytes"`
	DiskFreeBytes        uint64    `json:"diskFreeBytes"`
	UptimeSeconds        float64   `json:"uptimeSeconds"`
	EncryptedDataMounted bool      `json:"encryptedDataMounted"`
}

func fetchHostTelemetry(ctx context.Context, client *http.Client, token string) (hostTelemetry, error) {
	var result struct {
		Host hostTelemetry `json:"host"`
	}
	request, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/v1/telemetry", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, e := client.Do(request)
	if e != nil {
		return result.Host, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&result) != nil {
		return result.Host, errors.New("Host telemetry unavailable")
	}
	h := result.Host
	if h.Name != "vm" || (h.Status != "healthy" && h.Status != "degraded") || h.CPUCount < 1 || len(h.LoadAverage) != 3 || h.MemoryTotalBytes == 0 || h.MemoryAvailableBytes > h.MemoryTotalBytes || h.DiskTotalBytes == 0 || h.DiskFreeBytes > h.DiskTotalBytes || h.UptimeSeconds < 0 || len(h.Detail) > 2000 {
		return h, errors.New("Host telemetry returned invalid measured values")
	}
	for _, load := range h.LoadAverage {
		if load < 0 {
			return h, errors.New("Invalid host load")
		}
	}
	if !h.EncryptedDataMounted {
		h.Status = "degraded"
	}
	return h, nil
}

func managedContainer(labels string) bool {
	for _, label := range strings.Split(labels, ",") {
		if label == "io.autosoft.managed=true" || label == "com.docker.compose.project=autosoft" {
			return true
		}
	}
	return false
}

// Docker's formatter may add objects such as Platform. Only these known fields
// are consumed; pointers distinguish missing/null required strings from values.
type dockerServiceTelemetry struct {
	Names  *string `json:"Names"`
	State  *string `json:"State"`
	Status *string `json:"Status"`
	Labels *string `json:"Labels"`
}

type dockerMeasurementTelemetry struct {
	Name     *string `json:"Name"`
	CPUPerc  *string `json:"CPUPerc"`
	MemUsage *string `json:"MemUsage"`
	MemPerc  *string `json:"MemPerc"`
	NetIO    *string `json:"NetIO"`
	BlockIO  *string `json:"BlockIO"`
	PIDs     *string `json:"PIDs"`
}

func validDockerTelemetryString(value *string, required bool, limit int) bool {
	if value == nil || len(*value) > limit || (required && strings.TrimSpace(*value) == "") {
		return false
	}
	for _, ch := range *value {
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

func validDockerTelemetryState(state string) bool {
	switch state {
	case "created", "running", "paused", "restarting", "removing", "exited", "dead":
		return true
	default:
		return false
	}
}

func containerTelemetry(containers, stats string) ([]map[string]any, error) {
	measurements := map[string]dockerMeasurementTelemetry{}
	for _, line := range strings.Split(strings.TrimSpace(stats), "\n") {
		if line == "" {
			continue
		}
		var row dockerMeasurementTelemetry
		if json.Unmarshal([]byte(line), &row) != nil || !validDockerTelemetryString(row.Name, true, 300) {
			return nil, errors.New("Invalid Docker measurements")
		}
		for _, field := range []*string{row.CPUPerc, row.MemUsage, row.MemPerc, row.NetIO, row.BlockIO, row.PIDs} {
			if !validDockerTelemetryString(field, true, 200) {
				return nil, errors.New("Invalid Docker measurements")
			}
		}
		if _, duplicate := measurements[*row.Name]; duplicate {
			return nil, errors.New("Duplicate Docker measurement identity")
		}
		measurements[*row.Name] = row
	}
	services := []map[string]any{}
	identities := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(containers), "\n") {
		if line == "" {
			continue
		}
		var row dockerServiceTelemetry
		if json.Unmarshal([]byte(line), &row) != nil || !validDockerTelemetryString(row.Names, true, 300) || !validDockerTelemetryString(row.State, true, 30) || !validDockerTelemetryString(row.Status, true, 2000) || !validDockerTelemetryString(row.Labels, false, 16384) || !validDockerTelemetryState(*row.State) {
			return nil, errors.New("Invalid Docker service state")
		}
		if !managedContainer(*row.Labels) {
			continue
		}
		if identities[*row.Names] {
			return nil, errors.New("Duplicate Docker service identity")
		}
		identities[*row.Names] = true
		status := "stopped"
		if *row.State == "running" {
			status = "running"
		}
		if strings.Contains(*row.Status, "unhealthy") || *row.State == "restarting" || *row.State == "dead" {
			status = "degraded"
		}
		service := map[string]any{"name": *row.Names, "status": status, "detail": *row.Status}
		if m, ok := measurements[*row.Names]; ok {
			service["cpuPercent"] = *m.CPUPerc
			service["memoryUsage"] = *m.MemUsage
			service["memoryPercent"] = *m.MemPerc
			service["networkIO"] = *m.NetIO
			service["blockIO"] = *m.BlockIO
			service["pids"] = *m.PIDs
			service["detail"] = fmt.Sprintf("%s; CPU %s; memory %s; processes %s", *row.Status, *m.CPUPerc, *m.MemUsage, *m.PIDs)
		}
		services = append(services, service)
	}
	return services, nil
}

func (s *server) telemetry(w http.ResponseWriter, r *http.Request) {
	var value map[string]any
	if !decode(w, r, &value) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	containers, e := s.runner(ctx, "docker", "ps", "--all", "--format", "{{json .}}")
	stats, statError := s.runner(ctx, "docker", "stats", "--no-stream", "--format", "{{json .}}")
	services := []map[string]any{}
	if e == nil && statError == nil {
		services, e = containerTelemetry(containers, stats)
	}
	if e != nil || statError != nil {
		services = []map[string]any{{"name": "containers", "status": "unavailable", "detail": "Container measurements are unavailable"}}
	}
	var hostError error
	token, hostError := secret("QUOTA_HELPER_TOKEN")
	var host hostTelemetry
	if hostError == nil {
		host, hostError = fetchHostTelemetry(ctx, caddyClient(env("QUOTA_HELPER_SOCKET_FILE", "/run/autosoft/quota.sock")), token)
	}
	if hostError == nil {
		encoded, _ := json.Marshal(host)
		var measured map[string]any
		_ = json.Unmarshal(encoded, &measured)
		services = append([]map[string]any{measured}, services...)
	} else {
		services = append([]map[string]any{{"name": "vm", "status": "unavailable", "detail": "Authenticated host measurements are unavailable"}}, services...)
	}
	available := e == nil && statError == nil && hostError == nil && host.EncryptedDataMounted
	var certificateReport struct {
		CheckedAt string                `json:"checkedAt"`
		Results   []appTLSRenewalResult `json:"results"`
	}
	certificateStatus, certificateDetail := "unavailable", "Application certificate renewal has not produced a fresh report"
	if b, e := os.ReadFile(filepath.Join(s.data, "reports", "tls-renewal-report.json")); e == nil && len(b) <= 2<<20 && json.Unmarshal(b, &certificateReport) == nil {
		checked, e := time.Parse(time.RFC3339, certificateReport.CheckedAt)
		if e == nil && time.Since(checked) < 2*time.Hour && !checked.After(time.Now().Add(time.Minute)) {
			certificateStatus = "healthy"
			certificateDetail = fmt.Sprintf("%d application/preview certificates checked; leaves renew within30days", len(certificateReport.Results))
			for _, result := range certificateReport.Results {
				if result.Status == "failed" || result.Status == "unavailable" {
					certificateStatus = "degraded"
					certificateDetail = "Application certificate renewal requires attention: " + result.Detail
					break
				}
			}
		}
	}
	services = append(services, map[string]any{"name": "application-certificates", "status": certificateStatus, "detail": certificateDetail})
	var signingReport struct {
		CheckedAt     string                 `json:"checkedAt"`
		MaxAgeSeconds int                    `json:"maxAgeSeconds"`
		Results       []appJWKSRefreshResult `json:"results"`
	}
	signingStatus, signingDetail := "unavailable", "Application signing-key refresh has not produced a fresh report"
	if err := readBoundedJSON(filepath.Join(s.data, "reports", "jwks-refresh-report.json"), &signingReport); err == nil {
		checked, err := time.Parse(time.RFC3339, signingReport.CheckedAt)
		if err == nil && time.Since(checked) < 15*time.Minute && !checked.After(time.Now().Add(time.Minute)) && signingReport.MaxAgeSeconds == 3600 {
			signingStatus, signingDetail = "healthy", fmt.Sprintf("%d application/preview signing-key sets checked; one-hour freshness limit", len(signingReport.Results))
			for _, result := range signingReport.Results {
				if result.Status != "current" && result.Status != "refreshed" && result.Status != "not_running" {
					signingStatus, signingDetail = "degraded", "Application signing-key refresh requires attention: "+result.Detail
					break
				}
			}
		}
	}
	services = append(services, map[string]any{"name": "application-signing-keys", "status": signingStatus, "detail": signingDetail})
	services = append(services, s.filesystemRevocationTelemetry())
	status := "unavailable"
	if available {
		status = "healthy"
	}
	detail := "Measured container resources, encrypted disk, VM memory/load and sandbox concurrency"
	if !available {
		detail = "Some measurements or the encrypted data mount are unavailable"
	}
	respond(w, map[string]any{"services": services, "broker": map[string]any{"status": status, "available": available, "detail": detail, "concurrentBuildLimit": 1, "buildsRunning": len(s.buildSlot)}})
}
