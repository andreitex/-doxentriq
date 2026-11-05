package main

// Revocation is a read/stop reconciler only. It never provisions, starts, removes
// containers or changes source files, credentials, approval records or data.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type filesystemRevocationResult struct {
	AppID        string `json:"appId,omitempty"`
	ConnectionID string `json:"connectionId,omitempty"`
	ResourceID   string `json:"resourceId,omitempty"`
	ContainerID  string `json:"containerId,omitempty"`
	Status       string `json:"status"`
	Detail       string `json:"detail"`
	CheckedAt    string `json:"checkedAt"`
}

type filesystemLiveReceipt struct {
	AppID, ResourceID, ConnectionID, ScopeHash, Image, SourceHash, Adapter, ContainerID, CheckedAt, FeedUpdatedAt, ExpiresAt, Status string
}

type filesystemRevocationContainer struct {
	ID     string `json:"Id"`
	Name   string
	Config struct {
		Labels map[string]string
		Env    []string
	}
	State struct {
		Running, Paused, Restarting bool
		Status                      string
	}
	NetworkSettings struct {
		Networks map[string]struct{ NetworkID, IPAddress string }
	}
}

// The default sixty-second check is not a promise of instantaneous registry
// revocation. Busy app locks and unavailable provenance are explicitly reported.
func (s *server) startFilesystemRevocation(ctx context.Context, interval time.Duration) <-chan struct{} {
	if interval <= 0 || interval > time.Minute {
		interval = time.Minute
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			s.reconcileFilesystemRevocations(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func (s *server) reconcileFilesystemRevocations(ctx context.Context) []filesystemRevocationResult {
	passLock, _ := s.locks.LoadOrStore("filesystem-revocation-pass", &sync.Mutex{})
	if !passLock.(*sync.Mutex).TryLock() {
		return []filesystemRevocationResult{{Status: "unavailable", Detail: "A filesystem revocation pass is already running", CheckedAt: time.Now().UTC().Format(time.RFC3339)}}
	}
	defer passLock.(*sync.Mutex).Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	results := []filesystemRevocationResult{}
	unavailable := func(detail string) {
		results = append(results, filesystemRevocationResult{Status: "unavailable", Detail: detail, CheckedAt: time.Now().UTC().Format(time.RFC3339)})
	}
	out, err := s.runner(ctx, "docker", "ps", "--all", "--no-trunc", "--filter", "label=io.autosoft.managed=true", "--filter", "label=io.autosoft.connector.type=filesystem", "--format", "{{.ID}}")
	ids := strings.Fields(out)
	if err != nil || len(out) > 256*65 || len(ids) > 256 {
		unavailable("Bounded filesystem adapter inventory is unavailable; no container was stopped")
	} else {
		seen := map[string]bool{}
		valid := true
		for _, id := range ids {
			if !exactDockerID.MatchString(id) || seen[id] {
				unavailable("Filesystem adapter inventory contains ambiguous immutable IDs; all containers were preserved")
				valid = false
				break
			}
			seen[id] = true
		}
		if !valid {
			ids = nil
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				unavailable("Filesystem revocation pass reached its time bound; remaining adapters require reconciliation")
				break
			}
			results = append(results, s.reconcileFilesystemRevocationTarget(ctx, id, s.loadCurrentFilesystemSource))
		}
	}
	if atomicJSON(filepath.Join(s.data, "reports", "filesystem-revocation-report.json"), map[string]any{"checkedAt": time.Now().UTC().Format(time.RFC3339), "checkIntervalSeconds": 60, "registryRevocationSupported": false, "results": results}) != nil {
		unavailable("Filesystem revocation report could not be persisted")
	}
	return results
}

func (s *server) filesystemRevocationProvenance(ctx context.Context, id string, raw []byte) (filesystemRevocationContainer, filesystemContainerExpected, error) {
	var c filesystemRevocationContainer
	if len(raw) > 2<<20 || json.Unmarshal(raw, &c) != nil || c.ID != id || !exactDockerID.MatchString(id) {
		return c, filesystemContainerExpected{}, errors.New("Exact filesystem container discovery is unavailable")
	}
	appID, connectionID, candidate := c.Config.Labels["io.autosoft.connector.app"], c.Config.Labels["io.autosoft.connector.id"], c.Config.Labels["io.autosoft.connector.resource"]
	if !identity.MatchString(appID) || !identity.MatchString(connectionID) || !identity.MatchString(candidate) {
		return c, filesystemContainerExpected{}, errors.New("Filesystem adapter scope labels are invalid")
	}
	var state filesystemConnectorState
	if readEncrypted(s.filesystemStatePath(appID, connectionID), &state) != nil || state.Input.Scope.AppID != appID || state.Input.Scope.ConnectionID != connectionID || validateFilesystemRetirementState(state) != nil {
		return c, filesystemContainerExpected{}, errors.New("Filesystem original approved scope is unavailable")
	}
	var index connectorCandidate
	if readEncrypted(filepath.Join(s.data, "connectors", "candidates", candidate+".enc"), &index) != nil || index.AppID != appID || index.ResourceID != candidate || (index.OwnerResourceID != appID && index.OwnerResourceID != appID+"_preview") || len(index.Connections) == 0 || len(index.Connections) > 64 {
		return c, filesystemContainerExpected{}, errors.New("Filesystem encrypted candidate ownership is unavailable")
	}
	prefix := "as-app-" + appID + "-"
	if index.OwnerResourceID == appID+"_preview" {
		prefix = "as-preview-" + appID + "-"
	}
	if !strings.HasPrefix(candidate, prefix) || !regexp.MustCompile(`^[a-f0-9]{8}$`).MatchString(strings.TrimPrefix(candidate, prefix)) {
		return c, filesystemContainerExpected{}, errors.New("Filesystem candidate is outside its exact app namespace")
	}
	found, seen := false, map[string]bool{}
	for _, connection := range index.Connections {
		if !identity.MatchString(connection) || seen[connection] {
			return c, filesystemContainerExpected{}, errors.New("Filesystem candidate membership is ambiguous")
		}
		seen[connection] = true
		found = found || connection == connectionID
	}
	var resource resources
	if !found || readEncrypted(filepath.Join(s.data, "resources", index.OwnerResourceID+".enc"), &resource) != nil || resource.AppID != index.OwnerResourceID || resource.Network != "autosoft_app_"+hashBytes([]byte(index.OwnerResourceID))[:24] || index.Network != resource.Network || resource.Secrets != filepath.Join(s.data, "secrets", index.OwnerResourceID) {
		return c, filesystemContainerExpected{}, errors.New("Filesystem logical app resource/network ownership is unavailable")
	}
	resource.AppID = candidate
	expected, err := s.expectedFilesystemContainer(state, resource)
	if err != nil {
		return c, expected, err
	}
	validated, err := validateFilesystemContainer(raw, expected)
	if err != nil || validated != id {
		return c, expected, errors.New("Filesystem immutable container, image or readonly mounts changed")
	}
	// Docker keeps duplicate environment entries. The existence of the expected
	// entry alone cannot prove which value the adapter actually consumed.
	sealed := map[string]string{"CONNECTOR_CONFIG_FILE": "/run/connector/config.json", "CONNECTOR_TOKEN_FILE": "/run/connector/token", "CONNECTOR_TLS_CERT_FILE": "/run/connector/app.crt", "CONNECTOR_TLS_KEY_FILE": "/run/connector/app.key"}
	envSeen := map[string]bool{}
	for _, entry := range c.Config.Env {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "CONNECTOR_") {
			if sealed[name] != value || envSeen[name] {
				return c, expected, errors.New("Filesystem sealed environment is ambiguous or drifted")
			}
			envSeen[name] = true
		}
	}
	var receipt filesystemLiveReceipt
	if readBoundedJSON(filepath.Join(s.data, "connectors", "filesystem-live", candidate, connectionID+".json"), &receipt) != nil || receipt.AppID != appID || receipt.ResourceID != candidate || receipt.ConnectionID != connectionID || receipt.ContainerID != id || receipt.Adapter != expected.Name || receipt.ScopeHash != state.ScopeHash || receipt.Image != state.Template.Image || receipt.SourceHash != state.Template.SourceHash || receipt.ExpiresAt != state.Input.Scope.AccessExpiresAt || receipt.Status != "passed" {
		return c, expected, errors.New("Filesystem original immutable live-container receipt differs")
	}
	checked, err := time.Parse(time.RFC3339, receipt.CheckedAt)
	prepared, pe := time.Parse(time.RFC3339, state.PreparedAt)
	if err != nil || pe != nil || checked.Before(prepared) || checked.After(time.Now().Add(time.Minute)) {
		return c, expected, errors.New("Filesystem original live evidence time is invalid")
	}
	out, err := s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", resource.Network)
	network, ne := inspectServiceNetwork(out, resource.Network)
	if err != nil || ne != nil || network.Labels["io.autosoft.managed"] != "true" {
		return c, expected, errors.New("Filesystem independently owned private network is unavailable")
	}
	if c.State.Running {
		endpoint, ok := c.NetworkSettings.Networks[resource.Network]
		member, present := network.Containers[id]
		ip := trustedServiceIPv4(endpoint.IPAddress)
		retainedIP, _, parseErr := net.ParseCIDR(member.IPv4Address)
		inside := false
		for _, item := range network.IPAM.Config {
			_, subnet, err := net.ParseCIDR(item.Subnet)
			if err == nil && subnet.IP.To4() != nil && subnet.Contains(ip) {
				inside = true
			}
		}
		if !ok || endpoint.NetworkID != network.ID || !present || parseErr != nil || ip == nil || !retainedIP.Equal(ip) || !inside {
			return c, expected, errors.New("Filesystem immutable adapter membership in its exact private network changed")
		}
	}
	return c, expected, nil
}

// This summary intentionally discards all per-app IDs, source paths and dynamic
// details before telemetry. A malformed or old report never implies health.
func (s *server) filesystemRevocationTelemetry() map[string]any {
	result := map[string]any{"name": "filesystem-source-scopes", "status": "unavailable", "detail": "Filesystem source revocation evidence is missing, malformed or stale"}
	file := filepath.Join(s.data, "reports", "filesystem-revocation-report.json")
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return result
	}
	var report struct {
		CheckedAt                   string                       `json:"checkedAt"`
		CheckIntervalSeconds        int                          `json:"checkIntervalSeconds"`
		RegistryRevocationSupported *bool                        `json:"registryRevocationSupported"`
		Results                     []filesystemRevocationResult `json:"results"`
	}
	if readBoundedJSON(file, &report) != nil || report.CheckIntervalSeconds != 60 || report.RegistryRevocationSupported == nil || *report.RegistryRevocationSupported || report.Results == nil || len(report.Results) > 257 {
		return result
	}
	now := time.Now()
	checked, err := time.Parse(time.RFC3339, report.CheckedAt)
	if err != nil || checked.After(now) || now.Sub(checked) > 5*time.Minute {
		return result
	}
	current, stopped, pending := 0, 0, 0
	seen := map[string]bool{}
	for _, item := range report.Results {
		at, err := time.Parse(time.RFC3339, item.CheckedAt)
		if err != nil || at.After(checked) || now.Sub(at) > 5*time.Minute || len(item.Detail) > 2000 || item.ContainerID != "" && (!exactDockerID.MatchString(item.ContainerID) || seen[item.ContainerID]) {
			return result
		}
		if item.AppID != "" && !identity.MatchString(item.AppID) || item.ConnectionID != "" && !identity.MatchString(item.ConnectionID) || item.ResourceID != "" && !identity.MatchString(item.ResourceID) {
			return result
		}
		if item.ContainerID != "" {
			seen[item.ContainerID] = true
		}
		if item.Status != "unavailable" && (!identity.MatchString(item.AppID) || !identity.MatchString(item.ConnectionID) || !identity.MatchString(item.ResourceID) || !exactDockerID.MatchString(item.ContainerID)) {
			return result
		}
		switch item.Status {
		case "current":
			current++
		case "stopped":
			stopped++
		case "unavailable":
			pending++
		default:
			return result
		}
	}
	result["status"] = "healthy"
	if stopped > 0 || pending > 0 {
		result["status"] = "degraded"
	}
	result["detail"] = fmt.Sprintf("%d filesystem scopes current; %d scopes stopped after withdrawal, change or expiry; %d scopes pending reconciliation. Registry edits alone do not revoke running scopes.", current, stopped, pending)
	return result
}

// currentScope is always loadCurrentFilesystemSource in production. Injection here
// permits protocol tests on Windows without pretending it has Linux inode proof.
func (s *server) reconcileFilesystemRevocationTarget(ctx context.Context, id string, currentScope func(string, string) (filesystemConnectorState, error)) filesystemRevocationResult {
	result := filesystemRevocationResult{ContainerID: id, Status: "unavailable", Detail: "Filesystem adapter provenance is unavailable; no stop or deletion was attempted", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
	var discovery filesystemRevocationContainer
	if err != nil || len(out) > 2<<20 || json.Unmarshal([]byte(out), &discovery) != nil || discovery.ID != id || !exactDockerID.MatchString(id) || !identity.MatchString(discovery.Config.Labels["io.autosoft.connector.app"]) {
		return result
	}
	appID := discovery.Config.Labels["io.autosoft.connector.app"]
	appLock, _ := s.locks.LoadOrStore("app-"+appID, &sync.Mutex{})
	if !appLock.(*sync.Mutex).TryLock() {
		result.AppID, result.Detail = appID, "Application operation is busy; filesystem revocation is deferred and must be retried"
		return result
	}
	defer appLock.(*sync.Mutex).Unlock()
	// Rediscover after acquiring the app lock; no labels or captured mounts from
	// the unlocked read are used as authority for the eventual stop.
	out, err = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
	if err != nil {
		return result
	}
	c, expected, err := s.filesystemRevocationProvenance(ctx, id, []byte(out))
	if err != nil || expected.AppID != appID {
		return result
	}
	result.AppID, result.ConnectionID, result.ResourceID = expected.AppID, expected.ConnectionID, expected.ResourceID
	if _, err = currentScope(expected.AppID, expected.ConnectionID); err == nil {
		result.Status, result.Detail = "current", "Filesystem catalog, source identity, qualified adapter and approval expiry remain current; no container was started"
		return result
	}
	if c.State.Paused || c.State.Restarting || (c.State.Running && c.State.Status != "running") || (!c.State.Running && c.State.Status != "exited" && c.State.Status != "created") {
		result.Detail = "Filesystem runtime state is ambiguous; exact revocation remains pending"
		return result
	}
	if !c.State.Running {
		result.Status, result.Detail = "stopped", "Expired or withdrawn filesystem capability is independently confirmed stopped; data and approval records are preserved"
		return result
	}
	// Recheck current company policy and the exact immutable container immediately
	// before stopping it. A replacement with the same name is never targeted.
	if _, err = currentScope(expected.AppID, expected.ConnectionID); err == nil {
		result.Status, result.Detail = "current", "Filesystem catalog/source became current before revocation; no container was stopped"
		return result
	}
	out, err = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
	before, pinned, proofErr := s.filesystemRevocationProvenance(ctx, id, []byte(out))
	if ctx.Err() != nil || err != nil || proofErr != nil || pinned != expected || !before.State.Running || before.State.Paused || before.State.Restarting || before.State.Status != "running" {
		result.Detail = "Filesystem immutable provenance changed before stop; no container was stopped"
		return result
	}
	_, stopErr := s.runner(ctx, "docker", "stop", "--time", "10", id)
	out, err = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
	after, confirmed, proofErr := s.filesystemRevocationProvenance(ctx, id, []byte(out))
	if err != nil || proofErr != nil || confirmed != expected || after.State.Running || after.State.Paused || after.State.Restarting || (after.State.Status != "exited" && after.State.Status != "created") {
		result.Detail = "Exact filesystem stop outcome is unavailable; revocation remains pending without deletion or restart"
		return result
	}
	// Docker can lose a stop response after it stopped the container. Independent
	// immutable readback, rather than that response, determines confirmation.
	_ = stopErr
	result.Status, result.Detail = "stopped", "Withdrawn, changed or expired filesystem capability was stopped by its original immutable ID; business data and credentials are preserved"
	return result
}
