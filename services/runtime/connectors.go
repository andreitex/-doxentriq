package main

// Company-maintained connector provisioning. Generated sources never choose a
// Docker image, host path, network, share, credential or relay destination.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type connectorTemplate struct {
	Image         string `json:"image"`
	Qualification struct {
		Status     string `json:"status"`
		ReportHash string `json:"reportSha256"`
		CheckedAt  string `json:"checkedAt"`
		Scope      string `json:"scope"`
	} `json:"protocolQualification"`
}

type connectorProvision struct {
	Version      int    `json:"schemaVersion"`
	Action       string `json:"action"`
	ApprovalID   string `json:"approvalId"`
	AppID        string `json:"appId"`
	ConnectionID string `json:"connectionId"`
	Type         string `json:"type"`
	ServerIP     string `json:"serverIp"`
	Share        string `json:"share"`
	Root         string `json:"root"`
	ACLHash      string `json:"readonlyAclEvidenceSha256"`
	ApprovedAt   string `json:"approvedAt"`
	ExpiresAt    string `json:"expiresAt"`
	Principal    struct {
		ID         string `json:"id"`
		MFA        bool   `json:"mfa"`
		LocalOwner bool   `json:"localOwner"`
	} `json:"principal"`
	Credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"credentials"`
}

type connectorState struct {
	Input      connectorProvision `json:"input"`
	ScopeHash  string             `json:"scopeHash"`
	Template   connectorTemplate  `json:"template"`
	PreparedAt string             `json:"preparedAt"`
}

type connectorLiveReceipt struct {
	AppID         string `json:"appId"`
	ResourceID    string `json:"resourceId"`
	ConnectionID  string `json:"connectionId"`
	ScopeHash     string `json:"scopeHash"`
	Image         string `json:"image"`
	Adapter       string `json:"adapter"`
	Relay         string `json:"relay"`
	CheckedAt     string `json:"checkedAt"`
	FeedUpdatedAt string `json:"feedUpdatedAt"`
	ExpiresAt     string `json:"expiresAt"`
	Status        string `json:"status"`
}

var connectorName = regexp.MustCompile(`^[^\\/:%<>|?*"\x00-\x1f\x7f]{1,240}$`)
var connectorTokenPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{43}$`)

func validConnectorName(value string) bool {
	return len(value) <= 240 && connectorName.MatchString(value) && value != "." && value != ".." && !strings.HasSuffix(value, ".") && !strings.HasSuffix(value, " ") && !strings.HasPrefix(value, " ")
}

func validateConnectorProvision(in connectorProvision, now time.Time, owner string) error {
	if in.Version != 1 || in.Action != "approve_readonly_samba" || in.Type != "samba" || !identity.MatchString(in.AppID) || !identity.MatchString(in.ConnectionID) || !identity.MatchString(in.ApprovalID) {
		return errors.New("An exact readonly Samba app, connection and approval identity are required")
	}
	if owner == "" || in.Principal.ID != owner || !in.Principal.MFA || !in.Principal.LocalOwner {
		return errors.New("Connector credential/scope review requires the permanent owner's exact signed identity and MFA")
	}
	address := net.ParseIP(in.ServerIP)
	if address == nil || address.To4() == nil || address.String() != in.ServerIP || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() || in.ServerIP == "255.255.255.255" || address.To4()[0] >= 240 {
		return errors.New("One approved unicast literal IPv4 server on port 445 is required")
	}
	if !validConnectorName(in.Share) || strings.HasSuffix(in.Share, "$") || !validConnectorName(in.Root) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.ACLHash) {
		return errors.New("One ordinary share, logical root and reviewed remote readonly-account ACL evidence are required")
	}
	approved, e := time.Parse(time.RFC3339, in.ApprovedAt)
	if e != nil || approved.After(now.Add(time.Minute)) || now.Sub(approved) > 5*time.Minute {
		return errors.New("Connector approval is stale or invalid")
	}
	expires, e := time.Parse(time.RFC3339, in.ExpiresAt)
	if e != nil || !expires.After(now) || expires.After(now.Add(90*24*time.Hour)) {
		return errors.New("Connector access must expire within 90 days")
	}
	for _, value := range []string{in.Credentials.Username, in.Credentials.Password} {
		if len(value) < 1 || len(value) > 1024 || strings.ContainsRune(value, 0) {
			return errors.New("Dedicated remote readonly account credentials are required through protected setup")
		}
	}
	return nil
}

func readConnectorTemplate() (connectorTemplate, error) {
	var result connectorTemplate
	b, e := os.ReadFile(os.Getenv("RUNTIME_MANIFEST_PATH"))
	if e != nil {
		return result, errors.New("Signed company connector manifest is unavailable")
	}
	var manifest struct {
		Connectors map[string]connectorTemplate `json:"connectors"`
	}
	if json.Unmarshal(b, &manifest) != nil {
		return result, errors.New("Invalid company connector manifest")
	}
	result, ok := manifest.Connectors["samba"]
	if !ok || !digestImage.MatchString(result.Image) || !strings.HasPrefix(result.Image, "registry:5000/connectors/samba@") || result.Qualification.Status != "passed" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(result.Qualification.ReportHash) || result.Qualification.Scope != "synthetic-samba-server" {
		return connectorTemplate{}, errors.New("A pinned signed company connector with actual SMB3.1.1 protocol qualification is required")
	}
	checked, e := time.Parse(time.RFC3339, result.Qualification.CheckedAt)
	if e != nil || checked.After(time.Now().Add(time.Minute)) {
		return connectorTemplate{}, errors.New("Company connector qualification timestamp is invalid")
	}
	return result, nil
}

func connectorScopeHash(in connectorProvision) string {
	// The public scope hash never becomes an offline password-checking oracle.
	// Credential identity is checked against the separately encrypted whole record.
	in.Credentials.Username, in.Credentials.Password = "", ""
	b, _ := json.Marshal(in)
	return hashBytes(b)
}

func (s *server) connectorStatePath(appID, connectionID string) string {
	return filepath.Join(s.data, "connectors", "approved", appID, connectionID+".enc")
}

func (s *server) provisionConnector(w http.ResponseWriter, r *http.Request) {
	s.provisionConnectorWithClock(w, r, time.Now)
}

func (s *server) provisionConnectorWithClock(w http.ResponseWriter, r *http.Request, now func() time.Time) {
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
	if e != nil || !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		rejectDeployment(w, 403, errors.New("An exact protected connector approval proof is required"))
		return
	}
	var in connectorProvision
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		rejectDeployment(w, 400, errors.New("Invalid bounded connector approval"))
		return
	}
	if e = validateConnectorProvision(in, now(), os.Getenv("OWNER_SUBJECT")); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	template, e := readConnectorTemplate()
	if e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	if e = s.connectionWithdrawalBlocked(in.AppID, in.ConnectionID); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	if e = validateConnectorProvision(in, now(), os.Getenv("OWNER_SUBJECT")); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	scopeHash := connectorScopeHash(in)
	file := s.connectorStatePath(in.AppID, in.ConnectionID)
	var existing connectorState
	if e = readEncrypted(file, &existing); e == nil {
		if existing.ScopeHash != scopeHash || !reflect.DeepEqual(existing.Input, in) || !reflect.DeepEqual(existing.Template, template) {
			rejectDeployment(w, 409, errors.New("Connection scope or credentials changed; create a new reviewed connection identity"))
			return
		}
		respond(w, map[string]any{"status": "configured", "appId": in.AppID, "connectionId": in.ConnectionID, "approvalId": in.ApprovalID, "scopeHash": scopeHash, "liveShareVerified": false})
		return
	} else if !os.IsNotExist(e) {
		rejectDeployment(w, 409, errors.New("Protected connector state could not be verified"))
		return
	}
	if _, e = cachedFeed(); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	findings, e := s.scanImage(r.Context(), template.Image)
	if e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	for _, finding := range findings {
		if blockedSeverity(finding.Severity) {
			rejectDeployment(w, 409, errors.New("Connector image has a MEDIUM or higher or unclassified security finding"))
			return
		}
	}
	if e = validateConnectorProvision(in, now(), os.Getenv("OWNER_SUBJECT")); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	state := connectorState{in, scopeHash, template, now().UTC().Format(time.RFC3339)}
	if e = writeEncrypted(file, state); e != nil {
		fail(w, 500, errors.New("Connector approval could not be stored"))
		return
	}
	// No password, bearer token, server/share name or credential hash in the API/audit.
	respond(w, map[string]any{"status": "configured", "appId": in.AppID, "connectionId": in.ConnectionID, "approvalId": in.ApprovalID, "scopeHash": scopeHash, "liveShareVerified": false})
}

// Reconcile an ambiguous protected dispatch without resending credentials or
// replaying an expired approval. Missing state is unknown, never a safe-to-retry
// assertion; app verification still requires independent qualified state.
func (s *server) connectorStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AppID        string `json:"appId"`
		ConnectionID string `json:"connectionId"`
		ApprovalID   string `json:"approvalId"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !identity.MatchString(in.AppID) || !identity.MatchString(in.ConnectionID) || !identity.MatchString(in.ApprovalID) {
		fail(w, 400, errors.New("Exact app, connection and approval identities are required"))
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	var state connectorState
	if e := readEncrypted(s.connectorStatePath(in.AppID, in.ConnectionID), &state); e != nil {
		if os.IsNotExist(e) {
			respond(w, map[string]any{"status": "unknown", "appId": in.AppID, "connectionId": in.ConnectionID, "approvalId": in.ApprovalID, "liveShareVerified": false})
			return
		}
		fail(w, 409, errors.New("Protected connector reconciliation is unavailable; retain the pending operation"))
		return
	}
	if state.Input.AppID != in.AppID || state.Input.ConnectionID != in.ConnectionID || state.Input.ApprovalID != in.ApprovalID || state.ScopeHash != connectorScopeHash(state.Input) {
		fail(w, 409, errors.New("Connector reconciliation does not match the exact immutable approval"))
		return
	}
	template, e := readConnectorTemplate()
	expires, expiryError := time.Parse(time.RFC3339, state.Input.ExpiresAt)
	if e != nil || expiryError != nil || !expires.After(time.Now()) || !reflect.DeepEqual(template, state.Template) {
		fail(w, 409, errors.New("Connector company qualification or access expiry is unavailable; retain the pending operation"))
		return
	}
	respond(w, map[string]any{"status": "configured", "appId": in.AppID, "connectionId": in.ConnectionID, "approvalId": in.ApprovalID, "scopeHash": state.ScopeHash, "liveShareVerified": false})
}

func (s *server) validateConnectorRefs(m AppManifest) error {
	if len(m.Connections) > 8 {
		return errors.New("At most eight reviewed read-only connections per app are supported")
	}
	seen := map[string]bool{}
	for _, id := range m.Connections {
		if !identity.MatchString(id) || seen[id] {
			return errors.New("Connection identities must be exact and unique")
		}
		seen[id] = true
		filesystem, e := s.filesystemConnection(m.ID, id)
		if e != nil {
			return e
		}
		if filesystem {
			if _, e = s.loadApprovedFilesystem(m.ID, id); e != nil {
				return e
			}
			continue
		}
		state, e := s.loadApprovedConnector(m.ID, id)
		if e != nil {
			return e
		}
		if state.Input.AppID != m.ID {
			return errors.New("Connector app scope mismatch")
		}
	}
	return nil
}

func (s *server) loadApprovedConnector(appID, id string) (connectorState, error) {
	var state connectorState
	if e := s.connectionWithdrawalBlocked(appID, id); e != nil {
		return state, e
	}
	if !identity.MatchString(appID) || !identity.MatchString(id) {
		return state, errors.New("Invalid connector scope")
	}
	if e := readEncrypted(s.connectorStatePath(appID, id), &state); e != nil {
		return state, errors.New("Requested connection lacks a reviewed encrypted broker approval")
	}
	template, e := readConnectorTemplate()
	if e != nil {
		return state, e
	}
	expires, e := time.Parse(time.RFC3339, state.Input.ExpiresAt)
	if e != nil || !expires.After(time.Now()) || state.Input.AppID != appID || state.Input.ConnectionID != id || state.ScopeHash != connectorScopeHash(state.Input) || !reflect.DeepEqual(template, state.Template) {
		return state, errors.New("Connector approval expired, changed or belongs to another company image")
	}
	return state, nil
}

func newConnectorToken() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *server) connectorAppToken(resourceID string) (string, error) {
	file := filepath.Join(s.data, "connectors", "app-tokens", resourceID+".enc")
	var state struct {
		Token string `json:"token"`
	}
	if e := readEncrypted(file, &state); e == nil {
		if !connectorTokenPattern.MatchString(state.Token) {
			return "", errors.New("Invalid encrypted app connector token")
		}
		return state.Token, nil
	} else if !os.IsNotExist(e) {
		return "", e
	}
	token, e := newConnectorToken()
	if e != nil {
		return "", e
	}
	state.Token = token
	if e = writeEncrypted(file, state); e != nil {
		return "", e
	}
	return token, nil
}

func (s *server) ensureConnectorNetwork(ctx context.Context, name, scope string, internal bool) error {
	out, e := s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", name)
	if e != nil {
		args := []string{"network", "create", "--driver", "bridge", "--label", "io.autosoft.connector=" + scope}
		if internal {
			args = append(args, "--internal")
		} else {
			args = append(args, "--opt", "com.docker.network.bridge.enable_icc=false")
		}
		args = append(args, name)
		if _, e = s.runner(ctx, "docker", args...); e != nil {
			return errors.New("Scoped connector network could not be created")
		}
		out, e = s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", name)
	}
	var actual struct {
		Name     string
		Internal bool
		Driver   string
		Labels   map[string]string
	}
	if e != nil || json.Unmarshal([]byte(out), &actual) != nil || actual.Name != name || actual.Internal != internal || actual.Driver != "bridge" || actual.Labels["io.autosoft.connector"] != scope {
		return errors.New("Scoped connector network identity or isolation is invalid")
	}
	return nil
}

type connectorContainerExpected struct {
	Name, Mode, Image, ScopeHash, HostSecret, HostCA, Primary, Secondary, Alias string
	Hosts                                                                       []string
}

type connectorAddressProof struct {
	ResourceID   string `json:"resourceId"`
	ConnectionID string `json:"connectionId"`
	ScopeHash    string `json:"scopeHash"`
	IPAddress    string `json:"ipAddress"`
}

func (s *server) connectorRelayHosts(resourceID, id, scope string) ([]string, error) {
	var proof connectorAddressProof
	if e := readEncrypted(filepath.Join(s.data, "connectors", "addresses", resourceID, id+".enc"), &proof); e != nil || proof.ResourceID != resourceID || proof.ConnectionID != id || proof.ScopeHash != scope {
		return nil, errors.New("Connector relay mapping lacks encrypted scope evidence")
	}
	ip := net.ParseIP(proof.IPAddress)
	if ip == nil || ip.To4() == nil || ip.String() != proof.IPAddress || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("Connector relay mapping is invalid")
	}
	return []string{appTLSHost("connector-relay-"+resourceID+"-"+id) + ":" + proof.IPAddress}, nil
}

func validateConnectorContainer(b []byte, expected connectorContainerExpected) error {
	var c struct {
		ID     string `json:"Id"`
		Name   string
		Config struct {
			Image, User     string
			Cmd, Entrypoint []string
			Env             []string
			Labels          map[string]string
		}
		HostConfig struct {
			Runtime                      string
			ReadonlyRootfs, Privileged   bool
			CapDrop, CapAdd, SecurityOpt []string
			PidsLimit                    int
			Memory, NanoCpus             int64
			Tmpfs                        map[string]string
			Binds                        []string
			ExtraHosts                   []string
			LogConfig                    struct{ Type string }
			PortBindings                 map[string]any
		}
		Mounts []struct {
			Source, Destination string
			RW                  bool
		}
		NetworkSettings struct{ Networks map[string]any }
	}
	if json.Unmarshal(b, &c) != nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(c.ID) || c.Name != "/"+expected.Name || c.Config.Labels["io.autosoft.managed"] != "true" || c.Config.Image != expected.Image || c.Config.User != "10001:10001" || len(c.Config.Entrypoint) != 0 || !reflect.DeepEqual(c.Config.Cmd, []string{"python", "-I", "/opt/connector/samba.py"}) || c.Config.Labels["io.autosoft.connector.scope"] != expected.ScopeHash || c.Config.Labels["io.autosoft.connector.mode"] != expected.Mode || c.HostConfig.Runtime != env("RUNSC_RUNTIME", "runsc") || !c.HostConfig.ReadonlyRootfs || c.HostConfig.Privileged || len(c.HostConfig.CapAdd) != 0 || !reflect.DeepEqual(c.HostConfig.CapDrop, []string{"ALL"}) || c.HostConfig.PidsLimit != 64 || c.HostConfig.Memory != 256<<20 || c.HostConfig.NanoCpus != 500000000 || len(c.HostConfig.Tmpfs) != 1 || c.HostConfig.Tmpfs["/tmp"] != "rw,nosuid,nodev,size=16m,mode=1777" || len(c.HostConfig.PortBindings) != 0 || c.HostConfig.LogConfig.Type != "journald" {
		return errors.New("Connector container immutable identity/resource isolation does not match")
	}
	if !containsConnector(c.HostConfig.SecurityOpt, "no-new-privileges") && !containsConnector(c.HostConfig.SecurityOpt, "no-new-privileges:true") {
		return errors.New("Connector container privilege policy is invalid")
	}
	if len(c.NetworkSettings.Networks) != 2 || c.NetworkSettings.Networks[expected.Primary] == nil || c.NetworkSettings.Networks[expected.Secondary] == nil {
		return errors.New("Connector network membership escaped its approved scope")
	}
	if !reflect.DeepEqual(append([]string{}, c.HostConfig.ExtraHosts...), append([]string{}, expected.Hosts...)) {
		return errors.New("Connector trusted host mapping changed")
	}

	mounts := map[string]string{"/run/connector": expected.HostSecret, "/run/ca.crt": expected.HostCA}
	if len(c.Mounts) != len(mounts) {
		return errors.New("Connector mount inventory changed")
	}
	for _, mount := range c.Mounts {
		if mount.RW || mounts[mount.Destination] != mount.Source {
			return errors.New("Connector credentials or host mounts escaped scope")
		}
	}
	for _, value := range []string{"CONNECTOR_MODE=" + expected.Mode, "CONNECTOR_CONFIG_FILE=/run/connector/config.json", "CONNECTOR_TOKEN_FILE=/run/connector/token", "CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt", "CONNECTOR_TLS_KEY_FILE=/run/connector/app.key"} {
		if !containsConnector(c.Config.Env, value) {
			return errors.New("Connector sealed environment changed")
		}
	}
	return nil
}

func containsConnector(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (s *server) startConnectorContainer(ctx context.Context, expected connectorContainerExpected) error {
	out, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", expected.Name)
	if e == nil {
		if e = validateConnectorContainer([]byte(out), expected); e != nil {
			return e
		}
		if _, e = s.runner(ctx, "docker", "start", expected.Name); e != nil {
			return errors.New("Reviewed connector could not be resumed")
		}
		return nil
	}
	args := []string{"run", "-d", "--name", expected.Name, "--label", "io.autosoft.managed=true", "--label", "io.autosoft.connector.scope=" + expected.ScopeHash, "--label", "io.autosoft.connector.mode=" + expected.Mode, "--restart", "unless-stopped", "--runtime", env("RUNSC_RUNTIME", "runsc"), "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "256m", "--cpus", "0.5", "--log-driver", "journald", "--network", "name=" + expected.Primary + ",alias=" + expected.Alias, "--network", "name=" + expected.Secondary, "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m,mode=1777", "--mount", "type=bind,src=" + expected.HostSecret + ",dst=/run/connector,readonly", "--mount", "type=bind,src=" + expected.HostCA + ",dst=/run/ca.crt,readonly"}
	for _, host := range expected.Hosts {
		args = append(args, "--add-host", host)
	}
	for _, value := range []string{"CONNECTOR_MODE=" + expected.Mode, "CONNECTOR_CONFIG_FILE=/run/connector/config.json", "CONNECTOR_TOKEN_FILE=/run/connector/token", "CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt", "CONNECTOR_TLS_KEY_FILE=/run/connector/app.key", "CONNECTOR_CA_FILE=/run/ca.crt"} {
		args = append(args, "--env", value)
	}
	if expected.Mode == "adapter" {
		args = append(args, "--env", "CONNECTOR_CREDENTIALS_FILE=/run/connector/credentials.json", "--env", "CONNECTOR_RELAY_TOKEN_FILE=/run/connector/relay-token")
	}
	args = append(args, expected.Image)
	if _, e = s.runner(ctx, "docker", args...); e != nil {
		return errors.New("Scoped company connector could not be started")
	}
	out, e = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", expected.Name)
	if e != nil {
		return errors.New("New connector isolation could not be verified")
	}
	return validateConnectorContainer([]byte(out), expected)
}

func (s *server) connectorPrivateAddress(ctx context.Context, container, network string) (string, error) {
	out, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container)
	var networks map[string]struct{ IPAddress string }
	if e != nil || json.Unmarshal([]byte(out), &networks) != nil {
		return "", errors.New("Connector private network address is unavailable")
	}
	ip := net.ParseIP(networks[network].IPAddress)
	if ip == nil || ip.To4() == nil || ip.String() != networks[network].IPAddress || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return "", errors.New("Connector private network address is invalid")
	}
	return ip.String(), nil
}

// Reconcile only broker-owned connector sidecars. Grant records and business
// files are retained; removing a manifest reference revokes its running route.
func (s *server) reconcileConnectorSidecars(ctx context.Context, m AppManifest, v resources) error {
	return s.reconcileConnectorSidecarsMode(ctx, m, v, false)
}

func (s *server) reconcileConnectorSidecarsMode(ctx context.Context, m AppManifest, v resources, inspectOnly bool) error {
	desired := map[string]bool{}
	for _, id := range m.Connections {
		desired[id] = true
	}
	base := filepath.Join(s.data, "connector-secrets", v.AppID)
	entries, e := os.ReadDir(base)
	if os.IsNotExist(e) {
		entries = nil
	} else if e != nil {
		return errors.New("Connector sidecar inventory is unavailable")
	}
	if len(entries) != 0 {
		out, e := s.runner(ctx, "docker", "ps", "--all", "--format", "{{json .Names}}")
		if e != nil {
			return errors.New("Connector runtime inventory is unavailable; activation is blocked")
		}
		present := map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line == "" {
				continue
			}
			var name string
			if json.Unmarshal([]byte(line), &name) != nil || name == "" {
				return errors.New("Connector runtime inventory is invalid")
			}
			present[name] = true
		}
		for _, entry := range entries {
			id := entry.Name()
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !identity.MatchString(id) {
				return errors.New("Connector secret inventory escaped its broker-owned scope")
			}
			if desired[id] {
				continue
			}
			filesystem, err := s.filesystemConnection(m.ID, id)
			if err != nil {
				return err
			}
			if filesystem {
				key := hashBytes([]byte(v.AppID + ":" + id))[:24]
				if present["as-filesystem-"+key] {
					if err = s.retireFilesystemConnector(ctx, m, v, id, inspectOnly); err != nil {
						return err
					}
				}
				continue
			}
			var state connectorState
			if e = readEncrypted(s.connectorStatePath(m.ID, id), &state); e != nil || state.Input.AppID != m.ID || state.Input.ConnectionID != id || state.ScopeHash != connectorScopeHash(state.Input) || !digestImage.MatchString(state.Template.Image) {
				return errors.New("Removed connector lacks independent encrypted ownership evidence")
			}
			key := hashBytes([]byte(v.AppID + ":" + id))[:24]
			private, outbound := "as-connector-"+key, "as-connector-egress-"+key
			for _, mode := range []string{"adapter", "relay"} {
				name := "as-connector-" + key + "-" + mode
				if !present[name] {
					continue
				}
				primary, secondary := v.Network, private
				if mode == "relay" {
					primary, secondary = private, outbound
				}
				expected := connectorContainerExpected{Name: name, Mode: mode, Image: state.Template.Image, ScopeHash: state.ScopeHash, HostSecret: filepath.Join(s.hostRuntime, "connector-secrets", v.AppID, id, mode), HostCA: filepath.Join(env("HOST_DATA_DIR", ""), "tls", "ca.crt"), Primary: primary, Secondary: secondary}
				if mode == "adapter" {
					expected.Hosts, e = s.connectorRelayHosts(v.AppID, id, state.ScopeHash)
					if e != nil {
						return e
					}
				}
				out, e = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", name)
				if e != nil || validateConnectorContainer([]byte(out), expected) != nil {
					return errors.New("Removed connector container provenance changed; activation is blocked without deleting it")
				}
				var immutable struct {
					ID string `json:"Id"`
				}
				if json.Unmarshal([]byte(out), &immutable) != nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(immutable.ID) {
					return errors.New("Removed connector immutable container identity is unavailable")
				}
				if inspectOnly {
					continue
				}
				if _, e = s.runner(ctx, "docker", "rm", "--force", immutable.ID); e != nil {
					return errors.New("Removed connector access could not be revoked; activation is blocked")
				}
			}
		}
	}
	if len(m.Connections) == 0 {
		for _, name := range []string{"connector-token", "connector-registry.json"} {
			file := filepath.Join(v.Secrets, name)
			info, e := os.Lstat(file)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil || !info.Mode().IsRegular() {
				return errors.New("Stale app connector file is unsafe; activation is blocked")
			}
			if inspectOnly {
				continue
			}
			if e = os.Remove(file); e != nil {
				return errors.New("Stale app connector capability could not be removed")
			}
		}
	}
	return nil
}

func (s *server) ensureAppConnectors(ctx context.Context, m AppManifest, v resources, preview bool) error {
	if e := s.validateConnectorRefs(m); e != nil {
		return e
	}
	if e := s.reconcileConnectorSidecars(ctx, m, v); e != nil {
		return e
	}
	if len(m.Connections) == 0 {
		return nil
	}
	token, e := s.connectorAppToken(v.AppID)
	if e != nil {
		return e
	}
	feed, e := cachedFeed()
	if e != nil {
		return e
	}
	registry := map[string]any{"schemaVersion": 1, "connections": []map[string]any{}}
	connections := registry["connections"].([]map[string]any)
	for _, id := range m.Connections {
		filesystem, err := s.filesystemConnection(m.ID, id)
		if err != nil {
			return err
		}
		if filesystem {
			entry, err := s.ensureFilesystemConnector(ctx, m, v, id, preview)
			if err != nil {
				return err
			}
			connections = append(connections, entry)
			continue
		}
		state, e := s.loadApprovedConnector(m.ID, id)
		if e != nil {
			return e
		}
		findings, e := s.scanImage(ctx, state.Template.Image)
		if e != nil {
			return e
		}
		for _, f := range findings {
			if blockedSeverity(f.Severity) {
				return errors.New("Company connector security scan is blocked")
			}
		}
		key := hashBytes([]byte(v.AppID + ":" + id))[:24]
		private, outbound := "as-connector-"+key, "as-connector-egress-"+key
		for _, network := range []struct {
			name     string
			internal bool
		}{{private, true}, {outbound, false}} {
			if e = s.ensureConnectorNetwork(ctx, network.name, state.ScopeHash, network.internal); e != nil {
				return e
			}
		}
		base := filepath.Join(s.data, "connector-secrets", v.AppID, id)
		relayTokenFile := filepath.Join(s.data, "connectors", "relay-tokens", v.AppID, id+".enc")
		var relayToken struct {
			Token string `json:"token"`
		}
		if e = readEncrypted(relayTokenFile, &relayToken); e != nil {
			if !os.IsNotExist(e) {
				return errors.New("Protected relay token is unavailable")
			}
			relayToken.Token, e = newConnectorToken()
			if e != nil {
				return e
			}
			if e = writeEncrypted(relayTokenFile, relayToken); e != nil {
				return e
			}
		}
		if !connectorTokenPattern.MatchString(relayToken.Token) {
			return errors.New("Invalid protected relay token")
		}
		relayIdentity := "connector-relay-" + v.AppID + "-" + id
		adapterIdentity := "connector-adapter-" + v.AppID + "-" + id
		relayAlias, adapterAlias := appTLSHost(relayIdentity), appTLSHost(adapterIdentity)
		relayIP := ""
		for _, mode := range []string{"relay", "adapter"} {
			directory := filepath.Join(base, mode)
			if e = os.MkdirAll(directory, 0700); e != nil {
				return e
			}
			config := map[string]any{"schemaVersion": 1, "appId": m.ID, "connectionId": id, "serverIp": state.Input.ServerIP, "expiresAt": state.Input.ExpiresAt}
			files := map[string][]byte{}
			ownToken := relayToken.Token
			leafIdentity := relayIdentity
			if mode == "adapter" {
				config["root"], config["share"] = state.Input.Root, state.Input.Share
				config["relayHost"], config["relayServerName"], config["relayPort"] = relayAlias, relayAlias, 8444
				config["readonlyAclEvidenceSha256"] = state.Input.ACLHash
				credentialBytes, _ := json.Marshal(state.Input.Credentials)
				files["credentials.json"] = credentialBytes
				files["relay-token"] = []byte(relayToken.Token)
				ownToken = token
				leafIdentity = adapterIdentity
			}
			configBytes, _ := json.Marshal(config)
			files["config.json"], files["token"] = configBytes, []byte(ownToken)
			for name, value := range files {
				if e = atomicTLSFile(filepath.Join(directory, name), value); e != nil {
					return e
				}
			}
			if e = issueAppTLS(directory, leafIdentity); e != nil {
				return e
			}
			primary, secondary, alias := private, outbound, relayAlias
			if mode == "adapter" {
				primary, secondary, alias = v.Network, private, adapterAlias
			}
			expected := connectorContainerExpected{Name: "as-connector-" + key + "-" + mode, Mode: mode, Image: state.Template.Image, ScopeHash: state.ScopeHash, HostSecret: filepath.Join(s.hostRuntime, "connector-secrets", v.AppID, id, mode), HostCA: filepath.Join(env("HOST_DATA_DIR", ""), "tls", "ca.crt"), Primary: primary, Secondary: secondary, Alias: alias}
			if mode == "adapter" {
				expected.Hosts = []string{relayAlias + ":" + relayIP}
			}
			if e = s.startConnectorContainer(ctx, expected); e != nil {
				return e
			}
			if mode == "relay" {
				relayIP, e = s.connectorPrivateAddress(ctx, expected.Name, private)
				if e != nil {
					return e
				}
				proof := connectorAddressProof{v.AppID, id, state.ScopeHash, relayIP}
				if e = writeEncrypted(filepath.Join(s.data, "connectors", "addresses", v.AppID, id+".enc"), proof); e != nil {
					return e
				}
			}
		}
		// Actual share listing, with scoped token read only inside the adapter and TLS
		// checked against the installation CA. Process-running is never share proof.
		body, _ := json.Marshal(map[string]string{"appId": m.ID, "root": state.Input.Root, "path": ""})
		probe := "import http.client,json,ssl,socket;ctx=ssl.create_default_context(cafile='/run/ca.crt');c=http.client.HTTPSConnection('127.0.0.1',8443,context=ctx,timeout=10);c.connect=lambda:setattr(c,'sock',ctx.wrap_socket(socket.create_connection(('127.0.0.1',8443),timeout=10),server_hostname=" + strconv.Quote(adapterAlias) + "));token=open('/run/connector/token').read().strip();c.request('POST'," + strconv.Quote("/v1/connections/"+id+"/list") + "," + strconv.Quote(string(body)) + ",{'content-type':'application/json','authorization':'Bearer '+token});r=c.getresponse();b=r.read(2097152);assert r.status==200;value=json.loads(b);assert isinstance(value.get('entries'),list) and len(value['entries'])<=1000;print('share-verified')"
		adapterName := "as-connector-" + key + "-adapter"
		out, e := s.runner(ctx, "docker", "exec", "--user=10001:10001", adapterName, "python", "-I", "-c", probe)
		if e != nil || strings.TrimSpace(out) != "share-verified" {
			return errors.New("Approved share connectivity/permissions were not independently verified; app deployment remains blocked")
		}
		receipt := connectorLiveReceipt{m.ID, v.AppID, id, state.ScopeHash, state.Template.Image, adapterName, "as-connector-" + key + "-relay", time.Now().UTC().Format(time.RFC3339), feed, state.Input.ExpiresAt, "passed"}
		if e = atomicJSON(filepath.Join(s.data, "connectors", "live", v.AppID, id+".json"), receipt); e != nil {
			return e
		}
		connections = append(connections, map[string]any{"id": id, "type": "samba", "reviewStatus": "approved", "appIds": []string{m.ID}, "roots": []string{state.Input.Root}, "capabilities": []string{"files.list", "files.read"}, "adapterUrl": "https://" + adapterAlias + ":8443"})
	}
	registry["connections"] = connections
	data, _ := json.Marshal(registry)
	if e = atomicTLSFile(filepath.Join(v.Secrets, "connector-registry.json"), data); e != nil {
		return e
	}
	return atomicTLSFile(filepath.Join(v.Secrets, "connector-token"), []byte(token))
}

type connectorCandidate struct {
	AppID           string   `json:"appId"`
	ResourceID      string   `json:"resourceId"`
	OwnerResourceID string   `json:"ownerResourceId"`
	Network         string   `json:"network"`
	Connections     []string `json:"connections"`
}

func (s *server) validateAppConnectorMount(appID, resourceID, containerName, source string) error {
	if !identity.MatchString(appID) || !identity.MatchString(containerName) || (resourceID != appID && resourceID != appID+"_preview") {
		return errors.New("Connector capability mount app/resource identity is invalid")
	}
	candidate := filepath.Base(source)
	preview := containerName == "as-preview-"+appID
	if (preview && resourceID != appID+"_preview") || (!preview && resourceID != appID) {
		return errors.New("Connector mount resource does not match candidate role")
	}
	if (!preview && (!strings.HasPrefix(containerName, "as-app-"+appID+"-") || candidate != containerName)) || (preview && (!strings.HasPrefix(candidate, containerName+"-") || !regexp.MustCompile(`^[a-f0-9]{8}$`).MatchString(strings.TrimPrefix(candidate, containerName+"-")))) {
		return errors.New("Connector capability mount belongs to a different immutable candidate")
	}
	if source != filepath.Join(s.hostRuntime, "connectors", "capabilities", candidate) {
		return errors.New("Connector capability host mount escaped its bounded source")
	}
	var index connectorCandidate
	if e := readEncrypted(filepath.Join(s.data, "connectors", "candidates", candidate+".enc"), &index); e != nil || index.AppID != appID || index.ResourceID != candidate || index.OwnerResourceID != resourceID || index.Network == "" || len(index.Connections) == 0 {
		return errors.New("Connector capability mount lacks independent encrypted candidate ownership")
	}
	return nil
}

// Stage capabilities for this immutable candidate only. A failed candidate must
// never alter credentials or sidecars used by the routed release.
func (s *server) stageAppConnectors(ctx context.Context, m AppManifest, v resources, preview bool, candidate string) (resources, error) {
	if !identity.MatchString(candidate) || !identity.MatchString(m.ID) {
		return v, errors.New("Exact candidate connector identity is required")
	}
	if e := s.validateConnectorRefs(m); e != nil {
		return v, e
	}
	connections := append([]string(nil), m.Connections...)
	sort.Strings(connections)
	index := connectorCandidate{AppID: m.ID, ResourceID: candidate, OwnerResourceID: v.AppID, Network: v.Network, Connections: connections}
	path := filepath.Join(s.data, "connectors", "candidates", candidate+".enc")
	var existing connectorCandidate
	if e := readEncrypted(path, &existing); e == nil {
		if !reflect.DeepEqual(existing, index) {
			return v, errors.New("Candidate connector scope changed; use a new immutable candidate")
		}
	} else if !os.IsNotExist(e) {
		return v, errors.New("Candidate connector ownership is unavailable")
	} else if e := writeEncrypted(path, index); e != nil {
		return v, e
	}
	staged := v
	staged.AppID = candidate
	staged.Secrets = filepath.Join(s.data, "connectors", "capabilities", candidate)
	if e := os.MkdirAll(staged.Secrets, 0700); e != nil {
		return v, e
	}
	if e := s.ensureAppConnectors(ctx, m, staged, preview); e != nil {
		return v, e
	}
	v.ConnectorResourceID = candidate
	if len(m.Connections) != 0 {
		v.ConnectorSecrets = staged.Secrets
		v.ConnectorHostSecrets = filepath.Join(s.hostRuntime, "connectors", "capabilities", candidate)
	}
	return v, nil
}

// Called only after the new route and durable publication evidence are confirmed.
// Expired grants may be stopped using encrypted provenance, never activated.
func (s *server) retireAppConnectors(ctx context.Context, appID, resourceID, currentCandidate string) error {
	return s.reconcilePriorAppConnectors(ctx, appID, resourceID, currentCandidate, false)
}

func (s *server) checkRetirableAppConnectors(ctx context.Context, appID, resourceID, currentCandidate string) error {
	return s.reconcilePriorAppConnectors(ctx, appID, resourceID, currentCandidate, true)
}

func (s *server) reconcilePriorAppConnectors(ctx context.Context, appID, resourceID, currentCandidate string, inspectOnly bool) error {
	if !identity.MatchString(appID) || (resourceID != appID && resourceID != appID+"_preview") || !identity.MatchString(currentCandidate) {
		return errors.New("Connector retirement cannot target the active candidate")
	}
	directory := filepath.Join(s.data, "connectors", "candidates")
	entries, e := os.ReadDir(directory)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || len(entries) > 10000 {
		return errors.New("Connector candidate inventory is unavailable or exceeds its reviewed bound")
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".enc") {
			return errors.New("Connector candidate inventory has unsafe entries")
		}
		var index connectorCandidate
		if e = readEncrypted(filepath.Join(directory, entry.Name()), &index); e != nil || entry.Name() != index.ResourceID+".enc" || !identity.MatchString(index.ResourceID) || !identity.MatchString(index.AppID) || index.Network == "" {
			return errors.New("Previous connector candidate ownership is unavailable; operator attention is required")
		}
		if index.AppID != appID || index.OwnerResourceID != resourceID || index.ResourceID == currentCandidate {
			continue
		}
		v := resources{AppID: index.ResourceID, Network: index.Network, Secrets: filepath.Join(s.data, "connectors", "capabilities", index.ResourceID)}
		if e = s.reconcileConnectorSidecarsMode(ctx, AppManifest{ID: appID}, v, inspectOnly); e != nil {
			return e
		}
	}
	return nil
}

func connectorEnvironment(m AppManifest) map[string]string {
	if len(m.Connections) == 0 {
		return map[string]string{}
	}
	return map[string]string{"CONNECTOR_REGISTRY_FILE": "/run/app-connectors/connector-registry.json", "CONNECTOR_TOKEN_FILE": "/run/app-connectors/connector-token"}
}

// gVisor's isolated loopback cannot use Docker's embedded DNS. Map only exact
// independently inspected scoped adapters into a candidate's /etc/hosts.
func (s *server) appConnectorHosts(ctx context.Context, m AppManifest, v resources) (map[string]string, error) {
	result := map[string]string{}
	if len(m.Connections) == 0 {
		return result, nil
	}
	if !identity.MatchString(v.ConnectorResourceID) {
		return nil, errors.New("Candidate connector identity is unavailable")
	}
	for _, id := range m.Connections {
		filesystem, err := s.filesystemConnection(m.ID, id)
		if err != nil {
			return nil, err
		}
		if filesystem {
			alias, address, err := s.filesystemConnectorHost(ctx, m, v, id)
			if err != nil || result[alias] != "" {
				return nil, errors.New("Exact filesystem adapter host mapping is unavailable or duplicated")
			}
			result[alias] = address
			continue
		}
		state, e := s.loadApprovedConnector(m.ID, id)
		if e != nil {
			return nil, e
		}
		key := hashBytes([]byte(v.ConnectorResourceID + ":" + id))[:24]
		name := "as-connector-" + key + "-adapter"
		hosts, e := s.connectorRelayHosts(v.ConnectorResourceID, id, state.ScopeHash)
		if e != nil {
			return nil, e
		}
		expected := connectorContainerExpected{Name: name, Mode: "adapter", Image: state.Template.Image, ScopeHash: state.ScopeHash, HostSecret: filepath.Join(s.hostRuntime, "connector-secrets", v.ConnectorResourceID, id, "adapter"), HostCA: filepath.Join(env("HOST_DATA_DIR", ""), "tls/ca.crt"), Primary: v.Network, Secondary: "as-connector-" + key, Hosts: hosts}
		out, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", name)
		if e != nil || validateConnectorContainer([]byte(out), expected) != nil {
			return nil, errors.New("Scoped adapter host mapping failed immutable ownership validation")
		}
		ip, e := s.connectorPrivateAddress(ctx, name, v.Network)
		if e != nil {
			return nil, e
		}
		result[appTLSHost("connector-adapter-"+v.ConnectorResourceID+"-"+id)] = ip
	}
	return result, nil
}

// Security reports must scan these separate company containers too. The caller
// can merge findings/coverage into the existing app report, without accepting a
// generated manifest's claims about sidecar images or passing feed coverage.
func (s *server) scanAppConnectors(ctx context.Context, m AppManifest) ([]Finding, error) {
	if e := s.validateConnectorRefs(m); e != nil {
		return nil, e
	}
	images := map[string]bool{}
	for _, id := range m.Connections {
		filesystem, err := s.filesystemConnection(m.ID, id)
		if err != nil {
			return nil, err
		}
		if filesystem {
			state, err := s.loadApprovedFilesystem(m.ID, id)
			if err != nil {
				return nil, err
			}
			images[state.Template.Image] = true
			continue
		}
		state, e := s.loadApprovedConnector(m.ID, id)
		if e != nil {
			return nil, e
		}
		images[state.Template.Image] = true
	}
	ordered := []string{}
	for image := range images {
		ordered = append(ordered, image)
	}
	sort.Strings(ordered)
	findings := []Finding{}
	for _, image := range ordered {
		value, e := s.scanImage(ctx, image)
		if e != nil {
			return nil, fmt.Errorf("Connector image security coverage unavailable: %w", e)
		}
		findings = append(findings, value...)
	}
	return findings, nil
}
