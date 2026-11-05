package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func connectorApprovalFixture(now time.Time) connectorProvision {
	in := connectorProvision{Version: 1, Action: "approve_readonly_samba", ApprovalID: "approval-fixture", AppID: "app-fixture", ConnectionID: "connection-fixture", Type: "samba", ServerIP: "10.23.23.99", Share: "documents", Root: "documents", ACLHash: strings.Repeat("b", 64), ApprovedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339)}
	in.Principal.ID = "permanent-owner"
	in.Principal.MFA = true
	in.Principal.LocalOwner = true
	in.Credentials.Username = "readonly-user"
	in.Credentials.Password = "fixture-only-secret"
	return in
}

func connectorManifestFixture(t *testing.T) connectorTemplate {
	t.Helper()
	value := connectorTemplate{Image: "registry:5000/connectors/samba@sha256:" + strings.Repeat("a", 64)}
	value.Qualification.Status = "passed"
	value.Qualification.Scope = "synthetic-samba-server"
	value.Qualification.ReportHash = strings.Repeat("c", 64)
	value.Qualification.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	path := filepath.Join(t.TempDir(), "runtime-manifest.json")
	b, _ := json.Marshal(map[string]any{"connectors": map[string]connectorTemplate{"samba": value}})
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("RUNTIME_MANIFEST_PATH", path)
	return value
}

func TestConnectorScopeNeedsExactOwnerMFAReadonlyReviewAndExpiry(t *testing.T) {
	if validConnectorName(strings.Repeat("ă", 121)) || !validConnectorName(strings.Repeat("ă", 120)) {
		t.Fatal("UTF8 byte limit differs from the sealed adapter scope")
	}
	now := time.Now()
	valid := connectorApprovalFixture(now)
	if e := validateConnectorProvision(valid, now, "permanent-owner"); e != nil {
		t.Fatal(e)
	}
	changes := []func(*connectorProvision){
		func(in *connectorProvision) { in.Principal.ID = "sso-admin" }, func(in *connectorProvision) { in.Principal.MFA = false }, func(in *connectorProvision) { in.Principal.LocalOwner = false },
		func(in *connectorProvision) { in.Action = "write_samba" }, func(in *connectorProvision) { in.AppID = "../host" }, func(in *connectorProvision) { in.Root = "../documents" }, func(in *connectorProvision) { in.Share = "IPC$" }, func(in *connectorProvision) { in.ACLHash = "" },
		func(in *connectorProvision) { in.ApprovedAt = now.Add(-6 * time.Minute).Format(time.RFC3339) }, func(in *connectorProvision) { in.ApprovedAt = now.Add(2 * time.Minute).Format(time.RFC3339) }, func(in *connectorProvision) { in.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339) }, func(in *connectorProvision) { in.ExpiresAt = now.Add(91 * 24 * time.Hour).Format(time.RFC3339) }, func(in *connectorProvision) { in.Credentials.Password = "" },
	}
	for i, change := range changes {
		in := valid
		change(&in)
		if validateConnectorProvision(in, now, "permanent-owner") == nil {
			t.Fatalf("Invalid scope %d accepted", i)
		}
	}
}

func TestConnectorDestinationCannotUseDNSPortsOrSpecialAddresses(t *testing.T) {
	now := time.Now()
	for _, target := range []string{"localhost", "share.example", "127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "10.23.23.99:445", "010.23.23.99", "240.0.0.1"} {
		in := connectorApprovalFixture(now)
		in.ServerIP = target
		if validateConnectorProvision(in, now, "permanent-owner") == nil {
			t.Fatalf("Invalid SMB target accepted: %s", target)
		}
	}
}

func TestConnectorPublicScopeHashExcludesCredentialOracle(t *testing.T) {
	in := connectorApprovalFixture(time.Now())
	hash := connectorScopeHash(in)
	in.Credentials.Password = "different-password"
	in.Credentials.Username = "different-account"
	if connectorScopeHash(in) != hash {
		t.Fatal("Public scope digest exposes a password verification oracle")
	}
	in.Root = "other"
	if connectorScopeHash(in) == hash {
		t.Fatal("Approved share scope is not bound")
	}
}

func TestConnectorManifestRequiresActualProtocolQualificationAndPrivateImage(t *testing.T) {
	approved := connectorManifestFixture(t)
	if _, e := readConnectorTemplate(); e != nil {
		t.Fatal(e)
	}
	path := os.Getenv("RUNTIME_MANIFEST_PATH")
	variants := []connectorTemplate{approved, approved, approved, approved}
	variants[0].Image = "company.example/samba:latest"
	variants[1].Qualification.Status = "unavailable"
	variants[2].Qualification.ReportHash = ""
	variants[3].Qualification.Scope = "unit-tests-only"
	for i, value := range variants {
		b, _ := json.Marshal(map[string]any{"connectors": map[string]connectorTemplate{"samba": value}})
		_ = os.WriteFile(path, b, 0600)
		if _, e := readConnectorTemplate(); e == nil {
			t.Fatalf("Unqualified connector image %d accepted", i)
		}
	}
	_ = os.WriteFile(path, []byte(`{"templates":{}}`), 0600)
	if _, e := readConnectorTemplate(); e == nil {
		t.Fatal("Missing connector silently accepted")
	}
}

func TestConnectorReferencesRequireIndependentEncryptedAppScope(t *testing.T) {
	template := connectorManifestFixture(t)
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	s := server{data: t.TempDir()}
	in := connectorApprovalFixture(time.Now())
	state := connectorState{Input: in, ScopeHash: connectorScopeHash(in), Template: template, PreparedAt: time.Now().UTC().Format(time.RFC3339)}
	if e := writeEncrypted(s.connectorStatePath(in.AppID, in.ConnectionID), state); e != nil {
		t.Fatal(e)
	}
	m := AppManifest{ID: in.AppID, Connections: []string{in.ConnectionID}}
	if e := s.validateConnectorRefs(m); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []AppManifest{{ID: "other-app", Connections: m.Connections}, {ID: in.AppID, Connections: []string{"missing-connection"}}, {ID: in.AppID, Connections: []string{in.ConnectionID, in.ConnectionID}}, {ID: in.AppID, Connections: []string{"../host"}}} {
		if s.validateConnectorRefs(bad) == nil {
			t.Fatal("Unreviewed, duplicate or cross-app connection accepted")
		}
	}
	state.Input.ExpiresAt = time.Now().Add(-time.Hour).Format(time.RFC3339)
	state.ScopeHash = connectorScopeHash(state.Input)
	_ = writeEncrypted(s.connectorStatePath(in.AppID, in.ConnectionID), state)
	if s.validateConnectorRefs(m) == nil {
		t.Fatal("Expired connector accepted")
	}
}

func connectorInspectFixture(expected connectorContainerExpected) map[string]any {
	return map[string]any{
		"Id": hashBytes([]byte(expected.Name)), "Name": "/" + expected.Name,
		"Config":          map[string]any{"Image": expected.Image, "User": "10001:10001", "Cmd": []string{"python", "-I", "/opt/connector/samba.py"}, "Labels": map[string]string{"io.autosoft.managed": "true", "io.autosoft.connector.scope": expected.ScopeHash, "io.autosoft.connector.mode": expected.Mode}, "Env": []string{"CONNECTOR_MODE=" + expected.Mode, "CONNECTOR_CONFIG_FILE=/run/connector/config.json", "CONNECTOR_TOKEN_FILE=/run/connector/token", "CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt", "CONNECTOR_TLS_KEY_FILE=/run/connector/app.key"}},
		"HostConfig":      map[string]any{"ExtraHosts": expected.Hosts, "Runtime": "runsc", "ReadonlyRootfs": true, "Privileged": false, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "PidsLimit": 64, "Memory": 256 << 20, "NanoCpus": 500000000, "Tmpfs": map[string]string{"/tmp": "rw,nosuid,nodev,size=16m,mode=1777"}, "LogConfig": map[string]string{"Type": "journald"}},
		"Mounts":          []map[string]any{{"Source": expected.HostSecret, "Destination": "/run/connector", "RW": false}, {"Source": expected.HostCA, "Destination": "/run/ca.crt", "RW": false}},
		"NetworkSettings": map[string]any{"Networks": map[string]any{expected.Primary: map[string]any{}, expected.Secondary: map[string]any{}}},
	}
}

func TestConnectorContainerRejectsImageNetworkMountAndPrivilegeDrift(t *testing.T) {
	expected := connectorContainerExpected{Name: "as-connector-fixture", Mode: "adapter", Image: "registry:5000/connectors/samba@sha256:" + strings.Repeat("a", 64), ScopeHash: strings.Repeat("b", 64), HostSecret: "/encrypted/runtime/connector-secrets/app/connection/adapter", HostCA: "/encrypted/tls/ca.crt", Primary: "app-network", Secondary: "private-connector", Alias: "private.internal"}
	value := connectorInspectFixture(expected)
	b, _ := json.Marshal(value)
	if e := validateConnectorContainer(b, expected); e != nil {
		t.Fatal(e)
	}
	changes := []func(map[string]any){
		func(v map[string]any) { v["Config"].(map[string]any)["Image"] = "untrusted:latest" }, func(v map[string]any) { v["Config"].(map[string]any)["Entrypoint"] = []string{"sh", "-c"} }, func(v map[string]any) { v["Config"].(map[string]any)["User"] = "0:0" },
		func(v map[string]any) { v["HostConfig"].(map[string]any)["Privileged"] = true }, func(v map[string]any) { v["HostConfig"].(map[string]any)["Runtime"] = "runc" }, func(v map[string]any) { v["HostConfig"].(map[string]any)["ReadonlyRootfs"] = false }, func(v map[string]any) {
			v["HostConfig"].(map[string]any)["Tmpfs"] = map[string]string{"/tmp": "size=8g"}
		},
		func(v map[string]any) {
			v["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{"8443/tcp": []any{map[string]string{"HostPort": "8443"}}}
		},
		func(v map[string]any) {
			v["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)["outbound"] = map[string]any{}
		},
		func(v map[string]any) { v["Mounts"].([]map[string]any)[0]["Source"] = "/var/run/docker.sock" }, func(v map[string]any) { v["Mounts"].([]map[string]any)[0]["RW"] = true },
	}
	for i, change := range changes {
		value := connectorInspectFixture(expected)
		change(value)
		b, _ := json.Marshal(value)
		if validateConnectorContainer(b, expected) == nil {
			t.Fatalf("Connector isolation drift %d accepted", i)
		}
	}
}

func TestConnectorProvisionRejectsUnsignedRequestBeforeHostCalls(t *testing.T) {
	s := server{data: t.TempDir(), approvalKey: bytes.Repeat([]byte{4}, 32), runner: func(context.Context, string, ...string) (string, error) {
		t.Fatal("Unapproved connector reached the host runtime")
		return "", nil
	}}
	body, _ := json.Marshal(connectorApprovalFixture(time.Now()))
	request := httptest.NewRequest("POST", "/v1/connectors/provision", bytes.NewReader(body))
	response := httptest.NewRecorder()
	s.provisionConnector(response, request)
	if response.Code != 403 {
		t.Fatalf("Unsigned connector approval accepted: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "fixture-only-secret") {
		t.Fatal("Credential leaked in an error")
	}
}

func TestConnectorEnvironmentExposesOnlyAppScopedBearerAndRegistry(t *testing.T) {
	if len(connectorEnvironment(AppManifest{})) != 0 {
		t.Fatal("Unrequested connector configured")
	}
	environment := connectorEnvironment(AppManifest{Connections: []string{"connection-fixture"}})
	if len(environment) != 2 || environment["CONNECTOR_REGISTRY_FILE"] != "/run/app-connectors/connector-registry.json" || environment["CONNECTOR_TOKEN_FILE"] != "/run/app-connectors/connector-token" {
		t.Fatal("Connector environment escaped app scope")
	}
	for key, value := range environment {
		if strings.Contains(key+value, "credentials") || strings.Contains(key+value, "relay") {
			t.Fatal("SMB/relay credential exposed to application")
		}
	}
}

func TestConnectorApprovalCannotExpireWhileQueuedOrScanning(t *testing.T) {
	for _, expireAt := range []int{2, 3} {
		t.Run(map[int]string{2: "after-lock", 3: "after-scan"}[expireAt], func(t *testing.T) {
			if expireAt == 3 && runtime.GOOS != "linux" {
				t.Skip("post-scan approval expiry requires actual Linux encrypted retention/cache/active-marker lifecycle")
			}
			connectorManifestFixture(t)
			now := time.Now().UTC()
			in := connectorApprovalFixture(now)
			t.Setenv("OWNER_SUBJECT", in.Principal.ID)
			base := t.TempDir()
			data := filepath.Join(base, "runtime")
			if os.Mkdir(data, 0700) != nil {
				t.Fatal("fixture runtime unavailable")
			}
			t.Setenv("HOST_DATA_DIR", base)
			t.Setenv("SECURITY_CACHE_DIR", filepath.Join(base, "security-cache"))
			t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
			if e := atomicJSON(filepath.Join(base, "security-cache", "trivy/db/metadata.json"), map[string]any{"Version": 2, "UpdatedAt": now, "NextUpdate": now.Add(24 * time.Hour)}); e != nil {
				t.Fatal(e)
			}
			if os.WriteFile(filepath.Join(base, "security-cache", "trivy/db/trivy.db"), []byte("synthetic-db"), 0644) != nil {
				t.Fatal("fixture feed unavailable")
			}
			credentials := filepath.Join(data, "registry.json")
			_ = os.WriteFile(credentials, []byte(`{"username":"fixture","password":"fixture"}`), 0600)
			t.Setenv("REGISTRY_CREDENTIALS_FILE", credentials)
			calls := 0
			key := bytes.Repeat([]byte{3}, 32)
			s := server{data: data, approvalKey: key, manifest: RuntimeManifest{ScannerImage: "registry:5000/scanner@sha256:" + strings.Repeat("d", 64)}, runner: func(context.Context, string, ...string) (string, error) {
				calls++
				return `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"debian"}},"Results":[{"Vulnerabilities":[]}]}`, nil
			}}
			installTrustedServiceTestFixture(t, &s, "autosoft_artifact", "registry")
			scanner := installImageScannerServerFixture(t, &s, base, "")
			clockCalls := 0
			clock := func() time.Time {
				clockCalls++
				if clockCalls >= expireAt {
					return now.Add(6 * time.Minute)
				}
				return now
			}
			body, _ := json.Marshal(in)
			request := httptest.NewRequest("POST", "/v1/connectors/provision", bytes.NewReader(body))
			request.Header.Set("X-Autosoft-Proof", proofFor(key, body))
			response := httptest.NewRecorder()
			s.provisionConnectorWithClock(response, request, clock)
			if response.Code != 409 || !strings.Contains(response.Body.String(), `"rejectedBeforeExecution":true`) {
				t.Fatalf("Expired approval did not fail before mutation: %s", response.Body.String())
			}
			if _, e := os.Stat(s.connectorStatePath(in.AppID, in.ConnectionID)); !os.IsNotExist(e) {
				t.Fatal("Expired approval wrote encrypted grant state")
			}
			if calls != 0 || expireAt == 2 && scanner.count("create") != 0 || expireAt == 3 && (scanner.count("start") != 1 || !scanner.removed || imageScannerPriorClear(data) != nil) {
				t.Fatalf("Unexpected scanner lifecycle: global calls%d; starts%d", calls, scanner.count("start"))
			}
		})
	}
}

func TestConnectorRemovalRevokesExactSidecarsAndKeepsGrantAndBusinessData(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed-last", true: "reference-switch"}[retained], func(t *testing.T) {
			template := connectorManifestFixture(t)
			t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
			data := t.TempDir()
			t.Setenv("HOST_DATA_DIR", data)
			in := connectorApprovalFixture(time.Now())
			in.ExpiresAt = time.Now().Add(-time.Hour).Format(time.RFC3339)
			state := connectorState{Input: in, ScopeHash: connectorScopeHash(in), Template: template}
			s := server{data: data, hostRuntime: data}
			if e := writeEncrypted(s.connectorStatePath(in.AppID, in.ConnectionID), state); e != nil {
				t.Fatal(e)
			}
			v := resources{AppID: "candidate-old", Network: "app-private", Secrets: filepath.Join(data, "capability")}
			_ = os.MkdirAll(filepath.Join(data, "connector-secrets", v.AppID, in.ConnectionID), 0700)
			_ = os.MkdirAll(v.Secrets, 0700)
			for _, name := range []string{"connector-token", "connector-registry.json", "business-document"} {
				_ = os.WriteFile(filepath.Join(v.Secrets, name), []byte("fixture"), 0600)
			}
			key := hashBytes([]byte(v.AppID + ":" + in.ConnectionID))[:24]
			_ = writeEncrypted(filepath.Join(data, "connectors/addresses", v.AppID, in.ConnectionID+".enc"), connectorAddressProof{v.AppID, in.ConnectionID, state.ScopeHash, "172.19.0.2"})
			names := []string{"as-connector-" + key + "-adapter", "as-connector-" + key + "-relay"}
			removed := []string{}
			s.runner = func(_ context.Context, _ string, args ...string) (string, error) {
				switch args[0] {
				case "ps":
					return `"` + names[0] + `"` + "\n" + `"` + names[1] + `"`, nil
				case "inspect":
					mode := "adapter"
					primary, secondary := v.Network, "as-connector-"+key
					if args[len(args)-1] == names[1] {
						mode = "relay"
						primary, secondary = "as-connector-"+key, "as-connector-egress-"+key
					}
					expected := connectorContainerExpected{Name: args[len(args)-1], Mode: mode, Image: template.Image, ScopeHash: state.ScopeHash, HostSecret: filepath.Join(data, "connector-secrets", v.AppID, in.ConnectionID, mode), HostCA: filepath.Join(data, "tls/ca.crt"), Primary: primary, Secondary: secondary}
					if mode == "adapter" {
						expected.Hosts, _ = s.connectorRelayHosts(v.AppID, in.ConnectionID, state.ScopeHash)
					}
					b, _ := json.Marshal(connectorInspectFixture(expected))
					return string(b), nil
				case "rm":
					removed = append(removed, args[len(args)-1])
					return "", nil
				}
				return "", errors.New("Unexpected command")
			}
			m := AppManifest{ID: in.AppID}
			if retained {
				m.Connections = []string{"new-connection"}
			}
			if e := s.reconcileConnectorSidecarsMode(context.Background(), m, v, true); e != nil {
				t.Fatal(e)
			}
			if len(removed) != 0 {
				t.Fatal("Read-only retirement preflight deleted a sidecar")
			}
			if _, e := os.Stat(filepath.Join(v.Secrets, "connector-token")); e != nil {
				t.Fatal("Read-only preflight changed routed credentials")
			}
			if e := s.reconcileConnectorSidecars(context.Background(), m, v); e != nil {
				t.Fatal(e)
			}
			if len(removed) != 2 {
				t.Fatalf("Old capability left running: %v", removed)
			}
			if _, e := os.Stat(s.connectorStatePath(in.AppID, in.ConnectionID)); e != nil {
				t.Fatal("Grant history was deleted")
			}
			if _, e := os.Stat(filepath.Join(v.Secrets, "business-document")); e != nil {
				t.Fatal("Business file was deleted")
			}
			if !retained {
				if _, e := os.Stat(filepath.Join(v.Secrets, "connector-token")); !os.IsNotExist(e) {
					t.Fatal("Old app bearer survived removal")
				}
			}
		})
	}
}

func TestConnectorRemovalRefusesUnprovenContainerWithoutDeletingIt(t *testing.T) {
	template := connectorManifestFixture(t)
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	data := t.TempDir()
	t.Setenv("HOST_DATA_DIR", data)
	in := connectorApprovalFixture(time.Now())
	s := server{data: data, hostRuntime: data}
	state := connectorState{Input: in, ScopeHash: connectorScopeHash(in), Template: template}
	_ = writeEncrypted(s.connectorStatePath(in.AppID, in.ConnectionID), state)
	v := resources{AppID: "candidate-old", Network: "app-private", Secrets: filepath.Join(data, "capability")}
	_ = os.MkdirAll(filepath.Join(data, "connector-secrets", v.AppID, in.ConnectionID), 0700)
	name := "as-connector-" + hashBytes([]byte(v.AppID + ":" + in.ConnectionID))[:24] + "-adapter"
	s.runner = func(_ context.Context, _ string, args ...string) (string, error) {
		if args[0] == "ps" {
			return strconvQuoteForTest(name), nil
		}
		if args[0] == "inspect" {
			return `{"Config":{"Image":"untrusted:latest"}}`, nil
		}
		t.Fatal("Drifted container was deleted")
		return "", nil
	}
	if s.reconcileConnectorSidecars(context.Background(), AppManifest{ID: in.AppID}, v) == nil {
		t.Fatal("Unproven sidecar was accepted")
	}
}

func strconvQuoteForTest(value string) string { b, _ := json.Marshal(value); return string(b) }

func TestConnectorStagingDoesNotMutateRoutedReleaseCapabilities(t *testing.T) {
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	data := t.TempDir()
	current := filepath.Join(data, "secrets/current-app")
	_ = os.MkdirAll(current, 0700)
	for _, name := range []string{"connector-token", "connector-registry.json"} {
		_ = os.WriteFile(filepath.Join(current, name), []byte("current-scope"), 0600)
	}
	s := server{data: data, hostRuntime: data, runner: func(context.Context, string, ...string) (string, error) {
		t.Fatal("Empty candidate touched routed sidecars")
		return "", nil
	}}
	v, e := s.stageAppConnectors(context.Background(), AppManifest{ID: "app-fixture"}, resources{AppID: "app-fixture", Network: "app-private", Secrets: current}, false, "candidate-new")
	if e != nil || v.ConnectorResourceID != "candidate-new" || v.ConnectorSecrets != "" {
		t.Fatalf("Empty staged candidate failed: %v", e)
	}
	for _, name := range []string{"connector-token", "connector-registry.json"} {
		b, e := os.ReadFile(filepath.Join(current, name))
		if e != nil || string(b) != "current-scope" {
			t.Fatal("Staging changed current release capability")
		}
	}
	if s.retireAppConnectors(context.Background(), "app-fixture", "candidate-new", "candidate-new") == nil {
		t.Fatal("Retirement may revoke the active candidate")
	}
}

func TestConnectorStatusReconcilesOnlyExactStoredApprovalWithoutCredentials(t *testing.T) {
	template := connectorManifestFixture(t)
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	s := server{data: t.TempDir()}
	in := connectorApprovalFixture(time.Now())
	state := connectorState{Input: in, ScopeHash: connectorScopeHash(in), Template: template}
	status := func(approval string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"appId": in.AppID, "connectionId": in.ConnectionID, "approvalId": approval})
		response := httptest.NewRecorder()
		s.connectorStatus(response, httptest.NewRequest("POST", "/v1/connectors/status", bytes.NewReader(b)))
		return response
	}
	response := status(in.ApprovalID)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"unknown"`) {
		t.Fatal("Missing dispatch is not unknown")
	}
	if e := writeEncrypted(s.connectorStatePath(in.AppID, in.ConnectionID), state); e != nil {
		t.Fatal(e)
	}
	response = status(in.ApprovalID)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"configured"`) || !strings.Contains(response.Body.String(), `"liveShareVerified":false`) {
		t.Fatal("Prepared approval is not reconcilable")
	}
	if strings.Contains(response.Body.String(), in.Credentials.Password) || strings.Contains(response.Body.String(), in.Credentials.Username) {
		t.Fatal("Reconciliation leaked account credentials")
	}
	if status("other-approval").Code != 409 {
		t.Fatal("Different approval reconciled")
	}
}
