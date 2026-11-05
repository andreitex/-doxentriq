package main

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// This fixture serves the actual broker HTTP client over verified TLS. It
// models only identity administration; it does not claim a live Keycloak run.
type identityAPIFixture struct {
	mu             sync.Mutex
	realms         map[string]map[string]any
	profiles       map[string]map[string]any
	broker         map[string]any
	secret         string
	createdSecrets []string
	requests       int
	writes         int
	failRealmOnce  bool
	denyRealmRead  bool
	hideRealmOnce  bool
	redirectToken  string
}

func TestIdentityRealmUsesSupportedEmailRequirement(t *testing.T) {
	s, fixture, manifest := identityFixture(t)
	if _, _, _, err := s.appIdentity(context.Background(), manifest, true); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.realms) != 1 {
		t.Fatal("Expected one exact preview realm")
	}
	for _, realm := range fixture.realms {
		if realm["verifyEmail"] != false {
			t.Fatal("Private invitations must retain unverified email without requiring an unconfigured mail service")
		}
		if _, present := realm["defaultRequiredActions"]; present {
			t.Fatal("Keycloak rejects defaultRequiredActions on a realm representation")
		}
		clients, ok := realm["clients"].([]any)
		if !ok || len(clients) != 2 {
			t.Fatal("Application and MCP clients are required")
		}
		for _, raw := range clients {
			client := raw.(map[string]any)
			if client["protocol"] != "openid-connect" || client["publicClient"] != true || client["directAccessGrantsEnabled"] != false {
				t.Fatal("Browser/MCP clients require explicit OIDC with PKCE, without password grants")
			}
		}
	}
}

func TestIdentityCreationErrorsKeepStatusWithoutResponseSecrets(t *testing.T) {
	for _, status := range []int{400, 403, 503} {
		fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errorMessage":"fixture-private-client-secret"}`))
		}))
		err := identityCreate(context.Background(), fixture.Client(), fixture.URL, "fixture-token", map[string]any{})
		fixture.Close()
		if err == nil || strings.Contains(err.Error(), "fixture-private") || strings.Contains(err.Error(), "fixture-token") {
			t.Fatal("Failed identity responses must omit protected response/token material")
		}
		expected := map[int]string{400: "configuration", 403: "privileges", 503: "unavailable"}[status]
		if !strings.Contains(err.Error(), expected) || !strings.Contains(err.Error(), "HTTP ") {
			t.Fatal("Configuration refusal, permission refusal and outage must remain distinguishable")
		}
	}
}

func (f *identityAPIFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token") {
		if f.redirectToken != "" {
			w.Header().Set("Location", f.redirectToken)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture-admin-token"})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/certs") {
		curve := elliptic.P256().Params()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "fixture", "kty": "EC", "alg": "ES256", "use": "sig", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(curve.Gx.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(curve.Gy.FillBytes(make([]byte, 32)))}}})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
		realm := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/realms/"), "/.well-known/openid-configuration")
		issuer := "https://auth.example.test/realms/" + realm
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/protocol/openid-connect/certs"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer fixture-admin-token" {
		w.WriteHeader(401)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/realms/") && strings.HasSuffix(r.URL.Path, "/users/profile") {
		realm := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/realms/"), "/users/profile")
		if f.realms[realm] == nil {
			w.WriteHeader(404)
			return
		}
		if f.profiles == nil {
			f.profiles = map[string]map[string]any{}
		}
		if f.profiles[realm] == nil {
			f.profiles[realm] = map[string]any{"unmanagedAttributePolicy": "DISABLED", "attributes": []any{map[string]any{"name": "username"}}}
		}
		if r.Method == "PUT" {
			var proposed map[string]any
			if json.NewDecoder(r.Body).Decode(&proposed) != nil {
				w.WriteHeader(400)
				return
			}
			f.profiles[realm] = proposed
			f.writes++
		}
		_ = json.NewEncoder(w).Encode(f.profiles[realm])
		return
	}
	if r.URL.Path == "/admin/realms/platform/clients" {
		if r.Method == "GET" {
			if f.broker == nil || r.URL.Query().Get("clientId") != f.broker["clientId"] {
				_ = json.NewEncoder(w).Encode([]any{})
				return
			}
			_ = json.NewEncoder(w).Encode([]any{f.broker})
			return
		}
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		f.writes++
		if f.broker != nil {
			w.WriteHeader(409)
			return
		}
		if json.NewDecoder(r.Body).Decode(&f.broker) != nil {
			w.WriteHeader(400)
			return
		}
		f.secret, _ = f.broker["secret"].(string)
		f.createdSecrets = append(f.createdSecrets, f.secret)
		delete(f.broker, "secret")
		f.broker["id"] = "fixture-client"
		w.WriteHeader(201)
		return
	}
	if r.URL.Path == "/admin/realms/platform/clients/fixture-client/client-secret" && r.Method == "GET" {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": f.secret})
		return
	}
	if r.URL.Path == "/admin/realms" && r.Method == "POST" {
		f.writes++
		if f.failRealmOnce {
			f.failRealmOnce = false
			w.WriteHeader(503)
			return
		}
		var value map[string]any
		if json.NewDecoder(r.Body).Decode(&value) != nil {
			w.WriteHeader(400)
			return
		}
		realm, _ := value["realm"].(string)
		if f.realms[realm] != nil {
			w.WriteHeader(409)
			return
		}
		f.realms[realm] = value
		w.WriteHeader(201)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/realms/") && r.Method == "GET" {
		if f.denyRealmRead {
			w.WriteHeader(403)
			return
		}
		if f.hideRealmOnce {
			f.hideRealmOnce = false
			w.WriteHeader(404)
			return
		}
		realm := strings.TrimPrefix(r.URL.Path, "/admin/realms/")
		if f.realms[realm] == nil {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(f.realms[realm])
		return
	}
	w.WriteHeader(404)
}

func identityFixture(t *testing.T) (*server, *identityAPIFixture, AppManifest) {
	t.Helper()
	f := &identityAPIFixture{realms: map[string]map[string]any{}}
	api := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(api.Close)
	root := t.TempDir()
	ca := filepath.Join(root, "identity-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYCLOAK_CA_FILE", ca)
	t.Setenv("KEYCLOAK_INTERNAL_URL", api.URL)
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "synthetic-master-client-secret")
	t.Setenv("KEYCLOAK_PLATFORM_CLIENT_SECRET", "synthetic-platform-client-secret")
	t.Setenv("AUTH_ORIGIN", "https://auth.example.test")
	t.Setenv("APPS_BASE_URL", "https://apps.example.test")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	m := AppManifest{ID: "fixture-app", Slug: "documents", Auth: "sso", Permissions: []string{"dms.read", "dms.search", "dms.write"}}
	return &server{data: filepath.Join(root, "runtime")}, f, m
}

func TestIdentityInterruptedCreationRetainsEncryptedStableBrokerSecret(t *testing.T) {
	s, api, manifest := identityFixture(t)
	api.failRealmOnce = true
	if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err == nil {
		t.Fatal("Interrupted realm creation passed")
	}
	secret := api.secret
	if len(secret) != 64 || len(api.createdSecrets) != 1 {
		t.Fatal("Initial confidential client was not created exactly once")
	}
	entries, err := os.ReadDir(filepath.Join(s.data, "identity-policies"))
	if err != nil || len(entries) != 1 {
		t.Fatal("Identity policy was not persisted before remote creation")
	}
	path := filepath.Join(s.data, "identity-policies", entries[0].Name())
	encrypted, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encrypted, []byte(secret)) {
		t.Fatal("Stable broker secret was exposed in policy storage")
	}
	if os.PathSeparator == '/' {
		info, _ := os.Stat(path)
		if info.Mode().Perm()&0077 != 0 {
			t.Fatal("Identity secret is readable by other accounts")
		}
	}
	// A fresh server instance models process restart; the platform client exists,
	// while the app realm has not yet been created.
	restarted := &server{data: s.data}
	issuer, audience, keys, err := restarted.appIdentity(context.Background(), manifest, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(api.createdSecrets) != 1 || api.secret != secret || !strings.HasPrefix(issuer, "https://auth.example.test/realms/app-") || audience != "app-fixture-app" || len(keys) == 0 {
		t.Fatal("Identity retry changed the confidential client or returned invalid scoped identity")
	}
	for _, realm := range api.realms {
		providers := realm["identityProviders"].([]any)
		config := providers[0].(map[string]any)["config"].(map[string]any)
		if config["clientSecret"] != secret {
			t.Fatal("App broker secret differs from existing platform client secret")
		}
	}
}

func TestIdentityCodeUpdatesPreservePolicyAndRoleGrantsWhileAccessChangesPause(t *testing.T) {
	s, api, manifest := identityFixture(t)
	if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err != nil {
		t.Fatal(err)
	}
	manifest.Name = "Updated document browser"
	manifest.Permissions = []string{"dms.write", "dms.search", "dms.read"}
	if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err != nil {
		t.Fatal("Ordinary code update or role order was rejected:", err)
	}
	if len(api.createdSecrets) != 1 {
		t.Fatal("Idempotent update rotated confidential client")
	}
	for _, change := range []func(*AppManifest){func(m *AppManifest) { m.Auth = "public" }, func(m *AppManifest) { m.Slug = "other-app" }, func(m *AppManifest) { m.Permissions = append(m.Permissions, "dms.admin") }} {
		changed := manifest
		changed.Permissions = append([]string{}, manifest.Permissions...)
		change(&changed)
		before := api.requests
		if _, _, _, err := s.appIdentity(context.Background(), changed, false); err == nil || !strings.Contains(err.Error(), "separate approved") {
			t.Fatal("Changed access policy did not pause")
		}
		if api.requests != before {
			t.Fatal("Policy change contacted or modified identity service before separate approval")
		}
	}
}

func TestIdentityRealmConflictMissingOwnershipOrChangedHashFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing-marker", "changed-hash", "foreign-app", "read-denied", "conflict-race"} {
		t.Run(mode, func(t *testing.T) {
			s, api, manifest := identityFixture(t)
			if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err != nil {
				t.Fatal(err)
			}
			for _, realm := range api.realms {
				attributes := realm["attributes"].(map[string]any)
				switch mode {
				case "missing-marker":
					delete(attributes, "autosoft.policy-hash")
				case "changed-hash", "conflict-race":
					attributes["autosoft.policy-hash"] = strings.Repeat("0", 64)
				case "foreign-app":
					attributes["autosoft.app-id"] = "another-app"
				case "read-denied":
					api.denyRealmRead = true
				}
			}
			if mode == "conflict-race" {
				api.hideRealmOnce = true
			}
			before := api.writes
			if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err == nil {
				t.Fatal("Unverified owned realm was accepted")
			}
			if mode != "conflict-race" && api.writes != before {
				t.Fatal("Unowned or changed realm caused remote writes")
			}
		})
	}
}

func TestIdentityConfidentialClientDriftRejectsInsteadOfRotatingSecret(t *testing.T) {
	s, api, manifest := identityFixture(t)
	api.failRealmOnce = true
	if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err == nil {
		t.Fatal("Fixture interruption did not fail")
	}
	api.secret = strings.Repeat("f", 64)
	if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err == nil {
		t.Fatal("Existing confidential client secret drift passed")
	}
	if len(api.createdSecrets) != 1 || len(api.realms) != 0 {
		t.Fatal("Drifted secret was rotated or a mismatched realm was created")
	}
}

func TestIdentityCredentialRequestsNeverFollowProviderRedirects(t *testing.T) {
	s, api, manifest := identityFixture(t)
	forwarded := 0
	unexpected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.WriteHeader(200)
	}))
	defer unexpected.Close()
	api.redirectToken = unexpected.URL
	if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err == nil {
		t.Fatal("Identity credential redirect was accepted")
	}
	if forwarded != 0 {
		t.Fatal("Identity credentials were forwarded outside the configured verified TLS authority")
	}
}

func TestIdentityImportDefinesReferencedScopesAndOnlyAppClientRoles(t *testing.T) {
	s, api, manifest := identityFixture(t)
	if _, _, _, err := s.appIdentity(context.Background(), manifest, false); err != nil {
		t.Fatal(err)
	}
	for _, realm := range api.realms {
		scopes := map[string]map[string]any{}
		for _, raw := range realm["clientScopes"].([]any) {
			scope := raw.(map[string]any)
			scopes[scope["name"].(string)] = scope
		}
		for _, raw := range realm["clients"].([]any) {
			client := raw.(map[string]any)
			if strings.HasPrefix(client["clientId"].(string), "app-") {
				redirects := client["redirectUris"].([]any)
				if len(redirects) != 2 || redirects[0] != "https://documents.apps.example.test/auth/callback" || redirects[1] != "https://documents.apps.example.test/" {
					t.Fatal("Both supported browser callbacks must be exact paths on the one app origin")
				}
			}
			subject := false
			for _, value := range client["protocolMappers"].([]any) {
				mapper := value.(map[string]any)
				if mapper["protocolMapper"] == "oidc-sub-mapper" {
					subject = mapper["config"].(map[string]any)["access.token.claim"] == "true"
				}
			}
			if !subject {
				t.Fatal("App and MCP access tokens require the real identity provider subject")
			}
			for _, key := range []string{"defaultClientScopes", "optionalClientScopes"} {
				if values, ok := client[key].([]any); ok {
					for _, name := range values {
						if scopes[name.(string)] == nil {
							t.Fatal("Imported client references a missing scope:", name)
						}
					}
				}
			}
		}
		roles := scopes["roles"]["protocolMappers"].([]any)
		if len(roles) != 1 {
			t.Fatal("Role scope must have exactly one app-client role mapper")
		}
		mapper := roles[0].(map[string]any)
		config := mapper["config"].(map[string]any)
		if mapper["protocolMapper"] != "oidc-usermodel-client-role-mapper" || config["usermodel.clientRoleMapping.clientId"] != "app-fixture-app" || config["claim.name"] != "resource_access.app-fixture-app.roles" || config["multivalued"] != "true" || config["access.token.claim"] != "true" {
			t.Fatal("App role mapper cannot satisfy the scoped API/MCP authorization contract")
		}
	}
}

func TestAppUserProfileSetupPreservesFieldsAndRefusesUnexpectedPolicy(t *testing.T) {
	for _, policy := range []string{"DISABLED", "ADMIN_EDIT", "ENABLED"} {
		t.Run(policy, func(t *testing.T) {
			writes := 0
			profile := map[string]any{"unmanagedAttributePolicy": policy, "attributes": []any{map[string]any{"name": "username", "permissions": map[string]any{"edit": []any{"admin", "user"}}}}, "groups": []any{}}
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-profile-token" || r.URL.Path != "/admin/realms/app-fixture/users/profile" {
					w.WriteHeader(403)
					return
				}
				if r.Method == "PUT" {
					var proposed map[string]any
					if json.NewDecoder(r.Body).Decode(&proposed) != nil {
						w.WriteHeader(400)
						return
					}
					if accessHash(proposed["attributes"]) != accessHash(profile["attributes"]) || accessHash(proposed["groups"]) != accessHash(profile["groups"]) {
						t.Error("Existing user profile rules changed")
					}
					profile = proposed
					writes++
				}
				_ = json.NewEncoder(w).Encode(profile)
			}))
			defer api.Close()
			err := ensureAppUserProfile(context.Background(), api.Client(), api.URL, "fixture-profile-token", "app-fixture")
			if policy == "ENABLED" {
				if err == nil || writes != 0 {
					t.Fatal("Unexpected existing profile policy was silently changed")
				}
			} else if err != nil || writes != map[string]int{"DISABLED": 1, "ADMIN_EDIT": 0}[policy] || profile["unmanagedAttributePolicy"] != "ADMIN_EDIT" {
				t.Fatalf("Administrator-only metadata setup failed: %v, writes=%d", err, writes)
			}
		})
	}
}
