package main

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSigningKey(kid string) map[string]string {
	curve := elliptic.P256().Params()
	return map[string]string{"kid": kid, "kty": "EC", "alg": "ES256", "use": "sig", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(curve.Gx.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(curve.Gy.FillBytes(make([]byte, 32)))}
}
func testJWKSBundle(appID, resourceID, issuer, kid string, checked time.Time) appJWKSBundle {
	keys := []map[string]string{testSigningKey(kid)}
	encoded, _ := json.Marshal(keys)
	return appJWKSBundle{Keys: keys, Metadata: appJWKSMetadata{Version: 1, AppID: appID, ResourceID: resourceID, Issuer: issuer, CheckedAt: checked.UTC().Format(time.RFC3339Nano), ValidUntil: checked.Add(appJWKSMaxAge).UTC().Format(time.RFC3339Nano), KeysHash: hashBytes(encoded)}}
}

type jwksFixture struct {
	observation                                                *observationFixture
	realm, issuer, resourceID, directory, policyHash, kid      string
	unavailable, wrongIssuer, unowned, redirect, failNewHealth bool
	stops, restarts, identityWrites                            int
	loadedHash, oldHash                                        string
	onNewHealthFailure                                         func()
}

func newJWKSFixture(t *testing.T, preview bool) *jwksFixture {
	t.Helper()
	f := &jwksFixture{observation: newObservationFixture(t, "local"), kid: "original"}
	o := f.observation
	t.Setenv("AUTH_ORIGIN", "https://auth.example.test")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "synthetic-jwks-provisioner")
	f.realm = "app-" + hashBytes([]byte("app1"))[:24]
	f.resourceID = "app1"
	o.current.Container = "as-app-app1-" + o.request.ReleaseID[:8]
	if preview {
		f.realm += "-preview"
		f.resourceID += "_preview"
		o.current.Container = "as-preview-app1"
	}
	o.inspected.Name = "/" + o.current.Container
	o.inspected.Mounts[0].Source = filepath.Join(o.server.hostRuntime, "secrets", f.resourceID)
	if err := atomicJSON(filepath.Join(o.server.data, "active", "app1.json"), o.current); err != nil {
		t.Fatal(err)
	}
	f.issuer = "https://auth.example.test/realms/" + f.realm
	f.directory = filepath.Join(o.server.data, "secrets", f.resourceID)
	f.policyHash = strings.Repeat("9", 64)
	if err := writeEncrypted(filepath.Join(o.server.data, "identity-policies", f.realm+".enc"), identityPolicyState{AppID: "app1", Realm: f.realm, Hash: f.policyHash}); err != nil {
		t.Fatal(err)
	}
	if err := writeEncrypted(filepath.Join(o.server.data, "resources", f.resourceID+".enc"), resources{AppID: f.resourceID, Issuer: f.issuer, Audience: "app-app1", Secrets: f.directory}); err != nil {
		t.Fatal(err)
	}
	initial := testJWKSBundle("app1", f.resourceID, f.issuer, f.kid, time.Now().Add(-5*time.Minute))
	f.oldHash = initial.Metadata.KeysHash
	f.loadedHash = f.oldHash
	if err := installAppJWKS(f.directory, initial); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token"):
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture-owned-token"})
		case r.URL.Path == "/admin/realms/"+f.realm:
			if r.Header.Get("Authorization") != "Bearer fixture-owned-token" {
				t.Error("Ownership proof missing credential")
				w.WriteHeader(401)
				return
			}
			markers := identityMarkers("app1", f.realm, f.policyHash)
			if f.unowned {
				markers["autosoft.app-id"] = "other-app"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"realm": f.realm, "attributes": markers})
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			issuer := f.issuer
			if f.wrongIssuer {
				issuer = "https://other.example/realms/foreign"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/protocol/openid-connect/certs"})
		case strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/certs"):
			if f.unavailable {
				w.WriteHeader(503)
				return
			}
			if f.redirect {
				w.Header().Set("Location", "/untrusted")
				w.WriteHeader(307)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{testSigningKey(f.kid)}})
		default:
			if r.Method != "GET" {
				f.identityWrites++
			}
			t.Errorf("Unexpected identity request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(api.Close)
	t.Setenv("KEYCLOAK_INTERNAL_URL", api.URL)
	o.server.client = api.Client()
	o.server.routeProbe = func(_ context.Context, app, host, container string) (bool, error) {
		expectedApp, expectedHost := "app1", "documents."+o.server.appsHost()
		if preview {
			expectedApp = "preview-app1"
			expectedHost = "preview-" + expectedHost
		}
		if app != expectedApp || host != expectedHost || container != o.current.Container {
			t.Error("Route proof escaped exact scope")
			return false, nil
		}
		return o.routed, nil
	}
	o.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
		if command != "docker" {
			t.Fatal("Arbitrary host executable")
		}
		switch args[0] {
		case "ps":
			if preview {
				return `{"Names":"as-preview-app1"}`, nil
			}
			return "", nil
		case "inspect":
			if args[len(args)-1] != o.current.Container {
				t.Fatal("Container inspection escaped scope")
			}
			body, _ := json.Marshal(o.inspected)
			return string(body), nil
		case "restart":
			if len(args) != 4 || args[3] != o.inspected.ID {
				t.Fatal("Container reload escaped immutable scope")
			}
			f.restarts++
			o.inspected.State.Running = true
			var bundle appJWKSBundle
			if readBoundedJSON(filepath.Join(f.directory, "jwks.json"), &bundle) != nil {
				t.Fatal("Invalid installed bundle")
			}
			f.loadedHash = bundle.Metadata.KeysHash
			return "", nil
		case "stop":
			if len(args) != 4 || args[3] != o.inspected.ID {
				t.Fatal("Safe stop escaped immutable scope")
			}
			f.stops++
			o.inspected.State.Running = false
			return "", nil
		case "exec":
			if args[1] != o.inspected.ID {
				t.Fatal("Health probe escaped immutable scope")
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if f.failNewHealth && f.loadedHash != f.oldHash {
				if f.onNewHealthFailure != nil {
					f.onNewHealthFailure()
				}
				return "", errors.New("New verifier failed health")
			}
			return "", nil
		}
		t.Fatalf("Unexpected host invocation %v", args)
		return "", nil
	}
	return f
}

func TestAppJWKSRejectsPrivateWeakDuplicateAndMalformedSigningKeys(t *testing.T) {
	valid := testSigningKey("key-one")
	body, _ := json.Marshal(map[string]any{"keys": []any{valid}})
	keys, err := validatedAppJWKS(body)
	if err != nil || len(keys) != 1 {
		t.Fatal("Valid public EC key rejected", err)
	}
	for _, mutate := range []func(map[string]string){func(k map[string]string) { k["d"] = "private" }, func(k map[string]string) { k["x"] = "invalid" }, func(k map[string]string) { k["alg"] = "HS256" }, func(k map[string]string) { k["kid"] = "../../foreign" }, func(k map[string]string) { k["kty"] = "oct" }, func(k map[string]string) { k["kty"] = "RSA"; k["alg"] = "RS256"; k["n"] = "AQ"; k["e"] = "AQAB" }} {
		key := testSigningKey("key-one")
		mutate(key)
		b, _ := json.Marshal(map[string]any{"keys": []any{key}})
		if _, err = validatedAppJWKS(b); err == nil {
			t.Fatal("Unsafe public key accepted")
		}
	}
	for _, bad := range [][]byte{[]byte(`{"keys":[]}`), []byte(`{"keys":[]} {}`), bytes.Repeat([]byte("x"), appJWKSMaxBytes+1)} {
		if _, err = validatedAppJWKS(bad); err == nil {
			t.Fatal("Invalid bounded key representation accepted")
		}
	}
	body, _ = json.Marshal(map[string]any{"keys": []any{valid, valid}})
	if _, err = validatedAppJWKS(body); err == nil {
		t.Fatal("Duplicate key identities accepted")
	}
}

func TestAppJWKSRefreshRenewsFreshnessWithoutRestartAndReloadsChangedKeys(t *testing.T) {
	for _, preview := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "preview"}[preview], func(t *testing.T) {
			f := newJWKSFixture(t, preview)
			result := f.observation.server.reconcileAppJWKS(context.Background(), "app1", preview)
			if result.Status != "current" || f.restarts != 0 || f.stops != 0 {
				t.Fatalf("Unchanged keys restarted app: %+v", result)
			}
			f.kid = "rotated"
			result = f.observation.server.reconcileAppJWKS(context.Background(), "app1", preview)
			if result.Status != "refreshed" || f.restarts != 1 || f.stops != 0 || f.loadedHash == f.oldHash || f.identityWrites != 0 {
				t.Fatalf("Rotation failed or changed IAM: %+v", result)
			}
			var bundle appJWKSBundle
			if readBoundedJSON(filepath.Join(f.directory, "jwks.json"), &bundle) != nil || !validAppJWKSBundle(bundle, "app1", f.resourceID, f.issuer, true) {
				t.Fatal("Installed keys lost issuer/resource/freshness scope")
			}
		})
	}
}

func TestAppJWKSUnavailableRetainsFreshKeysThenStopsStaleAndResumesOnlyOwnedStop(t *testing.T) {
	f := newJWKSFixture(t, false)
	f.unavailable = true
	result := f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
	if result.Status != "degraded" || f.stops != 0 || f.restarts != 0 {
		t.Fatal("Transient outage stopped fresh app")
	}
	old := testJWKSBundle("app1", f.resourceID, f.issuer, "original", time.Now().Add(-2*time.Hour))
	if installAppJWKS(f.directory, old) != nil {
		t.Fatal("Expired fixture could not be installed")
	}
	result = f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
	if result.Status != "stopped_stale" || f.stops != 1 || f.observation.inspected.State.Running {
		t.Fatalf("Stale verifier kept serving: %+v", result)
	}
	f.unavailable = false
	f.kid = "fresh"
	result = f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
	if result.Status != "refreshed" || f.restarts != 1 || !f.observation.inspected.State.Running {
		t.Fatalf("Owned safe stop did not resume: %+v", result)
	}
	f.observation.inspected.State.Running = false
	f.kid = "another"
	result = f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
	if result.Status != "not_running" || f.restarts != 1 {
		t.Fatal("A manually stopped app was restarted")
	}
}

func TestAppJWKSRefreshRejectsForeignIssuerRedirectRealmAndContainer(t *testing.T) {
	for _, mutate := range []struct {
		name  string
		apply func(*jwksFixture)
	}{{"issuer", func(f *jwksFixture) { f.wrongIssuer = true }}, {"redirect", func(f *jwksFixture) { f.redirect = true }}, {"realm", func(f *jwksFixture) { f.unowned = true }}, {"container", func(f *jwksFixture) { f.observation.inspected.Config.Labels["io.autosoft.app"] = "other" }}, {"route", func(f *jwksFixture) { f.observation.routed = false }}} {
		t.Run(mutate.name, func(t *testing.T) {
			f := newJWKSFixture(t, false)
			mutate.apply(f)
			result := f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
			if result.Status == "current" || result.Status == "refreshed" || f.restarts != 0 {
				t.Fatal("Untrusted issuer/scope accepted")
			}
			if mutate.name == "realm" && f.stops != 1 {
				t.Fatal("Known changed realm ownership did not fail closed")
			}
			if (mutate.name == "container" || mutate.name == "route") && f.stops != 0 {
				t.Fatal("Unproven container/route was stopped")
			}
		})
	}
}

func TestAppJWKSFailedReloadRestoresStillFreshKeysAndInterruptedJournalReloads(t *testing.T) {
	f := newJWKSFixture(t, false)
	f.kid = "rotated"
	f.failNewHealth = true
	// Prerequisite HTTPS and filesystem verification have a bounded deadline,
	// but cancellation belongs to the new verifier's actual failed health probe.
	// A short wall-clock deadline could expire before reload and never exercise
	// restoration of the original still-fresh keys.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	newHealthReached := false
	f.onNewHealthFailure = func() { newHealthReached = true; cancel() }
	result := f.observation.server.reconcileAppJWKS(ctx, "app1", false)
	if !newHealthReached || ctx.Err() != context.Canceled || result.Status != "degraded" || f.restarts != 2 || f.loadedHash != f.oldHash || f.stops != 0 {
		t.Fatalf("Failed reload did not restore fresh prior verifier: %+v", result)
	}
	f.onNewHealthFailure = nil
	f.failNewHealth = false
	var old appJWKSBundle
	_ = readBoundedJSON(filepath.Join(f.directory, "jwks.json"), &old)
	candidate := testJWKSBundle("app1", f.resourceID, f.issuer, "rotated", time.Now())
	journal := appJWKSJournal{Version: 1, AppID: "app1", ResourceID: f.resourceID, ContainerID: f.observation.inspected.ID, Image: f.observation.current.Image, Issuer: f.issuer, Phase: "installed", UpdatedAt: time.Now().Format(time.RFC3339Nano), Old: old, Candidate: candidate}
	if atomicJSON(filepath.Join(f.observation.server.data, "jwks-rotations", f.resourceID+".json"), journal) != nil || installAppJWKS(f.directory, candidate) != nil {
		t.Fatal("Cannot create interrupted fixture")
	}
	result = f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
	if result.Status != "refreshed" || f.restarts != 3 || f.loadedHash == f.oldHash {
		t.Fatalf("Interrupted refresh was not reconciled: %+v", result)
	}
}

func TestAppJWKSReplacedContainerCannotResumeBrokerStoppedIdentity(t *testing.T) {
	f := newJWKSFixture(t, false)
	f.unavailable = true
	old := testJWKSBundle("app1", f.resourceID, f.issuer, "original", time.Now().Add(-2*time.Hour))
	_ = installAppJWKS(f.directory, old)
	_ = f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
	f.observation.inspected.ID = strings.Repeat("f", 64)
	f.unavailable = false
	result := f.observation.server.reconcileAppJWKS(context.Background(), "app1", false)
	if result.Status != "unavailable" || f.restarts != 0 {
		t.Fatal("Replaced container inherited automatic resume permission")
	}
}

func TestAppJWKSBundleRejectsChangedIssuerHashAndExtendedFreshness(t *testing.T) {
	bundle := testJWKSBundle("app1", "app1", "https://auth.test/realms/app1", "key", time.Now())
	if !validAppJWKSBundle(bundle, "app1", "app1", bundle.Metadata.Issuer, true) {
		t.Fatal("Valid issuer-bound bundle rejected")
	}
	for _, mutate := range []func(*appJWKSBundle){func(v *appJWKSBundle) { v.Metadata.AppID = "other" }, func(v *appJWKSBundle) { v.Metadata.ResourceID = "app1_preview" }, func(v *appJWKSBundle) { v.Metadata.Issuer = "https://foreign.test" }, func(v *appJWKSBundle) { v.Metadata.KeysHash = strings.Repeat("a", 64) }, func(v *appJWKSBundle) { v.Metadata.ValidUntil = time.Now().Add(2 * time.Hour).Format(time.RFC3339Nano) }} {
		copy := bundle
		mutate(&copy)
		if validAppJWKSBundle(copy, "app1", "app1", bundle.Metadata.Issuer, true) {
			t.Fatal("Changed scope or excessive freshness accepted")
		}
	}
}

func TestAppJWKSPeriodicReportDoesNotInventAppEvidence(t *testing.T) {
	s := &server{data: t.TempDir(), runner: func(context.Context, string, ...string) (string, error) { return "", nil }}
	results := s.reconcileApplicationJWKS(context.Background())
	if len(results) != 0 {
		t.Fatal("No apps should yield no app measurements")
	}
	body, err := os.ReadFile(filepath.Join(s.data, "reports", "jwks-refresh-report.json"))
	if err != nil || !bytes.Contains(body, []byte(`"maxAgeSeconds": 3600`)) {
		t.Fatal("Freshness maintenance report missing")
	}
}

func TestAppJWKSPreviewRouteRequiresExactGatewayCookieIsolationAndScopedTLS(t *testing.T) {
	const host = "preview-documents.apps.test.internal"
	const container = "as-preview-app1"
	encoded, _ := json.Marshal(expectedPreviewJWKSRoute("app1", host, container))
	var route map[string]any
	_ = json.Unmarshal(encoded, &route)
	if !exactPreviewJWKSRoute(route, "app1", host, container) {
		t.Fatal("Canonical protected preview route rejected")
	}
	for _, change := range [][2]string{{"control:3000", "other:3000"}, {`"status_code":[2]`, `"status_code":[4]`}, {"/api/auth/check", "/api/v1/session"}, {appTLSHost("app1_preview"), appTLSHost("other_preview")}, {container + ":8080", "as-preview-other:8080"}, {host, "preview-foreign.apps.test.internal"}, {"__Host-autosoft-preview", "unprotected-cookie"}} {
		changed := strings.ReplaceAll(string(encoded), change[0], change[1])
		var foreign map[string]any
		_ = json.Unmarshal([]byte(changed), &foreign)
		if exactPreviewJWKSRoute(foreign, "app1", host, container) {
			t.Fatalf("Changed preview gateway/credential/TLS scope accepted: %s", change[0])
		}
	}
}
