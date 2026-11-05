package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type observationFixture struct {
	server     *server
	request    observationRequest
	current    activeDeployment
	inspected  tlsContainer
	probe      string
	probeError error
	routed     bool
	calls      int
}

func newObservationFixture(t *testing.T, auth string) *observationFixture {
	t.Helper()
	f := &observationFixture{server: &server{data: t.TempDir(), hostRuntime: filepath.Join(t.TempDir(), "runtime")}, probe: "AUTOSOFT_HEALTHY", routed: true}
	t.Setenv("APPS_BASE_URL", "https://apps.test.internal")
	f.request = observationRequest{ID: "observation1", AppID: "app1", ReleaseID: "release001", Hash: strings.Repeat("a", 64), Images: []string{"registry.internal/apps/app1@sha256:" + strings.Repeat("b", 64)}, OperationID: "publication1"}
	manifest := AppManifest{Version: 1, ID: "app1", Slug: "documents", Kind: "web", Auth: auth, Template: "node-web"}
	manifest.Resources.CPU = 1
	manifest.Resources.Memory = 128
	manifest.Resources.Pids = 32
	manifest.Health.Path = "/healthz"
	manifest.Health.Port = 8080
	source := filepath.Join(f.server.data, "sources", "attempt1")
	if err := atomicJSON(filepath.Join(source, "app.manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := sourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	v := Verification{AppID: "app1", AttemptID: "attempt1", Template: "node-web", Images: f.request.Images, SourceHash: digest, Schema: 1, SchemaMin: 1, SchemaMax: 1, Evidence: Evidence{Status: "passed"}}
	if err = atomicJSON(filepath.Join(f.server.data, "receipts", "attempt1.json"), v); err != nil {
		t.Fatal(err)
	}
	publication := deployReceipt{OperationID: f.request.OperationID, Hash: f.request.Hash, ApprovalID: "approval1", Healthy: true, Phase: "completed", AppID: "app1", ReleaseID: f.request.ReleaseID, AttemptID: "attempt1"}
	for _, dir := range []string{"operations", "used-approvals"} {
		name := f.request.OperationID
		if dir == "used-approvals" {
			name = "approval1"
		}
		if err = atomicJSON(filepath.Join(f.server.data, dir, name+".json"), publication); err != nil {
			t.Fatal(err)
		}
	}
	f.current = activeDeployment{Hash: f.request.Hash, OperationID: f.request.OperationID, ReleaseID: f.request.ReleaseID, Container: "as-app-app1-release001", Image: f.request.Images[0], Schema: 1, URL: "https://documents.apps.test.internal"}
	if err = atomicJSON(filepath.Join(f.server.data, "active", "app1.json"), f.current); err != nil {
		t.Fatal(err)
	}
	f.inspected.ID = strings.Repeat("c", 64)
	f.inspected.Name = "/" + f.current.Container
	f.inspected.Config.Image = f.current.Image
	f.inspected.Config.Labels = map[string]string{"io.autosoft.managed": "true", "io.autosoft.app": "app1"}
	f.inspected.State.Running = true
	f.inspected.Mounts = append(f.inspected.Mounts, struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}{"bind", filepath.Join(f.server.hostRuntime, "secrets", "app1"), "/run/app-secrets", false})
	f.server.routeProbe = func(_ context.Context, app, host, container string) (bool, error) {
		if app != "app1" || host != "documents.apps.test.internal" || container != f.current.Container {
			t.Fatal("Route observation escaped exact application")
		}
		return f.routed, nil
	}
	f.server.runner = func(_ context.Context, command string, args ...string) (string, error) {
		f.calls++
		if command != "docker" {
			t.Fatal("Unexpected host command")
		}
		if args[0] == "inspect" {
			b, _ := json.Marshal(f.inspected)
			return string(b), nil
		}
		if args[0] == "exec" && args[1] == f.inspected.ID {
			return f.probe, f.probeError
		}
		t.Fatalf("Unexpected execution:%v", args)
		return "", nil
	}
	return f
}
func observeFixture(t *testing.T, f *observationFixture) releaseObservation {
	t.Helper()
	b, _ := json.Marshal(f.request)
	response := httptest.NewRecorder()
	f.server.observeRelease(response, httptest.NewRequest("POST", "/v1/observe", strings.NewReader(string(b))))
	var result releaseObservation
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatalf("Observation failed:%s", response.Body.String())
	}
	return result
}

func TestObservationUsesExactMeasuredHealthAndReplaysItsReceipt(t *testing.T) {
	f := newObservationFixture(t, "local")
	result := observeFixture(t, f)
	if result.Status != "healthy" || result.EvidenceHash == "" || result.Hash != f.request.Hash {
		t.Fatalf("Invalid result:%+v", result)
	}
	calls := f.calls
	f.probe = "AUTOSOFT_UNHEALTHY"
	if replay := observeFixture(t, f); !reflect.DeepEqual(result, replay) || f.calls != calls {
		t.Fatal("Observation retry repeated measurement or changed immutable evidence")
	}
	f.request.Images = []string{"registry.internal/other@sha256:" + strings.Repeat("d", 64)}
	b, _ := json.Marshal(f.request)
	response := httptest.NewRecorder()
	f.server.observeRelease(response, httptest.NewRequest("POST", "/v1/observe", strings.NewReader(string(b))))
	if response.Code != 409 || f.calls != calls {
		t.Fatal("Conflicting observation identity was accepted")
	}
}
func TestUnavailableRuntimeAndChangedRoutingNeverCountAsHealthFailure(t *testing.T) {
	f := newObservationFixture(t, "local")
	f.probeError = errors.New("Docker is unavailable")
	if observeFixture(t, f).Status != "unavailable" {
		t.Fatal("Infrastructure failure became application failure")
	}
	f.request.ID = "observation2"
	f.probeError = nil
	f.routed = false
	if observeFixture(t, f).Status != "unavailable" {
		t.Fatal("Uncertain routing became application failure")
	}
	f.request.ID = "observation3"
	f.routed = true
	f.probe = "AUTOSOFT_UNHEALTHY"
	if observeFixture(t, f).Status != "unhealthy" {
		t.Fatal("Actual HTTPS health failure was not recorded")
	}
}
func TestObservationRejectsCrossApplicationOwnershipAndSupersededRelease(t *testing.T) {
	f := newObservationFixture(t, "local")
	f.inspected.Config.Labels["io.autosoft.app"] = "other-app"
	if observeFixture(t, f).Status != "unavailable" {
		t.Fatal("Cross application container was measured")
	}
	f.request.ID = "observation2"
	active := f.current
	active.ReleaseID = "later-release"
	if err := atomicJSON(filepath.Join(f.server.data, "active", "app1.json"), active); err != nil {
		t.Fatal(err)
	}
	if observeFixture(t, f).Status != "superseded" {
		t.Fatal("Earlier release measured after a new publication")
	}
}
func TestPublicCatalogRequiresExplicitVerifiedPublicManifest(t *testing.T) {
	for _, auth := range []string{"local", "sso", "public"} {
		t.Run(auth, func(t *testing.T) {
			f := newObservationFixture(t, auth)
			response := httptest.NewRecorder()
			f.server.publicCatalog(response, httptest.NewRequest("POST", "/v1/public-catalog", strings.NewReader(`{}`)))
			var result struct {
				Apps []struct {
					AppID     string `json:"appId"`
					ReleaseID string `json:"releaseId"`
					Auth      string `json:"auth"`
				}
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil {
				t.Fatal(response.Body.String())
			}
			if auth != "public" && len(result.Apps) != 0 {
				t.Fatal("Private application disclosed")
			}
			if auth == "public" && (len(result.Apps) != 1 || result.Apps[0].ReleaseID != f.request.ReleaseID || result.Apps[0].Auth != "public") {
				t.Fatal("Exact public app not listed")
			}
			if err := os.WriteFile(filepath.Join(f.server.data, "sources", "attempt1", "tampered.txt"), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			response = httptest.NewRecorder()
			f.server.publicCatalog(response, httptest.NewRequest("POST", "/v1/public-catalog", strings.NewReader(`{}`)))
			if json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Apps) != 0 {
				t.Fatal("Tampered protected source disclosed")
			}
		})
	}
}

func TestProtectedCatalogRequiresExplicitInternalRequestAndVerifiedPublication(t *testing.T) {
	for _, auth := range []string{"local", "sso", "public"} {
		t.Run(auth, func(t *testing.T) {
			f := newObservationFixture(t, auth)
			request := func() []struct {
				Auth string `json:"auth"`
			} { response := httptest.NewRecorder(); f.server.publicCatalog(response, httptest.NewRequest("POST", "/v1/public-catalog", strings.NewReader(`{"includeProtected":true}`))); var result struct {
				Apps []struct {
					Auth string `json:"auth"`
				} `json:"apps"`
			}; if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil {
				t.Fatal(response.Body.String())
			}; return result.Apps }
			apps := request()
			if len(apps) != 1 || apps[0].Auth != auth {
				t.Fatal("Verified original authentication mode was not preserved")
			}
			if err := os.WriteFile(filepath.Join(f.server.data, "sources", "attempt1", "tampered.txt"), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			if len(request()) != 0 {
				t.Fatal("Protected catalog accepted tampered publication")
			}
		})
	}
}

func validRecoveryFixture(t *testing.T) (*observationFixture, recoveryRequest) {
	t.Helper()
	f := newObservationFixture(t, "local")
	f.probe = "AUTOSOFT_UNHEALTHY"
	g := recoveryGrant{ID: "grant1", AppID: "app1", FailedReleaseID: f.request.ReleaseID, FailedHash: f.request.Hash, FailedImages: f.request.Images, TargetReleaseID: "release000", TargetHash: strings.Repeat("e", 64), TargetImages: []string{"registry.internal/apps/app1@sha256:" + strings.Repeat("f", 64)}, Schema: 1, ApprovedBy: "owner", ApprovedAt: time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339), ExpiresAt: time.Now().Add(29 * 24 * time.Hour).UTC().Format(time.RFC3339), ApprovalID: "approval1", OperationID: f.request.OperationID}
	g.AuthorizationHash = grantAuthorizationHash(g)
	f.current.Previous = &activeDeployment{ReleaseID: g.TargetReleaseID, Hash: g.TargetHash, Image: g.TargetImages[0]}
	if err := atomicJSON(filepath.Join(f.server.data, "recovery-grants", g.ID+".json"), g); err != nil {
		t.Fatal(err)
	}
	in := recoveryRequest{OperationID: "recovery1", Grant: g, Release: release{ID: g.TargetReleaseID, AppID: "app1", Hash: g.TargetHash, Images: g.TargetImages, SchemaMin: 1, SchemaMax: 1}}
	in.App.ID = "app1"
	in.App.Slug = "documents"
	for i, id := range []string{"failure1", "failure2", "failure3"} {
		request := f.request
		request.ID = id
		observed := releaseObservation{observationRequest: request, Status: "unhealthy", Detail: "Measured failure", CheckedAt: time.Now().Add(time.Duration(-3+i) * time.Minute).UTC().Format(time.RFC3339Nano)}
		b, _ := json.Marshal(observed)
		observed.EvidenceHash = hashBytes(b)
		if err := atomicJSON(filepath.Join(f.server.data, "observations", id+".json"), observed); err != nil {
			t.Fatal(err)
		}
		in.ObservationIDs = append(in.ObservationIDs, id)
		in.EvidenceHashes = append(in.EvidenceHashes, observed.EvidenceHash)
	}
	return f, in
}
func TestRecoveryRequiresRepeatedFailuresAndTheOriginalExactAuthorization(t *testing.T) {
	f, in := validRecoveryFixture(t)
	if err := f.server.checkRecovery(context.Background(), in, &f.current); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name   string
		change func(*recoveryRequest)
	}{
		{"one failure", func(v *recoveryRequest) { v.ObservationIDs = v.ObservationIDs[:1] }},
		{"duplicate failures", func(v *recoveryRequest) { v.ObservationIDs = []string{"failure1", "failure1", "failure1"} }},
		{"different evidence", func(v *recoveryRequest) { v.EvidenceHashes = []string{"changed", "changed", "changed"} }},
		{"different grant", func(v *recoveryRequest) { v.Grant.ApprovedBy = "another-user" }},
		{"different target", func(v *recoveryRequest) { v.Release.Hash = strings.Repeat("0", 64) }},
		{"schema mismatch", func(v *recoveryRequest) { v.Release.SchemaMax = 0 }},
		{"expired", func(v *recoveryRequest) {
			v.Grant.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
			v.Grant.AuthorizationHash = grantAuthorizationHash(v.Grant)
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			copy := in
			mutate.change(&copy)
			if f.server.checkRecovery(context.Background(), copy, &f.current) == nil {
				t.Fatal("Unsafe recovery accepted")
			}
		})
	}
	f.probe = "AUTOSOFT_HEALTHY"
	if f.server.checkRecovery(context.Background(), in, &f.current) == nil {
		t.Fatal("Recovered health still caused rollback")
	}
	f.probe = "AUTOSOFT_UNHEALTHY"
	current := f.current
	current.ReleaseID = "newer-release"
	if f.server.checkRecovery(context.Background(), in, &current) == nil {
		t.Fatal("A later publication was rolled back")
	}
}
func TestRecoveryFailsBeforePrivilegedExecutionWithoutSignedProof(t *testing.T) {
	f, in := validRecoveryFixture(t)
	b, _ := json.Marshal(in)
	response := httptest.NewRecorder()
	f.server.recoverRelease(response, httptest.NewRequest("POST", "/v1/recover", strings.NewReader(string(b))))
	if response.Code != 403 || f.calls != 0 {
		t.Fatal("Unsigned recovery reached privileged execution")
	}
}
func TestUnknownAndMalformedSeverityCannotBypassEmergencyReview(t *testing.T) {
	for _, severity := range []string{"UNKNOWN", "", "BOGUS"} {
		in, v := goodDeployment()
		in.Action = "emergency_rollback"
		in.Approval.Action = in.Action
		v.Evidence.Findings = []Finding{{ID: "fixture", Severity: severity}}
		in.Release.Evidence = v.Evidence
		if checkDeploy(in, v, nil) == nil {
			t.Fatalf("Severity %q bypassed independent review", severity)
		}
	}
}

func TestRuntimeAuthenticationRejectsMissingSchemeAndEmptyCredentials(t *testing.T) {
	calls := 0
	s := server{token: "fixture-credential-with-thirty-two-characters"}
	handler := s.authenticated(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) })
	for _, header := range []string{"", s.token, "Basic " + s.token, "Bearer wrong"} {
		r := httptest.NewRequest("POST", "/v1/observe", strings.NewReader(`{}`))
		r.Header.Set("Authorization", header)
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 401 || calls != 0 {
			t.Fatal("Invalid bearer authentication accepted")
		}
	}
	r := httptest.NewRequest("POST", "/v1/observe", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+s.token)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != 204 || calls != 1 {
		t.Fatal("Valid credential rejected")
	}
	s.token = ""
	w = httptest.NewRecorder()
	handler(w, httptest.NewRequest("POST", "/v1/observe", strings.NewReader(`{}`)))
	if w.Code != 401 || calls != 1 {
		t.Fatal("Empty configured credential allowed unauthenticated execution")
	}
	file := filepath.Join(t.TempDir(), "empty-secret")
	if err := os.WriteFile(file, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BROKER_TOKEN_FILE", file)
	if _, err := secret("BROKER_TOKEN"); err == nil {
		t.Fatal("Empty protected secret file accepted")
	}
}

func TestPendingOperationNeedsExactActualPublicationAndHealthyRoute(t *testing.T) {
	f := newObservationFixture(t, "local")
	var receipt deployReceipt
	file := filepath.Join(f.server.data, "operations", f.request.OperationID+".json")
	if err := readBoundedJSON(file, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Phase = "started"
	receipt.Healthy = false
	if err := atomicJSON(file, receipt); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.server.operation(w, httptest.NewRequest("POST", "/v1/operation", strings.NewReader(`{"operationId":"publication1"}`)))
	var result struct {
		Status  string
		Schema  int `json:"schemaVersion"`
		Healthy bool
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Status != "succeeded" || !result.Healthy || result.Schema != 1 {
		t.Fatalf("Exact healthy operation was not reconciled:%s", w.Body.String())
	}
	if err := readBoundedJSON(file, &receipt); err != nil || receipt.Phase != "completed" || receipt.Schema != 1 {
		t.Fatal("Healthy reconciliation was not durable")
	}
}
func TestHistoricalVersionOrUncertainRouteCannotReconcileAnotherOperation(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*observationFixture)
	}{
		{"different operation", func(f *observationFixture) { f.current.OperationID = "different-operation" }},
		{"different artifact", func(f *observationFixture) { f.current.Hash = strings.Repeat("f", 64) }},
		{"different image", func(f *observationFixture) {
			f.current.Image = "registry.internal/other@sha256:" + strings.Repeat("f", 64)
		}},
		{"changed route", func(f *observationFixture) { f.routed = false }},
		{"unhealthy", func(f *observationFixture) { f.probe = "AUTOSOFT_UNHEALTHY" }},
		{"container ownership", func(f *observationFixture) { f.inspected.Config.Labels["io.autosoft.app"] = "another-app" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := newObservationFixture(t, "local")
			var receipt deployReceipt
			file := filepath.Join(f.server.data, "operations", f.request.OperationID+".json")
			if err := readBoundedJSON(file, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt.Phase = "started"
			receipt.Healthy = false
			if err := atomicJSON(file, receipt); err != nil {
				t.Fatal(err)
			}
			change.apply(f)
			if err := atomicJSON(filepath.Join(f.server.data, "active", "app1.json"), f.current); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			f.server.operation(w, httptest.NewRequest("POST", "/v1/operation", strings.NewReader(`{"operationId":"publication1"}`)))
			var result struct {
				Status  string
				Healthy bool
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Status != "running" || result.Healthy {
				t.Fatalf("Uncertain operation was incorrectly completed:%s", w.Body.String())
			}
			if err := readBoundedJSON(file, &receipt); err != nil || receipt.Phase != "started" {
				t.Fatal("Uncertain receipt was rewritten")
			}
		})
	}
}
