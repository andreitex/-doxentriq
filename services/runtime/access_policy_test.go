package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type accessAPIFixture struct {
	mu                               sync.Mutex
	appID, realm, clientID, baseline string
	roles                            map[string]kcRole
	composites                       map[string][]kcRole
	users                            map[string]kcUser
	assigned                         map[string][]kcRole
	passwords                        map[string]bool
	writes, creates                  int
	uncertainCreate                  bool
}

func (f *accessAPIFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token") {
		respond(w, map[string]string{"access_token": "fixture-token"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer fixture-token" {
		w.WriteHeader(401)
		return
	}
	prefix := "/admin/realms/" + f.realm
	if r.URL.Path == prefix && r.Method == "GET" {
		respond(w, map[string]any{"realm": f.realm, "attributes": identityMarkers(f.appID, f.realm, f.baseline)})
		return
	}
	if r.URL.Path == prefix+"/clients" {
		respond(w, []map[string]string{{"id": f.clientID, "clientId": "app-" + f.appID}})
		return
	}
	rolePrefix := prefix + "/clients/" + f.clientID + "/roles"
	if r.URL.Path == rolePrefix && r.Method == "POST" {
		var v kcRole
		_ = json.NewDecoder(r.Body).Decode(&v)
		v.ID = "role-" + v.Name
		v.ClientRole = true
		v.ContainerID = f.clientID
		f.roles[v.Name] = v
		f.composites[v.Name] = []kcRole{}
		f.writes++
		w.WriteHeader(201)
		return
	}
	if strings.HasPrefix(r.URL.Path, rolePrefix+"/") {
		name := strings.TrimPrefix(r.URL.Path, rolePrefix+"/")
		if strings.HasSuffix(name, "/composites") {
			name = strings.TrimSuffix(name, "/composites")
			if r.Method == "GET" {
				respond(w, f.composites[name])
				return
			}
			var selected []kcRole
			_ = json.NewDecoder(r.Body).Decode(&selected)
			if r.Method == "DELETE" {
				f.composites[name] = []kcRole{}
			} else {
				f.composites[name] = selected
			}
			f.writes++
			w.WriteHeader(204)
			return
		}
		v, found := f.roles[name]
		if !found {
			w.WriteHeader(404)
			return
		}
		respond(w, v)
		return
	}
	if r.URL.Path == prefix+"/users" && r.Method == "GET" {
		list := []kcUser{}
		for _, user := range f.users {
			if user.Username == r.URL.Query().Get("username") {
				list = append(list, user)
			}
		}
		respond(w, list)
		return
	}
	if r.URL.Path == prefix+"/users" && r.Method == "POST" {
		var body struct {
			kcUser
			Credentials []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"credentials"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		body.ID = "user-invited"
		f.users[body.ID] = body.kcUser
		for _, credential := range body.Credentials {
			f.passwords[body.ID] = credential.Type == "password" && credential.Value != ""
		}
		f.creates++
		f.writes++
		if f.uncertainCreate {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(201)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, prefix+"/users/") {
		tail := strings.TrimPrefix(r.URL.Path, prefix+"/users/")
		parts := strings.Split(tail, "/")
		id := parts[0]
		if len(parts) == 1 && r.Method == "PUT" {
			var update struct {
				Enabled bool `json:"enabled"`
			}
			_ = json.NewDecoder(r.Body).Decode(&update)
			v := f.users[id]
			v.Enabled = update.Enabled
			f.users[id] = v
			f.writes++
			w.WriteHeader(204)
			return
		}
		if strings.HasSuffix(tail, "/credentials") {
			credentials := []map[string]string{}
			if f.passwords[id] {
				credentials = append(credentials, map[string]string{"type": "password"})
			}
			respond(w, credentials)
			return
		}
		if strings.HasSuffix(tail, "/role-mappings/clients/"+f.clientID) {
			if r.Method == "GET" {
				roles := f.assigned[id]
				if roles == nil {
					roles = []kcRole{}
				}
				respond(w, roles)
				return
			}
			var roles []kcRole
			_ = json.NewDecoder(r.Body).Decode(&roles)
			f.assigned[id] = roles
			f.writes++
			w.WriteHeader(204)
			return
		}
	}
	w.WriteHeader(404)
}
func newAccessFixture(t *testing.T) (*server, *accessAPIFixture, appAccessSnapshot) {
	t.Helper()
	appID := "11111111-1111-4111-8111-111111111111"
	root := t.TempDir()
	s := &server{data: root, approvalKey: bytes.Repeat([]byte{5}, 32)}
	f := &accessAPIFixture{appID: appID, realm: "app-" + hashBytes([]byte(appID))[:24], clientID: "client-app", roles: map[string]kcRole{}, composites: map[string][]kcRole{}, users: map[string]kcUser{}, assigned: map[string][]kcRole{}, passwords: map[string]bool{}}
	api := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(api.Close)
	ca := filepath.Join(root, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0600)
	t.Setenv("KEYCLOAK_CA_FILE", ca)
	t.Setenv("KEYCLOAK_INTERNAL_URL", api.URL)
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "synthetic-secret")
	t.Setenv("AUTH_ORIGIN", "https://auth.example.test")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	m := AppManifest{Version: 1, ID: appID, Slug: "documents", Kind: "web", Auth: "local", Template: "node-web", Permissions: []string{"dms.read", "dms.write"}}
	m.Resources.CPU = 1
	m.Resources.Memory = 128
	m.Resources.Pids = 32
	m.Health.Path = "/healthz"
	m.Health.Port = 8080
	baseline, err := s.identityPolicy(m, f.realm, "https://auth.example.test/realms/"+f.realm, "https://documents.apps.example.test")
	if err != nil {
		t.Fatal(err)
	}
	f.baseline = baseline.Hash
	for _, name := range m.Permissions {
		f.roles[name] = kcRole{ID: "leaf-" + strings.ReplaceAll(name, ".", "-"), Name: name, ClientRole: true, ContainerID: f.clientID}
	}
	source := filepath.Join(root, "sources", "attempt-access")
	if err := atomicJSON(filepath.Join(source, "app.manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	digest, err := sourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	image := "registry.internal/app@sha256:" + strings.Repeat("b", 64)
	v := Verification{AppID: appID, AttemptID: "attempt-access", Template: "node-web", Images: []string{image}, SourceHash: digest, Evidence: Evidence{Status: "passed"}}
	_ = atomicJSON(filepath.Join(root, "receipts", "attempt-access.json"), v)
	active := activeDeployment{Hash: strings.Repeat("a", 64), OperationID: "publication-access", ReleaseID: "22222222-2222-4222-8222-222222222222", Image: image}
	_ = atomicJSON(filepath.Join(root, "active", appID+".json"), active)
	_ = atomicJSON(filepath.Join(root, "operations", active.OperationID+".json"), deployReceipt{AppID: appID, ReleaseID: active.ReleaseID, Hash: active.Hash, Phase: "completed", AttemptID: v.AttemptID})
	policy := appAccessPolicy{Version: 1, AppID: appID, InvitationsEnabled: true, RequireTOTP: true, Roles: []appAccessRole{}, GroupMappings: []appGroupMapping{}}
	snapshot := appAccessSnapshot{AppID: appID, ReleaseID: active.ReleaseID, IdentityHash: f.baseline, PolicyHash: accessHash(policy), Policy: policy, Permissions: m.Permissions}
	return s, f, snapshot
}
func signedAccessCall(t *testing.T, s *server, in accessRequest, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(in)
	request := httptest.NewRequest("POST", "/v1/access", bytes.NewReader(body))
	h := hmac.New(sha256.New, s.approvalKey)
	_, _ = h.Write(body)
	request.Header.Set("X-Autosoft-Proof", hex.EncodeToString(h.Sum(nil)))
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}
func policyRequest(snapshot appAccessSnapshot) accessRequest {
	now := time.Now().UTC()
	policy := snapshot.Policy
	policy.Roles = []appAccessRole{{ID: "33333333-3333-4333-8333-333333333333", Name: "Readers & editors", Permissions: []string{"dms.read"}}}
	in := accessRequest{OperationID: "policy-operation", AppID: snapshot.AppID, BaseHash: snapshot.PolicyHash, Policy: &policy, Principal: accessActor{ID: "admin-id", MFA: true}}
	in.Approval = accessApproval{ID: "44444444-4444-4444-8444-444444444444", AppID: snapshot.AppID, Action: "access_policy", BaseHash: snapshot.PolicyHash, ApprovedBy: in.Principal.ID, ApprovedAt: now.Format(time.RFC3339), ConsumedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339)}
	in.Approval.Hash = accessActionHash(in)
	return in
}
func inviteRequest(snapshot appAccessSnapshot) accessRequest {
	now := time.Now().UTC()
	v := &appInvitation{ID: "55555555-5555-4555-8555-555555555555", AppID: snapshot.AppID, Email: "reader@example.test", RoleIDs: []string{snapshot.Policy.Roles[0].ID}, PolicyHash: snapshot.PolicyHash, ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339), CreatedBy: "admin-id", CreatedAt: now.Format(time.RFC3339), ApprovalID: "66666666-6666-4666-8666-666666666666"}
	in := accessRequest{OperationID: "invitation-operation", Invitation: v, Principal: accessActor{ID: "admin-id", MFA: true}, Password: "Synthetic-Password-17!"}
	in.Approval = accessApproval{ID: v.ApprovalID, AppID: v.AppID, Action: "invitation", BaseHash: v.PolicyHash, ApprovedBy: in.Principal.ID, ApprovedAt: now.Format(time.RFC3339), ConsumedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339)}
	in.Approval.Hash = accessActionHash(in)
	return in
}
func TestApprovedScopedCompositePolicyAndInvitationLifecycle(t *testing.T) {
	s, f, snapshot := newAccessFixture(t)
	in := policyRequest(snapshot)
	response := signedAccessCall(t, s, in, s.applyAccessPolicy)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var result accessResult
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if result.Status != "succeeded" || result.PolicyHash != accessHash(in.Policy) {
		t.Fatal("Policy not confirmed")
	}
	writes := f.writes
	if replay := signedAccessCall(t, s, in, s.applyAccessPolicy); replay.Code != 200 || f.writes != writes {
		t.Fatal("Policy replay repeated writes")
	}
	otherApproval := in
	otherApproval.Approval.ID = "99999999-9999-4999-8999-999999999999"
	if replay := signedAccessCall(t, s, otherApproval, s.applyAccessPolicy); replay.Code != 409 || f.writes != writes {
		t.Fatal("Operation replay accepted a different approval identity")
	}
	otherOperation := in
	otherOperation.OperationID = "another-policy-operation"
	if replay := signedAccessCall(t, s, otherOperation, s.applyAccessPolicy); replay.Code != 409 || f.writes != writes {
		t.Fatal("One-use approval authorized another operation")
	}
	snapshot.Policy = *in.Policy
	snapshot.PolicyHash = result.PolicyHash
	invite := inviteRequest(snapshot)
	response = signedAccessCall(t, s, invite, s.acceptAppInvitation)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if result.Status != "succeeded" || result.UserID == "" || f.creates != 1 {
		t.Fatal("Invitation was not exactly confirmed")
	}
	user := f.users[result.UserID]
	if user.EmailVerified || !user.Enabled || !containsString(user.RequiredActions, "CONFIGURE_TOTP") {
		t.Fatal("App invitation MFA/email boundary incorrect")
	}
	receipt, err := os.ReadFile(s.accessReceiptPath(invite.OperationID))
	if err != nil || bytes.Contains(receipt, []byte(invite.Password)) {
		t.Fatal("Password was retained in durable identity state")
	}
	invite.Password = "Different-Password-Never-Used"
	writes = f.writes
	if replay := signedAccessCall(t, s, invite, s.acceptAppInvitation); replay.Code != 200 || f.writes != writes || f.creates != 1 {
		t.Fatal("Invitation replay reset a password or created another user")
	}
}
func TestAccessApprovalsForeignPermissionsAndRealmOwnershipFailClosed(t *testing.T) {
	s, f, snapshot := newAccessFixture(t)
	in := policyRequest(snapshot)
	in.Policy.Roles[0].Permissions = []string{"platform-owner"}
	in.Approval.Hash = accessActionHash(in)
	response := signedAccessCall(t, s, in, s.applyAccessPolicy)
	if response.Code != 409 || f.writes != 0 {
		t.Fatal("Foreign platform permission reached identity service")
	}
	in = policyRequest(snapshot)
	in.Principal.MFA = false
	response = signedAccessCall(t, s, in, s.applyAccessPolicy)
	if response.Code != 409 || f.writes != 0 {
		t.Fatal("Non-MFA policy approval accepted")
	}
	in = policyRequest(snapshot)
	f.baseline = strings.Repeat("f", 64)
	response = signedAccessCall(t, s, in, s.applyAccessPolicy)
	if response.Code != 409 || f.writes != 0 {
		t.Fatal("Unowned realm mutated")
	}
}
func TestUncertainInvitationNeverRetriesPasswordAndReconcilesOnlyConfirmedEnabledAccount(t *testing.T) {
	s, f, snapshot := newAccessFixture(t)
	policy := policyRequest(snapshot)
	response := signedAccessCall(t, s, policy, s.applyAccessPolicy)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	snapshot.Policy = *policy.Policy
	snapshot.PolicyHash = accessHash(policy.Policy)
	invite := inviteRequest(snapshot)
	f.uncertainCreate = true
	response = signedAccessCall(t, s, invite, s.acceptAppInvitation)
	if response.Code != 503 || f.creates != 1 {
		t.Fatal("Fixture did not interrupt remote creation")
	}
	restarted := &server{data: s.data, approvalKey: s.approvalKey}
	response = signedAccessCall(t, restarted, invite, restarted.acceptAppInvitation)
	var result accessResult
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if response.Code != 200 || result.Status != "running" || f.creates != 1 {
		t.Fatal("Uncertain invitation was blindly replayed")
	}
	query := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"appId": snapshot.AppID, "operationId": invite.OperationID})
		r := httptest.NewRecorder()
		restarted.accessOperation(r, httptest.NewRequest("POST", "/v1/access/operation", bytes.NewReader(body)))
		return r
	}
	response = query()
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if result.Status != "running" || f.users["user-invited"].Enabled {
		t.Fatal("Disabled ambiguous account was automatically enabled")
	}
	// Simulate confirmed completion by the identity operator; recovery only reads it.
	user := f.users["user-invited"]
	user.Enabled = true
	f.users[user.ID] = user
	f.assigned[user.ID] = []kcRole{f.roles[accessRoleName(snapshot.Policy.Roles[0].ID)]}
	writes := f.writes
	response = query()
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if result.Status != "succeeded" || result.UserID != user.ID || f.writes != writes || f.creates != 1 {
		t.Fatal("Confirmed original account could not reconcile read-only")
	}
}
func TestAccessRoleRemovalClearsExistingCompositeGrantAndCodeBaselineStaysIndependent(t *testing.T) {
	s, f, snapshot := newAccessFixture(t)
	in := policyRequest(snapshot)
	response := signedAccessCall(t, s, in, s.applyAccessPolicy)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	snapshot.Policy = *in.Policy
	snapshot.PolicyHash = accessHash(in.Policy)
	removed := policyRequest(snapshot)
	removed.OperationID = "remove-role-operation"
	removed.Approval.ID = "77777777-7777-4777-8777-777777777777"
	removed.Policy.Roles = []appAccessRole{}
	removed.Approval.Hash = accessActionHash(removed)
	response = signedAccessCall(t, s, removed, s.applyAccessPolicy)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	if len(f.composites[accessRoleName(in.Policy.Roles[0].ID)]) != 0 {
		t.Fatal("Removed role still grants backend permissions")
	}
	var baseline identityPolicyState
	if readEncrypted(filepath.Join(s.data, "identity-policies", f.realm+".enc"), &baseline) != nil || baseline.Hash != snapshot.IdentityHash {
		t.Fatal("Approved overlay modified code rollback identity baseline")
	}
}

func TestOldPolicyReconciliationCannotOverwriteNewerPolicyAndPendingIntentFencesChanges(t *testing.T) {
	s, _, snapshot := newAccessFixture(t)
	first := policyRequest(snapshot)
	response := signedAccessCall(t, s, first, s.applyAccessPolicy)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var old accessReceipt
	if readBoundedJSON(s.accessReceiptPath(first.OperationID), &old) != nil {
		t.Fatal("Missing receipt")
	}
	old.Result.Status = "running"
	old.Result.PolicyHash = ""
	_ = atomicJSON(s.accessReceiptPath(first.OperationID), old)
	snapshot.Policy = *first.Policy
	snapshot.PolicyHash = accessHash(first.Policy)
	newer := policyRequest(snapshot)
	newer.OperationID = "newer-policy-operation"
	newer.Approval.ID = "88888888-8888-4888-8888-888888888888"
	newer.Policy.InvitationsEnabled = false
	newer.Approval.Hash = accessActionHash(newer)
	// A retained app-level intent blocks independent new requests even across process restart.
	pending := filepath.Join(s.data, "access-pending", snapshot.AppID+".json")
	_ = atomicJSON(pending, map[string]string{"operationId": first.OperationID})
	response = signedAccessCall(t, s, newer, s.applyAccessPolicy)
	if response.Code != 409 {
		t.Fatal("Unconfirmed policy did not fence later writes")
	}
	_ = os.Remove(pending)
	// This also covers recovery of installations predating the pending pointer.
	response = signedAccessCall(t, s, newer, s.applyAccessPolicy)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	query, _ := json.Marshal(map[string]string{"appId": snapshot.AppID, "operationId": first.OperationID})
	response = httptest.NewRecorder()
	s.accessOperation(response, httptest.NewRequest("POST", "/v1/access/operation", bytes.NewReader(query)))
	var result accessResult
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if response.Code != 200 || result.Status != "failed" {
		t.Fatal("Superseded policy was incorrectly reconciled as success", response.Body.String())
	}
	var actual appAccessPolicy
	if readEncrypted(filepath.Join(s.data, "access-policies", snapshot.AppID+".enc"), &actual) != nil || actual.InvitationsEnabled || accessHash(actual) != accessHash(newer.Policy) {
		t.Fatal("Old operation reverted the newer invitation policy")
	}
}
