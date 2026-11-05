package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
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

type accountAPIFixture struct {
	mu                                sync.Mutex
	base                              *accessAPIFixture
	user                              accountUser
	roles                             []kcRole
	clients                           []accountClient
	realmLifespan, implicit           int
	sessions, offline, federations    []json.RawMessage
	disables, logouts                 int
	uncertainDisable, uncertainLogout bool
}

func (f *accountAPIFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := "/admin/realms/" + f.base.realm
	if r.URL.Path == prefix && r.Method == "GET" {
		respond(w, map[string]any{"realm": f.base.realm, "attributes": identityMarkers(f.base.appID, f.base.realm, f.base.baseline), "accessTokenLifespan": f.realmLifespan, "accessTokenLifespanForImplicitFlow": f.implicit})
		return
	}
	if r.URL.Path == prefix+"/clients" && r.URL.Query().Get("clientId") == "" {
		respond(w, f.clients)
		return
	}
	userPath := prefix + "/users/" + f.user.ID
	if r.URL.Path == userPath {
		if r.Method == "GET" {
			respond(w, f.user)
			return
		}
		if r.Method == "PUT" {
			var body map[string]bool
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["enabled"] {
				w.WriteHeader(400)
				return
			}
			enabled := false
			f.user.Enabled = &enabled
			f.disables++
			if f.uncertainDisable {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(204)
			}
			return
		}
	}
	if r.URL.Path == userPath+"/logout" && r.Method == "POST" {
		before := time.Now().Unix()
		f.user.NotBefore = &before
		f.sessions = []json.RawMessage{}
		f.logouts++
		if f.uncertainLogout {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
		return
	}
	if r.Method == "GET" {
		switch {
		case r.URL.Path == userPath+"/federated-identity":
			respond(w, f.federations)
			return
		case r.URL.Path == userPath+"/credentials":
			respond(w, []map[string]string{{"type": "password"}, {"type": "otp"}})
			return
		case r.URL.Path == userPath+"/role-mappings/clients/"+f.base.clientID:
			respond(w, f.roles)
			return
		case r.URL.Path == userPath+"/sessions":
			respond(w, f.sessions)
			return
		case strings.HasPrefix(r.URL.Path, userPath+"/offline-sessions/"):
			respond(w, f.offline)
			return
		}
	}
	f.base.serve(w, r)
}
func newAccountFixture(t *testing.T) (*server, *accountAPIFixture, accountTarget) {
	t.Helper()
	s, base, snapshot := newAccessFixture(t)
	request := policyRequest(snapshot)
	if result := signedAccessCall(t, s, request, s.applyAccessPolicy); result.Code != 200 {
		t.Fatal(result.Body.String())
	}
	snapshot.Policy = *request.Policy
	snapshot.PolicyHash = accessHash(snapshot.Policy)
	original := inviteRequest(snapshot)
	original.OperationID = "77777777-7777-4777-8777-777777777777"
	original.Password = ""
	userID := "88888888-8888-4888-8888-888888888888"
	target := accountTarget{snapshot.AppID, original.Invitation.ID, userID, original.OperationID}
	creation := accessReceipt{Request: original, Realm: base.realm, ClientID: base.clientID, CreatedAt: time.Now().UTC().Format(time.RFC3339), Result: accessResult{OperationID: original.OperationID, AppID: target.AppID, InvitationID: target.InvitationID, UserID: userID, Status: "succeeded", Action: "invitation", Hash: original.Approval.Hash}}
	if err := atomicJSON(s.accessReceiptPath(original.OperationID), creation); err != nil {
		t.Fatal(err)
	}
	enabled, verified, before := true, false, int64(0)
	f := &accountAPIFixture{base: base, realmLifespan: 300, implicit: 900, sessions: []json.RawMessage{json.RawMessage(`{"id":"synthetic-session"}`)}, offline: []json.RawMessage{}, federations: []json.RawMessage{}, roles: []kcRole{base.roles[accessRoleName(snapshot.Policy.Roles[0].ID)]}, user: accountUser{ID: userID, Username: original.Invitation.Email, Email: original.Invitation.Email, Enabled: &enabled, EmailVerified: &verified, NotBefore: &before, Attributes: map[string][]string{"autosoft.app-id": {target.AppID}, "autosoft.invitation-id": {target.InvitationID}, "autosoft.operation-id": {target.CreationOperationID}}, RequiredActions: []string{}}}
	f.clients = []accountClient{{ID: base.clientID, ClientID: "app-" + target.AppID, Protocol: "openid-connect", Attributes: map[string]string{}}, {ID: "mcp-client", ClientID: target.AppID + ":mcp", Protocol: "openid-connect", Attributes: map[string]string{"access.token.lifespan": "1200"}}}
	api := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(api.Close)
	ca := filepath.Join(s.data, "account-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYCLOAK_CA_FILE", ca)
	t.Setenv("KEYCLOAK_INTERNAL_URL", api.URL)
	t.Setenv("OWNER_SUBJECT", "permanent-owner")
	return s, f, target
}
func accountReview(t *testing.T, s *server, target accountTarget) accountDisableRequest {
	t.Helper()
	body, _ := json.Marshal(target)
	output := httptest.NewRecorder()
	s.accountSnapshot(output, httptest.NewRequest("POST", "/v1/accounts/snapshot", bytes.NewReader(body)))
	if output.Code != 200 {
		t.Fatalf("snapshot %d %s", output.Code, output.Body.String())
	}
	var q accountSnapshot
	if json.Unmarshal(output.Body.Bytes(), &q) != nil {
		t.Fatal("snapshot decode")
	}
	now := time.Now().UTC()
	a := accountApproval{ID: "99999999-9999-4999-8999-999999999999", AppID: target.AppID, Action: "disable_app_account", Snapshot: q, Hash: accountArtifactHash(q), Impact: []string{"Preserve account records and business data."}, CreatedAt: now.Format(time.RFC3339), ApprovedAt: now.Format(time.RFC3339), ConsumedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339), ApprovedBy: "permanent-owner"}
	return accountDisableRequest{OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Approval: a, Principal: accountActor{ID: "permanent-owner", MFA: true, LocalOwner: true}}
}
func accountCall(t *testing.T, s *server, in accountDisableRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(in)
	r := httptest.NewRequest("POST", "/v1/accounts/disable", bytes.NewReader(body))
	proof := hmac.New(sha256.New, s.approvalKey)
	proof.Write(body)
	r.Header.Set("X-Autosoft-Proof", hex.EncodeToString(proof.Sum(nil)))
	output := httptest.NewRecorder()
	s.disableAppAccount(output, r)
	return output
}
func accountInspect(t *testing.T, s *server, in accountDisableRequest) accountStatus {
	t.Helper()
	body, _ := json.Marshal(accountID(in))
	output := httptest.NewRecorder()
	s.accountOperation(output, httptest.NewRequest("POST", "/v1/accounts/operation", bytes.NewReader(body)))
	if output.Code != 200 {
		t.Fatalf("inspection %d %s", output.Code, output.Body.String())
	}
	var result accountStatus
	if json.Unmarshal(output.Body.Bytes(), &result) != nil {
		t.Fatal("result decode")
	}
	return result
}
func TestAppAccountDisableExactOwnedUserAndReadOnlyConfirmation(t *testing.T) {
	s, f, target := newAccountFixture(t)
	in := accountReview(t, s, target)
	if in.Approval.Snapshot.TokenLifespan != 1200 {
		t.Fatal("did not bind maximum measured realm/implicit/client lifespan")
	}
	sentinel := filepath.Join(s.data, "business-data.sentinel")
	os.WriteFile(sentinel, []byte("preserved synthetic business rows"), 0600)
	creationBefore, _ := os.ReadFile(s.accessReceiptPath(target.CreationOperationID))
	output := accountCall(t, s, in)
	if output.Code != 200 {
		t.Fatal(output.Body.String())
	}
	var result accountStatus
	json.Unmarshal(output.Body.Bytes(), &result)
	if result.Status != "disabled" || f.disables != 1 || f.logouts != 1 || *f.user.Enabled || len(f.sessions) != 0 {
		t.Fatal("exact disable/logout not confirmed")
	}
	if accountInspect(t, s, in).Status != "disabled" || f.disables != 1 || f.logouts != 1 {
		t.Fatal("inspection replayed a mutation")
	}
	if accountCall(t, s, in).Code != 200 || f.disables != 1 || f.logouts != 1 {
		t.Fatal("duplicate operation replayed")
	}
	changed := in
	changed.OperationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if accountCall(t, s, changed).Code != 409 {
		t.Fatal("approval reused for another operation")
	}
	after, _ := os.ReadFile(s.accessReceiptPath(target.CreationOperationID))
	bytesAfter, _ := os.ReadFile(sentinel)
	if !bytes.Equal(creationBefore, after) || string(bytesAfter) != "preserved synthetic business rows" || len(f.roles) != 1 {
		t.Fatal("records or business data changed")
	}
	encrypted, _ := os.ReadFile(s.accountPath("operations", in.OperationID))
	if bytes.Contains(encrypted, []byte(target.UserID)) || bytes.Contains(encrypted, []byte(f.user.Email)) {
		t.Fatal("retained account intent is plaintext")
	}
}
func TestAppAccountDisableUncertainWritesNeverReplay(t *testing.T) {
	for _, point := range []string{"disable", "logout"} {
		t.Run(point, func(t *testing.T) {
			s, f, target := newAccountFixture(t)
			in := accountReview(t, s, target)
			f.uncertainDisable = point == "disable"
			f.uncertainLogout = point == "logout"
			if accountCall(t, s, in).Code != 503 {
				t.Fatal("uncertain write falsely confirmed")
			}
			d, l := f.disables, f.logouts
			result := accountInspect(t, s, in)
			if point == "disable" && result.Status != "pending" || point == "logout" && result.Status != "disabled" || f.disables != d || f.logouts != l {
				t.Fatal("uncertain state replayed or misclassified")
			}
			if point == "disable" {
				now := time.Now().Unix()
				f.user.NotBefore = &now
				f.sessions = []json.RawMessage{}
				if accountInspect(t, s, in).Status != "disabled" || f.logouts != 0 {
					t.Fatal("read-only operator confirmation did not reconcile")
				}
			}
		})
	}
}
func TestAppAccountDisableRejectsChangedForeignFederatedOrAmbiguousEvidence(t *testing.T) {
	cases := map[string]func(*accountAPIFixture){"foreign app": func(f *accountAPIFixture) { f.user.Attributes["autosoft.app-id"] = []string{"other-app"} }, "changed email": func(f *accountAPIFixture) { f.user.Email = "different@example.test" }, "storage federation": func(f *accountAPIFixture) { v := "ldap"; f.user.FederationLink = &v }, "social federation": func(f *accountAPIFixture) {
		f.federations = []json.RawMessage{json.RawMessage(`{"identityProvider":"company"}`)}
	}, "offline sessions": func(f *accountAPIFixture) { f.offline = []json.RawMessage{json.RawMessage(`{"id":"offline"}`)} }, "token lifespan": func(f *accountAPIFixture) { f.clients[1].Attributes["access.token.lifespan"] = "1800" }, "unknown lifetime": func(f *accountAPIFixture) { f.clients[1].Attributes["access.token.lifespan"] = "-1" }, "role drift": func(f *accountAPIFixture) { f.roles[0].Attributes = map[string][]string{} }, "missing enabled": func(f *accountAPIFixture) { f.user.Enabled = nil }, "duplicate clients": func(f *accountAPIFixture) { f.clients = append(f.clients, f.clients[0]) }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, f, target := newAccountFixture(t)
			in := accountReview(t, s, target)
			change(f)
			if output := accountCall(t, s, in); output.Code != 409 || f.disables != 0 || f.logouts != 0 {
				t.Fatalf("changed target not rejected before mutation: %d", output.Code)
			}
		})
	}
}
func TestAppAccountDisableRequiresOwnerMFAArtifactAndProtectedRetention(t *testing.T) {
	for _, kind := range []string{"not-owner", "no-mfa", "wrong-hash", "expiry", "linked-ledger", "missing-creation"} {
		t.Run(kind, func(t *testing.T) {
			s, f, target := newAccountFixture(t)
			in := accountReview(t, s, target)
			switch kind {
			case "not-owner":
				in.Principal.ID = "other"
				in.Approval.ApprovedBy = "other"
			case "no-mfa":
				in.Principal.MFA = false
			case "wrong-hash":
				in.Approval.Hash = strings.Repeat("f", 64)
			case "expiry":
				in.Approval.CreatedAt = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
				in.Approval.ApprovedAt = in.Approval.CreatedAt
				in.Approval.ConsumedAt = in.Approval.CreatedAt
				in.Approval.ExpiresAt = time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
			case "missing-creation":
				os.Remove(s.accessReceiptPath(target.CreationOperationID))
			case "linked-ledger":
				if os.PathSeparator != '/' {
					t.Skip("Linux symlink boundary")
				}
				outside := t.TempDir()
				os.MkdirAll(filepath.Join(s.data, "app-accounts"), 0700)
				if err := os.Symlink(outside, filepath.Join(s.data, "app-accounts", "approvals")); err != nil {
					t.Fatal(err)
				}
			}
			output := accountCall(t, s, in)
			if output.Code < 400 || f.disables != 0 || f.logouts != 0 {
				t.Fatal("invalid review mutated account")
			}
		})
	}
}
func TestAppAccountReadbackDemotesReenabledOrChangedAccount(t *testing.T) {
	s, f, target := newAccountFixture(t)
	in := accountReview(t, s, target)
	if accountCall(t, s, in).Code != 200 {
		t.Fatal("disable failed")
	}
	yes := true
	f.user.Enabled = &yes
	if accountInspect(t, s, in).Status != "pending" || f.disables != 1 || f.logouts != 1 {
		t.Fatal("drift falsely retained disabled status or replayed")
	}
}
func TestAppAccountReadbackRequiresOriginalApprovalAndPendingBinding(t *testing.T) {
	for _, kind := range []string{"approvals", "pending"} {
		t.Run(kind, func(t *testing.T) {
			s, f, target := newAccountFixture(t)
			in := accountReview(t, s, target)
			if accountCall(t, s, in).Code != 200 {
				t.Fatal("disable failed")
			}
			id := in.Approval.ID
			if kind == "pending" {
				id = target.AppID + "-" + target.UserID
			}
			if err := os.Remove(s.accountPath(kind, id)); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(accountID(in))
			output := httptest.NewRecorder()
			s.accountOperation(output, httptest.NewRequest("POST", "/v1/accounts/operation", bytes.NewReader(body)))
			if output.Code != 503 || f.disables != 1 || f.logouts != 1 {
				t.Fatal("missing retained authority falsely confirmed or replayed")
			}
		})
	}
}
func TestAppAccountTokenLifetimeStrictAndOrderIndependent(t *testing.T) {
	clients := []accountClient{{ID: "app-client", ClientID: "app-11111111-1111-4111-8111-111111111111", Protocol: "openid-connect", Attributes: map[string]string{}}, {ID: "mcp-client", ClientID: "11111111-1111-4111-8111-111111111111:mcp", Protocol: "openid-connect", Attributes: map[string]string{"access.token.lifespan": "1200"}}}
	n, h, err := tokenPolicyLimit(300, 900, clients, "11111111-1111-4111-8111-111111111111", "app-client")
	if err != nil || n != 1200 {
		t.Fatal("wrong measured limit")
	}
	clients[0], clients[1] = clients[1], clients[0]
	_, other, e := tokenPolicyLimit(300, 900, clients, "11111111-1111-4111-8111-111111111111", "app-client")
	if e != nil || h != other {
		t.Fatal("client ordering changed token identity")
	}
	for _, value := range []string{"-1", "0", "001", "1.0", "true", " 300", "86401"} {
		clients[0].Attributes["access.token.lifespan"] = value
		if _, _, e := tokenPolicyLimit(300, 900, clients, "11111111-1111-4111-8111-111111111111", "app-client"); e == nil {
			t.Fatalf("accepted unbounded/malformed %q", value)
		}
	}
}
