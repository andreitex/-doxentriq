package main

// Offboarding is a separately approved identity action. It never deletes a
// user, role, credential, stored invitation, application file or business row.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type accountTarget struct {
	AppID               string `json:"appId"`
	InvitationID        string `json:"invitationId"`
	UserID              string `json:"userId"`
	CreationOperationID string `json:"creationOperationId"`
}
type accountSnapshot struct {
	accountTarget
	Version          int    `json:"schemaVersion"`
	ReleaseID        string `json:"releaseId"`
	IdentityHash     string `json:"identityHash"`
	PolicyHash       string `json:"policyHash"`
	Realm            string `json:"realm"`
	ClientID         string `json:"clientId"`
	Username         string `json:"username"`
	Email            string `json:"email"`
	Enabled          bool   `json:"enabled"`
	UserEvidenceHash string `json:"userEvidenceHash"`
	TokenPolicyHash  string `json:"tokenPolicyHash"`
	TokenLifespan    int    `json:"accessTokenLifespanSeconds"`
	CheckedAt        string `json:"checkedAt"`
}
type accountApproval struct {
	ID         string          `json:"id"`
	AppID      string          `json:"appId"`
	Action     string          `json:"action"`
	Hash       string          `json:"artifactHash"`
	Snapshot   accountSnapshot `json:"snapshot"`
	Impact     []string        `json:"impact"`
	CreatedAt  string          `json:"createdAt"`
	ExpiresAt  string          `json:"expiresAt"`
	ApprovedBy string          `json:"approvedBy"`
	ApprovedAt string          `json:"approvedAt"`
	ConsumedAt string          `json:"consumedAt"`
}
type accountActor struct {
	ID         string `json:"id"`
	MFA        bool   `json:"mfa"`
	LocalOwner bool   `json:"localOwner"`
}
type accountDisableRequest struct {
	OperationID string          `json:"operationId"`
	Approval    accountApproval `json:"approval"`
	Principal   accountActor    `json:"principal"`
}
type accountOperationIdentity struct {
	OperationID  string `json:"operationId"`
	ApprovalID   string `json:"approvalId"`
	AppID        string `json:"appId"`
	InvitationID string `json:"invitationId"`
	UserID       string `json:"userId"`
	Hash         string `json:"artifactHash"`
}
type accountStatus struct {
	accountOperationIdentity
	Status    string `json:"status"`
	CheckedAt string `json:"checkedAt"`
	Detail    string `json:"detail"`
}
type accountReceipt struct {
	Request   accountDisableRequest `json:"request"`
	StartedAt string                `json:"startedAt"`
	Status    accountStatus         `json:"status"`
}
type accountUser struct {
	ID              string              `json:"id"`
	Username        string              `json:"username"`
	Email           string              `json:"email"`
	Enabled         *bool               `json:"enabled"`
	EmailVerified   *bool               `json:"emailVerified"`
	Attributes      map[string][]string `json:"attributes"`
	RequiredActions []string            `json:"requiredActions"`
	FederationLink  *string             `json:"federationLink"`
	NotBefore       *int64              `json:"notBefore"`
}
type accountClient struct {
	ID         string            `json:"id"`
	ClientID   string            `json:"clientId"`
	Protocol   string            `json:"protocol"`
	Implicit   bool              `json:"implicitFlowEnabled"`
	Attributes map[string]string `json:"attributes"`
}
type accountTokenPolicy struct {
	RealmLifespan    int             `json:"realmLifespan"`
	ImplicitLifespan int             `json:"implicitLifespan"`
	Clients          []accountClient `json:"clients"`
}

func accountArtifactHash(snapshot accountSnapshot) string {
	b, _ := json.Marshal(snapshot)
	var value map[string]any
	_ = json.Unmarshal(b, &value)
	delete(value, "checkedAt")
	return accessHash(map[string]any{"action": "disable_app_account", "account": value})
}
func accountID(in accountDisableRequest) accountOperationIdentity {
	q := in.Approval.Snapshot
	return accountOperationIdentity{in.OperationID, in.Approval.ID, q.AppID, q.InvitationID, q.UserID, in.Approval.Hash}
}
func validAccountTarget(v accountTarget) bool {
	return accessUUID.MatchString(v.AppID) && accessUUID.MatchString(v.InvitationID) && accessUUID.MatchString(v.UserID) && accessUUID.MatchString(v.CreationOperationID)
}
func validAccountRequest(in accountDisableRequest, fresh bool) error {
	a, q := in.Approval, in.Approval.Snapshot
	created, e1 := time.Parse(time.RFC3339, a.CreatedAt)
	approved, e2 := time.Parse(time.RFC3339, a.ApprovedAt)
	expires, e3 := time.Parse(time.RFC3339, a.ExpiresAt)
	consumed, e4 := time.Parse(time.RFC3339, a.ConsumedAt)
	checked, e5 := time.Parse(time.RFC3339, q.CheckedAt)
	if !accessUUID.MatchString(in.OperationID) || !accessUUID.MatchString(a.ID) || !validAccountTarget(q.accountTarget) || a.AppID != q.AppID || a.Action != "disable_app_account" || a.Hash != accountArtifactHash(q) || !accessHex.MatchString(a.Hash) || q.Version != 1 || !q.Enabled || !accessUUID.MatchString(q.ReleaseID) || !accessHex.MatchString(q.IdentityHash) || !accessHex.MatchString(q.PolicyHash) || !accessHex.MatchString(q.UserEvidenceHash) || !accessHex.MatchString(q.TokenPolicyHash) || q.Realm != "app-"+hashBytes([]byte(q.AppID))[:24] || !identity.MatchString(q.ClientID) || q.TokenLifespan < 1 || q.TokenLifespan > 86400 || in.Principal.ID == "" || in.Principal.ID != os.Getenv("OWNER_SUBJECT") || !in.Principal.MFA || !in.Principal.LocalOwner || a.ApprovedBy != in.Principal.ID || e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || approved.Before(created) || consumed.Before(approved) || !consumed.Before(expires) || expires.Sub(created) > 5*time.Minute || !expires.After(created) || created.After(time.Now().Add(10*time.Second)) || checked.After(created.Add(10*time.Second)) || created.Sub(checked) > time.Minute || consumed.After(time.Now().Add(10*time.Second)) || len(a.Impact) < 1 || len(a.Impact) > 20 {
		return errors.New("Exact consumed permanent-owner MFA account review required")
	}
	if fresh && !expires.After(time.Now()) {
		return errors.New("Account approval expired")
	}
	return nil
}
func (s *server) accountPath(kind, id string) string {
	return filepath.Join(s.data, "app-accounts", kind, id+".enc")
}
func (s *server) accountRead(file string, output any) error {
	if err := withdrawalAncestors(s.data, filepath.Dir(file), false); err != nil {
		return err
	}
	info, err := os.Lstat(file)
	if err != nil {
		return err
	}
	if !withdrawalOrdinary(info) || info.Size() > 131072 || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		return errors.New("Protected account record unavailable")
	}
	return readEncrypted(file, output)
}
func (s *server) accountWrite(file string, value any) error {
	if err := withdrawalAncestors(s.data, filepath.Dir(file), true); err != nil {
		return err
	}
	if info, err := os.Lstat(file); err == nil && !withdrawalOrdinary(info) || err != nil && !os.IsNotExist(err) {
		return errors.New("Ambiguous account retention file")
	}
	key, err := vaultKey()
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	plain, err := json.Marshal(value)
	if err != nil || len(plain) > 100000 {
		return errors.New("Bounded account intent unavailable")
	}
	sealed := a.Seal(nonce, nonce, plain, []byte(filepath.Base(file)))
	tmp, err := os.CreateTemp(filepath.Dir(file), ".account-")
	if err != nil {
		return err
	}
	temporary := tmp.Name()
	defer os.Remove(temporary)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(sealed)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporary, file); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		root, _ := filepath.Abs(s.data)
		for current := filepath.Dir(file); ; current = filepath.Dir(current) {
			directory, e := os.Open(current)
			if e != nil {
				return e
			}
			e = directory.Sync()
			closed := directory.Close()
			if e != nil {
				return e
			}
			if closed != nil {
				return closed
			}
			if current == root {
				break
			}
		}
	}
	var check any
	if err := s.accountRead(file, &check); err != nil || accessHash(check) != accessHash(value) {
		return errors.New("Account intent readback unavailable")
	}
	return nil
}
func (s *server) accountCreation(a accessIdentity, target accountTarget) (accessReceipt, error) {
	var receipt accessReceipt
	file := s.accessReceiptPath(target.CreationOperationID)
	if !validAccountTarget(target) || withdrawalAncestors(s.data, filepath.Dir(file), false) != nil {
		return receipt, errors.New("Protected original account creation unavailable")
	}
	info, err := os.Lstat(file)
	if err != nil || !withdrawalOrdinary(info) || info.Size() > 131072 {
		return receipt, errors.New("Ordinary original account receipt unavailable")
	}
	if !validAccountTarget(target) || readBoundedJSON(s.accessReceiptPath(target.CreationOperationID), &receipt) != nil || receipt.Request.Invitation == nil || receipt.Request.Password != "" || receipt.Result.Status != "succeeded" || receipt.Result.Action != "invitation" || receipt.Result.AppID != target.AppID || receipt.Result.OperationID != target.CreationOperationID || receipt.Result.UserID != target.UserID || receipt.Result.InvitationID != target.InvitationID || receipt.Request.OperationID != target.CreationOperationID || receipt.Request.Invitation.ID != target.InvitationID || receipt.Request.Invitation.AppID != target.AppID || receipt.Realm != a.realm || receipt.ClientID != a.clientID || receipt.Result.Hash != accessActionHash(receipt.Request) || receipt.Result.Hash != receipt.Request.Approval.Hash || validAccessApproval(receipt.Request, "invitation") != nil {
		return receipt, errors.New("Original independently owned local account creation unavailable")
	}
	return receipt, nil
}
func (a accessIdentity) accountUser(ctx context.Context, target accountTarget, creation accessReceipt) (accountUser, []kcRole, error) {
	var u accountUser
	var roles []kcRole
	_, err := identityGET(ctx, a.client, a.endpoint("/users/"+target.UserID), a.token, &u, false)
	v := creation.Request.Invitation
	if err != nil || v == nil || u.ID != target.UserID || u.Username != v.Email || u.Email != v.Email || u.Enabled == nil || u.EmailVerified == nil || u.NotBefore == nil || *u.NotBefore < 0 || *u.NotBefore > time.Now().Unix()+10 || u.FederationLink != nil && *u.FederationLink != "" || !accessAttrEqual(u.Attributes, "autosoft.app-id", target.AppID) || !accessAttrEqual(u.Attributes, "autosoft.invitation-id", target.InvitationID) || !accessAttrEqual(u.Attributes, "autosoft.operation-id", target.CreationOperationID) {
		return u, roles, errors.New("Local user ownership changed or is ambiguous")
	}
	var federations []json.RawMessage
	if _, err = identityGET(ctx, a.client, a.endpoint("/users/"+u.ID+"/federated-identity"), a.token, &federations, false); err != nil || federations == nil || len(federations) != 0 {
		return u, roles, errors.New("Federated account offboarding is unsupported")
	}
	if _, err = identityGET(ctx, a.client, a.endpoint("/users/"+u.ID+"/role-mappings/clients/"+a.clientID), a.token, &roles, false); err != nil || roles == nil || len(roles) > 50 {
		return u, roles, errors.New("Exact local role evidence unavailable")
	}
	seen := map[string]bool{}
	for _, role := range roles {
		id := strings.TrimPrefix(role.Name, "autosoft-role-")
		if !accessUUID.MatchString(id) || seen[id] || role.Name != accessRoleName(id) || !role.ClientRole || role.ContainerID != a.clientID || !ownedAccessRole(role, target.AppID, id) {
			return u, roles, changedIdentityPolicy
		}
		seen[id] = true
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
	var credentials []struct {
		Type string `json:"type"`
	}
	if _, err = identityGET(ctx, a.client, a.endpoint("/users/"+u.ID+"/credentials"), a.token, &credentials, false); err != nil || len(credentials) > 20 {
		return u, roles, errors.New("Local credential type evidence unavailable")
	}
	hasPassword := false
	for _, value := range credentials {
		hasPassword = hasPassword || value.Type == "password"
	}
	if !hasPassword {
		return u, roles, errors.New("Original local password account unavailable")
	}
	return u, roles, nil
}
func tokenPolicyLimit(realm, implicit int, clients []accountClient, appID, ownedClientID string) (int, string, error) {
	if realm < 1 || realm > 86400 || implicit < 1 || implicit > 86400 || clients == nil || len(clients) < 2 || len(clients) > 128 {
		return 0, "", errors.New("Bounded token lifetime evidence unavailable")
	}
	limit := realm
	if implicit > limit {
		limit = implicit
	}
	ids, names := map[string]bool{}, map[string]bool{}
	app, mcp := false, false
	projected := make([]accountClient, 0, len(clients))
	for _, client := range clients {
		if !identity.MatchString(client.ID) || client.ClientID == "" || len(client.ClientID) > 128 || ids[client.ID] || names[client.ClientID] || client.Protocol != "openid-connect" && client.Protocol != "saml" {
			return 0, "", errors.New("Ambiguous realm client lifetime evidence")
		}
		ids[client.ID], names[client.ClientID] = true, true
		app = app || client.ID == ownedClientID && client.ClientID == "app-"+appID
		mcp = mcp || client.ClientID == appID+":mcp"
		override, exists := client.Attributes["access.token.lifespan"]
		attrs := map[string]string{}
		if exists {
			attrs["access.token.lifespan"] = override
			if override != "" {
				n, e := strconv.Atoi(override)
				if e != nil || strconv.Itoa(n) != override || n < 1 || n > 86400 {
					return 0, "", errors.New("Unbounded or malformed client token lifetime")
				}
				if n > limit {
					limit = n
				}
			}
		}
		projected = append(projected, accountClient{ID: client.ID, ClientID: client.ClientID, Protocol: client.Protocol, Implicit: client.Implicit, Attributes: attrs})
	}
	if !app || !mcp {
		return 0, "", errors.New("Exact app and MCP lifetime evidence unavailable")
	}
	sort.Slice(projected, func(i, j int) bool { return projected[i].ID < projected[j].ID })
	return limit, accessHash(accountTokenPolicy{realm, implicit, projected}), nil
}
func (a accessIdentity) accountTokenPolicy(ctx context.Context, appID, userID string) (int, string, error) {
	var realm struct {
		Realm      string            `json:"realm"`
		Attributes map[string]string `json:"attributes"`
		Lifespan   *int              `json:"accessTokenLifespan"`
		Implicit   *int              `json:"accessTokenLifespanForImplicitFlow"`
	}
	if _, err := identityGET(ctx, a.client, a.endpoint(""), a.token, &realm, false); err != nil || realm.Realm != a.realm || !matchingIdentityMarkers(realm.Attributes, appID, a.realm, a.snapshot.IdentityHash) || realm.Lifespan == nil || realm.Implicit == nil {
		return 0, "", errors.New("Owned realm token lifetime unavailable")
	}
	var clients []accountClient
	if _, err := identityGET(ctx, a.client, a.endpoint("/clients?first=0&max=129"), a.token, &clients, false); err != nil {
		return 0, "", err
	}
	limit, hash, err := tokenPolicyLimit(*realm.Lifespan, *realm.Implicit, clients, appID, a.clientID)
	if err != nil {
		return 0, "", err
	}
	for _, client := range clients {
		var offline []json.RawMessage
		if _, err := identityGET(ctx, a.client, a.endpoint("/users/"+userID+"/offline-sessions/"+client.ID), a.token, &offline, false); err != nil || offline == nil || len(offline) != 0 {
			return 0, "", errors.New("Offline session offboarding is unsupported or unconfirmed")
		}
	}
	return limit, hash, nil
}
func accountUserHash(u accountUser, roles []kcRole) string {
	return accessHash(map[string]any{"user": u, "roles": roles})
}
func (s *server) inspectAccount(ctx context.Context, target accountTarget) (accessIdentity, accountSnapshot, accountUser, error) {
	a, err := s.accessContext(ctx, target.AppID)
	var q accountSnapshot
	var u accountUser
	if err != nil || a.verifyRoles(ctx, a.snapshot.Policy) != nil {
		return a, q, u, errors.New("Published owned app policy unavailable")
	}
	creation, err := s.accountCreation(a, target)
	if err != nil {
		return a, q, u, err
	}
	u, roles, err := a.accountUser(ctx, target, creation)
	if err != nil {
		return a, q, u, err
	}
	limit, tokenHash, err := a.accountTokenPolicy(ctx, target.AppID, target.UserID)
	if err != nil {
		return a, q, u, err
	}
	q = accountSnapshot{accountTarget: target, Version: 1, ReleaseID: a.snapshot.ReleaseID, IdentityHash: a.snapshot.IdentityHash, PolicyHash: a.snapshot.PolicyHash, Realm: a.realm, ClientID: a.clientID, Username: u.Username, Email: u.Email, Enabled: *u.Enabled, UserEvidenceHash: accountUserHash(u, roles), TokenPolicyHash: tokenHash, TokenLifespan: limit, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	return a, q, u, nil
}
func (s *server) accountSnapshot(w http.ResponseWriter, r *http.Request) {
	var in accountTarget
	if !decode(w, r, &in) {
		return
	}
	if !validAccountTarget(in) {
		accessReject(w, 400, "Exact accepted app account identity required")
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, q, _, err := s.inspectAccount(ctx, in)
	if err != nil {
		accessReject(w, 503, "Protected local account and current token lifetime evidence unavailable")
		return
	}
	respond(w, q)
}
func (s *server) verifyDisabledAccount(ctx context.Context, receipt accountReceipt) (bool, error) {
	in := receipt.Request
	a, q, u, err := s.inspectAccount(ctx, in.Approval.Snapshot.accountTarget)
	if err != nil {
		return false, err
	}
	old := in.Approval.Snapshot
	start, err := time.Parse(time.RFC3339, receipt.StartedAt)
	if err != nil || q.Enabled || q.ReleaseID != old.ReleaseID || q.IdentityHash != old.IdentityHash || q.PolicyHash != old.PolicyHash || q.Realm != old.Realm || q.ClientID != old.ClientID || q.TokenPolicyHash != old.TokenPolicyHash || q.TokenLifespan != old.TokenLifespan || *u.NotBefore < start.Unix() {
		return false, errors.New("Disabled account state is not exactly confirmed")
	}
	// Only the two intended user properties may differ; role membership and all
	// other attributes/actions remain bound to the original reviewed projection.
	creation, err := s.accountCreation(a, q.accountTarget)
	if err != nil {
		return false, err
	}
	var baseline accountUser
	// The hash of a user with its original notBefore is checked using the
	// separately retained original projection, never guessed from current state.
	if err = s.accountRead(s.accountPath("baselines", in.OperationID), &baseline); err != nil {
		return false, err
	}
	var sessions []json.RawMessage
	if _, err = identityGET(ctx, a.client, a.endpoint("/users/"+q.UserID+"/sessions"), a.token, &sessions, false); err != nil || sessions == nil || len(sessions) != 0 {
		return false, errors.New("Account online sessions remain or are unavailable")
	}
	final, roles, err := a.accountUser(ctx, q.accountTarget, creation)
	if err != nil || *final.Enabled || *final.NotBefore < start.Unix() {
		return false, errors.New("Disabled account changed during confirmation")
	}
	enabled := true
	final.Enabled = &enabled
	final.NotBefore = baseline.NotBefore
	if accountUserHash(final, roles) != old.UserEvidenceHash {
		return false, errors.New("Account metadata or role evidence changed")
	}
	return true, nil
}
func (s *server) disableAppAccount(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	var in accountDisableRequest
	if err != nil || !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		accessReject(w, 403, "Exact signed account review required")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || validAccountRequest(in, false) != nil {
		accessReject(w, 409, "Exact consumed owner account review required")
		return
	}
	unlockApproval := s.lock("account-approval-" + in.Approval.ID)
	defer unlockApproval()
	unlock := s.lock("app-" + in.Approval.AppID)
	defer unlock()
	path := s.accountPath("operations", in.OperationID)
	var prior accountReceipt
	err = s.accountRead(path, &prior)
	if err == nil {
		if !reflect.DeepEqual(prior.Request, in) {
			accessReject(w, 409, "Account operation identity already used")
			return
		}
		respond(w, prior.Status)
		return
	}
	if !os.IsNotExist(err) || validAccountRequest(in, true) != nil {
		accessReject(w, 409, "Account intent is unavailable or approval expired")
		return
	}
	var used accountOperationIdentity
	if err = s.accountRead(s.accountPath("approvals", in.Approval.ID), &used); !os.IsNotExist(err) {
		accessReject(w, 409, "Account approval already dispatched; inspect its original operation")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	a, q, u, err := s.inspectAccount(ctx, in.Approval.Snapshot.accountTarget)
	if err != nil || accountArtifactHash(q) != in.Approval.Hash || !q.Enabled {
		accessReject(w, 409, "The owned account, release, policy or token lifetime changed")
		return
	}
	pendingPath := s.accountPath("pending", q.AppID+"-"+q.UserID)
	var pending accountOperationIdentity
	if err = s.accountRead(pendingPath, &pending); !os.IsNotExist(err) {
		accessReject(w, 409, "An original account operation needs confirmation")
		return
	}
	id := accountID(in)
	now := time.Now().UTC().Format(time.RFC3339)
	receipt := accountReceipt{Request: in, StartedAt: now, Status: accountStatus{accountOperationIdentity: id, Status: "pending", CheckedAt: now, Detail: "Exact local account disablement awaits read-only confirmation."}}
	// Every file is encrypted, synced and read back before the first remote write.
	if s.accountWrite(s.accountPath("baselines", in.OperationID), u) != nil || s.accountWrite(s.accountPath("approvals", in.Approval.ID), id) != nil || s.accountWrite(path, receipt) != nil || s.accountWrite(pendingPath, id) != nil {
		accessReject(w, 503, "Unable to retain exact single-use account intent; no account mutation attempted")
		return
	}
	if err = a.write(ctx, "PUT", a.endpoint("/users/"+q.UserID), map[string]bool{"enabled": false}, false); err != nil {
		fail(w, 503, errors.New("Account mutation outcome is uncertain; inspect original operation without replay"))
		return
	}
	// Reinspect ownership immediately before the second exact scoped mutation.
	creation, err := s.accountCreation(a, q.accountTarget)
	if err == nil {
		var current accountUser
		var roles []kcRole
		current, roles, err = a.accountUser(ctx, q.accountTarget, creation)
		if err == nil {
			if *current.Enabled {
				err = errors.New("Account disablement not confirmed")
			} else {
				yes := true
				current.Enabled = &yes
				if accountUserHash(current, roles) != q.UserEvidenceHash {
					err = errors.New("Account changed before logout")
				}
			}
		}
	}
	if err != nil {
		fail(w, 503, errors.New("Disabled account ownership requires protected inspection"))
		return
	}
	if err = a.write(ctx, "POST", a.endpoint("/users/"+q.UserID+"/logout"), map[string]any{}, false); err != nil {
		fail(w, 503, errors.New("Account logout outcome awaits read-only confirmation"))
		return
	}
	if okay, _ := s.verifyDisabledAccount(ctx, receipt); okay {
		receipt.Status.Status = "disabled"
		receipt.Status.Detail = "Exact local account disabled; online sessions are absent. Issued tokens retain their own expiry."
	}
	receipt.Status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	if s.accountWrite(path, receipt) != nil {
		fail(w, 503, errors.New("Account confirmation could not be retained"))
		return
	}
	respond(w, receipt.Status)
}
func (s *server) accountOperation(w http.ResponseWriter, r *http.Request) {
	var in accountOperationIdentity
	if !decode(w, r, &in) {
		return
	}
	if !accessUUID.MatchString(in.OperationID) || !accessUUID.MatchString(in.ApprovalID) || !accessUUID.MatchString(in.AppID) || !accessUUID.MatchString(in.InvitationID) || !accessUUID.MatchString(in.UserID) || !accessHex.MatchString(in.Hash) {
		fail(w, 400, errors.New("Exact account operation identity required"))
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	var receipt accountReceipt
	err := s.accountRead(s.accountPath("operations", in.OperationID), &receipt)
	if os.IsNotExist(err) {
		respond(w, accountStatus{accountOperationIdentity: in, Status: "unknown", CheckedAt: time.Now().UTC().Format(time.RFC3339), Detail: "The original account operation is unavailable; no mutation was attempted by inspection."})
		return
	}
	if err != nil || accountID(receipt.Request) != in || receipt.Status.accountOperationIdentity != in || validAccountRequest(receipt.Request, false) != nil {
		fail(w, 409, errors.New("Account operation binding unavailable"))
		return
	}
	var used, pending accountOperationIdentity
	if s.accountRead(s.accountPath("approvals", in.ApprovalID), &used) != nil || used != in || s.accountRead(s.accountPath("pending", in.AppID+"-"+in.UserID), &pending) != nil || pending != in {
		fail(w, 503, errors.New("Original single-use account approval or pending binding requires inspection"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	receipt.Status.Status = "pending"
	receipt.Status.Detail = "Current exact disabled account/session evidence is unavailable. No mutation was retried."
	if okay, _ := s.verifyDisabledAccount(ctx, receipt); okay {
		receipt.Status.Status = "disabled"
		receipt.Status.Detail = "Exact local account disabled; online sessions are absent. Issued tokens retain their own expiry."
	}
	receipt.Status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	if s.accountWrite(s.accountPath("operations", in.OperationID), receipt) != nil {
		fail(w, 503, errors.New("Account readback evidence could not be retained"))
		return
	}
	// Inspection never calls PUT, POST, DELETE or any identity mutation.
	respond(w, receipt.Status)
}
func registerAppAccountRoutes(mux *http.ServeMux, s *server) {
	mux.HandleFunc("/v1/accounts/snapshot", s.authenticated(s.accountSnapshot))
	mux.HandleFunc("/v1/accounts/disable", s.authenticated(s.disableAppAccount))
	mux.HandleFunc("/v1/accounts/operation", s.authenticated(s.accountOperation))
}
