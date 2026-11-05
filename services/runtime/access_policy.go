package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

type appAccessRole struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}
type appGroupMapping struct {
	Provider     string   `json:"provider"`
	TenantID     string   `json:"tenantId"`
	GroupID      string   `json:"groupId"`
	ConnectionID string   `json:"connectionId"`
	RoleIDs      []string `json:"roleIds"`
	Status       string   `json:"status"`
}
type appAccessPolicy struct {
	Version            int               `json:"schemaVersion"`
	AppID              string            `json:"appId"`
	InvitationsEnabled bool              `json:"invitationsEnabled"`
	RequireTOTP        bool              `json:"requireTotp"`
	Roles              []appAccessRole   `json:"roles"`
	GroupMappings      []appGroupMapping `json:"groupMappings"`
}
type appAccessSnapshot struct {
	AppID        string          `json:"appId"`
	ReleaseID    string          `json:"releaseId"`
	IdentityHash string          `json:"identityHash"`
	PolicyHash   string          `json:"policyHash"`
	Permissions  []string        `json:"permissions"`
	Policy       appAccessPolicy `json:"policy"`
	CheckedAt    string          `json:"checkedAt"`
}
type accessApproval struct {
	ID         string   `json:"id"`
	AppID      string   `json:"appId"`
	Action     string   `json:"action"`
	Hash       string   `json:"artifactHash"`
	BaseHash   string   `json:"basePolicyHash"`
	Impact     []string `json:"impact"`
	ExpiresAt  string   `json:"expiresAt"`
	ApprovedBy string   `json:"approvedBy"`
	ApprovedAt string   `json:"approvedAt"`
	ConsumedAt string   `json:"consumedAt"`
}
type accessActor struct {
	ID  string `json:"id"`
	MFA bool   `json:"mfa"`
}
type appInvitation struct {
	ID         string   `json:"id"`
	AppID      string   `json:"appId"`
	Email      string   `json:"email"`
	RoleIDs    []string `json:"roleIds"`
	PolicyHash string   `json:"policyHash"`
	ExpiresAt  string   `json:"expiresAt"`
	CreatedBy  string   `json:"createdBy"`
	CreatedAt  string   `json:"createdAt"`
	ApprovalID string   `json:"approvalId"`
}
type accessRequest struct {
	OperationID string           `json:"operationId"`
	AppID       string           `json:"appId,omitempty"`
	BaseHash    string           `json:"basePolicyHash,omitempty"`
	Policy      *appAccessPolicy `json:"policy,omitempty"`
	Invitation  *appInvitation   `json:"invitation,omitempty"`
	Approval    accessApproval   `json:"approval"`
	Principal   accessActor      `json:"principal"`
	Password    string           `json:"password,omitempty"`
}
type accessResult struct {
	OperationID  string `json:"operationId"`
	AppID        string `json:"appId"`
	Status       string `json:"status"`
	Action       string `json:"action,omitempty"`
	Hash         string `json:"artifactHash,omitempty"`
	PolicyHash   string `json:"policyHash,omitempty"`
	InvitationID string `json:"invitationId,omitempty"`
	UserID       string `json:"userId,omitempty"`
	Detail       string `json:"detail,omitempty"`
}
type accessReceipt struct {
	Result    accessResult  `json:"result"`
	Request   accessRequest `json:"request"`
	Realm     string        `json:"realm"`
	ClientID  string        `json:"clientId"`
	CreatedAt string        `json:"createdAt"`
}
type kcRole struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	ClientRole  bool                `json:"clientRole"`
	ContainerID string              `json:"containerId"`
	Composite   bool                `json:"composite"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}
type kcUser struct {
	ID              string              `json:"id"`
	Username        string              `json:"username"`
	Email           string              `json:"email"`
	Enabled         bool                `json:"enabled"`
	EmailVerified   bool                `json:"emailVerified"`
	Attributes      map[string][]string `json:"attributes"`
	RequiredActions []string            `json:"requiredActions"`
}
type accessIdentity struct {
	client   *http.Client
	base     string
	token    string
	realm    string
	clientID string
	snapshot appAccessSnapshot
}

var accessUUID = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var accessHex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var accessPermission = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,79}$`)

// Sorting every object recursively matches the control hashArtifact projection;
// no password, password hash or invitation token enters this durable digest.
func accessHash(value any) string {
	b, _ := json.Marshal(value)
	var normalized any
	_ = json.Unmarshal(b, &normalized)
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(normalized)
	return hashBytes(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))
}
func accessActionHash(in accessRequest) string {
	if in.Policy != nil {
		return accessHash(map[string]any{"action": "access_policy", "appId": in.AppID, "basePolicyHash": in.BaseHash, "policy": in.Policy})
	}
	return accessHash(map[string]any{"action": "invitation", "invitation": in.Invitation})
}
func accessRoleName(id string) string { return "autosoft-role-" + id }
func accessAttrs(appID, id string) map[string][]string {
	return map[string][]string{"autosoft.app-id": {appID}, "autosoft.role-id": {id}}
}
func accessAttrEqual(attrs map[string][]string, key, value string) bool {
	return len(attrs[key]) == 1 && attrs[key][0] == value
}
func validAccessPolicy(p appAccessPolicy, permissions []string, appID string) error {
	if p.Version != 1 || p.AppID != appID || !p.RequireTOTP || len(p.Roles) > 50 || len(p.GroupMappings) > 50 || p.Roles == nil || p.GroupMappings == nil {
		return errors.New("Invalid bounded app policy; authenticator enrollment is mandatory")
	}
	leaves, ids, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range permissions {
		if !accessPermission.MatchString(v) || leaves[v] {
			return changedIdentityPolicy
		}
		leaves[v] = true
	}
	for _, role := range p.Roles {
		if !accessUUID.MatchString(role.ID) || strings.TrimSpace(role.Name) == "" || len(role.Name) > 80 || strings.ContainsAny(role.Name, "\x00\r\n\u2028\u2029") || ids[role.ID] || names[strings.ToLower(role.Name)] || len(role.Permissions) < 1 || len(role.Permissions) > 100 {
			return errors.New("App roles require unique immutable IDs, names and existing protected permissions")
		}
		ids[role.ID], names[strings.ToLower(role.Name)] = true, true
		seen := map[string]bool{}
		for _, name := range role.Permissions {
			if !leaves[name] || seen[name] {
				return errors.New("A role cannot grant permissions outside its protected app")
			}
			seen[name] = true
		}
	}
	groups := map[string]bool{}
	for _, g := range p.GroupMappings {
		key := g.Provider + ":" + g.TenantID + ":" + g.GroupID
		if (g.Provider != "microsoft" && g.Provider != "google") || g.Status != "pending_validation" || !accessUUID.MatchString(g.ConnectionID) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(g.TenantID) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(g.GroupID) || (g.Provider == "microsoft" && (!accessUUID.MatchString(g.TenantID) || !accessUUID.MatchString(g.GroupID))) || groups[key] || len(g.RoleIDs) < 1 || len(g.RoleIDs) > 50 {
			return errors.New("Group mappings require immutable IDs and remain inactive without a verified resolver")
		}
		groups[key] = true
		seen := map[string]bool{}
		for _, id := range g.RoleIDs {
			if !ids[id] || seen[id] {
				return errors.New("Group draft references an unknown role")
			}
			seen[id] = true
		}
	}
	return nil
}
func validAccessApproval(in accessRequest, action string) error {
	a := in.Approval
	appID := in.AppID
	if in.Invitation != nil {
		appID = in.Invitation.AppID
	}
	approved, e1 := time.Parse(time.RFC3339, a.ApprovedAt)
	expiry, e2 := time.Parse(time.RFC3339, a.ExpiresAt)
	consumed, e3 := time.Parse(time.RFC3339, a.ConsumedAt)
	if !identity.MatchString(in.OperationID) || !accessUUID.MatchString(appID) || !accessUUID.MatchString(a.ID) || a.AppID != appID || a.Action != action || a.Hash != accessActionHash(in) || !accessHex.MatchString(a.BaseHash) || !in.Principal.MFA || in.Principal.ID == "" || in.Principal.ID != a.ApprovedBy || e1 != nil || e2 != nil || e3 != nil || approved.After(time.Now().Add(time.Minute)) || consumed.Before(approved) || consumed.After(expiry) || expiry.Sub(approved) > 31*time.Minute {
		return errors.New("Exact consumed MFA app access approval is required")
	}
	if action == "access_policy" && (!expiry.After(time.Now()) || in.BaseHash != a.BaseHash) {
		return errors.New("App access approval expired or changed baseline")
	}
	return nil
}
func (s *server) accessContext(ctx context.Context, appID string) (accessIdentity, error) {
	var out accessIdentity
	if !accessUUID.MatchString(appID) {
		return out, errors.New("Invalid app identity")
	}
	var active activeDeployment
	if readBoundedJSON(filepath.Join(s.data, "active", appID+".json"), &active) != nil || !identity.MatchString(active.OperationID) {
		return out, errors.New("A confirmed published app is required for account management")
	}
	_, _, m, err := s.publicationReceipt(observationRequest{ID: "access-inspection", AppID: appID, ReleaseID: active.ReleaseID, Hash: active.Hash, Images: []string{active.Image}, OperationID: active.OperationID})
	if err != nil {
		return out, err
	}
	realm := "app-" + hashBytes([]byte(appID))[:24]
	var baseline identityPolicyState
	if readEncrypted(filepath.Join(s.data, "identity-policies", realm+".enc"), &baseline) != nil || baseline.AppID != appID || baseline.Realm != realm || !accessHex.MatchString(baseline.Hash) {
		return out, changedIdentityPolicy
	}
	client, err := internalClient(os.Getenv("KEYCLOAK_CA_FILE"))
	if err != nil {
		return out, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base := env("KEYCLOAK_INTERNAL_URL", "https://keycloak:8443")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return out, errors.New("Identity authority must be exact verified HTTPS")
	}
	tokenRealm := env("KEYCLOAK_PROVISIONER_REALM", "master")
	if !identity.MatchString(tokenRealm) {
		return out, errors.New("Invalid identity provisioner realm")
	}
	credential, err := secret("KEYCLOAK_CLIENT_SECRET")
	if err != nil {
		return out, err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {env("KEYCLOAK_CLIENT_ID", "autosoft-provisioner")}, "client_secret": {credential}}
	request, _ := http.NewRequestWithContext(ctx, "POST", base+"/realms/"+tokenRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return out, errors.New("Identity provisioner unavailable")
	}
	defer response.Body.Close()
	var tokens struct {
		Token string `json:"access_token"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&tokens) != nil || tokens.Token == "" {
		return out, errors.New("Identity provisioner unavailable")
	}
	if _, err = ownedIdentityRealm(ctx, client, base, tokens.Token, realm, appID, baseline.Hash, false); err != nil {
		return out, err
	}
	var clients []struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	if _, err = identityGET(ctx, client, base+"/admin/realms/"+realm+"/clients?clientId="+url.QueryEscape("app-"+appID), tokens.Token, &clients, false); err != nil || len(clients) != 1 || !identity.MatchString(clients[0].ID) || clients[0].ClientID != "app-"+appID {
		return out, errors.New("Exact owned app client unavailable")
	}
	policy := appAccessPolicy{Version: 1, AppID: appID, InvitationsEnabled: m.Auth == "local", RequireTOTP: true, Roles: []appAccessRole{}, GroupMappings: []appGroupMapping{}}
	err = readEncrypted(filepath.Join(s.data, "access-policies", appID+".enc"), &policy)
	if err != nil && !os.IsNotExist(err) {
		return out, errors.New("Protected access policy unavailable")
	}
	if err = validAccessPolicy(policy, m.Permissions, appID); err != nil {
		return out, err
	}
	out = accessIdentity{client: client, base: base, token: tokens.Token, realm: realm, clientID: clients[0].ID, snapshot: appAccessSnapshot{AppID: appID, ReleaseID: active.ReleaseID, IdentityHash: baseline.Hash, PolicyHash: accessHash(policy), Permissions: append([]string{}, m.Permissions...), Policy: policy, CheckedAt: time.Now().UTC().Format(time.RFC3339)}}
	return out, nil
}
func (a accessIdentity) endpoint(suffix string) string {
	return a.base + "/admin/realms/" + url.PathEscape(a.realm) + suffix
}
func (a accessIdentity) write(ctx context.Context, method, address string, value any, allowConflict bool) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(request)
	if err != nil {
		return errors.New("Identity mutation has an uncertain outcome; inspect its retained operation")
	}
	defer response.Body.Close()
	if response.StatusCode != 201 && response.StatusCode != 204 && !(allowConflict && response.StatusCode == 409) {
		return errors.New("Identity service rejected the scoped mutation; inspect its retained operation")
	}
	return nil
}
func (a accessIdentity) getRole(ctx context.Context, name string, allowMissing bool) (kcRole, bool, error) {
	var role kcRole
	found, err := identityGET(ctx, a.client, a.endpoint("/clients/"+a.clientID+"/roles/"+url.PathEscape(name)), a.token, &role, allowMissing)
	if err != nil || !found {
		return role, found, err
	}
	if role.Name != name || !identity.MatchString(role.ID) || !role.ClientRole || role.ContainerID != a.clientID {
		return role, false, changedIdentityPolicy
	}
	return role, true, nil
}
func (a accessIdentity) compositeRoles(ctx context.Context, role kcRole) ([]kcRole, error) {
	var roles []kcRole
	_, err := identityGET(ctx, a.client, a.endpoint("/clients/"+a.clientID+"/roles/"+url.PathEscape(role.Name)+"/composites"), a.token, &roles, false)
	return roles, err
}
func ownedAccessRole(role kcRole, appID, roleID string) bool {
	return accessAttrEqual(role.Attributes, "autosoft.app-id", appID) && accessAttrEqual(role.Attributes, "autosoft.role-id", roleID)
}
func (a accessIdentity) verifyRoles(ctx context.Context, policy appAccessPolicy) error {
	for _, desired := range policy.Roles {
		role, found, err := a.getRole(ctx, accessRoleName(desired.ID), false)
		if err != nil || !found || !ownedAccessRole(role, policy.AppID, desired.ID) {
			return changedIdentityPolicy
		}
		children, err := a.compositeRoles(ctx, role)
		if err != nil {
			return err
		}
		names := []string{}
		for _, child := range children {
			if child.ContainerID != a.clientID || !child.ClientRole || child.Composite {
				return changedIdentityPolicy
			}
			names = append(names, child.Name)
		}
		want := append([]string{}, desired.Permissions...)
		sort.Strings(want)
		sort.Strings(names)
		if !reflect.DeepEqual(want, names) {
			return changedIdentityPolicy
		}
	}
	return nil
}
func (a accessIdentity) verifyPolicyTransition(ctx context.Context, previous, proposed appAccessPolicy) error {
	if err := a.verifyRoles(ctx, proposed); err != nil {
		return err
	}
	for _, old := range previous.Roles {
		retained := false
		for _, next := range proposed.Roles {
			retained = retained || old.ID == next.ID
		}
		if retained {
			continue
		}
		role, found, err := a.getRole(ctx, accessRoleName(old.ID), false)
		if err != nil || !found || !ownedAccessRole(role, previous.AppID, old.ID) {
			return changedIdentityPolicy
		}
		children, err := a.compositeRoles(ctx, role)
		if err != nil || len(children) != 0 {
			return changedIdentityPolicy
		}
	}
	return nil
}
func writeAccessPolicy(file string, value any) error {
	if err := writeEncrypted(file, value); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	err = f.Sync()
	_ = f.Close()
	if err != nil {
		return err
	}
	if os.PathSeparator == '/' {
		d, err := os.Open(filepath.Dir(file))
		if err != nil {
			return err
		}
		err = d.Sync()
		_ = d.Close()
		return err
	}
	return nil
}
func accessReject(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message, "rejectedBeforeExecution": true})
}
func (s *server) accessSnapshot(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AppID string `json:"appId"`
	}
	if !decode(w, r, &input) {
		return
	}
	unlock := s.lock("app-" + input.AppID)
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	a, err := s.accessContext(ctx, input.AppID)
	if err != nil || a.verifyRoles(ctx, a.snapshot.Policy) != nil {
		fail(w, 503, errors.New("Protected owned app access policy unavailable or differs from actual identity roles"))
		return
	}
	respond(w, a.snapshot)
}
func (s *server) signedAccess(w http.ResponseWriter, r *http.Request) (accessRequest, bool) {
	var in accessRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if err != nil || !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		accessReject(w, 403, "Exact signed app access action required")
		return in, false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		accessReject(w, 400, "Invalid bounded app access request")
		return in, false
	}
	return in, true
}
func (s *server) accessReceiptPath(id string) string {
	return filepath.Join(s.data, "access-operations", id+".json")
}
func (s *server) pendingAccessPolicy(appID string) error {
	var pending struct {
		OperationID string `json:"operationId"`
	}
	path := filepath.Join(s.data, "access-pending", appID+".json")
	err := readBoundedJSON(path, &pending)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !identity.MatchString(pending.OperationID) {
		return errors.New("Protected pending policy operation unavailable")
	}
	var receipt accessReceipt
	if readBoundedJSON(s.accessReceiptPath(pending.OperationID), &receipt) != nil || receipt.Result.AppID != appID || receipt.Result.Status == "running" {
		return errors.New("A retained policy operation requires confirmation before another policy change")
	}
	return os.Remove(path)
}
func (s *server) existingAccess(w http.ResponseWriter, in accessRequest) (bool, error) {
	var receipt accessReceipt
	err := readBoundedJSON(s.accessReceiptPath(in.OperationID), &receipt)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if receipt.Result.Hash != accessActionHash(in) || receipt.Request.Approval.ID != in.Approval.ID || receipt.Request.Principal.ID != in.Principal.ID || !reflect.DeepEqual(receipt.Request.Approval, in.Approval) || receipt.Result.AppID != in.AppID && in.Invitation == nil || in.Invitation != nil && receipt.Result.AppID != in.Invitation.AppID {
		return true, errors.New("Access operation identity was already used")
	}
	respond(w, receipt.Result)
	return true, nil
}
func (s *server) unusedAccessApproval(in accessRequest) error {
	var used struct {
		OperationID string `json:"operationId"`
		Hash        string `json:"artifactHash"`
	}
	err := readBoundedJSON(filepath.Join(s.data, "access-used-approvals", in.Approval.ID+".json"), &used)
	if os.IsNotExist(err) {
		return nil
	}
	return errors.New("This exact app identity approval was already dispatched; inspect its original operation")
}
func (s *server) retainAccessApproval(in accessRequest) error {
	return atomicJSON(filepath.Join(s.data, "access-used-approvals", in.Approval.ID+".json"), map[string]string{"operationId": in.OperationID, "artifactHash": in.Approval.Hash})
}
func (s *server) applyAccessPolicy(w http.ResponseWriter, r *http.Request) {
	in, ok := s.signedAccess(w, r)
	if !ok {
		return
	}
	if in.Policy == nil || in.Invitation != nil || in.Password != "" || validAccessApproval(in, "access_policy") != nil {
		accessReject(w, 409, "Exact reviewed app policy approval required")
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	if exists, err := s.existingAccess(w, in); exists {
		if err != nil {
			accessReject(w, 409, "Access operation identity mismatch")
		}
		return
	}
	if s.pendingAccessPolicy(in.AppID) != nil {
		accessReject(w, 409, "A previous app policy operation is awaiting confirmation")
		return
	}
	if s.unusedAccessApproval(in) != nil {
		accessReject(w, 409, "This app identity approval was already dispatched")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	a, err := s.accessContext(ctx, in.AppID)
	if err != nil || a.snapshot.PolicyHash != in.BaseHash || validAccessPolicy(*in.Policy, a.snapshot.Permissions, in.AppID) != nil || a.verifyRoles(ctx, a.snapshot.Policy) != nil {
		accessReject(w, 409, "Protected app policy baseline or permission scope changed")
		return
	}
	receipt := accessReceipt{Result: accessResult{OperationID: in.OperationID, AppID: in.AppID, Status: "running", Action: "access_policy", Hash: in.Approval.Hash}, Request: in, Realm: a.realm, ClientID: a.clientID, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if atomicJSON(filepath.Join(s.data, "access-pending", in.AppID+".json"), map[string]string{"operationId": in.OperationID}) != nil {
		accessReject(w, 503, "Unable to retain pending app policy lock")
		return
	}
	if s.retainAccessApproval(in) != nil {
		accessReject(w, 503, "Unable to retain single-use identity approval")
		return
	}
	if err = atomicJSON(s.accessReceiptPath(in.OperationID), receipt); err != nil {
		accessReject(w, 503, "Unable to retain app access intent")
		return
	}
	// Existing and removed composite roles are replaced only after ownership checks.
	all := map[string]appAccessRole{}
	for _, role := range a.snapshot.Policy.Roles {
		all[role.ID] = appAccessRole{ID: role.ID, Name: role.Name, Permissions: []string{}}
	}
	for _, role := range in.Policy.Roles {
		all[role.ID] = role
	}
	for _, desired := range all {
		name := accessRoleName(desired.ID)
		role, found, lookupErr := a.getRole(ctx, name, true)
		if lookupErr != nil {
			err = lookupErr
			break
		}
		if !found {
			if len(desired.Permissions) == 0 {
				continue
			}
			err = a.write(ctx, "POST", a.endpoint("/clients/"+a.clientID+"/roles"), map[string]any{"name": name, "description": desired.Name, "composite": true, "attributes": accessAttrs(in.AppID, desired.ID)}, true)
			if err != nil {
				break
			}
			role, found, err = a.getRole(ctx, name, false)
			if err != nil || !found {
				err = changedIdentityPolicy
				break
			}
		}
		if !ownedAccessRole(role, in.AppID, desired.ID) {
			err = changedIdentityPolicy
			break
		}
		children, lookupErr := a.compositeRoles(ctx, role)
		if lookupErr != nil {
			err = lookupErr
			break
		}
		for _, child := range children {
			if child.ContainerID != a.clientID || !child.ClientRole || child.Composite || !containsString(a.snapshot.Permissions, child.Name) {
				err = changedIdentityPolicy
				break
			}
		}
		if err != nil {
			break
		}
		if len(children) > 0 {
			err = a.write(ctx, "DELETE", a.endpoint("/clients/"+a.clientID+"/roles/"+url.PathEscape(name)+"/composites"), children, false)
			if err != nil {
				break
			}
		}
		selected := []kcRole{}
		for _, leaf := range desired.Permissions {
			v, found, lookupErr := a.getRole(ctx, leaf, false)
			if lookupErr != nil || !found || v.Composite {
				err = changedIdentityPolicy
				break
			}
			selected = append(selected, v)
		}
		if err != nil {
			break
		}
		if len(selected) > 0 {
			err = a.write(ctx, "POST", a.endpoint("/clients/"+a.clientID+"/roles/"+url.PathEscape(name)+"/composites"), selected, false)
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		err = a.verifyPolicyTransition(ctx, a.snapshot.Policy, *in.Policy)
	}
	if err == nil {
		err = writeAccessPolicy(filepath.Join(s.data, "access-policies", in.AppID+".enc"), in.Policy)
	}
	if err != nil {
		fail(w, 503, errors.New("App policy mutation is awaiting confirmation; retained operation prevents duplicate changes"))
		return
	}
	receipt.Result.Status = "succeeded"
	receipt.Result.PolicyHash = accessHash(in.Policy)
	if atomicJSON(s.accessReceiptPath(in.OperationID), receipt) != nil {
		fail(w, 503, errors.New("App policy confirmation could not be retained"))
		return
	}
	_ = s.pendingAccessPolicy(in.AppID)
	respond(w, receipt.Result)
}
func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func validInvitation(in accessRequest) error {
	if in.Invitation == nil || in.Policy != nil || in.AppID != "" || validAccessApproval(in, "invitation") != nil {
		return errors.New("Exact consumed invitation approval required")
	}
	v := in.Invitation
	created, e1 := time.Parse(time.RFC3339, v.CreatedAt)
	expires, e2 := time.Parse(time.RFC3339, v.ExpiresAt)
	if !accessUUID.MatchString(v.ID) || v.ApprovalID != in.Approval.ID || v.PolicyHash != in.Approval.BaseHash || !accessHex.MatchString(v.PolicyHash) || v.CreatedBy == "" || len(v.Email) > 254 || !regexp.MustCompile(`^[^\s@\x00-\x1f]+@[^\s@\x00-\x1f]+\.[^\s@\x00-\x1f]+$`).MatchString(v.Email) || strings.ToLower(v.Email) != v.Email || e1 != nil || e2 != nil || created.After(time.Now().Add(time.Minute)) || !expires.After(time.Now()) || expires.Sub(created) > 48*time.Hour+time.Minute || len(v.RoleIDs) < 1 || len(v.RoleIDs) > 50 {
		return errors.New("Invalid or expired scoped invitation")
	}
	seen := map[string]bool{}
	for _, id := range v.RoleIDs {
		if !accessUUID.MatchString(id) || seen[id] {
			return errors.New("Invalid invited app role")
		}
		seen[id] = true
	}
	return nil
}
func (a accessIdentity) invitedUser(ctx context.Context, v appInvitation, operationID string) (kcUser, bool, error) {
	var users []kcUser
	_, err := identityGET(ctx, a.client, a.endpoint("/users?username="+url.QueryEscape(v.Email)+"&exact=true"), a.token, &users, false)
	if err != nil {
		return kcUser{}, false, err
	}
	if len(users) == 0 {
		return kcUser{}, false, nil
	}
	if len(users) != 1 {
		return kcUser{}, false, changedIdentityPolicy
	}
	u := users[0]
	if !identity.MatchString(u.ID) || u.Username != v.Email || u.Email != v.Email || !accessAttrEqual(u.Attributes, "autosoft.app-id", v.AppID) || !accessAttrEqual(u.Attributes, "autosoft.invitation-id", v.ID) || !accessAttrEqual(u.Attributes, "autosoft.operation-id", operationID) {
		return kcUser{}, false, errors.New("An existing account cannot be overwritten by an invitation")
	}
	return u, true, nil
}
func (a accessIdentity) invitedRoles(ctx context.Context, v appInvitation) ([]kcRole, error) {
	roles := []kcRole{}
	for _, id := range v.RoleIDs {
		found := false
		for _, p := range a.snapshot.Policy.Roles {
			if p.ID == id {
				found = true
			}
		}
		if !found {
			return nil, changedIdentityPolicy
		}
		role, ok, err := a.getRole(ctx, accessRoleName(id), false)
		if err != nil || !ok || !ownedAccessRole(role, v.AppID, id) {
			return nil, changedIdentityPolicy
		}
		roles = append(roles, role)
	}
	return roles, nil
}
func (a accessIdentity) verifyInvitedUser(ctx context.Context, v appInvitation, operationID string) (string, error) {
	u, found, err := a.invitedUser(ctx, v, operationID)
	if err != nil || !found || !u.Enabled || u.EmailVerified {
		return "", errors.New("Invited local account is not confirmed")
	}
	var assigned []kcRole
	_, err = identityGET(ctx, a.client, a.endpoint("/users/"+u.ID+"/role-mappings/clients/"+a.clientID), a.token, &assigned, false)
	if err != nil {
		return "", err
	}
	names := []string{}
	for _, role := range assigned {
		if !role.ClientRole || role.ContainerID != a.clientID {
			return "", changedIdentityPolicy
		}
		names = append(names, role.Name)
	}
	want := []string{}
	for _, id := range v.RoleIDs {
		want = append(want, accessRoleName(id))
	}
	sort.Strings(names)
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		return "", changedIdentityPolicy
	}
	var credentials []struct {
		Type string `json:"type"`
	}
	_, err = identityGET(ctx, a.client, a.endpoint("/users/"+u.ID+"/credentials"), a.token, &credentials, false)
	if err != nil {
		return "", err
	}
	hasPassword, hasOTP := false, false
	for _, credential := range credentials {
		hasPassword = hasPassword || credential.Type == "password"
		hasOTP = hasOTP || credential.Type == "otp"
	}
	if !hasPassword || !hasOTP && !containsString(u.RequiredActions, "CONFIGURE_TOTP") {
		return "", errors.New("Invited account password or required authenticator enrollment unavailable")
	}
	return u.ID, nil
}
func (s *server) acceptAppInvitation(w http.ResponseWriter, r *http.Request) {
	in, ok := s.signedAccess(w, r)
	if !ok {
		return
	}
	if validInvitation(in) != nil || len(in.Password) < 12 || len(in.Password) > 512 || strings.ContainsAny(in.Password, "\x00\r\n") {
		accessReject(w, 409, "A current exact app invitation and protected password are required")
		return
	}
	unlock := s.lock("app-" + in.Invitation.AppID)
	defer unlock()
	if exists, err := s.existingAccess(w, in); exists {
		if err != nil {
			accessReject(w, 409, "Invitation operation identity mismatch")
		}
		return
	}
	if s.unusedAccessApproval(in) != nil {
		accessReject(w, 409, "This invitation approval was already dispatched")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	a, err := s.accessContext(ctx, in.Invitation.AppID)
	if err != nil || !a.snapshot.Policy.InvitationsEnabled || a.snapshot.PolicyHash != in.Invitation.PolicyHash || a.verifyRoles(ctx, a.snapshot.Policy) != nil {
		accessReject(w, 409, "Current protected app invitation policy changed")
		return
	}
	roles, err := a.invitedRoles(ctx, *in.Invitation)
	if err != nil {
		accessReject(w, 409, "Invited roles are not approved for this app")
		return
	}
	if _, found, lookupErr := a.invitedUser(ctx, *in.Invitation, in.OperationID); lookupErr != nil || found {
		accessReject(w, 409, "An existing account cannot be overwritten or reset by this invitation")
		return
	}
	durable := in
	durable.Password = ""
	receipt := accessReceipt{Result: accessResult{OperationID: in.OperationID, AppID: in.Invitation.AppID, Status: "running", Action: "invitation", Hash: in.Approval.Hash, InvitationID: in.Invitation.ID}, Request: durable, Realm: a.realm, ClientID: a.clientID, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if s.retainAccessApproval(durable) != nil {
		accessReject(w, 503, "Unable to retain single-use invitation approval")
		return
	}
	if atomicJSON(s.accessReceiptPath(in.OperationID), receipt) != nil {
		accessReject(w, 503, "Unable to retain invitation intent")
		return
	}
	body := map[string]any{"username": in.Invitation.Email, "email": in.Invitation.Email, "emailVerified": false, "enabled": false, "requiredActions": []string{"CONFIGURE_TOTP"}, "attributes": map[string][]string{"autosoft.app-id": {in.Invitation.AppID}, "autosoft.invitation-id": {in.Invitation.ID}, "autosoft.operation-id": {in.OperationID}}, "credentials": []map[string]any{{"type": "password", "value": in.Password, "temporary": false}}}
	err = a.write(ctx, "POST", a.endpoint("/users"), body, false)
	in.Password = ""
	delete(body, "credentials")
	if err != nil {
		fail(w, 503, errors.New("Invited account creation awaits confirmation; password is not retained or retried"))
		return
	}
	user, found, err := a.invitedUser(ctx, *in.Invitation, in.OperationID)
	if err != nil || !found || user.Enabled {
		fail(w, 503, errors.New("New disabled app account could not be verified"))
		return
	}
	receipt.Result.UserID = user.ID
	if atomicJSON(s.accessReceiptPath(in.OperationID), receipt) != nil {
		fail(w, 503, errors.New("Invited user identity could not be retained"))
		return
	}
	// Keycloak may append realm default VERIFY_EMAIL even when the new-user body
	// lists TOTP. This invitation is not email verification; remove only that
	// default on this exact new disabled owned account, keeping emailVerified false.
	for _, action := range user.RequiredActions {
		if action != "VERIFY_EMAIL" && action != "CONFIGURE_TOTP" {
			fail(w, 503, errors.New("Unexpected invited-account required action needs operator review"))
			return
		}
	}
	err = a.write(ctx, "PUT", a.endpoint("/users/"+user.ID), map[string]any{"requiredActions": []string{"CONFIGURE_TOTP"}}, false)
	if err == nil {
		err = a.write(ctx, "POST", a.endpoint("/users/"+user.ID+"/role-mappings/clients/"+a.clientID), roles, false)
	}
	if err == nil {
		err = a.write(ctx, "PUT", a.endpoint("/users/"+user.ID), map[string]any{"enabled": true}, false)
	}
	if err != nil {
		fail(w, 503, errors.New("Invited app role assignment awaits confirmation; no password reset will be retried"))
		return
	}
	userID, err := a.verifyInvitedUser(ctx, *in.Invitation, in.OperationID)
	if err != nil {
		fail(w, 503, errors.New("Invited app account is awaiting exact confirmation"))
		return
	}
	receipt.Result.Status = "succeeded"
	receipt.Result.UserID = userID
	if atomicJSON(s.accessReceiptPath(in.OperationID), receipt) != nil {
		fail(w, 503, errors.New("Invitation confirmation could not be retained"))
		return
	}
	respond(w, receipt.Result)
}
func (s *server) accessOperation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AppID       string `json:"appId"`
		OperationID string `json:"operationId"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !accessUUID.MatchString(input.AppID) || !identity.MatchString(input.OperationID) {
		fail(w, 400, errors.New("Invalid app access operation identity"))
		return
	}
	unlock := s.lock("app-" + input.AppID)
	defer unlock()
	var receipt accessReceipt
	err := readBoundedJSON(s.accessReceiptPath(input.OperationID), &receipt)
	if os.IsNotExist(err) {
		respond(w, accessResult{AppID: input.AppID, OperationID: input.OperationID, Status: "unknown"})
		return
	}
	if err != nil || receipt.Result.AppID != input.AppID || receipt.Request.Password != "" || receipt.Result.Hash != accessActionHash(receipt.Request) {
		fail(w, 409, errors.New("App access receipt identity mismatch"))
		return
	}
	if receipt.Result.Status == "running" {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		a, e := s.accessContext(ctx, input.AppID)
		if e == nil && a.realm == receipt.Realm && a.clientID == receipt.ClientID {
			if receipt.Request.Policy != nil {
				proposedHash := accessHash(receipt.Request.Policy)
				if a.snapshot.PolicyHash != receipt.Request.BaseHash && a.snapshot.PolicyHash != proposedHash {
					receipt.Result.Status = "failed"
					receipt.Result.Detail = "A newer approved policy superseded this unconfirmed operation; it was not replayed."
				} else if a.verifyPolicyTransition(ctx, a.snapshot.Policy, *receipt.Request.Policy) == nil {
					if a.snapshot.PolicyHash != proposedHash {
						e = writeAccessPolicy(filepath.Join(s.data, "access-policies", input.AppID+".enc"), receipt.Request.Policy)
					}
					if e == nil {
						receipt.Result.Status = "succeeded"
						receipt.Result.PolicyHash = proposedHash
					}
				}
			}
			if v := receipt.Request.Invitation; v != nil && a.snapshot.PolicyHash == v.PolicyHash {
				userID, e := a.verifyInvitedUser(ctx, *v, input.OperationID)
				if e == nil {
					receipt.Result.Status = "succeeded"
					receipt.Result.UserID = userID
				}
			}
			if receipt.Result.Status != "running" && atomicJSON(s.accessReceiptPath(input.OperationID), receipt) != nil {
				fail(w, 503, errors.New("App access confirmation could not be retained"))
				return
			}
			if receipt.Result.Action == "access_policy" && receipt.Result.Status != "running" {
				_ = s.pendingAccessPolicy(input.AppID)
			}
		}
	}
	respond(w, receipt.Result)
}
