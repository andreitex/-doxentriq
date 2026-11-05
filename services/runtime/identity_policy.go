package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type identityPolicyState struct {
	AppID        string `json:"appId"`
	Realm        string `json:"realm"`
	Hash         string `json:"policyHash"`
	BrokerSecret string `json:"brokerSecret,omitempty"`
}

var changedIdentityPolicy = errors.New("Application access policy changed or cannot be verified; a separate approved identity-policy change is required before publication")

// Permissions, login mode and public origins are an access policy independent
// of code releases. A rollback must not silently change an existing realm.
func (s *server) identityPolicy(m AppManifest, realm, issuer, origin string) (identityPolicyState, error) {
	var state identityPolicyState
	if !identity.MatchString(m.ID) || !identity.MatchString(realm) || (m.Auth != "sso" && m.Auth != "local" && m.Auth != "public") {
		return state, errors.New("Invalid scoped identity policy")
	}
	for _, address := range []string{issuer, origin} {
		parsed, err := url.Parse(address)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return state, errors.New("A valid HTTPS app and identity origin is required")
		}
	}
	permissions := append([]string{}, m.Permissions...)
	sort.Strings(permissions)
	for i, permission := range permissions {
		if !regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,79}$`).MatchString(permission) || (i > 0 && permission == permissions[i-1]) {
			return state, errors.New("App permissions must have unique bounded role names")
		}
	}
	payload, err := json.Marshal(struct {
		Version     int      `json:"version"`
		AppID       string   `json:"appId"`
		Auth        string   `json:"auth"`
		Slug        string   `json:"slug"`
		Realm       string   `json:"realm"`
		Issuer      string   `json:"issuer"`
		Origin      string   `json:"origin"`
		Permissions []string `json:"permissions"`
	}{2, m.ID, m.Auth, m.Slug, realm, issuer, origin, permissions})
	if err != nil {
		return state, err
	}
	hash := hashBytes(payload)
	file, err := safePath(filepath.Join(s.data, "identity-policies"), realm)
	if err != nil {
		return state, err
	}
	file += ".enc"
	err = readEncrypted(file, &state)
	if err == nil {
		if state.AppID != m.ID || state.Realm != realm || state.Hash != hash || (m.Auth == "sso" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(state.BrokerSecret)) {
			return state, changedIdentityPolicy
		}
		return state, nil
	}
	if !os.IsNotExist(err) {
		return state, errors.New("Protected application identity policy cannot be read")
	}
	state = identityPolicyState{AppID: m.ID, Realm: realm, Hash: hash}
	if m.Auth == "sso" {
		state.BrokerSecret = randomSecret()
	}
	// Persist and sync the encrypted stable credential before the first remote
	// request. A stopped process can retry without creating mismatched secrets.
	if err = writeEncrypted(file, state); err != nil {
		return state, err
	}
	f, err := os.OpenFile(file, os.O_RDWR, 0600)
	if err != nil {
		return state, err
	}
	err = f.Sync()
	_ = f.Close()
	if err != nil {
		return state, err
	}
	if os.PathSeparator == '/' {
		directory, err := os.Open(filepath.Dir(file))
		if err != nil {
			return state, err
		}
		err = directory.Sync()
		_ = directory.Close()
		if err != nil {
			return state, err
		}
	}
	return state, nil
}

func identityMarkers(appID, realm, hash string) map[string]string {
	return map[string]string{"autosoft.app-id": appID, "autosoft.realm": realm, "autosoft.policy-hash": hash}
}

// Importing an explicit clientScopes list suppresses Keycloak's default
// scopes. Provide every scope referenced by our clients, with roles limited
// to the one app API client (including when an MCP client requests a token).
func appIdentityScopes(audience string) []map[string]any {
	property := func(name, property, claim, kind string) map[string]any {
		return map[string]any{"name": name, "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-property-mapper", "config": map[string]string{"user.attribute": property, "claim.name": claim, "jsonType.label": kind, "access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"}}
	}
	scope := func(name, include string, mappers []map[string]any) map[string]any {
		return map[string]any{"name": name, "protocol": "openid-connect", "attributes": map[string]string{"include.in.token.scope": include}, "protocolMappers": mappers}
	}
	roleMapper := map[string]any{"name": "app-client-roles", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-client-role-mapper", "config": map[string]string{"usermodel.clientRoleMapping.clientId": audience, "usermodel.clientRoleMapping.rolePrefix": "", "claim.name": "resource_access." + audience + ".roles", "jsonType.label": "String", "multivalued": "true", "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"}}
	return []map[string]any{
		scope("roles", "false", []map[string]any{roleMapper}),
		scope("profile", "true", []map[string]any{property("username", "username", "preferred_username", "String"), property("given-name", "firstName", "given_name", "String"), property("family-name", "lastName", "family_name", "String")}),
		scope("email", "true", []map[string]any{property("email", "email", "email", "String"), property("verified-email", "emailVerified", "email_verified", "boolean")}),
		scope("dms.read", "true", []map[string]any{}),
		scope("dms.search", "true", []map[string]any{}),
	}
}
func matchingIdentityMarkers(attributes map[string]string, appID, realm, hash string) bool {
	return attributes["autosoft.app-id"] == appID && attributes["autosoft.realm"] == realm && attributes["autosoft.policy-hash"] == hash
}
func identityGET(ctx context.Context, client *http.Client, address, token string, output any, allowMissing bool) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return false, errors.New("Trusted identity policy lookup is unavailable")
	}
	defer response.Body.Close()
	if allowMissing && response.StatusCode == 404 {
		return false, nil
	}
	if response.StatusCode != 200 {
		return false, errors.New("Company identity provisioner must have read access to its app realm and broker clients")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if decoder.Decode(output) != nil || decoder.Decode(new(any)) != io.EOF {
		return false, errors.New("Identity policy lookup returned invalid bounded data")
	}
	return true, nil
}
func ownedIdentityRealm(ctx context.Context, client *http.Client, base, token, realm, appID, hash string, allowMissing bool) (bool, error) {
	var existing struct {
		Realm      string            `json:"realm"`
		Attributes map[string]string `json:"attributes"`
	}
	found, err := identityGET(ctx, client, base+"/admin/realms/"+url.PathEscape(realm), token, &existing, allowMissing)
	if err != nil || !found {
		return found, err
	}
	if existing.Realm != realm || !matchingIdentityMarkers(existing.Attributes, appID, realm, hash) {
		return false, changedIdentityPolicy
	}
	return true, nil
}
func identityCreate(ctx context.Context, client *http.Client, address, token string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", address, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Trusted identity creation is unavailable; stable protected credentials are retained for retry")
	}
	defer response.Body.Close()
	// A conflict is never success on its own: callers must read and compare the
	// owned policy (and, for confidential clients, the exact persisted secret).
	if response.StatusCode != 201 && response.StatusCode != 409 {
		status := " (HTTP " + strconv.Itoa(response.StatusCode) + ")"
		if response.StatusCode == 401 || response.StatusCode == 403 {
			return errors.New("Application identity creation requires company-managed realm/client privileges" + status)
		}
		if response.StatusCode == 400 || response.StatusCode == 422 {
			return errors.New("Identity service rejected the app realm/client configuration" + status + "; company configuration review is required")
		}
		return errors.New("Trusted identity creation is unavailable" + status + "; protected credentials and work are retained")
	}
	return nil
}
func createOwnedIdentityRealm(ctx context.Context, client *http.Client, base, token string, body any, realm, appID, hash string) error {
	if err := identityCreate(ctx, client, base+"/admin/realms", token, body); err != nil {
		return err
	}
	if _, err := ownedIdentityRealm(ctx, client, base, token, realm, appID, hash, false); err != nil {
		return err
	}
	return ensureAppUserProfile(ctx, client, base, token, realm)
}
func createOwnedIdentityBroker(ctx context.Context, client *http.Client, base, token string, body any, appID, realm, hash, brokerID, redirect, secret string) error {
	if err := identityCreate(ctx, client, base+"/admin/realms/platform/clients", token, body); err != nil {
		return err
	}
	var existing []struct {
		ID                  string            `json:"id"`
		ClientID            string            `json:"clientId"`
		Protocol            string            `json:"protocol"`
		PublicClient        *bool             `json:"publicClient"`
		StandardFlowEnabled *bool             `json:"standardFlowEnabled"`
		DirectAccessEnabled *bool             `json:"directAccessGrantsEnabled"`
		RedirectURIs        []string          `json:"redirectUris"`
		Attributes          map[string]string `json:"attributes"`
	}
	if _, err := identityGET(ctx, client, base+"/admin/realms/platform/clients?clientId="+url.QueryEscape(brokerID), token, &existing, false); err != nil {
		return err
	}
	if len(existing) != 1 {
		return changedIdentityPolicy
	}
	v := existing[0]
	if !identity.MatchString(v.ID) || v.ClientID != brokerID || v.Protocol != "openid-connect" || v.PublicClient == nil || *v.PublicClient || v.StandardFlowEnabled == nil || !*v.StandardFlowEnabled || v.DirectAccessEnabled == nil || *v.DirectAccessEnabled || len(v.RedirectURIs) != 1 || v.RedirectURIs[0] != redirect || !matchingIdentityMarkers(v.Attributes, appID, realm, hash) {
		return changedIdentityPolicy
	}
	var credential struct {
		Value string `json:"value"`
	}
	if _, err := identityGET(ctx, client, base+"/admin/realms/platform/clients/"+url.PathEscape(v.ID)+"/client-secret", token, &credential, false); err != nil {
		return err
	}
	if len(credential.Value) != len(secret) || subtle.ConstantTimeCompare([]byte(credential.Value), []byte(secret)) != 1 || strings.TrimSpace(secret) == "" {
		return changedIdentityPolicy
	}
	return nil
}
