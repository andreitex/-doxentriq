package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Directory lookups never write users, groups, roles or federation links.
// The platform reader has separate read-only credentials; the app provisioner
// is used only for its own realm. No email is an authorization identity.
type directorySubjectRequest struct {
	AppID           string  `json:"appId"`
	AppSubject      string  `json:"appSubject,omitempty"`
	Provider        string  `json:"provider"`
	TenantID        string  `json:"tenantId"`
	WorkspaceDomain *string `json:"workspaceDomain"`
}
type directoryConfiguration struct {
	AppID           string  `json:"appId"`
	Provider        string  `json:"provider"`
	TenantID        string  `json:"tenantId"`
	WorkspaceDomain *string `json:"workspaceDomain"`
	BindingHash     string  `json:"bindingHash"`
	CheckedAt       string  `json:"checkedAt"`
}
type directorySubject struct {
	directorySubjectRequest
	UpstreamUserID string `json:"upstreamUserId"`
	BindingHash    string `json:"bindingHash"`
	PolicyHash     string `json:"policyHash"`
	ReleaseID      string `json:"releaseId"`
	CheckedAt      string `json:"checkedAt"`
}
type directoryFederation struct {
	Provider string `json:"identityProvider"`
	UserID   string `json:"userId"`
}
type directoryProvider struct {
	Alias      string            `json:"alias"`
	ProviderID string            `json:"providerId"`
	Enabled    bool              `json:"enabled"`
	Config     map[string]string `json:"config"`
}
type directoryMapper struct {
	Provider string            `json:"identityProviderAlias"`
	Mapper   string            `json:"identityProviderMapper"`
	Config   map[string]string `json:"config"`
}
type directoryProfile struct {
	Unmanaged  string `json:"unmanagedAttributePolicy"`
	Attributes []struct {
		Name        string `json:"name"`
		Permissions struct {
			Edit []string `json:"edit"`
			View []string `json:"view"`
		} `json:"permissions"`
	} `json:"attributes"`
}

var directoryDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,}$`)
var directoryGoogleID = regexp.MustCompile(`^[0-9]{1,128}$`)
var directoryCustomer = regexp.MustCompile(`^C[A-Za-z0-9_-]{1,127}$`)

func validDirectoryRequest(in directorySubjectRequest, subject bool) bool {
	if !accessUUID.MatchString(in.AppID) || (subject && !accessUUID.MatchString(in.AppSubject)) || (!subject && in.AppSubject != "") {
		return false
	}
	if in.Provider == "microsoft" {
		return accessUUID.MatchString(in.TenantID) && strings.ToLower(in.TenantID) == in.TenantID && in.WorkspaceDomain == nil
	}
	return in.Provider == "google" && directoryCustomer.MatchString(in.TenantID) && in.WorkspaceDomain != nil && directoryDomain.MatchString(*in.WorkspaceDomain)
}
func directoryOneLink(links []directoryFederation, provider string) (string, error) {
	if len(links) != 1 || links[0].Provider != provider || links[0].UserID == "" {
		return "", errors.New("A single exact protected federation link is required")
	}
	return links[0].UserID, nil
}
func directoryProfileProtected(profile directoryProfile, attributes []string) bool {
	if profile.Unmanaged != "DISABLED" {
		return false
	}
	for _, name := range attributes {
		count := 0
		for _, attribute := range profile.Attributes {
			if attribute.Name == name {
				count++
				if len(attribute.Permissions.Edit) != 1 || attribute.Permissions.Edit[0] != "admin" || len(attribute.Permissions.View) != 1 || attribute.Permissions.View[0] != "admin" {
					return false
				}
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}
func directoryMapperProtected(mappers []directoryMapper, provider string, attributes map[string]string) bool {
	for claim, attribute := range attributes {
		count := 0
		for _, mapper := range mappers {
			target := mapper.Config["user.attribute"]
			if provider == "google" {
				target = mapper.Config["userAttribute"]
			}
			if target != attribute {
				continue
			}
			count++
			if mapper.Provider != provider || mapper.Config["syncMode"] != "FORCE" {
				return false
			}
			if provider == "google" {
				if mapper.Mapper != "google-user-attribute-mapper" || mapper.Config["jsonField"] != claim {
					return false
				}
			} else if mapper.Mapper != "oidc-user-attribute-idp-mapper" || mapper.Config["claim"] != claim {
				return false
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}
func directoryProviderProtected(provider directoryProvider, in directorySubjectRequest) bool {
	c := provider.Config
	if provider.Alias != in.Provider || !provider.Enabled || c["validateSignature"] != "true" || c["syncMode"] != "FORCE" || c["clientId"] == "" {
		return false
	}
	if in.Provider == "google" {
		return provider.ProviderID == "google" && in.WorkspaceDomain != nil && c["hostedDomain"] == *in.WorkspaceDomain
	}
	prefix := "https://login.microsoftonline.com/" + in.TenantID
	return provider.ProviderID == "oidc" && c["issuer"] == prefix+"/v2.0" && c["authorizationUrl"] == prefix+"/oauth2/v2.0/authorize" && c["tokenUrl"] == prefix+"/oauth2/v2.0/token" && c["jwksUrl"] == prefix+"/discovery/v2.0/keys" && c["useJwksUrl"] == "true" && (c["userInfoUrl"] == "" || c["userInfoUrl"] == "https://graph.microsoft.com/oidc/userinfo")
}
func directoryClaims(provider string) map[string]string {
	if provider == "google" {
		return map[string]string{"sub": "autosoft.directory.google.sub", "hd": "autosoft.directory.google.hd"}
	}
	return map[string]string{"sub": "autosoft.directory.microsoft.sub", "oid": "autosoft.directory.microsoft.oid", "tid": "autosoft.directory.microsoft.tid", "iss": "autosoft.directory.microsoft.iss"}
}
func directoryReader(ctx context.Context, client *http.Client, base string) (string, error) {
	credential, err := secret("KEYCLOAK_DIRECTORY_READER_SECRET")
	if err != nil || credential == "" {
		return "", errors.New("Separate protected platform directory reader is unavailable")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"platform-directory-reader"}, "client_secret": {credential}}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/realms/platform/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		return "", errors.New("Protected platform reader unavailable")
	}
	defer response.Body.Close()
	var token struct {
		Token string `json:"access_token"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 65536))
	if response.StatusCode != 200 || decoder.Decode(&token) != nil || decoder.Decode(new(any)) != io.EOF || token.Token == "" || len(token.Token) > 16384 || strings.ContainsAny(token.Token, "\r\n ") {
		return "", errors.New("Protected platform reader unavailable")
	}
	return token.Token, nil
}
func (a accessIdentity) directoryConfiguration(ctx context.Context, in directorySubjectRequest, readerToken string) (directoryConfiguration, error) {
	var out directoryConfiguration
	var company directoryProvider
	if _, err := identityGET(ctx, a.client, a.endpoint("/identity-provider/instances/company"), a.token, &company, false); err != nil {
		return out, err
	}
	public := strings.TrimRight(env("AUTH_ORIGIN", ""), "/")
	u, err := url.Parse(public)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return out, errors.New("Exact public identity authority unavailable")
	}
	c := company.Config
	issuer := public + "/realms/platform"
	if company.Alias != "company" || company.ProviderID != "keycloak-oidc" || !company.Enabled || c["clientId"] != "platform-broker-"+a.realm || c["validateSignature"] != "true" || c["useJwksUrl"] != "true" || c["issuer"] != issuer || c["authorizationUrl"] != issuer+"/protocol/openid-connect/auth" || c["tokenUrl"] != a.base+"/realms/platform/protocol/openid-connect/token" || c["jwksUrl"] != a.base+"/realms/platform/protocol/openid-connect/certs" || c["userInfoUrl"] != a.base+"/realms/platform/protocol/openid-connect/userinfo" {
		return out, errors.New("The app company identity binding is unavailable or changed")
	}
	var provider directoryProvider
	var profile directoryProfile
	var mappers []directoryMapper
	prefix := a.base + "/admin/realms/platform"
	for _, item := range []struct {
		path  string
		value any
	}{{"/identity-provider/instances/" + in.Provider, &provider}, {"/users/profile", &profile}, {"/identity-provider/instances/" + in.Provider + "/mappers", &mappers}} {
		if _, err := identityGET(ctx, a.client, prefix+item.path, readerToken, item.value, false); err != nil {
			return out, err
		}
	}
	attrs := directoryClaims(in.Provider)
	names := []string{}
	for _, name := range attrs {
		names = append(names, name)
	}
	if !directoryProviderProtected(provider, in) || !directoryProfileProtected(profile, names) || !directoryMapperProtected(mappers, in.Provider, attrs) {
		return out, errors.New("Directory provider must have exact signature validation, forced immutable-claim mappers and admin-only profile attributes")
	}
	// Only security-relevant public configuration enters the binding. No client
	// secret, directory credential, email or user-profile text leaves the broker.
	cfg := map[string]string{}
	for _, key := range []string{"clientId", "issuer", "authorizationUrl", "tokenUrl", "jwksUrl", "useJwksUrl", "validateSignature", "syncMode", "hostedDomain", "userInfoUrl"} {
		cfg[key] = provider.Config[key]
	}
	out = directoryConfiguration{AppID: in.AppID, Provider: in.Provider, TenantID: in.TenantID, WorkspaceDomain: in.WorkspaceDomain, BindingHash: accessHash(map[string]any{"version": 1, "appIdentityHash": a.snapshot.IdentityHash, "provider": in.Provider, "tenantId": in.TenantID, "domain": in.WorkspaceDomain, "providerConfig": cfg, "claims": attrs}), CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	return out, nil
}
func (a accessIdentity) directorySubject(ctx context.Context, in directorySubjectRequest, readerToken string) (directorySubject, error) {
	var out directorySubject
	configuration, err := a.directoryConfiguration(ctx, in, readerToken)
	if err != nil {
		return out, err
	}
	var appUser kcUser
	var links []directoryFederation
	if _, err = identityGET(ctx, a.client, a.endpoint("/users/"+in.AppSubject), a.token, &appUser, false); err != nil || appUser.ID != in.AppSubject || !appUser.Enabled || len(appUser.RequiredActions) > 0 {
		return out, errors.New("Active fully enrolled app user unavailable")
	}
	if _, err = identityGET(ctx, a.client, a.endpoint("/users/"+in.AppSubject+"/federated-identity"), a.token, &links, false); err != nil {
		return out, err
	}
	platformID, err := directoryOneLink(links, "company")
	if err != nil || !accessUUID.MatchString(platformID) {
		return out, errors.New("App-local accounts without an exact company federation binding cannot receive directory permissions")
	}
	var platformUser kcUser
	links = nil
	prefix := a.base + "/admin/realms/platform/users/" + platformID
	if _, err = identityGET(ctx, a.client, prefix, readerToken, &platformUser, false); err != nil || platformUser.ID != platformID || !platformUser.Enabled || len(platformUser.RequiredActions) > 0 {
		return out, errors.New("Active fully enrolled upstream user unavailable")
	}
	if _, err = identityGET(ctx, a.client, prefix+"/federated-identity", readerToken, &links, false); err != nil {
		return out, err
	}
	externalID, err := directoryOneLink(links, in.Provider)
	if err != nil || !accessAttrEqual(platformUser.Attributes, "autosoft.directory."+in.Provider+".sub", externalID) {
		return out, errors.New("The protected upstream subject is missing or differs from its native provider binding")
	}
	upstream := externalID
	if in.Provider == "microsoft" {
		attrs := platformUser.Attributes
		upstream = ""
		if len(attrs["autosoft.directory.microsoft.oid"]) == 1 {
			upstream = attrs["autosoft.directory.microsoft.oid"][0]
		}
		if !accessUUID.MatchString(upstream) || strings.ToLower(upstream) != upstream || !accessAttrEqual(attrs, "autosoft.directory.microsoft.tid", in.TenantID) || !accessAttrEqual(attrs, "autosoft.directory.microsoft.iss", "https://login.microsoftonline.com/"+in.TenantID+"/v2.0") {
			return out, errors.New("Signed immutable Microsoft object and tenant claims unavailable")
		}
	} else if !directoryGoogleID.MatchString(upstream) || in.WorkspaceDomain == nil || !accessAttrEqual(platformUser.Attributes, "autosoft.directory.google.hd", *in.WorkspaceDomain) {
		return out, errors.New("Protected native Google subject and hosted-domain binding unavailable")
	}
	out = directorySubject{directorySubjectRequest: in, UpstreamUserID: upstream, BindingHash: accessHash(map[string]any{"configuration": configuration.BindingHash, "appSubject": in.AppSubject, "platformSubject": platformID, "externalSubject": externalID, "upstreamUserId": upstream}), PolicyHash: a.snapshot.PolicyHash, ReleaseID: a.snapshot.ReleaseID, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	return out, nil
}
func registerDirectoryIdentityRoutes(mux *http.ServeMux, s *server) {
	for _, route := range []struct {
		path          string
		subject, keys bool
	}{{"/v1/access/directory-keys", false, true}, {"/v1/access/directory-configuration", false, false}, {"/v1/access/directory-subject", true, false}} {
		mux.HandleFunc(route.path, s.authenticated(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				accessReject(w, 405, "POST required")
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 16385))
			if err != nil || len(body) > 16384 || !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
				accessReject(w, 403, "Exact signed directory read required")
				return
			}
			var in directorySubjectRequest
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || (!route.keys && !validDirectoryRequest(in, route.subject)) || (route.keys && (!accessUUID.MatchString(in.AppID) || in.AppSubject != "" || in.Provider != "" || in.TenantID != "" || in.WorkspaceDomain != nil)) {
				accessReject(w, 400, "Invalid directory identity scope")
				return
			}
			unlock := s.lock("app-" + in.AppID)
			defer unlock()
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			a, err := s.accessContext(ctx, in.AppID)
			if err != nil {
				accessReject(w, 503, "Current owned published app identity is unavailable")
				return
			}
			if route.keys {
				issuer := strings.TrimRight(env("AUTH_ORIGIN", ""), "/") + "/realms/" + a.realm
				bundle, err := fetchAppJWKS(ctx, a.client, a.base, a.realm, in.AppID, in.AppID, issuer)
				if err != nil {
					accessReject(w, 503, "Fresh app signing keys unavailable")
					return
				}
				respond(w, map[string]any{"appId": in.AppID, "releaseId": a.snapshot.ReleaseID, "policyHash": a.snapshot.PolicyHash, "issuer": issuer, "audience": "app-" + in.AppID, "checkedAt": time.Now().UTC().Format(time.RFC3339), "jwks": map[string]any{"keys": bundle.Keys}})
				return
			}
			reader, err := directoryReader(ctx, a.client, a.base)
			if err != nil {
				accessReject(w, 503, "Protected directory reader unavailable; use company setup, never chat credentials")
				return
			}
			if route.subject {
				result, err := a.directorySubject(ctx, in, reader)
				if err != nil {
					accessReject(w, 503, "Exact immutable provider identity unavailable; no group authorization")
					return
				}
				respond(w, result)
			} else {
				result, err := a.directoryConfiguration(ctx, in, reader)
				if err != nil {
					accessReject(w, 503, "Protected immutable-claim provider configuration unavailable")
					return
				}
				respond(w, result)
			}
		}))
	}
}
