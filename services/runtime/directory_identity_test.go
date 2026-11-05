package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type directoryIdentityFixture struct {
	in                      directorySubjectRequest
	app                     accessIdentity
	company, provider       directoryProvider
	profile                 directoryProfile
	mappers                 []directoryMapper
	appUser, platformUser   kcUser
	appLinks, platformLinks []directoryFederation
	writes                  int
}

func newDirectoryIdentityFixture(t *testing.T, provider string) *directoryIdentityFixture {
	t.Helper()
	f := &directoryIdentityFixture{}
	f.in = directorySubjectRequest{AppID: "11111111-1111-4111-8111-111111111111", AppSubject: "22222222-2222-4222-8222-222222222222", Provider: provider, TenantID: "33333333-3333-4333-8333-333333333333"}
	f.app = accessIdentity{realm: "app-fixture", token: "app-reader", snapshot: appAccessSnapshot{AppID: f.in.AppID, IdentityHash: strings.Repeat("a", 64), PolicyHash: strings.Repeat("b", 64), ReleaseID: "44444444-4444-4444-8444-444444444444"}}
	domain := "example.com"
	if provider == "google" {
		f.in.TenantID = "C0123example"
		f.in.WorkspaceDomain = &domain
	}
	f.appUser = kcUser{ID: f.in.AppSubject, Enabled: true}
	platformID := "55555555-5555-4555-8555-555555555555"
	f.appLinks = []directoryFederation{{Provider: "company", UserID: platformID}}
	externalID := "signed-pairwise-subject"
	if provider == "google" {
		externalID = "123456789012345678901"
	}
	f.platformLinks = []directoryFederation{{Provider: provider, UserID: externalID}}
	f.platformUser = kcUser{ID: platformID, Enabled: true, Attributes: map[string][]string{}}
	attrs := []map[string]any{}
	for claim, name := range directoryClaims(provider) {
		attrs = append(attrs, map[string]any{"name": name, "permissions": map[string]any{"view": []string{"admin"}, "edit": []string{"admin"}}})
		cfg := map[string]string{"syncMode": "FORCE", "claim": claim, "user.attribute": name}
		mapper := "oidc-user-attribute-idp-mapper"
		if provider == "google" {
			cfg = map[string]string{"syncMode": "FORCE", "jsonField": claim, "userAttribute": name}
			mapper = "google-user-attribute-mapper"
		}
		f.mappers = append(f.mappers, directoryMapper{Provider: provider, Mapper: mapper, Config: cfg})
	}
	body, _ := json.Marshal(map[string]any{"unmanagedAttributePolicy": "DISABLED", "attributes": attrs})
	_ = json.Unmarshal(body, &f.profile)
	f.platformUser.Attributes["autosoft.directory."+provider+".sub"] = []string{externalID}
	if provider == "microsoft" {
		f.platformUser.Attributes["autosoft.directory.microsoft.oid"] = []string{"66666666-6666-4666-8666-666666666666"}
		f.platformUser.Attributes["autosoft.directory.microsoft.tid"] = []string{f.in.TenantID}
		f.platformUser.Attributes["autosoft.directory.microsoft.iss"] = []string{"https://login.microsoftonline.com/" + f.in.TenantID + "/v2.0"}
	} else {
		f.platformUser.Attributes["autosoft.directory.google.hd"] = []string{domain}
	}
	c := map[string]string{"clientId": "upstream-client", "validateSignature": "true", "syncMode": "FORCE"}
	if provider == "microsoft" {
		prefix := "https://login.microsoftonline.com/" + f.in.TenantID
		c["issuer"] = prefix + "/v2.0"
		c["authorizationUrl"] = prefix + "/oauth2/v2.0/authorize"
		c["tokenUrl"] = prefix + "/oauth2/v2.0/token"
		c["jwksUrl"] = prefix + "/discovery/v2.0/keys"
		c["useJwksUrl"] = "true"
	} else {
		c["hostedDomain"] = domain
	}
	f.provider = directoryProvider{Alias: provider, ProviderID: "oidc", Enabled: true, Config: c}
	if provider == "google" {
		f.provider.ProviderID = "google"
	}
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			f.writes++
			w.WriteHeader(405)
			return
		}
		token := "Bearer platform-reader"
		if strings.HasPrefix(r.URL.Path, "/admin/realms/app-fixture/") {
			token = "Bearer app-reader"
		}
		if r.Header.Get("Authorization") != token {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/realms/app-fixture/identity-provider/instances/company":
			respond(w, f.company)
		case "/admin/realms/platform/identity-provider/instances/" + provider:
			respond(w, f.provider)
		case "/admin/realms/platform/identity-provider/instances/" + provider + "/mappers":
			respond(w, f.mappers)
		case "/admin/realms/platform/users/profile":
			respond(w, f.profile)
		case "/admin/realms/app-fixture/users/" + f.in.AppSubject:
			respond(w, f.appUser)
		case "/admin/realms/app-fixture/users/" + f.in.AppSubject + "/federated-identity":
			respond(w, f.appLinks)
		case "/admin/realms/platform/users/" + platformID:
			respond(w, f.platformUser)
		case "/admin/realms/platform/users/" + platformID + "/federated-identity":
			respond(w, f.platformLinks)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(api.Close)
	f.app.client = api.Client()
	f.app.base = api.URL
	t.Setenv("AUTH_ORIGIN", "https://auth.example.test")
	issuer := "https://auth.example.test/realms/platform"
	f.company = directoryProvider{Alias: "company", ProviderID: "keycloak-oidc", Enabled: true, Config: map[string]string{"clientId": "platform-broker-app-fixture", "validateSignature": "true", "useJwksUrl": "true", "issuer": issuer, "authorizationUrl": issuer + "/protocol/openid-connect/auth", "tokenUrl": api.URL + "/realms/platform/protocol/openid-connect/token", "jwksUrl": api.URL + "/realms/platform/protocol/openid-connect/certs", "userInfoUrl": api.URL + "/realms/platform/protocol/openid-connect/userinfo"}}
	return f
}
func TestDirectoryIdentityExactNativeImmutableBindings(t *testing.T) {
	for _, provider := range []string{"microsoft", "google"} {
		t.Run(provider, func(t *testing.T) {
			f := newDirectoryIdentityFixture(t, provider)
			result, err := f.app.directorySubject(context.Background(), f.in, "platform-reader")
			if err != nil {
				t.Fatal(err)
			}
			if result.AppSubject != f.in.AppSubject || result.PolicyHash != f.app.snapshot.PolicyHash || !accessHex.MatchString(result.BindingHash) || result.UpstreamUserID == f.appUser.ID || strings.Contains(result.UpstreamUserID, "@") || f.writes != 0 {
				t.Fatalf("Wrong isolated immutable subject: %+v writes %d", result, f.writes)
			}
		})
	}
}
func TestDirectoryIdentityMissingAmbiguousEditableAndUnsignedDeny(t *testing.T) {
	cases := map[string]func(*directoryIdentityFixture){
		"no company federation": func(f *directoryIdentityFixture) { f.appLinks = nil },
		"ambiguous app federation": func(f *directoryIdentityFixture) {
			f.appLinks = append(f.appLinks, directoryFederation{Provider: "other", UserID: "other"})
		},
		"app-local account": func(f *directoryIdentityFixture) {
			f.appLinks = []directoryFederation{{Provider: "local", UserID: f.in.AppSubject}}
		},
		"disabled app user":                  func(f *directoryIdentityFixture) { f.appUser.Enabled = false },
		"unfinished upstream MFA enrollment": func(f *directoryIdentityFixture) { f.platformUser.RequiredActions = []string{"CONFIGURE_TOTP"} },
		"foreign upstream alias":             func(f *directoryIdentityFixture) { f.platformLinks[0].Provider = "google" },
		"ambiguous upstream federation":      func(f *directoryIdentityFixture) { f.platformLinks = append(f.platformLinks, f.platformLinks[0]) },
		"email only identity": func(f *directoryIdentityFixture) {
			f.platformUser.Attributes = map[string][]string{}
			f.platformUser.Email = "admin@example.com"
		},
		"forged mutable subject": func(f *directoryIdentityFixture) {
			f.platformUser.Attributes["autosoft.directory.microsoft.sub"] = []string{"other-sub"}
		},
		"foreign tenant": func(f *directoryIdentityFixture) {
			f.platformUser.Attributes["autosoft.directory.microsoft.tid"] = []string{"77777777-7777-4777-8777-777777777777"}
		},
		"unmanaged profile": func(f *directoryIdentityFixture) { f.profile.Unmanaged = "ENABLED" },
		"user editable claim": func(f *directoryIdentityFixture) {
			f.profile.Attributes[0].Permissions.Edit = []string{"admin", "user"}
		},
		"missing mapper":               func(f *directoryIdentityFixture) { f.mappers = nil },
		"mapper import stale":          func(f *directoryIdentityFixture) { f.mappers[0].Config["syncMode"] = "IMPORT" },
		"unsigned upstream":            func(f *directoryIdentityFixture) { f.provider.Config["validateSignature"] = "false" },
		"unsigned company broker":      func(f *directoryIdentityFixture) { f.company.Config["validateSignature"] = "false" },
		"foreign company issuer":       func(f *directoryIdentityFixture) { f.company.Config["issuer"] = "https://evil.example/realms/platform" },
		"arbitrary upstream user info": func(f *directoryIdentityFixture) { f.provider.Config["userInfoUrl"] = "https://evil.example/claims" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newDirectoryIdentityFixture(t, "microsoft")
			mutate(f)
			if _, err := f.app.directorySubject(context.Background(), f.in, "platform-reader"); err == nil {
				t.Fatal("Unverified identity was accepted")
			}
			if f.writes != 0 {
				t.Fatal("Directory read changed identity grants")
			}
		})
	}
}
func TestDirectoryIdentityRoutesRequireSignedProtectedControlRead(t *testing.T) {
	s := &server{token: "fixture-broker-token", approvalKey: []byte(strings.Repeat("a", 32))}
	mux := http.NewServeMux()
	registerDirectoryIdentityRoutes(mux, s)
	r := httptest.NewRequest("POST", "/v1/access/directory-subject", strings.NewReader(`{"appId":"11111111-1111-4111-8111-111111111111"}`))
	r.Header.Set("Authorization", "Bearer fixture-broker-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("Unsigned control read accepted: %d", w.Code)
	}
	for _, in := range []directorySubjectRequest{{AppID: "11111111-1111-4111-8111-111111111111", AppSubject: "user@example.com", Provider: "microsoft", TenantID: "33333333-3333-4333-8333-333333333333"}, {AppID: "11111111-1111-4111-8111-111111111111", AppSubject: "22222222-2222-4222-8222-222222222222", Provider: "google", TenantID: "my_customer"}} {
		if validDirectoryRequest(in, true) {
			t.Fatal("Email-only or implicit customer identity accepted")
		}
	}
}
