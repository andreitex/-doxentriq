package main

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
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

const appJWKSMaxAge = time.Hour
const appJWKSMaxBytes = 1 << 20

type appJWKSMetadata struct {
	Version    int    `json:"schemaVersion"`
	AppID      string `json:"appId"`
	ResourceID string `json:"resourceId"`
	Issuer     string `json:"issuer"`
	CheckedAt  string `json:"checkedAt"`
	ValidUntil string `json:"validUntil"`
	KeysHash   string `json:"keysHash"`
}
type appJWKSBundle struct {
	Keys     []map[string]string `json:"keys"`
	Metadata appJWKSMetadata     `json:"autosoft"`
}
type appJWKSRefreshResult struct {
	AppID      string `json:"appId"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	CheckedAt  string `json:"checkedAt,omitempty"`
	ValidUntil string `json:"validUntil,omitempty"`
}
type appJWKSJournal struct {
	Version     int           `json:"version"`
	AppID       string        `json:"appId"`
	ResourceID  string        `json:"resourceId"`
	ContainerID string        `json:"containerId"`
	Image       string        `json:"image"`
	Issuer      string        `json:"issuer"`
	Phase       string        `json:"phase"`
	UpdatedAt   string        `json:"updatedAt"`
	Old         appJWKSBundle `json:"old"`
	Candidate   appJWKSBundle `json:"candidate"`
}
type appJWKSStop struct {
	Version     int    `json:"version"`
	AppID       string `json:"appId"`
	ResourceID  string `json:"resourceId"`
	ContainerID string `json:"containerId"`
	Image       string `json:"image"`
	Issuer      string `json:"issuer"`
	Phase       string `json:"phase"`
	UpdatedAt   string `json:"updatedAt"`
}

// Keep only supported public signing material. Private keys, arbitrary fetch URLs,
// duplicate key identities, weak RSA and invalid EC points never reach app mounts.
func validatedAppJWKS(body []byte) ([]map[string]string, error) {
	if len(body) == 0 || len(body) > appJWKSMaxBytes {
		return nil, errors.New("Application signing keys exceed their bounded representation")
	}
	var input struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.Keys) < 1 || len(input.Keys) > 32 {
		return nil, errors.New("Application signing keys are invalid or empty")
	}
	selected := []map[string]string{}
	seen := map[string]bool{}
	decode := func(key map[string]json.RawMessage, name string) string {
		var value string
		_ = json.Unmarshal(key[name], &value)
		return value
	}
	for _, key := range input.Keys {
		for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := key[name]; ok {
				return nil, errors.New("Private signing material is forbidden")
			}
		}
		use := decode(key, "use")
		if use == "enc" {
			continue
		}
		if use != "" && use != "sig" {
			return nil, errors.New("Unsupported application signing-key use")
		}
		kid, kind, algorithm := decode(key, "kid"), decode(key, "kty"), decode(key, "alg")
		if !regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,200}$`).MatchString(kid) || seen[kid] {
			return nil, errors.New("Signing-key identities must be unique and bounded")
		}
		seen[kid] = true
		if operations, ok := key["key_ops"]; ok {
			var values []string
			if json.Unmarshal(operations, &values) != nil || len(values) != 1 || values[0] != "verify" {
				return nil, errors.New("Only public verification keys are allowed")
			}
		}
		public := map[string]string{"kid": kid, "kty": kind, "use": "sig"}
		switch kind {
		case "RSA":
			if algorithm != "" && algorithm != "RS256" {
				return nil, errors.New("Only RS256 and ES256 app signing keys are supported")
			}
			n, e := decode(key, "n"), decode(key, "e")
			modulus, err := base64.RawURLEncoding.DecodeString(n)
			if err != nil || len(modulus) < 256 || len(modulus) > 1024 || modulus[0] == 0 {
				return nil, errors.New("Invalid RSA signing modulus")
			}
			exponent, err := base64.RawURLEncoding.DecodeString(e)
			if err != nil || len(exponent) < 1 || len(exponent) > 4 {
				return nil, errors.New("Invalid RSA signing exponent")
			}
			number := new(big.Int).SetBytes(exponent)
			if number.Int64() < 3 || number.Bit(0) == 0 || new(big.Int).SetBytes(modulus).BitLen() < 2048 {
				return nil, errors.New("Weak RSA signing key")
			}
			public["alg"], public["n"], public["e"] = "RS256", n, e
		case "EC":
			if (algorithm != "" && algorithm != "ES256") || decode(key, "crv") != "P-256" {
				return nil, errors.New("Only P-256 ES256 app signing keys are supported")
			}
			x, y := decode(key, "x"), decode(key, "y")
			xb, xe := base64.RawURLEncoding.DecodeString(x)
			yb, ye := base64.RawURLEncoding.DecodeString(y)
			if xe != nil || ye != nil || len(xb) != 32 || len(yb) != 32 || !elliptic.P256().IsOnCurve(new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)) {
				return nil, errors.New("Invalid EC signing point")
			}
			public["alg"], public["crv"], public["x"], public["y"] = "ES256", "P-256", x, y
		default:
			return nil, errors.New("Unsupported application signing-key type")
		}
		selected = append(selected, public)
	}
	if len(selected) == 0 {
		return nil, errors.New("No supported public signing keys are available")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i]["kid"] < selected[j]["kid"] })
	return selected, nil
}

func readIdentityJSON(ctx context.Context, client *http.Client, address string, max int, value any) error {
	if client == nil {
		return errors.New("Trusted identity HTTPS client is unavailable")
	}
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := safeClient.Do(request)
	if err != nil {
		return errors.New("Trusted identity signing-key service is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("Trusted identity endpoint did not return exact HTTPS evidence")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(max)+1))
	if err != nil || len(body) > max {
		return errors.New("Identity response exceeds its bounded representation")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("Identity endpoint returned malformed data")
	}
	return nil
}

func fetchAppJWKS(ctx context.Context, client *http.Client, base, realm, appID, resourceID, issuer string) (appJWKSBundle, error) {
	var bundle appJWKSBundle
	internal, err := url.Parse(base)
	public, pe := url.Parse(issuer)
	if err != nil || pe != nil || internal.Scheme != "https" || public.Scheme != "https" || internal.Host == "" || public.Host == "" || internal.User != nil || public.User != nil || internal.RawQuery != "" || public.RawQuery != "" || internal.Fragment != "" || public.Fragment != "" || !identity.MatchString(realm) || !identity.MatchString(appID) || !identity.MatchString(resourceID) {
		return bundle, errors.New("Exact HTTPS identity authority and app scope are required")
	}
	base = strings.TrimRight(base, "/")
	expectedURI := issuer + "/protocol/openid-connect/certs"
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err = readIdentityJSON(ctx, client, base+"/realms/"+realm+"/.well-known/openid-configuration", 65536, &discovery); err != nil {
		return bundle, err
	}
	if discovery.Issuer != issuer || discovery.JWKSURI != expectedURI {
		return bundle, errors.New("Signing-key discovery does not match the exact configured app issuer")
	}
	var raw json.RawMessage
	if err = readIdentityJSON(ctx, client, base+"/realms/"+realm+"/protocol/openid-connect/certs", appJWKSMaxBytes, &raw); err != nil {
		return bundle, err
	}
	keys, err := validatedAppJWKS(raw)
	if err != nil {
		return bundle, err
	}
	encoded, _ := json.Marshal(keys)
	now := time.Now().UTC()
	bundle = appJWKSBundle{Keys: keys, Metadata: appJWKSMetadata{Version: 1, AppID: appID, ResourceID: resourceID, Issuer: issuer, CheckedAt: now.Format(time.RFC3339Nano), ValidUntil: now.Add(appJWKSMaxAge).Format(time.RFC3339Nano), KeysHash: hashBytes(encoded)}}
	return bundle, nil
}

func validAppJWKSBundle(bundle appJWKSBundle, appID, resourceID, issuer string, requireFresh bool) bool {
	m := bundle.Metadata
	keys, _ := json.Marshal(map[string]any{"keys": bundle.Keys})
	selected, err := validatedAppJWKS(keys)
	encoded, _ := json.Marshal(selected)
	checked, ce := time.Parse(time.RFC3339Nano, m.CheckedAt)
	until, ue := time.Parse(time.RFC3339Nano, m.ValidUntil)
	return err == nil && reflect.DeepEqual(selected, bundle.Keys) && m.Version == 1 && m.AppID == appID && m.ResourceID == resourceID && m.Issuer == issuer && m.KeysHash == hashBytes(encoded) && ce == nil && ue == nil && !checked.After(time.Now().Add(time.Minute)) && until.After(checked) && !until.After(checked.Add(appJWKSMaxAge)) && (!requireFresh || until.After(time.Now()))
}
func installAppJWKS(directory string, bundle appJWKSBundle) error {
	if !validAppJWKSBundle(bundle, bundle.Metadata.AppID, bundle.Metadata.ResourceID, bundle.Metadata.Issuer, false) {
		return errors.New("Invalid issuer-bound signing-key installation")
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	return atomicTLSFile(filepath.Join(directory, "jwks.json"), encoded)
}

func (s *server) ownedAppJWKS(ctx context.Context, m AppManifest, resourceID string, preview bool) (appJWKSBundle, error) {
	var empty appJWKSBundle
	realm := "app-" + hashBytes([]byte(m.ID))[:24]
	if preview {
		realm += "-preview"
	}
	issuer := strings.TrimRight(env("AUTH_ORIGIN", ""), "/") + "/realms/" + realm
	var policy identityPolicyState
	if readEncrypted(filepath.Join(s.data, "identity-policies", realm+".enc"), &policy) != nil || policy.AppID != m.ID || policy.Realm != realm || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(policy.Hash) {
		return empty, errors.New("Owned app identity policy is unavailable")
	}
	var scope resources
	if readEncrypted(filepath.Join(s.data, "resources", resourceID+".enc"), &scope) != nil || scope.AppID != resourceID || scope.Issuer != issuer || scope.Audience != "app-"+m.ID || scope.Secrets != filepath.Join(s.data, "secrets", resourceID) {
		return empty, errors.New("Stored app issuer and credential scope do not match")
	}
	base := strings.TrimRight(env("KEYCLOAK_INTERNAL_URL", "https://keycloak:8443"), "/")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return empty, errors.New("A configured HTTPS identity authority is required")
	}
	client := s.client
	if client == nil {
		client, err = internalClient(os.Getenv("KEYCLOAK_CA_FILE"))
		if err != nil {
			return empty, err
		}
	}
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	credential, err := secret("KEYCLOAK_CLIENT_SECRET")
	if err != nil {
		return empty, err
	}
	tokenRealm := env("KEYCLOAK_PROVISIONER_REALM", "master")
	if !identity.MatchString(tokenRealm) {
		return empty, errors.New("Invalid identity provisioner realm")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {env("KEYCLOAK_CLIENT_ID", "autosoft-provisioner")}, "client_secret": {credential}}
	request, _ := http.NewRequestWithContext(ctx, "POST", base+"/realms/"+tokenRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := safeClient.Do(request)
	if err != nil {
		return empty, errors.New("Identity ownership verification is unavailable")
	}
	defer response.Body.Close()
	var token struct {
		Value string `json:"access_token"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 65536))
	if response.StatusCode != 200 || decoder.Decode(&token) != nil || decoder.Decode(new(any)) != io.EOF || token.Value == "" {
		return empty, errors.New("Identity ownership verification credentials are unavailable")
	}
	if _, err = ownedIdentityRealm(ctx, &safeClient, base, token.Value, realm, m.ID, policy.Hash, false); err != nil {
		return empty, err
	}
	return fetchAppJWKS(ctx, &safeClient, base, realm, m.ID, resourceID, issuer)
}

func (s *server) startApplicationJWKSRefresh(ctx context.Context, interval time.Duration) <-chan struct{} {
	if interval <= 0 || interval > 15*time.Minute {
		interval = 5 * time.Minute
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			s.reconcileApplicationJWKS(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func (s *server) reconcileApplicationJWKS(ctx context.Context) []appJWKSRefreshResult {
	unlock := s.lock("jwks-refresh-pass")
	defer unlock()
	type target struct {
		appID   string
		preview bool
	}
	targets := map[string]target{}
	results := []appJWKSRefreshResult{}
	entries, err := os.ReadDir(filepath.Join(s.data, "active"))
	if err != nil && !os.IsNotExist(err) {
		results = append(results, appJWKSRefreshResult{Target: "published", Status: "unavailable", Detail: "Published app discovery is unavailable"})
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && identity.MatchString(id) {
			targets[id] = target{id, false}
		}
	}
	output, err := s.runner(ctx, "docker", "ps", "--all", "--filter", "label=io.autosoft.managed=true", "--format", "{{json .}}")
	if err != nil {
		results = append(results, appJWKSRefreshResult{Target: "preview", Status: "unavailable", Detail: "Preview app discovery is unavailable"})
	} else {
		for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
			if line == "" {
				continue
			}
			var row struct{ Names string }
			if json.Unmarshal([]byte(line), &row) != nil {
				results = append(results, appJWKSRefreshResult{Target: "preview", Status: "unavailable", Detail: "Preview app discovery returned invalid evidence"})
				break
			}
			id := strings.TrimPrefix(row.Names, "as-preview-")
			if strings.HasPrefix(row.Names, "as-preview-") && identity.MatchString(id) && identity.MatchString(id+"_preview") {
				targets[id+"_preview"] = target{id, true}
			}
		}
	}
	ids := []string{}
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		target := targets[id]
		unlockApp := s.lock("app-" + target.appID)
		appCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		result := s.reconcileAppJWKS(appCtx, target.appID, target.preview)
		cancel()
		unlockApp()
		results = append(results, result)
	}
	if err = atomicJSON(filepath.Join(s.data, "reports", "jwks-refresh-report.json"), map[string]any{"checkedAt": time.Now().UTC().Format(time.RFC3339), "maxAgeSeconds": 3600, "results": results}); err != nil {
		results = append(results, appJWKSRefreshResult{Target: "report", Status: "unavailable", Detail: "Signing-key refresh report could not be persisted"})
	}
	return results
}

func (s *server) previewJWKSRoute(ctx context.Context, appID, host, container string) (bool, error) {
	if s.routeProbe != nil {
		return s.routeProbe(ctx, "preview-"+appID, host, container)
	}
	client := caddyClient(env("CADDY_ADMIN_SOCKET_FILE", "/run/caddy/admin.sock"))
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/config/apps/http/servers/"+env("CADDY_SERVER_NAME", "apps")+"/routes", nil)
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return false, errors.New("Preview route proof is unavailable")
	}
	var routes []map[string]any
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	if decoder.Decode(&routes) != nil {
		return false, errors.New("Preview route proof is invalid")
	}
	for _, route := range routes {
		if route["@id"] != "autosoft-app-preview-"+appID {
			continue
		}
		return exactPreviewJWKSRoute(route, appID, host, container), nil
	}
	return false, nil
}

func expectedPreviewJWKSRoute(appID, host, container string) map[string]any {
	gate := controlProxy()
	gate["rewrite"] = map[string]string{"method": "GET", "uri": "/api/auth/check"}
	gate["handle_response"] = []map[string]any{{"match": map[string]any{"status_code": []int{2}}, "routes": []map[string]any{{"handle": []map[string]any{{"handler": "headers", "request": map[string]any{"delete": []string{"X-Auth-User"}}}}}}}}
	setHost := map[string]any{"handler": "headers", "request": map[string]any{"set": map[string][]string{"X-Autosoft-Preview-Host": {host}}}}
	headers := map[string]any{"delete": []string{"X-Auth-User", "X-Auth-Roles", "X-Platform-Owner", "X-Autosoft-Preview-Host"}, "replace": map[string]any{"Cookie": []map[string]string{{"search_regexp": `(?:^|;\s*)(?:__Host-autosoft-preview|__Host-autosoft-session|__Host-autosoft-oauth-state|autosoft_session)=[^;]*`, "replace": ""}}}}
	final := map[string]any{"handler": "reverse_proxy", "upstreams": []map[string]string{{"dial": container + ":8080"}}, "headers": map[string]any{"request": headers}, "transport": map[string]any{"protocol": "http", "tls": map[string]any{"server_name": appTLSHost(appID + "_preview"), "ca": map[string]any{"provider": "file", "pem_files": []string{env("CADDY_INTERNAL_CA_FILE", "/etc/autosoft/ca.crt")}}}}}
	exchange := map[string]any{"match": []map[string]any{{"path": []string{"/__autosoft/preview"}}}, "handle": []map[string]any{setHost, {"handler": "rewrite", "uri": "/api/auth/preview/exchange?{http.request.uri.query}"}, controlProxy()}, "terminal": true}
	return map[string]any{"@id": "autosoft-app-preview-" + appID, "match": []map[string]any{{"host": []string{host}}}, "handle": []map[string]any{{"handler": "subroute", "routes": []map[string]any{exchange, {"handle": []map[string]any{setHost, gate, final}}}}}, "terminal": true}
}
func exactPreviewJWKSRoute(route map[string]any, appID, host, container string) bool {
	actual, _ := json.Marshal(route)
	expected, _ := json.Marshal(expectedPreviewJWKSRoute(appID, host, container))
	return bytes.Equal(actual, expected)
}

func (s *server) jwksTarget(ctx context.Context, appID string, preview bool) (tlsContainer, AppManifest, string, error) {
	var manifest AppManifest
	resourceID, name, image := appID, "", ""
	if preview {
		resourceID += "_preview"
		name = "as-preview-" + appID
	} else {
		var active activeDeployment
		if readBoundedJSON(filepath.Join(s.data, "active", appID+".json"), &active) != nil {
			return tlsContainer{}, manifest, resourceID, errors.New("Published app state is unavailable")
		}
		name, image = active.Container, active.Image
		if !identity.MatchString(active.ReleaseID) || len(active.ReleaseID) < 8 || name != "as-app-"+appID+"-"+active.ReleaseID[:8] {
			return tlsContainer{}, manifest, resourceID, errors.New("Published app container identity is invalid")
		}
		_, _, m, err := s.publicationReceipt(observationRequest{ID: "jwks-refresh", AppID: appID, ReleaseID: active.ReleaseID, Hash: active.Hash, Images: []string{active.Image}, OperationID: active.OperationID})
		if err != nil {
			return tlsContainer{}, manifest, resourceID, err
		}
		manifest = m
	}
	container, err := s.inspectTLSContainer(ctx, name, appID, resourceID, image)
	if err != nil {
		return container, manifest, resourceID, err
	}
	if preview {
		entries, err := os.ReadDir(filepath.Join(s.data, "receipts"))
		if err != nil || len(entries) > 10000 {
			return container, manifest, resourceID, errors.New("Preview verification proof is unavailable")
		}
		found := false
		for _, entry := range entries {
			var verified Verification
			if entry.IsDir() || readBoundedJSON(filepath.Join(s.data, "receipts", entry.Name()), &verified) != nil || verified.AppID != appID || verified.Evidence.Status != "passed" || !reflect.DeepEqual(verified.Images, []string{container.Config.Image}) || !identity.MatchString(verified.AttemptID) {
				continue
			}
			source, err := safePath(filepath.Join(s.data, "sources"), verified.AttemptID)
			if err != nil {
				continue
			}
			digest, err := sourceDigest(source)
			if err == nil && digest == verified.SourceHash && readBoundedJSON(filepath.Join(source, "app.manifest.json"), &manifest) == nil && validateApp(manifest, appID, verified.Template) == nil {
				found = true
				break
			}
		}
		if !found {
			return container, manifest, resourceID, errors.New("Exact protected preview source is unavailable")
		}
	}
	host := manifest.Slug + "." + s.appsHost()
	var matched bool
	if preview {
		matched, err = s.previewJWKSRoute(ctx, appID, "preview-"+host, name)
	} else {
		matched, err = s.routeMatches(ctx, appID, host, name)
	}
	if err != nil || !matched {
		return container, manifest, resourceID, errors.New("Actual app route no longer matches signing-key maintenance scope")
	}
	return container, manifest, resourceID, nil
}

func (s *server) reconcileAppJWKS(ctx context.Context, appID string, preview bool) appJWKSRefreshResult {
	result := appJWKSRefreshResult{AppID: appID, Target: "published", Status: "unavailable"}
	if preview {
		result.Target = "preview"
	}
	container, manifest, resourceID, err := s.jwksTarget(ctx, appID, preview)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	directory, err := safePath(filepath.Join(s.data, "secrets"), resourceID)
	if err != nil {
		result.Detail = "Signing-key credential scope is invalid"
		return result
	}
	realm := "app-" + hashBytes([]byte(appID))[:24]
	if preview {
		realm += "-preview"
	}
	issuer := strings.TrimRight(env("AUTH_ORIGIN", ""), "/") + "/realms/" + realm
	var old appJWKSBundle
	oldErr := readBoundedJSON(filepath.Join(directory, "jwks.json"), &old)
	if oldErr == nil && validAppJWKSBundle(old, appID, resourceID, issuer, false) {
		result.CheckedAt = old.Metadata.CheckedAt
		result.ValidUntil = old.Metadata.ValidUntil
	} else {
		old = appJWKSBundle{}
	}
	stopFile := filepath.Join(s.data, "jwks-stops", resourceID+".json")
	var stopped appJWKSStop
	stopErr := readBoundedJSON(stopFile, &stopped)
	stopOwned := stopErr == nil && stopped.Version == 1 && stopped.AppID == appID && stopped.ResourceID == resourceID && stopped.ContainerID == container.ID && stopped.Image == container.Config.Image && stopped.Issuer == issuer && (stopped.Phase == "stopping" || stopped.Phase == "stopped" || stopped.Phase == "resuming")
	if stopErr == nil && !stopOwned && stopped.Phase != "resumed" {
		result.Detail = "Signing-key stop belongs to a replaced container; company reconciliation is required"
		return result
	}
	if stopErr != nil && !os.IsNotExist(stopErr) {
		result.Detail = "Signing-key stop receipt is unavailable"
		return result
	}
	// Stop known stale cached verifiers before waiting on a potentially unavailable
	// identity authority. A recorded stop remains bound to the immutable container.
	if !validAppJWKSBundle(old, appID, resourceID, issuer, true) && container.State.Running {
		stopped, err = s.stopStaleJWKS(container, appID, resourceID, issuer, stopFile)
		if err != nil {
			result.Detail = "Expired signing-key evidence could not safely stop the exact app; company attention is required"
			return result
		}
		stopOwned = true
		container.State.Running = false
	}
	candidate, refreshErr := s.ownedAppJWKS(ctx, manifest, resourceID, preview)
	if refreshErr != nil {
		result.Detail = "Owned issuer signing-key refresh is unavailable; previous evidence is retained"
		if (!validAppJWKSBundle(old, appID, resourceID, issuer, true) || errors.Is(refreshErr, changedIdentityPolicy)) && container.State.Running {
			stopped, err = s.stopStaleJWKS(container, appID, resourceID, issuer, stopFile)
			if err != nil {
				result.Detail = "Signing-key evidence is stale and the exact app could not be stopped; company attention is required"
				return result
			}
			result.Status = "stopped_stale"
			result.Detail = "Expired signing-key evidence stopped only this exact managed app; it resumes after an owned issuer refresh and health verification"
		} else if stopOwned {
			result.Status = "stopped_stale"
		} else if !container.State.Running {
			result.Status = "not_running"
		} else {
			result.Status = "degraded"
		}
		return result
	}
	result.CheckedAt, result.ValidUntil = candidate.Metadata.CheckedAt, candidate.Metadata.ValidUntil
	journalFile := filepath.Join(s.data, "jwks-rotations", resourceID+".json")
	var journal appJWKSJournal
	journalErr := readBoundedJSON(journalFile, &journal)
	pending := journalErr == nil && (journal.Phase == "prepared" || journal.Phase == "installed")
	if pending && (journal.Version != 1 || journal.AppID != appID || journal.ResourceID != resourceID || journal.ContainerID != container.ID || journal.Image != container.Config.Image || journal.Issuer != issuer) {
		result.Detail = "Interrupted key refresh belongs to another container or issuer"
		return result
	}
	if journalErr != nil && !os.IsNotExist(journalErr) {
		result.Detail = "Signing-key recovery record is unavailable"
		return result
	}
	if pending && validAppJWKSBundle(journal.Old, appID, resourceID, issuer, false) {
		old = journal.Old
	}
	changed := old.Metadata.KeysHash != candidate.Metadata.KeysHash || pending
	if (changed || stopOwned) && (container.State.Running || stopOwned) {
		journal = appJWKSJournal{Version: 1, AppID: appID, ResourceID: resourceID, ContainerID: container.ID, Image: container.Config.Image, Issuer: issuer, Phase: "prepared", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Old: old, Candidate: candidate}
		if atomicJSON(journalFile, journal) != nil {
			result.Detail = "Durable signing-key recovery record cannot be written"
			return result
		}
	}
	if err = installAppJWKS(directory, candidate); err != nil {
		result.Detail = "Atomic signing-key installation failed"
		return result
	}
	if !container.State.Running && !stopOwned {
		result.Status = "not_running"
		result.Detail = "Scoped signing keys refreshed; a manually stopped app was not started"
		return result
	}
	if changed || stopOwned {
		journal.Phase = "installed"
		journal.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if changed && atomicJSON(journalFile, journal) != nil {
			result.Detail = "Installed keys await durable reload reconciliation"
			return result
		}
		if stopOwned {
			stopped.Phase = "resuming"
			if atomicJSON(stopFile, stopped) != nil {
				result.Detail = "Safe automatic app resume cannot be recorded"
				return result
			}
		}
		if _, err = s.runner(ctx, "docker", "restart", "--time", "45", container.ID); err == nil {
			err = s.healthy(ctx, container.ID, manifest)
		}
		if err != nil {
			return s.restoreAppJWKS(directory, journalFile, stopFile, journal, stopped, stopOwned, manifest, result)
		}
		if changed {
			journal.Phase = "completed"
			journal.Old = appJWKSBundle{}
			journal.Candidate = appJWKSBundle{}
			if atomicJSON(journalFile, journal) != nil {
				result.Detail = "App reload is healthy but its completion receipt is unavailable"
				return result
			}
		}
		if stopOwned {
			stopped.Phase = "resumed"
			if atomicJSON(stopFile, stopped) != nil {
				result.Detail = "App is healthy but safe-resume receipt is unavailable"
				return result
			}
		}
		result.Status = "refreshed"
		result.Detail = "Owned issuer keys refreshed and only the exact managed container was reloaded and health verified"
		return result
	}
	result.Status = "current"
	result.Detail = "Owned issuer signing keys are unchanged and freshness was renewed without restarting the app"
	return result
}

func (s *server) stopStaleJWKS(container tlsContainer, appID, resourceID, issuer, file string) (appJWKSStop, error) {
	stopped := appJWKSStop{Version: 1, AppID: appID, ResourceID: resourceID, ContainerID: container.ID, Image: container.Config.Image, Issuer: issuer, Phase: "stopping", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := atomicJSON(file, stopped); err != nil {
		return stopped, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := s.runner(ctx, "docker", "stop", "--time", "45", container.ID); err != nil {
		return stopped, err
	}
	verified, err := s.inspectTLSContainer(ctx, strings.TrimPrefix(container.Name, "/"), appID, resourceID, container.Config.Image)
	if err != nil || verified.ID != container.ID || verified.State.Running {
		return stopped, errors.New("The exact managed app stop cannot be independently verified")
	}
	stopped.Phase = "stopped"
	return stopped, atomicJSON(file, stopped)
}

func (s *server) restoreAppJWKS(directory, journalFile, stopFile string, journal appJWKSJournal, stopped appJWKSStop, stopOwned bool, manifest AppManifest, result appJWKSRefreshResult) appJWKSRefreshResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if validAppJWKSBundle(journal.Old, journal.AppID, journal.ResourceID, journal.Issuer, true) && !stopOwned {
		if installAppJWKS(directory, journal.Old) == nil {
			if _, err := s.runner(ctx, "docker", "restart", "--time", "45", journal.ContainerID); err == nil && s.healthy(ctx, journal.ContainerID, manifest) == nil && validAppJWKSBundle(journal.Old, journal.AppID, journal.ResourceID, journal.Issuer, true) {
				journal.Phase = "rolled_back"
				journal.Candidate = appJWKSBundle{}
				_ = atomicJSON(journalFile, journal)
				result.Status = "degraded"
				result.CheckedAt = journal.Old.Metadata.CheckedAt
				result.ValidUntil = journal.Old.Metadata.ValidUntil
				result.Detail = "New signing keys failed app health; the prior still-fresh keys were restored to the exact container"
				return result
			}
		}
	}
	// Never keep a cached stale verifier serving when refresh/reload cannot be proved.
	if !stopOwned {
		stopped = appJWKSStop{Version: 1, AppID: journal.AppID, ResourceID: journal.ResourceID, ContainerID: journal.ContainerID, Image: journal.Image, Issuer: journal.Issuer, Phase: "stopping", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	} else {
		stopped.Phase = "stopping"
	}
	if atomicJSON(stopFile, stopped) == nil {
		if _, err := s.runner(ctx, "docker", "stop", "--time", "45", journal.ContainerID); err == nil {
			stopped.Phase = "stopped"
			_ = atomicJSON(stopFile, stopped)
			result.Status = "stopped_stale"
			result.Detail = "Key reload health failed; the exact managed app was stopped for safe retry"
			return result
		}
	}
	result.Detail = "Key reload and safe-stop evidence are unavailable; company attention is required"
	return result
}
