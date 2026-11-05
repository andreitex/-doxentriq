package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
)

type resources struct {
	AppID                string            `json:"appId"`
	Database             string            `json:"database"`
	User                 string            `json:"user"`
	Password             string            `json:"password"`
	MySQLGrantVersion    int               `json:"mysqlGrantVersion,omitempty"`
	MySQLGrantVerified   bool              `json:"mysqlGrantVerified,omitempty"`
	RedisPassword        string            `json:"redisPassword"`
	RabbitPassword       string            `json:"rabbitPassword"`
	Network              string            `json:"network"`
	Secrets              string            `json:"secrets"`
	Schema               int               `json:"schema"`
	Issuer               string            `json:"issuer"`
	Audience             string            `json:"audience"`
	Applied              map[string]string `json:"applied"`
	StorageHost          string            `json:"storageHost,omitempty"`
	StorageContainer     string            `json:"storageContainer,omitempty"`
	ConnectorResourceID  string            `json:"connectorResourceId,omitempty"`
	ConnectorSecrets     string            `json:"connectorSecrets,omitempty"`
	ConnectorHostSecrets string            `json:"connectorHostSecrets,omitempty"`
}

func randomSecret() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func vaultKey() ([]byte, error) {
	v, e := secret("BROKER_VAULT_KEY")
	if e != nil {
		return nil, e
	}
	k, e := base64.StdEncoding.DecodeString(v)
	if e != nil || len(k) != 32 {
		return nil, errors.New("Broker vault key must contain 32 bytes")
	}
	return k, nil
}
func writeEncrypted(file string, v any) error {
	k, e := vaultKey()
	if e != nil {
		return e
	}
	c, e := aes.NewCipher(k)
	if e != nil {
		return e
	}
	a, e := cipher.NewGCM(c)
	if e != nil {
		return e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	sealed := a.Seal(nonce, nonce, b, []byte(filepath.Base(file)))
	if e = os.MkdirAll(filepath.Dir(file), 0700); e != nil {
		return e
	}
	tmp := file + ".new"
	if e = os.WriteFile(tmp, sealed, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, file)
}
func readEncrypted(file string, v any) error {
	b, e := os.ReadFile(file)
	if e != nil {
		return e
	}
	k, e := vaultKey()
	if e != nil {
		return e
	}
	c, e := aes.NewCipher(k)
	if e != nil {
		return e
	}
	a, e := cipher.NewGCM(c)
	if e != nil {
		return e
	}
	if len(b) < a.NonceSize() {
		return errors.New("Invalid encrypted resource state")
	}
	plain, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(filepath.Base(file)))
	if e != nil {
		return e
	}
	return json.Unmarshal(plain, v)
}

var mysqlTLSOnce sync.Once
var mysqlTLSError error

func rootTLS(file string) (*tls.Config, error) {
	b, e := os.ReadFile(file)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("Invalid internal TLS trust material")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
func mysqlConnection() (*sql.DB, error) {
	password, e := secret("MYSQL_PROVISIONER_PASSWORD")
	if e != nil {
		password, e = secret("MYSQL_PASSWORD")
	}
	if e != nil {
		return nil, e
	}
	return mysqlConnectionAs(env("MYSQL_USER", "provisioner"), password)
}
func mysqlConnectionAs(user, password string) (*sql.DB, error) {
	mysqlTLSOnce.Do(func() {
		cfg, e := rootTLS(os.Getenv("MYSQL_CA_FILE"))
		if e != nil {
			mysqlTLSError = e
			return
		}
		mysqlTLSError = mysql.RegisterTLSConfig("autosoft-verified", cfg)
	})
	if mysqlTLSError != nil {
		return nil, mysqlTLSError
	}
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(env("MYSQL_HOST", "mysql"), env("MYSQL_PORT", "3306"))
	cfg.TLSConfig = "autosoft-verified"
	cfg.Timeout = 15 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.MultiStatements = false
	cfg.ParseTime = true
	return sql.Open("mysql", cfg.FormatDSN())
}
func (s *server) provision(ctx context.Context, appID string, manifest AppManifest, preview bool) (resources, error) {
	var v resources
	if !applicationSQLResource.MatchString(appID) {
		return v, errors.New("Application database resource identity is invalid")
	}
	file := filepath.Join(s.data, "resources", appID+".enc")
	e := readEncrypted(file, &v)
	if e != nil && !os.IsNotExist(e) {
		return v, e
	}
	if os.IsNotExist(e) {
		suffix := hashBytes([]byte(appID))[:24]
		v = resources{AppID: appID, Database: "app_" + suffix, User: "app_" + suffix, Password: randomSecret(), MySQLGrantVersion: mysqlGrantPolicyVersion, RedisPassword: randomSecret(), RabbitPassword: randomSecret(), Network: "autosoft_app_" + suffix, Secrets: filepath.Join(s.data, "secrets", appID), Schema: 1, Applied: map[string]string{}}
		// Retain the exact initial account/password intent before SQL creation.
		if e = retainApplicationSQLResources(file, v); e != nil {
			return v, e
		}
	}
	if v.AppID != appID {
		return v, errors.New("Stored application database resource identity differs")
	}
	if e = applicationSQLNames(appID, v.Database, v.User); e != nil {
		return v, e
	}
	if !applicationSQLPassword.MatchString(v.Password) {
		return v, errors.New("Stored application database credential format is invalid")
	}
	db, e := mysqlConnection()
	if e != nil {
		return v, e
	}
	defer db.Close()
	account := applicationSQLAccount{ResourceID: appID, Database: v.Database, User: v.User, Password: v.Password, Version: v.MySQLGrantVersion, Verified: v.MySQLGrantVerified}
	if e = ensureApplicationSQLGrants(ctx, db, account, func() (*sql.DB, error) {
		return mysqlConnectionAs(v.User, v.Password)
	}, func() error {
		v.MySQLGrantVersion = mysqlGrantPolicyVersion
		v.MySQLGrantVerified = true
		return retainApplicationSQLResources(file, v)
	}); e != nil {
		return v, e
	}
	if e = s.redisACL(ctx, v); e != nil {
		return v, e
	}
	if e = s.rabbitScope(ctx, v); e != nil {
		return v, e
	}
	{
		issuer, audience, jwks, e := s.appIdentity(ctx, manifest, preview)
		if e != nil {
			return v, e
		}
		v.Issuer = issuer
		v.Audience = audience
		if e = os.MkdirAll(v.Secrets, 0700); e != nil {
			return v, e
		}
		if e = atomicTLSFile(filepath.Join(v.Secrets, "jwks.json"), jwks); e != nil {
			return v, e
		}
	}
	if e = s.appNetwork(ctx, v.Network); e != nil {
		return v, e
	}
	if len(manifest.Storage) == 1 {
		storageName := manifest.Storage[0].Name
		if preview {
			storageName = "preview-" + storageName
		}
		host, container, e := s.quotaStorage(ctx, manifest.ID, storageName, manifest.Storage[0].MaxMB)
		if e != nil {
			return v, e
		}
		v.StorageHost = host
		v.StorageContainer = container
	}
	if e = os.MkdirAll(v.Secrets, 0700); e != nil {
		return v, e
	}
	secrets := map[string]string{"mysql-password": v.Password, "redis-password": v.RedisPassword, "rabbitmq-password": v.RabbitPassword}
	for name, value := range secrets {
		file := filepath.Join(v.Secrets, name)
		if e = os.WriteFile(file, []byte(value), 0400); e != nil {
			return v, e
		}
	}
	ca, e := os.ReadFile(os.Getenv("MYSQL_CA_FILE"))
	if e != nil {
		return v, e
	}
	if e = os.WriteFile(filepath.Join(v.Secrets, "ca.crt"), ca, 0400); e != nil {
		return v, e
	}
	if e = issueAppTLS(v.Secrets, v.AppID); e != nil {
		return v, e
	}
	if e = ownership(v.Secrets); e != nil {
		return v, e
	}
	if e = writeEncrypted(file, v); e != nil {
		return v, e
	}
	return v, nil
}
func (s *server) appNetwork(ctx context.Context, network string) error {
	if _, e := s.runner(ctx, "docker", "network", "inspect", network); e != nil {
		if _, e = s.runner(ctx, "docker", "network", "create", "--internal", "--driver", "bridge", "--label", "io.autosoft.managed=true", network); e != nil {
			return e
		}
	}
	for _, service := range []string{"mysql", "redis", "rabbitmq", "caddy"} {
		out, e := s.runner(ctx, "docker", "ps", "--filter", "label=com.docker.compose.project=autosoft", "--filter", "label=com.docker.compose.service="+service, "--format", "{{.ID}}")
		if e != nil {
			return e
		}
		id := strings.TrimSpace(out)
		if !regexpDockerID(id) {
			return errors.New("Required private infrastructure service is unavailable")
		}
		if _, e = s.runner(ctx, "docker", "network", "connect", "--alias", service, network, id); e != nil {
			inspect, e2 := s.runner(ctx, "docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", id)
			if e2 != nil || !strings.Contains(inspect, `"`+network+`"`) {
				return e
			}
		}
	}
	return s.attachDirectoryControl(ctx, network)
}
func regexpDockerID(value string) bool {
	if len(value) < 12 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func (s *server) redisACL(ctx context.Context, v resources) error {
	tlsConfig, e := rootTLS(os.Getenv("REDIS_CA_FILE"))
	if e != nil {
		return e
	}
	tlsConfig.ServerName = "redis"
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, e := tls.DialWithDialer(dialer, "tcp", "redis:6379", tlsConfig)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	password, e := secret("REDIS_ADMIN_PASSWORD")
	if e != nil {
		password, e = secret("REDIS_PASSWORD")
	}
	if e != nil {
		return e
	}
	send := func(parts ...string) error {
		var b strings.Builder
		fmt.Fprintf(&b, "*%d\r\n", len(parts))
		for _, p := range parts {
			fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
		}
		if _, e := io.WriteString(conn, b.String()); e != nil {
			return e
		}
		response := make([]byte, 4096)
		n, e := conn.Read(response)
		if e != nil {
			return e
		}
		if n == 0 || response[0] != '+' {
			return errors.New("Scoped Redis ACL provisioning failed")
		}
		return nil
	}
	if e = send("AUTH", env("REDIS_USER", "provisioner"), password); e != nil {
		return e
	}
	if e = send("ACL", "SETUSER", v.User, "reset", "on", ">"+v.RedisPassword, "~app:"+v.AppID+":*", "&app:"+v.AppID+":*", "+@read", "+@write", "+@connection", "-@dangerous", "+publish", "+subscribe", "+psubscribe"); e != nil {
		return e
	}
	return send("ACL", "SAVE")
}
func internalClient(caFile string) (*http.Client, error) {
	cfg, e := rootTLS(caFile)
	if e != nil {
		return nil, e
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}
func (s *server) rabbitScope(ctx context.Context, v resources) error {
	client, e := internalClient(os.Getenv("RABBITMQ_CA_FILE"))
	if e != nil {
		return e
	}
	password, e := secret("RABBITMQ_ADMIN_PASSWORD")
	if e != nil {
		return e
	}
	base := env("RABBITMQ_MANAGEMENT_URL", "https://rabbitmq:15671")
	for _, operation := range []struct {
		Path string
		Body any
	}{{"/api/vhosts/" + url.PathEscape(v.Database), map[string]any{}}, {"/api/users/" + v.User, map[string]any{"password": v.RabbitPassword, "tags": ""}}, {"/api/permissions/" + url.PathEscape(v.Database) + "/" + v.User, map[string]string{"configure": "^app\\..*", "write": "^app\\..*", "read": "^app\\..*"}}} {
		b, _ := json.Marshal(operation.Body)
		request, e := http.NewRequestWithContext(ctx, "PUT", base+operation.Path, bytes.NewReader(b))
		if e != nil {
			return e
		}
		request.SetBasicAuth(env("RABBITMQ_ADMIN_USER", "provisioner"), password)
		request.Header.Set("Content-Type", "application/json")
		response, e := client.Do(request)
		if e != nil {
			return e
		}
		_ = response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode > 299 {
			return errors.New("Scoped RabbitMQ provisioning failed")
		}
	}
	return nil
}
func (s *server) rehearse(ctx context.Context, v resources, migrations []Migration) error {
	return s.applyMigrations(ctx, &v, migrations)
}

func (s *server) quotaStorage(ctx context.Context, appID, name string, size int) (string, string, error) {
	if !identity.MatchString(appID) || !identity.MatchString(name) || size < 1 || size > 32768 {
		return "", "", errors.New("Invalid storage quota request")
	}
	token, e := secret("QUOTA_HELPER_TOKEN")
	if e != nil {
		return "", "", e
	}
	client := caddyClient(env("QUOTA_HELPER_SOCKET_FILE", "/run/autosoft/quota.sock"))
	body, _ := json.Marshal(map[string]any{"appId": appID, "name": name, "sizeMb": size})
	request, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/v1/storage", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, e := client.Do(request)
	if e != nil {
		return "", "", errors.New("Host storage quota enforcement is unavailable")
	}
	defer response.Body.Close()
	var result struct {
		Host      string `json:"hostPath"`
		Container string `json:"containerPath"`
		Enforced  bool   `json:"quotaEnforced"`
		Size      int    `json:"sizeMb"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) != nil || !result.Enforced || result.Size != size || result.Host != filepath.Join(s.hostRuntime, "storage", appID, name) || result.Container != filepath.Join(s.data, "storage", appID, name) {
		return "", "", errors.New("Host helper did not verify the exact scoped hard quota")
	}
	return result.Host, result.Container, nil
}
func (s *server) applyMigrations(ctx context.Context, v *resources, migrations []Migration) error {
	db, e := mysqlConnection()
	if e != nil {
		return e
	}
	defer db.Close()
	conn, e := db.Conn(ctx)
	if e != nil {
		return e
	}
	defer conn.Close()
	if _, e = conn.ExecContext(ctx, "USE `"+v.Database+"`"); e != nil {
		return e
	}
	if _, e = conn.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS _autosoft_migrations (id VARCHAR(80) PRIMARY KEY, checksum CHAR(64) NOT NULL, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP) ENCRYPTION='Y'"); e != nil {
		return e
	}
	for _, m := range migrations {
		var checksum string
		e = conn.QueryRowContext(ctx, "SELECT checksum FROM _autosoft_migrations WHERE id=?", m.ID).Scan(&checksum)
		if e == nil {
			if checksum != m.Checksum {
				return errors.New("An applied migration was changed; create a new migration instead")
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e = validateSQL(m.SQL); e != nil {
			return e
		}
		for _, statement := range strings.Split(m.SQL, ";") {
			statement = strings.TrimSpace(statement)
			if statement != "" {
				if _, e = conn.ExecContext(ctx, statement); e != nil {
					return fmt.Errorf("Additive migration %s failed; partial MySQL DDL retained for inspection: %w", m.ID, e)
				}
			}
		}
		if _, e = conn.ExecContext(ctx, "INSERT INTO _autosoft_migrations (id,checksum) VALUES (?,?)", m.ID, m.Checksum); e != nil {
			return e
		}
		v.Applied[m.ID] = m.Checksum
	}
	return writeEncrypted(filepath.Join(s.data, "resources", v.AppID+".enc"), v)
}
func (s *server) appIdentity(ctx context.Context, m AppManifest, preview bool) (string, string, []byte, error) {
	realm := "app-" + hashBytes([]byte(m.ID))[:24]
	if preview {
		realm += "-preview"
	}
	unlock := s.lock("identity-" + realm)
	defer unlock()
	audience := "app-" + m.ID
	issuer := strings.TrimRight(env("AUTH_ORIGIN", ""), "/") + "/realms/" + realm
	origin := "https://" + m.Slug + "." + s.appsHost()
	if preview {
		origin = "https://preview-" + m.Slug + "." + s.appsHost()
	}
	policy, e := s.identityPolicy(m, realm, issuer, origin)
	if e != nil {
		return "", "", nil, e
	}
	client, e := internalClient(os.Getenv("KEYCLOAK_CA_FILE"))
	if e != nil {
		return "", "", nil, e
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	base := env("KEYCLOAK_INTERNAL_URL", "https://keycloak:8443")
	if parsed, err := url.Parse(base); err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", nil, errors.New("Identity provisioning requires an authenticated HTTPS authority")
	}
	clientSecret, e := secret("KEYCLOAK_CLIENT_SECRET")
	if e != nil {
		return "", "", nil, e
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {env("KEYCLOAK_CLIENT_ID", "autosoft-provisioner")}, "client_secret": {clientSecret}}
	tokenRealm := env("KEYCLOAK_PROVISIONER_REALM", "master")
	request, _ := http.NewRequestWithContext(ctx, "POST", base+"/realms/"+tokenRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := client.Do(request)
	if e != nil {
		return "", "", nil, e
	}
	defer response.Body.Close()
	var tokens struct {
		Token string `json:"access_token"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&tokens) != nil || tokens.Token == "" {
		return "", "", nil, errors.New("Trusted identity provisioner unavailable")
	}
	// Compare an existing realm before creating any broker client. A stale or
	// unowned realm never receives automatic access-policy changes.
	if _, e = ownedIdentityRealm(ctx, client, base, tokens.Token, realm, m.ID, policy.Hash, true); e != nil {
		return "", "", nil, e
	}
	roles := []map[string]string{}
	for _, permission := range m.Permissions {
		roles = append(roles, map[string]string{"name": permission})
	}
	// App invitations deliberately do not attest email ownership. Keep that
	// claim false without forcing an unavailable SMTP verification step.
	body := map[string]any{"realm": realm, "enabled": true, "registrationAllowed": false, "resetPasswordAllowed": true, "sslRequired": "all", "bruteForceProtected": true, "verifyEmail": false}
	mappers := func(aud string) []map[string]any {
		return []map[string]any{{"name": "app-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": map[string]string{"included.client.audience": aud, "access.token.claim": "true"}}, {"name": "app-identity", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper", "config": map[string]string{"claim.name": "app_id", "claim.value": m.ID, "jsonType.label": "String", "access.token.claim": "true", "id.token.claim": "true"}}, {"name": "app-subject", "protocol": "openid-connect", "protocolMapper": "oidc-sub-mapper", "config": map[string]string{"access.token.claim": "true", "introspection.token.claim": "true"}}}
	}
	appClient := map[string]any{"clientId": audience, "protocol": "openid-connect", "enabled": true, "publicClient": true, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "fullScopeAllowed": true, "redirectUris": []string{origin + "/auth/callback", origin + "/"}, "webOrigins": []string{origin}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "defaultClientScopes": []string{"roles", "profile", "email"}, "protocolMappers": mappers(audience)}
	mcpClient := map[string]any{"clientId": m.ID + ":mcp", "protocol": "openid-connect", "enabled": true, "publicClient": true, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "fullScopeAllowed": true, "redirectUris": []string{origin + "/auth/callback"}, "webOrigins": []string{origin}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}, "defaultClientScopes": []string{"roles", "profile", "email"}, "optionalClientScopes": []string{"dms.read", "dms.search"}, "protocolMappers": mappers(m.ID + ":mcp")}
	body["clients"] = []map[string]any{appClient, mcpClient}
	body["attributes"] = identityMarkers(m.ID, realm, policy.Hash)
	body["roles"] = map[string]any{"client": map[string]any{audience: roles}}
	body["clientScopes"] = appIdentityScopes(audience)
	if m.Auth == "sso" {
		brokerID := "platform-broker-" + realm
		brokerSecret := policy.BrokerSecret
		brokerRedirect := strings.TrimRight(env("AUTH_ORIGIN", ""), "/") + "/realms/" + realm + "/broker/company/endpoint"
		platformClient := map[string]any{"clientId": brokerID, "protocol": "openid-connect", "secret": brokerSecret, "enabled": true, "publicClient": false, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "redirectUris": []string{brokerRedirect}, "defaultClientScopes": []string{"profile", "email"}, "optionalClientScopes": []string{}, "attributes": identityMarkers(m.ID, realm, policy.Hash)}
		platformToken, e := platformIdentityToken(ctx, client, base)
		if e != nil {
			return "", "", nil, e
		}
		if e = createOwnedIdentityBroker(ctx, client, base, platformToken, platformClient, m.ID, realm, policy.Hash, brokerID, brokerRedirect, brokerSecret); e != nil {
			return "", "", nil, e
		}
		body["identityProviders"] = []map[string]any{{"alias": "company", "providerId": "keycloak-oidc", "enabled": true, "trustEmail": true, "storeToken": false, "addReadTokenRoleOnCreate": false, "config": map[string]string{"clientId": brokerID, "clientSecret": brokerSecret, "issuer": strings.TrimRight(env("AUTH_ORIGIN", ""), "/") + "/realms/platform", "validateSignature": "true", "authorizationUrl": strings.TrimRight(env("AUTH_ORIGIN", ""), "/") + "/realms/platform/protocol/openid-connect/auth", "tokenUrl": base + "/realms/platform/protocol/openid-connect/token", "userInfoUrl": base + "/realms/platform/protocol/openid-connect/userinfo", "jwksUrl": base + "/realms/platform/protocol/openid-connect/certs", "useJwksUrl": "true", "defaultScope": "openid profile email", "syncMode": "IMPORT"}}}
		body["registrationAllowed"] = false
	}
	if e = createOwnedIdentityRealm(ctx, client, base, tokens.Token, body, realm, m.ID, policy.Hash); e != nil {
		return "", "", nil, e
	}
	resourceID := m.ID
	if preview {
		resourceID += "_preview"
	}
	bundle, e := fetchAppJWKS(ctx, client, base, realm, m.ID, resourceID, issuer)
	if e != nil {
		return "", "", nil, e
	}
	jwks, e := json.Marshal(bundle)
	return issuer, audience, jwks, e
}

func platformIdentityToken(ctx context.Context, client *http.Client, base string) (string, error) {
	secret, e := secret("KEYCLOAK_PLATFORM_CLIENT_SECRET")
	if e != nil {
		return "", e
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {env("KEYCLOAK_PLATFORM_CLIENT_ID", "platform-provisioner")}, "client_secret": {secret}}
	request, _ := http.NewRequestWithContext(ctx, "POST", base+"/realms/platform/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := client.Do(request)
	if e != nil {
		return "", e
	}
	defer response.Body.Close()
	var result struct {
		Token string `json:"access_token"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) != nil || result.Token == "" {
		return "", errors.New("Platform broker-client provisioning is unavailable")
	}
	return result.Token, nil
}
