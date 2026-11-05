package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var identity = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$`)
var digestImage = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)
var mandatoryStages = []string{"dependencies", "build", "application_tests", "security", "image_packaging", "preview", "migration_rehearsal", "acceptance"}

type Template struct {
	ToolchainImage string   `json:"toolchainImage"`
	RuntimeImage   string   `json:"runtimeImage"`
	Entrypoint     []string `json:"entrypoint"`
	Port           int      `json:"port"`
}
type RuntimeManifest struct {
	Version         int                 `json:"schemaVersion"`
	Templates       map[string]Template `json:"templates"`
	ScannerImage    string              `json:"scannerImage"`
	Registry        string              `json:"registry"`
	DependencyProxy string              `json:"dependencyProxy"`
	ServiceImages   map[string]string   `json:"serviceImages"`
}
type Stage struct {
	Name     string   `json:"name"`
	Commands []string `json:"commands"`
	Timeout  int      `json:"timeoutSeconds"`
}
type Pipeline struct {
	Version  int     `json:"schemaVersion"`
	Template string  `json:"template"`
	Stages   []Stage `json:"stages"`
}
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}
type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Package     string `json:"package"`
	Installed   string `json:"installedVersion"`
	Fixed       string `json:"fixedVersion,omitempty"`
	Source      string `json:"source"`
	Description string `json:"description"`
}
type Evidence struct {
	Status        string    `json:"status"`
	CheckedAt     string    `json:"checkedAt"`
	FeedUpdatedAt string    `json:"feedUpdatedAt"`
	Findings      []Finding `json:"findings"`
	Checks        []Check   `json:"checks"`
}
type Migration struct {
	ID          string `json:"id"`
	SQL         string `json:"sql,omitempty"`
	Destructive bool   `json:"destructive"`
	Impact      string `json:"impact"`
	Checksum    string `json:"checksum"`
}
type Verification struct {
	Evidence             Evidence                  `json:"evidence"`
	Images               []string                  `json:"images"`
	Commit               string                    `json:"commit"`
	PreviewURL           string                    `json:"previewUrl"`
	Schema               int                       `json:"schemaVersion"`
	SchemaMin            int                       `json:"compatibleSchemaMin"`
	SchemaMax            int                       `json:"compatibleSchemaMax"`
	Migrations           []Migration               `json:"migrations"`
	AppID                string                    `json:"appId,omitempty"`
	AttemptID            string                    `json:"attemptId,omitempty"`
	FilesHash            string                    `json:"filesHash,omitempty"`
	SourceBindingVersion int                       `json:"sourceBindingVersion,omitempty"`
	InputSourceHash      string                    `json:"inputSourceHash,omitempty"`
	PipelineHash         string                    `json:"pipelineHash,omitempty"`
	SourceHash           string                    `json:"sourceHash,omitempty"`
	Template             string                    `json:"template,omitempty"`
	MigrationSnapshot    *migrationSnapshotReceipt `json:"migrationSnapshot,omitempty"`
}
type AppManifest struct {
	Version     int      `json:"schemaVersion"`
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Template    string   `json:"template"`
	Auth        string   `json:"auth"`
	Connections []string `json:"connections"`
	Permissions []string `json:"permissions"`
	Resources   struct {
		CPU    float64 `json:"cpu"`
		Memory int     `json:"memoryMb"`
		Pids   int     `json:"pids"`
	} `json:"resources"`
	Health struct {
		Path string `json:"path"`
		Port int    `json:"port"`
	} `json:"health"`
	Storage []struct {
		Name  string `json:"name"`
		MaxMB int    `json:"maxMb"`
	} `json:"storage"`
}

type server struct {
	manifest            RuntimeManifest
	token               string
	approvalKey         []byte
	data                string
	workspace           string
	hostWorkspace       string
	hostRuntime         string
	runner              func(context.Context, string, ...string) (string, error)
	locks               sync.Map
	buildSlot           chan struct{}
	client              *http.Client
	routeProbe          func(context.Context, string, string, string) (bool, error)
	routeChange         func(context.Context, string, string, string, int, bool) error
	snapshotOpen        func(resources) (*sql.DB, error)
	snapshotAdminOpen   func() (*sql.DB, error)
	snapshotAuditorOpen func() (*sql.DB, error)
	imageScannerDocker  imageScannerDocker
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func secret(name string) (string, error) {
	if file := os.Getenv(name + "_FILE"); file != "" {
		b, e := os.ReadFile(file)
		if e != nil {
			return "", e
		}
		value := strings.TrimSpace(string(b))
		if value == "" {
			return "", fmt.Errorf("%s secret file is empty", name)
		}
		return value, nil
	}
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}
func fail(w http.ResponseWriter, code int, e error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
}
func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	if e := d.Decode(value); e != nil {
		fail(w, 400, errors.New("Invalid bounded JSON request"))
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, errors.New("Only one JSON value is accepted"))
		return false
	}
	return true
}
func (s *server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			fail(w, 405, errors.New("POST required"))
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || s.token == "" {
			fail(w, 401, errors.New("Runtime authentication required"))
			return
		}
		actual := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(actual) != len(s.token) || subtle.ConstantTimeCompare([]byte(actual), []byte(s.token)) != 1 {
			fail(w, 401, errors.New("Runtime authentication required"))
			return
		}
		next(w, r)
	}
}
func (s *server) lock(name string) func() {
	m, _ := s.locks.LoadOrStore(name, &sync.Mutex{})
	m.(*sync.Mutex).Lock()
	return m.(*sync.Mutex).Unlock
}
func run(ctx context.Context, name string, args ...string) (string, error) {
	if name != "docker" && name != "git" {
		return "", errors.New("Host executable is not approved")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var out boundedOutput
	out.limit = 2 << 20
	cmd.Stdout = &out
	cmd.Stderr = &out
	e := cmd.Run()
	if e != nil {
		return out.String(), fmt.Errorf("Trusted %s command failed: %w", name, e)
	}
	return out.String(), nil
}

type boundedOutput struct {
	data  []byte
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.data) < b.limit {
		remain := b.limit - len(b.data)
		if n > remain {
			p = p[:remain]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
func (b *boundedOutput) String() string { return string(b.data) }
func atomicJSON(file string, v any) error {
	if e := os.MkdirAll(filepath.Dir(file), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	tmp := file + ".new"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	f, e := os.OpenFile(tmp, os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = f.Sync()
	_ = f.Close()
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, file); e != nil {
		return e
	}
	// Linux directory fsync makes the receipt rename durable across a power loss.
	if os.PathSeparator == '/' {
		directory, err := os.Open(filepath.Dir(file))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	}
	return nil
}
func hashBytes(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func safePath(root string, parts ...string) (string, error) {
	for _, p := range parts {
		if !identity.MatchString(p) {
			return "", errors.New("Invalid scoped identity")
		}
	}
	candidate := filepath.Join(append([]string{root}, parts...)...)
	rel, e := filepath.Rel(root, candidate)
	if e != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", errors.New("Path escapes authorized root")
	}
	for cur := candidate; cur != filepath.Clean(root); cur = filepath.Dir(cur) {
		f, e := os.Lstat(cur)
		if e == nil && f.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("Symlink in authorized path")
		}
		if e != nil && !os.IsNotExist(e) {
			return "", e
		}
	}
	return candidate, nil
}
func main() {
	b, e := os.ReadFile(env("RUNTIME_MANIFEST_PATH", "/etc/autosoft/runtime-manifest.json"))
	if e != nil {
		log.Fatal(e)
	}
	var m RuntimeManifest
	if e = json.Unmarshal(b, &m); e != nil {
		log.Fatal(e)
	}
	if m.Version != 1 || len(m.Templates) == 0 {
		log.Fatal("Validated runtime manifest is required")
	}
	if e = validateServiceCatalog(m); e != nil {
		log.Fatal(e)
	}
	for _, t := range m.Templates {
		if !digestImage.MatchString(t.RuntimeImage) || !digestImage.MatchString(t.ToolchainImage) || len(t.Entrypoint) == 0 || t.Port != 8080 {
			log.Fatal("Every runtime/toolchain must be digest pinned with a fixed entrypoint")
		}
	}
	token, e := secret("BROKER_TOKEN")
	if e != nil || len(token) < 32 {
		log.Fatal("Runtime bearer credential must contain at least32characters")
	}
	transport, e := trustedTransport()
	if e != nil {
		log.Fatal(e)
	}
	s := &server{manifest: m, token: token, data: env("DATA_DIR", "/data/runtime"), workspace: env("WORKSPACE_ROOT", "/data/workspaces"), hostWorkspace: env("HOST_WORKSPACE_ROOT", ""), hostRuntime: env("HOST_RUNTIME_DIR", ""), runner: run, client: &http.Client{Timeout: time.Hour, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Internal service redirects are not permitted")
	}}, buildSlot: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]string{"status": "ok", "mode": env("MODE", "broker")})
	})
	if env("MODE", "broker") == "packager" {
		mux.HandleFunc("/v1/package", s.authenticated(s.packageImage))
	} else {
		k, e := secret("BROKER_APPROVAL_KEY")
		if e != nil {
			log.Fatal(e)
		}
		s.approvalKey, e = base64.StdEncoding.DecodeString(k)
		if e != nil || len(s.approvalKey) != 32 {
			log.Fatal("Publication proof key must be 32 bytes")
		}
		if s.hostWorkspace == "" || s.hostRuntime == "" {
			log.Fatal("Host encrypted-storage mappings are required")
		}
		mux.HandleFunc("/v1/verify", s.authenticated(s.verify))
		s.registerMigrationSnapshotRoutes(mux)
		mux.HandleFunc("/v1/deploy", s.authenticated(s.deploy))
		mux.HandleFunc("/v1/telemetry", s.authenticated(s.telemetry))
		mux.HandleFunc("/v1/security", s.authenticated(s.releaseSecurity))
		mux.HandleFunc("/v1/observe", s.authenticated(s.observeRelease))
		mux.HandleFunc("/v1/recover", s.authenticated(s.recoverRelease))
		mux.HandleFunc("/v1/public-catalog", s.authenticated(s.publicCatalog))
		mux.HandleFunc("/v1/operation", s.authenticated(s.operation))
		mux.HandleFunc("/v1/cancel-operation", s.authenticated(s.cancelOperation))
		mux.HandleFunc("/v1/source", s.authenticated(s.source))
		mux.HandleFunc("/v1/access/snapshot", s.authenticated(s.accessSnapshot))
		mux.HandleFunc("/v1/access/policy", s.authenticated(s.applyAccessPolicy))
		mux.HandleFunc("/v1/access/invite", s.authenticated(s.acceptAppInvitation))
		mux.HandleFunc("/v1/access/operation", s.authenticated(s.accessOperation))
		registerAppAccountRoutes(mux, s)
		mux.HandleFunc("/v1/connectors/provision", s.authenticated(s.provisionConnector))
		mux.HandleFunc("/v1/connectors/status", s.authenticated(s.connectorStatus))
		s.registerFilesystemConnectorRoutes(mux)
		s.registerConnectionRevocationRoutes(mux)
		registerDirectoryIdentityRoutes(mux, s)
	}
	certificate, privateKey := os.Getenv("SERVER_TLS_CERT_FILE"), os.Getenv("SERVER_TLS_KEY_FILE")
	if certificate == "" || privateKey == "" {
		log.Fatal("Internal TLS certificate and private key are required")
	}
	httpServer := &http.Server{Addr: env("LISTEN_ADDR", ":8090"), Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	serviceContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	backgroundContext, cancelBackground := context.WithCancel(serviceContext)
	defer cancelBackground()
	var background []<-chan struct{}
	if env("MODE", "broker") != "packager" {
		background = append(background,
			s.startApplicationTLSRenewal(backgroundContext, time.Hour),
			s.startApplicationJWKSRefresh(backgroundContext, 5*time.Minute),
			s.startFilesystemRevocation(backgroundContext, time.Minute),
			s.startConnectionWithdrawals(backgroundContext))
	}
	log.Printf("Trusted runtime listening %s", httpServer.Addr)
	if e := serveRuntime(serviceContext, cancelBackground, httpServer, certificate, privateKey, background, runtimeShutdownBudget); e != nil {
		log.Fatal(e)
	}
}
func signedBody(key []byte, body []byte, proof string) bool {
	actual, e := hex.DecodeString(proof)
	if e != nil {
		return false
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(body)
	return hmac.Equal(actual, h.Sum(nil))
}
