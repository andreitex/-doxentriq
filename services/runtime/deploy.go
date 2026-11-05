package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type release struct {
	ID                string                    `json:"id"`
	AppID             string                    `json:"appId"`
	Hash              string                    `json:"artifactHash"`
	Commit            string                    `json:"commit"`
	Images            []string                  `json:"images"`
	BaseID            *string                   `json:"baseReleaseId"`
	Evidence          Evidence                  `json:"evidence"`
	Schema            int                       `json:"schemaVersion"`
	SchemaMin         int                       `json:"compatibleSchemaMin"`
	SchemaMax         int                       `json:"compatibleSchemaMax"`
	Migrations        []Migration               `json:"migrations"`
	MigrationSnapshot *migrationSnapshotReceipt `json:"migrationSnapshot,omitempty"`
}
type approval struct {
	ID           string  `json:"id"`
	AppID        string  `json:"appId"`
	ReleaseID    string  `json:"releaseId"`
	Hash         string  `json:"artifactHash"`
	Action       string  `json:"action"`
	ApprovedBy   string  `json:"approvedBy"`
	ApprovedAt   string  `json:"approvedAt"`
	ExpiresAt    string  `json:"expiresAt"`
	CheckpointID *string `json:"checkpointId"`
}
type deployment struct {
	App struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	} `json:"app"`
	Release     release  `json:"release"`
	Approval    approval `json:"approval"`
	OperationID string   `json:"operationId"`
	Action      string   `json:"action"`
	Principal   struct {
		ID         string `json:"id"`
		LocalOwner bool   `json:"localOwner"`
		MFA        bool   `json:"mfa"`
	} `json:"principal"`
	ApprovedFindings []Finding      `json:"approvedFindings"`
	RecoveryGrant    *recoveryGrant `json:"recoveryGrant,omitempty"`
	recovery         *recoveryRequest
}
type activeDeployment struct {
	Hash        string            `json:"artifactHash,omitempty"`
	OperationID string            `json:"operationId,omitempty"`
	ReleaseID   string            `json:"releaseId"`
	Container   string            `json:"container"`
	Image       string            `json:"image"`
	Schema      int               `json:"schema"`
	URL         string            `json:"url"`
	Previous    *activeDeployment `json:"previous,omitempty"`
}
type deployReceipt struct {
	OperationID     string             `json:"operationId"`
	Hash            string             `json:"artifactHash"`
	ApprovalID      string             `json:"approvalId"`
	URL             string             `json:"url"`
	Healthy         bool               `json:"healthy"`
	Phase           string             `json:"phase"`
	AppID           string             `json:"appId"`
	ReleaseID       string             `json:"releaseId"`
	AttemptID       string             `json:"attemptId,omitempty"`
	Schema          int                `json:"schemaVersion,omitempty"`
	PreviousRuntime *retirementBinding `json:"previousRuntime,omitempty"`
}

func checkDeploy(in deployment, v Verification, current *activeDeployment) error {
	a, r := in.Approval, in.Release
	if in.Action != "publish" && in.Action != "rollback" && in.Action != "emergency_rollback" {
		return errors.New("Unsupported publication action")
	}
	if a.Action != in.Action || a.AppID != in.App.ID || r.AppID != in.App.ID || a.ReleaseID != r.ID || a.Hash != r.Hash || a.ApprovedBy == "" || a.ApprovedAt == "" || len(r.Hash) != 64 {
		return errors.New("Exact approved identity, action and artifact are required")
	}
	expiry, e := time.Parse(time.RFC3339, a.ExpiresAt)
	if e != nil || !expiry.After(time.Now()) {
		return errors.New("Approval expired")
	}
	if current != nil && (current.Schema < r.SchemaMin || current.Schema > r.SchemaMax) {
		return errors.New("Release is incompatible with the live database")
	}
	if in.Action == "publish" {
		base := ""
		if r.BaseID != nil {
			base = *r.BaseID
		}
		live := ""
		if current != nil {
			live = current.ReleaseID
		}
		if base != live {
			return errors.New("A different release changed the application baseline")
		}
	}
	if v.AppID != r.AppID || v.Commit != r.Commit || !reflect.DeepEqual(v.Images, r.Images) || v.Schema != r.Schema || v.SchemaMin != r.SchemaMin || v.SchemaMax != r.SchemaMax || !reflect.DeepEqual(v.Evidence, r.Evidence) || !reflect.DeepEqual(v.MigrationSnapshot, r.MigrationSnapshot) {
		return errors.New("Release does not match independently stored verification evidence")
	}
	if v.Evidence.Status != "passed" || len(r.Images) != 1 || !digestImage.MatchString(r.Images[0]) {
		return errors.New("Healthy verified image evidence is required")
	}
	seen := map[string]bool{}
	for _, check := range v.Evidence.Checks {
		if check.Name == "" || seen[check.Name] || !check.Passed {
			return errors.New("Independent evidence contains duplicate, contradictory or failed checks")
		}
		seen[check.Name] = true
	}
	for _, name := range mandatoryStages {
		found := false
		for _, check := range v.Evidence.Checks {
			if check.Name == name && check.Passed {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("Mandatory %s evidence is missing", name)
		}
	}
	if in.Action == "publish" {
		for _, date := range []string{v.Evidence.CheckedAt, v.Evidence.FeedUpdatedAt} {
			t, e := time.Parse(time.RFC3339, date)
			if e != nil || time.Since(t) > 24*time.Hour || t.After(time.Now().Add(time.Minute)) {
				return errors.New("Security evidence or feed is stale")
			}
		}
	}
	for _, f := range v.Evidence.Findings {
		if !classifiedSeverity(f.Severity) {
			return errors.New("Unclassified findings require review before any publication")
		}
		if blockedSeverity(f.Severity) && in.Action != "emergency_rollback" {
			return errors.New("Vulnerable release is blocked")
		}
	}
	for _, m := range v.Migrations {
		if m.Destructive {
			return errors.New("Destructive changes require an independently restored checkpoint; this runtime rejects them")
		}
	}
	if len(v.Migrations) != len(r.Migrations) {
		return errors.New("Migration list was changed")
	}
	for i, m := range r.Migrations {
		if m.ID != v.Migrations[i].ID || m.Checksum != v.Migrations[i].Checksum || m.Destructive != v.Migrations[i].Destructive {
			return errors.New("Migration checksum was changed")
		}
	}
	return nil
}
func (s *server) deploy(w http.ResponseWriter, r *http.Request) {
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if e != nil {
		fail(w, 400, e)
		return
	}
	if !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		fail(w, 403, errors.New("An authenticated exact-action publication proof is required"))
		return
	}
	var in deployment
	if json.Unmarshal(body, &in) != nil || !identity.MatchString(in.OperationID) || !identity.MatchString(in.App.ID) || !identity.MatchString(in.Release.ID) || len(in.Release.ID) < 8 || !identity.MatchString(in.Approval.ID) {
		fail(w, 400, errors.New("Invalid deployment identity"))
		return
	}
	s.executeDeployment(w, r, in)
}

func (s *server) executeDeployment(w http.ResponseWriter, r *http.Request, in deployment) {
	var e error
	if in.Action == "emergency_rollback" && (!in.Principal.LocalOwner || !in.Principal.MFA || in.Principal.ID != os.Getenv("OWNER_SUBJECT") || in.Principal.ID != in.Approval.ApprovedBy) {
		fail(w, 409, errors.New("Emergency rollback requires the permanent local owner's exact identity, MFA and distinct approval"))
		return
	}
	unlock := s.lock("app-" + in.App.ID)
	defer unlock()
	receiptPath := filepath.Join(s.data, "operations", in.OperationID+".json")
	var operation deployReceipt
	if b, e := os.ReadFile(receiptPath); e == nil {
		if json.Unmarshal(b, &operation) != nil || operation.Hash != in.Release.Hash || operation.ApprovalID != in.Approval.ID || operation.AppID != in.App.ID || operation.ReleaseID != in.Release.ID {
			fail(w, 409, errors.New("Operation identity conflict"))
			return
		}
		if operation.Phase == "completed" {
			respond(w, operation)
			return
		}
		if operation.Phase == "failed" {
			rejectDeployment(w, 409, errors.New("This operation was cancelled or failed; use a new reviewed approval and operation"))
			return
		}
	}
	usedPath := filepath.Join(s.data, "used-approvals", in.Approval.ID+".json")
	if b, e := os.ReadFile(usedPath); e == nil {
		var used deployReceipt
		_ = json.Unmarshal(b, &used)
		if used.OperationID != in.OperationID {
			fail(w, 409, errors.New("Approval was already used by another operation"))
			return
		}
	}
	var current *activeDeployment
	b, e := os.ReadFile(filepath.Join(s.data, "active", in.App.ID+".json"))
	if e == nil {
		current = &activeDeployment{}
		if json.Unmarshal(b, current) != nil {
			fail(w, 500, errors.New("Live deployment state is invalid"))
			return
		}
	} else if !os.IsNotExist(e) {
		fail(w, 500, e)
		return
	}
	if len(in.Release.ID) < 8 || !identity.MatchString(in.Release.ID) || !identity.MatchString(in.App.ID) {
		rejectDeployment(w, 409, errors.New("Exact publication identities are required"))
		return
	}
	container := "as-app-" + in.App.ID + "-" + in.Release.ID[:8]
	if current != nil && current.Container == container {
		rejectDeployment(w, 409, errors.New("The proposed runtime name conflicts with the active runtime; its route and data are preserved. Review a release with a distinct runtime identity"))
		return
	}
	if in.recovery != nil {
		if e = s.checkRecovery(r.Context(), *in.recovery, current); e != nil {
			rejectDeployment(w, 409, e)
			return
		}
	}
	var v Verification
	entries, e := os.ReadDir(filepath.Join(s.data, "receipts"))
	if e != nil {
		fail(w, 409, errors.New("Stored verification receipt unavailable"))
		return
	}
	found := false
	for _, entry := range entries {
		b, e := os.ReadFile(filepath.Join(s.data, "receipts", entry.Name()))
		if e == nil && json.Unmarshal(b, &v) == nil && v.AppID == in.App.ID && v.Commit == in.Release.Commit && reflect.DeepEqual(v.Images, in.Release.Images) {
			found = true
			break
		}
	}
	if !found {
		fail(w, 409, errors.New("No independent verification receipt matches this release"))
		return
	}
	if e = checkDeploy(in, v, current); e != nil {
		fail(w, 409, e)
		return
	}
	if in.RecoveryGrant != nil {
		if e = s.validatePublicationGrant(in, current); e != nil {
			rejectDeployment(w, 409, e)
			return
		}
	}
	var manifest AppManifest
	b, e = os.ReadFile(filepath.Join(s.data, "sources", v.AttemptID, "app.manifest.json"))
	if e != nil || json.Unmarshal(b, &manifest) != nil || manifest.Slug != in.App.Slug {
		fail(w, 409, errors.New("Authorized application manifest unavailable"))
		return
	}
	if _, e = cachedFeed(); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	findings, e := s.scanImage(r.Context(), in.Release.Images[0])
	if e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	for _, finding := range findings {
		if !classifiedSeverity(finding.Severity) {
			rejectDeployment(w, 409, errors.New("Fresh scan returned an unclassified finding; emergency rollback cannot bypass missing severity"))
			return
		}
		if !blockedSeverity(finding.Severity) {
			continue
		}
		if in.Action != "emergency_rollback" {
			rejectDeployment(w, 409, errors.New("Fresh image scan found a Medium-or-higher vulnerability"))
			return
		}
		acknowledged := false
		for _, approved := range in.ApprovedFindings {
			if approved.ID == finding.ID && approved.Package == finding.Package && approved.Installed == finding.Installed && approved.Severity == finding.Severity {
				acknowledged = true
				break
			}
		}
		if !acknowledged {
			rejectDeployment(w, 409, errors.New("Fresh security findings changed; a new local-owner emergency approval is required"))
			return
		}
	}
	if in.recovery != nil {
		if e = s.checkRecoverySource(r.Context(), v); e != nil {
			rejectDeployment(w, 409, e)
			return
		}
	}
	if in.RecoveryGrant != nil {
		if e = atomicJSON(filepath.Join(s.data, "recovery-grants", in.RecoveryGrant.ID+".json"), in.RecoveryGrant); e != nil {
			fail(w, 500, e)
			return
		}
	}
	var previousRuntime *pinnedRuntime
	if current != nil {
		previousRuntime, e = s.pinPublishedRuntime(r.Context(), in.App.ID, current)
		if e != nil {
			rejectDeployment(w, 409, e)
			return
		}
	}
	operation = deployReceipt{OperationID: in.OperationID, Hash: in.Release.Hash, ApprovalID: in.Approval.ID, Phase: "started", AppID: in.App.ID, ReleaseID: in.Release.ID, AttemptID: v.AttemptID}
	if previousRuntime != nil {
		operation.PreviousRuntime = &retirementBinding{ID: previousRuntime.ID, Name: previousRuntime.Name, Image: previousRuntime.Image, ReleaseID: current.ReleaseID, Hash: current.Hash, OperationID: current.OperationID}
	}
	if e = atomicJSON(receiptPath, operation); e != nil {
		fail(w, 500, e)
		return
	}
	if e = atomicJSON(usedPath, operation); e != nil {
		fail(w, 500, e)
		return
	}
	routingAttempted := false
	defer func() {
		// Before any routing attempt, a failure has a known non-publication outcome.
		// Ambiguous routing outcomes remain pending and require actual reconciliation.
		if operation.Phase == "started" && !routingAttempted {
			operation.Phase = "failed"
			operation.Healthy = false
			_ = atomicJSON(receiptPath, operation)
		}
	}()
	freshDatabase, admissionError := s.migrationAdmission(r.Context(), in.App.ID, v.Migrations, v.MigrationSnapshot, in.Action == "publish")
	if admissionError != nil {
		fail(w, 409, admissionError)
		return
	}
	resources, e := s.provision(r.Context(), in.App.ID, manifest, false)
	if e != nil {
		fail(w, 409, e)
		return
	}
	if freshDatabase {
		if e = s.applyMigrations(r.Context(), &resources, v.Migrations); e != nil {
			fail(w, 409, e)
			return
		}
	}
	resources, e = s.stageAppConnectors(r.Context(), manifest, resources, false, container)
	if e != nil {
		fail(w, 409, e)
		return
	}
	if e = s.checkRetirableAppConnectors(r.Context(), in.App.ID, resources.AppID, container); e != nil {
		fail(w, 409, e)
		return
	}
	workerHandover := previousRuntime != nil && (manifest.Kind == "worker" || previousRuntime.Manifest.Kind == "worker")
	if workerHandover && previousRuntime.WasRunning {
		if e = s.stopRuntimeCandidate(previousRuntime.Name, in.App.ID, in.App.ID, previousRuntime.Image, previousRuntime.ID); e != nil {
			routingAttempted = true
			fail(w, 503, errors.New("Worker handover shutdown is unconfirmed; publication remains pending"))
			return
		}
	}
	if e = s.startApp(r.Context(), container, in.Release.Images[0], manifest, resources, false); e != nil {
		if candidateShutdownUncertain(e) {
			routingAttempted = true // Preserve a pending receipt; never resume a competing worker.
			fail(w, 503, e)
			return
		}
		if stopErr := s.stopFailedCandidate(container, manifest.ID, resources.AppID, in.Release.Images[0]); stopErr != nil {
			routingAttempted = true
			fail(w, 503, stopErr)
			return
		}
		if workerHandover {
			if restoreErr := s.restorePinnedRuntime(in.App.ID, current, previousRuntime, container, false); restoreErr != nil {
				routingAttempted = true
				fail(w, 503, restoreErr)
				return
			}
		}
		fail(w, 409, e)
		return
	}
	host := manifest.Slug + "." + s.appsHost()
	routingAttempted = true
	if e = s.route(r.Context(), in.App.ID, host, container, 8080, false); e != nil {
		if stopErr := s.stopFailedCandidate(container, manifest.ID, resources.AppID, in.Release.Images[0]); stopErr != nil {
			fail(w, 503, stopErr)
			return
		}
		if previousRuntime != nil {
			if restoreErr := s.restorePinnedRuntime(in.App.ID, current, previousRuntime, container, true); restoreErr != nil {
				fail(w, 503, restoreErr)
				return
			}
		}
		fail(w, 409, e)
		return
	}
	next := activeDeployment{Hash: in.Release.Hash, OperationID: in.OperationID, ReleaseID: in.Release.ID, Container: container, Image: in.Release.Images[0], Schema: resources.Schema, URL: "https://" + host, Previous: current}
	if e = atomicJSON(filepath.Join(s.data, "active", in.App.ID+".json"), next); e != nil {
		if stopErr := s.stopFailedCandidate(container, manifest.ID, resources.AppID, in.Release.Images[0]); stopErr != nil {
			fail(w, 503, stopErr)
			return
		}
		if previousRuntime != nil {
			if restoreErr := s.restorePinnedRuntime(in.App.ID, current, previousRuntime, container, true); restoreErr != nil {
				fail(w, 503, restoreErr)
				return
			}
		}
		fail(w, 500, e)
		return
	}
	if current != nil && current.Container != container {
		if e = s.stopRuntimeCandidate(previousRuntime.Name, in.App.ID, in.App.ID, previousRuntime.Image, previousRuntime.ID); e != nil {
			fail(w, 503, errors.New("The new route is active, but previous runtime shutdown requires reconciliation; publication remains pending"))
			return
		}
	}
	if e = s.retireAppConnectors(r.Context(), in.App.ID, resources.AppID, container); e != nil {
		fail(w, 503, errors.New("The new route is active, but exact previous connector retirement requires reconciliation; publication is still pending"))
		return
	}
	operation.URL = next.URL
	operation.Schema = next.Schema
	operation.Healthy = true
	operation.Phase = "completed"
	if e = atomicJSON(receiptPath, operation); e != nil {
		fail(w, 500, e)
		return
	}
	respond(w, operation)
}
func (s *server) appsHost() string {
	u, e := url.Parse(env("APPS_BASE_URL", env("APPS_ORIGIN", "")))
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "invalid.invalid"
	}
	return u.Hostname()
}
func rejectDeployment(w http.ResponseWriter, status int, e error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": e.Error(), "rejectedBeforeExecution": true})
}
func controlProxy() map[string]any {
	return map[string]any{"handler": "reverse_proxy", "upstreams": []map[string]string{{"dial": "control:3000"}}, "headers": map[string]any{"request": map[string]any{"set": map[string][]string{"Host": {"{http.request.host}"}}}}, "transport": map[string]any{"protocol": "http", "tls": map[string]any{"server_name": "control", "ca": map[string]any{"provider": "file", "pem_files": []string{env("CADDY_INTERNAL_CA_FILE", "/etc/autosoft/ca.crt")}}}}}
}
func (s *server) startApp(ctx context.Context, container, image string, m AppManifest, v resources, preview bool) error {
	if !identity.MatchString(container) || !digestImage.MatchString(image) {
		return errors.New("Invalid runtime identity")
	}
	for _, legacy := range []string{"connector-token", "connector-registry.json"} {
		if _, err := os.Lstat(filepath.Join(v.Secrets, legacy)); err == nil || !os.IsNotExist(err) {
			return errors.New("Legacy shared connector capabilities require company migration before activation")
		}
	}
	if len(m.Connections) > 0 {
		if v.ConnectorResourceID == "" || v.ConnectorSecrets == "" || v.ConnectorHostSecrets == "" || s.validateAppConnectorMount(m.ID, v.AppID, container, v.ConnectorHostSecrets) != nil {
			return errors.New("Exact candidate-scoped connector capabilities are required")
		}
	}
	hostSecrets := filepath.Join(s.hostRuntime, "secrets", v.AppID)
	args := []string{"run", "-d", "--name", container, "--label", "io.autosoft.managed=true", "--label", "io.autosoft.app=" + m.ID, "--restart", "unless-stopped", "--runtime", env("RUNSC_RUNTIME", "runsc"), "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", strconv.Itoa(m.Resources.Pids), "--memory", strconv.Itoa(m.Resources.Memory) + "m", "--cpus", strconv.FormatFloat(m.Resources.CPU, 'f', 2, 64), "--network", v.Network, "--network-alias", container, "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777", "--mount", "type=bind,src=" + hostSecrets + ",dst=/run/app-secrets,readonly"}
	if len(m.Connections) > 0 {
		args = append(args, "--mount", "type=bind,src="+v.ConnectorHostSecrets+",dst=/run/app-connectors,readonly")
	}
	serviceNames := []string{"mysql", "redis", "rabbitmq"}
	if directoryAuthorizationEnabled() && m.Auth != "public" {
		serviceNames = append(serviceNames, "control")
	}
	hosts, e := s.trustedServiceHosts(ctx, v.Network, serviceNames)
	if e != nil {
		return e
	}
	connectorHosts, e := s.appConnectorHosts(ctx, m, v)
	if e != nil {
		return e
	}
	aliases := make([]string, 0, len(connectorHosts))
	for alias := range connectorHosts {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		hosts = append(hosts, "--add-host", alias+":"+connectorHosts[alias])
	}
	args = append(args, hosts...)
	exists, removed, e := s.reconcileExistingAppHosts(ctx, container, m.ID, v.AppID, image, hosts, preview)
	if e != nil {
		return e
	}
	if exists && !removed {
		if _, e = s.runner(ctx, "docker", "start", container); e != nil {
			return s.failedCandidate(container, m.ID, v.AppID, image, errors.New("The exact existing application runtime could not start"))
		}
		if e = s.healthy(ctx, container, m); e != nil {
			return s.failedCandidate(container, m.ID, v.AppID, image, e)
		}
		return nil
	}
	environment := map[string]string{"MYSQL_HOST": "mysql", "MYSQL_DATABASE": v.Database, "MYSQL_USER": v.User, "MYSQL_PASSWORD_FILE": "/run/app-secrets/mysql-password", "MYSQL_CA_FILE": "/run/app-secrets/ca.crt", "REDIS_HOST": "redis", "REDIS_USER": v.User, "REDIS_PASSWORD_FILE": "/run/app-secrets/redis-password", "REDIS_KEY_PREFIX": "app:" + v.AppID + ":", "REDIS_CA_FILE": "/run/app-secrets/ca.crt", "RABBITMQ_HOST": "rabbitmq", "RABBITMQ_VHOST": v.Database, "RABBITMQ_USER": v.User, "RABBITMQ_PASSWORD_FILE": "/run/app-secrets/rabbitmq-password", "RABBITMQ_CA_FILE": "/run/app-secrets/ca.crt", "OIDC_ISSUER": v.Issuer, "OIDC_AUDIENCE": v.Audience, "OIDC_JWKS_FILE": "/run/app-secrets/jwks.json", "APP_ID": m.ID, "NODE_EXTRA_CA_CERTS": "/run/app-secrets/ca.crt"}
	appHost := m.Slug + "." + s.appsHost()
	if preview {
		appHost = "preview-" + appHost
	}
	environment["APP_ORIGIN"] = "https://" + appHost
	environment["OIDC_JWKS_RESOURCE_ID"] = v.AppID
	environment["APP_TLS_CERT_FILE"] = "/run/app-secrets/app.crt"
	environment["APP_TLS_KEY_FILE"] = "/run/app-secrets/app.key"
	environment["SSL_CERT_FILE"] = "/run/app-secrets/ca.crt"
	if directoryAuthorizationEnabled() && m.Auth != "public" {
		environment["DIRECTORY_AUTHORIZATION_URL"] = "https://control:3000/api/public/v1/apps/" + m.ID + "/directory/authorize"
	}
	for key, value := range connectorEnvironment(m) {
		environment[key] = value
	}
	for key, value := range environment {
		args = append(args, "--env", key+"="+value)
	}
	if len(m.Storage) == 1 {
		if v.StorageHost == "" || v.StorageContainer == "" {
			return errors.New("Verified persistent storage quota is required")
		}
		args = append(args, "--mount", "type=bind,src="+v.StorageHost+",dst=/data", "--env", "APP_STORAGE_ROOT=/data", "--env", "APP_STORAGE_QUOTA_BYTES="+strconv.FormatInt(int64(m.Storage[0].MaxMB)<<20, 10))
	}
	args = append(args, image)
	if _, e := s.runner(ctx, "docker", args...); e != nil {
		return s.failedCandidate(container, m.ID, v.AppID, image, errors.New("Application runtime failed to start"))
	}
	if e := s.healthy(ctx, container, m); e != nil {
		return s.failedCandidate(container, m.ID, v.AppID, image, e)
	}
	return nil
}
func (s *server) healthy(ctx context.Context, container string, m AppManifest) error {
	healthCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	target := "https://127.0.0.1:8080" + m.Health.Path
	for {
		var command []string
		if m.Template == "python-api" {
			command = []string{"python", "-c", "import urllib.request; assert urllib.request.urlopen(" + strconv.Quote(target) + ",timeout=3).status==200"}
		} else {
			command = []string{"node", "--input-type=module", "-e", "const r=await fetch(" + strconv.Quote(target) + ",{signal:AbortSignal.timeout(3000)});if(r.status!==200)process.exit(1)"}
		}
		if _, e := s.runner(healthCtx, "docker", append([]string{"exec", container}, command...)...); e == nil {
			return nil
		}
		select {
		case <-healthCtx.Done():
			return errors.New("Application did not become healthy; prior route is retained")
		case <-time.After(2 * time.Second):
		}
	}
}
func caddyClient(socket string) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}
func (s *server) route(ctx context.Context, id, host, container string, port int, preview bool) error {
	if !identity.MatchString(id) || !identity.MatchString(container) || !regexp.MustCompile(`^[a-z0-9.-]+$`).MatchString(host) || port != 8080 {
		return errors.New("Invalid private route")
	}
	if s.routeChange != nil {
		return s.routeChange(ctx, id, host, container, port, preview)
	}
	unlock := s.lock("caddy-routes")
	defer unlock()
	client := caddyClient(env("CADDY_ADMIN_SOCKET_FILE", "/run/caddy/admin.sock"))
	endpoint := "http://localhost/config/apps/http/servers/" + env("CADDY_SERVER_NAME", "apps") + "/routes"
	request, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	response, e := client.Do(request)
	if e != nil {
		return errors.New("Restricted routing service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("Caddy app server configuration unavailable")
	}
	etag := response.Header.Get("ETag")
	if etag == "" {
		return errors.New("Routing configuration has no concurrency token")
	}
	var routes []map[string]any
	if json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&routes) != nil {
		return errors.New("Caddy route configuration invalid")
	}
	handlers := []map[string]any{}
	if preview {
		proxy := controlProxy()
		proxy["rewrite"] = map[string]string{"method": "GET", "uri": "/api/auth/check"}
		proxy["handle_response"] = []map[string]any{{"match": map[string]any{"status_code": []int{2}}, "routes": []map[string]any{{"handle": []map[string]any{{"handler": "headers", "request": map[string]any{"delete": []string{"X-Auth-User"}}}}}}}}
		handlers = append(handlers, proxy)
	}
	resourceID := id
	if preview {
		resourceID = strings.TrimPrefix(id, "preview-") + "_preview"
	}
	deletedHeaders := []string{"X-Auth-User", "X-Auth-Roles", "X-Platform-Owner", "X-Autosoft-Preview-Host"}
	requestHeaders := map[string]any{"delete": deletedHeaders}
	if preview {
		requestHeaders["replace"] = map[string]any{"Cookie": []map[string]string{{"search_regexp": `(?:^|;\s*)(?:__Host-autosoft-preview|__Host-autosoft-session|__Host-autosoft-oauth-state|autosoft_session)=[^;]*`, "replace": ""}}}
	}
	handlers = append(handlers, map[string]any{"handler": "reverse_proxy", "upstreams": []map[string]string{{"dial": container + ":8080"}}, "headers": map[string]any{"request": requestHeaders}, "transport": map[string]any{"protocol": "http", "tls": map[string]any{"server_name": appTLSHost(resourceID), "ca": map[string]any{"provider": "file", "pem_files": []string{env("CADDY_INTERNAL_CA_FILE", "/etc/autosoft/ca.crt")}}}}})
	if preview {
		setHost := map[string]any{"handler": "headers", "request": map[string]any{"set": map[string][]string{"X-Autosoft-Preview-Host": {host}}}}
		protected := append([]map[string]any{setHost}, handlers...)
		exchange := map[string]any{"match": []map[string]any{{"path": []string{"/__autosoft/preview"}}}, "handle": []map[string]any{setHost, {"handler": "rewrite", "uri": "/api/auth/preview/exchange?{http.request.uri.query}"}, controlProxy()}, "terminal": true}
		handlers = []map[string]any{{"handler": "subroute", "routes": []map[string]any{exchange, {"handle": protected}}}}
	}
	newRoute := map[string]any{"@id": "autosoft-app-" + id, "match": []map[string]any{{"host": []string{host}}}, "handle": handlers, "terminal": true}
	updated := []map[string]any{}
	for _, route := range routes {
		if route["@id"] != "autosoft-app-"+id {
			updated = append(updated, route)
		}
	}
	updated = append([]map[string]any{newRoute}, updated...)
	body, _ := json.Marshal(updated)
	request, _ = http.NewRequestWithContext(ctx, "PATCH", endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", etag)
	response, e = client.Do(request)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed {
		return errors.New("Routing configuration changed concurrently; the current routes were preserved")
	}
	if response.StatusCode != 200 {
		return errors.New("Atomic routing change was rejected")
	}
	return nil
}
func (s *server) operation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"operationId"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !identity.MatchString(in.ID) {
		fail(w, 400, errors.New("Invalid operation identity"))
		return
	}
	var receipt deployReceipt
	b, e := os.ReadFile(filepath.Join(s.data, "operations", in.ID+".json"))
	if os.IsNotExist(e) {
		respond(w, map[string]string{"status": "unknown"})
		return
	}
	if e != nil || json.Unmarshal(b, &receipt) != nil {
		fail(w, 500, errors.New("Operation receipt cannot be read"))
		return
	}
	status := "running"
	if receipt.Phase == "completed" {
		status = "succeeded"
	}
	if receipt.Phase == "failed" {
		status = "failed"
	}
	if status == "running" {
		if !identity.MatchString(receipt.AppID) || receipt.OperationID != in.ID {
			fail(w, 500, errors.New("Pending operation identity is invalid"))
			return
		}
		unlock := s.lock("app-" + receipt.AppID)
		defer unlock()
		// Reload after the shared app lock; an in-flight deployment may have finished.
		if e = readBoundedJSON(filepath.Join(s.data, "operations", in.ID+".json"), &receipt); e != nil {
			fail(w, 500, e)
			return
		}
		if receipt.Phase == "failed" {
			status = "failed"
		} else if receipt.Phase == "completed" {
			status = "succeeded"
		} else if receipt.Phase == "started" {
			if active, verified := s.reconcileHealthyOperation(r.Context(), receipt); verified {
				receipt.Phase = "completed"
				receipt.URL = active.URL
				receipt.Healthy = true
				receipt.Schema = active.Schema
				if e = atomicJSON(filepath.Join(s.data, "operations", in.ID+".json"), receipt); e != nil {
					fail(w, 500, e)
					return
				}
				status = "succeeded"
			}
		}
	}
	respond(w, map[string]any{"status": status, "url": receipt.URL, "healthy": receipt.Healthy, "schemaVersion": receipt.Schema, "appId": receipt.AppID, "releaseId": receipt.ReleaseID})
}
