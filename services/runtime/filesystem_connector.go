package main

// A company catalog chooses encrypted import roots. Neither generated sources
// nor connector requests can choose a host path, image or network destination.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type filesystemSource struct {
	ID         string   `json:"id"`
	AppIDs     []string `json:"appIds"`
	Device     uint64   `json:"device"`
	Inode      uint64   `json:"inode"`
	ReviewedAt string   `json:"reviewedAt"`
	ExpiresAt  string   `json:"expiresAt"`
}
type filesystemTemplate struct {
	Image         string `json:"image"`
	SourceHash    string `json:"sourceSha256"`
	Qualification struct {
		Status     string `json:"status"`
		ReportHash string `json:"reportSha256"`
		CheckedAt  string `json:"checkedAt"`
		Scope      string `json:"scope"`
	} `json:"protocolQualification"`
}
type filesystemSourceEvidence struct {
	SourceID           string `json:"sourceRootId"`
	SourceHash         string `json:"sourceEvidenceHash"`
	ExpiresAt          string `json:"sourceExpiresAt"`
	TemplateSourceHash string `json:"templateSourceHash"`
	Image              string `json:"templateImage"`
	QualificationHash  string `json:"qualificationReportHash"`
}
type filesystemScope struct {
	filesystemSourceEvidence
	AppID           string `json:"appId"`
	ConnectionID    string `json:"connectionId"`
	Type            string `json:"type"`
	Root            string `json:"root"`
	AccessExpiresAt string `json:"accessExpiresAt"`
	RegistryHash    string `json:"registryHash"`
}
type filesystemProvision struct {
	Version      int             `json:"schemaVersion"`
	Action       string          `json:"action"`
	OperationID  string          `json:"operationId"`
	ApprovalID   string          `json:"approvalId"`
	ArtifactHash string          `json:"artifactHash"`
	Scope        filesystemScope `json:"scope"`
	ApprovedAt   string          `json:"approvedAt"`
	Principal    struct {
		ID         string `json:"id"`
		MFA        bool   `json:"mfa"`
		LocalOwner bool   `json:"localOwner"`
	} `json:"principal"`
}
type filesystemConnectorState struct {
	Input      filesystemProvision `json:"input"`
	ScopeHash  string              `json:"scopeHash"`
	Template   filesystemTemplate  `json:"template"`
	PreparedAt string              `json:"preparedAt"`
}
type filesystemOperationIdentity struct {
	OperationID  string `json:"operationId"`
	ApprovalID   string `json:"approvalId"`
	AppID        string `json:"appId"`
	ConnectionID string `json:"connectionId"`
	ArtifactHash string `json:"artifactHash"`
}

var filesystemAlias = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,79}$`)

func filesystemArtifactHash(scope filesystemScope) string {
	return accessHash(map[string]any{"schemaVersion": 1, "action": "approve_readonly_filesystem", "scope": scope})
}
func readFilesystemTemplate() (filesystemTemplate, error) {
	var result filesystemTemplate
	b, e := os.ReadFile(os.Getenv("RUNTIME_MANIFEST_PATH"))
	if e != nil || len(b) > 1<<20 {
		return result, errors.New("Company filesystem manifest unavailable")
	}
	var manifest struct {
		Connectors map[string]filesystemTemplate `json:"connectors"`
	}
	if json.Unmarshal(b, &manifest) != nil {
		return result, errors.New("Company filesystem manifest invalid")
	}
	result, ok := manifest.Connectors["filesystem"]
	checked, e := time.Parse(time.RFC3339, result.Qualification.CheckedAt)
	if !ok || !digestImage.MatchString(result.Image) || !strings.HasPrefix(result.Image, "registry:5000/connectors/filesystem@") || !accessHex.MatchString(result.SourceHash) || result.Qualification.Status != "passed" || !accessHex.MatchString(result.Qualification.ReportHash) || result.Qualification.Scope != "synthetic-readonly-filesystem-runsc" || e != nil || checked.After(time.Now().Add(time.Minute)) || time.Since(checked) > 30*24*time.Hour {
		return filesystemTemplate{}, errors.New("A source-bound pinned filesystem adapter with current actual runsc read-only/openat2 qualification is required")
	}
	return result, nil
}

// Reflection keeps the company runtime's Windows unit-test build portable;
// actual source provisioning requires Linux device/inode metadata.
func filesystemStatIdentity(info os.FileInfo) (uint64, uint64, error) {
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, 0, errors.New("Linux source identity unavailable")
	}
	dev, ino := value.FieldByName("Dev"), value.FieldByName("Ino")
	if !dev.IsValid() || !ino.IsValid() || !dev.CanUint() || !ino.CanUint() || ino.Uint() == 0 {
		return 0, 0, errors.New("Linux source identity unavailable")
	}
	return dev.Uint(), ino.Uint(), nil
}

func filesystemRoot(source filesystemSource) (string, error) {
	if !identity.MatchString(source.ID) || source.Inode == 0 {
		return "", errors.New("Exact company source identity required")
	}
	base := "/data/imports"
	info, e := os.Lstat(base)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Company encrypted import mount unavailable")
	}
	baseDevice, _, e := filesystemStatIdentity(info)
	if e != nil {
		return "", e
	}
	root := filepath.Join(base, source.ID)
	info, e = os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Company source must be an ordinary import directory")
	}
	device, inode, e := filesystemStatIdentity(info)
	if e != nil || device != baseDevice || device != source.Device || inode != source.Inode {
		return "", errors.New("Company import root identity or filesystem changed")
	}
	return root, nil
}
func readFilesystemSources(appID string) ([]filesystemSource, error) {
	if !identity.MatchString(appID) {
		return nil, errors.New("Exact app identity required")
	}
	file := env("FILESYSTEM_SOURCE_CATALOG", "/etc/autosoft/filesystem-sources.json")
	info, e := os.Lstat(file)
	if e != nil || !info.Mode().IsRegular() || !filesystemCatalogOwner(info.Sys(), info.Mode()) || info.Size() > 65536 {
		return nil, errors.New("Protected company source catalog unavailable")
	}
	b, e := os.ReadFile(file)
	if e != nil {
		return nil, errors.New("Protected company source catalog unavailable")
	}
	var catalog struct {
		Version int                `json:"schemaVersion"`
		Sources []filesystemSource `json:"sources"`
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&catalog) != nil || decoder.Decode(new(any)) != io.EOF || catalog.Version != 1 || len(catalog.Sources) > 32 {
		return nil, errors.New("Company source catalog invalid")
	}
	result := []filesystemSource{}
	seen := map[string]bool{}
	for _, source := range catalog.Sources {
		if !identity.MatchString(source.ID) || seen[source.ID] || source.Inode == 0 || len(source.AppIDs) == 0 || len(source.AppIDs) > 64 {
			return nil, errors.New("Company source catalog has duplicate or invalid scope")
		}
		seen[source.ID] = true
		authorized := false
		apps := map[string]bool{}
		for _, id := range source.AppIDs {
			if !identity.MatchString(id) || apps[id] {
				return nil, errors.New("Company source app scopes invalid")
			}
			apps[id] = true
			if id == appID {
				authorized = true
			}
		}
		reviewed, re := time.Parse(time.RFC3339, source.ReviewedAt)
		expires, ee := time.Parse(time.RFC3339, source.ExpiresAt)
		if re != nil || ee != nil || reviewed.After(time.Now().Add(time.Minute)) || time.Since(reviewed) > 30*24*time.Hour || !expires.After(time.Now()) || expires.After(reviewed.Add(90*24*time.Hour)) {
			continue
		}
		if authorized {
			if _, e := filesystemRoot(source); e != nil {
				return nil, e
			}
			result = append(result, source)
		}
	}
	return result, nil
}

func filesystemCatalogOwner(metadata any, mode os.FileMode) bool {
	if mode.Perm() != 0640 {
		return false
	}
	owner := reflect.ValueOf(metadata)
	if owner.Kind() == reflect.Pointer {
		if owner.IsNil() {
			return false
		}
		owner = owner.Elem()
	}
	if owner.Kind() != reflect.Struct {
		return false
	}
	uid, gid := owner.FieldByName("Uid"), owner.FieldByName("Gid")
	return uid.IsValid() && gid.IsValid() && uid.CanUint() && gid.CanUint() && uid.Uint() == 0 && gid.Uint() == 10001
}
func filesystemEvidence(source filesystemSource, template filesystemTemplate) filesystemSourceEvidence {
	// Device/inode values are uint64; project them as decimal strings so the
	// canonical JSON normalizer cannot round distinct identities above 2^53.
	projection := map[string]any{"id": source.ID, "appIds": source.AppIDs, "device": strconv.FormatUint(source.Device, 10), "inode": strconv.FormatUint(source.Inode, 10), "reviewedAt": source.ReviewedAt, "expiresAt": source.ExpiresAt}
	return filesystemSourceEvidence{source.ID, accessHash(map[string]any{"schemaVersion": 1, "source": projection}), source.ExpiresAt, template.SourceHash, template.Image, template.Qualification.ReportHash}
}
func currentFilesystemScope(scope filesystemScope) (filesystemSource, filesystemTemplate, error) {
	template, e := readFilesystemTemplate()
	if e != nil {
		return filesystemSource{}, template, e
	}
	sources, e := readFilesystemSources(scope.AppID)
	if e != nil {
		return filesystemSource{}, template, e
	}
	for _, source := range sources {
		if source.ID == scope.SourceID {
			if !reflect.DeepEqual(filesystemEvidence(source, template), scope.filesystemSourceEvidence) {
				return source, template, errors.New("Reviewed source or qualified adapter changed")
			}
			return source, template, nil
		}
	}
	return filesystemSource{}, template, errors.New("App lacks a current company-approved import root")
}
func validateFilesystemProvision(in filesystemProvision, now time.Time, owner string) error {
	if in.Version != 1 || in.Action != "approve_readonly_filesystem" || in.Scope.Type != "filesystem" || !identity.MatchString(in.OperationID) || !identity.MatchString(in.ApprovalID) || !identity.MatchString(in.Scope.AppID) || !identity.MatchString(in.Scope.ConnectionID) || !identity.MatchString(in.Scope.SourceID) || !filesystemAlias.MatchString(in.Scope.Root) || !accessHex.MatchString(in.Scope.RegistryHash) || in.ArtifactHash != filesystemArtifactHash(in.Scope) {
		return errors.New("Exact reviewed filesystem artifact and scoped identities are required")
	}
	if owner == "" || in.Principal.ID != owner || !in.Principal.MFA || !in.Principal.LocalOwner {
		return errors.New("Filesystem scope approval requires permanent owner MFA")
	}
	approved, e := time.Parse(time.RFC3339, in.ApprovedAt)
	if e != nil || approved.After(now.Add(time.Minute)) || now.Sub(approved) > 5*time.Minute {
		return errors.New("Filesystem approval is stale")
	}
	expires, e := time.Parse(time.RFC3339, in.Scope.AccessExpiresAt)
	sourceExpires, se := time.Parse(time.RFC3339, in.Scope.ExpiresAt)
	if e != nil || se != nil || !expires.After(now) || expires.After(now.Add(90*24*time.Hour)) || expires.After(sourceExpires) {
		return errors.New("Filesystem access must expire within company source lifetime and 90 days")
	}
	return nil
}
func (s *server) filesystemStatePath(appID, id string) string {
	return filepath.Join(s.data, "connectors", "approved-filesystem", appID, id+".enc")
}
func (s *server) registerFilesystemConnectorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/connectors/filesystem/sources", s.authenticated(s.filesystemSources))
	mux.HandleFunc("/v1/connectors/filesystem/provision", s.authenticated(s.provisionFilesystem))
	mux.HandleFunc("/v1/connectors/filesystem/status", s.authenticated(s.filesystemStatus))
}
func (s *server) filesystemSources(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AppID string `json:"appId"`
	}
	if !decode(w, r, &in) {
		return
	}
	template, e := readFilesystemTemplate()
	if e != nil {
		fail(w, 409, e)
		return
	}
	sources, e := readFilesystemSources(in.AppID)
	if e != nil {
		fail(w, 409, e)
		return
	}
	result := []filesystemSourceEvidence{}
	for _, source := range sources {
		result = append(result, filesystemEvidence(source, template))
	}
	respond(w, map[string]any{"schemaVersion": 1, "appId": in.AppID, "sources": result})
}
func (s *server) provisionFilesystem(w http.ResponseWriter, r *http.Request) {
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
	if e != nil || !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		rejectDeployment(w, 403, errors.New("Protected exact filesystem approval proof required"))
		return
	}
	var in filesystemProvision
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		rejectDeployment(w, 400, errors.New("Invalid bounded filesystem approval"))
		return
	}
	if e = validateFilesystemProvision(in, time.Now(), os.Getenv("OWNER_SUBJECT")); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	unlock := s.lock("app-" + in.Scope.AppID)
	defer unlock()
	if e = s.connectionWithdrawalBlocked(in.Scope.AppID, in.Scope.ConnectionID); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	_, template, e := currentFilesystemScope(in.Scope)
	if e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	file := s.filesystemStatePath(in.Scope.AppID, in.Scope.ConnectionID)
	var existing filesystemConnectorState
	if e = readEncrypted(file, &existing); e == nil {
		if !reflect.DeepEqual(existing.Input, in) || existing.ScopeHash != in.ArtifactHash || !reflect.DeepEqual(existing.Template, template) {
			rejectDeployment(w, 409, errors.New("Filesystem scope changed; retain original operation and use a new connection identity"))
			return
		}
		respond(w, filesystemStatusValue(in, "configured"))
		return
	} else if !os.IsNotExist(e) {
		rejectDeployment(w, 409, errors.New("Filesystem retained approval unavailable"))
		return
	}
	if _, e = os.Lstat(s.connectorStatePath(in.Scope.AppID, in.Scope.ConnectionID)); !os.IsNotExist(e) {
		rejectDeployment(w, 409, errors.New("Connection identity belongs to a different adapter"))
		return
	}
	if _, e = cachedFeed(); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	findings, e := s.scanImage(r.Context(), template.Image)
	if e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	for _, finding := range findings {
		if blockedSeverity(finding.Severity) {
			rejectDeployment(w, 409, errors.New("Filesystem adapter has a MEDIUM+ or unclassified finding"))
			return
		}
	}
	if e = validateFilesystemProvision(in, time.Now(), os.Getenv("OWNER_SUBJECT")); e != nil {
		rejectDeployment(w, 409, e)
		return
	}
	if _, fresh, e := currentFilesystemScope(in.Scope); e != nil || !reflect.DeepEqual(fresh, template) {
		rejectDeployment(w, 409, errors.New("Filesystem source or company qualification changed during scanning"))
		return
	}
	if e = writeEncrypted(file, filesystemConnectorState{in, in.ArtifactHash, template, time.Now().UTC().Format(time.RFC3339)}); e != nil {
		fail(w, 500, errors.New("Filesystem approval persistence outcome unavailable"))
		return
	}
	respond(w, filesystemStatusValue(in, "configured"))
}
func filesystemStatusValue(in filesystemProvision, status string) map[string]any {
	result := map[string]any{"schemaVersion": 1, "type": "filesystem", "status": status, "operationId": in.OperationID, "approvalId": in.ApprovalID, "appId": in.Scope.AppID, "connectionId": in.Scope.ConnectionID, "artifactHash": in.ArtifactHash, "liveRootVerified": false}
	if status == "configured" {
		result["scopeHash"] = in.ArtifactHash
	}
	return result
}
func (s *server) filesystemStatus(w http.ResponseWriter, r *http.Request) {
	var in filesystemOperationIdentity
	if !decode(w, r, &in) {
		return
	}
	if !identity.MatchString(in.AppID) || !identity.MatchString(in.ConnectionID) || !identity.MatchString(in.OperationID) || !identity.MatchString(in.ApprovalID) || !accessHex.MatchString(in.ArtifactHash) {
		fail(w, 400, errors.New("Exact filesystem operation identity required"))
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	var state filesystemConnectorState
	if e := readEncrypted(s.filesystemStatePath(in.AppID, in.ConnectionID), &state); e != nil {
		if os.IsNotExist(e) {
			respond(w, filesystemStatusValue(filesystemProvision{OperationID: in.OperationID, ApprovalID: in.ApprovalID, ArtifactHash: in.ArtifactHash, Scope: filesystemScope{AppID: in.AppID, ConnectionID: in.ConnectionID}}, "unknown"))
			return
		}
		fail(w, 409, errors.New("Filesystem reconciliation unavailable; retain pending operation"))
		return
	}
	if state.Input.OperationID != in.OperationID || state.Input.ApprovalID != in.ApprovalID || state.Input.Scope.AppID != in.AppID || state.Input.Scope.ConnectionID != in.ConnectionID || state.Input.ArtifactHash != in.ArtifactHash || state.ScopeHash != filesystemArtifactHash(state.Input.Scope) {
		fail(w, 409, errors.New("Filesystem reconciliation differs from exact approved artifact"))
		return
	}
	if _, e := s.loadApprovedFilesystem(in.AppID, in.ConnectionID); e != nil {
		fail(w, 409, e)
		return
	}
	respond(w, filesystemStatusValue(state.Input, "configured"))
}
func (s *server) filesystemConnectorExists(appID, id string) (bool, error) {
	if !identity.MatchString(appID) || !identity.MatchString(id) {
		return false, errors.New("Exact connector identities required")
	}
	info, e := os.Lstat(s.filesystemStatePath(appID, id))
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil || !info.Mode().IsRegular() {
		return false, errors.New("Filesystem approval inventory unavailable")
	}
	return true, nil
}
func (s *server) loadApprovedFilesystem(appID, id string) (filesystemConnectorState, error) {
	var state filesystemConnectorState
	if e := s.connectionWithdrawalBlocked(appID, id); e != nil {
		return state, e
	}
	return s.loadCurrentFilesystemSource(appID, id)
}

// The source watcher evaluates catalog/inode/expiry/qualification withdrawal.
// Explicit tombstones are not stop authority for that watcher: only the explicit
// withdrawal reconciler may stop on their successfully synchronized intent.
// This function is never an execution/provisioning admission entry point.
func (s *server) loadCurrentFilesystemSource(appID, id string) (filesystemConnectorState, error) {
	var state filesystemConnectorState
	if !identity.MatchString(appID) || !identity.MatchString(id) {
		return state, errors.New("Exact filesystem scope required")
	}
	if e := readEncrypted(s.filesystemStatePath(appID, id), &state); e != nil {
		return state, errors.New("No independently retained filesystem approval")
	}
	prepared, pe := time.Parse(time.RFC3339, state.PreparedAt)
	if pe != nil || validateFilesystemProvision(state.Input, prepared, os.Getenv("OWNER_SUBJECT")) != nil {
		return state, errors.New("Filesystem retained approval provenance is invalid")
	}
	expires, e := time.Parse(time.RFC3339, state.Input.Scope.AccessExpiresAt)
	if e != nil || !expires.After(time.Now()) || state.Input.Scope.AppID != appID || state.Input.Scope.ConnectionID != id || state.ScopeHash != filesystemArtifactHash(state.Input.Scope) || state.Input.ArtifactHash != state.ScopeHash {
		return state, errors.New("Filesystem approval expired or changed")
	}
	_, template, e := currentFilesystemScope(state.Input.Scope)
	if e != nil || !reflect.DeepEqual(template, state.Template) {
		return state, errors.New("Filesystem source or qualified image changed")
	}
	return state, nil
}

type filesystemContainerExpected struct{ Name, AppID, ResourceID, ConnectionID, Image, ScopeHash, HostSecret, HostSource, HostCA, Network string }

func (s *server) expectedFilesystemContainer(state filesystemConnectorState, v resources) (filesystemContainerExpected, error) {
	hostBase := env("HOST_DATA_DIR", "")
	if !filepath.IsAbs(hostBase) || strings.ContainsAny(hostBase, ",\x00\n\r") || !filepath.IsAbs(s.hostRuntime) || !identity.MatchString(v.AppID) || v.Network == "" {
		return filesystemContainerExpected{}, errors.New("Trusted company filesystem mount/network paths unavailable")
	}
	key := hashBytes([]byte(v.AppID + ":" + state.Input.Scope.ConnectionID))[:24]
	return filesystemContainerExpected{"as-filesystem-" + key, state.Input.Scope.AppID, v.AppID, state.Input.Scope.ConnectionID, state.Template.Image, state.ScopeHash, filepath.Join(s.hostRuntime, "connector-secrets", v.AppID, state.Input.Scope.ConnectionID, "filesystem"), filepath.Join(hostBase, "imports", state.Input.Scope.SourceID), filepath.Join(hostBase, "tls", "ca.crt"), v.Network}, nil
}
func validateFilesystemContainer(b []byte, expected filesystemContainerExpected) (string, error) {
	var c struct {
		ID     string `json:"Id"`
		Name   string
		Config struct {
			Image, User          string
			Cmd, Entrypoint, Env []string
			Labels               map[string]string
		}
		HostConfig struct {
			Runtime                                  string
			ReadonlyRootfs, Privileged               bool
			CapDrop, CapAdd, SecurityOpt, ExtraHosts []string
			PidsLimit                                int
			Memory, NanoCpus                         int64
			Tmpfs                                    map[string]string
			PortBindings                             map[string]any
			LogConfig                                struct{ Type string }
		}
		Mounts []struct {
			Type, Source, Destination string
			RW                        bool
		}
		NetworkSettings struct{ Networks map[string]any }
	}
	if json.Unmarshal(b, &c) != nil || !accessHex.MatchString(c.ID) || c.Name != "/"+expected.Name || c.Config.Image != expected.Image || c.Config.User != "10001:10001" || len(c.Config.Entrypoint) != 0 || !reflect.DeepEqual(c.Config.Cmd, []string{"python", "-I", "/opt/connector/filesystem.py"}) || c.Config.Labels["io.autosoft.managed"] != "true" || c.Config.Labels["io.autosoft.connector.type"] != "filesystem" || c.Config.Labels["io.autosoft.connector.app"] != expected.AppID || c.Config.Labels["io.autosoft.connector.resource"] != expected.ResourceID || c.Config.Labels["io.autosoft.connector.id"] != expected.ConnectionID || c.Config.Labels["io.autosoft.connector.scope"] != expected.ScopeHash {
		return "", errors.New("Filesystem adapter immutable ownership changed")
	}
	if c.HostConfig.Runtime != env("RUNSC_RUNTIME", "runsc") || !c.HostConfig.ReadonlyRootfs || c.HostConfig.Privileged || len(c.HostConfig.CapAdd) != 0 || !reflect.DeepEqual(c.HostConfig.CapDrop, []string{"ALL"}) || !containsConnector(c.HostConfig.SecurityOpt, "no-new-privileges") && !containsConnector(c.HostConfig.SecurityOpt, "no-new-privileges:true") || c.HostConfig.PidsLimit != 64 || c.HostConfig.Memory != 128<<20 || c.HostConfig.NanoCpus != 500000000 || len(c.HostConfig.Tmpfs) != 1 || c.HostConfig.Tmpfs["/tmp"] != "rw,nosuid,nodev,noexec,size=16m,mode=1777" || len(c.HostConfig.PortBindings) != 0 || c.HostConfig.LogConfig.Type != "journald" || len(c.HostConfig.ExtraHosts) != 0 || len(c.NetworkSettings.Networks) != 1 || c.NetworkSettings.Networks[expected.Network] == nil {
		return "", errors.New("Filesystem adapter escaped execution/network limits")
	}
	mounts := map[string]string{"/run/source": expected.HostSource, "/run/connector": expected.HostSecret, "/run/ca.crt": expected.HostCA}
	if len(c.Mounts) != len(mounts) {
		return "", errors.New("Filesystem mount inventory changed")
	}
	seen := map[string]bool{}
	for _, mount := range c.Mounts {
		if mount.Type != "bind" || mount.RW || mounts[mount.Destination] != mount.Source || seen[mount.Destination] {
			return "", errors.New("Filesystem source or credential mount escaped approved readonly scope")
		}
		seen[mount.Destination] = true
	}
	for _, value := range []string{"CONNECTOR_CONFIG_FILE=/run/connector/config.json", "CONNECTOR_TOKEN_FILE=/run/connector/token", "CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt", "CONNECTOR_TLS_KEY_FILE=/run/connector/app.key"} {
		if !containsConnector(c.Config.Env, value) {
			return "", errors.New("Filesystem sealed environment changed")
		}
	}
	return c.ID, nil
}
func (s *server) ensureFilesystemConnector(ctx context.Context, m AppManifest, v resources, id string, preview bool) (map[string]any, error) {
	state, e := s.loadApprovedFilesystem(m.ID, id)
	if e != nil {
		return nil, e
	}
	expected, e := s.expectedFilesystemContainer(state, v)
	if e != nil {
		return nil, e
	}
	var network struct {
		Name, Driver string
		Internal     bool
	}
	out, e := s.runner(ctx, "docker", "network", "inspect", "--format", "{{json .}}", v.Network)
	if e != nil || json.Unmarshal([]byte(out), &network) != nil || network.Name != v.Network || network.Driver != "bridge" || !network.Internal {
		return nil, errors.New("Filesystem adapters require the exact isolated internal application network")
	}
	feed, e := cachedFeed()
	if e != nil {
		return nil, e
	}
	findings, e := s.scanImage(ctx, state.Template.Image)
	if e != nil {
		return nil, e
	}
	for _, finding := range findings {
		if blockedSeverity(finding.Severity) {
			return nil, errors.New("Filesystem adapter security gate blocked")
		}
	}
	token, e := s.connectorAppToken(v.AppID)
	if e != nil {
		return nil, e
	}
	directory := filepath.Join(s.data, "connector-secrets", v.AppID, id, "filesystem")
	if e = os.MkdirAll(directory, 0700); e != nil {
		return nil, e
	}
	config := map[string]any{"schemaVersion": 1, "appId": m.ID, "connectionId": id, "sourceRootId": state.Input.Scope.SourceID, "root": state.Input.Scope.Root, "expiresAt": state.Input.Scope.AccessExpiresAt, "sourceEvidenceHash": state.Input.Scope.SourceHash, "templateSourceHash": state.Template.SourceHash, "capabilities": []string{"files.list", "files.read"}}
	b, _ := json.Marshal(config)
	if e = atomicTLSFile(filepath.Join(directory, "config.json"), b); e != nil {
		return nil, e
	}
	if e = atomicTLSFile(filepath.Join(directory, "token"), []byte(token)); e != nil {
		return nil, e
	}
	leaf := "filesystem-adapter-" + v.AppID + "-" + id
	if e = issueAppTLS(directory, leaf); e != nil {
		return nil, e
	}
	out, e = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", expected.Name)
	immutable := ""
	if e == nil {
		if immutable, e = validateFilesystemContainer([]byte(out), expected); e != nil {
			return nil, e
		}
		if _, e = s.runner(ctx, "docker", "start", immutable); e != nil {
			return nil, errors.New("Filesystem adapter resume unavailable")
		}
	} else {
		args := []string{"run", "-d", "--name", expected.Name, "--label", "io.autosoft.managed=true", "--label", "io.autosoft.connector.type=filesystem", "--label", "io.autosoft.connector.app=" + m.ID, "--label", "io.autosoft.connector.resource=" + v.AppID, "--label", "io.autosoft.connector.id=" + id, "--label", "io.autosoft.connector.scope=" + state.ScopeHash, "--restart", "unless-stopped", "--runtime", env("RUNSC_RUNTIME", "runsc"), "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5", "--log-driver", "journald", "--network", "name=" + v.Network + ",alias=" + appTLSHost(leaf), "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777", "--mount", "type=bind,src=" + expected.HostSource + ",dst=/run/source,readonly,bind-recursive=readonly", "--mount", "type=bind,src=" + expected.HostSecret + ",dst=/run/connector,readonly", "--mount", "type=bind,src=" + expected.HostCA + ",dst=/run/ca.crt,readonly"}
		for _, value := range []string{"CONNECTOR_CONFIG_FILE=/run/connector/config.json", "CONNECTOR_TOKEN_FILE=/run/connector/token", "CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt", "CONNECTOR_TLS_KEY_FILE=/run/connector/app.key"} {
			args = append(args, "--env", value)
		}
		args = append(args, state.Template.Image)
		out, e = s.runner(ctx, "docker", args...)
		immutable = strings.TrimSpace(out)
		if e != nil || !accessHex.MatchString(immutable) {
			return nil, errors.New("Filesystem adapter startup outcome unavailable")
		}
	}
	out, e = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", immutable)
	if e != nil {
		return nil, errors.New("Filesystem adapter isolation evidence unavailable")
	}
	if checked, checkError := validateFilesystemContainer([]byte(out), expected); checkError != nil || checked != immutable {
		return nil, errors.New("Filesystem immutable candidate changed before probe")
	}
	body, _ := json.Marshal(map[string]string{"appId": m.ID, "root": state.Input.Scope.Root, "path": ""})
	alias := appTLSHost(leaf)
	probe := "import http.client,json,ssl,socket;ctx=ssl.create_default_context(cafile='/run/ca.crt');c=http.client.HTTPSConnection('127.0.0.1',8443,context=ctx,timeout=8);c.connect=lambda:setattr(c,'sock',ctx.wrap_socket(socket.create_connection(('127.0.0.1',8443),timeout=8),server_hostname=" + strconv.Quote(alias) + "));token=open('/run/connector/token').read().strip();c.request('POST'," + strconv.Quote("/v1/connections/"+id+"/list") + "," + strconv.Quote(string(body)) + ",{'content-type':'application/json','authorization':'Bearer '+token});r=c.getresponse();b=r.read(1048576);assert r.status==200;v=json.loads(b);assert isinstance(v.get('entries'),list) and len(v['entries'])<=1000;print('root-verified')"
	out, e = s.runner(ctx, "docker", "exec", "--user=10001:10001", immutable, "python", "-I", "-c", probe)
	if e != nil || strings.TrimSpace(out) != "root-verified" {
		return nil, errors.New("Actual read-only filesystem/openat2 root access unavailable")
	}
	if _, e = s.loadApprovedFilesystem(m.ID, id); e != nil {
		return nil, e
	}
	out, e = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", immutable)
	if e != nil {
		return nil, errors.New("Filesystem immutable candidate evidence unavailable after probe")
	}
	if checked, checkError := validateFilesystemContainer([]byte(out), expected); checkError != nil || checked != immutable {
		return nil, errors.New("Filesystem immutable candidate changed after probe")
	}
	receipt := map[string]any{"appId": m.ID, "resourceId": v.AppID, "connectionId": id, "scopeHash": state.ScopeHash, "image": state.Template.Image, "sourceHash": state.Template.SourceHash, "adapter": expected.Name, "containerId": immutable, "checkedAt": time.Now().UTC().Format(time.RFC3339), "feedUpdatedAt": feed, "expiresAt": state.Input.Scope.AccessExpiresAt, "status": "passed"}
	if e = atomicJSON(filepath.Join(s.data, "connectors", "filesystem-live", v.AppID, id+".json"), receipt); e != nil {
		return nil, e
	}
	return map[string]any{"id": id, "type": "filesystem", "reviewStatus": "approved", "appIds": []string{m.ID}, "roots": []string{state.Input.Scope.Root}, "capabilities": []string{"files.list", "files.read"}, "adapterUrl": "https://" + alias + ":8443"}, nil
}
func (s *server) filesystemConnectorHost(ctx context.Context, m AppManifest, v resources, id string) (string, string, error) {
	state, e := s.loadApprovedFilesystem(m.ID, id)
	if e != nil {
		return "", "", e
	}
	candidate := v
	if identity.MatchString(v.ConnectorResourceID) {
		candidate.AppID = v.ConnectorResourceID
	}
	expected, e := s.expectedFilesystemContainer(state, candidate)
	if e != nil {
		return "", "", e
	}
	out, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", expected.Name)
	if e != nil {
		return "", "", errors.New("Filesystem host mapping unavailable")
	}
	if _, e = validateFilesystemContainer([]byte(out), expected); e != nil {
		return "", "", e
	}
	ip, e := s.connectorPrivateAddress(ctx, expected.Name, v.Network)
	return appTLSHost("filesystem-adapter-" + candidate.AppID + "-" + id), ip, e
}
func (s *server) retireFilesystemConnector(ctx context.Context, m AppManifest, v resources, id string, inspectOnly bool) error {
	var state filesystemConnectorState
	if !identity.MatchString(m.ID) || !identity.MatchString(id) || readEncrypted(s.filesystemStatePath(m.ID, id), &state) != nil || state.Input.Scope.AppID != m.ID || state.Input.Scope.ConnectionID != id || validateFilesystemRetirementState(state) != nil {
		return errors.New("Filesystem retirement lacks independent ownership evidence")
	}
	expected, e := s.expectedFilesystemContainer(state, v)
	if e != nil {
		return e
	}
	out, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", expected.Name)
	if e != nil {
		return errors.New("Filesystem retirement outcome unavailable; no broad deletion")
	}
	immutable, e := validateFilesystemContainer([]byte(out), expected)
	if e != nil {
		return e
	}
	if inspectOnly {
		return nil
	}
	if _, e = s.runner(ctx, "docker", "rm", "--force", immutable); e != nil {
		return errors.New("Filesystem capability retirement outcome unavailable")
	}
	return nil
}

// Revoking a retained exact owned container must remain possible after its grant
// expires; the original approved record still has to prove its immutable origin.
func validateFilesystemRetirementState(state filesystemConnectorState) error {
	prepared, e := time.Parse(time.RFC3339, state.PreparedAt)
	checked, qe := time.Parse(time.RFC3339, state.Template.Qualification.CheckedAt)
	if e != nil || qe != nil || checked.After(prepared.Add(time.Minute)) || prepared.Sub(checked) > 30*24*time.Hour || validateFilesystemProvision(state.Input, prepared, os.Getenv("OWNER_SUBJECT")) != nil || state.ScopeHash != filesystemArtifactHash(state.Input.Scope) || state.Input.ArtifactHash != state.ScopeHash || !digestImage.MatchString(state.Template.Image) || !strings.HasPrefix(state.Template.Image, "registry:5000/connectors/filesystem@") || state.Template.Image != state.Input.Scope.Image || !accessHex.MatchString(state.Template.SourceHash) || state.Template.SourceHash != state.Input.Scope.TemplateSourceHash || !accessHex.MatchString(state.Input.Scope.SourceHash) || state.Template.Qualification.ReportHash != state.Input.Scope.QualificationHash || !accessHex.MatchString(state.Template.Qualification.ReportHash) || state.Template.Qualification.Status != "passed" || state.Template.Qualification.Scope != "synthetic-readonly-filesystem-runsc" {
		return errors.New("Filesystem retirement origin is not bound to its approved qualified source/image")
	}
	return nil
}
func (s *server) scanFilesystemConnector(ctx context.Context, m AppManifest, id string) ([]Finding, error) {
	state, e := s.loadApprovedFilesystem(m.ID, id)
	if e != nil {
		return nil, e
	}
	findings, e := s.scanImage(ctx, state.Template.Image)
	if e != nil {
		return nil, fmt.Errorf("Filesystem adapter image coverage unavailable: %w", e)
	}
	return findings, nil
}
