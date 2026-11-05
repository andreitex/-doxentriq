package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func filesystemRequestFixture() filesystemProvision {
	in := filesystemProvision{Version: 1, Action: "approve_readonly_filesystem", OperationID: "operation-one", ApprovalID: "approval-one", ApprovedAt: time.Now().UTC().Format(time.RFC3339), Scope: filesystemScope{filesystemSourceEvidence: filesystemSourceEvidence{"import-one", strings.Repeat("a", 64), time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339), strings.Repeat("b", 64), "registry:5000/connectors/filesystem@sha256:" + strings.Repeat("c", 64), strings.Repeat("d", 64)}, AppID: "app-one", ConnectionID: "connection-one", Type: "filesystem", Root: "documents", AccessExpiresAt: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), RegistryHash: strings.Repeat("e", 64)}}
	in.Principal.ID = "owner-one"
	in.Principal.MFA = true
	in.Principal.LocalOwner = true
	in.ArtifactHash = filesystemArtifactHash(in.Scope)
	return in
}
func TestFilesystemApprovalExactOwnerArtifactScopeAndExpiry(t *testing.T) {
	in := filesystemRequestFixture()
	if e := validateFilesystemProvision(in, time.Now(), "owner-one"); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*filesystemProvision){func(v *filesystemProvision) { v.Principal.MFA = false }, func(v *filesystemProvision) { v.Principal.LocalOwner = false }, func(v *filesystemProvision) { v.Principal.ID = "sso-admin" }, func(v *filesystemProvision) { v.Scope.Root = "../outside" }, func(v *filesystemProvision) { v.Scope.Root = "different" }, func(v *filesystemProvision) { v.Scope.AppID = "other-app" }, func(v *filesystemProvision) { v.Scope.SourceID = "../../etc" }, func(v *filesystemProvision) {
		v.ApprovedAt = time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339)
	}, func(v *filesystemProvision) {
		v.Scope.AccessExpiresAt = time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
		v.ArtifactHash = filesystemArtifactHash(v.Scope)
	}} {
		changed := in
		mutate(&changed)
		if validateFilesystemProvision(changed, time.Now(), "owner-one") == nil {
			t.Fatal("changed scope/approval accepted")
		}
	}
}
func TestFilesystemManifestRequiresPinnedSourceAndActualRunscQualification(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "manifest.json")
	t.Setenv("RUNTIME_MANIFEST_PATH", file)
	valid := map[string]any{"image": "registry:5000/connectors/filesystem@sha256:" + strings.Repeat("c", 64), "sourceSha256": strings.Repeat("b", 64), "protocolQualification": map[string]any{"status": "passed", "reportSha256": strings.Repeat("d", 64), "checkedAt": time.Now().UTC().Format(time.RFC3339), "scope": "synthetic-readonly-filesystem-runsc"}}
	write := func(value map[string]any) {
		b, _ := json.Marshal(map[string]any{"connectors": map[string]any{"filesystem": value}})
		if e := os.WriteFile(file, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(valid)
	if _, e := readFilesystemTemplate(); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"image", "sourceSha256", "protocolQualification"} {
		b, _ := json.Marshal(valid)
		var changed map[string]any
		_ = json.Unmarshal(b, &changed)
		changed[field] = "unqualified"
		write(changed)
		if _, e := readFilesystemTemplate(); e == nil {
			t.Fatal("invalid qualification accepted: " + field)
		}
	}
}
func filesystemContainerFixture(expected filesystemContainerExpected) map[string]any {
	return map[string]any{"Id": strings.Repeat("f", 64), "Name": "/" + expected.Name, "Config": map[string]any{"Image": expected.Image, "User": "10001:10001", "Cmd": []string{"python", "-I", "/opt/connector/filesystem.py"}, "Entrypoint": []string{}, "Env": []string{"CONNECTOR_CONFIG_FILE=/run/connector/config.json", "CONNECTOR_TOKEN_FILE=/run/connector/token", "CONNECTOR_TLS_CERT_FILE=/run/connector/app.crt", "CONNECTOR_TLS_KEY_FILE=/run/connector/app.key"}, "Labels": map[string]string{"io.autosoft.managed": "true", "io.autosoft.connector.type": "filesystem", "io.autosoft.connector.app": expected.AppID, "io.autosoft.connector.resource": expected.ResourceID, "io.autosoft.connector.id": expected.ConnectionID, "io.autosoft.connector.scope": expected.ScopeHash}}, "HostConfig": map[string]any{"Runtime": "runsc", "ReadonlyRootfs": true, "Privileged": false, "CapDrop": []string{"ALL"}, "CapAdd": []string{}, "SecurityOpt": []string{"no-new-privileges"}, "PidsLimit": 64, "Memory": 128 << 20, "NanoCpus": 500000000, "Tmpfs": map[string]string{"/tmp": "rw,nosuid,nodev,noexec,size=16m,mode=1777"}, "PortBindings": map[string]any{}, "ExtraHosts": []string{}, "LogConfig": map[string]string{"Type": "journald"}}, "NetworkSettings": map[string]any{"Networks": map[string]any{expected.Network: map[string]any{}}}, "Mounts": []map[string]any{{"Type": "bind", "Source": expected.HostSource, "Destination": "/run/source", "RW": false}, {"Type": "bind", "Source": expected.HostSecret, "Destination": "/run/connector", "RW": false}, {"Type": "bind", "Source": expected.HostCA, "Destination": "/run/ca.crt", "RW": false}}}
}
func TestFilesystemContainerRejectsForeignOwnershipWritableRootsHostNetworkAndDockerSocket(t *testing.T) {
	t.Setenv("RUNSC_RUNTIME", "runsc")
	expected := filesystemContainerExpected{"as-filesystem-test", "app-one", "candidate-one", "connection-one", "registry:5000/connectors/filesystem@sha256:" + strings.Repeat("c", 64), strings.Repeat("a", 64), "/encrypted/runtime/secrets", "/encrypted/imports/import-one", "/encrypted/tls/ca.crt", "as-app-one"}
	valid := filesystemContainerFixture(expected)
	b, _ := json.Marshal(valid)
	id, e := validateFilesystemContainer(b, expected)
	if e != nil || id != strings.Repeat("f", 64) {
		t.Fatal("valid company scope rejected", e)
	}
	for _, change := range []func(map[string]any){func(c map[string]any) {
		c["Config"].(map[string]any)["Labels"].(map[string]string)["io.autosoft.connector.app"] = "other"
	}, func(c map[string]any) { c["HostConfig"].(map[string]any)["Privileged"] = true }, func(c map[string]any) { c["HostConfig"].(map[string]any)["Runtime"] = "runc" }, func(c map[string]any) {
		c["NetworkSettings"] = map[string]any{"Networks": map[string]any{"host": map[string]any{}}}
	}, func(c map[string]any) { c["Mounts"].([]map[string]any)[0]["RW"] = true }, func(c map[string]any) { c["Mounts"].([]map[string]any)[0]["Source"] = "/etc" }, func(c map[string]any) {
		c["Mounts"] = append(c["Mounts"].([]map[string]any), map[string]any{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": false})
	}, func(c map[string]any) {
		c["HostConfig"].(map[string]any)["ExtraHosts"] = []string{"api.example.test:127.0.0.1"}
	}} {
		changed := filesystemContainerFixture(expected)
		change(changed)
		b, _ := json.Marshal(changed)
		if _, e := validateFilesystemContainer(b, expected); e == nil {
			t.Fatal("escaped connector accepted")
		}
	}
}
func TestFilesystemDispatchWithoutProofIsConfirmedRejectedAndDoesNotMutate(t *testing.T) {
	s := &server{approvalKey: bytes.Repeat([]byte{7}, 32), data: t.TempDir()}
	in := filesystemRequestFixture()
	b, _ := json.Marshal(in)
	r := httptest.NewRequest(http.MethodPost, "/v1/connectors/filesystem/provision", bytes.NewReader(b))
	w := httptest.NewRecorder()
	s.provisionFilesystem(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"rejectedBeforeExecution":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, e := os.Stat(s.filesystemStatePath(in.Scope.AppID, in.Scope.ConnectionID)); !os.IsNotExist(e) {
		t.Fatal("unauthorized state mutation")
	}
}
func TestFilesystemArtifactHashMatchesControlCanonicalProjection(t *testing.T) {
	in := filesystemRequestFixture()
	in.Scope.ExpiresAt = "2026-10-11T00:00:00.000Z"
	in.Scope.AccessExpiresAt = "2026-10-10T23:00:00.000Z"
	canonical := `{"action":"approve_readonly_filesystem","schemaVersion":1,"scope":{"accessExpiresAt":"2026-10-10T23:00:00.000Z","appId":"app-one","connectionId":"connection-one","qualificationReportHash":"` + strings.Repeat("d", 64) + `","registryHash":"` + strings.Repeat("e", 64) + `","root":"documents","sourceEvidenceHash":"` + strings.Repeat("a", 64) + `","sourceExpiresAt":"2026-10-11T00:00:00.000Z","sourceRootId":"import-one","templateImage":"registry:5000/connectors/filesystem@sha256:` + strings.Repeat("c", 64) + `","templateSourceHash":"` + strings.Repeat("b", 64) + `","type":"filesystem"}}`
	if filesystemArtifactHash(in.Scope) != hashBytes([]byte(canonical)) {
		t.Fatal("artifact projection differs from control")
	}
}

func TestFilesystemExpiredCapabilityRetiresOnlyFromOriginalExactQualifiedApproval(t *testing.T) {
	t.Setenv("OWNER_SUBJECT", "owner-one")
	prepared := time.Now().Add(-48 * time.Hour).UTC()
	in := filesystemRequestFixture()
	in.ApprovedAt = prepared.Format(time.RFC3339)
	in.Scope.AccessExpiresAt = prepared.Add(time.Hour).Format(time.RFC3339)
	in.Scope.ExpiresAt = prepared.Add(2 * time.Hour).Format(time.RFC3339)
	in.ArtifactHash = filesystemArtifactHash(in.Scope)
	template := filesystemTemplate{Image: in.Scope.Image, SourceHash: in.Scope.TemplateSourceHash}
	template.Qualification.Status = "passed"
	template.Qualification.ReportHash = in.Scope.QualificationHash
	template.Qualification.Scope = "synthetic-readonly-filesystem-runsc"
	template.Qualification.CheckedAt = prepared.Format(time.RFC3339)
	state := filesystemConnectorState{in, in.ArtifactHash, template, prepared.Format(time.RFC3339)}
	if e := validateFilesystemRetirementState(state); e != nil {
		t.Fatal("expired exact owned capability could not retire", e)
	}
	for _, mutation := range []func(*filesystemConnectorState){func(v *filesystemConnectorState) { v.Input.Principal.MFA = false }, func(v *filesystemConnectorState) { v.Template.SourceHash = strings.Repeat("f", 64) }, func(v *filesystemConnectorState) {
		v.Template.Image = "registry:5000/connectors/filesystem@sha256:" + strings.Repeat("f", 64)
	}, func(v *filesystemConnectorState) { v.Input.Scope.SourceID = "../../etc" }, func(v *filesystemConnectorState) { v.Template.Qualification.CheckedAt = "unknown" }, func(v *filesystemConnectorState) { v.ScopeHash = strings.Repeat("f", 64) }} {
		changed := state
		mutation(&changed)
		if validateFilesystemRetirementState(changed) == nil {
			t.Fatal("foreign or unqualified retirement provenance accepted")
		}
	}
}

func TestFilesystemSourceEvidencePreservesExact64BitInodeIdentity(t *testing.T) {
	source := filesystemSource{ID: "import-one", AppIDs: []string{"app-one"}, Device: 2, Inode: 9007199254740992, ReviewedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	one := filesystemEvidence(source, filesystemTemplate{})
	source.Inode++
	two := filesystemEvidence(source, filesystemTemplate{})
	if one.SourceHash == two.SourceHash {
		t.Fatal("distinct 64-bit source inode identities collided after canonical JSON normalization")
	}
}

func TestFilesystemCatalogIsRootOwnedAndReadOnlyForBrokerGroup(t *testing.T) {
	type owner struct{ Uid, Gid uint32 }
	if !filesystemCatalogOwner(&owner{0, 10001}, 0640) {
		t.Fatal("protected root:broker read-only catalog rejected")
	}
	for _, item := range []struct {
		owner owner
		mode  os.FileMode
	}{{owner{10001, 10001}, 0640}, {owner{0, 0}, 0640}, {owner{0, 10001}, 0660}, {owner{0, 10001}, 0644}, {owner{0, 10001}, 0600}, {owner{0, 10001}, 0740}} {
		if filesystemCatalogOwner(item.owner, item.mode) {
			t.Fatal("mutable, unreadable or foreign company catalog accepted")
		}
	}
}
