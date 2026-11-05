package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testManifest() RuntimeManifest {
	return RuntimeManifest{Version: 1, Templates: map[string]Template{"node-api": {ToolchainImage: "registry:5000/node@sha256:" + strings.Repeat("a", 64), RuntimeImage: "registry:5000/node@sha256:" + strings.Repeat("b", 64), Entrypoint: []string{"node", "/app/server.mjs"}, Port: 8080}}}
}
func TestMandatoryPipeline(t *testing.T) {
	m := testManifest()
	p := Pipeline{Version: 1, Template: "node-api"}
	for _, name := range mandatoryStages {
		p.Stages = append(p.Stages, Stage{Name: name, Timeout: 60})
	}
	if e := validatePipeline(p, m); e != nil {
		t.Fatal(e)
	}
	p.Stages[0].Name = "build"
	if validatePipeline(p, m) == nil {
		t.Fatal("Duplicate mandatory stage accepted")
	}
	p.Template = "untrusted-custom"
	if validatePipeline(p, m) == nil {
		t.Fatal("Unapproved runtime accepted")
	}
}
func TestScopedPaths(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"../other", "/root", "app/id", "app\\id", "app,src=/etc"} {
		if _, e := safePath(root, id); e == nil {
			t.Fatalf("Unsafe identifier accepted: %s", id)
		}
	}
	if _, e := safePath(root, "app1", "job1"); e != nil {
		t.Fatal(e)
	}
}
func TestSandboxContainsGeneratedCommands(t *testing.T) {
	var actual []string
	s := server{manifest: testManifest(), runner: func(_ context.Context, name string, args ...string) (string, error) {
		if name != "docker" {
			t.Fatal("Generated command escaped to host executable")
		}
		actual = args
		return "ok", nil
	}}
	_, e := s.sandbox(context.Background(), "build1", filepath.Join(t.TempDir(), "work"), s.manifest.Templates["node-api"], []string{"/bin/sh", "-lc", "curl http://private; cat /etc/shadow"}, false)
	if e != nil {
		t.Fatal(e)
	}
	text := strings.Join(actual, " ")
	for _, required := range []string{"--runtime runsc", "--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--pids-limit 128", "--memory 1g", "--cpus 2", "--user 10001:10001"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Missing containment %s", required)
		}
	}
	if strings.Contains(text, "docker.sock") || strings.Contains(text, "--privileged") {
		t.Fatal("Privileged mount exposed")
	}
}
func TestDependencyProvenance(t *testing.T) {
	root := t.TempDir()
	for _, version := range []string{"^1.0.0", "https://evil.example/package.tgz", "git+ssh://host/repo", "file:/etc"} {
		b, _ := json.Marshal(map[string]any{"dependencies": map[string]string{"package": version}})
		_ = os.WriteFile(filepath.Join(root, "package.json"), b, 0600)
		if _, e := dependencyCommand(root, "node-api"); e == nil {
			t.Fatalf("Unsafe dependency accepted: %s", version)
		}
	}
	_ = os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"package":"1.0.0"}}`), 0600)
	if _, e := dependencyCommand(root, "node-api"); e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"packages":{"node_modules/package":{"resolved":"https://evil.example/p.tgz","integrity":"sha512-x"}}}`), 0600)
	if _, e := dependencyCommand(root, "node-api"); e == nil {
		t.Fatal("Untrusted transitive download accepted")
	}
}
func TestSQLDestructionAndCrossDatabaseAccess(t *testing.T) {
	for _, sql := range []string{"DROP TABLE documents", "ALTER TABLE documents DROP COLUMN body", "DELETE FROM documents", "CREATE TABLE leaked AS SELECT * FROM app_other.documents", "CREATE TABLE t (x int); GRANT ALL ON *.* TO 'evil'", "CREATE TABLE t (x int) /*hidden*/"} {
		if validateSQL(sql) == nil {
			t.Fatalf("Unsafe migration accepted: %s", sql)
		}
	}
	if e := validateSQL("CREATE TABLE IF NOT EXISTS documents (id VARCHAR(80) PRIMARY KEY, title TEXT NOT NULL) ENCRYPTION='Y'; ALTER TABLE documents ADD COLUMN tag VARCHAR(100)"); e != nil {
		t.Fatal(e)
	}
}
func TestAdditivePrefixCannotHideOtherOperations(t *testing.T) {
	for _, statement := range []string{
		"ALTER TABLE documents ADD safe INT, MODIFY original VARCHAR(1)",
		"ALTER TABLE documents ADD safe INT, CHANGE COLUMN original renamed VARCHAR(1)",
		"ALTER TABLE documents ADD safe INT, CONVERT TO CHARACTER SET latin1",
		"ALTER TABLE documents ADD safe INT, ADD other INT",
		"ALTER TABLE documents ADD PARTITION (PARTITION p1 VALUES LESS THAN (100))",
		"ALTER TABLE documents ADD safe INT, RENAME COLUMN title TO name",
		"CREATE TABLE documents (id INT) ENGINE=BLACKHOLE",
		"CREATE TABLE documents (id INT) DATA DIRECTORY='/var/lib/mysql/other'",
		"CREATE TABLE documents (id INT) ENCRYPTION='N'",
		"CREATE TABLE documents (id INT) ENCRYPTION='Y' ENCRYPTION='N'",
		"CREATE TABLE documents (id INT) DEFAULT CHARSET=latin1",
		"ALTER TABLE _autosoft_migrations ADD forged INT",
		"CREATE INDEX forged ON `_autosoft_migrations` (checksum)",
		"ALTER TABLE documents ADD malformed VARCHAR(10",
		"ALTER TABLE documents ADD bad VARCHAR(10) DEFAULT 'unterminated",
		"ALTER TABLE documents ADD required_title TEXT NOT NULL",
		"ALTER TABLE documents ADD counter INT NOT NULL DEFAULT 0",
		"ALTER TABLE documents ADD UNIQUE INDEX title_unique (title)",
		"ALTER TABLE documents ADD CHECK (id > 0)",
		"ALTER TABLE documents ADD COLUMN before_title TEXT FIRST",
		"CREATE UNIQUE INDEX unique_title ON documents (title,id)",
	} {
		if validateSQL(statement) == nil {
			t.Fatalf("Non-additive capability accepted: %s", statement)
		}
	}
	for _, statement := range []string{
		"CREATE TABLE IF NOT EXISTS documents (id VARCHAR(80) PRIMARY KEY, title TEXT NOT NULL) ENCRYPTION='Y'",
		"ALTER TABLE documents ADD COLUMN amount DECIMAL(10,2)",
		"ALTER TABLE documents ADD INDEX metadata_lookup (title, id)",
		"ALTER TABLE documents ADD COLUMN label VARCHAR(50) DEFAULT 'a,b'",
	} {
		if e := validateSQL(statement); e != nil {
			t.Fatalf("Safe additive statement rejected: %s: %v", statement, e)
		}
	}
}
func TestArchiveHasSafePermissionsAndNoTraversal(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "server.mjs"), []byte("console.log('test')"), 0777)
	archive, e := layerArchive(root)
	if e != nil {
		t.Fatal(e)
	}
	tr := tar.NewReader(bytes.NewReader(archive))
	h, e := tr.Next()
	if e != nil {
		t.Fatal(e)
	}
	if h.Name != "app/server.mjs" || h.Mode != 0444 || h.Uid != 10001 || h.Gid != 10001 {
		t.Fatalf("Unsafe header: %+v", h)
	}
	if _, e = tr.Next(); e != io.EOF {
		t.Fatal("Unexpected artifact")
	}
	if e = os.Symlink(filepath.Join(root, "server.mjs"), filepath.Join(root, "escape")); e == nil {
		if _, e = layerArchive(root); e == nil {
			t.Fatal("Symbolic link accepted")
		}
	}
}
func TestPublicationProofBindsExactBody(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	body := []byte(`{"appId":"a","artifactHash":"h"}`)
	h := hmac.New(sha256.New, key)
	h.Write(body)
	proof := hex.EncodeToString(h.Sum(nil))
	if !signedBody(key, body, proof) {
		t.Fatal("Valid proof rejected")
	}
	if signedBody(key, append(body, ' '), proof) || signedBody(bytes.Repeat([]byte{2}, 32), body, proof) {
		t.Fatal("Altered proof accepted")
	}
}
func goodDeployment() (deployment, Verification) {
	date := time.Now().UTC().Format(time.RFC3339)
	image := "registry:5000/apps/app1@sha256:" + strings.Repeat("a", 64)
	v := Verification{AppID: "app1", Commit: strings.Repeat("b", 40), Images: []string{image}, Schema: 1, SchemaMin: 1, SchemaMax: 1, Evidence: Evidence{Status: "passed", CheckedAt: date, FeedUpdatedAt: date, Findings: []Finding{}}}
	for _, name := range mandatoryStages {
		v.Evidence.Checks = append(v.Evidence.Checks, Check{name, true, "verified"})
	}
	in := deployment{Release: release{ID: "r1", AppID: "app1", Hash: strings.Repeat("c", 64), Commit: v.Commit, Images: v.Images, Schema: 1, SchemaMin: 1, SchemaMax: 1, Evidence: v.Evidence}, Approval: approval{ID: "approve1", AppID: "app1", ReleaseID: "r1", Hash: strings.Repeat("c", 64), Action: "publish", ApprovedBy: "owner", ApprovedAt: date, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, OperationID: "op1", Action: "publish"}
	in.App.ID = "app1"
	return in, v
}
func TestReleaseReceiptIsIndependent(t *testing.T) {
	in, v := goodDeployment()
	if e := checkDeploy(in, v, nil); e != nil {
		t.Fatal(e)
	}
	in.Release.Images = []string{"registry:5000/apps/app1@sha256:" + strings.Repeat("d", 64)}
	if checkDeploy(in, v, nil) == nil {
		t.Fatal("Tampered image accepted")
	}
	in, v = goodDeployment()
	v.Evidence.Findings = append(v.Evidence.Findings, Finding{Severity: "MEDIUM"})
	in.Release.Evidence = v.Evidence
	if checkDeploy(in, v, nil) == nil {
		t.Fatal("Vulnerable image accepted")
	}
	in, v = goodDeployment()
	in.Approval.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
	if checkDeploy(in, v, nil) == nil {
		t.Fatal("Expired approval accepted")
	}
	in, v = goodDeployment()
	if checkDeploy(in, v, &activeDeployment{ReleaseID: "changed", Schema: 1}) == nil {
		t.Fatal("Stale baseline accepted")
	}
}
func TestRejectedProofDoesNotExecuteDocker(t *testing.T) {
	calls := 0
	s := server{approvalKey: bytes.Repeat([]byte{1}, 32), runner: func(context.Context, string, ...string) (string, error) {
		calls++
		return "", errors.New("should not execute")
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/deploy", strings.NewReader(`{}`))
	s.deploy(w, r)
	if w.Code != 403 || calls != 0 {
		t.Fatal("Unapproved request reached privileged command")
	}
}
