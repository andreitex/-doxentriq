package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDailySecurityBindsSourceAndImageToTheIndependentRelease(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "runtime")
	if e := os.Mkdir(data, 0700); e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(data, "sources", "attempt1")
	if e := os.MkdirAll(source, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(source, "server.mjs"), []byte("export const safe=true;"), 0600); e != nil {
		t.Fatal(e)
	}
	manifest := AppManifest{Version: 1, ID: "app1", Slug: "documents", Name: "Documents", Kind: "api", Template: "node-api", Auth: "sso", Connections: []string{}}
	manifest.Resources.CPU, manifest.Resources.Memory, manifest.Resources.Pids = 1, 256, 64
	manifest.Health.Path, manifest.Health.Port = "/healthz", 8080
	if e := atomicJSON(filepath.Join(source, "app.manifest.json"), manifest); e != nil {
		t.Fatal(e)
	}
	hash, e := sourceDigest(source)
	if e != nil {
		t.Fatal(e)
	}
	image := "registry:5000/apps/app1@sha256:" + strings.Repeat("a", 64)
	v := Verification{AppID: "app1", AttemptID: "attempt1", Template: manifest.Template, Commit: strings.Repeat("b", 40), Images: []string{image}, SourceHash: hash, Evidence: Evidence{Status: "passed"}}
	if e := atomicJSON(filepath.Join(data, "receipts", "attempt1.json"), v); e != nil {
		t.Fatal(e)
	}
	cache := filepath.Join(base, "security-cache")
	now := time.Now()
	if e := atomicJSON(filepath.Join(cache, "trivy", "db", "metadata.json"), map[string]any{"Version": 2, "UpdatedAt": now, "NextUpdate": now.Add(24 * time.Hour)}); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(cache, "trivy", "db", "trivy.db"), []byte("synthetic-db"), 0644); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SECURITY_CACHE_DIR", cache)
	t.Setenv("HOST_DATA_DIR", base)
	credentials := filepath.Join(data, "registry.json")
	_ = os.WriteFile(credentials, []byte(`{"username":"fixture","password":"fixture"}`), 0600)
	t.Setenv("REGISTRY_CREDENTIALS_FILE", credentials)
	scans := 0
	s := &server{data: data, hostRuntime: data, manifest: RuntimeManifest{ScannerImage: "registry:5000/scanner@sha256:" + strings.Repeat("c", 64)}, runner: func(_ context.Context, _ string, args ...string) (string, error) {
		scans++
		text := strings.Join(args, " ")
		if !strings.Contains(text, "--read-only") {
			t.Fatal("Uncontained scan")
		}
		if strings.Contains(text, " image ") {
			return `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"debian","EOSL":false}},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-fixture","Severity":"MEDIUM","PkgName":"fixture","InstalledVersion":"1.0","Title":"Fixed version available"}]}]}`, nil
		}
		return `{"SchemaVersion":2,"Results":[]}`, nil
	}}
	installTrustedServiceTestFixture(t, s, "autosoft_artifact", "registry")
	scanner := installImageScannerServerFixture(t, s, base, "MEDIUM")
	t.Setenv("BROKER_VAULT_KEY_FILE", "")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x07", 32))))
	if key, err := vaultKey(); err != nil || len(key) != 32 {
		t.Fatal("Daily security fixture requires a valid 32-byte synthetic vault key")
	}
	in := releaseSecurityRequest{AppID: "app1", ReleaseID: "release1", Commit: v.Commit, Images: v.Images}
	body, _ := json.Marshal(in)
	request := httptest.NewRequest("POST", "/v1/security", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	s.releaseSecurity(response, request)
	var report releaseSecurityReport
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &report) != nil || report.ReleaseID != "release1" || scans != 1 {
		t.Fatalf("Daily result invalid: %s; scans%d", response.Body.String(), scans)
	}
	if runtime.GOOS == "linux" {
		if report.Status != "failed" || len(report.Findings) != 1 || scanner.count("start") != 1 || !scanner.removed {
			t.Fatalf("Native scanner lifecycle result invalid: %s", response.Body.String())
		}
	} else if report.Status != "unavailable" || len(report.Findings) != 0 || scanner.created {
		t.Fatal("Non-Linux test claimed durable scanner execution")
	}
	wrong := in
	wrong.Images = []string{"registry:5000/other@sha256:" + strings.Repeat("d", 64)}
	if _, e = s.securityReceipt(wrong); e == nil {
		t.Fatal("Another image's security evidence was reused")
	}
	_ = os.WriteFile(filepath.Join(source, "server.mjs"), []byte("changed"), 0600)
	response = httptest.NewRecorder()
	s.releaseSecurity(response, httptest.NewRequest("POST", "/v1/security", strings.NewReader(string(body))))
	if json.Unmarshal(response.Body.Bytes(), &report) != nil || report.Status != "unavailable" || scans != 1 {
		t.Fatal("Tampered source obtained daily security coverage")
	}
}
