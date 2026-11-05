package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFailedVerificationWirePreservesActualChecks(t *testing.T) {
	v := Verification{Evidence: Evidence{Status: "failed", Checks: []Check{{"security", false, "Scanner returned invalid evidence"}}}}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(b, &result) != nil {
		t.Fatal("Invalid verification JSON")
	}
	if result["previewUrl"] != nil || strings.Count(string(b), `"previewUrl"`) != 1 {
		t.Fatal("Missing preview must be exactly one JSON null")
	}
	for _, key := range []string{"images", "migrations"} {
		if list, ok := result[key].([]any); !ok || len(list) != 0 {
			t.Fatalf("%s must remain an empty array", key)
		}
	}
	evidence := result["evidence"].(map[string]any)
	if findings, ok := evidence["findings"].([]any); !ok || len(findings) != 0 {
		t.Fatal("A failed scan must have a schema-valid findings array")
	}
	if evidence["status"] != "failed" || evidence["checks"].([]any)[0].(map[string]any)["passed"] != false {
		t.Fatal("Failure must never become successful verification")
	}
	var replay Verification
	if json.Unmarshal(b, &replay) != nil || replay.PreviewURL != "" || replay.Evidence.Checks[0].Detail != v.Evidence.Checks[0].Detail {
		t.Fatal("Retained failure must remain readable for reconciliation")
	}
	v.PreviewURL = "https://preview-app.example.test"
	b, err = json.Marshal(v)
	if err != nil || !strings.Contains(string(b), `"previewUrl":"https://preview-app.example.test"`) {
		t.Fatal("An existing preview URL must survive encoding")
	}
}

func TestSourceScannerKeepsCombinedOutputMachineReadable(t *testing.T) {
	cache := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "trivy", "db"), 0700); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]string{"UpdatedAt": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(cache, "trivy", "db", "metadata.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOST_SECURITY_CACHE_DIR", cache)
	t.Setenv("SECURITY_CACHE_DIR", cache)
	s := server{manifest: testManifest(), runner: func(_ context.Context, _ string, args ...string) (string, error) {
		flags := " " + strings.Join(args, " ") + " "
		for _, flag := range []string{" --quiet ", " --config= ", " --ignorefile= "} {
			if !strings.Contains(flags, flag) {
				t.Fatalf("Missing scanner protocol control %s", flag)
			}
		}
		return `{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-fixture","Severity":"MEDIUM","PkgName":"fixture","InstalledVersion":"1"}]}]}`, nil
	}}
	s.manifest.ScannerImage = "registry:5000/scanner@sha256:" + strings.Repeat("c", 64)
	findings, feed, err := s.scan(context.Background(), "/fixture")
	if err != nil || feed == "" || len(findings) != 1 || !blockedSeverity(findings[0].Severity) {
		t.Fatalf("Quiet machine output must preserve the blocking Medium finding: error=%v feed=%q findings=%d", err, feed, len(findings))
	}
}
