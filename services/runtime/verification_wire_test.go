package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
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

func TestSourceScannerKeepsMachineOutputAndBlockingFindings(t *testing.T) {
	s, f, workspace := sourceScannerServerFixture(t)
	findings, feed, err := s.scan(context.Background(), workspace, sourceScannerFixtureInput(t, s))
	if err != nil || feed == "" || len(findings) != 1 || !blockedSeverity(findings[0].Severity) || !f.removed {
		t.Fatalf("Machine output must preserve Medium findings only after confirmed cleanup: %v", err)
	}
	for _, command := range f.calls {
		if command[0] == "create" {
			flags := " " + strings.Join(command, " ") + " "
			for _, flag := range []string{" --quiet ", " --config= ", " --ignorefile= "} {
				if !strings.Contains(flags, flag) {
					t.Fatalf("missing protocol control %s", flag)
				}
			}
		}
	}
}
