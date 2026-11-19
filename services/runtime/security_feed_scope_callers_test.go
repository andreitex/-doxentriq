//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecurityFeedScopeConnectorApprovalRechecksAfterScanning(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "promoted-after-scan"}[change], func(t *testing.T) {
			connectorManifestFixture(t)
			now := time.Now().UTC()
			in := connectorApprovalFixture(now)
			t.Setenv("OWNER_SUBJECT", in.Principal.ID)
			base := t.TempDir()
			data := filepath.Join(base, "runtime")
			if os.Mkdir(data, 0700) != nil {
				t.Fatal("fixture runtime unavailable")
			}
			t.Setenv("HOST_DATA_DIR", base)
			t.Setenv("SECURITY_CACHE_DIR", filepath.Join(base, "security-cache"))
			t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
			if e := atomicJSON(filepath.Join(base, "security-cache", "trivy/db/metadata.json"), map[string]any{"Version": 2, "UpdatedAt": now, "NextUpdate": now.Add(24 * time.Hour), "DownloadedAt": now}); e != nil {
				t.Fatal(e)
			}
			if os.WriteFile(filepath.Join(base, "security-cache", "trivy/db/trivy.db"), []byte("synthetic-db"), 0644) != nil {
				t.Fatal("fixture feed unavailable")
			}
			fixtureProtectedFeedLocks(t, filepath.Join(base, "security-cache"))
			credentials := filepath.Join(data, "registry.json")
			if err := os.WriteFile(credentials, []byte(`{"username":"fixture","password":"fixture"}`), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("REGISTRY_CREDENTIALS_FILE", credentials)
			calls := 0
			key := bytes.Repeat([]byte{3}, 32)
			s := server{data: data, approvalKey: key, manifest: RuntimeManifest{ScannerImage: "registry:5000/scanner@sha256:" + strings.Repeat("d", 64)}, runner: func(context.Context, string, ...string) (string, error) {
				calls++
				return `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"debian"}},"Results":[{"Vulnerabilities":[]}]}`, nil
			}}
			installTrustedServiceTestFixture(t, &s, "autosoft_artifact", "registry")
			scanner := installImageScannerServerFixture(t, &s, base, "")

			t.Setenv("BROKER_VAULT_KEY_FILE", "")
			clockCalls := 0
			clock := func() time.Time {
				clockCalls++
				if clockCalls == 3 && change {
					feedScopePromotion(t, filepath.Join(base, "security-cache"), func() {
						if os.WriteFile(filepath.Join(base, "security-cache/trivy/db/trivy.db"), []byte("promoted after verified reader cleanup"), 0644) != nil {
							t.Fatal("fixture promotion")
						}
					})
				}
				return now
			}
			body, _ := json.Marshal(in)
			request := httptest.NewRequest("POST", "/v1/connectors/provision", bytes.NewReader(body))
			request.Header.Set("X-Autosoft-Proof", proofFor(key, body))
			response := httptest.NewRecorder()
			s.provisionConnectorWithClock(response, request, clock)
			_, stateError := os.Stat(s.connectorStatePath(in.AppID, in.ConnectionID))
			if change {
				if response.Code != 409 || !strings.Contains(response.Body.String(), `"rejectedBeforeExecution":true`) || !os.IsNotExist(stateError) {
					t.Fatalf("changed feed wrote approval: %s", response.Body.String())
				}
			} else if response.Code != 200 || stateError != nil {
				t.Fatalf("unchanged scope did not approve: %s", response.Body.String())
			}
			if calls != 0 || scanner.count("start") != 1 || !scanner.removed || imageScannerPriorClear(data) != nil {
				t.Fatal("approval bypassed owned reader cleanup")
			}
		})
	}
}

func scopeDailyFixture(t *testing.T) (*server, *imageScannerFixture, *imageScannerFixture, releaseSecurityRequest, string) {
	t.Helper()
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
	sourceScannerFixtureLocks(t, source, true)
	hash, e := sourceDigest(source)
	if e != nil {
		t.Fatal(e)
	}
	image := "registry:5000/apps/app1@sha256:" + strings.Repeat("a", 64)
	v := Verification{AppID: "app1", AttemptID: "attempt1", Template: manifest.Template, Commit: strings.Repeat("b", 40), Images: []string{image}, SourceHash: hash, SourceBindingVersion: sourceBindingVersion, Evidence: Evidence{Status: "passed"}}
	if e := atomicJSON(filepath.Join(data, "receipts", "attempt1.json"), v); e != nil {
		t.Fatal(e)
	}
	cache := filepath.Join(base, "security-cache")
	now := time.Now().UTC()
	if e := atomicJSON(filepath.Join(cache, "trivy", "db", "metadata.json"), map[string]any{"Version": 2, "UpdatedAt": now, "NextUpdate": now.Add(24 * time.Hour), "DownloadedAt": now}); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(cache, "trivy", "db", "trivy.db"), []byte("synthetic-db"), 0644); e != nil {
		t.Fatal(e)
	}
	fixtureProtectedFeedLocks(t, cache)
	t.Setenv("SECURITY_CACHE_DIR", cache)
	t.Setenv("HOST_DATA_DIR", base)
	credentials := filepath.Join(data, "registry.json")
	if err := os.WriteFile(credentials, []byte(`{"username":"fixture","password":"fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_CREDENTIALS_FILE", credentials)

	s := &server{data: data, hostRuntime: data, manifest: RuntimeManifest{ScannerImage: "registry:5000/scanner@sha256:" + strings.Repeat("c", 64)}, runner: func(_ context.Context, _ string, args ...string) (string, error) {
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
	sourceScanner := installSourceScannerServerFixture(t, s, base)
	t.Setenv("BROKER_VAULT_KEY_FILE", "")
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x07", 32))))
	if key, err := vaultKey(); err != nil || len(key) != 32 {
		t.Fatal("Daily security fixture requires a valid 32-byte synthetic vault key")
	}
	in := releaseSecurityRequest{AppID: "app1", ReleaseID: "release1", Commit: v.Commit, Images: v.Images}

	return s, scanner, sourceScanner, in, cache
}

func TestSecurityFeedScopeDailyReportKeepsSourceFindingOnLaterUnavailableImage(t *testing.T) {
	s, image, source, in, cache := scopeDailyFixture(t)
	image.createHook = func() {
		if os.WriteFile(filepath.Join(cache, "trivy/db/trivy.db"), []byte("unauthorized in-flight replacement"), 0644) != nil {
			t.Fatal("fixture replacement")
		}
	}
	raw, _ := json.Marshal(in)
	response := httptest.NewRecorder()
	s.releaseSecurity(response, httptest.NewRequest("POST", "/v1/security", bytes.NewReader(raw)))
	var result releaseSecurityReport
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatal("report unavailable", response.Body.String())
	}
	if result.Status != "failed" || len(result.Findings) != 1 || result.Findings[0].Severity != "MEDIUM" {
		t.Fatalf("positive result lost: %s", response.Body.String())
	}
	coverage := map[string]string{}
	for _, entry := range result.Coverage {
		coverage[entry.Name] = entry.Status
	}
	if coverage["vulnerability-feed"] != "unavailable" || coverage["image-packages"] != "unavailable" || coverage["source-dependencies-configuration-secrets"] != "passed" {
		t.Fatal("mixed report incorrectly complete", coverage)
	}
	if !source.removed || !image.removed || imageScannerPriorClear(s.data) != nil {
		t.Fatal("report changed cleanup authority")
	}
}

func TestSecurityFeedScopeDeploymentRejectsPromotionBeforeOperationAcceptance(t *testing.T) {
	for _, action := range []string{"publish", "rollback"} {
		t.Run(action, func(t *testing.T) {
			s, cache := feedScopeFixture(t)
			s.manifest = testManifest()
			s.manifest.ScannerImage = "registry:5000/scanner@sha256:" + strings.Repeat("c", 64)
			t.Setenv("HOST_DATA_DIR", filepath.Dir(s.data))
			t.Setenv("HOST_SECURITY_CACHE_DIR", cache)
			t.Setenv("BROKER_VAULT_KEY_FILE", "")
			t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
			credentials := filepath.Join(s.data, "registry.json")
			if os.WriteFile(credentials, []byte(`{"username":"fixture","password":"fixture"}`), 0600) != nil {
				t.Fatal("credentials fixture")
			}
			t.Setenv("REGISTRY_CREDENTIALS_FILE", credentials)
			installTrustedServiceTestFixture(t, s, "autosoft_artifact", "registry")
			scanner := installImageScannerServerFixture(t, s, filepath.Dir(s.data), "")
			in, v := goodDeployment()
			in.Action = action
			in.Approval.Action = action
			in.Release.ID = "release-one"
			in.Approval.ReleaseID = in.Release.ID
			in.App.Slug = "documents"
			v.AttemptID = "attempt1"
			if checkDeploy(in, v, nil) != nil {
				t.Fatal("deployment fixture invalid")
			}
			if atomicJSON(filepath.Join(s.data, "receipts/attempt1.json"), v) != nil || atomicJSON(filepath.Join(s.data, "sources/attempt1/app.manifest.json"), AppManifest{Slug: in.App.Slug}) != nil {
				t.Fatal("deployment prestate fixture")
			}
			ctx, cancel, e := s.beginSecurityFeedScope(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer cancel()
			feedScopePromotion(t, cache, func() {
				if os.WriteFile(filepath.Join(cache, "trivy/db/trivy.db"), []byte("next feed"), 0644) != nil {
					t.Fatal("fixture promotion")
				}
			})
			response := httptest.NewRecorder()
			s.executeDeployment(response, httptest.NewRequest("POST", "/v1/deploy", nil).WithContext(ctx), in)
			if response.Code != 409 || !strings.Contains(response.Body.String(), `"rejectedBeforeExecution":true`) || scanner.created {
				t.Fatalf("changed feed reached publication: %s", response.Body.String())
			}
			for _, file := range []string{filepath.Join(s.data, "operations", in.OperationID+".json"), filepath.Join(s.data, "used-approvals", in.Approval.ID+".json")} {
				if _, e := os.Stat(file); !os.IsNotExist(e) {
					t.Fatal("publication state written before coherent evidence", file)
				}
			}
		})
	}
}
