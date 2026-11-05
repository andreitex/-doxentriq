package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tlsRotationIssuer(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "Rotation fixture issuer"}, NotBefore: time.Now().Add(-730 * 24 * time.Hour), NotAfter: time.Now().Add(730 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(root, "issuer.crt"), filepath.Join(root, "issuer.key")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_TLS_CA_CERT_FILE", certFile)
	t.Setenv("APP_TLS_CA_KEY_FILE", keyFile)
}

type tlsRotationFixture struct {
	server                                                 *server
	appID, resourceID, name, image, containerID, directory string
	manifest                                               AppManifest
	inspected                                              tlsContainer
	served                                                 string
	restarts                                               []string
	failCandidate                                          bool
	cancel                                                 context.CancelFunc
	oldFingerprint                                         string
}

func newTLSRotationFixture(t *testing.T, preview bool, daysRemaining int) *tlsRotationFixture {
	t.Helper()
	tlsRotationIssuer(t)
	f := &tlsRotationFixture{appID: "app_tlsfixture", image: "registry.internal/app@sha256:" + strings.Repeat("a", 64), containerID: strings.Repeat("b", 64)}
	f.server = &server{data: t.TempDir(), hostRuntime: filepath.Join(t.TempDir(), "runtime")}
	f.resourceID = f.appID
	f.name = "as-app-" + f.appID + "-release1"
	if preview {
		f.resourceID += "_preview"
		f.name = "as-preview-" + f.appID
	}
	f.directory = filepath.Join(f.server.data, "secrets", f.resourceID)
	pair, err := generateAppTLS(f.resourceID, time.Now().Add(time.Duration(daysRemaining-365)*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAppCertificatePair(f.directory, pair); err != nil {
		t.Fatal(err)
	}
	f.oldFingerprint = pair.Fingerprint
	f.served = pair.Fingerprint
	f.manifest.Version = 1
	f.manifest.ID = f.appID
	f.manifest.Slug = "documents"
	f.manifest.Auth = "sso"
	f.manifest.Template = "node-web"
	f.manifest.Resources.CPU = 1
	f.manifest.Resources.Memory = 128
	f.manifest.Resources.Pids = 32
	f.manifest.Health.Port = 8080
	f.manifest.Health.Path = "/healthz"
	if err = atomicJSON(filepath.Join(f.server.data, "sources", "attempt1", "app.manifest.json"), f.manifest); err != nil {
		t.Fatal(err)
	}
	sourceHash, err := sourceDigest(filepath.Join(f.server.data, "sources", "attempt1"))
	if err != nil {
		t.Fatal(err)
	}
	if err = atomicJSON(filepath.Join(f.server.data, "receipts", "attempt1.json"), Verification{AppID: f.appID, AttemptID: "attempt1", Template: f.manifest.Template, Images: []string{f.image}, SourceHash: sourceHash, Evidence: Evidence{Status: "passed"}}); err != nil {
		t.Fatal(err)
	}
	if !preview {
		if err = atomicJSON(filepath.Join(f.server.data, "active", f.appID+".json"), activeDeployment{ReleaseID: "release12345", Container: f.name, Image: f.image}); err != nil {
			t.Fatal(err)
		}
	}
	f.inspected.ID = f.containerID
	f.inspected.Name = "/" + f.name
	f.inspected.Config.Image = f.image
	f.inspected.Config.Labels = map[string]string{"io.autosoft.managed": "true", "io.autosoft.app": f.appID}
	f.inspected.State.Running = true
	f.inspected.Mounts = append(f.inspected.Mounts, struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}{"bind", filepath.Join(f.server.hostRuntime, "secrets", f.resourceID), "/run/app-secrets", false})
	f.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
		if command != "docker" {
			t.Fatalf("Arbitrary host command invoked: %s", command)
		}
		switch args[0] {
		case "ps":
			if preview {
				return `{"Names":"` + f.name + `"}`, nil
			}
			return "", nil
		case "inspect":
			if args[len(args)-1] != f.name {
				t.Fatal("Inspection escaped its exact container")
			}
			b, _ := json.Marshal(f.inspected)
			return string(b), nil
		case "restart":
			if len(args) != 4 || args[1] != "--time" || args[2] != "45" || args[3] != f.containerID {
				t.Fatalf("Restart did not use immutable ID: %v", args)
			}
			f.restarts = append(f.restarts, args[3])
			pair, err := readAppCertificatePair(f.directory, f.resourceID)
			if err != nil {
				return "", err
			}
			f.served = pair.Fingerprint
			if f.failCandidate && pair.Fingerprint != f.oldFingerprint {
				if f.cancel != nil {
					f.cancel()
				}
				return "", errors.New("fixture candidate failed")
			}
			return "", nil
		case "exec":
			if args[1] != f.containerID {
				t.Fatal("TLS verification escaped immutable container ID")
			}
			if strings.Contains(args[len(args)-1], "getPeerCertificate") || strings.Contains(args[len(args)-1], "getpeercert") {
				return f.served, nil
			}
			return "", nil
		default:
			t.Fatalf("Unexpected operation: %v", args)
			return "", nil
		}
	}
	return f
}

func TestApplicationTLSRenewalCoversPublishedAndPreviewWithinThirtyDays(t *testing.T) {
	for _, preview := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "preview"}[preview], func(t *testing.T) {
			f := newTLSRotationFixture(t, preview, 20)
			results := f.server.reconcileApplicationTLS(context.Background())
			if len(results) != 1 || results[0].Status != "renewed" || len(f.restarts) != 1 {
				t.Fatalf("Idle app was not renewed: %+v restarts=%v", results, f.restarts)
			}
			pair, err := readAppCertificatePair(f.directory, f.resourceID)
			if err != nil || pair.Fingerprint == f.oldFingerprint || !pair.ExpiresAt.After(time.Now().Add(applicationTLSRenewalWindow)) || f.served != pair.Fingerprint {
				t.Fatalf("New serving pair invalid: %+v %v", pair, err)
			}
			report, err := os.ReadFile(filepath.Join(f.server.data, "reports", "tls-renewal-report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(report), "privateKey") || strings.Contains(string(report), "BEGIN") || strings.Contains(string(report), "Automatic signing-key refresh is not yet implemented") {
				t.Fatal("Report leaked a key or retained an obsolete static JWKS warning")
			}
		})
	}
}

func TestApplicationTLSFreshServingPairDoesNotRestart(t *testing.T) {
	f := newTLSRotationFixture(t, false, 120)
	result := f.server.reconcileApplicationTLS(context.Background())
	if len(result) != 1 || result[0].Status != "current" || len(f.restarts) != 0 {
		t.Fatalf("Fresh app restarted: %+v", result)
	}
}

func TestApplicationTLSRotationRejectsForeignOwnershipImageAndCredentialMount(t *testing.T) {
	for _, change := range []string{"owner", "image", "mount"} {
		t.Run(change, func(t *testing.T) {
			f := newTLSRotationFixture(t, false, 20)
			switch change {
			case "owner":
				f.inspected.Config.Labels["io.autosoft.app"] = "other-app"
			case "image":
				f.inspected.Config.Image = "registry.internal/other@sha256:" + strings.Repeat("c", 64)
			case "mount":
				f.inspected.Mounts[0].Source = filepath.Join(f.server.hostRuntime, "secrets", "other-app")
			}
			result := f.server.reconcileApplicationTLS(context.Background())
			pair, err := readAppCertificatePair(f.directory, f.resourceID)
			if len(result) != 1 || result[0].Status != "unavailable" || len(f.restarts) != 0 || err != nil || pair.Fingerprint != f.oldFingerprint {
				t.Fatalf("Foreign target mutated: %+v %v", result, err)
			}
		})
	}
}

func TestApplicationTLSInspectorRequiresExactCandidateConnectorMount(t *testing.T) {
	for _, preview := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "preview"}[preview], func(t *testing.T) {
			for _, change := range []string{"valid", "cross-app", "cross-candidate", "namespace", "path", "writable", "volume", "duplicate", "nested", "missing-owner"} {
				t.Run(change, func(t *testing.T) {
					f := newTLSRotationFixture(t, preview, 120)
					t.Setenv("BROKER_VAULT_KEY_FILE", "")
					t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32))))
					candidate := f.name
					if preview {
						candidate += "-d34db33f"
					}
					index := connectorCandidate{AppID: f.appID, ResourceID: candidate, OwnerResourceID: f.resourceID, Network: "app-private", Connections: []string{"connection-fixture"}}
					if change == "cross-app" {
						index.AppID = "other-app"
					}
					if change == "cross-candidate" {
						candidate += "-other"
						index.ResourceID = candidate
					}
					if change == "namespace" {
						f.resourceID = f.appID + "_preview"
						if preview {
							f.resourceID = f.appID
						}
						f.inspected.Mounts[0].Source = filepath.Join(f.server.hostRuntime, "secrets", f.resourceID)
					}
					if change != "missing-owner" {
						if err := writeEncrypted(filepath.Join(f.server.data, "connectors", "candidates", candidate+".enc"), index); err != nil {
							t.Fatal(err)
						}
					}
					mount := struct {
						Type, Source, Destination string
						RW                        bool
					}{"bind", filepath.Join(f.server.hostRuntime, "connectors", "capabilities", candidate), "/run/app-connectors", false}
					switch change {
					case "path":
						mount.Source = filepath.Join(f.server.hostRuntime, "connectors", "other", candidate)
					case "writable":
						mount.RW = true
					case "volume":
						mount.Type = "volume"
					case "nested":
						mount.Destination += "/connector-token"
					}
					f.inspected.Mounts = append(f.inspected.Mounts, mount)
					if change == "duplicate" {
						f.inspected.Mounts = append(f.inspected.Mounts, mount)
					}
					_, err := f.server.inspectTLSContainer(context.Background(), f.name, f.appID, f.resourceID, f.image)
					if (change == "valid") != (err == nil) || len(f.restarts) != 0 {
						t.Fatalf("Candidate capability validation %s: %v", change, err)
					}
				})
			}
		})
	}
}

func TestApplicationTLSInspectorRejectsLegacySharedConnectorCapabilities(t *testing.T) {
	for _, name := range []string{"connector-token", "connector-registry.json"} {
		t.Run(name, func(t *testing.T) {
			f := newTLSRotationFixture(t, false, 120)
			if err := os.WriteFile(filepath.Join(f.directory, name), []byte("fixture-only-retained-capability"), 0400); err != nil {
				t.Fatal(err)
			}
			if _, err := f.server.inspectTLSContainer(context.Background(), f.name, f.appID, f.resourceID, f.image); err == nil || len(f.restarts) != 0 {
				t.Fatal("Legacy shared connector capability did not fail closed")
			}
		})
	}
}

func TestApplicationTLSFailedRestartRestoresPreviousPairDespiteCancellation(t *testing.T) {
	f := newTLSRotationFixture(t, false, 20)
	f.failCandidate = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.cancel = cancel
	result := f.server.reconcileApplicationTLS(ctx)
	pair, err := readAppCertificatePair(f.directory, f.resourceID)
	if len(result) != 1 || result[0].Status != "rolled_back" || len(f.restarts) != 2 || err != nil || pair.Fingerprint != f.oldFingerprint || f.served != f.oldFingerprint {
		t.Fatalf("Previous TLS identity not restored: %+v %v", result, err)
	}
	// A failed candidate is not repeatedly restarted every maintenance interval.
	result = f.server.reconcileApplicationTLS(context.Background())
	if result[0].Status != "rolled_back" || len(f.restarts) != 2 {
		t.Fatal("Failed renewal retried without backoff")
	}
}

func TestApplicationTLSInterruptedMixedPairIsDurablyRecovered(t *testing.T) {
	f := newTLSRotationFixture(t, false, 20)
	old, err := readAppCertificatePair(f.directory, f.resourceID)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := generateAppTLS(f.resourceID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	journal := appTLSRotation{Version: 1, AppID: f.appID, ResourceID: f.resourceID, ContainerID: f.containerID, Image: f.image, Phase: "prepared", UpdatedAt: time.Now(), Old: old, Candidate: candidate}
	file := filepath.Join(f.server.data, "tls-rotations", f.resourceID, "rotation.json")
	if err = atomicJSON(file, journal); err != nil {
		t.Fatal(err)
	}
	// Simulate power loss after the private key rename and before the certificate rename.
	if err = atomicTLSFile(filepath.Join(f.directory, "app.key"), candidate.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err = readAppCertificatePair(f.directory, f.resourceID); err == nil {
		t.Fatal("Fixture did not produce mismatched files")
	}
	result := f.server.reconcileApplicationTLS(context.Background())
	pair, err := readAppCertificatePair(f.directory, f.resourceID)
	if len(result) != 1 || result[0].Status != "rolled_back" || len(f.restarts) != 1 || err != nil || pair.Fingerprint != old.Fingerprint {
		t.Fatalf("Interrupted rotation was not recovered: %+v %v", result, err)
	}
}

func TestProvisionedFreshDiskPairReloadsOldRunningCertificate(t *testing.T) {
	f := newTLSRotationFixture(t, false, 20)
	if err := issueAppTLS(f.directory, f.resourceID); err != nil {
		t.Fatal(err)
	}
	pair, err := readAppCertificatePair(f.directory, f.resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Fingerprint == f.served {
		t.Fatal("Fixture process unexpectedly reloaded certificate")
	}
	result := f.server.reconcileApplicationTLS(context.Background())
	if len(result) != 1 || result[0].Status != "reloaded" || len(f.restarts) != 1 || f.served != pair.Fingerprint {
		t.Fatalf("Old process certificate was ignored: %+v", result)
	}
}

func TestProvisioningTLSInstallationRepairsInterruptedPairAndRejectsOtherResource(t *testing.T) {
	tlsRotationIssuer(t)
	directory := t.TempDir()
	pair, err := generateAppTLS("app-one", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = atomicJSON(filepath.Join(directory, ".app-tls-install.json"), pair); err != nil {
		t.Fatal(err)
	}
	if err = issueAppTLS(directory, "app-two"); err == nil {
		t.Fatal("Foreign resource installation record accepted")
	}
	if err = issueAppTLS(directory, "app-one"); err != nil {
		t.Fatal(err)
	}
	loaded, err := readAppCertificatePair(directory, "app-one")
	if err != nil || loaded.Fingerprint != pair.Fingerprint {
		t.Fatal("Pending certificate pair was not recovered")
	}
}

func TestApplicationTLSRenewalSharesPublicationLockAndLeavesStoppedAppsStopped(t *testing.T) {
	f := newTLSRotationFixture(t, false, 20)
	inspected := make(chan struct{}, 1)
	previousRunner := f.server.runner
	f.server.runner = func(ctx context.Context, command string, args ...string) (string, error) {
		if args[0] == "inspect" {
			inspected <- struct{}{}
		}
		return previousRunner(ctx, command, args...)
	}
	unlock := f.server.lock("app-" + f.appID)
	done := make(chan []appTLSRenewalResult, 1)
	go func() { done <- f.server.reconcileApplicationTLS(context.Background()) }()
	select {
	case <-inspected:
		unlock()
		t.Fatal("Maintenance bypassed the active publication lock")
	case <-time.After(25 * time.Millisecond):
	}
	f.inspected.State.Running = false
	unlock()
	select {
	case results := <-done:
		if len(results) != 1 || results[0].Status != "not_running" || len(f.restarts) != 0 {
			t.Fatalf("Stopped app was restarted: %+v", results)
		}
	case <-time.After(time.Second):
		t.Fatal("Maintenance did not resume after publication lock released")
	}
}

func TestApplicationTLSInterruptedJournalCannotRestartReplacementContainer(t *testing.T) {
	f := newTLSRotationFixture(t, false, 20)
	old, err := readAppCertificatePair(f.directory, f.resourceID)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := generateAppTLS(f.resourceID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	journal := appTLSRotation{Version: 1, AppID: f.appID, ResourceID: f.resourceID, ContainerID: strings.Repeat("c", 64), Image: f.image, Phase: "installed", UpdatedAt: time.Now(), Old: old, Candidate: candidate}
	if err = atomicJSON(filepath.Join(f.server.data, "tls-rotations", f.resourceID, "rotation.json"), journal); err != nil {
		t.Fatal(err)
	}
	results := f.server.reconcileApplicationTLS(context.Background())
	if len(results) != 1 || results[0].Status != "unavailable" || !strings.Contains(results[0].Detail, "replaced container") || len(f.restarts) != 0 {
		t.Fatalf("Stale journal targeted replacement: %+v", results)
	}
	pair, err := readAppCertificatePair(f.directory, f.resourceID)
	if err != nil || pair.Fingerprint != old.Fingerprint {
		t.Fatal("Stale journal changed certificate files")
	}
}

func TestApplicationTLSShortIssuerValidityFailsBeforeCertificateReplacement(t *testing.T) {
	f := newTLSRotationFixture(t, false, 20)
	certBytes, err := os.ReadFile(os.Getenv("APP_TLS_CA_CERT_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certBytes)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile(os.Getenv("APP_TLS_CA_KEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(keyBytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificate.NotAfter = time.Now().Add(20 * 24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.(*ecdsa.PrivateKey).PublicKey, key.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("APP_TLS_CA_CERT_FILE"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	results := f.server.reconcileApplicationTLS(context.Background())
	pair, err := readAppCertificatePair(f.directory, f.resourceID)
	if len(results) != 1 || results[0].Status != "unavailable" || !strings.Contains(results[0].Detail, "Issuer renewal") || len(f.restarts) != 0 || err != nil || pair.Fingerprint != f.oldFingerprint {
		t.Fatalf("Short issuer produced unsafe rotation: %+v %v", results, err)
	}
}

func TestApplicationTLSInterruptedHealthyRenewalKeepsNewLeafWhenOldLeafExpired(t *testing.T) {
	f := newTLSRotationFixture(t, false, -2)
	old, err := readAppCertificatePair(f.directory, f.resourceID)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := generateAppTLS(f.resourceID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	journal := appTLSRotation{Version: 1, AppID: f.appID, ResourceID: f.resourceID, ContainerID: f.containerID, Image: f.image, Phase: "installed", UpdatedAt: time.Now(), Old: old, Candidate: candidate}
	if err = atomicJSON(filepath.Join(f.server.data, "tls-rotations", f.resourceID, "rotation.json"), journal); err != nil {
		t.Fatal(err)
	}
	if err = writeAppCertificatePair(f.directory, candidate); err != nil {
		t.Fatal(err)
	}
	f.served = candidate.Fingerprint
	results := f.server.reconcileApplicationTLS(context.Background())
	pair, err := readAppCertificatePair(f.directory, f.resourceID)
	if len(results) != 1 || results[0].Status != "renewed" || !strings.Contains(results[0].Detail, "Interrupted renewal completed") || len(f.restarts) != 0 || err != nil || pair.Fingerprint != candidate.Fingerprint {
		t.Fatalf("Healthy renewed leaf was lost after interruption: %+v %v", results, err)
	}
}
