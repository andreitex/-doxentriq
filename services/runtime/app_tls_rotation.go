package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var dockerImmutableID = regexp.MustCompile(`^[a-f0-9]{64}$`)

type appTLSRenewalResult struct {
	AppID     string `json:"appId"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

type appTLSRotation struct {
	Version     int                `json:"version"`
	AppID       string             `json:"appId"`
	ResourceID  string             `json:"resourceId"`
	ContainerID string             `json:"containerId"`
	Image       string             `json:"image"`
	Phase       string             `json:"phase"`
	UpdatedAt   time.Time          `json:"updatedAt"`
	Old         appCertificatePair `json:"old"`
	Candidate   appCertificatePair `json:"candidate"`
}

type tlsContainer struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Mounts []struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	} `json:"Mounts"`
}

func atomicTLSFile(file string, value []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(file), ".tls-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0400); err != nil {
		_ = f.Close()
		return err
	}
	// The production broker and applications use UID 10001. A company helper
	// executed as root must also preserve the scoped application ownership.
	if os.PathSeparator == '/' && os.Geteuid() == 0 {
		if err = f.Chown(10001, 10001); err != nil {
			_ = f.Close()
			return err
		}
	}
	if _, err = f.Write(value); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// Windows test files have the DOS read-only bit; deployment uses Linux permissions.
	if os.PathSeparator == '\\' {
		_ = os.Chmod(file, 0600)
	}
	if err = os.Rename(f.Name(), file); err != nil {
		return err
	}
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

func writeAppCertificatePair(directory string, pair appCertificatePair) error {
	if err := atomicTLSFile(filepath.Join(directory, "app.key"), pair.PrivateKey); err != nil {
		return err
	}
	return atomicTLSFile(filepath.Join(directory, "app.crt"), pair.Certificate)
}

func recoverAppTLSInstall(directory, resourceID string) error {
	file := filepath.Join(directory, ".app-tls-install.json")
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved appCertificatePair
	if len(b) > 64<<10 || json.Unmarshal(b, &saved) != nil {
		return errors.New("Application TLS installation record is invalid")
	}
	pair, err := parseAppCertificatePair(saved.Certificate, saved.PrivateKey, resourceID)
	if err != nil || pair.Fingerprint != saved.Fingerprint {
		return errors.New("Application TLS installation record identity is invalid")
	}
	if err = writeAppCertificatePair(directory, pair); err != nil {
		return err
	}
	return os.Remove(file)
}

// startApplicationTLSRenewal runs immediately and then periodically. The application lock
// is shared with verification/publication, so no resources or identity grants are changed.
func (s *server) startApplicationTLSRenewal(ctx context.Context, interval time.Duration) <-chan struct{} {
	if interval <= 0 {
		interval = time.Hour
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			s.reconcileApplicationTLS(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func (s *server) reconcileApplicationTLS(ctx context.Context) []appTLSRenewalResult {
	unlock := s.lock("tls-renewal-pass")
	defer unlock()
	type target struct {
		appID   string
		preview bool
	}
	targets := map[string]target{}
	results := []appTLSRenewalResult{}
	entries, err := os.ReadDir(filepath.Join(s.data, "active"))
	if err != nil && !os.IsNotExist(err) {
		results = append(results, appTLSRenewalResult{Target: "published", Status: "unavailable", Detail: "Published application records could not be read"})
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && identity.MatchString(id) {
			targets[id] = target{id, false}
		}
	}
	output, err := s.runner(ctx, "docker", "ps", "--all", "--filter", "label=io.autosoft.managed=true", "--format", "{{json .}}")
	if err != nil {
		results = append(results, appTLSRenewalResult{Target: "preview", Status: "unavailable", Detail: "Preview container discovery is unavailable"})
	} else {
		for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
			var row struct{ Names string }
			if line == "" {
				continue
			}
			if json.Unmarshal([]byte(line), &row) != nil {
				results = append(results, appTLSRenewalResult{Target: "preview", Status: "unavailable", Detail: "Preview container discovery returned invalid records"})
				break
			}
			id := strings.TrimPrefix(row.Names, "as-preview-")
			if strings.HasPrefix(row.Names, "as-preview-") && identity.MatchString(id) && identity.MatchString(id+"_preview") {
				targets[id+"_preview"] = target{id, true}
			}
		}
	}
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if ctx.Err() != nil {
			break
		}
		t := targets[key]
		appUnlock := s.lock("app-" + t.appID)
		appCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		result := s.reconcileAppTLS(appCtx, t.appID, t.preview)
		cancel()
		appUnlock()
		results = append(results, result)
	}
	report := map[string]any{"checkedAt": time.Now().UTC().Format(time.RFC3339), "renewalWindowDays": 30, "results": results}
	if atomicJSON(filepath.Join(s.data, "reports", "tls-renewal-report.json"), report) != nil {
		results = append(results, appTLSRenewalResult{Target: "report", Status: "unavailable", Detail: "TLS renewal report could not be persisted"})
	}
	return results
}

func (s *server) inspectTLSContainer(ctx context.Context, name, appID, resourceID, expectedImage string) (tlsContainer, error) {
	var inspected tlsContainer
	output, err := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", name)
	if err != nil || json.Unmarshal([]byte(output), &inspected) != nil {
		return inspected, errors.New("Application container inspection is unavailable")
	}
	if !dockerImmutableID.MatchString(inspected.ID) || inspected.Name != "/"+name || inspected.Config.Labels["io.autosoft.managed"] != "true" || inspected.Config.Labels["io.autosoft.app"] != appID || !digestImage.MatchString(inspected.Config.Image) || (expectedImage != "" && inspected.Config.Image != expectedImage) {
		return inspected, errors.New("Application container ownership or immutable image does not match trusted state")
	}
	expectedMount := filepath.Clean(filepath.Join(s.hostRuntime, "secrets", resourceID))
	matched := false
	connectorMounts := 0
	for _, mount := range inspected.Mounts {
		if mount.Destination == "/run/app-secrets" {
			matched = mount.Type == "bind" && !mount.RW && filepath.Clean(mount.Source) == expectedMount
		}
		if strings.HasPrefix(mount.Destination, "/run/app-connectors/") {
			return inspected, errors.New("Application connector capability has an unapproved nested mount")
		}
		if mount.Destination == "/run/app-connectors" {
			connectorMounts++
			if connectorMounts != 1 || mount.Type != "bind" || mount.RW {
				return inspected, errors.New("Application connector capability must have one exact read-only bind mount")
			}
			if err := s.validateAppConnectorMount(appID, resourceID, name, mount.Source); err != nil {
				return inspected, err
			}
		}
	}
	if !matched {
		return inspected, errors.New("Application container does not have its exact read-only credential mount")
	}
	// Legacy shared capability files could grant a new release access to a
	// previous release's adapters despite its separate connector mount.
	for _, file := range []string{"connector-token", "connector-registry.json"} {
		if _, err := os.Lstat(filepath.Join(s.data, "secrets", resourceID, file)); !os.IsNotExist(err) {
			return inspected, errors.New("Legacy shared connector capability requires protected operator migration")
		}
	}
	return inspected, nil
}

func (s *server) tlsManifest(appID, image string) (AppManifest, error) {
	var manifest AppManifest
	if !identity.MatchString(appID) || !digestImage.MatchString(image) {
		return manifest, errors.New("Exact application image identity is required")
	}
	entries, err := os.ReadDir(filepath.Join(s.data, "receipts"))
	if err != nil || len(entries) > 10000 {
		return manifest, errors.New("Independent application verification is unavailable")
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var receipt Verification
		if readBoundedJSON(filepath.Join(s.data, "receipts", entry.Name()), &receipt) != nil || receipt.AppID != appID || receipt.Evidence.Status != "passed" || len(receipt.Images) != 1 || receipt.Images[0] != image || !identity.MatchString(receipt.AttemptID) || !dockerImmutableID.MatchString(receipt.SourceHash) {
			continue
		}
		path, err := safePath(filepath.Join(s.data, "sources"), receipt.AttemptID)
		if err != nil {
			continue
		}
		if readBoundedJSON(filepath.Join(path, "app.manifest.json"), &manifest) == nil && validateApp(manifest, appID, receipt.Template) == nil {
			digest, err := sourceDigest(path)
			if err == nil && digest == receipt.SourceHash {
				return manifest, nil
			}
		}
	}
	return manifest, errors.New("The running image has no matching verified application manifest")
}

func (s *server) servedAppTLS(ctx context.Context, containerID, resourceID string, m AppManifest) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := []string{"node", "--input-type=module", "-e", "import tls from 'node:tls';import crypto from 'node:crypto';import fs from 'node:fs';const s=tls.connect({host:'127.0.0.1',port:8080,servername:" + strconv.Quote(appTLSHost(resourceID)) + ",ca:fs.readFileSync('/run/app-secrets/ca.crt'),rejectUnauthorized:true},()=>{console.log(crypto.createHash('sha256').update(s.getPeerCertificate().raw).digest('hex'));s.end()});s.setTimeout(4000,()=>{s.destroy();process.exit(1)});s.on('error',()=>process.exit(1));"}
	if m.Template == "python-api" {
		command = []string{"python", "-c", "import ssl,socket,hashlib; c=ssl.create_default_context(cafile='/run/app-secrets/ca.crt'); s=c.wrap_socket(socket.create_connection(('127.0.0.1',8080),timeout=4),server_hostname=" + strconv.Quote(appTLSHost(resourceID)) + "); print(hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()); s.close()"}
	}
	output, err := s.runner(probeCtx, "docker", append([]string{"exec", containerID}, command...)...)
	fingerprint := strings.TrimSpace(output)
	if err != nil || !dockerImmutableID.MatchString(fingerprint) {
		return "", errors.New("The served TLS certificate could not be verified")
	}
	return fingerprint, nil
}

func (s *server) reconcileAppTLS(ctx context.Context, appID string, preview bool) appTLSRenewalResult {
	result := appTLSRenewalResult{AppID: appID, Target: "published", Status: "unavailable"}
	resourceID, name, image := appID, "", ""
	if preview {
		result.Target = "preview"
		resourceID += "_preview"
		name = "as-preview-" + appID
	} else {
		var active activeDeployment
		b, err := os.ReadFile(filepath.Join(s.data, "active", appID+".json"))
		if err != nil || json.Unmarshal(b, &active) != nil || !identity.MatchString(active.ReleaseID) || len(active.ReleaseID) < 8 || active.Container != "as-app-"+appID+"-"+active.ReleaseID[:8] {
			result.Detail = "Published application identity is invalid"
			return result
		}
		name, image = active.Container, active.Image
	}
	inspected, err := s.inspectTLSContainer(ctx, name, appID, resourceID, image)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	if !inspected.State.Running {
		result.Status = "not_running"
		result.Detail = "Stopped applications are not started by certificate maintenance"
		return result
	}
	manifest, err := s.tlsManifest(appID, inspected.Config.Image)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	directory, err := safePath(filepath.Join(s.data, "secrets"), resourceID)
	if err != nil {
		result.Detail = "Application credential scope is invalid"
		return result
	}
	rotationDir, err := safePath(filepath.Join(s.data, "tls-rotations"), resourceID)
	if err != nil {
		result.Detail = "Application renewal record scope is invalid"
		return result
	}
	journalFile := filepath.Join(rotationDir, "rotation.json")
	var journal appTLSRotation
	if b, readErr := os.ReadFile(journalFile); readErr == nil {
		if len(b) > 128<<10 || json.Unmarshal(b, &journal) != nil || journal.Version != 1 || journal.AppID != appID || journal.ResourceID != resourceID {
			result.Detail = "Application renewal record is invalid"
			return result
		}
		if journal.Phase != "prepared" && journal.Phase != "installed" && journal.Phase != "recovering" && journal.Phase != "completed" && journal.Phase != "rolled_back" {
			result.Detail = "Application renewal record phase is invalid"
			return result
		}
		if journal.Phase == "prepared" || journal.Phase == "installed" || journal.Phase == "recovering" {
			if journal.ContainerID != inspected.ID || journal.Image != inspected.Config.Image {
				result.Detail = "Interrupted renewal belongs to a replaced container; company recovery is required"
				return result
			}
			// A crash after successful restart but before the completion receipt must
			// not replace a healthy new leaf with an already expired previous leaf.
			if journal.Phase != "recovering" {
				candidate, candidateErr := parseAppCertificatePair(journal.Candidate.Certificate, journal.Candidate.PrivateKey, resourceID)
				installed, installedErr := readAppCertificatePair(directory, resourceID)
				if candidateErr == nil && installedErr == nil && candidate.Fingerprint == journal.Candidate.Fingerprint && installed.Fingerprint == candidate.Fingerprint && candidate.ExpiresAt.After(time.Now().Add(applicationTLSRenewalWindow)) {
					served, servedErr := s.servedAppTLS(ctx, inspected.ID, resourceID, manifest)
					if servedErr == nil && served == candidate.Fingerprint && s.healthy(ctx, inspected.ID, manifest) == nil {
						journal.Phase = "completed"
						journal.UpdatedAt = time.Now()
						journal.Old, journal.Candidate = appCertificatePair{}, appCertificatePair{}
						if atomicJSON(journalFile, journal) != nil {
							result.Detail = "Recovered app is healthy; completion record is unavailable"
							return result
						}
						result.Status = "renewed"
						result.Detail = "Interrupted renewal completed after verifying the installed and serving certificate and app health"
						result.ExpiresAt = candidate.ExpiresAt.UTC().Format(time.RFC3339)
						return result
					}
				}
			}
			return s.restoreAppTLS(directory, journalFile, journal, manifest, result, "Interrupted certificate replacement recovered")
		}
		if journal.Phase == "rolled_back" && time.Since(journal.UpdatedAt) < 24*time.Hour {
			result.Status = "rolled_back"
			result.Detail = "Previous certificate retained; failed renewal will retry after 24 hours"
			result.ExpiresAt = journal.Old.ExpiresAt.UTC().Format(time.RFC3339)
			return result
		}
	} else if !os.IsNotExist(readErr) {
		result.Detail = "Application renewal record is unreadable"
		return result
	}
	if err = recoverAppTLSInstall(directory, resourceID); err != nil {
		result.Detail = "Interrupted application certificate installation could not be recovered"
		return result
	}
	pair, err := readAppCertificatePair(directory, resourceID)
	if err != nil {
		result.Detail = "Application certificate and key could not be verified"
		return result
	}
	result.ExpiresAt = pair.ExpiresAt.UTC().Format(time.RFC3339)
	served, probeErr := s.servedAppTLS(ctx, inspected.ID, resourceID, manifest)
	threshold := time.Now().Add(applicationTLSRenewalWindow)
	if pair.ExpiresAt.After(threshold) && probeErr == nil && served == pair.Fingerprint {
		result.Status = "current"
		result.Detail = "The app serves its verified certificate beyond the 30-day renewal window"
		return result
	}
	candidate, old := pair, pair
	status, detail := "reloaded", "The running app reloaded its verified certificate"
	if !pair.ExpiresAt.After(threshold) {
		candidate, err = generateAppTLS(resourceID, time.Now())
		if err != nil || !candidate.ExpiresAt.After(threshold) {
			result.Detail = "Issuer renewal is required before application certificates can be renewed"
			return result
		}
		status, detail = "renewed", "Application certificate renewed and the exact running container passed TLS health verification"
	} else if served != pair.Fingerprint {
		// Provisioning can have replaced disk files while this process retained the old leaf.
		cert, e1 := os.ReadFile(filepath.Join(directory, "app.previous.crt"))
		key, e2 := os.ReadFile(filepath.Join(directory, "app.previous.key"))
		previous, e3 := parseAppCertificatePair(cert, key, resourceID)
		if e1 == nil && e2 == nil && e3 == nil && (probeErr != nil || previous.Fingerprint == served) {
			old = previous
		} else {
			result.Detail = "The serving certificate differs from disk files and no matching verified recovery pair exists"
			return result
		}
	}
	journal = appTLSRotation{Version: 1, AppID: appID, ResourceID: resourceID, ContainerID: inspected.ID, Image: inspected.Config.Image, Phase: "prepared", UpdatedAt: time.Now(), Old: old, Candidate: candidate}
	if err = atomicJSON(journalFile, journal); err != nil {
		result.Detail = "A durable certificate recovery record could not be created"
		return result
	}
	if err = writeAppCertificatePair(directory, candidate); err != nil {
		return s.restoreAppTLS(directory, journalFile, journal, manifest, result, "Certificate installation failed")
	}
	journal.Phase = "installed"
	journal.UpdatedAt = time.Now()
	if err = atomicJSON(journalFile, journal); err != nil {
		return s.restoreAppTLS(directory, journalFile, journal, manifest, result, "Certificate installation record failed")
	}
	if _, err = s.runner(ctx, "docker", "restart", "--time", "45", inspected.ID); err == nil {
		err = s.healthy(ctx, inspected.ID, manifest)
	}
	if err == nil {
		served, err = s.servedAppTLS(ctx, inspected.ID, resourceID, manifest)
		if err == nil && served != candidate.Fingerprint {
			err = errors.New("The restarted app did not serve the reviewed certificate")
		}
	}
	if err != nil {
		return s.restoreAppTLS(directory, journalFile, journal, manifest, result, "Renewed certificate failed its restart or TLS health check")
	}
	journal.Phase = "completed"
	journal.UpdatedAt = time.Now()
	journal.Old = appCertificatePair{}
	journal.Candidate = appCertificatePair{}
	if atomicJSON(journalFile, journal) != nil {
		result.Detail = "App is healthy; renewal completion record is unavailable"
		return result
	}
	result.Status = status
	result.Detail = detail
	result.ExpiresAt = candidate.ExpiresAt.UTC().Format(time.RFC3339)
	return result
}

func (s *server) restoreAppTLS(directory, journalFile string, journal appTLSRotation, manifest AppManifest, result appTLSRenewalResult, reason string) appTLSRenewalResult {
	// Cancellation must not abandon a mismatched pair. Recovery has its own bounded context.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	old, err := parseAppCertificatePair(journal.Old.Certificate, journal.Old.PrivateKey, journal.ResourceID)
	if err != nil || old.Fingerprint != journal.Old.Fingerprint {
		result.Detail = "Certificate recovery pair is invalid; company recovery is required"
		return result
	}
	journal.Phase = "recovering"
	journal.UpdatedAt = time.Now()
	if atomicJSON(journalFile, journal) != nil {
		result.Detail = "Certificate recovery record could not be persisted"
		return result
	}
	if err = writeAppCertificatePair(directory, old); err == nil {
		_, err = s.runner(ctx, "docker", "restart", "--time", "45", journal.ContainerID)
	}
	if err == nil {
		err = s.healthy(ctx, journal.ContainerID, manifest)
	}
	if err == nil {
		var fingerprint string
		fingerprint, err = s.servedAppTLS(ctx, journal.ContainerID, journal.ResourceID, manifest)
		if err == nil && fingerprint != old.Fingerprint {
			err = errors.New("Previous certificate was not reloaded")
		}
	}
	result.ExpiresAt = old.ExpiresAt.UTC().Format(time.RFC3339)
	if err != nil {
		result.Detail = reason + "; previous pair restored but recovery health is unavailable"
		return result
	}
	journal.Phase = "rolled_back"
	journal.UpdatedAt = time.Now()
	journal.Candidate = appCertificatePair{}
	if atomicJSON(journalFile, journal) != nil {
		result.Detail = "Previous certificate is healthy; recovery completion record is unavailable"
		return result
	}
	result.Status = "rolled_back"
	result.Detail = reason + "; previous certificate restored and verified"
	return result
}
