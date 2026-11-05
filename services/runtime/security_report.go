package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"time"
)

type releaseSecurityRequest struct {
	AppID     string   `json:"appId"`
	ReleaseID string   `json:"releaseId"`
	Commit    string   `json:"commit"`
	Images    []string `json:"images"`
}
type securityCoverage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type releaseSecurityReport struct {
	Subject       string             `json:"subject"`
	AppID         string             `json:"appId"`
	ReleaseID     string             `json:"releaseId"`
	Status        string             `json:"status"`
	CheckedAt     string             `json:"checkedAt"`
	FeedUpdatedAt string             `json:"feedUpdatedAt"`
	Findings      []Finding          `json:"findings"`
	Coverage      []securityCoverage `json:"coverage"`
}

func sourceDigest(root string) (string, error) {
	type entry struct {
		Path string `json:"path"`
		Hash string `json:"hash"`
	}
	files := []entry{}
	var size int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || d.Type()&os.ModeSymlink != 0 {
			return errors.New("Verified source contains linked or special files")
		}
		size += info.Size()
		if size > 20<<20 || len(files) >= 600 {
			return errors.New("Verified source exceeds its bound")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		files = append(files, entry{filepath.ToSlash(rel), hashBytes(b)})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	b, _ := json.Marshal(files)
	return hashBytes(b), nil
}

func (s *server) securityReceipt(in releaseSecurityRequest) (Verification, error) {
	var match Verification
	if !identity.MatchString(in.AppID) || !identity.MatchString(in.ReleaseID) || !regexp.MustCompile(`^[a-f0-9]{40,64}$`).MatchString(in.Commit) || len(in.Images) != 1 || !digestImage.MatchString(in.Images[0]) {
		return match, errors.New("Exact application release identity, commit and immutable image are required")
	}
	entries, e := os.ReadDir(filepath.Join(s.data, "receipts"))
	if e != nil {
		return match, e
	}
	if len(entries) > 10000 {
		return match, errors.New("Security receipt enumeration requires indexed maintenance")
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, e := os.ReadFile(filepath.Join(s.data, "receipts", entry.Name()))
		if e != nil || len(b) > 2<<20 {
			continue
		}
		var v Verification
		if json.Unmarshal(b, &v) == nil && v.Evidence.Status == "passed" && v.AppID == in.AppID && v.Commit == in.Commit && reflect.DeepEqual(v.Images, in.Images) && identity.MatchString(v.AttemptID) && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(v.SourceHash) {
			return v, nil
		}
	}
	return match, errors.New("No independent receipt matches the exact release security target")
}

func (s *server) releaseSecurity(w http.ResponseWriter, r *http.Request) {
	var in releaseSecurityRequest
	if !decode(w, r, &in) {
		return
	}
	v, e := s.securityReceipt(in)
	if e != nil {
		fail(w, 409, e)
		return
	}
	unlock := s.lock("app-" + in.AppID)
	defer unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	report := releaseSecurityReport{Subject: "app", AppID: in.AppID, ReleaseID: in.ReleaseID, Status: "unavailable", CheckedAt: time.Now().UTC().Format(time.RFC3339), FeedUpdatedAt: "1970-01-01T00:00:00Z", Findings: []Finding{}, Coverage: []securityCoverage{}}
	finish := func(name, status, detail string) {
		report.Coverage = append(report.Coverage, securityCoverage{name, status, detail})
	}
	if feed, e := cachedFeed(); e == nil {
		report.FeedUpdatedAt = feed
		finish("vulnerability-feed", "passed", "Current advisory database is within24hours")
	} else {
		finish("vulnerability-feed", "unavailable", "Current vulnerability feed is unavailable or stale")
		respond(w, report)
		return
	}
	source := filepath.Join(s.data, "sources", v.AttemptID)
	digest, e := sourceDigest(source)
	if e != nil || digest != v.SourceHash {
		finish("immutable-source", "unavailable", "Preserved source does not match its independent verification digest")
		respond(w, report)
		return
	}
	finish("immutable-source", "passed", "Exact verified source including actual dependency locks is preserved")
	findings, feed, e := s.scan(ctx, filepath.Join(s.hostRuntime, "sources", v.AttemptID))
	if e != nil {
		finish("source-dependencies-configuration-secrets", "unavailable", "Source dependency, configuration and secret scanning failed")
	} else {
		report.Findings = append(report.Findings, findings...)
		report.FeedUpdatedAt = feed
		finish("source-dependencies-configuration-secrets", "passed", "Immutable source and dependency locks scanned against fresh advisories; configuration and secrets scanned")
	}
	if e = staticPolicy(source); e != nil {
		finish("source-security-policy", "failed", "Immutable source violates company security policy")
	} else {
		finish("source-security-policy", "passed", "Recorded source passed the enforced risky-code policy; business acceptance remains in original release evidence")
	}
	imageFindings, e := s.scanImage(ctx, in.Images[0])
	if e != nil {
		finish("image-packages", "unavailable", "Exact immutable image package coverage is unavailable")
	} else {
		report.Findings = append(report.Findings, imageFindings...)
		finish("image-packages", "passed", "Exact retained runtime image and installed libraries scanned against the current feed")
	}
	var manifest AppManifest
	manifestBytes, manifestError := os.ReadFile(filepath.Join(source, "app.manifest.json"))
	if manifestError != nil || json.Unmarshal(manifestBytes, &manifest) != nil || manifest.ID != in.AppID {
		finish("scoped-connectors", "unavailable", "The exact verified application's connection references are unavailable")
	} else if len(manifest.Connections) > 0 {
		connectorFindings, connectorError := s.scanAppConnectors(ctx, manifest)
		if connectorError != nil {
			finish("scoped-connectors", "unavailable", "Approved connector provenance, access expiry or fresh image coverage is unavailable")
		} else {
			report.Findings = append(report.Findings, connectorFindings...)
			finish("scoped-connectors", "passed", "All approved scoped connector images scanned against current advisories; connection credentials remain separate")
		}
	}
	report.Status = "passed"
	for _, c := range report.Coverage {
		if c.Status == "unavailable" {
			report.Status = "unavailable"
			break
		}
	}
	for _, c := range report.Coverage {
		if c.Status == "failed" {
			report.Status = "failed"
		}
	}
	for _, f := range report.Findings {
		if blockedSeverity(f.Severity) {
			report.Status = "failed"
		}
	}
	report.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	respond(w, report)
}
