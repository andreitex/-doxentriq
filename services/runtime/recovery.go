package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"time"
)

type recoveryGrant struct {
	ID                string   `json:"id"`
	AppID             string   `json:"appId"`
	FailedReleaseID   string   `json:"failedReleaseId"`
	FailedHash        string   `json:"failedArtifactHash"`
	FailedImages      []string `json:"failedImages"`
	TargetReleaseID   string   `json:"targetReleaseId"`
	TargetHash        string   `json:"targetArtifactHash"`
	TargetImages      []string `json:"targetImages"`
	Schema            int      `json:"currentSchemaVersion"`
	ApprovedBy        string   `json:"approvedBy"`
	ApprovedAt        string   `json:"approvedAt"`
	ExpiresAt         string   `json:"expiresAt"`
	AuthorizationHash string   `json:"authorizationHash"`
	ApprovalID        string   `json:"publicationApprovalId"`
	OperationID       string   `json:"publicationOperationId"`
}
type recoveryRequest struct {
	OperationID string `json:"operationId"`
	App         struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	} `json:"app"`
	Release        release       `json:"release"`
	Grant          recoveryGrant `json:"grant"`
	ObservationIDs []string      `json:"observationIds"`
	EvidenceHashes []string      `json:"evidenceHashes"`
}

func classifiedSeverity(value string) bool {
	return value == "LOW" || value == "MEDIUM" || value == "HIGH" || value == "CRITICAL"
}

func grantAuthorizationHash(g recoveryGrant) string {
	// encoding/json sorts object keys. The projection is identical to core hashArtifact.
	b, _ := json.Marshal(map[string]any{"id": g.ID, "appId": g.AppID, "failedReleaseId": g.FailedReleaseID, "failedArtifactHash": g.FailedHash, "failedImages": g.FailedImages, "targetReleaseId": g.TargetReleaseID, "targetArtifactHash": g.TargetHash, "targetImages": g.TargetImages, "currentSchemaVersion": g.Schema, "expiresAt": g.ExpiresAt, "publicationApprovalId": g.ApprovalID})
	return hashBytes(b)
}

func validateGrant(g recoveryGrant) error {
	hex := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if !identity.MatchString(g.ID) || !identity.MatchString(g.AppID) || !identity.MatchString(g.FailedReleaseID) || !identity.MatchString(g.TargetReleaseID) || !identity.MatchString(g.ApprovalID) || !identity.MatchString(g.OperationID) || !hex.MatchString(g.FailedHash) || !hex.MatchString(g.TargetHash) || g.FailedReleaseID == g.TargetReleaseID || g.ApprovedBy == "" || len(g.ApprovedBy) > 512 || g.Schema < 1 || len(g.FailedImages) != 1 || len(g.TargetImages) != 1 || !digestImage.MatchString(g.FailedImages[0]) || !digestImage.MatchString(g.TargetImages[0]) || g.AuthorizationHash != grantAuthorizationHash(g) {
		return errors.New("Exact reviewed automatic recovery authorization is invalid")
	}
	approved, err := time.Parse(time.RFC3339, g.ApprovedAt)
	if err != nil || approved.After(time.Now().Add(time.Minute)) {
		return errors.New("Automatic recovery approval time is invalid")
	}
	expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || expires.After(approved.Add(30*24*time.Hour+time.Minute)) {
		return errors.New("Automatic recovery authorization expired or exceeds its disclosed30days")
	}
	return nil
}

func (s *server) validatePublicationGrant(in deployment, current *activeDeployment) error {
	g := *in.RecoveryGrant
	if err := validateGrant(g); err != nil {
		return err
	}
	if in.Action != "publish" || !in.Principal.MFA || in.Principal.ID != g.ApprovedBy || g.ApprovedBy != in.Approval.ApprovedBy || g.ApprovedAt != in.Approval.ApprovedAt || g.ApprovalID != in.Approval.ID || g.OperationID != in.OperationID || g.AppID != in.App.ID || g.FailedReleaseID != in.Release.ID || g.FailedHash != in.Release.Hash || !reflect.DeepEqual(g.FailedImages, in.Release.Images) || current == nil || current.ReleaseID != g.TargetReleaseID || current.Hash != g.TargetHash || current.Image != g.TargetImages[0] || g.Schema != max(current.Schema, in.Release.Schema) {
		return errors.New("Recovery grant does not match the exact MFA publication approval and immediate previous release")
	}
	var existing recoveryGrant
	if err := readBoundedJSON(filepath.Join(s.data, "recovery-grants", g.ID+".json"), &existing); err == nil && !reflect.DeepEqual(existing, g) {
		return errors.New("Automatic recovery authorization identity was already used")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *server) checkRecovery(ctx context.Context, in recoveryRequest, current *activeDeployment) error {
	g := in.Grant
	if err := validateGrant(g); err != nil {
		return err
	}
	var retained recoveryGrant
	if err := readBoundedJSON(filepath.Join(s.data, "recovery-grants", g.ID+".json"), &retained); err != nil || !reflect.DeepEqual(retained, g) {
		return errors.New("No independently retained exact publication recovery grant matches")
	}
	if current == nil || current.ReleaseID != g.FailedReleaseID || current.Hash != g.FailedHash || current.OperationID != g.OperationID || current.Image != g.FailedImages[0] || current.Schema != g.Schema || current.Previous == nil || current.Previous.ReleaseID != g.TargetReleaseID || current.Previous.Hash != g.TargetHash || current.Previous.Image != g.TargetImages[0] || in.App.ID != g.AppID || in.Release.ID != g.TargetReleaseID || in.Release.AppID != g.AppID || in.Release.Hash != g.TargetHash || !reflect.DeepEqual(in.Release.Images, g.TargetImages) || g.Schema < in.Release.SchemaMin || g.Schema > in.Release.SchemaMax {
		return errors.New("A later release, changed schema or different recovery artifact invalidated automatic recovery")
	}
	var publication deployReceipt
	if err := readBoundedJSON(filepath.Join(s.data, "operations", g.OperationID+".json"), &publication); err != nil || publication.Phase != "completed" || publication.Hash != g.FailedHash || publication.ApprovalID != g.ApprovalID || publication.AppID != g.AppID || publication.ReleaseID != g.FailedReleaseID {
		return errors.New("Original consumed healthy publication receipt unavailable")
	}
	var used deployReceipt
	if err := readBoundedJSON(filepath.Join(s.data, "used-approvals", g.ApprovalID+".json"), &used); err != nil || used.OperationID != g.OperationID || used.Hash != g.FailedHash {
		return errors.New("Original publication approval consumption cannot be verified")
	}
	if len(in.ObservationIDs) != 3 || len(in.EvidenceHashes) != 3 {
		return errors.New("Three independently recorded health failures are required")
	}
	seen := map[string]bool{}
	var previous time.Time
	for i, id := range in.ObservationIDs {
		if !identity.MatchString(id) || seen[id] {
			return errors.New("Distinct exact health failure receipts are required")
		}
		seen[id] = true
		var observed releaseObservation
		if err := readBoundedJSON(filepath.Join(s.data, "observations", id+".json"), &observed); err != nil || observed.ID != id || observed.AppID != g.AppID || observed.ReleaseID != g.FailedReleaseID || observed.Hash != g.FailedHash || !reflect.DeepEqual(observed.Images, g.FailedImages) || observed.OperationID != g.OperationID || observed.Status != "unhealthy" || observed.EvidenceHash != in.EvidenceHashes[i] {
			return errors.New("Health failure evidence does not match the failed immutable release")
		}
		checked, err := time.Parse(time.RFC3339Nano, observed.CheckedAt)
		if err != nil || checked.After(time.Now().Add(time.Minute)) || time.Since(checked) > 10*time.Minute || (!previous.IsZero() && checked.Sub(previous) < 10*time.Second) || (i == 2 && time.Since(checked) > 5*time.Minute) {
			return errors.New("Repeated health failures are stale or were measured too closely together")
		}
		copy := observed
		copy.EvidenceHash = ""
		body, _ := json.Marshal(copy)
		if hashBytes(body) != observed.EvidenceHash {
			return errors.New("Recorded health evidence digest does not match")
		}
		previous = checked
	}
	inObserve := observationRequest{ID: in.ObservationIDs[2], AppID: g.AppID, ReleaseID: g.FailedReleaseID, Hash: g.FailedHash, Images: g.FailedImages, OperationID: g.OperationID}
	_, _, manifest, err := s.publicationReceipt(inObserve)
	if err != nil || manifest.Slug != in.App.Slug {
		return errors.New("Failed release protected manifest unavailable")
	}
	probeContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	matched, err := s.routeMatches(probeContext, g.AppID, manifest.Slug+"."+s.appsHost(), current.Container)
	if err != nil || !matched {
		return errors.New("Actual routing is unavailable or changed; automatic recovery is paused")
	}
	container, err := s.inspectTLSContainer(probeContext, current.Container, g.AppID, g.AppID, current.Image)
	if err != nil {
		return err
	}
	status, _ := s.healthObservation(probeContext, container, manifest)
	if status != "unhealthy" {
		return errors.New("Current health does not confirm an actual application failure; automatic recovery is paused")
	}
	return nil
}

func (s *server) checkRecoverySource(ctx context.Context, v Verification) error {
	source := filepath.Join(s.data, "sources", v.AttemptID)
	digest, err := sourceDigest(source)
	if err != nil || digest != v.SourceHash {
		return errors.New("Recovery source no longer matches independently verified artifacts")
	}
	if err = staticPolicy(source); err != nil {
		return errors.New("Recovery source violates the current company security policy")
	}
	findings, _, err := s.scan(ctx, filepath.Join(s.hostRuntime, "sources", v.AttemptID))
	if err != nil {
		return errors.New("Current recovery dependency, configuration and secret coverage is unavailable")
	}
	for _, finding := range findings {
		if blockedSeverity(finding.Severity) {
			return errors.New("Current security findings prevent automatic recovery")
		}
	}
	return nil
}

func (s *server) recoverRelease(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		fail(w, 400, err)
		return
	}
	if !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		fail(w, 403, errors.New("Exact automatic recovery proof required"))
		return
	}
	var in recoveryRequest
	if json.Unmarshal(body, &in) != nil || !identity.MatchString(in.OperationID) || !identity.MatchString(in.App.ID) || !identity.MatchString(in.Release.ID) || len(in.Release.ID) < 8 || validateGrant(in.Grant) != nil {
		rejectDeployment(w, 400, errors.New("Invalid exact recovery identity or authorization"))
		return
	}
	// This internal approval is the retained, user-approved recovery grant. It cannot be
	// supplied through /deploy and is consumed by the same durable operation machinery.
	deploy := deployment{Release: in.Release, OperationID: in.OperationID, Action: "rollback", recovery: &in, Approval: approval{ID: in.Grant.ID, AppID: in.Grant.AppID, ReleaseID: in.Grant.TargetReleaseID, Hash: in.Grant.TargetHash, Action: "rollback", ApprovedBy: in.Grant.ApprovedBy, ApprovedAt: in.Grant.ApprovedAt, ExpiresAt: in.Grant.ExpiresAt}}
	deploy.App = in.App
	s.executeDeployment(w, r, deploy)
}
