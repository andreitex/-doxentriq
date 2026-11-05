package main

// Metadata admission is separate from clone execution. Nothing in this file
// registers a route, opens SQL, creates a clone or changes an import ledger.
import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

const migrationCloneReviewLifetime = 5 * time.Minute

type migrationCloneSelector struct {
	Version   int    `json:"schemaVersion"`
	AppID     string `json:"appId"`
	JobID     string `json:"jobId"`
	AttemptID string `json:"attemptId"`
	Fence     uint64 `json:"fence"`
}

type migrationCloneReview struct {
	Version              int                    `json:"schemaVersion"`
	Purpose              string                 `json:"purpose"`
	Binding              migrationImportRequest `json:"binding"`
	RequestHash          string                 `json:"requestHash"`
	VerificationHash     string                 `json:"verificationHash"`
	SnapshotReceiptHash  string                 `json:"snapshotReceiptHash"`
	OldColumnPrimaryHash string                 `json:"oldColumnPrimaryHash"`
	ResourceHash         string                 `json:"resourceHash"`
	ArtifactHash         string                 `json:"artifactHash"`
	CheckedAt            string                 `json:"checkedAt"`
	ExpiresAt            string                 `json:"expiresAt"`
	Rows                 int                    `json:"rowCount"`
	Tables               int                    `json:"tableCount"`
	EncryptedBytes       int64                  `json:"encryptedByteCount"`
	Status               string                 `json:"status"`
	DataPreservation     string                 `json:"dataPreservation"`
	DatabaseCheckpoint   string                 `json:"databaseCheckpoint"`
	DatabaseReadback     string                 `json:"currentDatabaseReadback"`
	WriteQuiescence      string                 `json:"currentWriteQuiescence"`
	Compatibility        string                 `json:"previousReleaseCompatibility"`
	MigrationDDL         string                 `json:"migrationDDL"`
	EpochAdvancement     string                 `json:"schemaEpochAdvancement"`
	ExecutionAuthorized  bool                   `json:"executionAuthorized"`
	PublicationEligible  bool                   `json:"publicationEligible"`
}

type migrationCloneInspection struct {
	Review              migrationCloneReview `json:"review"`
	Status              string               `json:"status"`
	StatePresent        bool                 `json:"statePresent"`
	RetainedStatus      string               `json:"retainedStatus"`
	RetainedReceiptHash string               `json:"retainedReceiptHash"`
	DatabaseReadback    string               `json:"databaseReadback"`
	ExecutionAuthorized bool                 `json:"executionAuthorized"`
	PublicationEligible bool                 `json:"publicationEligible"`
}

func validMigrationCloneSelector(q migrationCloneSelector) bool {
	return q.Version == 1 && identity.MatchString(q.AppID) && identity.MatchString(q.JobID) && identity.MatchString(q.AttemptID) && q.Fence > 0 && q.Fence <= 9007199254740991
}

func cloneReviewArtifact(v migrationCloneReview) string {
	v.ArtifactHash = ""
	return accessHash(v)
}

func validMigrationCloneReview(v migrationCloneReview, now time.Time) bool {
	checked, e1 := time.Parse(time.RFC3339Nano, v.CheckedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, v.ExpiresAt)
	if e1 != nil || e2 != nil || checked.After(now.Add(10*time.Second)) || !expires.After(now) || expires.Sub(checked) != migrationCloneReviewLifetime || v.Version != 1 || v.Purpose != "prepare_private_clone_import" || !validImportRequest(v.Binding) || v.RequestHash != accessHash(v.Binding) || v.ArtifactHash != cloneReviewArtifact(v) || v.Status != "metadata_reviewed" || v.Rows < 0 || v.Rows > snapshotMaximumRows || v.Tables < 0 || v.Tables > 64 || v.EncryptedBytes < 1 || v.EncryptedBytes > snapshotMaximumBytes || v.DataPreservation != "not_proven" || v.DatabaseCheckpoint != "not_proven" || v.DatabaseReadback != "not_run" || v.WriteQuiescence != "not_run" || v.Compatibility != "not_run" || v.MigrationDDL != "not_run" || v.EpochAdvancement != "not_run" || v.ExecutionAuthorized || v.PublicationEligible {
		return false
	}
	for _, h := range []string{v.VerificationHash, v.SnapshotReceiptHash, v.OldColumnPrimaryHash, v.ResourceHash, v.ArtifactHash} {
		if !accessHex.MatchString(h) || h == strings.Repeat("0", 64) {
			return false
		}
	}
	return true
}

func copyCloneSnapshotBinding(q migrationSnapshotRequest) migrationSnapshotRequest {
	if q.BaseReleaseID != nil {
		base := *q.BaseReleaseID
		q.BaseReleaseID = &base
	}
	return q
}

func (s *server) cloneReviewLock(q migrationCloneSelector) (func(), error) {
	if s == nil || !validMigrationCloneSelector(q) {
		return nil, snapshotUnavailable
	}
	value, _ := s.locks.LoadOrStore("app-"+q.AppID, new(sync.Mutex))
	lock, ok := value.(*sync.Mutex)
	if !ok || !lock.TryLock() {
		return nil, snapshotUnavailable
	}
	return lock.Unlock, nil
}

// The exact import request comes from company-retained evidence, never from a
// supplied database, image, SQL statement, path, credentials or limit.
func (s *server) prepareMigrationCloneReview(ctx context.Context, selector migrationCloneSelector) (migrationCloneReview, error) {
	var out migrationCloneReview
	if ctx == nil || ctx.Err() != nil {
		return out, snapshotUnavailable
	}
	unlock, e := s.cloneReviewLock(selector)
	if e != nil {
		return out, e
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	return s.migrationCloneReviewLocked(ctx, selector)
}

func (s *server) migrationCloneReviewLocked(ctx context.Context, selector migrationCloneSelector) (migrationCloneReview, error) {
	var out migrationCloneReview
	verificationPath := filepath.Join(s.data, "receipts", selector.AttemptID+".json")
	verificationBytes, e := snapshotFile(s, verificationPath, 1<<20)
	var verification Verification
	if e != nil || importerJSON(verificationBytes, &verification) != nil || verification.AppID != selector.AppID || verification.AttemptID != selector.AttemptID || verification.MigrationSnapshot == nil || len(verification.Images) != 1 || !digestImage.MatchString(verification.Images[0]) {
		return out, snapshotUnavailable
	}
	proof := *verification.MigrationSnapshot
	q := migrationImportRequest{Version: 1, Snapshot: copyCloneSnapshotBinding(proof.Binding), StreamHash: proof.StreamHash, CandidateImage: verification.Images[0]}
	if !validImportRequest(q) || q.Snapshot.AppID != selector.AppID || q.Snapshot.JobID != selector.JobID || q.Snapshot.AttemptID != selector.AttemptID || q.Snapshot.Fence != selector.Fence || verification.SourceHash != q.Snapshot.SourceHash || migrationSetHash(verification.Migrations) != q.Snapshot.MigrationHash || validateSnapshotReceipt(proof) != nil || proof.Status != "captured" || s.snapshotContext(q.Snapshot) != nil {
		return out, snapshotUnavailable
	}
	record, e := s.readSnapshot(q.Snapshot)
	if e != nil || !reflect.DeepEqual(record.Receipt, proof) {
		return out, snapshotUnavailable
	}
	resourcePath := filepath.Join(s.data, "resources", selector.AppID+".enc")
	resourceBytes, e := snapshotFile(s, resourcePath, 1<<20)
	account, exists, accountError := s.snapshotAccount(selector.AppID)
	if e != nil || !exists || accountError != nil || account.Schema != proof.SchemaEpoch || hashBytes(resourceBytes) != record.ResourceHash {
		return out, snapshotUnavailable
	}
	f, e := s.openImportStream(record)
	if e != nil {
		return out, snapshotUnavailable
	}
	before, statError := f.Stat()
	var decoded importedSnapshot
	if statError == nil {
		decoded, e = decodeImportSnapshot(ctx, f, record, nil)
	}
	after, afterError := f.Stat()
	pathInfo, pathError := os.Lstat(filepath.Join(s.snapshotDirectory(q.Snapshot), "rows.enc"))
	closeError := f.Close()
	if statError != nil || e != nil || afterError != nil || pathError != nil || closeError != nil || !snapshotOrdinary(before, snapshotMaximumBytes) || !snapshotOrdinary(after, snapshotMaximumBytes) || !snapshotOrdinary(pathInfo, snapshotMaximumBytes) || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) || before.Size() != after.Size() || before.Size() != pathInfo.Size() || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(pathInfo.ModTime()) || decoded.Rows != proof.Rows {
		return out, snapshotUnavailable
	}
	// These are independent byte/context rechecks after the authenticated read.
	currentVerification, verificationError := snapshotFile(s, verificationPath, 1<<20)
	currentResource, resourceError := snapshotFile(s, resourcePath, 1<<20)
	currentRecord, recordError := s.readSnapshot(q.Snapshot)
	contextError := s.snapshotContext(q.Snapshot)
	if verificationError != nil || resourceError != nil || recordError != nil || contextError != nil || hashBytes(currentVerification) != hashBytes(verificationBytes) || hashBytes(currentResource) != record.ResourceHash || !reflect.DeepEqual(currentRecord, record) || ctx.Err() != nil {
		return out, snapshotUnavailable
	}
	now := time.Now().UTC()
	out = migrationCloneReview{Version: 1, Purpose: "prepare_private_clone_import", Binding: q, RequestHash: accessHash(q), VerificationHash: hashBytes(verificationBytes), SnapshotReceiptHash: accessHash(proof), OldColumnPrimaryHash: importerSchemaHash(decoded.Metadata), ResourceHash: record.ResourceHash, CheckedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(migrationCloneReviewLifetime).Format(time.RFC3339Nano), Rows: proof.Rows, Tables: proof.Tables, EncryptedBytes: proof.Bytes, Status: "metadata_reviewed", DataPreservation: "not_proven", DatabaseCheckpoint: "not_proven", DatabaseReadback: "not_run", WriteQuiescence: "not_run", Compatibility: "not_run", MigrationDDL: "not_run", EpochAdvancement: "not_run"}
	out.ArtifactHash = cloneReviewArtifact(out)
	if !validMigrationCloneReview(out, now) {
		return migrationCloneReview{}, snapshotUnavailable
	}
	return out, nil
}

// This deliberately does not call importMigrationSnapshot/runMigrationImport.
// Missing, pending and quarantined state never enters the fresh writer branch.
// Even an imported ledger reports retained metadata, not a live clone proof.
func (s *server) inspectRetainedMigrationClone(ctx context.Context, selector migrationCloneSelector) (migrationCloneInspection, error) {
	out := migrationCloneInspection{Status: "unavailable", RetainedStatus: "unavailable", DatabaseReadback: "not_run"}
	if ctx == nil || ctx.Err() != nil {
		return out, snapshotUnavailable
	}
	unlock, e := s.cloneReviewLock(selector)
	if e != nil {
		return out, e
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	review, e := s.migrationCloneReviewLocked(ctx, selector)
	if e != nil {
		return out, snapshotUnavailable
	}
	out.Review = review
	retained, e := s.readMigrationImport(review.Binding)
	if e != nil || retained.SnapshotResourceHash != review.ResourceHash {
		return out, snapshotUnavailable
	}
	current, e := s.readMigrationImport(review.Binding)
	captured, snapshotError := s.readSnapshot(review.Binding.Snapshot)
	verification, verificationError := snapshotFile(s, filepath.Join(s.data, "receipts", selector.AttemptID+".json"), 1<<20)
	resource, resourceError := snapshotFile(s, filepath.Join(s.data, "resources", selector.AppID+".enc"), 1<<20)
	contextError := s.snapshotContext(review.Binding.Snapshot)
	if e != nil || snapshotError != nil || verificationError != nil || resourceError != nil || contextError != nil || !reflect.DeepEqual(current, retained) || accessHash(captured.Receipt) != review.SnapshotReceiptHash || captured.ResourceHash != review.ResourceHash || hashBytes(verification) != review.VerificationHash || hashBytes(resource) != review.ResourceHash || ctx.Err() != nil {
		return out, snapshotUnavailable
	}
	if retained.Receipt.Status == "imported" && (retained.Receipt.Rows != review.Rows || retained.Receipt.Tables != review.Tables || retained.Receipt.RowDigest != captured.Receipt.RowDigest || retained.Receipt.LedgerHash != captured.Receipt.LedgerHash || retained.Receipt.OldColumnPrimaryHash != review.OldColumnPrimaryHash) {
		return out, snapshotUnavailable
	}
	out.Status, out.StatePresent, out.RetainedStatus = "retained_metadata_only", true, retained.Receipt.Status
	out.RetainedReceiptHash = accessHash(retained.Receipt)
	return out, nil
}
