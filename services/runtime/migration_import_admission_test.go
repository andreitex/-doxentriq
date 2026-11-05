package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func cloneAdmissionEncryptedFixture(t *testing.T, path, aad string, v any) {
	t.Helper()
	key, e := vaultKey()
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		t.Fatal(e)
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	nonce := bytes.Repeat([]byte{8}, a.NonceSize())
	sealed := a.Seal(nonce, nonce, b, []byte(aad))
	if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, sealed, 0600) != nil {
		t.Fatal("fixture retention")
	}
}

func cloneAdmissionFixture(t *testing.T) (*server, *snapshotSQLFixture, migrationCloneSelector, migrationSnapshotRecord, Verification) {
	t.Helper()
	s, f, q := snapshotFixture(t)
	base := "release1"
	q.BaseReleaseID, q.BaseHash, q.BaseImage = &base, strings.Repeat("1", 64), "registry/base@sha256:"+strings.Repeat("b", 64)
	if atomicJSON(filepath.Join(s.data, "active", q.AppID+".json"), activeDeployment{ReleaseID: base, Hash: q.BaseHash, Image: q.BaseImage}) != nil {
		t.Fatal("base")
	}
	retainSnapshotResource(t, s, f)
	resource, e := snapshotFile(s, filepath.Join(s.data, "resources", q.AppID+".enc"), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	meta, rows := importFixtureMeta(), importFixtureRows()
	v := migrationSnapshotRecord{Receipt: emptySnapshot(q), Key: bytes.Repeat([]byte{3}, 32), NoncePrefix: bytes.Repeat([]byte{4}, 8), ResourceHash: hashBytes(resource)}
	v.Receipt.Status, v.Receipt.Preservation, v.Receipt.Reason = "captured", "captured_only", "none"
	v.Receipt.Rows, v.Receipt.Tables = len(rows), len(meta.Tables)
	v.Receipt.SchemaHash, v.Receipt.LedgerHash = accessHash(meta.Tables), accessHash(meta.Ledger)
	digest := importerDigest(v.Key, v.Receipt.RequestHash)
	frames := []any{map[string]any{"type": "snapshot", "requestHash": v.Receipt.RequestHash, "metadata": meta}, map[string]any{"type": "table", "schema": meta.Tables[0]}}
	for _, row := range rows {
		frames = append(frames, map[string]any{"type": "row", "table": "records", "values": row})
		if importerDigestRow(digest, "records", row) != nil {
			t.Fatal("digest")
		}
	}
	v.Receipt.RowDigest = hex.EncodeToString(digest.Sum(nil))
	frames = append(frames, map[string]any{"type": "complete", "rows": v.Receipt.Rows, "schemaHash": v.Receipt.SchemaHash, "ledgerHash": v.Receipt.LedgerHash})
	stream := importFixtureFrames(t, v, frames)
	v.Receipt.StreamHash, v.Receipt.Bytes = hashBytes(stream), int64(len(stream))
	dir := s.snapshotDirectory(q)
	if os.MkdirAll(dir, 0700) != nil || os.WriteFile(filepath.Join(dir, "rows.enc"), stream, 0600) != nil {
		t.Fatal("stream")
	}
	cloneAdmissionEncryptedFixture(t, filepath.Join(dir, "state.enc"), "state.enc", v)
	// A retained captured attempt may still be unavailable for publication.
	verification := Verification{AppID: q.AppID, AttemptID: q.AttemptID, SourceHash: q.SourceHash, Images: []string{"registry/candidate@sha256:" + strings.Repeat("d", 64)}, Migrations: []Migration{}, MigrationSnapshot: &v.Receipt, Evidence: Evidence{Status: "unavailable", Checks: []Check{}, Findings: []Finding{}}}
	if atomicJSON(filepath.Join(s.data, "receipts", q.AttemptID+".json"), verification) != nil {
		t.Fatal("verification")
	}
	return s, f, migrationCloneSelector{1, q.AppID, q.JobID, q.AttemptID, q.Fence}, v, verification
}

func TestMigrationCloneAdmissionProtectedReviewHasNoExecutionAuthority(t *testing.T) {
	s, f, selector, captured, _ := cloneAdmissionFixture(t)
	before, e := sourceDigest(s.data)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.prepareMigrationCloneReview(context.Background(), selector)
	if e != nil || !validMigrationCloneReview(got, time.Now()) || got.Binding.StreamHash != captured.Receipt.StreamHash || got.SnapshotReceiptHash != accessHash(captured.Receipt) || got.ResourceHash != captured.ResourceHash || got.Status != "metadata_reviewed" || got.DatabaseCheckpoint != "not_proven" || got.DatabaseReadback != "not_run" || got.ExecutionAuthorized || got.PublicationEligible {
		t.Fatalf("review failed: %v %+v", e, got)
	}
	checked, _ := time.Parse(time.RFC3339Nano, got.CheckedAt)
	expires, _ := time.Parse(time.RFC3339Nano, got.ExpiresAt)
	if expires.Sub(checked) != 5*time.Minute || validMigrationCloneReview(got, expires) {
		t.Fatal("expiry not exact")
	}
	public, _ := json.Marshal(got)
	for _, private := range []string{"private-canary", "rows.enc", "cloneDatabase", "NoncePrefix", "Key", captured.Receipt.Binding.AppID + ".enc", f.value.Password} {
		if bytes.Contains(public, []byte(private)) {
			t.Fatal("private material in review")
		}
	}
	after, e := sourceDigest(s.data)
	if e != nil || before != after || f.connections != 0 || f.writes != 0 {
		t.Fatal("metadata review changed files or opened SQL")
	}
}

func TestMigrationCloneAdmissionRejectsForeignOrChangedRetainedEvidence(t *testing.T) {
	for _, kind := range []string{"app", "job", "attempt", "fence", "image", "source", "migration", "base", "pending", "genesis", "receipt-drift", "resource", "epoch", "stream"} {
		t.Run(kind, func(t *testing.T) {
			s, f, q, captured, v := cloneAdmissionFixture(t)
			switch kind {
			case "app":
				q.AppID = "foreign"
			case "job":
				q.JobID = "foreign"
			case "attempt":
				q.AttemptID = "foreign"
			case "fence":
				q.Fence++
			case "image":
				v.Images = []string{"mutable:latest"}
			case "source":
				v.SourceHash = strings.Repeat("f", 64)
			case "migration":
				v.Migrations = []Migration{{ID: "foreign", Checksum: strings.Repeat("e", 64)}}
			case "base":
				if atomicJSON(filepath.Join(s.data, "active", q.AppID+".json"), activeDeployment{ReleaseID: "foreign", Hash: captured.Receipt.Binding.BaseHash, Image: captured.Receipt.Binding.BaseImage}) != nil {
					t.Fatal("base")
				}
			case "pending":
				v.MigrationSnapshot.Status = "pending"
			case "genesis":
				v.MigrationSnapshot.Binding.BaseReleaseID = nil
				v.MigrationSnapshot.Binding.BaseHash = ""
				v.MigrationSnapshot.Binding.BaseImage = ""
			case "receipt-drift":
				v.MigrationSnapshot.RowDigest = strings.Repeat("e", 64)
			case "resource":
				f.value.Password = strings.Repeat("b", 64)
				retainSnapshotResource(t, s, f)
			case "epoch":
				f.value.Schema++
				retainSnapshotResource(t, s, f)
			case "stream":
				path := filepath.Join(s.snapshotDirectory(captured.Receipt.Binding), "rows.enc")
				b, _ := os.ReadFile(path)
				b[10] ^= 1
				if os.WriteFile(path, b, 0600) != nil {
					t.Fatal("stream")
				}
			}
			if atomicJSON(filepath.Join(s.data, "receipts", captured.Receipt.Binding.AttemptID+".json"), v) != nil {
				t.Fatal("verification")
			}
			if _, e := s.prepareMigrationCloneReview(context.Background(), q); e == nil || f.connections != 0 || f.writes != 0 {
				t.Fatal("foreign/changed proof admitted")
			}
			if _, e := os.Stat(filepath.Join(s.data, "migration-imports")); !os.IsNotExist(e) {
				t.Fatal("rejected review created import state")
			}
		})
	}
}

func TestMigrationCloneAdmissionStrictRetainedVerificationJSON(t *testing.T) {
	for _, kind := range []string{"unknown", "duplicate", "alias", "invalidUTF8"} {
		t.Run(kind, func(t *testing.T) {
			s, f, q, _, v := cloneAdmissionFixture(t)
			b, _ := json.Marshal(v)
			switch kind {
			case "unknown":
				b = append([]byte(`{"execute":true,`), b[1:]...)
			case "duplicate":
				b = append([]byte(`{"appId":"app1",`), b[1:]...)
			case "alias":
				b = bytes.Replace(b, []byte(`"appId"`), []byte(`"AppId"`), 1)
			case "invalidUTF8":
				b = append(b, 255)
			}
			if os.WriteFile(filepath.Join(s.data, "receipts", q.AttemptID+".json"), b, 0600) != nil {
				t.Fatal("fixture")
			}
			if _, e := s.prepareMigrationCloneReview(context.Background(), q); e == nil || f.connections != 0 {
				t.Fatal("malformed retained JSON admitted")
			}
		})
	}
}

func TestMigrationCloneInspectionMissingStateNeverEntersWriter(t *testing.T) {
	s, f, q, _, _ := cloneAdmissionFixture(t)
	before, _ := sourceDigest(s.data)
	got, e := s.inspectRetainedMigrationClone(context.Background(), q)
	after, _ := sourceDigest(s.data)
	if e == nil || got.Status != "unavailable" || got.StatePresent || got.ExecutionAuthorized || got.PublicationEligible || before != after || f.connections != 0 || f.writes != 0 {
		t.Fatal("missing state dispatched or became success")
	}
	if _, e := os.Stat(filepath.Join(s.data, "migration-imports")); !os.IsNotExist(e) {
		t.Fatal("missing-state inspection created ledger")
	}
}

func TestMigrationCloneInspectionRetainedStatesAreMetadataOnly(t *testing.T) {
	for _, status := range []string{"pending", "quarantined", "imported"} {
		t.Run(status, func(t *testing.T) {
			s, f, selector, captured, _ := cloneAdmissionFixture(t)
			review, e := s.prepareMigrationCloneReview(context.Background(), selector)
			if e != nil {
				t.Fatal(e)
			}
			r := migrationImportRecord{Receipt: emptyImportReceipt(review.Binding), CloneDatabase: importCloneDatabase(review.Binding), SnapshotResourceHash: captured.ResourceHash}
			r.Receipt.Status = status
			if status == "imported" {
				r.Receipt.Preservation, r.Receipt.Reason = "snapshot_import_only", "remaining_contract_required"
				r.Receipt.Rows, r.Receipt.Tables = captured.Receipt.Rows, captured.Receipt.Tables
				r.Receipt.RowDigest, r.Receipt.LedgerHash, r.Receipt.OldColumnPrimaryHash = captured.Receipt.RowDigest, captured.Receipt.LedgerHash, importerSchemaHash(importFixtureMeta())
			}
			cloneAdmissionEncryptedFixture(t, filepath.Join(s.importDirectory(review.Binding), "state.enc"), "autosoft:migration-import:v1:state", r)
			before, _ := sourceDigest(s.data)
			got, e := s.inspectRetainedMigrationClone(context.Background(), selector)
			after, _ := sourceDigest(s.data)
			if e != nil || got.Status != "retained_metadata_only" || !got.StatePresent || got.RetainedStatus != status || got.RetainedReceiptHash != accessHash(r.Receipt) || got.DatabaseReadback != "not_run" || got.ExecutionAuthorized || got.PublicationEligible || before != after || f.connections != 0 || f.writes != 0 {
				t.Fatalf("state became effect/proof: %v %+v", e, got)
			}
		})
	}
}

func TestMigrationCloneReviewExpiryAndArtifactMutation(t *testing.T) {
	s, _, q, _, _ := cloneAdmissionFixture(t)
	v, e := s.prepareMigrationCloneReview(context.Background(), q)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"binding", "hash", "expiry", "checkpoint", "readback", "compatibility", "quiescence", "ddl", "epoch", "execute", "publish"} {
		t.Run(kind, func(t *testing.T) {
			changed := v
			switch kind {
			case "binding":
				changed.Binding.Snapshot.Fence++
			case "hash":
				changed.ResourceHash = strings.Repeat("e", 64)
			case "expiry":
				changed.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			case "checkpoint":
				changed.DatabaseCheckpoint = "passed"
			case "readback":
				changed.DatabaseReadback = "passed"
			case "compatibility":
				changed.Compatibility = "passed"
			case "quiescence":
				changed.WriteQuiescence = "passed"
			case "ddl":
				changed.MigrationDDL = "passed"
			case "epoch":
				changed.EpochAdvancement = "passed"
			case "execute":
				changed.ExecutionAuthorized = true
			case "publish":
				changed.PublicationEligible = true
			}
			if validMigrationCloneReview(changed, time.Now()) {
				t.Fatal("changed review accepted")
			}
			changed.ArtifactHash = cloneReviewArtifact(changed)
			if kind != "hash" && validMigrationCloneReview(changed, time.Now()) {
				t.Fatal("unsupported semantic claim accepted with recomputed hash")
			}
		})
	}
}

func TestMigrationCloneInspectionRejectsForeignImportedLedgerClaims(t *testing.T) {
	for _, kind := range []string{"resource", "rows", "tables", "digest", "ledger", "columns", "binding"} {
		t.Run(kind, func(t *testing.T) {
			s, f, selector, captured, _ := cloneAdmissionFixture(t)
			review, e := s.prepareMigrationCloneReview(context.Background(), selector)
			if e != nil {
				t.Fatal(e)
			}
			r := migrationImportRecord{Receipt: emptyImportReceipt(review.Binding), CloneDatabase: importCloneDatabase(review.Binding), SnapshotResourceHash: captured.ResourceHash}
			r.Receipt.Status, r.Receipt.Preservation, r.Receipt.Reason = "imported", "snapshot_import_only", "remaining_contract_required"
			r.Receipt.Rows, r.Receipt.Tables = review.Rows, review.Tables
			r.Receipt.RowDigest, r.Receipt.LedgerHash, r.Receipt.OldColumnPrimaryHash = captured.Receipt.RowDigest, captured.Receipt.LedgerHash, review.OldColumnPrimaryHash
			switch kind {
			case "resource":
				r.SnapshotResourceHash = strings.Repeat("e", 64)
			case "rows":
				r.Receipt.Rows++
			case "tables":
				r.Receipt.Tables++
			case "digest":
				r.Receipt.RowDigest = strings.Repeat("e", 64)
			case "ledger":
				r.Receipt.LedgerHash = strings.Repeat("e", 64)
			case "columns":
				r.Receipt.OldColumnPrimaryHash = strings.Repeat("e", 64)
			case "binding":
				r.Receipt.Binding.CandidateImage = "registry/foreign@sha256:" + strings.Repeat("e", 64)
				r.Receipt.RequestHash = accessHash(r.Receipt.Binding)
				r.CloneDatabase = importCloneDatabase(r.Receipt.Binding)
			}
			cloneAdmissionEncryptedFixture(t, filepath.Join(s.importDirectory(review.Binding), "state.enc"), "autosoft:migration-import:v1:state", r)
			before, _ := sourceDigest(s.data)
			got, e := s.inspectRetainedMigrationClone(context.Background(), selector)
			after, _ := sourceDigest(s.data)
			if e == nil || got.Status != "unavailable" || before != after || f.connections != 0 || f.writes != 0 {
				t.Fatal("foreign imported claim accepted or mutated")
			}
		})
	}
}

func TestMigrationCloneAdmissionCancelledBusyAndInvalidSelectors(t *testing.T) {
	s, f, q, _, _ := cloneAdmissionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.prepareMigrationCloneReview(ctx, q); e == nil {
		t.Fatal("cancelled review")
	}
	unlock := s.lock("app-" + q.AppID)
	if _, e := s.prepareMigrationCloneReview(context.Background(), q); e == nil {
		t.Fatal("busy review")
	}
	if _, e := s.inspectRetainedMigrationClone(context.Background(), q); e == nil {
		t.Fatal("busy inspection")
	}
	unlock()
	for _, bad := range []migrationCloneSelector{{2, q.AppID, q.JobID, q.AttemptID, q.Fence}, {1, "../foreign", q.JobID, q.AttemptID, q.Fence}, {1, q.AppID, q.JobID, q.AttemptID, 0}} {
		if _, e := s.prepareMigrationCloneReview(context.Background(), bad); e == nil {
			t.Fatal("invalid selector")
		}
	}
	if f.connections != 0 || f.writes != 0 {
		t.Fatal("rejected request opened SQL")
	}
}

func TestMigrationCloneAdmissionRetainedPathLinksRejectedLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux link/mode enforcement")
	}
	for _, kind := range []string{"hardlink", "symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			s, f, q, captured, _ := cloneAdmissionFixture(t)
			path := filepath.Join(s.snapshotDirectory(captured.Receipt.Binding), "rows.enc")
			switch kind {
			case "hardlink":
				if os.Link(path, path+".linked") != nil {
					t.Fatal("link")
				}
			case "symlink":
				if os.Rename(path, path+".original") != nil || os.Symlink(path+".original", path) != nil {
					t.Fatal("link")
				}
			case "public":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("mode")
				}
			}
			if _, e := s.prepareMigrationCloneReview(context.Background(), q); e == nil || f.connections != 0 {
				t.Fatal("unprotected stream admitted")
			}
		})
	}
}

func TestMigrationCloneAdmissionHasNoMutationOrRouteCall(t *testing.T) {
	b, e := os.ReadFile("migration_import_admission.go")
	if e != nil {
		t.Fatal(e)
	}
	file, e := parser.ParseFile(token.NewFileSet(), "admission.go", b, 0)
	if e != nil {
		t.Fatal(e)
	}
	forbidden := map[string]bool{"importMigrationSnapshot": true, "runMigrationImport": true, "retainMigrationImport": true, "retainSnapshot": true, "Prepare": true, "Insert": true, "ExecContext": true, "QueryContext": true, "QueryRowContext": true, "HandleFunc": true, "snapshotDatabase": true, "snapshotAdmin": true}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if forbidden[name] {
			t.Fatalf("mutation/SQL/route capability added: %s", name)
		}
		return true
	})
	q := migrationSnapshotRequest{BaseReleaseID: new(string)}
	*q.BaseReleaseID = "base"
	copy := copyCloneSnapshotBinding(q)
	*copy.BaseReleaseID = "other"
	if reflect.DeepEqual(q, copy) || *q.BaseReleaseID != "base" {
		t.Fatal("binding pointer not detached")
	}
}
