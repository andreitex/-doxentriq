package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"
)

const sourceBindingVersion = 1

type verificationInput struct {
	AppID                string   `json:"appId"`
	JobID                string   `json:"jobId"`
	AttemptID            string   `json:"attemptId"`
	Pipeline             Pipeline `json:"pipeline"`
	FilesHash            string   `json:"filesHash"`
	SourceBindingVersion int      `json:"sourceBindingVersion"`
	Fence                uint64   `json:"fence"`
	BaseReleaseID        *string  `json:"baseReleaseId"`
}

func pipelineDefinitionHash(p Pipeline) string {
	b, _ := json.Marshal(p)
	return hashBytes(b)
}

func capturedPipeline(root string, expected Pipeline) error {
	f, e := os.Open(filepath.Join(root, "autosoft.pipeline.json"))
	if e != nil {
		return errors.New("Captured pipeline is unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("Captured pipeline is unavailable")
	}
	p, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(p) > 1<<20 {
		return errors.New("Captured pipeline is unavailable")
	}
	d := json.NewDecoder(bytes.NewReader(p))
	d.DisallowUnknownFields()
	var captured Pipeline
	if d.Decode(&captured) != nil || d.Decode(new(any)) != io.EOF || !reflect.DeepEqual(captured, expected) {
		return errors.New("Requested pipeline differs from the exact captured source")
	}
	return nil
}

// Read the actual source directory, not the workspace enumeration returned by copyTree.
func verificationSourceInput(root string, in verificationInput) (string, error) {
	if in.SourceBindingVersion != sourceBindingVersion || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.FilesHash) {
		return "", errors.New("Versioned canonical source binding is required; legacy attempts need company review")
	}
	h, e := sourceDigest(root)
	if e != nil || h != in.FilesHash {
		return "", errors.New("Actual submitted source does not match its canonical input hash")
	}
	if e = capturedPipeline(root, in.Pipeline); e != nil {
		return "", e
	}
	return h, nil
}

// No pre-existing partial source/build tree is adopted or scheduled for cleanup.
func createVerificationSnapshots(workspace, source, build string, in verificationInput) (string, bool, error) {
	for _, p := range []string{source, build} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return "", false, errors.New("Partial verification snapshot exists; preserve it for company reconciliation")
		}
	}
	for _, p := range []string{filepath.Dir(source), filepath.Dir(build)} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return "", false, e
		}
	}
	if e := os.Mkdir(source, 0700); e != nil {
		return "", false, e
	}
	if _, e := copyTree(workspace, source, 20<<20, 600); e != nil {
		return "", false, e
	}
	h, e := verificationSourceInput(source, in)
	if e != nil {
		return "", false, e
	}
	if e = os.Mkdir(build, 0700); e != nil {
		return "", false, e
	}
	if _, e = copyTree(source, build, 20<<20, 600); e != nil {
		return "", true, e
	}
	if _, e = verificationSourceInput(build, in); e != nil {
		return "", true, e
	}
	return h, true, nil
}

func verificationReplayBinding(v Verification, in verificationInput, inputHash, source string) bool {
	if in.SourceBindingVersion != sourceBindingVersion || in.FilesHash != inputHash || v.SourceBindingVersion != sourceBindingVersion || v.InputSourceHash != inputHash || v.FilesHash != inputHash ||
		v.AppID != in.AppID || v.AttemptID != in.AttemptID || v.Template != in.Pipeline.Template ||
		v.PipelineHash != pipelineDefinitionHash(in.Pipeline) || v.MigrationSnapshot == nil {
		return false
	}
	q := v.MigrationSnapshot.Binding
	if capturedPipeline(source, in.Pipeline) != nil {
		return false
	}
	migrations, e := readMigrations(source)
	if e != nil || !reflect.DeepEqual(migrations, v.Migrations) {
		return false
	}
	final, e := sourceDigest(source)
	return e == nil && final == v.SourceHash && q.SourceHash == final && q.JobID == in.JobID &&
		q.AppID == in.AppID && q.AttemptID == in.AttemptID && q.Fence == in.Fence &&
		reflect.DeepEqual(q.BaseReleaseID, in.BaseReleaseID) && q.MigrationHash == migrationSetHash(v.Migrations)
}

type capturedSourceFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Hash the exact returned UTF-8 bytes using the historical final-source algorithm.
// JSON cannot preserve invalid UTF-8, so reject rather than return replacement bytes.
func capturedSourceDigest(files []capturedSourceFile) (string, error) {
	type entry struct {
		Path string `json:"path"`
		Hash string `json:"hash"`
	}
	entries := []entry{}
	size := 0
	seen := map[string]bool{}
	for _, f := range files {
		if !utf8.ValidString(f.Path) || !utf8.ValidString(f.Content) || seen[f.Path] || len(files) > 600 {
			return "", errors.New("Invalid source capture")
		}
		seen[f.Path] = true
		size += len(f.Content)
		if size > 20<<20 {
			return "", errors.New("Source capture exceeds its bound")
		}
		entries = append(entries, entry{f.Path, hashBytes([]byte(f.Content))})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	b, _ := json.Marshal(entries)
	return hashBytes(b), nil
}

func bindFinalVerificationSource(v *Verification, source string) error {
	if v.SourceBindingVersion != sourceBindingVersion || v.InputSourceHash != v.FilesHash ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(v.InputSourceHash) {
		return errors.New("Input source binding is unavailable")
	}
	h, e := sourceDigest(source)
	if e == nil {
		v.SourceHash = h
	}
	return e
}

func verifiedMigrationRequest(in verificationInput, v Verification, migrations []Migration) migrationSnapshotRequest {
	return migrationSnapshotRequest{Version: 1, AppID: in.AppID, JobID: in.JobID, AttemptID: in.AttemptID,
		Fence: in.Fence, BaseReleaseID: in.BaseReleaseID, SourceHash: v.SourceHash, MigrationHash: migrationSetHash(migrations)}
}

// A completed dependency/test context is not migration authority. Preserve request cancellation.
func captureVerificationMigration(parent context.Context, q migrationSnapshotRequest, migrations []Migration,
	capture func(context.Context, migrationSnapshotRequest, []Migration) (migrationSnapshotReceipt, error)) (migrationSnapshotReceipt, error) {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return emptySnapshot(q), snapshotUnavailable
	}
	v, e := capture(ctx, q, migrations)
	if ctx.Err() != nil {
		return emptySnapshot(q), snapshotUnavailable
	}
	return v, e
}
