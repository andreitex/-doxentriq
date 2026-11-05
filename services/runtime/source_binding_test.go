package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const bindingVectors = `[{"name":"empty","files":[],"hash":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"},{"name":"basic","files":[{"path":"a.txt","content":"x\n"},{"path":"empty.txt","content":""}],"hash":"ab8634c7c735ccf6792c22ffd7c2387e39cb390eb574361c378570514871953a"},{"name":"html-and-separators","files":[{"path":"<>&\u2028\u2029.txt","content":"<>&\u2028\u2029"}],"hash":"cedb2de6b3895d35077e79e53b0c90f66649face49bb616fa61ba7fef92d98c3"},{"name":"utf8-order","files":[{"path":"\ud800\udc00.txt","content":"supplementary"},{"path":"\ue000.txt","content":"bmp"},{"path":"\u00e9.txt","content":"accent"}],"hash":"784d572d5d240d18577a24c3b296cc14d5de9af9a1ba0a0c3f834c64f02bc89c"},{"name":"nul-single","files":[{"path":"a","content":"x\u0000b\u0000y"}],"hash":"e9c0e4f9704fe03ac2e05dcec8ec71b158531e4187a46b75984ecb9e1b9ee1ed"},{"name":"nul-pair","files":[{"path":"a","content":"x"},{"path":"b","content":"y"}],"hash":"f7cb1e2c431a7dc6460ce02493a2efacf2212eb8d0961d8c9857b747f0ea607a"}]`
const bindingPipelineVector = `{"pipeline":{"schemaVersion":1,"template":"node-api","stages":[{"name":"dependencies","commands":[],"timeoutSeconds":60},{"name":"build","commands":["echo <>&\u2028\u2029"],"timeoutSeconds":60},{"name":"application_tests","commands":[],"timeoutSeconds":60},{"name":"security","commands":[],"timeoutSeconds":60},{"name":"image_packaging","commands":[],"timeoutSeconds":60},{"name":"preview","commands":[],"timeoutSeconds":60},{"name":"migration_rehearsal","commands":[],"timeoutSeconds":60},{"name":"acceptance","commands":[],"timeoutSeconds":60}]},"hash":"024548cb9a57601133fe055d77bb6566ea077537da76e10b3f9356d57010a81c"}`

func bindingPipeline() Pipeline {
	p := Pipeline{Version: 1, Template: "node-api"}
	for _, n := range mandatoryStages {
		p.Stages = append(p.Stages, Stage{Name: n, Commands: []string{}, Timeout: 60})
	}
	return p
}
func bindingWrite(t *testing.T, root, path string, b []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(path))
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func bindingWorkspace(t *testing.T) (string, verificationInput) {
	t.Helper()
	root := t.TempDir()
	in := verificationInput{AppID: "app1", JobID: "job1", AttemptID: "attempt1", Fence: 1, SourceBindingVersion: 1, Pipeline: bindingPipeline()}
	p, _ := json.Marshal(in.Pipeline)
	bindingWrite(t, root, "autosoft.pipeline.json", p)
	bindingWrite(t, root, "server.mjs", []byte("export const ready=true;\n"))
	h, e := sourceDigest(root)
	if e != nil {
		t.Fatal(e)
	}
	in.FilesHash = h
	return root, in
}
func bindingHandler(t *testing.T, workspace string) (*server, *int) {
	t.Helper()
	calls := new(int)
	s := &server{workspace: t.TempDir(), data: t.TempDir(), manifest: testManifest(), buildSlot: make(chan struct{}, 1), runner: func(context.Context, string, ...string) (string, error) {
		*calls++
		return "", errors.New("Unexpected runner")
	}}
	_, e := copyTree(workspace, filepath.Join(s.workspace, "app1", "job1", "attempt1"), 20<<20, 600)
	if e != nil {
		t.Fatal(e)
	}
	return s, calls
}
func bindingVerify(s *server, in verificationInput) *httptest.ResponseRecorder {
	b, _ := json.Marshal(in)
	r := httptest.NewRequest("POST", "/v1/verify", bytes.NewReader(b))
	w := httptest.NewRecorder()
	s.verify(w, r)
	return w
}
func TestSourceBindingCrossLanguageVectors(t *testing.T) {
	var vectors []struct {
		Name  string               `json:"name"`
		Files []capturedSourceFile `json:"files"`
		Hash  string               `json:"hash"`
	}
	if e := json.Unmarshal([]byte(bindingVectors), &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			h, e := capturedSourceDigest(v.Files)
			if e != nil || h != v.Hash {
				t.Fatalf("%s %v", h, e)
			}
			for i, j := 0, len(v.Files)-1; i < j; i, j = i+1, j-1 {
				v.Files[i], v.Files[j] = v.Files[j], v.Files[i]
			}
			h, e = capturedSourceDigest(v.Files)
			if e != nil || h != v.Hash {
				t.Fatal("Order changed digest")
			}
			if v.Name != "html-and-separators" {
				root := t.TempDir()
				for _, f := range v.Files {
					bindingWrite(t, root, f.Path, []byte(f.Content))
				}
				actual, e := sourceDigest(root)
				if e != nil || actual != v.Hash {
					t.Fatal("Actual legacy source digest differs", actual, e)
				}
			}
		})
	}
	var pv struct {
		Pipeline Pipeline `json:"pipeline"`
		Hash     string   `json:"hash"`
	}
	if e := json.Unmarshal([]byte(bindingPipelineVector), &pv); e != nil {
		t.Fatal(e)
	}
	if pipelineDefinitionHash(pv.Pipeline) != pv.Hash {
		t.Fatal("Pipeline hash differs from Node vector")
	}
}
func TestSourceBindingRequestDenialBeforeRunner(t *testing.T) {
	for _, name := range []string{"forged", "legacy", "wrong-version", "pipeline", "extra-file"} {
		t.Run(name, func(t *testing.T) {
			root, in := bindingWorkspace(t)
			s, calls := bindingHandler(t, root)
			switch name {
			case "forged":
				in.FilesHash = strings.Repeat("a", 64)
			case "legacy":
				in.SourceBindingVersion = 0
			case "wrong-version":
				in.SourceBindingVersion = 2
			case "pipeline":
				in.Pipeline.Stages[1].Commands = []string{"echo changed"}
			case "extra-file":
				bindingWrite(t, filepath.Join(s.workspace, "app1", "job1", "attempt1"), "stale.txt", []byte("unseen"))
			}
			w := bindingVerify(s, in)
			if w.Code != 409 || *calls != 0 {
				t.Fatal("Unbound input reached runner", w.Code, *calls, w.Body.String())
			}
			if _, e := os.Stat(filepath.Join(s.data, "sources", in.AttemptID)); !os.IsNotExist(e) {
				t.Fatal("Rejected input produced a snapshot")
			}
		})
	}
}
func TestSourceBindingExactPipelineReadback(t *testing.T) {
	root, in := bindingWorkspace(t)
	if h, e := verificationSourceInput(root, in); e != nil || h != in.FilesHash {
		t.Fatal(h, e)
	}
	for _, body := range []string{`{"schemaVersion":1,"template":"node-api","stages":[],"unknown":true}`, `{} {}`, strings.Repeat(" ", (1<<20)+1)} {
		bindingWrite(t, root, "autosoft.pipeline.json", []byte(body))
		in.FilesHash, _ = sourceDigest(root)
		if _, e := verificationSourceInput(root, in); e == nil {
			t.Fatal("Malformed captured pipeline passed")
		}
	}
}
func TestSourceBindingSnapshotsRefuseExistingAndPreserveSentinels(t *testing.T) {
	for _, existing := range []string{"source", "build"} {
		t.Run(existing, func(t *testing.T) {
			workspace, in := bindingWorkspace(t)
			root := t.TempDir()
			source, build := filepath.Join(root, "sources", "a"), filepath.Join(root, "builds", "a")
			keep := source
			if existing == "build" {
				keep = build
			}
			bindingWrite(t, keep, "sentinel", []byte("preserve"))
			h, owned, e := createVerificationSnapshots(workspace, source, build, in)
			if e == nil || owned || h != "" {
				t.Fatal("Existing snapshot adopted")
			}
			b, re := os.ReadFile(filepath.Join(keep, "sentinel"))
			if re != nil || string(b) != "preserve" {
				t.Fatal("Sentinel removed")
			}
			other := build
			if existing == "build" {
				other = source
			}
			if _, e := os.Stat(other); !os.IsNotExist(e) {
				t.Fatal("Refusal caused partial new snapshot")
			}
		})
	}
	workspace, in := bindingWorkspace(t)
	root := t.TempDir()
	source, build := filepath.Join(root, "sources", "a"), filepath.Join(root, "builds", "a")
	h, owned, e := createVerificationSnapshots(workspace, source, build, in)
	if e != nil || !owned || h != in.FilesHash {
		t.Fatal(h, owned, e)
	}
	if h, e = verificationSourceInput(build, in); e != nil || h != in.FilesHash {
		t.Fatal("Actual copied build differs")
	}
}
func TestSourceBindingPartialSourcePreservedAfterReadbackDenial(t *testing.T) {
	workspace, in := bindingWorkspace(t)
	in.FilesHash = strings.Repeat("f", 64)
	root := t.TempDir()
	source, build := filepath.Join(root, "sources", "a"), filepath.Join(root, "builds", "a")
	_, owned, e := createVerificationSnapshots(workspace, source, build, in)
	if e == nil || owned {
		t.Fatal("Forged copy accepted")
	}
	if b, e := os.ReadFile(filepath.Join(source, "server.mjs")); e != nil || len(b) == 0 {
		t.Fatal("Partial source removed")
	}
	if _, e := os.Stat(build); !os.IsNotExist(e) {
		t.Fatal("Build created before input verification")
	}
}
func TestSourceBindingHandlerPreservesExistingBuild(t *testing.T) {
	root, in := bindingWorkspace(t)
	s, calls := bindingHandler(t, root)
	build := filepath.Join(s.data, "builds", in.AttemptID)
	bindingWrite(t, build, "sentinel", []byte("preserve"))
	w := bindingVerify(s, in)
	if w.Code != 400 || *calls != 0 {
		t.Fatal(w.Code, *calls, w.Body.String())
	}
	b, e := os.ReadFile(filepath.Join(build, "sentinel"))
	if e != nil || string(b) != "preserve" {
		t.Fatal("Existing disposable tree was cleaned")
	}
}
func bindingReceipt(t *testing.T, source string, in verificationInput) Verification {
	t.Helper()
	v := Verification{AppID: in.AppID, AttemptID: in.AttemptID, FilesHash: in.FilesHash, InputSourceHash: in.FilesHash, SourceBindingVersion: 1, PipelineHash: pipelineDefinitionHash(in.Pipeline), Template: in.Pipeline.Template, Migrations: []Migration{}}
	if e := bindFinalVerificationSource(&v, source); e != nil {
		t.Fatal(e)
	}
	q := verifiedMigrationRequest(in, v, v.Migrations)
	r := emptySnapshot(q)
	v.MigrationSnapshot = &r
	return v
}
func TestSourceBindingGeneratedLockBindsFinalMigrationAndReplay(t *testing.T) {
	source, in := bindingWorkspace(t)
	bindingWrite(t, source, "package-lock.json", []byte("{\"lockfileVersion\":3}\n"))
	v := bindingReceipt(t, source, in)
	if v.SourceHash == v.InputSourceHash || v.MigrationSnapshot.Binding.SourceHash != v.SourceHash {
		t.Fatal("Migration used pre-lock input")
	}
	if !verificationReplayBinding(v, in, in.FilesHash, source) {
		t.Fatal("Exactly bound replay refused")
	}
	bindingWrite(t, source, "package-lock.json", []byte("changed"))
	if verificationReplayBinding(v, in, in.FilesHash, source) {
		t.Fatal("Changed generated lock passed replay")
	}
}
func TestSourceBindingReplayRejectsLegacyAndEveryConflict(t *testing.T) {
	source, in := bindingWorkspace(t)
	v := bindingReceipt(t, source, in)
	for _, name := range []string{"legacy", "input", "files", "pipeline", "app", "attempt", "template", "final", "migration-source", "migration-set", "job", "fence", "base"} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(v)
			var changed Verification
			json.Unmarshal(b, &changed)
			switch name {
			case "legacy":
				changed.SourceBindingVersion = 0
			case "input":
				changed.InputSourceHash = strings.Repeat("f", 64)
			case "files":
				changed.FilesHash = strings.Repeat("f", 64)
			case "pipeline":
				changed.PipelineHash = strings.Repeat("f", 64)
			case "app":
				changed.AppID = "other"
			case "attempt":
				changed.AttemptID = "other"
			case "template":
				changed.Template = "python-api"
			case "final":
				changed.SourceHash = strings.Repeat("f", 64)
			case "migration-source":
				changed.MigrationSnapshot.Binding.SourceHash = in.FilesHash + "f"
			case "migration-set":
				changed.Migrations = []Migration{{ID: "add1", Checksum: strings.Repeat("d", 64)}}
			case "job":
				changed.MigrationSnapshot.Binding.JobID = "other"
			case "fence":
				changed.MigrationSnapshot.Binding.Fence++
			case "base":
				other := "release1"
				changed.MigrationSnapshot.Binding.BaseReleaseID = &other
			}
			if verificationReplayBinding(changed, in, in.FilesHash, source) {
				t.Fatal("Conflicting replay admitted")
			}
		})
	}
	bindingWrite(t, source, "autosoft.pipeline.json", []byte(`{}`))
	v.SourceHash, _ = sourceDigest(source)
	v.MigrationSnapshot.Binding.SourceHash = v.SourceHash
	if verificationReplayBinding(v, in, in.FilesHash, source) {
		t.Fatal("Rehashed incompatible pipeline admitted")
	}
}

func TestSourceBindingReplayRejectsRehashedMigrationMetadata(t *testing.T) {
	source, in := bindingWorkspace(t)
	v := bindingReceipt(t, source, in)
	v.Migrations = []Migration{{ID: "add1", SQL: "CREATE TABLE docs (id INT)", Checksum: hashBytes([]byte("CREATE TABLE docs (id INT)"))}}
	v.MigrationSnapshot.Binding.MigrationHash = migrationSetHash(v.Migrations)
	if verificationReplayBinding(v, in, in.FilesHash, source) {
		t.Fatal("Rehashed migration receipt differs from actual captured migrations")
	}
}

func TestSourceBindingUnreadableCacheBlocksBeforeSnapshot(t *testing.T) {
	workspace, in := bindingWorkspace(t)
	s, calls := bindingHandler(t, workspace)
	p := filepath.Join(s.data, "receipts", in.AttemptID+".json")
	if e := os.MkdirAll(p, 0700); e != nil {
		t.Fatal(e)
	}
	w := bindingVerify(s, in)
	if w.Code != 409 || *calls != 0 {
		t.Fatal("Unknown cache outcome admitted new work", w.Code, *calls)
	}
	if info, e := os.Stat(p); e != nil || !info.IsDir() {
		t.Fatal("Unknown cache record removed")
	}
	if _, e := os.Stat(filepath.Join(s.data, "sources", in.AttemptID)); !os.IsNotExist(e) {
		t.Fatal("Unknown cache outcome produced a source snapshot")
	}
}
func TestSourceBindingCachedLegacyConflictPreservedBeforeRunner(t *testing.T) {
	workspace, in := bindingWorkspace(t)
	s, calls := bindingHandler(t, workspace)
	source := filepath.Join(s.data, "sources", in.AttemptID)
	if _, e := copyTree(workspace, source, 20<<20, 600); e != nil {
		t.Fatal(e)
	}
	v := bindingReceipt(t, source, in)
	v.SourceBindingVersion = 0
	p := filepath.Join(s.data, "receipts", in.AttemptID+".json")
	if e := atomicJSON(p, v); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(p)
	w := bindingVerify(s, in)
	after, _ := os.ReadFile(p)
	if w.Code != 409 || *calls != 0 || !bytes.Equal(before, after) {
		t.Fatal("Historical receipt adopted or changed", w.Code, *calls)
	}
}
func TestSourceBindingCaptureFreshContextAndCancellation(t *testing.T) {
	_, in := bindingWorkspace(t)
	q := verifiedMigrationRequest(in, Verification{SourceHash: in.FilesHash}, nil)
	old, cancelOld := context.WithCancel(context.Background())
	cancelOld()
	if old.Err() == nil {
		t.Fatal("Fixture was not canceled")
	}
	for _, name := range []string{"success", "error", "parent-before", "parent-during"} {
		t.Run(name, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "parent-before" {
				cancel()
			}
			calls := 0
			var used context.Context
			r, e := captureVerificationMigration(parent, q, nil, func(ctx context.Context, got migrationSnapshotRequest, _ []Migration) (migrationSnapshotReceipt, error) {
				calls++
				used = ctx
				if ctx.Err() != nil || got.SourceHash != in.FilesHash {
					t.Fatal("Fresh live bound context not supplied")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 120*time.Second || time.Until(deadline) < 119*time.Second {
					t.Fatal("Capture bound is not 120 seconds")
				}
				if name == "parent-during" {
					cancel()
				}
				if name == "error" {
					return emptySnapshot(q), errors.New("capture failed")
				}
				return emptySnapshot(q), nil
			})
			if name == "success" {
				if e != nil || calls != 1 || r.Binding.SourceHash != in.FilesHash {
					t.Fatal(e, calls)
				}
			} else if e == nil {
				t.Fatal("Unknown/canceled capture succeeded")
			}
			if name == "parent-before" && calls != 0 {
				t.Fatal("Canceled parent invoked capture")
			}
			if used != nil && used.Err() == nil {
				t.Fatal("Capture context was not canceled after return")
			}
		})
	}
}
func TestSourceBindingReturnedSourceBytesAndHistoricalEligibility(t *testing.T) {
	for _, name := range []string{"unchanged", "altered", "missing", "extra", "invalid-utf8", "bad-attempt"} {
		t.Run(name, func(t *testing.T) {
			workspace, in := bindingWorkspace(t)
			s, _ := bindingHandler(t, workspace)
			source := filepath.Join(s.data, "sources", in.AttemptID)
			copyTree(workspace, source, 20<<20, 600)
			h, _ := sourceDigest(source)
			v := Verification{AppID: in.AppID, AttemptID: in.AttemptID, SourceHash: h, Commit: strings.Repeat("a", 40), Evidence: Evidence{Status: "passed"}} // Legacy final binding remains readable.
			switch name {
			case "altered":
				bindingWrite(t, source, "server.mjs", []byte("tampered"))
			case "missing":
				os.Remove(filepath.Join(source, "server.mjs"))
			case "extra":
				bindingWrite(t, source, "unseen", []byte("unreviewed"))
			case "invalid-utf8":
				bindingWrite(t, source, "server.mjs", []byte{0xff})
				v.SourceHash, _ = sourceDigest(source)
			case "bad-attempt":
				v.AttemptID = "../other"
			}
			if e := atomicJSON(filepath.Join(s.data, "receipts", in.AttemptID+".json"), v); e != nil {
				t.Fatal(e)
			}
			b, _ := json.Marshal(map[string]string{"appId": in.AppID, "commit": v.Commit})
			w := httptest.NewRecorder()
			s.source(w, httptest.NewRequest("POST", "/v1/source", bytes.NewReader(b)))
			if name == "unchanged" {
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
				var out struct {
					Files []capturedSourceFile `json:"files"`
				}
				json.Unmarshal(w.Body.Bytes(), &out)
				returned, e := capturedSourceDigest(out.Files)
				if e != nil || returned != h {
					t.Fatal("Returned bytes are not exact final source")
				}
			} else if w.Code == 200 {
				t.Fatal("Unbound returned source passed", name)
			}
		})
	}
}
func TestSourceBindingCapturedBytesBounds(t *testing.T) {
	cases := [][]capturedSourceFile{
		{{Path: "a", Content: "x"}, {Path: "a", Content: "y"}},
		{{Path: "a", Content: string([]byte{0xff})}},
		make([]capturedSourceFile, 601),
		{{Path: "a", Content: strings.Repeat("x", (20<<20)+1)}},
	}
	for _, files := range cases {
		if _, e := capturedSourceDigest(files); e == nil {
			t.Fatal("Invalid capture accepted")
		}
	}
}
