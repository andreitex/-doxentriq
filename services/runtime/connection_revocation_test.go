package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func explicitWithdrawalFixture(t *testing.T, preview bool) (*filesystemRevocationFixture, withdrawalRequest) {
	t.Helper()
	f := newFilesystemRevocationFixture(t, preview)
	f.container["Image"] = "sha256:" + strings.Repeat("c", 64)
	old := f.server.runner
	f.server.runner = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "docker" && reflect.DeepEqual(args, []string{"ps", "--all", "--no-trunc", "--format", "{{.ID}}"}) {
			return f.listed, nil
		}
		return old(ctx, name, args...)
	}
	snapshot, e := f.server.withdrawalSnapshot(context.Background(), f.state.Input.Scope.AppID, f.state.Input.Scope.ConnectionID)
	if e != nil {
		t.Fatal(e)
	}
	in := withdrawalRequest{Version: 1, Action: "revoke_readonly_filesystem", OperationID: "withdrawal-one", ApprovalID: "owner-review-one", Change: withdrawalChange{snapshot, strings.Repeat("a", 64), strings.Repeat("b", 64)}, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: time.Now().Add(4 * time.Minute).UTC().Format(time.RFC3339Nano)}
	in.Principal.ID = "owner-one"
	in.Principal.MFA = true
	in.Principal.LocalOwner = true
	in.Hash = withdrawalArtifactHash(in.Change)
	return f, in
}

// Injected persistence tests the protocol ordering on every development host;
// the separate Linux test below exercises actual file+directory synchronization.
func withdrawalTestRetain(t *testing.T, s *server) func(string, withdrawalRecord) error {
	return func(file string, v withdrawalRecord) error {
		t.Helper()
		if e := writeEncrypted(file, v); e != nil {
			return e
		}
		var actual withdrawalRecord
		if e := s.readWithdrawal(file, &actual); e != nil {
			return e
		}
		if !reflect.DeepEqual(actual, v) {
			return errors.New("Synthetic readback mismatch")
		}
		return nil
	}
}

func TestExplicitWithdrawalStopsExpiredOriginalPublishedAndPreviewAfterDurableIntent(t *testing.T) {
	for _, preview := range []bool{false, true} {
		f, in := explicitWithdrawalFixture(t, preview)
		retained := 0
		retain := withdrawalTestRetain(t, f.server)
		old := f.server.runner
		f.server.runner = func(ctx context.Context, name string, args ...string) (string, error) {
			if len(args) > 0 && args[0] == "stop" {
				if retained == 0 || f.server.connectionWithdrawalBlocked(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID) == nil {
					t.Fatal("Stop preceded permanent intent")
				}
			}
			return old(ctx, name, args...)
		}
		wrapped := func(file string, v withdrawalRecord) error {
			e := retain(file, v)
			if e == nil {
				retained++
			}
			return e
		}
		v, e, started := f.server.applyWithdrawal(context.Background(), in, wrapped)
		if e != nil || !started || v.Status != "revoked" || !reflect.DeepEqual(v.Stopped, []string{f.receipt.ContainerID}) || len(f.stops) != 1 {
			t.Fatal(v, e, started, f.stops)
		}
		if f.server.connectionWithdrawalBlocked(in.Change.Snapshot.AppID, "other-connection") != nil || f.server.connectionWithdrawalBlocked("other-app", in.Change.Snapshot.ConnectionID) != nil {
			t.Fatal("Withdrawal escaped app/connection scope")
		}
		if _, e := os.Stat(f.server.filesystemStatePath(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID)); e != nil {
			t.Fatal("Original credential/scope record removed")
		}
		if _, e := f.server.loadApprovedFilesystem(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID); e == nil {
			t.Fatal("Application rollback revived retained filesystem access")
		}
		if _, e := f.server.loadApprovedConnector(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID); e == nil {
			t.Fatal("Adapter substitution bypassed tombstone")
		}
		again, e, _ := f.server.applyWithdrawal(context.Background(), in, wrapped)
		if e != nil || again.Status != "revoked" || len(f.stops) != 1 {
			t.Fatal("Duplicate dispatch repeated stop", again, e)
		}
	}
}
func TestExplicitWithdrawalRejectsChangedCompleteInventoryBeforeIntent(t *testing.T) {
	for _, kind := range []string{"profile", "missing", "label", "new-id"} {
		t.Run(kind, func(t *testing.T) {
			f, in := explicitWithdrawalFixture(t, false)
			switch kind {
			case "profile":
				f.container["Config"].(map[string]any)["Env"] = append(f.container["Config"].(map[string]any)["Env"].([]string), "UNEXPECTED=changed")
			case "missing":
				f.listed = ""
			case "label":
				f.container["Config"].(map[string]any)["Labels"].(map[string]string)["io.autosoft.connector.app"] = "other-app"
			case "new-id":
				f.listed += "\n" + f.receipt.ContainerID
			}
			retained := false
			_, e, started := f.server.applyWithdrawal(context.Background(), in, func(string, withdrawalRecord) error { retained = true; return nil })
			if e == nil || started || retained || len(f.stops) != 0 {
				t.Fatal("Stale inventory authorized withdrawal", kind, e, started)
			}
		})
	}
}
func TestExplicitWithdrawalOwnerMFAHashAndExpiryAreIndependent(t *testing.T) {
	_, in := explicitWithdrawalFixture(t, false)
	for _, kind := range []string{"owner", "mfa", "local", "expiry", "artifact", "snapshot", "order", "future"} {
		t.Run(kind, func(t *testing.T) {
			v := in
			v.Change.Snapshot.Targets = append([]withdrawalTarget{}, in.Change.Snapshot.Targets...)
			switch kind {
			case "owner":
				v.Principal.ID = "sso-admin"
			case "mfa":
				v.Principal.MFA = false
			case "local":
				v.Principal.LocalOwner = false
			case "expiry":
				v.ExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
			case "artifact":
				v.Hash = strings.Repeat("0", 64)
			case "snapshot":
				v.Change.Snapshot.Hash = strings.Repeat("0", 64)
			case "order":
				v.Change.Snapshot.Targets = append(v.Change.Snapshot.Targets, v.Change.Snapshot.Targets[0])
				v.Change.Snapshot.Hash = withdrawalSnapshotHash(v.Change.Snapshot)
				v.Hash = withdrawalArtifactHash(v.Change)
			case "future":
				v.ApprovedAt = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
			}
			if validateWithdrawal(v, time.Now()) == nil {
				t.Fatal("Invalid owner approval accepted", kind)
			}
		})
	}
}
func TestExplicitWithdrawalUncertainStopStaysPendingAndReadOnlyStatusNeverDispatches(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	f.keepAlive = true
	retain := withdrawalTestRetain(t, f.server)
	v, e, _ := f.server.applyWithdrawal(context.Background(), in, retain)
	if e != nil || v.Status != "pending" || len(f.stops) != 1 {
		t.Fatal(v, e)
	}
	var recovered withdrawalRecord
	if e := f.server.readWithdrawal(f.server.withdrawalPath(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID), &recovered); e != nil {
		t.Fatal(e)
	}
	readOnly, e, _ := f.server.reconcileWithdrawal(context.Background(), recovered, retain, false)
	if e != nil || readOnly.Status != "pending" || len(f.stops) != 1 {
		t.Fatal("Read-only inspection repeated stop", e, f.stops)
	}
	f.keepAlive = false
	reconciled, e, _ := f.server.reconcileWithdrawal(context.Background(), recovered, retain, true)
	if e != nil || reconciled.Status != "revoked" || len(f.stops) != 2 {
		t.Fatal("Exact boot intent did not recover", reconciled, e)
	}
	replacement := in
	replacement.ApprovalID = "new-review"
	_, e, _ = f.server.applyWithdrawal(context.Background(), replacement, retain)
	if e == nil || len(f.stops) != 2 {
		t.Fatal("Retained tombstone was replaced")
	}
}
func TestExplicitWithdrawalFailedRetentionNeverStopsAndDriftPreservesIntent(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	_, e, started := f.server.applyWithdrawal(context.Background(), in, func(string, withdrawalRecord) error { return errors.New("Synthetic directory sync failure") })
	if e == nil || !started || len(f.stops) != 0 {
		t.Fatal("Unsynchronized intent authorized stop")
	}
	retain := withdrawalTestRetain(t, f.server)
	f.keepAlive = true
	v, e, _ := f.server.applyWithdrawal(context.Background(), in, retain)
	if e != nil {
		t.Fatal(e)
	}
	f.container["HostConfig"].(map[string]any)["Memory"] = 129 << 20
	after, e, _ := f.server.reconcileWithdrawal(context.Background(), v, retain, true)
	if e != nil || after.Status != "pending" || len(f.stops) != 1 || f.server.connectionWithdrawalBlocked(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID) == nil {
		t.Fatal("Drift authorized substitute stop or dropped tombstone", after, e)
	}
}
func TestExplicitWithdrawalLostStopResponseRequiresIndependentStoppedReadback(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	f.stopError = true
	v, e, _ := f.server.applyWithdrawal(context.Background(), in, withdrawalTestRetain(t, f.server))
	if e != nil || v.Status != "revoked" || len(f.stops) != 1 {
		t.Fatal("Independent stopped readback did not resolve response loss", v, e)
	}
}
func TestExplicitWithdrawalMalformedOrLinkedPresenceNeverPermitsProvision(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	file := f.server.withdrawalPath(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID)
	if e := os.MkdirAll(filepath.Dir(file), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(file, []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if f.server.connectionWithdrawalBlocked(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID) == nil {
		t.Fatal("Corrupt tombstone bypassed admission")
	}
	if runtime.GOOS == "linux" {
		_ = os.Remove(file)
		if e := os.Symlink(filepath.Join(t.TempDir(), "absent"), file); e != nil {
			t.Fatal(e)
		}
		if f.server.connectionWithdrawalBlocked(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID) == nil {
			t.Fatal("Dangling linked tombstone treated as absent")
		}
	}
}
func TestExplicitWithdrawalDurableEncryptedLinuxReadback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Actual Linux directory fsync/permissions proof requires Linux")
	}
	f, in := explicitWithdrawalFixture(t, false)
	v, e, _ := f.server.applyWithdrawal(context.Background(), in, f.server.retainWithdrawal)
	if e != nil || v.Status != "revoked" {
		t.Fatal(v, e)
	}
	file := f.server.withdrawalPath(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID)
	b, e := os.ReadFile(file)
	if e != nil || bytesContainPlaintextWithdrawal(b, in) {
		t.Fatal("Encrypted tombstone missing or plaintext")
	}
	var actual withdrawalRecord
	if f.server.readWithdrawal(file, &actual) != nil || !reflect.DeepEqual(actual, v) {
		t.Fatal("Durable exact tombstone readback failed")
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if os.Link(file, linked) != nil {
		t.Fatal("Hardlink fixture unavailable")
	}
	if f.server.readWithdrawal(file, &actual) == nil {
		t.Fatal("Multiply-linked encrypted record accepted")
	}
}
func bytesContainPlaintextWithdrawal(b []byte, in withdrawalRequest) bool {
	encoded, _ := json.Marshal(in)
	return strings.Contains(string(b), string(encoded)) || strings.Contains(string(b), in.OperationID)
}

func TestExplicitWithdrawalVisibleUnsynchronizedIntentCannotAuthorizeTimerOrSourceWatcherStop(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	file := f.server.withdrawalPath(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID)
	at := time.Now().UTC().Format(time.RFC3339Nano)
	v := withdrawalRecord{1, in, "pending", []string{}, at, at}
	// Simulate successful rename followed by failed directory Sync.
	if e := writeEncrypted(file, v); e != nil {
		t.Fatal(e)
	}
	result, e, _ := f.server.reconcileWithdrawal(context.Background(), v, func(string, withdrawalRecord) error { return errors.New("Synthetic persistent directory sync failure") }, true)
	if e == nil || result.Status != "pending" || len(f.stops) != 0 {
		t.Fatal("Visible uncommitted intent authorized stop", result, e)
	}
	sourceCurrent := func(string, string) (filesystemConnectorState, error) { return f.state, nil }
	if watched := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, sourceCurrent); watched.Status != "current" || len(f.stops) != 0 {
		t.Fatal("Independent source watcher consumed explicit unsynchronized intent", watched)
	}
	if watched := f.server.reconcileFilesystemRevocationTarget(context.Background(), f.receipt.ContainerID, func(string, string) (filesystemConnectorState, error) {
		return f.state, errors.New("Independent source withdrawal")
	}); watched.Status != "stopped" || len(f.stops) != 1 {
		t.Fatal("Independent source retirement was suppressed", watched)
	}
}
func TestExplicitWithdrawalExpiredExactDuplicateNeverClaimsPreExecutionRejection(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	past := time.Now().Add(-time.Hour)
	in.Change.Snapshot.ObservedAt = past.Format(time.RFC3339Nano)
	in.ApprovedAt = past.Add(time.Second).Format(time.RFC3339Nano)
	in.ExpiresAt = past.Add(4 * time.Minute).Format(time.RFC3339Nano)
	in.Hash = withdrawalArtifactHash(in.Change)
	v := withdrawalRecord{1, in, "pending", []string{}, past.Add(2 * time.Second).Format(time.RFC3339Nano), past.Add(2 * time.Second).Format(time.RFC3339Nano)}
	if e := writeEncrypted(f.server.withdrawalPath(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID), v); e != nil {
		t.Fatal(e)
	}
	f.server.approvalKey = bytes.Repeat([]byte{8}, 32)
	body, _ := json.Marshal(in)
	mac := hmac.New(sha256.New, f.server.approvalKey)
	_, _ = mac.Write(body)
	r := httptest.NewRequest("POST", "/v1/connectors/revoke", bytes.NewReader(body))
	r.Header.Set("X-Autosoft-Proof", hex.EncodeToString(mac.Sum(nil)))
	w := httptest.NewRecorder()
	f.server.revokeConnection(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "rejectedBeforeExecution") || len(f.stops) != 0 {
		t.Fatal("Expired retained duplicate permitted a false rejection/replay", w.Code, w.Body.String())
	}
}
func TestExplicitWithdrawalCompletedReadbackDemotesOnDriftOrUnavailableInventory(t *testing.T) {
	for _, kind := range []string{"profile", "unavailable", "missing", "restarted"} {
		t.Run(kind, func(t *testing.T) {
			f, in := explicitWithdrawalFixture(t, false)
			retain := withdrawalTestRetain(t, f.server)
			v, e, _ := f.server.applyWithdrawal(context.Background(), in, retain)
			if e != nil || v.Status != "revoked" {
				t.Fatal(v, e)
			}
			switch kind {
			case "profile":
				f.container["HostConfig"].(map[string]any)["Memory"] = 129 << 20
			case "missing":
				f.listed = ""
			case "restarted":
				f.container["State"] = map[string]any{"Running": true, "Paused": false, "Restarting": false, "Status": "running"}
			case "unavailable":
				old := f.server.runner
				f.server.runner = func(ctx context.Context, name string, args ...string) (string, error) {
					if len(args) > 0 && args[0] == "ps" {
						return "", errors.New("Synthetic inventory outage")
					}
					return old(ctx, name, args...)
				}
			}
			current, e, _ := f.server.reconcileWithdrawal(context.Background(), v, retain, false)
			if e != nil || current.Status != "pending" || len(current.Stopped) != 1 || len(f.stops) != 1 {
				t.Fatal("Old completed status survived unverifiable current readback", current, e)
			}
		})
	}
}
func TestExplicitWithdrawalFinalIndependentStateRejectsRestartRace(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	old := f.server.runner
	inventories := 0
	f.server.runner = func(ctx context.Context, name string, args ...string) (string, error) {
		if reflect.DeepEqual(args, []string{"ps", "--all", "--no-trunc", "--format", "{{.ID}}"}) {
			inventories++
			if inventories == 3 {
				f.container["State"] = map[string]any{"Running": true, "Paused": false, "Restarting": false, "Status": "running"}
			}
		}
		return old(ctx, name, args...)
	}
	v, e, _ := f.server.applyWithdrawal(context.Background(), in, withdrawalTestRetain(t, f.server))
	if e != nil || v.Status != "pending" || len(v.Stopped) != 1 || len(f.stops) != 1 {
		t.Fatal("Final profile-only equality falsely implied stopped state", v, e, inventories)
	}
}
func TestExplicitWithdrawalNoSidecarsStillRetainsPermanentDenyWithoutStop(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	f.listed = ""
	snapshot, e := f.server.withdrawalSnapshot(context.Background(), in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID)
	if e != nil || len(snapshot.Targets) != 0 {
		t.Fatal(snapshot, e)
	}
	in.Change.Snapshot = snapshot
	in.ApprovedAt = time.Now().UTC().Format(time.RFC3339Nano)
	in.Hash = withdrawalArtifactHash(in.Change)
	v, e, _ := f.server.applyWithdrawal(context.Background(), in, withdrawalTestRetain(t, f.server))
	if e != nil || v.Status != "revoked" || len(v.Stopped) != 0 || len(f.stops) != 0 || f.server.connectionWithdrawalBlocked(snapshot.AppID, snapshot.ConnectionID) == nil {
		t.Fatal("Zero-container withdrawal lost deny authority", v, e)
	}
}
func TestExplicitWithdrawalCompletePreviewAndPublishedInventoryRetainsPartialStops(t *testing.T) {
	f, in := explicitWithdrawalFixture(t, false)
	other := newFilesystemRevocationFixture(t, true)
	other.server = f.server
	other.state = f.state
	other.resource.Secrets = filepath.Join(f.server.data, "secrets", other.resource.AppID)
	ownerBase := filepath.Dir(filepath.Dir(f.expected.HostCA))
	t.Setenv("HOST_DATA_DIR", ownerBase)
	v := other.resource
	v.AppID = other.index.ResourceID
	var e error
	other.expected, e = f.server.expectedFilesystemContainer(other.state, v)
	if e != nil {
		t.Fatal(e)
	}
	other.container = filesystemContainerFixture(other.expected)
	second := strings.Repeat("e", 64)
	other.container["Id"] = second
	other.container["Image"] = "sha256:" + strings.Repeat("c", 64)
	other.container["State"] = map[string]any{"Running": true, "Paused": false, "Restarting": false, "Status": "running"}
	other.container["NetworkSettings"] = map[string]any{"Networks": map[string]any{other.resource.Network: map[string]any{"NetworkID": strings.Repeat("9", 64), "IPAddress": "172.30.1.2"}}}
	other.receipt.AppID = f.state.Input.Scope.AppID
	other.receipt.ContainerID = second
	other.receipt.ScopeHash = f.state.ScopeHash
	other.receipt.ExpiresAt = f.state.Input.Scope.AccessExpiresAt
	other.receipt.CheckedAt = f.receipt.CheckedAt
	other.receipt.Adapter = other.expected.Name
	other.write(t)
	old := f.server.runner
	f.server.runner = func(ctx context.Context, name string, args ...string) (string, error) {
		if reflect.DeepEqual(args, []string{"ps", "--all", "--no-trunc", "--format", "{{.ID}}"}) {
			return second + "\n" + f.receipt.ContainerID, nil
		}
		if reflect.DeepEqual(args, []string{"inspect", "--format", "{{json .}}", second}) {
			b, _ := json.Marshal(other.container)
			return string(b), nil
		}
		if reflect.DeepEqual(args, []string{"stop", "--time", "10", second}) {
			other.stops = append(other.stops, second)
			other.container["State"] = map[string]any{"Running": false, "Paused": false, "Restarting": false, "Status": "exited"}
			return second, nil
		}
		if reflect.DeepEqual(args, []string{"network", "inspect", "--format", "{{json .}}", other.resource.Network}) {
			b, _ := json.Marshal(map[string]any{"Id": strings.Repeat("9", 64), "Name": other.resource.Network, "Driver": "bridge", "Internal": true, "Labels": map[string]string{"io.autosoft.managed": "true"}, "IPAM": map[string]any{"Config": []map[string]string{{"Subnet": "172.30.1.0/24"}}}, "Containers": map[string]any{second: map[string]string{"IPv4Address": "172.30.1.2/24"}}})
			return string(b), nil
		}
		return old(ctx, name, args...)
	}
	snapshot, e := f.server.withdrawalSnapshot(context.Background(), f.state.Input.Scope.AppID, f.state.Input.Scope.ConnectionID)
	if e != nil || len(snapshot.Targets) != 2 {
		t.Fatal("Complete candidate inventory omitted preview/published sidecar", snapshot, e)
	}
	in.Change.Snapshot = snapshot
	in.ApprovedAt = time.Now().UTC().Format(time.RFC3339Nano)
	in.Hash = withdrawalArtifactHash(in.Change)
	f.keepAlive = true
	retain := withdrawalTestRetain(t, f.server)
	current, e, _ := f.server.applyWithdrawal(context.Background(), in, retain)
	if e != nil || current.Status != "pending" || !reflect.DeepEqual(current.Stopped, []string{second}) {
		t.Fatal("Partial exact stop receipts were lost", current, e)
	}
	f.keepAlive = false
	done, e, _ := f.server.reconcileWithdrawal(context.Background(), current, retain, true)
	if e != nil || done.Status != "revoked" || len(done.Stopped) != 2 || len(other.stops) != 1 {
		t.Fatal("Exact partial intent did not recover remaining original", done, e)
	}
}

func TestExplicitWithdrawalGoldenHashesMatchControlForNestedTargetsAndNanosecondObservation(t *testing.T) {
	snapshot := withdrawalSnapshot{Version: 1, Type: "filesystem", AppID: "app-one", ConnectionID: "connection-one", ScopeHash: strings.Repeat("a", 64), GrantApprovalID: "grant-one", Targets: []withdrawalTarget{{strings.Repeat("1", 64), "as-app-app-one-deadbeef", strings.Repeat("2", 64)}, {strings.Repeat("3", 64), "as-preview-app-one-cafebabe", strings.Repeat("4", 64)}}, ObservedAt: "2026-10-10T10:00:00.123456789Z"}
	snapshot.Hash = withdrawalSnapshotHash(snapshot)
	impact := accessHash([]string{"Stop exact original reads.", "Preserve documents and credentials."})
	change := withdrawalChange{snapshot, strings.Repeat("5", 64), impact}
	if snapshot.Hash != "401811b80247f716615f5b7440df3d2cd0e862c43d7bc6ce12e850dfb7e01a34" || impact != "9074d6e10576d2ee92da5ec60cabc029f99b1e71dcc58f2e55ba3ddc7cab95d2" || withdrawalArtifactHash(change) != "1cf0958bb02a4ba535d851137807596a00a5842c3b0bab148931b8940141727f" {
		t.Fatal("Canonical withdrawal contract differs from TypeScript", snapshot.Hash, impact, withdrawalArtifactHash(change))
	}
}
