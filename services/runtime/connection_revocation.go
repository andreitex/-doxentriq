package main

// Explicit withdrawal is independent of app releases. It retains an encrypted,
// synchronized tombstone before stopping any independently proven full ID.
// No removal, data mutation, credential deletion, start or regrant exists here.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type withdrawalTarget struct {
	ContainerID string `json:"containerId"`
	ResourceID  string `json:"resourceId"`
	ProfileHash string `json:"profileHash"`
}
type withdrawalSnapshot struct {
	Version         int                `json:"schemaVersion"`
	Type            string             `json:"type"`
	AppID           string             `json:"appId"`
	ConnectionID    string             `json:"connectionId"`
	ScopeHash       string             `json:"scopeHash"`
	GrantApprovalID string             `json:"grantApprovalId"`
	Targets         []withdrawalTarget `json:"targets"`
	ObservedAt      string             `json:"observedAt"`
	Hash            string             `json:"snapshotHash"`
}
type withdrawalChange struct {
	Snapshot     withdrawalSnapshot `json:"snapshot"`
	RegistryHash string             `json:"registryHash"`
	ImpactHash   string             `json:"impactHash"`
}
type withdrawalRequest struct {
	Version     int              `json:"schemaVersion"`
	Action      string           `json:"action"`
	OperationID string           `json:"operationId"`
	ApprovalID  string           `json:"approvalId"`
	Hash        string           `json:"artifactHash"`
	Change      withdrawalChange `json:"change"`
	ApprovedAt  string           `json:"approvedAt"`
	ExpiresAt   string           `json:"expiresAt"`
	Principal   struct {
		ID         string `json:"id"`
		MFA        bool   `json:"mfa"`
		LocalOwner bool   `json:"localOwner"`
	} `json:"principal"`
}
type withdrawalIdentity struct {
	OperationID  string `json:"operationId"`
	ApprovalID   string `json:"approvalId"`
	AppID        string `json:"appId"`
	ConnectionID string `json:"connectionId"`
	Hash         string `json:"artifactHash"`
}
type withdrawalRecord struct {
	Version    int               `json:"schemaVersion"`
	Input      withdrawalRequest `json:"input"`
	Status     string            `json:"status"`
	Stopped    []string          `json:"stoppedContainerIds"`
	RetainedAt string            `json:"retainedAt"`
	CheckedAt  string            `json:"checkedAt"`
}
type withdrawalStatus struct {
	Version int    `json:"schemaVersion"`
	Type    string `json:"type"`
	withdrawalIdentity
	Status       string   `json:"status"`
	Tombstone    bool     `json:"tombstone"`
	SnapshotHash string   `json:"snapshotHash"`
	Stopped      []string `json:"stoppedContainerIds"`
	CheckedAt    string   `json:"checkedAt"`
}

func withdrawalSnapshotHash(v withdrawalSnapshot) string {
	return accessHash(map[string]any{"schemaVersion": v.Version, "type": v.Type, "appId": v.AppID, "connectionId": v.ConnectionID, "scopeHash": v.ScopeHash, "grantApprovalId": v.GrantApprovalID, "targets": v.Targets})
}
func withdrawalArtifactHash(v withdrawalChange) string {
	return accessHash(map[string]any{"schemaVersion": 1, "action": "revoke_readonly_filesystem", "change": v})
}
func withdrawalID(v withdrawalRequest) withdrawalIdentity {
	return withdrawalIdentity{v.OperationID, v.ApprovalID, v.Change.Snapshot.AppID, v.Change.Snapshot.ConnectionID, v.Hash}
}
func withdrawalStatusValue(v withdrawalRecord) withdrawalStatus {
	return withdrawalStatus{1, "filesystem", withdrawalID(v.Input), v.Status, true, v.Input.Change.Snapshot.Hash, v.Stopped, v.CheckedAt}
}
func validateWithdrawal(v withdrawalRequest, now time.Time) error {
	q := v.Change.Snapshot
	if v.Version != 1 || v.Action != "revoke_readonly_filesystem" || !identity.MatchString(v.OperationID) || !identity.MatchString(v.ApprovalID) || !accessHex.MatchString(v.Hash) || !accessHex.MatchString(v.Change.RegistryHash) || !accessHex.MatchString(v.Change.ImpactHash) || q.Version != 1 || q.Type != "filesystem" || !identity.MatchString(q.AppID) || !identity.MatchString(q.ConnectionID) || !identity.MatchString(q.GrantApprovalID) || !accessHex.MatchString(q.ScopeHash) || q.Targets == nil || len(q.Targets) > 256 || q.Hash != withdrawalSnapshotHash(q) || v.Hash != withdrawalArtifactHash(v.Change) || v.Principal.ID == "" || v.Principal.ID != os.Getenv("OWNER_SUBJECT") || !v.Principal.MFA || !v.Principal.LocalOwner {
		return errors.New("Exact owner/MFA filesystem withdrawal proof is required")
	}
	for i, t := range q.Targets {
		if !exactDockerID.MatchString(t.ContainerID) || !identity.MatchString(t.ResourceID) || !accessHex.MatchString(t.ProfileHash) || i > 0 && t.ContainerID <= q.Targets[i-1].ContainerID {
			return errors.New("Withdrawal inventory is ambiguous")
		}
	}
	observed, e := time.Parse(time.RFC3339Nano, q.ObservedAt)
	approved, ae := time.Parse(time.RFC3339Nano, v.ApprovedAt)
	expiry, ee := time.Parse(time.RFC3339Nano, v.ExpiresAt)
	if e != nil || ae != nil || ee != nil || observed.After(approved) || approved.After(now) || !expiry.After(now) || expiry.Sub(observed) > 5*time.Minute || approved.Before(observed) {
		return errors.New("The exact withdrawal inventory and owner review must be current within five minutes")
	}
	return nil
}
func (s *server) withdrawalPath(appID, connectionID string) string {
	return filepath.Join(s.data, "connectors", "revoked", appID, connectionID+".enc")
}

// Only an actually absent record permits access. Malformed, linked, unreadable
// or unsupported records are denial evidence, never an implicit regrant.
func (s *server) connectionWithdrawalBlocked(appID, connectionID string) error {
	if !identity.MatchString(appID) || !identity.MatchString(connectionID) {
		return errors.New("Invalid withdrawal identity")
	}
	file := s.withdrawalPath(appID, connectionID)
	if e := withdrawalAncestors(s.data, filepath.Dir(file), false); e != nil {
		return errors.New("Connection withdrawal retention is unavailable")
	}
	_, e := os.Lstat(file)
	if os.IsNotExist(e) {
		return nil
	}
	return errors.New("This application connection is permanently withdrawn or its retained status is unavailable; use a new connection ID")
}
func withdrawalOrdinary(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 || info.Size() > 2<<20 {
		return false
	}
	sys := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if sys.IsValid() && sys.Kind() == reflect.Struct {
		n := sys.FieldByName("Nlink")
		if n.IsValid() {
			return n.Uint() == 1
		}
	}
	return runtime.GOOS == "windows"
}
func withdrawalAncestors(base, dir string, create bool) error {
	base, dir = filepath.Clean(base), filepath.Clean(dir)
	if !filepath.IsAbs(base) || !filepath.IsAbs(dir) {
		return errors.New("Withdrawal retention requires an absolute runtime root")
	}
	relative, e := filepath.Rel(base, dir)
	if e != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("Withdrawal directory escaped the runtime")
	}
	current := base
	for _, part := range append([]string{""}, strings.Split(relative, string(filepath.Separator))...) {
		if part != "" && part != "." {
			current = filepath.Join(current, part)
		}
		info, e := os.Lstat(current)
		if os.IsNotExist(e) && create {
			e = os.Mkdir(current, 0700)
			if e == nil {
				info, e = os.Lstat(current)
			}
		}
		if os.IsNotExist(e) && !create {
			return nil
		}
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0 {
			return errors.New("Withdrawal retention directory is not independently protected")
		}
	}
	return nil
}

// Unlike older vault writes, this path requires successful file AND directory
// synchronization and encrypted readback before returning stop authority.
func (s *server) retainWithdrawal(file string, v withdrawalRecord) error {
	if runtime.GOOS != "linux" {
		return errors.New("Durable runtime withdrawal requires Linux filesystem synchronization")
	}
	if e := withdrawalAncestors(s.data, filepath.Dir(file), true); e != nil {
		return e
	}
	if info, e := os.Lstat(file); e == nil && !withdrawalOrdinary(info) || e != nil && !os.IsNotExist(e) {
		return errors.New("Withdrawal retention file is ambiguous")
	}
	key, e := vaultKey()
	if e != nil {
		return e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	plain, e := json.Marshal(v)
	if e != nil {
		return e
	}
	sealed := a.Seal(nonce, nonce, plain, []byte(filepath.Base(file)))
	tmp, e := os.CreateTemp(filepath.Dir(file), ".withdrawal-")
	if e != nil {
		return e
	}
	temporary := tmp.Name()
	defer os.Remove(temporary)
	if e = tmp.Chmod(0600); e == nil {
		_, e = tmp.Write(sealed)
	}
	if e == nil {
		e = tmp.Sync()
	}
	closeError := tmp.Close()
	if e == nil {
		e = closeError
	}
	if e != nil {
		return errors.New("Withdrawal intent could not be synchronized")
	}
	if e = os.Rename(temporary, file); e != nil {
		return e
	}
	// Synchronize each containing directory up to the runtime root, including
	// newly-created app directories, so a reboot cannot lose their names.
	for dir := filepath.Dir(file); ; dir = filepath.Dir(dir) {
		handle, e := os.Open(dir)
		if e != nil {
			return e
		}
		e = handle.Sync()
		_ = handle.Close()
		if e != nil {
			return errors.New("Withdrawal directory could not be synchronized")
		}
		if dir == filepath.Clean(s.data) {
			break
		}
	}
	var actual withdrawalRecord
	if e = s.readWithdrawal(file, &actual); e != nil || !reflect.DeepEqual(actual, v) {
		return errors.New("Withdrawal intent readback was not exact")
	}
	return nil
}
func (s *server) readWithdrawal(file string, v *withdrawalRecord) error {
	if e := withdrawalAncestors(s.data, filepath.Dir(file), false); e != nil {
		return e
	}
	info, e := os.Lstat(file)
	if e != nil {
		return e
	}
	if !withdrawalOrdinary(info) {
		return errors.New("Withdrawal record is not ordinary bounded private storage")
	}
	if e = readEncrypted(file, v); e != nil {
		return errors.New("Withdrawal encrypted record is unavailable")
	}
	at, e := time.Parse(time.RFC3339Nano, v.RetainedAt)
	if e != nil || v.Version != 1 || validateWithdrawal(v.Input, at) != nil || v.Status != "pending" && v.Status != "revoked" || v.Stopped == nil || len(v.Stopped) > len(v.Input.Change.Snapshot.Targets) {
		return errors.New("Withdrawal retained evidence is invalid")
	}
	seen := map[string]bool{}
	for _, id := range v.Stopped {
		found := false
		for _, t := range v.Input.Change.Snapshot.Targets {
			found = found || id == t.ContainerID
		}
		if !found || seen[id] {
			return errors.New("Withdrawal partial stop evidence is ambiguous")
		}
		seen[id] = true
	}
	return nil
}
func withdrawalProfile(raw string) (string, error) {
	var all map[string]json.RawMessage
	if len(raw) > 2<<20 || json.Unmarshal([]byte(raw), &all) != nil {
		return "", errors.New("Withdrawal profile unavailable")
	}
	p := map[string]any{}
	for _, key := range []string{"Id", "Name", "Image", "Config", "HostConfig", "Mounts"} {
		v, ok := all[key]
		if !ok || bytes.Equal(v, []byte("null")) {
			return "", errors.New("Withdrawal profile lacks required provenance")
		}
		var item any
		if json.Unmarshal(v, &item) != nil {
			return "", errors.New("Withdrawal profile malformed")
		}
		p[key] = item
	}
	return accessHash(p), nil
}

// The all-container inventory also discovers a retained ID whose labels drifted.
// An old removed candidate is excluded only after independent complete absence.
func (s *server) withdrawalInventory(ctx context.Context, appID, connectionID string) ([]withdrawalTarget, error) {
	out, e := s.runner(ctx, "docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}")
	ids := strings.Fields(out)
	if e != nil || len(out) > 512*65 || len(ids) > 512 {
		return nil, errors.New("Complete bounded immutable container inventory unavailable")
	}
	present := map[string]bool{}
	raws := map[string]string{}
	for _, id := range ids {
		if !exactDockerID.MatchString(id) || present[id] {
			return nil, errors.New("All-container inventory is ambiguous")
		}
		present[id] = true
		raw, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", id)
		var c filesystemRevocationContainer
		if e != nil || len(raw) > 2<<20 || json.Unmarshal([]byte(raw), &c) != nil || c.ID != id {
			return nil, errors.New("Independent all-container discovery unavailable")
		}
		if c.Config.Labels["io.autosoft.connector.app"] == appID && c.Config.Labels["io.autosoft.connector.id"] == connectionID {
			raws[id] = raw
		}
	}
	root := filepath.Join(s.data, "connectors", "filesystem-live")
	dirs, e := os.ReadDir(root)
	if e != nil && !os.IsNotExist(e) || len(dirs) > 512 {
		return nil, errors.New("Original filesystem live inventory unavailable")
	}
	for _, dir := range dirs {
		if !dir.IsDir() || dir.Type()&os.ModeSymlink != 0 || !identity.MatchString(dir.Name()) {
			return nil, errors.New("Original candidate receipt directory is ambiguous")
		}
		file := filepath.Join(root, dir.Name(), connectionID+".json")
		info, e := os.Lstat(file)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 2<<20 {
			return nil, errors.New("Original receipt is unavailable")
		}
		var receipt filesystemLiveReceipt
		if readBoundedJSON(file, &receipt) != nil {
			return nil, errors.New("Original receipt cannot be verified")
		}
		if receipt.AppID != appID {
			continue
		}
		if receipt.ConnectionID != connectionID || receipt.ResourceID != dir.Name() || !exactDockerID.MatchString(receipt.ContainerID) {
			return nil, errors.New("Original receipt identity is ambiguous")
		}
		if present[receipt.ContainerID] {
			raw, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", receipt.ContainerID)
			if e != nil {
				return nil, errors.New("Original immutable sidecar readback unavailable")
			}
			raws[receipt.ContainerID] = raw
		}
	}
	targets := []withdrawalTarget{}
	for id, raw := range raws {
		c, expected, e := s.filesystemRevocationProvenance(ctx, id, []byte(raw))
		if e != nil || expected.AppID != appID || expected.ConnectionID != connectionID {
			return nil, errors.New("Original filesystem sidecar provenance is unavailable; no stop is authorized")
		}
		profile, e := withdrawalProfile(raw)
		if e != nil {
			return nil, e
		}
		targets = append(targets, withdrawalTarget{id, c.Config.Labels["io.autosoft.connector.resource"], profile})
	}
	if len(targets) > 256 {
		return nil, errors.New("Withdrawal target count exceeded bound")
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ContainerID < targets[j].ContainerID })
	return targets, nil
}
func (s *server) withdrawalSnapshot(ctx context.Context, appID, connectionID string) (withdrawalSnapshot, error) {
	v := withdrawalSnapshot{Version: 1, Type: "filesystem", AppID: appID, ConnectionID: connectionID, Targets: []withdrawalTarget{}}
	if !identity.MatchString(appID) || !identity.MatchString(connectionID) {
		return v, errors.New("Invalid withdrawal scope")
	}
	var state filesystemConnectorState
	if readEncrypted(s.filesystemStatePath(appID, connectionID), &state) != nil || state.Input.Scope.AppID != appID || state.Input.Scope.ConnectionID != connectionID || validateFilesystemRetirementState(state) != nil {
		return v, errors.New("Original approved filesystem scope unavailable")
	}
	targets, e := s.withdrawalInventory(ctx, appID, connectionID)
	if e != nil {
		return v, e
	}
	v.ScopeHash, v.GrantApprovalID, v.Targets, v.ObservedAt = state.ScopeHash, state.Input.ApprovalID, targets, time.Now().UTC().Format(time.RFC3339Nano)
	v.Hash = withdrawalSnapshotHash(v)
	return v, nil
}
func (s *server) registerConnectionRevocationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/connectors/revocation/snapshot", s.authenticated(s.reviewWithdrawal))
	mux.HandleFunc("/v1/connectors/revoke", s.authenticated(s.revokeConnection))
	mux.HandleFunc("/v1/connectors/revocation/status", s.authenticated(s.withdrawalOperation))
}
func strictWithdrawalBody(w http.ResponseWriter, r *http.Request, value any) ([]byte, error) {
	if r.Method != "POST" {
		return nil, errors.New("POST required")
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("Invalid bounded withdrawal request")
	}
	return body, nil
}
func (s *server) reviewWithdrawal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AppID        string `json:"appId"`
		ConnectionID string `json:"connectionId"`
	}
	if _, e := strictWithdrawalBody(w, r, &in); e != nil {
		fail(w, 400, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if !identity.MatchString(in.AppID) || !identity.MatchString(in.ConnectionID) {
		fail(w, 400, errors.New("Invalid withdrawal scope"))
		return
	}
	lock, _ := s.locks.LoadOrStore("app-"+in.AppID, &sync.Mutex{})
	if !lock.(*sync.Mutex).TryLock() {
		fail(w, 409, errors.New("Application operation busy"))
		return
	}
	defer lock.(*sync.Mutex).Unlock()
	if e := s.connectionWithdrawalBlocked(in.AppID, in.ConnectionID); e != nil {
		fail(w, 409, e)
		return
	}
	v, e := s.withdrawalSnapshot(ctx, in.AppID, in.ConnectionID)
	if e != nil {
		fail(w, 409, e)
		return
	}
	respond(w, v)
}
func (s *server) revokeConnection(w http.ResponseWriter, r *http.Request) {
	var in withdrawalRequest
	body, e := strictWithdrawalBody(w, r, &in)
	if e != nil || !signedBody(s.approvalKey, body, r.Header.Get("X-Autosoft-Proof")) {
		rejectDeployment(w, 400, errors.New("Signed exact withdrawal body required"))
		return
	}
	if !identity.MatchString(in.Change.Snapshot.AppID) || !identity.MatchString(in.Change.Snapshot.ConnectionID) || !identity.MatchString(in.OperationID) || !identity.MatchString(in.ApprovalID) {
		rejectDeployment(w, 400, errors.New("Invalid withdrawal identity"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 110*time.Second)
	defer cancel()
	lock, _ := s.locks.LoadOrStore("app-"+in.Change.Snapshot.AppID, &sync.Mutex{})
	if !lock.(*sync.Mutex).TryLock() {
		fail(w, 409, errors.New("Application operation busy; retained withdrawal status must be inspected"))
		return
	}
	defer lock.(*sync.Mutex).Unlock()
	v, e, started := s.applyWithdrawal(ctx, in, s.retainWithdrawal)
	if e != nil {
		if !started {
			rejectDeployment(w, 409, e)
		} else {
			fail(w, 409, errors.New("Withdrawal intent may be retained; inspect its exact operation without dispatching again"))
		}
		return
	}
	respond(w, withdrawalStatusValue(v))
}
func (s *server) applyWithdrawal(ctx context.Context, in withdrawalRequest, retain func(string, withdrawalRecord) error) (withdrawalRecord, error, bool) {
	file := s.withdrawalPath(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID)
	var v withdrawalRecord
	if info, e := os.Lstat(file); e == nil {
		if !withdrawalOrdinary(info) || s.readWithdrawal(file, &v) != nil || !reflect.DeepEqual(v.Input, in) {
			return v, errors.New("Retained withdrawal cannot be replaced or regranted"), true
		}
		return v, nil, true
	} else if !os.IsNotExist(e) {
		return v, errors.New("Withdrawal retention unavailable"), true
	}
	if e := s.connectionWithdrawalBlocked(in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID); e != nil {
		return v, e, false
	}
	if e := validateWithdrawal(in, time.Now()); e != nil {
		return v, e, false
	}
	fresh, e := s.withdrawalSnapshot(ctx, in.Change.Snapshot.AppID, in.Change.Snapshot.ConnectionID)
	if e != nil || fresh.Hash != in.Change.Snapshot.Hash {
		return v, errors.New("Exact complete withdrawal inventory changed; prepare a fresh owner review"), false
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	v = withdrawalRecord{1, in, "pending", []string{}, at, at}
	if e = retain(file, v); e != nil {
		return v, errors.New("Withdrawal intent durability or readback is unavailable; no stop attempted"), true
	}
	return s.reconcileWithdrawal(ctx, v, retain, true)
}

// allowStop is true only for the signed first dispatch or bounded boot/timer
// replay of its durable intent. The status endpoint never stops containers;
// it persists independently observed current readback evidence.
func (s *server) reconcileWithdrawal(ctx context.Context, v withdrawalRecord, retain func(string, withdrawalRecord) error, allowStop bool) (withdrawalRecord, error, bool) {
	q := v.Input.Change.Snapshot
	v.Status = "pending"
	finish := func() (withdrawalRecord, error, bool) {
		v.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if e := retain(s.withdrawalPath(q.AppID, q.ConnectionID), v); e != nil {
			return v, e, true
		}
		return v, nil, true
	}
	if allowStop {
		if e := retain(s.withdrawalPath(q.AppID, q.ConnectionID), v); e != nil {
			return v, e, true
		}
	}
	targets, e := s.withdrawalInventory(ctx, q.AppID, q.ConnectionID)
	if e != nil {
		return finish()
	}
	if !reflect.DeepEqual(targets, q.Targets) {
		return finish()
	}
	stopped := []string{}
	for _, target := range q.Targets {
		if ctx.Err() != nil {
			break
		}
		raw, e := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", target.ContainerID)
		c, expected, proofError := s.filesystemRevocationProvenance(ctx, target.ContainerID, []byte(raw))
		profile, he := withdrawalProfile(raw)
		if e != nil || proofError != nil || he != nil || profile != target.ProfileHash || expected.AppID != q.AppID || expected.ConnectionID != q.ConnectionID || c.Config.Labels["io.autosoft.connector.resource"] != target.ResourceID {
			break
		}
		if c.State.Running && c.State.Status == "running" && allowStop && !c.State.Paused && !c.State.Restarting {
			_, _ = s.runner(ctx, "docker", "stop", "--time", "10", target.ContainerID)
			raw, e = s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", target.ContainerID)
			c, expected, proofError = s.filesystemRevocationProvenance(ctx, target.ContainerID, []byte(raw))
			profile, he = withdrawalProfile(raw)
		}
		if e != nil || proofError != nil || he != nil || profile != target.ProfileHash || expected.AppID != q.AppID || expected.ConnectionID != q.ConnectionID || expected.ResourceID != target.ResourceID || c.State.Running || c.State.Paused || c.State.Restarting || c.State.Status != "exited" && c.State.Status != "created" {
			break
		}
		stopped = append(stopped, target.ContainerID)
		seen := false
		for _, id := range v.Stopped {
			seen = seen || id == target.ContainerID
		}
		if !seen {
			v.Stopped = append(v.Stopped, target.ContainerID)
			sort.Strings(v.Stopped)
		}
		v.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if e = retain(s.withdrawalPath(q.AppID, q.ConnectionID), v); e != nil {
			return v, e, true
		}
	}
	if len(stopped) == len(q.Targets) {
		last, e := s.withdrawalInventory(ctx, q.AppID, q.ConnectionID)
		if e == nil && reflect.DeepEqual(last, q.Targets) {
			allStopped := true
			for _, target := range q.Targets {
				raw, ie := s.runner(ctx, "docker", "inspect", "--format", "{{json .}}", target.ContainerID)
				c, expected, pe := s.filesystemRevocationProvenance(ctx, target.ContainerID, []byte(raw))
				profile, he := withdrawalProfile(raw)
				if ie != nil || pe != nil || he != nil || profile != target.ProfileHash || expected.AppID != q.AppID || expected.ConnectionID != q.ConnectionID || expected.ResourceID != target.ResourceID || c.State.Running || c.State.Paused || c.State.Restarting || c.State.Status != "exited" && c.State.Status != "created" {
					allStopped = false
					break
				}
			}
			if allStopped {
				v.Status = "revoked"
			}
		}
	}
	return finish()
}
func (s *server) withdrawalOperation(w http.ResponseWriter, r *http.Request) {
	var in withdrawalIdentity
	if _, e := strictWithdrawalBody(w, r, &in); e != nil {
		fail(w, 400, e)
		return
	}
	if !identity.MatchString(in.AppID) || !identity.MatchString(in.ConnectionID) || !identity.MatchString(in.OperationID) || !identity.MatchString(in.ApprovalID) || !accessHex.MatchString(in.Hash) {
		fail(w, 400, errors.New("Invalid withdrawal identity"))
		return
	}
	lock, _ := s.locks.LoadOrStore("app-"+in.AppID, &sync.Mutex{})
	if !lock.(*sync.Mutex).TryLock() {
		fail(w, 409, errors.New("Withdrawal is busy"))
		return
	}
	defer lock.(*sync.Mutex).Unlock()
	file := s.withdrawalPath(in.AppID, in.ConnectionID)
	var v withdrawalRecord
	e := s.readWithdrawal(file, &v)
	if os.IsNotExist(e) {
		if guard := s.connectionWithdrawalBlocked(in.AppID, in.ConnectionID); guard != nil {
			fail(w, 409, guard)
			return
		}
		respond(w, withdrawalStatus{1, "filesystem", in, "unknown", false, strings.Repeat("0", 64), []string{}, time.Now().UTC().Format(time.RFC3339Nano)})
		return
	}
	if e != nil || withdrawalID(v.Input) != in {
		fail(w, 409, errors.New("Exact retained withdrawal evidence unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	actual, err, _ := s.reconcileWithdrawal(ctx, v, s.retainWithdrawal, false)
	if err != nil {
		fail(w, 409, errors.New("Withdrawal readback retention unavailable"))
		return
	}
	respond(w, withdrawalStatusValue(actual))
}
func (s *server) startConnectionWithdrawals(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			s.reconcileConnectionWithdrawals(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}
func (s *server) reconcileConnectionWithdrawals(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	root := filepath.Join(s.data, "connectors", "revoked")
	dirs, e := os.ReadDir(root)
	if e != nil || len(dirs) > 256 {
		return
	}
	count := 0
	for _, dir := range dirs {
		if ctx.Err() != nil {
			return
		}
		if !dir.IsDir() || dir.Type()&os.ModeSymlink != 0 || !identity.MatchString(dir.Name()) {
			continue
		}
		files, e := os.ReadDir(filepath.Join(root, dir.Name()))
		if e != nil {
			continue
		}
		for _, file := range files {
			count++
			if count > 512 || ctx.Err() != nil {
				return
			}
			id := strings.TrimSuffix(file.Name(), ".enc")
			if !identity.MatchString(id) || file.Name() != id+".enc" {
				continue
			}
			lock, _ := s.locks.LoadOrStore("app-"+dir.Name(), &sync.Mutex{})
			if !lock.(*sync.Mutex).TryLock() {
				continue
			}
			var v withdrawalRecord
			if s.readWithdrawal(s.withdrawalPath(dir.Name(), id), &v) == nil && v.Input.Change.Snapshot.AppID == dir.Name() && v.Input.Change.Snapshot.ConnectionID == id {
				_, _, _ = s.reconcileWithdrawal(ctx, v, s.retainWithdrawal, true)
			}
			lock.(*sync.Mutex).Unlock()
		}
	}
}
