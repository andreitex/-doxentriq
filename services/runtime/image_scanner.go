package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const imageScannerSeconds = 300
const imageScannerOutputLimit = 32 << 20
const imageScannerErrorLimit = 256 << 10

var imageScannerUnavailable = errors.New("Packaged image scan or independently confirmed scanner cleanup is unavailable; publication is blocked")

var imageScannerSerial = make(chan struct{}, 1)

type imageScannerCommandResult struct {
	Stdout, Stderr []byte
	ExitCode       int
	Overflow       bool
	Reaped         bool
}
type imageScannerDocker func(context.Context, []string, int64) (imageScannerCommandResult, error)

// The scanner has its own executor. The existing Docker/Git runner is unchanged.
// Every command selects the local socket and a fresh empty protected config.
func imageScannerCommand(ctx context.Context, args []string, maximum int64) (imageScannerCommandResult, error) {
	result := imageScannerCommandResult{ExitCode: -1}
	if maximum < 1 || maximum > imageScannerOutputLimit || len(args) < 5 || args[0] != "--host" || args[1] != "unix:///var/run/docker.sock" || args[2] != "--config" || !filepath.IsAbs(args[3]) {
		return result, imageScannerUnavailable
	}
	return runImageScannerProcess(ctx, "/usr/local/bin/docker", args, maximum, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"})
}

// The production caller supplies only the fixed Docker binary above. Keeping
// capture separate permits real credential-free child-process boundary tests.
func runImageScannerProcess(ctx context.Context, binary string, args []string, maximum int64, environment []string) (imageScannerCommandResult, error) {
	result := imageScannerCommandResult{ExitCode: -1}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &imageScannerBuffer{maximum: maximum, cancel: cancel}
	stderr := &imageScannerBuffer{maximum: imageScannerErrorLimit, cancel: cancel}
	command := exec.CommandContext(child, binary, args...)
	command.Env = environment
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = 5 * time.Second
	err := command.Run()
	result.Stdout, result.Stderr = stdout.data, stderr.data
	result.Overflow = stdout.overflow || stderr.overflow
	result.Reaped = command.ProcessState != nil
	if result.Reaped {
		result.ExitCode = command.ProcessState.ExitCode()
	}
	if err != nil || result.Overflow || !result.Reaped || ctx.Err() != nil {
		return result, imageScannerUnavailable
	}
	return result, nil
}

type imageScannerBuffer struct {
	mu       sync.Mutex
	data     []byte
	maximum  int64
	overflow bool
	cancel   context.CancelFunc
}

func (b *imageScannerBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if int64(len(p)) > b.maximum-int64(len(b.data)) {
		b.overflow = true
		b.cancel()
		return 0, imageScannerUnavailable
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

type imageScannerRecord struct {
	Version          int    `json:"schemaVersion"`
	OperationID      string `json:"operationId"`
	Image, Scanner   string
	NetworkID        string
	Status           string
	ContainerID      string
	ProfileHash      string
	RawPrestartHash  string
	FeedHash         string
	CleanupConfirmed bool
	CheckedAt        string
}

const imageScannerFeedLimit = 512 << 20
const imageScannerOSFeedLimit = 2 << 30

// Limits are selected only for the four admitted feed members. Size admission
// does not establish database validity or sufficient scanner memory.
func imageScannerFeedFileLimit(relative string, size int64) (int64, error) {
	var limit int64
	switch relative {
	case "trivy/db/trivy.db":
		limit = imageScannerOSFeedLimit
	case "trivy/java-db/trivy-java.db":
		limit = imageScannerFeedLimit
	case "trivy/db/metadata.json", "trivy/java-db/metadata.json":
		limit = 65536
	default:
		return 0, imageScannerUnavailable
	}
	if size < 1 || size > limit {
		return 0, imageScannerUnavailable
	}
	return limit, nil
}

type imageScannerFeedEvidence struct {
	UpdatedAt string
	Files     map[string]string
	Sizes     map[string]int64
}

// This fixed sibling mapping matches the company broker's runtime/cache mounts.
// A custom cache alias is unavailable rather than assumed to map to host data.
func imageScannerFeed(ctx context.Context, runtimeRoot, localCache string) (imageScannerFeedEvidence, error) {
	evidence := imageScannerFeedEvidence{Files: map[string]string{}, Sizes: map[string]int64{}}
	base := filepath.Dir(runtimeRoot)
	if !filepath.IsAbs(runtimeRoot) || filepath.Clean(runtimeRoot) != runtimeRoot || localCache != filepath.Join(base, "security-cache") || withdrawalAncestors(base, filepath.Join(localCache, "trivy", "db"), false) != nil {
		return evidence, imageScannerUnavailable
	}
	var metadata []byte
	for _, relative := range []string{"trivy/db/metadata.json", "trivy/db/trivy.db", "trivy/java-db/metadata.json", "trivy/java-db/trivy-java.db"} {
		path := filepath.Join(localCache, filepath.FromSlash(relative))
		if withdrawalAncestors(base, filepath.Dir(path), false) != nil || ctx.Err() != nil {
			return evidence, imageScannerUnavailable
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) && strings.HasPrefix(relative, "trivy/java-db/") {
			evidence.Files[relative], evidence.Sizes[relative] = "absent", 0
			continue
		}
		if err != nil || !imageScannerFeedOrdinary(info) {
			return evidence, imageScannerUnavailable
		}
		limit, err := imageScannerFeedFileLimit(relative, info.Size())
		if err != nil {
			return evidence, imageScannerUnavailable
		}
		f, err := os.Open(path)
		if err != nil {
			return evidence, imageScannerUnavailable
		}
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) {
			_ = f.Close()
			return evidence, imageScannerUnavailable
		}
		hash := sha256.New()
		var small bytes.Buffer
		buffer := make([]byte, 65536)
		total := int64(0)
		for {
			if ctx.Err() != nil {
				err = imageScannerUnavailable
				break
			}
			n, readErr := f.Read(buffer)
			total += int64(n)
			if total > limit {
				err = imageScannerUnavailable
				break
			}
			_, _ = hash.Write(buffer[:n])
			if relative == "trivy/db/metadata.json" {
				_, _ = small.Write(buffer[:n])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				err = imageScannerUnavailable
				break
			}
		}
		closed := f.Close()
		after, statErr := os.Lstat(path)
		if err != nil || closed != nil || statErr != nil || !imageScannerFeedOrdinary(after) || !os.SameFile(info, after) || total != info.Size() || after.Size() != info.Size() || after.ModTime() != info.ModTime() || withdrawalAncestors(base, filepath.Dir(path), false) != nil {
			return evidence, imageScannerUnavailable
		}
		evidence.Files[relative], evidence.Sizes[relative] = hex.EncodeToString(hash.Sum(nil)), total
		if relative == "trivy/db/metadata.json" {
			metadata = small.Bytes()
		}
	}
	if (evidence.Files["trivy/java-db/metadata.json"] == "absent") != (evidence.Files["trivy/java-db/trivy-java.db"] == "absent") {
		return evidence, imageScannerUnavailable
	}
	m, err := imageScannerJSON(metadata)
	if err != nil || !scannerNumber(m["Version"], 2) {
		return evidence, imageScannerUnavailable
	}
	updated, err := time.Parse(time.RFC3339Nano, scannerString(m["UpdatedAt"]))
	next, nextErr := time.Parse(time.RFC3339Nano, scannerString(m["NextUpdate"]))
	now := time.Now()
	if err != nil || nextErr != nil || updated.IsZero() || now.Sub(updated) > 24*time.Hour || updated.After(now.Add(time.Minute)) || !next.After(updated) {
		return evidence, imageScannerUnavailable
	}
	evidence.UpdatedAt = updated.UTC().Format(time.RFC3339Nano)
	return evidence, nil
}

func imageScannerFeedOrdinary(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		return true // Linux link/mode qualification remains a separate native test.
	}
	sys := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if sys.IsValid() && sys.Kind() == reflect.Struct {
		n := sys.FieldByName("Nlink")
		return n.IsValid() && n.Uint() == 1
	}
	return false
}

type imageScannerDependencies struct {
	docker imageScannerDocker
	retain func(string, any) error
}
type imageScannerExecution struct {
	d           imageScannerDependencies
	r           imageScannerRecord
	dir, config string
	sequence    int
	lastRawHash string
	inputGuard  func() error
	spec        imageScannerSpec
}
type imageScannerSpec struct {
	name, image, runtime, network, cache, ca, envFile string
	command, environment, hosts                       []string
	imageConfig                                       map[string]any
	descriptor                                        map[string]any
}

type imageScannerActive struct {
	Version     int    `json:"schemaVersion"`
	OperationID string `json:"operationId"`
	Status      string `json:"status"`
	RecordHash  string `json:"recordHash"`
}

type imageScannerLease struct {
	root, directory, lock string
	lockInfo              os.FileInfo
	retain                func(string, any) error
}

func readImageScannerPrivate(file string, value any) error {
	info, err := os.Lstat(file)
	if err != nil || !withdrawalOrdinary(info) {
		return imageScannerUnavailable
	}
	var raw json.RawMessage
	if readEncrypted(file, &raw) != nil {
		return imageScannerUnavailable
	}
	if _, err = imageScannerJSON(raw); err != nil {
		return imageScannerUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return imageScannerUnavailable
	}
	return nil
}

// A clear marker is reusable only with its exact durably retained cleanup
// result. Active, malformed and unavailable records never become absence.
func imageScannerPriorClear(root string) error {
	directory := filepath.Join(root, "security", "runtime-image-scans")
	if withdrawalAncestors(root, directory, false) != nil {
		return imageScannerUnavailable
	}
	file := filepath.Join(directory, "active.enc")
	_, err := os.Lstat(file)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return imageScannerUnavailable
	}
	var active imageScannerActive
	if readImageScannerPrivate(file, &active) != nil || active.Version != 1 || active.Status != "clear" || len(active.OperationID) != 32 || !exactDockerID.MatchString(active.OperationID+active.OperationID) || !exactDockerID.MatchString(active.RecordHash) {
		return imageScannerUnavailable
	}
	var record imageScannerRecord
	file = filepath.Join(directory, active.OperationID, "state.enc")
	if withdrawalAncestors(root, filepath.Dir(file), false) != nil || readImageScannerPrivate(file, &record) != nil || record.Version != 1 || record.OperationID != active.OperationID || !record.CleanupConfirmed || !exactDockerID.MatchString(record.ContainerID) || !exactDockerID.MatchString(record.NetworkID) || !exactDockerID.MatchString(record.FeedHash) || !exactDockerID.MatchString(record.ProfileHash) || !exactDockerID.MatchString(record.RawPrestartHash) || !digestImage.MatchString(record.Image) || !digestImage.MatchString(record.Scanner) || (record.Status != "completed" && record.Status != "unavailable") || accessHash(record) != active.RecordHash {
		return imageScannerUnavailable
	}
	return nil
}

func claimImageScanner(root string, record imageScannerRecord, retain func(string, any) error) (*imageScannerLease, error) {
	if imageScannerPriorClear(root) != nil {
		return nil, imageScannerUnavailable
	}
	directory := filepath.Join(root, "security", "runtime-image-scans")
	if withdrawalAncestors(root, directory, true) != nil {
		return nil, imageScannerUnavailable
	}
	lock := filepath.Join(directory, "scanner.lock")
	// Atomic creation serializes other broker processes too. A crashed lease
	// remains a blocker; there is no stale-age deletion or restart recovery.
	if os.Mkdir(lock, 0700) != nil {
		return nil, imageScannerUnavailable
	}
	info, err := os.Lstat(lock)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, imageScannerUnavailable
	}
	lease := &imageScannerLease{root: root, directory: directory, lock: lock, lockInfo: info, retain: retain}
	if retain(filepath.Join(directory, "active.enc"), imageScannerActive{Version: 1, OperationID: record.OperationID, Status: "active", RecordHash: accessHash(record)}) != nil {
		return nil, imageScannerUnavailable
	}
	return lease, nil
}

func (l *imageScannerLease) release(record imageScannerRecord) error {
	if !record.CleanupConfirmed || !exactDockerID.MatchString(record.ContainerID) || !exactDockerID.MatchString(record.ProfileHash) {
		return imageScannerUnavailable
	}
	if l.retain(filepath.Join(l.directory, "active.enc"), imageScannerActive{Version: 1, OperationID: record.OperationID, Status: "clear", RecordHash: accessHash(record)}) != nil || imageScannerPriorClear(l.root) != nil {
		return imageScannerUnavailable
	}
	info, err := os.Lstat(l.lock)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(l.lockInfo, info) {
		return imageScannerUnavailable
	}
	entries, err := os.ReadDir(l.lock)
	if err != nil || len(entries) != 0 || os.Remove(l.lock) != nil {
		return imageScannerUnavailable
	}
	f, err := os.Open(l.directory)
	if err != nil {
		return imageScannerUnavailable
	}
	err = f.Sync()
	closed := f.Close()
	if err != nil || closed != nil {
		return imageScannerUnavailable
	}
	if _, err = os.Lstat(l.lock); !os.IsNotExist(err) {
		return imageScannerUnavailable
	}
	return nil
}

func imageScannerOrdinary(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > imageScannerOutputLimit*2+imageScannerErrorLimit+65536 {
		return false
	}
	sys := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if sys.IsValid() && sys.Kind() == reflect.Struct {
		n := sys.FieldByName("Nlink")
		return n.IsValid() && n.Uint() == 1
	}
	return false
}

// Linux file and containing-directory synchronization precede any daemon side
// effect. Raw output/credentials remain encrypted private journal data.
func retainImageScannerFile(root, file string, value any) error {
	if runtime.GOOS != "linux" || withdrawalAncestors(root, filepath.Dir(file), true) != nil {
		return imageScannerUnavailable
	}
	if info, err := os.Lstat(file); err == nil && !imageScannerOrdinary(info) || err != nil && !os.IsNotExist(err) {
		return imageScannerUnavailable
	}
	key, err := vaultKey()
	if err != nil {
		return imageScannerUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return imageScannerUnavailable
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return imageScannerUnavailable
	}
	plain, err := json.Marshal(value)
	if err != nil || len(plain) > imageScannerOutputLimit*2+imageScannerErrorLimit {
		return imageScannerUnavailable
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return imageScannerUnavailable
	}
	sealed := a.Seal(nonce, nonce, plain, []byte(filepath.Base(file)))
	f, err := os.CreateTemp(filepath.Dir(file), ".scanner-")
	if err != nil {
		return imageScannerUnavailable
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(sealed)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil || os.Rename(f.Name(), file) != nil {
		return imageScannerUnavailable
	}
	for dir := filepath.Dir(file); ; dir = filepath.Dir(dir) {
		h, err := os.Open(dir)
		if err != nil {
			return imageScannerUnavailable
		}
		err = h.Sync()
		_ = h.Close()
		if err != nil {
			return imageScannerUnavailable
		}
		if dir == filepath.Clean(root) {
			break
		}
	}
	info, err := os.Lstat(file)
	if err != nil || !imageScannerOrdinary(info) {
		return imageScannerUnavailable
	}
	raw, err := os.ReadFile(file)
	if err != nil || len(raw) < a.NonceSize() {
		return imageScannerUnavailable
	}
	actual, err := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], []byte(filepath.Base(file)))
	if err != nil || !bytes.Equal(actual, plain) {
		return imageScannerUnavailable
	}
	return nil
}

func (x *imageScannerExecution) retain() error {
	x.r.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return x.d.retain(filepath.Join(x.dir, "state.enc"), x.r)
}
func (x *imageScannerExecution) call(ctx context.Context, maximum int64, args ...string) (imageScannerCommandResult, error) {
	if x.sequence >= 24 {
		return imageScannerCommandResult{}, imageScannerUnavailable
	}
	if x.inputGuard != nil && x.inputGuard() != nil {
		return imageScannerCommandResult{}, imageScannerUnavailable
	}
	x.sequence++
	all := append([]string{"--host", "unix:///var/run/docker.sock", "--config", x.config}, args...)
	deadline := 20 * time.Second
	if len(args) > 1 && args[0] == "start" && args[1] == "--attach" {
		deadline = imageScannerSeconds * time.Second
	}
	child, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	result, err := x.d.docker(child, all, maximum)
	// Persist bounded outputs before interpreting a create ID or report.
	if int64(len(result.Stdout)) > maximum || len(result.Stderr) > imageScannerErrorLimit {
		result.Stdout, result.Stderr, result.Overflow = nil, nil, true
	}
	if x.d.retain(filepath.Join(x.dir, "command-"+strconv.Itoa(x.sequence)+".enc"), result) != nil || err != nil || result.Overflow || !result.Reaped || result.ExitCode != 0 || ctx.Err() != nil {
		return result, imageScannerUnavailable
	}
	return result, nil
}

// Duplicate object keys, numeric aliases and excessive nesting are rejected.
func imageScannerJSON(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > imageScannerOutputLimit || !utf8.Valid(raw) {
		return nil, imageScannerUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		nodes++
		if depth > 32 || nodes > 200000 {
			return nil, imageScannerUnavailable
		}
		t, err := d.Token()
		if err != nil {
			return nil, imageScannerUnavailable
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				m := map[string]any{}
				keys := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					k, ok := key.(string)
					if err != nil || !ok || len(m) >= 50000 {
						return nil, imageScannerUnavailable
					}
					if keys[strings.ToLower(k)] {
						return nil, imageScannerUnavailable
					}
					keys[strings.ToLower(k)] = true
					v, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					m[k] = v
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return nil, imageScannerUnavailable
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					if len(a) >= 50000 {
						return nil, imageScannerUnavailable
					}
					v, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					a = append(a, v)
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return nil, imageScannerUnavailable
				}
				return a, nil
			default:
				return nil, imageScannerUnavailable
			}
		}
		return t, nil
	}
	v, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, imageScannerUnavailable
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, imageScannerUnavailable
	}
	return m, nil
}
func scannerMap(v any) map[string]any       { m, _ := v.(map[string]any); return m }
func scannerString(v any) string            { s, _ := v.(string); return s }
func scannerBool(v any, expected bool) bool { b, ok := v.(bool); return ok && b == expected }
func scannerNumber(v any, expected int64) bool {
	n, ok := v.(json.Number)
	return ok && string(n) == strconv.FormatInt(expected, 10)
}
func scannerEmpty(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}
func scannerStrings(v any) ([]string, error) {
	a, ok := v.([]any)
	if v == nil {
		return []string{}, nil
	}
	if !ok {
		return nil, imageScannerUnavailable
	}
	r := []string{}
	for _, v := range a {
		s, ok := v.(string)
		if !ok || len(s) > 8192 || strings.ContainsAny(s, "\x00\r\n") {
			return nil, imageScannerUnavailable
		}
		r = append(r, s)
	}
	return r, nil
}
func scannerEnvironment(base any, supplied []string) (map[string]string, error) {
	b, err := scannerStrings(base)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, list := range [][]string{b, supplied} {
		seen := map[string]bool{}
		for _, entry := range list {
			key, value, ok := strings.Cut(entry, "=")
			if !ok || key == "" || strings.ContainsAny(entry, "\x00\r\n") || seen[key] {
				return nil, imageScannerUnavailable
			}
			seen[key] = true
			out[key] = value
		}
	}
	return out, nil
}

func (s imageScannerSpec) create() []string {
	args := []string{"create", "--name", s.name, "--hostname", s.name, "--label", "io.autosoft.runtime-image-scan=" + strings.TrimPrefix(s.name, "as-image-scan-"), "--runtime", s.runtime, "--network", s.network, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--workdir", "/", "--cpus", "1", "--memory", "3g", "--memory-swap", "3g", "--pids-limit", "128", "--restart", "no", "--log-driver", "none", "--no-healthcheck", "--stop-signal", "SIGTERM", "--tmpfs", "/tmp:size=128m,mode=1777", "--mount", "type=bind,src=" + s.cache + ",dst=/cache,readonly", "--mount", "type=bind,src=" + s.ca + ",dst=/etc/autosoft/ca.crt,readonly"}
	for _, host := range s.hosts {
		args = append(args, host)
	}
	args = append(args, "--env-file", s.envFile)
	return append(append(args, s.image), s.command...)
}

// The requested digest and independently inspected selected descriptor are
// separate identities. Only Docker's measured platform addition is derived.
func (x *imageScannerExecution) image(ctx context.Context) error {
	r, err := x.call(ctx, 4<<20, "image", "inspect", "--format", "{{json .}}", x.spec.image)
	if err != nil {
		return err
	}
	m, err := imageScannerJSON(r.Stdout)
	if err != nil {
		return err
	}
	c := scannerMap(m["Config"])
	d := scannerMap(m["Descriptor"])
	if c == nil || d == nil || scannerString(m["Os"]) != "linux" || scannerString(m["Architecture"]) != "amd64" || !exactDockerID.MatchString(strings.TrimPrefix(scannerString(m["Id"]), "sha256:")) || !strings.HasPrefix(scannerString(m["Id"]), "sha256:") || scannerString(d["digest"]) != scannerString(m["Id"]) || !scannerEmpty(c["Volumes"]) {
		return imageScannerUnavailable
	}
	root := scannerMap(m["RootFS"])
	layers, e := scannerStrings(root["Layers"])
	if e != nil || root["Type"] != "layers" || len(layers) == 0 || len(layers) > 128 {
		return imageScannerUnavailable
	}
	for _, layer := range layers {
		if !strings.HasPrefix(layer, "sha256:") || !exactDockerID.MatchString(strings.TrimPrefix(layer, "sha256:")) {
			return imageScannerUnavailable
		}
	}
	media := scannerString(d["mediaType"])
	if media != "application/vnd.oci.image.manifest.v1+json" && media != "application/vnd.docker.distribution.manifest.v2+json" {
		return imageScannerUnavailable
	}
	size, ok := d["size"].(json.Number)
	if !ok {
		return imageScannerUnavailable
	}
	n, e := strconv.ParseInt(string(size), 10, 64)
	if e != nil || n < 1 || n > 4<<20 || string(size) != strconv.FormatInt(n, 10) {
		return imageScannerUnavailable
	}
	platform := map[string]any{"architecture": "amd64", "os": "linux"}
	if p, present := d["platform"]; present && accessHash(p) != accessHash(platform) {
		return imageScannerUnavailable
	}
	d["platform"] = platform
	if _, err = scannerEnvironment(c["Env"], x.spec.environment); err != nil {
		return err
	}
	x.spec.imageConfig, x.spec.descriptor = c, d
	return nil
}

func (x *imageScannerExecution) inspect(ctx context.Context) (map[string]any, string, error) {
	if !exactDockerID.MatchString(x.r.ContainerID) {
		return nil, "", imageScannerUnavailable
	}
	r, e := x.call(ctx, 4<<20, "inspect", "--format", "{{json .}}", x.r.ContainerID)
	if e != nil {
		return nil, "", e
	}
	m, e := imageScannerJSON(r.Stdout)
	if e != nil {
		return nil, "", e
	}
	x.lastRawHash = hashBytes(r.Stdout)
	c, h, state := scannerMap(m["Config"]), scannerMap(m["HostConfig"]), scannerMap(m["State"])
	if c == nil || h == nil || state == nil || m["Id"] != x.r.ContainerID || m["Name"] != "/"+x.spec.name || m["Image"] != strings.Split(x.spec.image, "@")[1] || m["Platform"] != "linux" || accessHash(m["ImageManifestDescriptor"]) != accessHash(x.spec.descriptor) || c["Image"] != x.spec.image || c["User"] != "10001:10001" || c["WorkingDir"] != "/" || c["Hostname"] != x.spec.name || c["Domainname"] != "" || !scannerBool(c["Tty"], false) || !scannerBool(c["OpenStdin"], false) || !scannerBool(c["StdinOnce"], false) || !scannerBool(c["AttachStdin"], false) || accessHash(c["Cmd"]) != accessHash(x.spec.command) || accessHash(c["Entrypoint"]) != accessHash(x.spec.imageConfig["Entrypoint"]) || c["StopSignal"] != "SIGTERM" {
		return nil, "", imageScannerUnavailable
	}
	labels := scannerMap(c["Labels"])
	expected := map[string]any{}
	for k, v := range scannerMap(x.spec.imageConfig["Labels"]) {
		expected[k] = v
	}
	expected["io.autosoft.runtime-image-scan"] = x.r.OperationID
	base, e := scannerEnvironment(x.spec.imageConfig["Env"], x.spec.environment)
	actual, ae := scannerEnvironment(c["Env"], nil)
	if e != nil || ae != nil || !reflect.DeepEqual(base, actual) || accessHash(labels) != accessHash(expected) {
		return nil, "", imageScannerUnavailable
	}
	if accessHash(scannerMap(c["Healthcheck"])["Test"]) != accessHash([]string{"NONE"}) {
		return nil, "", imageScannerUnavailable
	}
	for _, key := range []string{"CapAdd", "PortBindings", "Devices", "DeviceRequests", "ExtraHosts", "OomKillDisable"} {
		if _, ok := h[key]; !ok {
			return nil, "", imageScannerUnavailable
		}
	}
	if h["Runtime"] != x.spec.runtime || h["NetworkMode"] != x.spec.network || !scannerBool(h["ReadonlyRootfs"], true) || !scannerBool(h["Privileged"], false) || !scannerBool(h["AutoRemove"], false) || !scannerNumber(h["NanoCpus"], 1000000000) || !scannerNumber(h["Memory"], 3<<30) || !scannerNumber(h["MemorySwap"], 3<<30) || !scannerNumber(h["PidsLimit"], 128) || !scannerEmpty(h["CapAdd"]) || accessHash(h["CapDrop"]) != accessHash([]string{"ALL"}) || !scannerEmpty(h["PortBindings"]) || !scannerEmpty(h["Devices"]) || !scannerEmpty(h["DeviceRequests"]) || h["PidMode"] != "" || h["UTSMode"] != "" || h["IpcMode"] != "private" || h["UsernsMode"] != "" || accessHash(h["Tmpfs"]) != accessHash(map[string]string{"/tmp": "size=128m,mode=1777"}) || scannerMap(h["LogConfig"])["Type"] != "none" || scannerMap(h["RestartPolicy"])["Name"] != "no" {
		return nil, "", imageScannerUnavailable
	}
	security, e := scannerStrings(h["SecurityOpt"])
	if e != nil || len(security) != 1 || (security[0] != "no-new-privileges" && security[0] != "no-new-privileges:true") {
		return nil, "", imageScannerUnavailable
	}
	hosts, e := scannerStrings(h["ExtraHosts"])
	expectedHosts := []string{}
	for i := 0; i < len(x.spec.hosts); i += 2 {
		if i+1 >= len(x.spec.hosts) || x.spec.hosts[i] != "--add-host" {
			return nil, "", imageScannerUnavailable
		}
		expectedHosts = append(expectedHosts, x.spec.hosts[i+1])
	}
	if e != nil || !reflect.DeepEqual(hosts, expectedHosts) {
		return nil, "", imageScannerUnavailable
	}
	mounts, ok := m["Mounts"].([]any)
	if !ok || len(mounts) != 2 {
		return nil, "", imageScannerUnavailable
	}
	seen := map[string]bool{}
	for _, v := range mounts {
		mount := scannerMap(v)
		dst := scannerString(mount["Destination"])
		source := ""
		if dst == "/cache" {
			source = x.spec.cache
		} else if dst == "/etc/autosoft/ca.crt" {
			source = x.spec.ca
		} else {
			return nil, "", imageScannerUnavailable
		}
		if seen[dst] || mount["Type"] != "bind" || mount["Source"] != source || !scannerBool(mount["RW"], false) {
			return nil, "", imageScannerUnavailable
		}
		seen[dst] = true
	}
	if !scannerBool(state["Paused"], false) || !scannerBool(state["Restarting"], false) || !scannerBool(state["Dead"], false) {
		return nil, "", imageScannerUnavailable
	}
	status := scannerString(state["Status"])
	if status != "created" && status != "running" && status != "exited" || !scannerBool(state["Running"], status == "running") {
		return nil, "", imageScannerUnavailable
	}
	networks := scannerMap(scannerMap(m["NetworkSettings"])["Networks"])
	if !imageScannerNetworkState(networks, state, x.spec.network) {
		return nil, "", imageScannerUnavailable
	}
	// Actual Docker29 lifecycle evidence permits only present null/false here.
	oom, present := h["OomKillDisable"]
	if !present || oom != nil && !scannerBool(oom, false) {
		return nil, "", imageScannerUnavailable
	}
	h["OomKillDisable"] = false
	profile := map[string]any{}
	for _, key := range []string{"Id", "Name", "Image", "Config", "HostConfig", "Mounts", "ImageManifestDescriptor", "Platform"} {
		v, present := m[key]
		if !present || v == nil {
			return nil, "", imageScannerUnavailable
		}
		profile[key] = v
	}
	profile["networkAuthority"] = map[string]string{"name": "autosoft_artifact", "id": x.spec.network}
	hash := accessHash(profile)
	if x.r.ProfileHash != "" && hash != x.r.ProfileHash {
		return nil, "", imageScannerUnavailable
	}
	return m, hash, nil
}

// Docker29 attaches the endpoint only at start. Before that, the exact immutable
// HostConfig.NetworkMode is already checked above, while this one named endpoint
// is empty. Never extend that allowance to a started or foreign network.
func imageScannerNetworkState(networks, state map[string]any, networkID string) bool {
	if len(networks) != 1 || !exactDockerID.MatchString(networkID) {
		return false
	}
	endpoint := scannerMap(networks["autosoft_artifact"])
	status := scannerString(state["Status"])
	if endpoint == nil || (status != "created" && status != "running" && status != "exited") || !scannerBool(state["Running"], status == "running") {
		return false
	}
	if endpoint["NetworkID"] == networkID {
		return true
	}
	if status != "created" || endpoint["NetworkID"] != "" || !scannerNumber(state["Pid"], 0) || state["StartedAt"] != "0001-01-01T00:00:00Z" {
		return false
	}
	for _, key := range []string{"EndpointID", "Gateway", "IPAddress", "MacAddress", "IPv6Gateway", "GlobalIPv6Address"} {
		value, ok := endpoint[key].(string)
		if !ok || value != "" {
			return false
		}
	}
	for _, key := range []string{"IPPrefixLen", "GlobalIPv6PrefixLen", "GwPriority"} {
		if !scannerNumber(endpoint[key], 0) {
			return false
		}
	}
	for _, key := range []string{"IPAMConfig", "Links", "Aliases", "DriverOpts", "DNSNames"} {
		value, present := endpoint[key]
		if !present || !scannerEmpty(value) {
			return false
		}
	}
	return true
}

func (x *imageScannerExecution) cleanup() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if x.r.ProfileHash == "" || x.retain() != nil {
		return false
	}
	m, _, err := x.inspect(ctx)
	if err != nil {
		return false
	}
	if scannerMap(m["State"])["Status"] == "running" {
		_, _ = x.call(ctx, 65536, "stop", "--time", "15", x.r.ContainerID)
	}
	m, _, err = x.inspect(ctx)
	if err != nil || scannerMap(m["State"])["Status"] == "running" {
		return false
	}
	_, _ = x.call(ctx, 65536, "rm", x.r.ContainerID)
	r, err := x.call(ctx, 1<<20, "ps", "--all", "--no-trunc", "--format", "{{.ID}}")
	if err != nil {
		return false
	}
	ids := strings.Split(strings.TrimSuffix(string(r.Stdout), "\n"), "\n")
	if len(ids) > 8192 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" && len(ids) == 1 {
			continue
		}
		if !exactDockerID.MatchString(id) || seen[id] || id == x.r.ContainerID {
			return false
		}
		seen[id] = true
	}
	x.r.CleanupConfirmed = true
	return x.retain() == nil
}

func (x *imageScannerExecution) execute(ctx context.Context) (out []byte, err error) {
	err = imageScannerUnavailable
	if len(x.spec.hosts)%2 != 0 {
		return nil, err
	}
	if x.retain() != nil || x.image(ctx) != nil {
		return nil, err
	}
	created, ce := x.call(ctx, 65536, x.spec.create()...)
	id := strings.TrimSuffix(string(created.Stdout), "\n")
	if !exactDockerID.MatchString(id) {
		x.r.Status = "unknown_create"
		_ = x.retain()
		return nil, err
	}
	x.r.ContainerID = id
	x.r.Status = "created"
	if x.retain() != nil {
		return nil, err
	}
	// A lost/cancelled create response may still return an exact ID. Its first
	// independent ownership inspection is detached, but it never authorizes start.
	proof, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	m, profile, ie := x.inspect(proof)
	cancel()
	if ie != nil {
		return nil, err
	}
	x.r.ProfileHash = profile
	x.r.RawPrestartHash = x.lastRawHash
	defer func() {
		if !x.cleanup() {
			out = nil
			err = imageScannerUnavailable
			x.r.Status = "cleanup_unconfirmed"
		} else if err != nil {
			x.r.Status = "unavailable"
		} else {
			x.r.Status = "completed"
		}
		if x.retain() != nil {
			out = nil
			err = imageScannerUnavailable
		}
	}()
	if ce != nil || scannerMap(m["State"])["Status"] != "created" || x.retain() != nil {
		return nil, err
	}
	x.r.Status = "start_intent"
	if x.retain() != nil {
		return nil, err
	}
	if _, _, ie = x.inspect(ctx); ie != nil {
		return nil, err
	}
	result, e := x.call(ctx, imageScannerOutputLimit, "start", "--attach", id)
	if e != nil {
		return nil, err
	}
	m, _, e = x.inspect(ctx)
	state := scannerMap(m["State"])
	if e != nil || state["Status"] != "exited" || !scannerNumber(state["ExitCode"], 0) || !scannerBool(state["OOMKilled"], false) {
		return nil, err
	}
	return result.Stdout, nil
}

func (s *server) scanImageSafely(ctx context.Context, image string) (findings []Finding, err error) {
	if !digestImage.MatchString(image) || !digestImage.MatchString(s.manifest.ScannerImage) || !filepath.IsAbs(s.data) || env("RUNSC_RUNTIME", "runsc") != "runsc" {
		return nil, imageScannerUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, imageScannerSeconds*time.Second)
	defer cancel()
	select {
	case imageScannerSerial <- struct{}{}:
		defer func() { <-imageScannerSerial }()
	case <-ctx.Done():
		return nil, imageScannerUnavailable
	}
	if imageScannerPriorClear(s.data) != nil {
		return nil, imageScannerUnavailable
	}
	credentialsPath := env("REGISTRY_CREDENTIALS_FILE", "/run/secrets/registry.json")
	info, e := os.Lstat(credentialsPath)
	if e != nil || !withdrawalOrdinary(info) || info.Size() > 65536 {
		return nil, imageScannerUnavailable
	}
	b, e := os.ReadFile(credentialsPath)
	if e != nil {
		return nil, imageScannerUnavailable
	}
	var credentials struct{ Username, Password string }
	if json.Unmarshal(b, &credentials) != nil || credentials.Username == "" || len(credentials.Username) > 256 || credentials.Password == "" || len(credentials.Password) > 4096 || strings.ContainsAny(credentials.Username+credentials.Password, "\x00\r\n") {
		return nil, imageScannerUnavailable
	}
	hostData := env("HOST_DATA_DIR", "")
	if !filepath.IsAbs(hostData) {
		return nil, imageScannerUnavailable
	}
	localCache := env("SECURITY_CACHE_DIR", filepath.Join(filepath.Dir(s.data), "security-cache"))
	if env("HOST_SECURITY_CACHE_DIR", filepath.Join(hostData, "security-cache")) != filepath.Join(hostData, "security-cache") {
		return nil, imageScannerUnavailable
	}
	feed, e := imageScannerFeed(ctx, s.data, localCache)
	if e != nil {
		return nil, imageScannerUnavailable
	}
	op := randomSecret()[:32]
	dir := filepath.Join(s.data, "security", "runtime-image-scans", op)
	docker := s.imageScannerDocker
	if docker == nil {
		docker = imageScannerCommand
	}
	x := imageScannerExecution{d: imageScannerDependencies{docker: docker, retain: func(path string, v any) error { return retainImageScannerFile(s.data, path, v) }}, r: imageScannerRecord{Version: 1, OperationID: op, Image: image, Scanner: s.manifest.ScannerImage, Status: "intent"}, dir: dir, config: filepath.Join(dir, "docker-config")}
	x.r.FeedHash = accessHash(feed)
	if x.retain() != nil || x.d.retain(filepath.Join(dir, "feed-before.enc"), feed) != nil {
		return nil, imageScannerUnavailable
	}
	lease, e := claimImageScanner(s.data, x.r, x.d.retain)
	if e != nil {
		return nil, imageScannerUnavailable
	}
	defer func() {
		if !x.r.CleanupConfirmed {
			return
		}
		if err != nil {
			x.r.Status = "unavailable"
		}
		if x.retain() != nil || lease.release(x.r) != nil {
			findings = nil
			err = imageScannerUnavailable
		}
	}()
	if withdrawalAncestors(s.data, x.config, true) != nil {
		return nil, imageScannerUnavailable
	}
	// The empty config contains no registry login. Scanner credentials stay in
	// the owned container's private environment and encrypted inspection seal.
	if e = os.WriteFile(filepath.Join(x.config, "config.json"), []byte("{}\n"), 0600); e != nil {
		return nil, imageScannerUnavailable
	}
	environment := []string{"SSL_CERT_FILE=/etc/autosoft/ca.crt", "TRIVY_USERNAME=" + credentials.Username, "TRIVY_PASSWORD=" + credentials.Password}
	envFile := filepath.Join(dir, "scanner.env")
	envBytes := []byte(strings.Join(environment, "\n") + "\n")
	if e = os.WriteFile(envFile, envBytes, 0600); e != nil {
		return nil, imageScannerUnavailable
	}
	x.inputGuard = func() error {
		for path, want := range map[string][]byte{envFile: envBytes, filepath.Join(x.config, "config.json"): []byte("{}\n")} {
			i, err := os.Lstat(path)
			if err != nil || !withdrawalOrdinary(i) || i.Size() != int64(len(want)) {
				return imageScannerUnavailable
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				return imageScannerUnavailable
			}
		}
		return nil
	}
	// Resolver reads use the same explicit local daemon/config/capture boundary,
	// rather than inheriting the global runner's ambient Docker environment.
	resolver := &server{manifest: s.manifest, runner: func(c context.Context, name string, args ...string) (string, error) {
		if name != "docker" {
			return "", imageScannerUnavailable
		}
		result, err := x.call(c, 4<<20, args...)
		return string(result.Stdout), err
	}}
	hosts, e := resolver.trustedServiceHosts(ctx, "autosoft_artifact", []string{"registry"})
	if e != nil {
		return nil, imageScannerUnavailable
	}
	r, e := x.call(ctx, 4<<20, "network", "inspect", "--format", "{{json .}}", "autosoft_artifact")
	if e != nil {
		return nil, imageScannerUnavailable
	}
	n, e := inspectServiceNetwork(string(r.Stdout), "autosoft_artifact")
	if e != nil {
		return nil, imageScannerUnavailable
	}
	x.r.NetworkID = n.ID
	x.spec = imageScannerSpec{name: "as-image-scan-" + op, image: s.manifest.ScannerImage, runtime: env("RUNSC_RUNTIME", "runsc"), network: n.ID, cache: filepath.Join(hostData, "security-cache"), ca: filepath.Join(hostData, "tls", "ca.crt"), hosts: hosts, envFile: envFile, environment: environment, command: []string{"image", "--cache-dir", "/cache/trivy", "--cache-backend", "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--list-all-pkgs", "--format", "json", image}}
	out, e := x.execute(ctx)
	if e != nil {
		return nil, imageScannerUnavailable
	}
	after, e := imageScannerFeed(ctx, s.data, localCache)
	if e != nil || accessHash(after) != accessHash(feed) || x.d.retain(filepath.Join(dir, "feed-after.enc"), after) != nil {
		return nil, imageScannerUnavailable
	}
	currentCredentials, e := os.Lstat(credentialsPath)
	if e != nil || !withdrawalOrdinary(currentCredentials) || currentCredentials.Size() != int64(len(b)) {
		return nil, imageScannerUnavailable
	}
	currentBytes, e := os.ReadFile(credentialsPath)
	if e != nil || !bytes.Equal(b, currentBytes) {
		return nil, imageScannerUnavailable
	}
	afterHosts, e := resolver.trustedServiceHosts(ctx, "autosoft_artifact", []string{"registry"})
	if e != nil || !reflect.DeepEqual(hosts, afterHosts) {
		return nil, imageScannerUnavailable
	}
	return imageScannerFindings(out, image)
}

func imageScannerFindings(out []byte, image string) ([]Finding, error) {
	// Trivy v0.75's container_image/os-pkgs contract and --list-all-pkgs provide
	// positive OS-package evidence. This does not certify every language analyzer.
	report, e := imageScannerJSON(out)
	if e != nil || !digestImage.MatchString(image) || !scannerNumber(report["SchemaVersion"], 2) || report["ArtifactName"] != image || report["ArtifactType"] != "container_image" {
		return nil, imageScannerUnavailable
	}
	osEvidence := scannerMap(scannerMap(report["Metadata"])["OS"])
	family := scannerString(osEvidence["Family"])
	if family != "debian" && family != "alpine" {
		return nil, imageScannerUnavailable
	}
	if eosl, present := osEvidence["EOSL"]; present && !scannerBool(eosl, false) {
		return nil, imageScannerUnavailable
	}
	results, ok := report["Results"].([]any)
	if !ok || len(results) == 0 || len(results) > 4096 {
		return nil, imageScannerUnavailable
	}
	findings := []Finding{}
	packages, coveredOS := 0, false
	for _, value := range results {
		result := scannerMap(value)
		class, kind := scannerString(result["Class"]), scannerString(result["Type"])
		if (class != "os-pkgs" && class != "lang-pkgs") || !scannerText(result["Target"], 8192, false) || !scannerText(result["Type"], 128, false) {
			return nil, imageScannerUnavailable
		}
		pkgList, ok := result["Packages"].([]any)
		if !ok || len(pkgList) == 0 {
			return nil, imageScannerUnavailable
		}
		packages += len(pkgList)
		if packages > 50000 {
			return nil, imageScannerUnavailable
		}
		for _, value := range pkgList {
			pkg := scannerMap(value)
			if !scannerText(pkg["Name"], 1024, false) || !scannerText(pkg["Version"], 4096, false) {
				return nil, imageScannerUnavailable
			}
		}
		if class == "os-pkgs" {
			if kind != family {
				return nil, imageScannerUnavailable
			}
			coveredOS = true
		}
		vulns, present := result["Vulnerabilities"]
		if !present {
			continue // Trivy omits zero vulnerabilities, while packages remain present.
		}
		list, ok := vulns.([]any)
		if !ok || len(findings)+len(list) > 50000 {
			return nil, imageScannerUnavailable
		}
		for _, value := range list {
			v := scannerMap(value)
			severity := scannerString(v["Severity"])
			if !scannerText(v["VulnerabilityID"], 1024, false) || !scannerText(v["PkgName"], 1024, false) || !scannerText(v["InstalledVersion"], 4096, false) || (severity != "UNKNOWN" && severity != "LOW" && severity != "MEDIUM" && severity != "HIGH" && severity != "CRITICAL") {
				return nil, imageScannerUnavailable
			}
			for _, key := range []string{"FixedVersion", "Title"} {
				if text, present := v[key]; present && !scannerText(text, 8192, true) {
					return nil, imageScannerUnavailable
				}
			}
			findings = append(findings, Finding{scannerString(v["VulnerabilityID"]), severity, scannerString(v["PkgName"]), scannerString(v["InstalledVersion"]), scannerString(v["FixedVersion"]), "trivy-image", scannerString(v["Title"])})
		}
	}
	if !coveredOS {
		return nil, imageScannerUnavailable
	}
	return findings, nil
}

func scannerText(v any, maximum int, empty bool) bool {
	value, ok := v.(string)
	if !ok || len(value) > maximum || !empty && value == "" {
		return false
	}
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
