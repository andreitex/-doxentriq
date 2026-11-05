package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type imageScannerFixture struct {
	t                                   *testing.T
	x                                   *imageScannerExecution
	calls                               [][]string
	states                              []imageScannerRecord
	container                           map[string]any
	created, removed                    bool
	createFault, stopFault, removeFault bool
	lostID, foreignID                   bool
	inspectCount                        int
	driftAt                             int
	startHook                           func()
	createHook                          func()
	retentionFailure                    func(imageScannerRecord) bool
}

func newImageScannerFixture(t *testing.T) *imageScannerFixture {
	t.Helper()
	op := strings.Repeat("a", 32)
	spec := imageScannerSpec{name: "as-image-scan-" + op, image: "registry:5000/scanner@sha256:" + strings.Repeat("c", 64), runtime: "runsc", network: strings.Repeat("b", 64), cache: "/host/security-cache", ca: "/host/tls/ca.crt", envFile: "/private/scanner.env", hosts: []string{"--add-host", "registry:172.30.2.2"}, environment: []string{"SSL_CERT_FILE=/etc/autosoft/ca.crt", "TRIVY_USERNAME=fixture", "TRIVY_PASSWORD=private-fixture"}, command: []string{"image", "--cache-dir", "/cache/trivy", "--cache-backend", "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--format", "json", "registry:5000/apps/app1@sha256:" + strings.Repeat("d", 64)}}
	f := &imageScannerFixture{t: t}
	x := &imageScannerExecution{spec: spec, dir: "/private", config: "/private/config", r: imageScannerRecord{Version: 1, OperationID: op, Image: spec.command[len(spec.command)-1], Scanner: spec.image, NetworkID: spec.network, Status: "intent"}}
	x.d = imageScannerDependencies{docker: f.docker, retain: func(_ string, v any) error {
		if state, ok := v.(imageScannerRecord); ok {
			f.states = append(f.states, state)
			if f.retentionFailure != nil && f.retentionFailure(state) {
				return errors.New("private-retention-error")
			}
		}
		return nil
	}}
	f.x = x
	return f
}
func (f *imageScannerFixture) image() map[string]any {
	return map[string]any{"Id": "sha256:" + strings.Repeat("e", 64), "Os": "linux", "Architecture": "amd64", "Config": map[string]any{"Env": []string{"PATH=/usr/local/bin:/usr/bin"}, "Labels": map[string]string{"company": "scanner"}, "Entrypoint": []string{"trivy"}, "Volumes": nil}, "Descriptor": map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + strings.Repeat("e", 64), "size": 123, "annotations": map[string]string{"io.containerd.image.config.digest": "sha256:" + strings.Repeat("4", 64)}}, "RootFS": map[string]any{"Type": "layers", "Layers": []string{"sha256:" + strings.Repeat("f", 64)}}}
}
func (f *imageScannerFixture) makeContainer() map[string]any {
	s := f.x.spec
	op := strings.TrimPrefix(s.name, "as-image-scan-")
	env := append(append([]string{}, s.environment...), "PATH=/usr/local/bin:/usr/bin")
	hosts := []string{}
	for i := 0; i < len(s.hosts); i += 2 {
		hosts = append(hosts, s.hosts[i+1])
	}
	return map[string]any{"Id": strings.Repeat("1", 64), "Name": "/" + s.name, "Image": strings.Split(s.image, "@")[1], "Platform": "linux", "ImageManifestDescriptor": map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + strings.Repeat("e", 64), "size": 123, "annotations": map[string]string{"io.containerd.image.config.digest": "sha256:" + strings.Repeat("4", 64)}, "platform": map[string]string{"architecture": "amd64", "os": "linux"}}, "Config": map[string]any{"Image": s.image, "User": "10001:10001", "WorkingDir": "/", "Hostname": s.name, "Domainname": "", "Tty": false, "OpenStdin": false, "StdinOnce": false, "AttachStdin": false, "Cmd": s.command, "Entrypoint": []string{"trivy"}, "StopSignal": "SIGTERM", "Env": env, "Labels": map[string]string{"company": "scanner", "io.autosoft.runtime-image-scan": op}, "Healthcheck": map[string]any{"Test": []string{"NONE"}}}, "HostConfig": map[string]any{"Runtime": "runsc", "NetworkMode": s.network, "ReadonlyRootfs": true, "Privileged": false, "AutoRemove": false, "NanoCpus": 1000000000, "Memory": 3 << 30, "MemorySwap": 3 << 30, "PidsLimit": 128, "CapAdd": nil, "CapDrop": []string{"ALL"}, "PortBindings": nil, "Devices": nil, "DeviceRequests": nil, "PidMode": "", "UTSMode": "", "IpcMode": "private", "UsernsMode": "", "Tmpfs": map[string]string{"/tmp": "size=128m,mode=1777"}, "LogConfig": map[string]string{"Type": "none"}, "RestartPolicy": map[string]any{"Name": "no"}, "SecurityOpt": []string{"no-new-privileges"}, "ExtraHosts": hosts, "OomKillDisable": false}, "State": map[string]any{"Status": "created", "Running": false, "Paused": false, "Restarting": false, "Dead": false, "ExitCode": 0, "OOMKilled": false}, "NetworkSettings": map[string]any{"Networks": map[string]any{"autosoft_artifact": map[string]any{"NetworkID": s.network}}}, "Mounts": []map[string]any{{"Type": "bind", "Source": s.cache, "Destination": "/cache", "RW": false}, {"Type": "bind", "Source": s.ca, "Destination": "/etc/autosoft/ca.crt", "RW": false}}}
}
func scannerFixtureMap(m map[string]any, key string) map[string]any { return m[key].(map[string]any) }

func installImageScannerServerFixture(t *testing.T, s *server, hostData, severity string) *imageScannerFixture {
	t.Helper()
	f := newImageScannerFixture(t)
	f.x.spec.image = s.manifest.ScannerImage
	f.x.spec.network = strings.Repeat("a", 64)
	f.x.spec.cache = filepath.Join(hostData, "security-cache")
	f.x.spec.ca = filepath.Join(hostData, "tls", "ca.crt")
	s.imageScannerDocker = func(ctx context.Context, args []string, limit int64) (imageScannerCommandResult, error) {
		command := args[4:]
		if command[0] == "network" || command[0] == "ps" && strings.Contains(strings.Join(command, " "), "--filter") || command[0] == "inspect" && command[len(command)-1] == strings.Repeat("9", 64) {
			out, err := s.runner(ctx, "docker", command...)
			return imageScannerCommandResult{Stdout: []byte(out), ExitCode: 0, Reaped: true}, err
		}
		if command[0] == "create" {
			for i := 1; i < len(command)-1; i++ {
				if command[i] == "--name" {
					f.x.spec.name = command[i+1]
				}
				if command[i] == "--env-file" {
					b, err := os.ReadFile(command[i+1])
					if err != nil {
						t.Fatal(err)
					}
					f.x.spec.environment = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
				}
				if command[i] == f.x.spec.image {
					f.x.spec.command = command[i+1:]
					f.x.r.Image = command[len(command)-1]
					break
				}
			}
		}
		result, err := f.docker(ctx, args, limit)
		if command[0] == "start" {
			result.Stdout, _ = json.Marshal(scannerFixtureReport(f.x.r.Image, severity))
		}
		return result, err
	}
	return f
}
func (f *imageScannerFixture) docker(ctx context.Context, args []string, _ int64) (imageScannerCommandResult, error) {
	if len(args) < 5 || !reflect.DeepEqual(args[:3], []string{"--host", "unix:///var/run/docker.sock", "--config"}) {
		f.t.Fatal("ambient Docker endpoint could be used")
	}
	a := append([]string{}, args[4:]...)
	f.calls = append(f.calls, a)
	ok := func(v any) (imageScannerCommandResult, error) {
		b, _ := json.Marshal(v)
		return imageScannerCommandResult{Stdout: b, ExitCode: 0, Reaped: true}, nil
	}
	plain := func(b string) (imageScannerCommandResult, error) {
		return imageScannerCommandResult{Stdout: []byte(b), ExitCode: 0, Reaped: true}, nil
	}
	switch a[0] {
	case "image":
		return ok(f.image())
	case "network":
		return ok(serviceNetworkInspection{ID: f.x.spec.network, Name: "autosoft_artifact", Driver: "bridge", Internal: true, Labels: map[string]string{"io.autosoft.managed": "true"}})
	case "create":
		f.created = true
		f.container = f.makeContainer()
		if f.createHook != nil {
			f.createHook()
		}
		if f.lostID {
			return imageScannerCommandResult{ExitCode: 1, Reaped: true}, errors.New("private-create-output")
		}
		result, _ := plain(strings.Repeat("1", 64) + "\n")
		if f.createFault {
			return result, errors.New("private-create-unconfirmed")
		}
		return result, nil
	case "inspect":
		f.inspectCount++
		if f.foreignID {
			f.container["Id"] = strings.Repeat("2", 64)
		}
		if f.driftAt == f.inspectCount {
			scannerFixtureMap(f.container, "HostConfig")["PidsLimit"] = 129
		}
		return ok(f.container)
	case "start":
		if !reflect.DeepEqual(a, []string{"start", "--attach", strings.Repeat("1", 64)}) {
			f.t.Fatal("start did not use exact immutable ID")
		}
		state := scannerFixtureMap(f.container, "State")
		state["Status"], state["Running"] = "running", true
		if f.startHook != nil {
			f.startHook()
		}
		if ctx.Err() != nil {
			return imageScannerCommandResult{ExitCode: -1, Reaped: true}, errors.New("private-start-cancel")
		}
		state["Status"], state["Running"] = "exited", false
		b, _ := json.Marshal(scannerFixtureReport(f.x.r.Image, ""))
		return plain(string(b))
	case "stop":
		if ctx.Err() != nil {
			f.t.Fatal("request cancellation skipped detached cleanup")
		}
		if !reflect.DeepEqual(a, []string{"stop", "--time", "15", strings.Repeat("1", 64)}) {
			f.t.Fatal("stop guessed a name or foreign ID")
		}
		if f.stopFault {
			return imageScannerCommandResult{ExitCode: 1, Reaped: true}, errors.New("private-stop-unavailable")
		}
		state := scannerFixtureMap(f.container, "State")
		state["Status"], state["Running"] = "exited", false
		return plain(strings.Repeat("1", 64) + "\n")
	case "rm":
		if !reflect.DeepEqual(a, []string{"rm", strings.Repeat("1", 64)}) {
			f.t.Fatal("force/name/volume cleanup")
		}
		f.removed = true
		if f.removeFault {
			return imageScannerCommandResult{ExitCode: 1, Reaped: true}, errors.New("private-rm-response-lost")
		}
		return plain(strings.Repeat("1", 64) + "\n")
	case "ps":
		if !reflect.DeepEqual(a, []string{"ps", "--all", "--no-trunc", "--format", "{{.ID}}"}) {
			f.t.Fatal("absence not independently inspected")
		}
		if f.removed {
			return plain(strings.Repeat("9", 64) + "\n")
		}
		return plain(strings.Repeat("1", 64) + "\n")
	default:
		f.t.Fatal("unexpected command")
		return imageScannerCommandResult{}, imageScannerUnavailable
	}
}
func (f *imageScannerFixture) count(command string) int {
	n := 0
	for _, a := range f.calls {
		if a[0] == command {
			n++
		}
	}
	return n
}

func TestRuntimeImageScannerCapacitySizeAdmission(t *testing.T) {
	for _, test := range []struct {
		name, member string
		size, limit  int64
		accepted     bool
	}{
		{"os_observed_1607704576", "trivy/db/trivy.db", 1607704576, 2 << 30, true},
		{"os_max", "trivy/db/trivy.db", 2 << 30, 2 << 30, true},
		{"os_max_plus_one", "trivy/db/trivy.db", (2 << 30) + 1, 0, false},
		{"os_empty", "trivy/db/trivy.db", 0, 0, false},
		{"os_negative", "trivy/db/trivy.db", -1, 0, false},
		{"java_max", "trivy/java-db/trivy-java.db", 512 << 20, 512 << 20, true},
		{"java_max_plus_one", "trivy/java-db/trivy-java.db", (512 << 20) + 1, 0, false},
		{"java_cannot_use_os_capacity", "trivy/java-db/trivy-java.db", 1607704576, 0, false},
		{"os_metadata_max", "trivy/db/metadata.json", 65536, 65536, true},
		{"os_metadata_max_plus_one", "trivy/db/metadata.json", 65537, 0, false},
		{"java_metadata_max", "trivy/java-db/metadata.json", 65536, 65536, true},
		{"java_metadata_max_plus_one", "trivy/java-db/metadata.json", 65537, 0, false},
		{"metadata_empty", "trivy/db/metadata.json", 0, 0, false},
		{"unknown_db", "trivy/db/foreign.db", 1, 0, false},
		{"unknown_metadata", "trivy/foreign/metadata.json", 1, 0, false},
		{"absolute_path", "/trivy/db/trivy.db", 1, 0, false},
		{"traversal", "trivy/db/../db/trivy.db", 1, 0, false},
		{"backslash_alias", "trivy\\db\\trivy.db", 1, 0, false},
		{"case_alias", "trivy/db/TRIVY.db", 1, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			limit, err := imageScannerFeedFileLimit(test.member, test.size)
			if (err == nil) != test.accepted || limit != test.limit {
				t.Fatalf("size admission mismatch: limit=%d err=%v", limit, err)
			}
			if err != nil && err != imageScannerUnavailable {
				t.Fatal("fixed unavailable result was lost")
			}
		})
	}
}

func TestRuntimeImageScannerCapacityCreateMemoryAndSwap(t *testing.T) {
	f := newImageScannerFixture(t)
	args := f.x.spec.create()
	for _, flag := range []string{"--memory", "--memory-swap"} {
		count := 0
		for i, argument := range args {
			if argument == flag {
				count++
				if i+1 >= len(args) || args[i+1] != "3g" {
					t.Fatalf("create omitted exact capacity for %s", flag)
				}
			}
		}
		if count != 1 {
			t.Fatalf("create has %d occurrences of %s", count, flag)
		}
	}
	if _, err := f.x.execute(context.Background()); err != nil || f.count("start") != 1 || !f.x.r.CleanupConfirmed {
		t.Fatal("exact new profile failed prestart or cleanup")
	}
}

func TestRuntimeImageScannerCapacityPrestartRejectsResourceMismatch(t *testing.T) {
	for _, test := range []struct {
		name         string
		memory, swap any
	}{
		{"old_1g_profile", 1 << 30, 1 << 30},
		{"old_1g_memory", 1 << 30, 3 << 30},
		{"old_1g_swap", 3 << 30, 1 << 30},
		{"excess_memory", 4 << 30, 3 << 30},
		{"excess_swap", 3 << 30, 4 << 30},
		{"unlimited_swap", 3 << 30, -1},
		{"memory_numeric_alias", json.RawMessage("3221225472.0"), 3 << 30},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newImageScannerFixture(t)
			f.createHook = func() {
				host := scannerFixtureMap(f.container, "HostConfig")
				host["Memory"], host["MemorySwap"] = test.memory, test.swap
			}
			if output, err := f.x.execute(context.Background()); err == nil || output != nil || f.count("create") != 1 || f.count("inspect") != 1 || f.count("start")+f.count("stop")+f.count("rm") != 0 || f.x.r.CleanupConfirmed {
				t.Fatal("unverified resource profile was started, cleaned or confirmed")
			}
		})
	}
}

func TestRuntimeImageScannerCapacityCleanupRejectsResourceDrift(t *testing.T) {
	for _, test := range []struct {
		name         string
		memory, swap int64
	}{
		{"old_1g_profile", 1 << 30, 1 << 30},
		{"old_1g_memory", 1 << 30, 3 << 30},
		{"old_1g_swap", 3 << 30, 1 << 30},
		{"excess_memory", 4 << 30, 3 << 30},
		{"excess_swap", 3 << 30, 4 << 30},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newImageScannerFixture(t)
			f.startHook = func() {
				host := scannerFixtureMap(f.container, "HostConfig")
				host["Memory"], host["MemorySwap"] = test.memory, test.swap
			}
			if output, err := f.x.execute(context.Background()); err == nil || output != nil || f.count("start") != 1 || f.count("stop")+f.count("rm") != 0 || f.x.r.Status != "cleanup_unconfirmed" || f.x.r.CleanupConfirmed {
				t.Fatal("post-seal resource drift was cleaned or confirmed")
			}
		})
	}
}

func TestRuntimeImageScannerDurableIntentAndExactLifecycle(t *testing.T) {
	f := newImageScannerFixture(t)
	out, err := f.x.execute(context.Background())
	if err != nil || len(out) == 0 || !f.x.r.CleanupConfirmed || f.x.r.Status != "completed" || f.count("create") != 1 || f.count("start") != 1 || f.count("rm") != 1 || f.count("ps") != 1 {
		t.Fatalf("actual lifecycle failed: %v", err)
	}
	if len(f.states) < 4 || f.states[0].Status != "intent" {
		t.Fatal("create preceded retained intent")
	}
	for _, a := range f.calls {
		if a[0] == "create" {
			text := strings.Join(a, " ")
			if strings.Contains(text, "private-fixture") || strings.Contains(text, "--rm") || !strings.Contains(text, "--cache-backend memory") || !strings.Contains(text, "--env-file /private/scanner.env") {
				t.Fatal("credentials or unsafe scan policy in command")
			}
		}
	}
}
func TestRuntimeImageScannerUnknownCreateAndForeignIDNeverStartOrClean(t *testing.T) {
	for _, variant := range []string{"lost", "foreign"} {
		t.Run(variant, func(t *testing.T) {
			f := newImageScannerFixture(t)
			f.lostID = variant == "lost"
			f.foreignID = variant == "foreign"
			if _, err := f.x.execute(context.Background()); err == nil {
				t.Fatal("uncertain create accepted")
			}
			if f.count("start")+f.count("stop")+f.count("rm") != 0 {
				t.Fatal("unknown/foreign object mutated")
			}
		})
	}
}
func TestRuntimeImageScannerAmbiguousCreateCanOnlyCleanVerifiedID(t *testing.T) {
	f := newImageScannerFixture(t)
	f.createFault = true
	if _, err := f.x.execute(context.Background()); err == nil || f.count("start") != 0 || f.count("rm") != 1 || !f.x.r.CleanupConfirmed {
		t.Fatal("ambiguous create was started or known owned ID not reconciled")
	}
}

func TestRuntimeImageScannerCancellationAfterCreateOnlyCleansVerifiedID(t *testing.T) {
	f := newImageScannerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.createHook = cancel
	if _, err := f.x.execute(ctx); err == nil || f.count("start") != 0 || f.count("rm") != 1 || !f.x.r.CleanupConfirmed {
		t.Fatal("cancelled create skipped exact ownership proof or started a scanner")
	}
}
func TestRuntimeImageScannerDriftRefusesStopAndRemove(t *testing.T) {
	f := newImageScannerFixture(t)
	f.driftAt = 2
	if _, err := f.x.execute(context.Background()); err == nil || f.count("start")+f.count("stop")+f.count("rm") != 0 || f.x.r.CleanupConfirmed {
		t.Fatal("drifted profile mutated or accepted")
	}
}
func TestRuntimeImageScannerCancellationCleansDetachedOrRetainsUncertainty(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(strconvBool(fault), func(t *testing.T) {
			f := newImageScannerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			f.startHook = cancel
			f.stopFault = fault
			if _, err := f.x.execute(ctx); err == nil {
				t.Fatal("cancelled scan accepted")
			}
			if f.count("stop") != 1 {
				t.Fatal("exact detached stop not attempted")
			}
			if fault && (f.count("rm") != 0 || f.x.r.CleanupConfirmed) || !fault && (f.count("rm") != 1 || !f.x.r.CleanupConfirmed) {
				t.Fatal("cleanup uncertainty hidden")
			}
		})
	}
}
func strconvBool(v bool) string {
	if v {
		return "unavailable_stop"
	}
	return "confirmed_stop"
}
func TestRuntimeImageScannerFailedDurabilityPreventsEveryMutation(t *testing.T) {
	f := newImageScannerFixture(t)
	f.retentionFailure = func(imageScannerRecord) bool { return true }
	if _, err := f.x.execute(context.Background()); err == nil || len(f.calls) != 0 {
		t.Fatal("unsynchronized intent reached Docker")
	}
	f = newImageScannerFixture(t)
	f.startHook = func() { f.retentionFailure = func(imageScannerRecord) bool { return true } }
	if _, err := f.x.execute(context.Background()); err == nil || f.count("stop")+f.count("rm") != 0 || f.x.r.CleanupConfirmed {
		t.Fatal("cleanup ignored failed durable authority")
	}
	f = newImageScannerFixture(t)
	f.retentionFailure = func(v imageScannerRecord) bool { return v.Status == "start_intent" }
	if _, err := f.x.execute(context.Background()); err == nil || f.count("start")+f.count("stop")+f.count("rm") != 0 {
		t.Fatal("failed durable pre-start proof reached mutation")
	}
}

func TestRuntimeImageScannerBoundedOutputUncertaintyNeverPasses(t *testing.T) {
	for _, variant := range []string{"stdout_overflow", "stderr_overflow", "unreaped", "nonzero"} {
		t.Run(variant, func(t *testing.T) {
			f := newImageScannerFixture(t)
			original := f.x.d.docker
			f.x.d.docker = func(ctx context.Context, args []string, limit int64) (imageScannerCommandResult, error) {
				r, e := original(ctx, args, limit)
				if args[4] == "start" {
					switch variant {
					case "stdout_overflow":
						r.Stdout = make([]byte, limit+1)
					case "stderr_overflow":
						r.Stderr = make([]byte, imageScannerErrorLimit+1)
					case "unreaped":
						r.Reaped = false
					case "nonzero":
						r.ExitCode = 1
					}
				}
				return r, e
			}
			if out, e := f.x.execute(context.Background()); e == nil || out != nil || !f.x.r.CleanupConfirmed || f.count("rm") != 1 {
				t.Fatal("uncertain scan passed or exact stopped cleanup missing")
			}
		})
	}
}

func TestRuntimeImageScannerPostSealEnvironmentOrderDriftAndOddHostRefuse(t *testing.T) {
	f := newImageScannerFixture(t)
	f.x.spec.hosts = []string{"--add-host"}
	if _, e := f.x.execute(context.Background()); e == nil || len(f.calls) != 0 {
		t.Fatal("malformed host vector reached create")
	}
	f = newImageScannerFixture(t)
	if f.x.image(context.Background()) != nil {
		t.Fatal("fixture image failed")
	}
	f.container = f.makeContainer()
	f.x.r.ContainerID = strings.Repeat("1", 64)
	_, hash, e := f.x.inspect(context.Background())
	if e != nil {
		t.Fatal("fixture profile failed")
	}
	f.x.r.ProfileHash = hash
	env := scannerFixtureMap(f.container, "Config")["Env"].([]string)
	env[0], env[1] = env[1], env[0]
	if _, _, e := f.x.inspect(context.Background()); e == nil || f.count("start")+f.count("stop")+f.count("rm") != 0 {
		t.Fatal("actual raw environment order lost after seal")
	}
}
func TestRuntimeImageScannerLostRemovalResponseUsesIndependentAbsence(t *testing.T) {
	f := newImageScannerFixture(t)
	f.removeFault = true
	if _, err := f.x.execute(context.Background()); err != nil || f.count("rm") != 1 || f.count("ps") != 1 || !f.x.r.CleanupConfirmed {
		t.Fatal("absence unresolved or removal retried")
	}
}
func TestRuntimeImageScannerStrictProfileAndEnvironment(t *testing.T) {
	for _, variant := range []string{"extra_environment", "changed_value", "duplicate_environment", "runtime", "write_mount", "image", "descriptor", "platform", "cpu", "network", "extra_network", "odd_hosts", "numeric_alias", "missing_oom", "true_oom"} {
		t.Run(variant, func(t *testing.T) {
			f := newImageScannerFixture(t)
			if f.x.image(context.Background()) != nil {
				t.Fatal("fixture image rejected")
			}
			f.container = f.makeContainer()
			f.x.r.ContainerID = strings.Repeat("1", 64)
			c, h := scannerFixtureMap(f.container, "Config"), scannerFixtureMap(f.container, "HostConfig")
			switch variant {
			case "extra_environment":
				c["Env"] = append(c["Env"].([]string), "EXTRA=x")
			case "changed_value":
				c["Env"] = []string{"PATH=/usr/bin"}
			case "duplicate_environment":
				c["Env"] = append(c["Env"].([]string), "PATH=/usr/local/bin:/usr/bin")
			case "runtime":
				h["Runtime"] = "runc"
			case "write_mount":
				f.container["Mounts"].([]map[string]any)[0]["RW"] = true
			case "image":
				f.container["Image"] = "sha256:" + strings.Repeat("e", 64)
			case "descriptor":
				scannerFixtureMap(f.container, "ImageManifestDescriptor")["digest"] = "sha256:" + strings.Repeat("4", 64)
			case "cpu":
				h["NanoCpus"] = 2000000000
			case "network":
				scannerFixtureMap(scannerFixtureMap(f.container, "NetworkSettings"), "Networks")["autosoft_artifact"] = map[string]any{"NetworkID": strings.Repeat("8", 64)}
			case "extra_network":
				scannerFixtureMap(scannerFixtureMap(f.container, "NetworkSettings"), "Networks")["foreign"] = map[string]any{"NetworkID": strings.Repeat("8", 64)}
			case "odd_hosts":
				f.x.spec.hosts = []string{"--add-host"}
			case "platform":
				f.container["Platform"] = "windows"
			case "numeric_alias":
				h["PidsLimit"] = 128.0
			case "missing_oom":
				delete(h, "OomKillDisable")
			case "true_oom":
				h["OomKillDisable"] = true
			}
			if variant == "numeric_alias" {
				h["PidsLimit"] = json.RawMessage("128.0")
			}
			if _, _, err := f.x.inspect(context.Background()); err == nil {
				t.Fatal("adversarial profile accepted")
			}
		})
	}
}
func TestRuntimeImageScannerOutputBoundsAndParserRefusals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := imageScannerBuffer{maximum: 4, cancel: cancel}
	if n, e := b.Write([]byte("1234")); n != 4 || e != nil {
		t.Fatal("bounded data refused")
	}
	if _, e := b.Write([]byte("5")); e == nil || ctx.Err() == nil || len(b.data) != 4 || !b.overflow {
		t.Fatal("overflow silently truncated")
	}
	for _, raw := range []string{`{"SchemaVersion":2,"SchemaVersion":2}`, `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"unknown"}},"Results":[{}]}`, `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"alpine","EOSL":true}},"Results":[{}]}`, `{"SchemaVersion":2,"Metadata":{"OS":{"Family":"alpine"}},"Results":[]}`, `{"x":1}junk`, strings.Repeat("[", 40) + strings.Repeat("]", 40)} {
		if _, e := imageScannerFindings([]byte(raw), "registry:5000/apps/app1@sha256:"+strings.Repeat("d", 64)); e == nil {
			t.Fatal("unsupported/malformed report accepted")
		}
	}
	if _, e := imageScannerCommand(context.Background(), []string{"--host", "tcp://foreign", "--config", "/tmp", "ps"}, 1); e == nil {
		t.Fatal("foreign endpoint reached execution")
	}
}

func scannerFixtureReport(image, severity string) map[string]any {
	result := map[string]any{"Target": "synthetic (alpine 3.24.2)", "Class": "os-pkgs", "Type": "alpine", "Packages": []any{map[string]any{"Name": "fixture", "Version": "1.0"}}}
	if severity != "" {
		result["Vulnerabilities"] = []any{map[string]any{"VulnerabilityID": "CVE-fixture", "Severity": severity, "PkgName": "fixture", "InstalledVersion": "1.0"}}
	}
	return map[string]any{"SchemaVersion": 2, "ArtifactName": image, "ArtifactType": "container_image", "Metadata": map[string]any{"OS": map[string]any{"Family": "alpine", "EOSL": false}}, "Results": []any{result}}
}

func TestRuntimeImageScannerRequiresPositiveArtifactPackageCoverage(t *testing.T) {
	image := "registry:5000/apps/app1@sha256:" + strings.Repeat("d", 64)
	for _, variant := range []string{"valid_empty", "valid_low", "wrong_image", "wrong_artifact", "empty_package", "missing_class", "mismatched_os", "unknown_severity", "missing_severity", "missing_version", "metadata_only", "wrong_package_type"} {
		t.Run(variant, func(t *testing.T) {
			report := scannerFixtureReport(image, "LOW")
			result := report["Results"].([]any)[0].(map[string]any)
			v := result["Vulnerabilities"].([]any)[0].(map[string]any)
			switch variant {
			case "valid_empty":
				delete(result, "Vulnerabilities")
			case "wrong_image":
				report["ArtifactName"] = image + "foreign"
			case "wrong_artifact":
				report["ArtifactType"] = "filesystem"
			case "empty_package":
				result["Packages"] = []any{}
			case "missing_class":
				delete(result, "Class")
			case "mismatched_os":
				result["Type"] = "debian"
			case "unknown_severity":
				v["Severity"] = "unreviewed"
			case "missing_severity":
				delete(v, "Severity")
			case "missing_version":
				delete(v, "InstalledVersion")
			case "metadata_only":
				report["Results"] = []any{map[string]any{}}
			case "wrong_package_type":
				result["Packages"].([]any)[0].(map[string]any)["Name"] = 4
			}
			b, _ := json.Marshal(report)
			findings, err := imageScannerFindings(b, image)
			valid := variant == "valid_empty" || variant == "valid_low"
			if valid != (err == nil) || variant == "valid_low" && (len(findings) != 1 || findings[0].Severity != "LOW" || blockedSeverity(findings[0].Severity)) {
				t.Fatalf("coverage result mismatched %s: %v", variant, err)
			}
		})
	}
	if _, err := imageScannerJSON([]byte(`{"SchemaVersion":2,"schemaversion":3}`)); err == nil {
		t.Fatal("case alias accepted")
	}
}

func scannerFixtureFeed(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root, cache := filepath.Join(base, "runtime"), filepath.Join(base, "security-cache")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := atomicJSON(filepath.Join(cache, "trivy", "db", "metadata.json"), map[string]any{"Version": 2, "UpdatedAt": now, "NextUpdate": now.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "trivy", "db", "trivy.db"), []byte("synthetic-database"), 0644); err != nil {
		t.Fatal(err)
	}
	return root, cache
}

func TestRuntimeImageScannerFeedBindsBytesMappingAndLimits(t *testing.T) {
	for _, variant := range []string{"valid", "elapsed_schedule", "invalid_schedule", "same_timestamp_changed_bytes", "wrong_mapping", "missing_db", "oversized_db", "wrong_schema", "stale", "partial_java", "cancelled"} {
		t.Run(variant, func(t *testing.T) {
			root, cache := scannerFixtureFeed(t)
			before, err := imageScannerFeed(context.Background(), root, cache)
			if err != nil || len(before.Files) != 4 {
				t.Fatal("valid complete feed refused")
			}
			db := filepath.Join(cache, "trivy", "db", "trivy.db")
			ctx := context.Background()
			switch variant {
			case "same_timestamp_changed_bytes":
				if os.WriteFile(db, []byte("changed--database"), 0644) != nil {
					t.Fatal("fixture write failed")
				}
			case "wrong_mapping":
				cache = filepath.Join(cache, "..", "security-cache", ".") + string(filepath.Separator)
			case "missing_db":
				if os.Remove(db) != nil {
					t.Fatal("fixture remove failed")
				}
			case "oversized_db":
				if _, err := imageScannerFeedFileLimit("trivy/db/trivy.db", imageScannerOSFeedLimit+1); err == nil {
					t.Fatal("oversized database passed size admission")
				}
				return // Size policy only; no multi-GiB fixture or stream is created.
			case "wrong_schema", "stale":
				now := time.Now()
				version := 2
				if variant == "wrong_schema" {
					version = 1
				} else {
					now = now.Add(-25 * time.Hour)
				}
				if atomicJSON(filepath.Join(cache, "trivy", "db", "metadata.json"), map[string]any{"Version": version, "UpdatedAt": now, "NextUpdate": time.Now().Add(time.Hour)}) != nil {
					t.Fatal("fixture metadata failed")
				}
			case "elapsed_schedule", "invalid_schedule":
				updated := time.Now().Add(-10 * time.Hour)
				next := updated.Add(6 * time.Hour)
				if variant == "invalid_schedule" {
					next = updated.Add(-time.Hour)
				}
				if atomicJSON(filepath.Join(cache, "trivy", "db", "metadata.json"), map[string]any{"Version": 2, "UpdatedAt": updated, "NextUpdate": next}) != nil {
					t.Fatal("schedule fixture failed")
				}
			case "partial_java":
				if atomicJSON(filepath.Join(cache, "trivy", "java-db", "metadata.json"), map[string]any{"Version": 1}) != nil {
					t.Fatal("java fixture failed")
				}
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			after, err := imageScannerFeed(ctx, root, cache)
			if variant == "valid" && (err != nil || accessHash(before) != accessHash(after)) {
				t.Fatal("unchanged feed refused")
			}
			if variant == "same_timestamp_changed_bytes" && (err != nil || before.UpdatedAt != after.UpdatedAt || accessHash(before) == accessHash(after)) {
				t.Fatal("timestamp substituted for byte evidence")
			}
			if variant == "elapsed_schedule" && err != nil {
				t.Fatal("publisher schedule silently shortened 24-hour feed freshness")
			}
			if variant != "valid" && variant != "elapsed_schedule" && variant != "same_timestamp_changed_bytes" && err == nil {
				t.Fatal("unsupported feed admitted")
			}
		})
	}
}

func scannerFixtureCompletedRecord() imageScannerRecord {
	return imageScannerRecord{Version: 1, OperationID: strings.Repeat("a", 32), Image: "registry:5000/app@sha256:" + strings.Repeat("b", 64), Scanner: "registry:5000/scanner@sha256:" + strings.Repeat("c", 64), NetworkID: strings.Repeat("d", 64), FeedHash: strings.Repeat("e", 64), ContainerID: strings.Repeat("f", 64), ProfileHash: strings.Repeat("1", 64), RawPrestartHash: strings.Repeat("2", 64), Status: "completed", CleanupConfirmed: true, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}

func TestRuntimeImageScannerDurableActivePolicyRejectsUncertainAndMalformedHistory(t *testing.T) {
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	for _, variant := range []string{"absent", "clear", "active_crash", "unknown_create", "cleanup_unconfirmed", "changed_profile", "wrong_hash", "missing_state", "unknown_field", "malformed", "failed_claim"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			record := scannerFixtureCompletedRecord()
			directory := filepath.Join(root, "security", "runtime-image-scans")
			state := filepath.Join(directory, record.OperationID, "state.enc")
			activePath := filepath.Join(directory, "active.enc")
			if variant == "absent" {
				if imageScannerPriorClear(root) != nil {
					t.Fatal("genuine absent state rejected")
				}
				return
			}
			if variant == "failed_claim" {
				writes := 0
				retain := func(string, any) error { writes++; return imageScannerUnavailable }
				if _, err := claimImageScanner(root, record, retain); err == nil {
					t.Fatal("failed durable claim accepted")
				}
				if _, err := claimImageScanner(root, record, retain); err == nil || writes != 1 {
					t.Fatal("prior crashed lock was bypassed/replaced")
				}
				return
			}
			active := imageScannerActive{Version: 1, OperationID: record.OperationID, Status: "clear", RecordHash: accessHash(record)}
			switch variant {
			case "active_crash":
				active.Status = "active"
			case "unknown_create":
				record.Status = "unknown_create"
				record.CleanupConfirmed = false
			case "cleanup_unconfirmed":
				record.CleanupConfirmed = false
			case "changed_profile":
				record.ProfileHash = strings.Repeat("3", 64)
			case "wrong_hash":
				active.RecordHash = strings.Repeat("0", 64)
			}
			if writeEncrypted(state, record) != nil {
				t.Fatal("synthetic state fixture failed")
			}
			var value any = active
			if variant == "unknown_field" {
				value = map[string]any{"schemaVersion": 1, "operationId": record.OperationID, "status": "clear", "recordHash": accessHash(record), "unexpected": true}
			}
			if variant == "malformed" {
				value = "synthetic-invalid"
			}
			if writeEncrypted(activePath, value) != nil {
				t.Fatal("synthetic active fixture failed")
			}
			if variant == "missing_state" && os.Remove(state) != nil {
				t.Fatal("synthetic missing fixture failed")
			}
			err := imageScannerPriorClear(root)
			if (variant == "clear") != (err == nil) {
				t.Fatal("uncertain marker/record accepted or clear result rejected")
			}
		})
	}
}

func TestRuntimeImageScannerLinuxFeedRejectsLinksAndWritableFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actual Linux file/link/mode feed checks required")
	}
	for _, variant := range []string{"hardlink", "symlink", "writable"} {
		t.Run(variant, func(t *testing.T) {
			root, cache := scannerFixtureFeed(t)
			db := filepath.Join(cache, "trivy", "db", "trivy.db")
			switch variant {
			case "hardlink":
				if os.Link(db, db+".link") != nil {
					t.Fatal("fixture link failed")
				}
			case "symlink":
				if os.Rename(db, db+".original") != nil || os.Symlink(db+".original", db) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "writable":
				if os.Chmod(db, 0666) != nil {
					t.Fatal("fixture mode failed")
				}
			}
			if _, err := imageScannerFeed(context.Background(), root, cache); err == nil {
				t.Fatal("unsafe feed admitted")
			}
		})
	}
}

func TestRuntimeImageScannerProcessFixture(t *testing.T) {
	mode := os.Getenv("AUTOSOFT_SCANNER_SYNTHETIC_CHILD")
	if mode == "" {
		return
	}
	switch mode {
	case "streams":
		_, _ = os.Stdout.Write([]byte("synthetic-stdout"))
		_, _ = os.Stderr.Write([]byte("synthetic-stderr"))
	case "overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 1<<20))
	case "stderr_overflow":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("x"), imageScannerErrorLimit+1))
	case "wait":
		_, _ = os.Stdout.Write([]byte("synthetic-ready"))
		if os.WriteFile(os.Getenv("AUTOSOFT_SCANNER_READY_FILE"), []byte("ready"), 0600) != nil {
			os.Exit(2)
		}
		time.Sleep(60 * time.Second)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func TestRuntimeImageScannerActualBoundedProcessCaptureAndReap(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"streams", "overflow", "stderr_overflow", "wait"} {
		t.Run(mode, func(t *testing.T) {
			// The bound includes OS startup. Cancellation of the running-child
			// case begins only after independent readiness, not during startup.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			environment := append(os.Environ(), "AUTOSOFT_SCANNER_SYNTHETIC_CHILD="+mode)
			ready := make(chan bool, 1)
			if mode == "wait" {
				file := filepath.Join(t.TempDir(), "ready")
				environment = append(environment, "AUTOSOFT_SCANNER_READY_FILE="+file)
				go func() {
					ticker := time.NewTicker(10 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							ready <- false
							return
						case <-ticker.C:
							if data, err := os.ReadFile(file); err == nil && string(data) == "ready" {
								ready <- true
								cancel()
								return
							}
						}
					}
				}()
			}
			result, err := runImageScannerProcess(ctx, binary, []string{"-test.run=^TestRuntimeImageScannerProcessFixture$"}, 1024, environment)
			if !result.Reaped || len(result.Stdout) > 1024 || len(result.Stderr) > imageScannerErrorLimit {
				t.Fatal("capture was unbounded or not reaped")
			}
			if mode == "streams" {
				if err != nil || result.ExitCode != 0 || string(result.Stdout) != "synthetic-stdout" || string(result.Stderr) != "synthetic-stderr" {
					t.Fatal("streams mixed or failed")
				}
			} else if err == nil || err.Error() != imageScannerUnavailable.Error() {
				t.Fatal("uncertain process accepted or raw error exposed")
			}
			if strings.Contains(mode, "overflow") && !result.Overflow {
				t.Fatal("overflow distinction lost")
			}
			if mode == "wait" && (!<-ready || result.Overflow || string(result.Stdout) != "synthetic-ready" || ctx.Err() != context.Canceled) {
				t.Fatal("cancellation never reached running synthetic child")
			}
		})
	}
	t.Run("expired_deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		result, err := runImageScannerProcess(ctx, binary, []string{"-test.run=^TestRuntimeImageScannerProcessFixture$"}, 1024, append(os.Environ(), "AUTOSOFT_SCANNER_SYNTHETIC_CHILD=streams"))
		if err != imageScannerUnavailable || ctx.Err() != context.DeadlineExceeded || result.Reaped || result.ExitCode != -1 || len(result.Stdout) != 0 || len(result.Stderr) != 0 || result.Overflow {
			t.Fatal("expired deadline started or accepted a child")
		}
	})
}
func TestRuntimeImageScannerRealEncryptedLinuxRetention(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actual Linux file/directory synchronization required; no native scan proof")
	}
	root := t.TempDir()
	t.Setenv("BROKER_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	file := filepath.Join(root, "security", "runtime-image-scans", strings.Repeat("a", 32), "state.enc")
	v := imageScannerRecord{Version: 1, OperationID: strings.Repeat("a", 32), Status: "intent", Image: "private-fixture"}
	if retainImageScannerFile(root, file, v) != nil {
		t.Fatal("synchronized encrypted retention failed")
	}
	raw, _ := os.ReadFile(file)
	if bytes.Contains(raw, []byte("private-fixture")) {
		t.Fatal("plain private state retained")
	}
	var got imageScannerRecord
	if readEncrypted(file, &got) != nil || !reflect.DeepEqual(got, v) {
		t.Fatal("exact encrypted reopen failed")
	}
	large := filepath.Join(filepath.Dir(file), "command-large.enc")
	if retainImageScannerFile(root, large, imageScannerCommandResult{Stdout: bytes.Repeat([]byte("x"), 3<<20), Reaped: true}) != nil {
		t.Fatal("bounded output incorrectly inherited small tombstone size cap")
	}
	if os.Symlink(file, file+".symlink") != nil || retainImageScannerFile(root, file+".symlink", v) == nil {
		t.Fatal("symlink retained as ordinary encrypted evidence")
	}
	record := scannerFixtureCompletedRecord()
	retain := func(path string, value any) error { return retainImageScannerFile(root, path, value) }
	lease, err := claimImageScanner(root, record, retain)
	if err != nil || imageScannerPriorClear(root) == nil {
		t.Fatal("active durable intent missing or did not block")
	}
	if retain(filepath.Join(lease.directory, record.OperationID, "state.enc"), record) != nil || lease.release(record) != nil || imageScannerPriorClear(root) != nil {
		t.Fatal("exact cleanup result/clear marker/empty lock release failed")
	}
	if _, err := claimImageScanner(root, record, retain); err != nil {
		t.Fatal("confirmed absent prior resources did not admit next explicit scan")
	}
	link := file + ".link"
	if os.Link(file, link) != nil {
		t.Fatal("test link unavailable")
	}
	if retainImageScannerFile(root, file, v) == nil {
		t.Fatal("linked retention accepted")
	}
}
