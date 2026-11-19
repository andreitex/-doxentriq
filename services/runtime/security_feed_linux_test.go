//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func nativeFeedFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned Linux lock fixture")
	}
	root, cache := scannerFixtureFeed(t)
	fixtureProtectedFeedLocks(t, cache)
	return root, cache
}

func TestFeedLeaseCoordinatesActualPythonWriter(t *testing.T) {
	root, cache := nativeFeedFixture(t)
	first, err := holdSecurityFeed(context.Background(), root, cache)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code := `import fcntl,os,sys
fds=[os.open(os.path.join(sys.argv[1],n),os.O_RDONLY) for n in ('.feed-admission.lock','.feed-readers.lock')]
fcntl.flock(fds[0],fcntl.LOCK_EX|fcntl.LOCK_NB)
try:
 fcntl.flock(fds[1],fcntl.LOCK_EX|fcntl.LOCK_NB)
 raise AssertionError('existing Go reader was not held')
except BlockingIOError: pass
print('writer-admitted',flush=True)
assert sys.stdin.readline()=='release-reader\n'
fcntl.flock(fds[1],fcntl.LOCK_EX|fcntl.LOCK_NB)
print('writer-exclusive',flush=True)
`
	child := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", code, cache)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil || child.Start() != nil {
		t.Fatal("cross-process fixture start failed")
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	reader := bufio.NewReaderSize(stdout, 128)
	if text, err := reader.ReadString('\n'); err != nil || text != "writer-admitted\n" {
		t.Fatal("writer was not admitted behind the existing reader")
	}
	if other, err := holdSecurityFeed(ctx, root, cache); err == nil {
		_ = other.Close()
		t.Fatal("new reader bypassed an admitted writer")
	}
	if _, err := first.Check(ctx); err != nil {
		t.Fatal("writer admission invalidated the existing reader")
	}
	if first.Close() != nil {
		t.Fatal("reader release failed")
	}
	if _, err := stdin.Write([]byte("release-reader\n")); err != nil {
		t.Fatal(err)
	}
	if text, err := reader.ReadString('\n'); err != nil || text != "writer-exclusive\n" {
		t.Fatal("writer did not acquire after existing reader release")
	}
	if child.Wait() != nil {
		t.Fatal("writer fixture failed")
	}
	final, err := holdSecurityFeed(ctx, root, cache)
	if err != nil {
		t.Fatal("closed writer blocked subsequent read")
	}
	_ = final.Close()
}

func TestFeedLeaseRejectsLockReplacementAndTerminalExpiry(t *testing.T) {
	for _, change := range []string{"lock", "bytes", "expiry", "metadata_same_bytes_new_inode"} {
		t.Run(change, func(t *testing.T) {
			root, cache := nativeFeedFixture(t)
			lease, err := holdSecurityFeed(context.Background(), root, cache)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			switch change {
			case "lock":
				path := filepath.Join(cache, ".feed-readers.lock")
				if os.Rename(path, path+".retained") != nil || os.WriteFile(path, nil, 0440) != nil || os.Chown(path, 0, 10001) != nil {
					t.Fatal("fixture substitution failed")
				}
			case "bytes":
				if os.WriteFile(filepath.Join(cache, "trivy/db/trivy.db"), []byte("different database"), 0644) != nil {
					t.Fatal("fixture write failed")
				}
			case "expiry":
				value := feedMetadataFixture(time.Now())
				value["NextUpdate"] = time.Now().Add(-time.Nanosecond).UTC().Format(time.RFC3339Nano)
				raw, _ := json.Marshal(value)
				if os.WriteFile(filepath.Join(cache, "trivy/db/metadata.json"), raw, 0600) != nil {
					t.Fatal("fixture expiry failed")
				}
			case "metadata_same_bytes_new_inode":
				path := filepath.Join(cache, "trivy/db/metadata.json")
				raw, err := os.ReadFile(path)
				if err != nil || os.Rename(path, path+".retained") != nil || os.WriteFile(path, raw, 0600) != nil {
					t.Fatal("fixture substitution failed")
				}
			}
			if _, err := lease.Check(context.Background()); err == nil {
				t.Fatal("changed feed or protected lock was accepted")
			}
		})
	}
}

func TestFeedLeaseRejectsMissingUnsafeAndLinkedLocks(t *testing.T) {
	for _, change := range []string{"missing", "nonroot", "writable", "nonempty", "symlink", "hardlink"} {
		t.Run(change, func(t *testing.T) {
			root, cache := nativeFeedFixture(t)
			path := filepath.Join(cache, ".feed-admission.lock")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("fixture mutation failed before the reader check: %v", err)
				}
			}
			switch change {
			case "missing":
				must(os.Remove(path))
			case "nonroot":
				must(os.Chown(path, 65534, 10001))
			case "writable":
				must(os.Chmod(path, 0640))
			case "nonempty":
				must(os.Chmod(path, 0600))
				must(os.WriteFile(path, []byte("x"), 0600))
				must(os.Chmod(path, 0440))
			case "symlink":
				must(os.Rename(path, path+".retained"))
				must(os.Symlink(path+".retained", path))
			case "hardlink":
				must(os.Link(path, path+".retained"))
			}
			if lease, err := holdSecurityFeed(context.Background(), root, cache); err == nil {
				_ = lease.Close()
				t.Fatal("unsafe lock admitted")
			}
		})
	}
}

func TestSourceScannerLeaseIsHeldThroughDetachedCleanupAndFinalRead(t *testing.T) {
	s, scanner, workspace := sourceScannerServerFixture(t)
	cache := filepath.Join(filepath.Dir(s.data), "security-cache")
	calls := 0
	original := s.imageScannerDocker
	s.imageScannerDocker = func(ctx context.Context, args []string, limit int64) (imageScannerCommandResult, error) {
		calls++
		f, err := os.Open(filepath.Join(cache, ".feed-readers.lock"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != syscall.EWOULDBLOCK {
			t.Fatalf("scanner dropped shared feed lease before cleanup: %v", err)
		}
		result, e := original(ctx, args, limit)
		if args[4] == "rm" {
			if err := os.WriteFile(filepath.Join(cache, "trivy/db/trivy.db"), []byte("drift"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		return result, e
	}
	if findings, updated, err := s.scan(context.Background(), workspace, sourceScannerFixtureInput(t, s)); err == nil || findings != nil || updated != "" || calls < 8 || !scanner.removed || imageScannerPriorClear(s.data) != nil {
		t.Fatal("output escaped final feed check or exact cleanup failed")
	}
}
