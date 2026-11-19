//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func feedScopeFixture(t *testing.T) (*server, string) {
	t.Helper()
	root, cache := nativeFeedFixture(t)
	t.Setenv("SECURITY_CACHE_DIR", cache)
	return &server{data: root}, cache
}

// A synthetic writer uses the actual two-lock order. Failure to acquire is a
// regression: report scopes must not retain a shared lease between readers.
func feedScopePromotion(t *testing.T, cache string, mutate func()) {
	t.Helper()
	for _, name := range []string{".feed-admission.lock", ".feed-readers.lock"} {
		f, err := os.Open(filepath.Join(cache, name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("scope retained an outer reader lease: %v", err)
		}
	}
	mutate()
}

func TestSecurityFeedScopeSeparatesReportsAndRejectsMixedBytes(t *testing.T) {
	s, cache := feedScopeFixture(t)
	ctx, cancel, err := s.beginSecurityFeedScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	updated, err := checkSecurityFeedScope(ctx)
	if err != nil || updated == "" {
		t.Fatal("unchanged scope unavailable", err)
	}
	child, childCancel, err := s.beginSecurityFeedScope(ctx)
	if err != nil || child != ctx {
		t.Fatal("nested caller replaced expected feed")
	}
	childCancel()
	if ctx.Err() != nil {
		t.Fatal("nested caller cancelled parent")
	}
	feedScopePromotion(t, cache, func() {
		if err := os.WriteFile(filepath.Join(cache, "trivy/db/trivy.db"), []byte("same timestamp; new advisory bytes"), 0644); err != nil {
			t.Fatal(err)
		}
	})
	if lease, err := holdSecurityFeed(ctx, s.data, cache); err == nil {
		lease.Close()
		t.Fatal("mixed feed admitted")
	}
	if _, err := checkSecurityFeedScope(ctx); err == nil {
		t.Fatal("changed aggregate accepted")
	}
	next, stop, err := s.beginSecurityFeedScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if got, err := checkSecurityFeedScope(next); err != nil || got != updated {
		t.Fatal("independent new report unavailable", err)
	}
}

func TestSecurityFeedScopeRejectsIdentityMembershipExpiryAndCancellation(t *testing.T) {
	for _, kind := range []string{"inode", "java-membership", "expiry", "cancelled", "deadline", "foreign-root", "typed-nil"} {
		t.Run(kind, func(t *testing.T) {
			s, cache := feedScopeFixture(t)
			ctx, cancel, err := s.beginSecurityFeedScope(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			switch kind {
			case "inode":
				feedScopePromotion(t, cache, func() {
					p := filepath.Join(cache, "trivy/db/trivy.db")
					b, e := os.ReadFile(p)
					if e != nil || os.Rename(p, p+".retained") != nil || os.WriteFile(p, b, 0644) != nil {
						t.Fatal("inode fixture")
					}
				})
			case "java-membership":
				feedScopePromotion(t, cache, func() {
					m := feedMetadataFixture(time.Now())
					m["Version"] = 1
					if atomicJSON(filepath.Join(cache, "trivy/java-db/metadata.json"), m) != nil || os.WriteFile(filepath.Join(cache, "trivy/java-db/trivy-java.db"), []byte("java database"), 0644) != nil {
						t.Fatal("java fixture")
					}
				})
			case "expiry":
				feedScopePromotion(t, cache, func() {
					m := feedMetadataFixture(time.Now())
					m["NextUpdate"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
					if atomicJSON(filepath.Join(cache, "trivy/db/metadata.json"), m) != nil {
						t.Fatal("expiry fixture")
					}
				})
			case "cancelled":
				cancel()
			case "deadline":
				ctx.Value(securityFeedScopeKey{}).(*securityFeedScope).deadline = time.Now().Add(-time.Second)
			case "foreign-root":
				other := &server{data: filepath.Join(filepath.Dir(s.data), "other")}
				if _, stop, e := other.beginSecurityFeedScope(ctx); e == nil {
					stop()
					t.Fatal("scope crossed runtime root")
				}
				return
			case "typed-nil":
				ctx = context.WithValue(ctx, securityFeedScopeKey{}, (*securityFeedScope)(nil))
			}
			if _, e := checkSecurityFeedScope(ctx); e == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
}

func TestSecurityFeedScopeSourceAndImageReadersCannotMixSnapshots(t *testing.T) {
	s, _, workspace := sourceScannerServerFixture(t)
	base := filepath.Dir(s.data)
	cache := filepath.Join(base, "security-cache")
	credentials := filepath.Join(s.data, "registry.json")
	if os.WriteFile(credentials, []byte(`{"username":"fixture","password":"fixture"}`), 0600) != nil {
		t.Fatal("credentials fixture")
	}
	t.Setenv("REGISTRY_CREDENTIALS_FILE", credentials)
	installTrustedServiceTestFixture(t, s, "autosoft_artifact", "registry")
	image := installImageScannerServerFixture(t, s, base, "")
	source := installSourceScannerServerFixture(t, s, base)
	ctx, cancel, e := s.beginSecurityFeedScope(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer cancel()
	findings, _, e := s.scan(ctx, workspace, sourceScannerFixtureInput(t, s))
	if e != nil || len(findings) != 1 || !source.removed {
		t.Fatal("first actual source reader", e)
	}
	feedScopePromotion(t, cache, func() {
		if os.WriteFile(filepath.Join(cache, "trivy/db/trivy.db"), []byte("replacement"), 0644) != nil {
			t.Fatal("feed mutation")
		}
	})
	if _, e = s.scanImage(ctx, "registry:5000/apps/app1@sha256:"+strings.Repeat("a", 64)); e == nil || image.created {
		t.Fatal("next image reader started on another snapshot")
	}
	if len(findings) != 1 || findings[0].Severity != "MEDIUM" {
		t.Fatal("prior finding lost")
	}
	if imageScannerPriorClear(s.data) != nil {
		t.Fatal("refused reader left uncertain lifecycle")
	}
}

func TestSecurityFeedScopeSourceRefusalBeforeAnyContainer(t *testing.T) {
	s, f, workspace := sourceScannerServerFixture(t)
	ctx, cancel, e := s.beginSecurityFeedScope(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer cancel()
	feedScopePromotion(t, filepath.Join(filepath.Dir(s.data), "security-cache"), func() { cancel() })
	var pending error
	findings, _, e := s.scanVerificationSource(ctx, workspace, sourceScannerFixtureInput(t, s), &pending)
	if e == nil || len(findings) != 0 || f.created || sourceScannerPreservesWorkspace(pending, workspace) {
		t.Fatal("normal refusal lost cancellation/cleanup boundary")
	}
	if _, e = os.Stat(workspace); e != nil {
		t.Fatal("reader mutated input")
	}
}

type scopeCloseFailure struct{ securityFeedLocks }

func (f scopeCloseFailure) Close() error {
	_ = f.securityFeedLocks.Close()
	return imageScannerUnavailable
}

func TestSecurityFeedScopeFinalCloseFailureClearsAcceptance(t *testing.T) {
	s, cache := feedScopeFixture(t)
	ctx, cancel, err := s.beginSecurityFeedScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	lease, err := holdSecurityFeed(ctx, s.data, cache)
	if err != nil {
		t.Fatal(err)
	}
	// The real protected locks and full database Check succeed. Only final Close
	// reports an injected uncertain outcome after releasing its owned resources.
	lease.locks = scopeCloseFailure{lease.locks}
	if updated, err := finishSecurityFeedScope(ctx, lease); err == nil || updated != "" {
		t.Fatal("failed final Close accepted a completed scope")
	}
	feedScopePromotion(t, cache, func() {})
}
