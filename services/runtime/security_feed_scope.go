package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// A scope binds one acceptance decision, not an installation-wide scan batch.
// It owns no flock between readers. Each reader still holds its ordinary lease
// through exact container cleanup; promotion between reads invalidates the scope.
type securityFeedScopeKey struct{}

type securityFeedScope struct {
	root, cache string
	before      imageScannerFeedEvidence
	identities  map[string]os.FileInfo
	deadline    time.Time
}

func (scope *securityFeedScope) valid(ctx context.Context, root, cache string) bool {
	return scope != nil && ctx.Err() == nil && time.Now().Before(scope.deadline) &&
		scope.root == root && scope.cache == cache
}

func securityFeedScopeMatch(ctx context.Context, lease *securityFeedLease) error {
	value := ctx.Value(securityFeedScopeKey{})
	if value == nil {
		return nil // A standalone reader retains the existing per-scan contract.
	}
	scope, ok := value.(*securityFeedScope)
	if !ok || lease == nil || !scope.valid(ctx, lease.root, lease.cache) ||
		!reflect.DeepEqual(scope.before, lease.before) ||
		!securityFeedSameIdentities(scope.identities, lease.identities) {
		return imageScannerUnavailable
	}
	return nil
}

func (s *server) beginSecurityFeedScope(ctx context.Context) (context.Context, context.CancelFunc, error) {
	cache := env("SECURITY_CACHE_DIR", filepath.Join(filepath.Dir(s.data), "security-cache"))
	if value := ctx.Value(securityFeedScopeKey{}); value != nil {
		scope, ok := value.(*securityFeedScope)
		if !ok || !scope.valid(ctx, s.data, cache) {
			return ctx, func() {}, imageScannerUnavailable
		}
		return ctx, func() {}, nil // Connector helpers inherit their caller's scope.
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Minute)
	lease, err := holdSecurityFeed(bounded, s.data, cache)
	if err != nil {
		cancel()
		return ctx, func() {}, imageScannerUnavailable
	}
	deadline, ok := bounded.Deadline()
	scope := &securityFeedScope{root: s.data, cache: cache, before: lease.before,
		identities: lease.identities, deadline: deadline}
	if closeError := lease.Close(); !ok || closeError != nil || bounded.Err() != nil {
		cancel()
		return ctx, func() {}, imageScannerUnavailable
	}
	return context.WithValue(bounded, securityFeedScopeKey{}, scope), cancel, nil
}

func securityFeedScopeUpdatedAt(ctx context.Context) (string, error) {
	scope, ok := ctx.Value(securityFeedScopeKey{}).(*securityFeedScope)
	if !ok || scope == nil || !scope.valid(ctx, scope.root, scope.cache) {
		return "", imageScannerUnavailable
	}
	return scope.before.UpdatedAt, nil
}

// Recheck immediately before the caller accepts its aggregate. This final lease
// is short and independent; callers never retain it across packaging or routing.
func checkSecurityFeedScope(ctx context.Context) (updated string, err error) {
	scope, ok := ctx.Value(securityFeedScopeKey{}).(*securityFeedScope)
	if !ok || scope == nil || !scope.valid(ctx, scope.root, scope.cache) {
		return "", imageScannerUnavailable
	}
	lease, err := holdSecurityFeed(ctx, scope.root, scope.cache)
	if err != nil {
		return "", imageScannerUnavailable
	}
	return finishSecurityFeedScope(ctx, lease)
}

func finishSecurityFeedScope(ctx context.Context, lease *securityFeedLease) (updated string, err error) {
	defer func() {
		if lease.Close() != nil {
			updated, err = "", imageScannerUnavailable
		}
	}()
	after, err := lease.Check(ctx)
	if err != nil || securityFeedScopeMatch(ctx, lease) != nil {
		return "", imageScannerUnavailable
	}
	return after.UpdatedAt, nil
}
