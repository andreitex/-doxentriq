package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"time"
)

// The lock files are provisioned separately, once, outside replaceable database
// directories. Readers never create them. A lease says nothing about scanner
// cleanup after process death, feed provenance, or writer eligibility.
type securityFeedLocks interface {
	Check() error
	Close() error
}

type securityFeedLease struct {
	locks       securityFeedLocks
	root, cache string
	before      imageScannerFeedEvidence
	identities  map[string]os.FileInfo
}

func securityFeedIdentities(cache string) (map[string]os.FileInfo, error) {
	values := map[string]os.FileInfo{}
	for _, relative := range []string{".", "trivy", "trivy/db", "trivy/db/metadata.json", "trivy/db/trivy.db", "trivy/java-db", "trivy/java-db/metadata.json", "trivy/java-db/trivy-java.db"} {
		info, err := os.Lstat(filepath.Join(cache, relative))
		if os.IsNotExist(err) && (relative == "trivy/java-db" || relative == "trivy/java-db/metadata.json" || relative == "trivy/java-db/trivy-java.db") {
			values[relative] = nil
			continue
		}
		directory := relative == "." || relative == "trivy" || relative == "trivy/db" || relative == "trivy/java-db"
		if err != nil || !securityFeedSafeMember(info, directory) {
			return nil, imageScannerUnavailable
		}
		values[relative] = info
	}
	if (values["trivy/java-db"] == nil) != (values["trivy/java-db/metadata.json"] == nil) || (values["trivy/java-db"] == nil) != (values["trivy/java-db/trivy-java.db"] == nil) {
		return nil, imageScannerUnavailable
	}
	return values, nil
}

func securityFeedSameIdentities(before, after map[string]os.FileInfo) bool {
	if len(before) != len(after) {
		return false
	}
	for path, first := range before {
		last, present := after[path]
		if !present || (first == nil) != (last == nil) {
			return false
		}
		if first != nil && (!os.SameFile(first, last) || !securityFeedSameStat(first, last)) {
			return false
		}
	}
	return true
}

var securityFeedStamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

func securityFeedMetadata(raw []byte, version int, now time.Time) (string, error) {
	if len(raw) < 1 || len(raw) > 65536 || now.IsZero() {
		return "", imageScannerUnavailable
	}
	m, err := imageScannerJSON(raw)
	if err != nil || len(m) != 4 || !scannerNumber(m["Version"], int64(version)) {
		return "", imageScannerUnavailable
	}
	stamps := make([]time.Time, 0, 3)
	for _, key := range []string{"UpdatedAt", "NextUpdate", "DownloadedAt"} {
		text := scannerString(m[key])
		stamp, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || stamp.IsZero() || !securityFeedStamp.MatchString(text) {
			return "", imageScannerUnavailable
		}
		stamps = append(stamps, stamp)
	}
	updated, next, downloaded := stamps[0], stamps[1], stamps[2]
	if now.Sub(updated) > 24*time.Hour || updated.After(now.Add(time.Minute)) || !next.After(updated) || !next.After(now) || downloaded.After(now.Add(time.Minute)) || downloaded.Before(updated.Add(-time.Minute)) {
		return "", imageScannerUnavailable
	}
	return updated.UTC().Format(time.RFC3339Nano), nil
}

func holdSecurityFeed(ctx context.Context, root, cache string) (*securityFeedLease, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if ctx.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || cache != filepath.Join(filepath.Dir(root), "security-cache") {
		return nil, imageScannerUnavailable
	}
	locks, err := acquireSecurityFeedLocks(cache)
	if err != nil {
		return nil, imageScannerUnavailable
	}
	identities, err := securityFeedIdentities(cache)
	if err != nil {
		_ = locks.Close()
		return nil, imageScannerUnavailable
	}
	before, err := imageScannerFeed(ctx, root, cache)
	afterIDs, idErr := securityFeedIdentities(cache)
	if err != nil || idErr != nil || ctx.Err() != nil || !securityFeedSameIdentities(identities, afterIDs) || locks.Check() != nil {
		_ = locks.Close()
		return nil, imageScannerUnavailable
	}
	lease := &securityFeedLease{locks: locks, root: root, cache: cache, before: before, identities: afterIDs}
	if securityFeedScopeMatch(ctx, lease) != nil {
		_ = lease.Close()
		return nil, imageScannerUnavailable
	}
	return lease, nil
}

func (lease *securityFeedLease) Check(ctx context.Context) (imageScannerFeedEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if lease == nil || lease.locks == nil || lease.locks.Check() != nil {
		return imageScannerFeedEvidence{}, imageScannerUnavailable
	}
	after, err := imageScannerFeed(ctx, lease.root, lease.cache)
	afterIDs, idErr := securityFeedIdentities(lease.cache)
	if err != nil || idErr != nil || ctx.Err() != nil || !securityFeedSameIdentities(lease.identities, afterIDs) || !reflect.DeepEqual(after, lease.before) || lease.locks.Check() != nil {
		return imageScannerFeedEvidence{}, imageScannerUnavailable
	}
	return after, nil
}

func (lease *securityFeedLease) Close() error {
	if lease == nil || lease.locks == nil {
		return imageScannerUnavailable
	}
	err := lease.locks.Close()
	lease.locks = nil
	return err
}
