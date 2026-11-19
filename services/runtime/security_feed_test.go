package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixtureProtectedFeedLocks(t *testing.T, cache string) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("the real root-owned feed lease is exercised by the privileged native component suite")
	}
	for _, name := range []string{".feed-admission.lock", ".feed-readers.lock"} {
		path := filepath.Join(cache, name)
		if os.WriteFile(path, nil, 0440) != nil || os.Chown(path, 0, 10001) != nil || os.Chmod(path, 0440) != nil {
			t.Fatal("protected synthetic lock unavailable")
		}
	}
}

func feedMetadataFixture(now time.Time) map[string]any {
	return map[string]any{"Version": 2, "UpdatedAt": now.Add(-time.Hour).UTC().Format(time.RFC3339Nano), "NextUpdate": now.Add(time.Hour).UTC().Format(time.RFC3339Nano), "DownloadedAt": now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)}
}

func TestFeedMetadataExactExpiryAndAge(t *testing.T) {
	now := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, field string
		value       any
		accepted    bool
	}{
		{"valid", "NextUpdate", now.Add(time.Hour).Format(time.RFC3339Nano), true},
		{"next_equal", "NextUpdate", now.Format(time.RFC3339Nano), false},
		{"next_one_ns_after", "NextUpdate", now.Add(time.Nanosecond).Format(time.RFC3339Nano), true},
		{"next_one_ns_before", "NextUpdate", now.Add(-time.Nanosecond).Format(time.RFC3339Nano), false},
		{"exact_age", "UpdatedAt", now.Add(-24 * time.Hour).Format(time.RFC3339Nano), true},
		{"age_one_ns_over", "UpdatedAt", now.Add(-24*time.Hour - time.Nanosecond).Format(time.RFC3339Nano), false},
		{"bad_schema", "Version", 1, false},
		{"boolean_schema", "Version", true, false},
		{"wrong_case", "version", 2, false},
		{"offset_not_utc", "NextUpdate", "2026-11-08T15:00:00+00:00", false},
		{"bad_calendar", "NextUpdate", "2026-11-31T15:00:00Z", false},
		{"download_future", "DownloadedAt", now.Add(time.Minute + time.Nanosecond).Format(time.RFC3339Nano), false},
		{"download_before_publication", "DownloadedAt", now.Add(-time.Hour - time.Minute - time.Nanosecond).Format(time.RFC3339Nano), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := feedMetadataFixture(now)
			value[test.field] = test.value
			raw, _ := json.Marshal(value)
			_, err := securityFeedMetadata(raw, 2, now)
			if (err == nil) != test.accepted {
				t.Fatalf("freshness decision differs: %v", err)
			}
		})
	}
}

func TestFeedMetadataRejectsAmbiguousAndOversizedJSON(t *testing.T) {
	now := time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)
	raw, _ := json.Marshal(feedMetadataFixture(now))
	for _, text := range []string{"", strings.Repeat(" ", 65537), strings.Replace(string(raw), `"Version":2`, `"Version":2,"Version":2`, 1), strings.Replace(string(raw), `"Version":2`, `"Version":2.0`, 1), strings.Replace(string(raw), `"Version":2`, `"Version":2,"version":2`, 1)} {
		if _, err := securityFeedMetadata([]byte(text), 2, now); err == nil {
			t.Fatal("ambiguous feed metadata admitted")
		}
	}
}
