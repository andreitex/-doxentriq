package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConnectorDispatchRejectsAmbiguousRetainedAdapterTypes(t *testing.T) {
	s := &server{data: t.TempDir()}
	appID, connectionID := "12345678-1234-1234-1234-123456789012", "12345678-1234-1234-1234-123456789013"
	for _, kind := range []string{"none", "samba", "filesystem", "ambiguous"} {
		t.Run(kind, func(t *testing.T) {
			s.data = t.TempDir()
			paths := []string{}
			if kind == "samba" || kind == "ambiguous" {
				paths = append(paths, s.connectorStatePath(appID, connectionID))
			}
			if kind == "filesystem" || kind == "ambiguous" {
				paths = append(paths, s.filesystemStatePath(appID, connectionID))
			}
			for _, path := range paths {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("opaque-retained-approval"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fs, err := s.filesystemConnection(appID, connectionID)
			if kind == "ambiguous" {
				if err == nil {
					t.Fatal("Ambiguous adapter selection accepted")
				}
				return
			}
			if err != nil || fs != (kind == "filesystem") {
				t.Fatalf("Adapter type selection unavailable: %v %v", fs, err)
			}
		})
	}
}

func TestConnectorDispatchRejectsUnsafeApprovalFilesAndIdentities(t *testing.T) {
	s := &server{data: t.TempDir()}
	appID, connectionID := "12345678-1234-1234-1234-123456789012", "12345678-1234-1234-1234-123456789013"
	path := s.connectorStatePath(appID, connectionID)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.filesystemConnection(appID, connectionID); err == nil {
		t.Fatal("Approval directory accepted as retained file")
	}
	for _, id := range []string{"../../secret", "", "12345678-1234-1234-1234-123456789012/other"} {
		if _, err := s.filesystemConnection(appID, id); err == nil {
			t.Fatal("Malformed connector identity accepted")
		}
	}
}
