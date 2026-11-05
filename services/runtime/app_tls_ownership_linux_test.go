//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRenewedSecretRetainsApplicationOwnership(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.key")
	if err := atomicTLSFile(file, []byte("replacement fixture key")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	wantUID, wantGID := uint32(os.Geteuid()), uint32(os.Getegid())
	if os.Geteuid() == 0 {
		wantUID, wantGID = 10001, 10001
	}
	if info.Mode().Perm() != 0400 || stat.Uid != wantUID || stat.Gid != wantGID {
		t.Fatal("Renewed scoped secret has incorrect application permissions or ownership")
	}
}
