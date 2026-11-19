//go:build !linux

package main

import "os"

// Unsupported hosts may build and inspect source but cannot attest a native
// shared feed lease. There is no process-local replacement or test bypass.
func acquireSecurityFeedLocks(cache string) (securityFeedLocks, error) {
	return nil, imageScannerUnavailable
}

func securityFeedSameStat(a, b os.FileInfo) bool { return false }

func securityFeedSafeMember(info os.FileInfo, directory bool) bool { return false }
