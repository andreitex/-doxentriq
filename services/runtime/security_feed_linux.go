//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

type securityFeedLinuxLock struct {
	path string
	file *os.File
	info syscall.Stat_t
}

type securityFeedLinuxLocks struct {
	cache string
	files []securityFeedLinuxLock
}

func securityFeedLockInfo(path string) (syscall.Stat_t, error) {
	var info syscall.Stat_t
	err := syscall.Lstat(path, &info)
	if err != nil || info.Mode != syscall.S_IFREG|0440 || info.Uid != 0 || info.Gid != 10001 || info.Nlink != 1 || info.Size != 0 {
		return info, imageScannerUnavailable
	}
	return info, nil
}

func securityFeedSameLock(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func securityFeedSameStat(a, b os.FileInfo) bool {
	first, aok := a.Sys().(*syscall.Stat_t)
	last, bok := b.Sys().(*syscall.Stat_t)
	return aok && bok && securityFeedSameLock(*first, *last)
}

func securityFeedSafeMember(info os.FileInfo, directory bool) bool {
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && value.Uid == 0 && value.Mode&0022 == 0 &&
		((directory && value.Mode&syscall.S_IFMT == syscall.S_IFDIR) ||
			(!directory && value.Mode&syscall.S_IFMT == syscall.S_IFREG && value.Nlink == 1))
}

func securityFeedLockDirectories(cache string) error {
	if !filepath.IsAbs(cache) || filepath.Clean(cache) != cache || filepath.Base(cache) != "security-cache" {
		return imageScannerUnavailable
	}
	for _, path := range []string{filepath.Dir(cache), cache} {
		var info syscall.Stat_t
		if syscall.Lstat(path, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFDIR || info.Mode&0022 != 0 || info.Uid != 0 {
			return imageScannerUnavailable
		}
	}
	return nil
}

func (locks *securityFeedLinuxLocks) Check() error {
	if len(locks.files) != 2 || securityFeedLockDirectories(locks.cache) != nil {
		return imageScannerUnavailable
	}
	for _, entry := range locks.files {
		current, err := securityFeedLockInfo(entry.path)
		var opened syscall.Stat_t
		if err != nil || syscall.Fstat(int(entry.file.Fd()), &opened) != nil || !securityFeedSameLock(entry.info, current) || !securityFeedSameLock(entry.info, opened) {
			return imageScannerUnavailable
		}
	}
	return nil
}

func (locks *securityFeedLinuxLocks) Close() error {
	var failure error
	for i := len(locks.files) - 1; i >= 0; i-- {
		if locks.files[i].file.Close() != nil {
			failure = imageScannerUnavailable
		}
	}
	locks.files = nil
	return failure
}

func acquireSecurityFeedLocks(cache string) (securityFeedLocks, error) {
	if securityFeedLockDirectories(cache) != nil {
		return nil, imageScannerUnavailable
	}
	locks := &securityFeedLinuxLocks{cache: cache}
	complete := false
	defer func() {
		if !complete {
			_ = locks.Close()
		}
	}()
	for _, name := range []string{".feed-admission.lock", ".feed-readers.lock"} {
		path := filepath.Join(cache, name)
		info, err := securityFeedLockInfo(path)
		if err != nil {
			return nil, imageScannerUnavailable
		}
		descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, imageScannerUnavailable
		}
		locks.files = append(locks.files, securityFeedLinuxLock{path: path, file: os.NewFile(uintptr(descriptor), path), info: info})
	}
	if locks.Check() != nil || syscall.Flock(int(locks.files[0].file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, imageScannerUnavailable
	}
	// No waiting while holding admission: readers fail closed when a writer is
	// admitted. A future writer holds admission while waiting for readers and
	// must never acquire a per-scanner lock in that scope.
	if syscall.Flock(int(locks.files[1].file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil || locks.Check() != nil || syscall.Flock(int(locks.files[0].file.Fd()), syscall.LOCK_UN) != nil {
		return nil, imageScannerUnavailable
	}
	complete = true
	return locks, nil
}
