//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// lockApply serializes all confirmed janitor filesystem mutations across
// processes. The lock stays held through the action journal and filesystem op.
func lockApply(stateDir string) (func(), error) {
	fd, file, err := openLockFile(filepath.Join(stateDir, "apply.lock"), "apply lock")
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another janitor apply or restore is active: %w", err)
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
}

// lockScan serializes the cycle's scan, plan and quarantine with the
// watcher's scans. Apply accepts only a plan bound to the latest completed
// scan, so a watcher scan recorded between the cycle's plan and its apply
// makes the apply refuse the plan. Both holders are short, so a second
// holder waits rather than failing, until ctx ends.
func lockScan(ctx context.Context, stateDir string) (func(), error) {
	// A first cycle can run before anything else has created the state dir.
	if err := config.EnsureDir(stateDir); err != nil {
		return nil, err
	}
	fd, file, err := openLockFile(filepath.Join(stateDir, "scan.lock"), "scan lock")
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			file.Close()
			return nil, fmt.Errorf("scan lock: %w", err)
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// openLockFile opens a lock file that only the current user can have created.
func openLockFile(path, name string) (int, *os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return 0, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return 0, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return 0, nil, fmt.Errorf("%s has unsafe ownership or permissions", name)
	}
	return fd, file, nil
}

func lockRestore(stateDir string) (func(), error) { return lockApply(stateDir) }
