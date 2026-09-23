//go:build linux

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockApply serializes all confirmed janitor filesystem mutations across
// processes. The lock stays held through the action journal and filesystem op.
func lockApply(stateDir string) (func(), error) {
	path := filepath.Join(stateDir, "apply.lock")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, fmt.Errorf("apply lock has unsafe ownership or permissions")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another janitor apply or restore is active: %w", err)
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
}

func lockRestore(stateDir string) (func(), error) { return lockApply(stateDir) }
