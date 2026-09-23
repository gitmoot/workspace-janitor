//go:build linux

package action

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// createReceiptDir walks from / through directory descriptors, refusing
// symlink components. A pre-existing symlink in a quarantine path must not
// redirect a manifest or a future move to a different tree.
func createReceiptDir(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("receipt directory must be absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { unix.Close(fd) }()
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			if err = unix.Mkdirat(fd, part, 0700); err != nil {
				return fmt.Errorf("create receipt component %s: %w", part, err)
			}
			if err = unix.Fsync(fd); err != nil {
				return fmt.Errorf("sync new receipt parent: %w", err)
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return fmt.Errorf("open receipt component %s without symlinks: %w", part, err)
		}
		unix.Close(fd)
		fd = next
	}
	return unix.Fsync(fd)
}

// openExistingDirNoSymlinks anchors every path component from /, not only
// the final component of the parent. The caller owns the returned descriptor.
func openExistingDirNoSymlinks(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("directory path must be absolute and canonical: %s", path)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open directory component %q without symlinks: %w", part, err)
		}
		fd = next
	}
	return fd, nil
}
