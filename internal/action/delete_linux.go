//go:build linux

package action

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

func fileIdentity(info os.FileInfo) core.FilesystemID {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return core.FilesystemID{}
	}
	return core.FilesystemID{Device: uint64(stat.Dev), Inode: stat.Ino}
}

// deleteAnchored never follows symlinks and never resolves a child outside the
// opened quarantine parent. A partial recursive deletion remains a recorded
// quarantined item requiring investigation; it is never retried blindly.
func deleteAnchored(path string, expected core.FilesystemID) error {
	parent, err := openExistingDirNoSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	name := filepath.Base(path)
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if expected.Device != uint64(stat.Dev) || expected.Inode != stat.Ino {
		return fmt.Errorf("quarantined identity changed")
	}
	if err := removeAt(parent, name, uint64(stat.Dev)); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

// verifyDeletionTree checks mount boundaries before mutation. It uses the
// same no-follow descriptor traversal as removeAt but retains no inode map
// and no directory-sized listing in memory.
func verifyDeletionTree(ctx context.Context, path string, expected core.FilesystemID) error {
	parent, err := openExistingDirNoSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	name := filepath.Base(path)
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if expected.Device != uint64(stat.Dev) || expected.Inode != stat.Ino {
		return fmt.Errorf("quarantined identity changed")
	}
	return verifyAt(ctx, parent, name, expected.Device)
}

func verifyAt(ctx context.Context, parent int, name string, device uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if uint64(stat.Dev) != device {
		return fmt.Errorf("mounted child %s crossed the deletion filesystem", name)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		unix.Close(fd)
		return err
	}
	if stat.Dev != opened.Dev || stat.Ino != opened.Ino {
		unix.Close(fd)
		return fmt.Errorf("directory changed during deletion")
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	for {
		children, err := file.Readdirnames(128)
		if err != nil && err != io.EOF {
			return err
		}
		for _, child := range children {
			if err := verifyAt(ctx, fd, child, device); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func removeAt(parent int, name string, device uint64) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if uint64(stat.Dev) != device {
		return fmt.Errorf("mounted child %s crossed the deletion filesystem", name)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parent, name, 0)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		unix.Close(fd)
		return err
	}
	if stat.Dev != opened.Dev || stat.Ino != opened.Ino {
		unix.Close(fd)
		return fmt.Errorf("directory changed during deletion")
	}
	file := os.NewFile(uintptr(fd), name)
	for {
		var children []string
		children, err = file.Readdirnames(128)
		if err != nil && err != io.EOF {
			break
		}
		for _, child := range children {
			if err = removeAt(fd, child, device); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
		if len(children) == 0 {
			break
		}
	}
	if err == io.EOF {
		err = nil
	}
	if err == nil {
		err = unix.Fsync(fd)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
}
