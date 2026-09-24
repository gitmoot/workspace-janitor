//go:build linux

package action

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// renameNoReplace anchors both names to opened parent directories and never
// follows the source's final symlink. A collision cannot overwrite a receipt
// or an occupied original location.
func renameNoReplace(from, to string, expected core.FilesystemID) error {
	fromDir, err := openExistingDirNoSymlinks(filepath.Dir(from))
	if err != nil {
		return fmt.Errorf("open source parent: %w", err)
	}
	defer unix.Close(fromDir)
	toDir, err := openExistingDirNoSymlinks(filepath.Dir(to))
	if err != nil {
		return fmt.Errorf("open destination parent: %w", err)
	}
	defer unix.Close(toDir)
	var source, destination unix.Stat_t
	if err := unix.Fstatat(fromDir, filepath.Base(from), &source, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	if uint64(source.Dev) != expected.Device || source.Ino != expected.Inode {
		return fmt.Errorf("source identity changed before rename")
	}
	if err := unix.Fstat(toDir, &destination); err != nil {
		return fmt.Errorf("stat destination parent: %w", err)
	}
	if uint64(source.Dev) != uint64(destination.Dev) {
		return fmt.Errorf("cross-filesystem quarantine is unsupported")
	}
	if err := unix.Renameat2(fromDir, filepath.Base(from), toDir, filepath.Base(to), unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("atomic no-replace rename: %w", err)
	}
	if err := unix.Fstatat(toDir, filepath.Base(to), &destination, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(destination.Dev) != expected.Device || destination.Ino != expected.Inode {
		return fmt.Errorf("moved object identity did not match the checked source: %v", err)
	}
	if err := unix.Fsync(toDir); err != nil {
		return fmt.Errorf("sync destination parent: %w", err)
	}
	if err := unix.Fsync(fromDir); err != nil {
		return fmt.Errorf("sync source parent: %w", err)
	}
	return nil
}

func syncDir(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	return fd.Sync()
}
