//go:build linux

package action

import (
	"fmt"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type gitMetadata struct {
	device uint64
	inode  uint64
	mode   uint32
	atime  time.Time
	mtime  time.Time
}

func captureGitMetadata(path string) (gitMetadata, error) {
	parent, err := openExistingDirNoSymlinks(filepath.Dir(path))
	if err != nil {
		return gitMetadata{}, err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return gitMetadata{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR && stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return gitMetadata{}, fmt.Errorf("Git metadata path %s is not a directory or regular file", path)
	}
	return gitMetadata{device: uint64(stat.Dev), inode: stat.Ino, mode: stat.Mode,
		atime: time.Unix(stat.Atim.Sec, stat.Atim.Nsec), mtime: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec)}, nil
}

func restoreGitMetadata(path string, before gitMetadata) error {
	parent, err := openExistingDirNoSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	name := filepath.Base(path)
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if uint64(stat.Dev) != before.device || stat.Mode&unix.S_IFMT != before.mode&unix.S_IFMT ||
		(stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Ino != before.inode) {
		return fmt.Errorf("Git metadata path %s changed identity or type", path)
	}
	// Git may replace the .git pointer file while rewriting it. Its inode is
	// intentionally not required to match; the verified pointer contents and
	// original mode and timestamps are the preserved contract.
	if err := unix.Fchmodat(parent, name, before.mode&07777, 0); err != nil {
		return err
	}
	stamp := []unix.Timespec{unix.NsecToTimespec(before.atime.UnixNano()), unix.NsecToTimespec(before.mtime.UnixNano())}
	if err := unix.UtimesNanoAt(parent, name, stamp, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := unix.Fsync(parent); err != nil {
		return err
	}
	return nil
}
