//go:build linux

package exportarchive

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

func openPath(path string, flags int, mode uint32) (*os.File, error) {
	if !core.IsCanonicalPath(path) {
		return nil, errors.New("archive path must be canonical and absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	defer unix.Close(fd)
	leaf := parts[len(parts)-1]
	if path == "/" {
		leaf = "."
	}
	result, err := unix.Openat(fd, leaf, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(result), path), nil
}

func openDirectory(path string) (*os.File, error) {
	return openPath(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
}
func openRegular(path string) (*os.File, error) {
	f, err := openPath(path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("archive input must be an ordinary regular file without symlinks")
	}
	return f, nil
}
func descriptorPath(f *os.File) string { return fmt.Sprintf("/proc/self/fd/%d", f.Fd()) }

func snapshot(f *os.File) (FileState, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return FileState{}, err
	}
	var mount unix.Statx_t
	if err := unix.Statx(int(f.Fd()), "", unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &mount); err != nil {
		return FileState{}, err
	}
	if mount.Mask&unix.STATX_MNT_ID == 0 {
		return FileState{}, errors.New("archive mount identity unavailable")
	}
	return FileState{Identity: core.FilesystemID{Device: uint64(stat.Dev), Inode: stat.Ino}, MountID: mount.Mnt_id, Size: stat.Size, AllocatedBytes: stat.Blocks * 512, Mode: stat.Mode & 07777, UID: stat.Uid, GID: stat.Gid, ModifiedNS: stat.Mtim.Sec*1e9 + stat.Mtim.Nsec, ChangedNS: stat.Ctim.Sec*1e9 + stat.Ctim.Nsec, Links: uint64(stat.Nlink)}, nil
}
func checkExportFile(f *os.File, limit int64) (FileState, error) {
	s, err := snapshot(f)
	if err != nil {
		return s, err
	}
	if s.Size < 0 || s.Size > limit || s.Links != 1 || s.Mode&07000 != 0 {
		return s, errors.New("export is oversized, multiply linked, or has special permission bits")
	}
	n, err := unix.Flistxattr(int(f.Fd()), nil)
	if err != nil || n != 0 {
		return s, errors.New("export has unknown or unsupported extended metadata; retain the original")
	}
	var prefix [16]byte
	n, err = f.ReadAt(prefix[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return s, err
	}
	if n == 16 && string(prefix[:]) == "SQLite format 3\x00" {
		return s, errors.New("raw databases are not evidence exports")
	}
	return s, nil
}
func requireSpace(f *os.File, bytes uint64) error {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &stat); err != nil {
		return err
	}
	available := stat.Bavail * uint64(stat.Bsize)
	if available < bytes || available-bytes < core.MinimumAllocationReserveBytes {
		return errors.New("archive/restore allocation would cross the 10 GB reserve")
	}
	return nil
}
func publishDirectory(root *os.File, stage, final string) error {
	if filepath.Base(stage) != stage || filepath.Base(final) != final {
		return errors.New("invalid archive publication name")
	}
	if err := unix.Renameat2(int(root.Fd()), stage, int(root.Fd()), final, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return root.Sync()
}

func openChild(parent *os.File, name string, flags int) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("invalid archive child name")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func setMetadata(f *os.File, s FileState) error {
	if err := f.Chown(int(s.UID), int(s.GID)); err != nil {
		return err
	}
	if err := f.Chmod(os.FileMode(s.Mode)); err != nil {
		return err
	}
	times := []unix.Timespec{unix.NsecToTimespec(s.ModifiedNS), unix.NsecToTimespec(s.ModifiedNS)}
	return unix.UtimesNanoAt(int(f.Fd()), "", times, unix.AT_EMPTY_PATH)
}

func removeCreated(parent *os.File, name string, file *os.File) {
	var current, opened unix.Stat_t
	if unix.Fstat(int(file.Fd()), &opened) != nil || unix.Fstatat(int(parent.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return
	}
	if current.Dev == opened.Dev && current.Ino == opened.Ino {
		_ = unix.Unlinkat(int(parent.Fd()), name, 0)
	}
}

func independentContainer(sourceContainer string, archive FileState) (FileState, error) {
	source, err := openDirectory(sourceContainer)
	if err != nil {
		return FileState{}, err
	}
	defer source.Close()
	state, err := snapshot(source)
	if err != nil {
		return state, err
	}
	if state.Identity == archive.Identity || (state.Identity.Device == archive.Identity.Device && state.MountID != archive.MountID) {
		return state, errors.New("source/archive container identity overlaps or same-device mount aliases are ambiguous")
	}
	return state, nil
}
