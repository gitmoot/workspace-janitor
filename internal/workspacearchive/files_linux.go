//go:build linux

package workspacearchive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// beneath confines resolution to one tree: no symlinks, no magic links, no
// mount crossings and no escape above the anchoring descriptor.
const beneath = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

type contextReader struct {
	context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

// renameat2 is unix.Renameat2; tests replace it to model a filesystem that
// lacks RENAME_NOREPLACE.
var renameat2 = unix.Renameat2

// publishNoReplace moves the regular file from into to and never replaces an
// existing name. Some filesystems, sshfs among them, reject RENAME_NOREPLACE
// with EINVAL; a plain rename there would silently overwrite. For a regular
// file a hard link gives the same guarantee, because linkat refuses an
// existing name, and removing the staged name then completes the move.
func publishNoReplace(fromDir int, from string, toDir int, to string) error {
	err := renameat2(fromDir, from, toDir, to, unix.RENAME_NOREPLACE)
	if !errors.Is(err, unix.EINVAL) {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(fromDir, from, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("filesystem lacks no-replace rename and %s is not a regular file", from)
	}
	if err := unix.Linkat(fromDir, from, toDir, to, 0); err != nil {
		return fmt.Errorf("no-replace link (filesystem lacks no-replace rename): %w", err)
	}
	return unix.Unlinkat(fromDir, from, 0)
}

type spaceWriter struct {
	root    *os.File
	reserve uint64
	out     io.Writer
}

func (w spaceWriter) Write(p []byte) (int, error) {
	if err := requireSpace(w.root, w.reserve+uint64(len(p))); err != nil {
		return 0, err
	}
	return w.out.Write(p)
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// state is one statx observation. Device numbers come from statx alone so
// every comparison in this package uses one encoding.
type state struct {
	id      core.FilesystemID
	mountID uint64
	mode    uint32
	uid     uint32
	gid     uint32
	size    int64
	mtimeNS int64
	ctimeNS int64
	nlink   uint32
}

func (s state) kind() uint32 { return s.mode & unix.S_IFMT }

func statxAt(dirfd int, name string, flags int) (state, error) {
	var sx unix.Statx_t
	if err := unix.Statx(dirfd, name, flags|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &sx); err != nil {
		return state{}, err
	}
	if sx.Mask&unix.STATX_MNT_ID == 0 {
		return state{}, errors.New("mount identity unavailable; retain the original")
	}
	return state{
		id:      core.FilesystemID{Device: unix.Mkdev(sx.Dev_major, sx.Dev_minor), Inode: sx.Ino},
		mountID: sx.Mnt_id,
		mode:    uint32(sx.Mode),
		uid:     sx.Uid,
		gid:     sx.Gid,
		size:    int64(sx.Size),
		mtimeNS: sx.Mtime.Sec*1e9 + int64(sx.Mtime.Nsec),
		ctimeNS: sx.Ctime.Sec*1e9 + int64(sx.Ctime.Nsec),
		nlink:   sx.Nlink,
	}, nil
}

func fstate(f *os.File) (state, error) { return statxAt(int(f.Fd()), "", unix.AT_EMPTY_PATH) }

// openPath walks an absolute canonical path component by component and
// refuses any symlink on the way.
func openPath(path string, flags int) (*os.File, error) {
	if !core.IsCanonicalPath(path) {
		return nil, errors.New("workspace archive path must be canonical and absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if path == "/" {
		return os.NewFile(uintptr(fd), path), nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open %s: %w", path, openErr)
		}
		fd = next
	}
	defer unix.Close(fd)
	result, err := unix.Openat(fd, parts[len(parts)-1], flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return os.NewFile(uintptr(result), path), nil
}

func openDirectory(path string) (*os.File, error) {
	return openPath(path, unix.O_RDONLY|unix.O_DIRECTORY)
}

func descriptorPath(f *os.File) string { return fmt.Sprintf("/proc/self/fd/%d", f.Fd()) }

// openBeneath opens rel strictly inside root. O_PATH|O_NOFOLLOW returns a
// descriptor for a trailing symlink itself.
func openBeneath(root *os.File, rel string, flags int) (*os.File, error) {
	if rel != "." && !validMemberPath(rel) {
		return nil, fmt.Errorf("invalid archive member path %q", rel)
	}
	fd, err := unix.Openat2(int(root.Fd()), rel, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: beneath})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", rel, err)
	}
	return os.NewFile(uintptr(fd), rel), nil
}

func statBeneath(root *os.File, rel string) (state, error) {
	f, err := openBeneath(root, rel, unix.O_PATH|unix.O_NOFOLLOW)
	if err != nil {
		return state{}, err
	}
	defer f.Close()
	return fstate(f)
}

func openChild(parent *os.File, name string, flags int) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("invalid archive child name")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

func createChild(parent *os.File, name string) (*os.File, error) {
	return openChild(parent, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
}

// openRegularChild opens one existing single-link regular file.
func openRegularChild(parent *os.File, name string) (*os.File, state, error) {
	f, err := openChild(parent, name, unix.O_RDONLY)
	if err != nil {
		return nil, state{}, err
	}
	st, err := fstate(f)
	if err != nil || st.kind() != unix.S_IFREG || st.nlink != 1 {
		f.Close()
		return nil, st, fmt.Errorf("%s must be an ordinary single-link regular file", name)
	}
	return f, st, nil
}

func childExists(parent *os.File, name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return false, err
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

// validMemberPath accepts only clean relative paths that stay inside the tree.
func validMemberPath(path string) bool {
	if path == "" || path == "." || strings.HasPrefix(path, "/") || strings.ContainsRune(path, 0) || filepath.Clean(path) != path {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}

func joinMember(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

// setMetadata applies archived ownership, permissions and modification time
// to an open regular file or directory. Ownership first: chown clears setid.
func setMetadata(f *os.File, m Member) error {
	if err := unix.Fchown(int(f.Fd()), int(m.UID), int(m.GID)); err != nil {
		return fmt.Errorf("restore ownership of %s: %w", m.Path, err)
	}
	if err := unix.Fchmod(int(f.Fd()), m.Mode); err != nil {
		return fmt.Errorf("restore mode of %s: %w", m.Path, err)
	}
	times := []unix.Timespec{unix.NsecToTimespec(m.ModifiedNS), unix.NsecToTimespec(m.ModifiedNS)}
	return unix.UtimesNanoAt(int(f.Fd()), "", times, unix.AT_EMPTY_PATH)
}

func setLinkMetadata(parent *os.File, name string, m Member) error {
	if err := unix.Fchownat(int(parent.Fd()), name, int(m.UID), int(m.GID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("restore ownership of %s: %w", m.Path, err)
	}
	times := []unix.Timespec{unix.NsecToTimespec(m.ModifiedNS), unix.NsecToTimespec(m.ModifiedNS)}
	return unix.UtimesNanoAt(int(parent.Fd()), name, times, unix.AT_SYMLINK_NOFOLLOW)
}
