//go:build linux

package cli

import (
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// entryCreatedAt is path's birth time, or its inode change time where the
// filesystem records no birth, while path is still the scanned inode.
func entryCreatedAt(path string, id core.FilesystemID) (*time.Time, string) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME|unix.STATX_CTIME|unix.STATX_INO, &st); err != nil {
		return nil, "unavailable"
	}
	if st.Ino != id.Inode || unix.Mkdev(st.Dev_major, st.Dev_minor) != id.Device {
		return nil, "replaced_since_scan"
	}
	at, source := st.Ctime, "ctime"
	if st.Mask&unix.STATX_BTIME != 0 {
		at, source = st.Btime, "birth"
	}
	t := time.Unix(at.Sec, int64(at.Nsec)).UTC()
	return &t, source
}
