//go:build linux

package collect

import (
	"io/fs"
	"syscall"
	"time"
)

// systemStat exposes the POSIX metadata Go's fs.FileInfo hides.
type systemStat struct {
	Device     uint64
	Inode      uint64
	UID        uint32
	GID        uint32
	AccessedAt time.Time
	Known      bool
}

// statOf extracts filesystem identity and ownership from an lstat result.
func statOf(info fs.FileInfo) systemStat {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return systemStat{}
	}
	return systemStat{
		Device:     uint64(sys.Dev),
		Inode:      sys.Ino,
		UID:        sys.Uid,
		GID:        sys.Gid,
		AccessedAt: time.Unix(sys.Atim.Sec, sys.Atim.Nsec).UTC(),
		Known:      true,
	}
}
