//go:build !linux

package collect

import (
	"io/fs"
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

// statOf reports unknown identity on platforms this release does not target.
// Callers treat an unknown identity as missing evidence, never as a clean
// result, so an unsupported platform cannot silently look safe.
func statOf(fs.FileInfo) systemStat { return systemStat{} }

var _ = time.Time{}
