//go:build linux

package collect

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// A unit changed in place after it was read is not a proven alias target.
// ctime catches rewrites whose size and mtime were restored.
func sameUnitFile(a, b os.FileInfo) bool {
	if !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	left, okLeft := a.Sys().(*syscall.Stat_t)
	right, okRight := b.Sys().(*syscall.Stat_t)
	return okLeft && okRight && left.Ctim == right.Ctim
}

// O_NONBLOCK prevents a swapped-in FIFO or device from hanging the scanner.
// os.Root confines all path components to the already-opened definition root.
func openSystemdUnit(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
}

// An exact /dev/null link is systemd's documented mask, not a unit file.
// Never read it or accept an arbitrary external target as an alias.
func provenSystemdMask() bool {
	var info unix.Stat_t
	return unix.Lstat("/dev/null", &info) == nil && info.Mode&unix.S_IFMT == unix.S_IFCHR &&
		unix.Major(uint64(info.Rdev)) == 1 && unix.Minor(uint64(info.Rdev)) == 3
}
