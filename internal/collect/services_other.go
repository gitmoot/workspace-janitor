//go:build !linux

package collect

import "os"

func sameUnitFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// The advisory service collector is deployed on Linux. On non-Linux builds,
// os.Root still confines paths, but a concurrent regular-file-to-FIFO swap
// can block here because a portable nonblocking open is unavailable.
// Do not configure systemd definition roots on unsupported hosts.
func openSystemdUnit(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}

func provenSystemdMask() bool { return false }
