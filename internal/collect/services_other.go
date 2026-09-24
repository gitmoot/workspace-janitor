//go:build !linux

package collect

import "os"

func sameUnitFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func openSystemdUnit(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}

func provenSystemdMask() bool { return false }
