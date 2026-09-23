//go:build linux

package cli

import (
	"fmt"
	"os"
	"syscall"
)

type diskVolume struct {
	Device     uint64
	FreeBytes  uint64
	TotalBytes uint64
}

func measureDisk(root string) (diskVolume, error) {
	info, err := os.Stat(root)
	if err != nil {
		return diskVolume{}, err
	}
	if !info.IsDir() {
		return diskVolume{}, fmt.Errorf("%s is not a directory", root)
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return diskVolume{}, fmt.Errorf("filesystem identity unavailable for %s", root)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(root, &stat); err != nil {
		return diskVolume{}, err
	}
	if stat.Blocks == 0 || stat.Bsize <= 0 || stat.Bavail > stat.Blocks ||
		stat.Blocks > ^uint64(0)/uint64(stat.Bsize) {
		return diskVolume{}, fmt.Errorf("invalid filesystem capacity for %s", root)
	}
	return diskVolume{Device: uint64(identity.Dev), FreeBytes: stat.Bavail * uint64(stat.Bsize),
		TotalBytes: stat.Blocks * uint64(stat.Bsize)}, nil
}
