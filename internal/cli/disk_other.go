//go:build !linux

package cli

import "errors"

type diskVolume struct {
	Device     uint64
	FreeBytes  uint64
	TotalBytes uint64
}

func measureDisk(string) (diskVolume, error) {
	return diskVolume{}, errors.New("disk pressure measurement requires Linux")
}
