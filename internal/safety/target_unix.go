//go:build linux

package safety

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ResolveTarget inspects a destination directory: which filesystem it is on
// and how much space it has.
//
// A destination that cannot be inspected comes back with Known false, which
// the guards treat as a refusal. Reporting "unknown" is the point: a
// mutation must never proceed on an unmeasured destination.
func ResolveTarget(dir string) Target {
	target := Target{Dir: dir}
	if dir == "" {
		target.Detail = "no destination is configured"
		return target
	}
	// A quarantine directory that does not exist yet is not an unknown: it
	// will be created inside its nearest existing ancestor, which is the
	// filesystem whose device and free space actually apply.
	probe, created, err := nearestExistingDir(dir)
	if err != nil {
		target.Detail = err.Error()
		return target
	}
	info, err := os.Stat(probe)
	if err != nil {
		target.Detail = err.Error()
		return target
	}
	if !info.IsDir() {
		target.Detail = fmt.Sprintf("%s is not a directory", probe)
		return target
	}
	if created {
		target.Detail = fmt.Sprintf("%s does not exist yet; measured its nearest existing parent %s", dir, probe)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		target.Detail = "filesystem identity is unavailable for the destination"
		return target
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(probe, &stat); err != nil {
		target.Detail = fmt.Sprintf("statfs %s: %v", probe, err)
		return target
	}
	// Bavail, not Bfree: blocks reserved for root are not space this tool
	// may plan to use.
	target.Device = uint64(sys.Dev)
	target.FreeBytes = int64(stat.Bavail) * int64(stat.Bsize)
	target.Known = true
	return target
}

// nearestExistingDir walks up from dir to the first path that exists. It
// reports whether any component is still missing, which callers surface as
// "will be created" rather than as an unknown destination.
func nearestExistingDir(dir string) (probe string, missing bool, err error) {
	probe = filepath.Clean(dir)
	for {
		if _, statErr := os.Stat(probe); statErr == nil {
			return probe, missing, nil
		} else if !os.IsNotExist(statErr) {
			return "", missing, statErr
		}
		missing = true
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", missing, fmt.Errorf("no existing parent directory for %s", dir)
		}
		probe = parent
	}
}
