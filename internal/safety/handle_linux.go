//go:build linux

package safety

import (
	"fmt"
	"os"
	"syscall"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// oPath is O_PATH, which Go's syscall package does not export.
//
// It opens a reference to the object without opening it for I/O: no read
// permission is required, a fifo does not block, and a device node is not
// initialized. The value is 0o10000000 on every Linux architecture Go
// targets. Taking the constant here avoids making golang.org/x/sys a direct
// dependency, which would raise this module's required Go version.
const oPath = 0o10000000

// Handle is an open reference to the exact object that was checked.
//
// Comparing paths is not enough to close a time-of-check to time-of-use
// window. Removing a directory and recreating it under the same name can
// reuse the inode, and on a filesystem whose timestamps come from a cached
// clock tick the new object can carry the same device, inode, and
// modification time as the old one. Measured on ext4 while building this
// engine: after rmdir + mkdir the identity and all three timestamps were
// byte-identical.
//
// A handle does not have that ambiguity. It refers to one kernel object.
// If that object is unlinked, the handle knows, even when the path now
// resolves to a different object with the same numbers.
//
// The apply engine is expected to open a handle, revalidate through it, and
// perform the mutation relative to it, so the object checked is the object
// mutated.
type Handle struct {
	file *os.File
	path string
	id   core.FilesystemID
}

// Open opens path without following a final symlink.
//
// O_PATH takes no read permission and triggers no side effects: opening a
// fifo does not block, and opening a device does not initialize it.
func Open(path string) (*Handle, error) {
	fd, err := syscall.Open(path, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("safety: open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, fmt.Errorf("safety: fstat %s: %w", path, err)
	}
	return &Handle{
		file: file,
		path: path,
		id:   core.FilesystemID{Device: uint64(stat.Dev), Inode: stat.Ino},
	}, nil
}

// Path returns the path this handle was opened from.
func (h *Handle) Path() string { return h.path }

// Identity returns the device and inode observed when the handle was opened.
func (h *Handle) Identity() core.FilesystemID { return h.id }

// ProcPath returns a path that always refers to this handle's object, for
// mutations that must not re-resolve the original name.
func (h *Handle) ProcPath() string { return fmt.Sprintf("/proc/self/fd/%d", h.file.Fd()) }

// Linked reports whether the object still has at least one directory entry.
// A removed object answers false even if its inode number was handed to a
// replacement.
func (h *Handle) Linked() (bool, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(h.file.Fd()), &stat); err != nil {
		return false, fmt.Errorf("safety: fstat %s: %w", h.path, err)
	}
	return stat.Nlink > 0, nil
}

// Close releases the handle.
func (h *Handle) Close() error { return h.file.Close() }
