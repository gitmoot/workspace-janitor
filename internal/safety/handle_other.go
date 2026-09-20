//go:build !linux

package safety

import (
	"errors"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Handle is unavailable on platforms this release does not target.
type Handle struct{ path string }

// Open reports that handle-based validation is unsupported. Callers treat
// the error as an unknown, which refuses the mutation.
func Open(path string) (*Handle, error) {
	return nil, errors.New("safety: handle-based validation is not supported on this platform")
}

// Path returns the path this handle was opened from.
func (h *Handle) Path() string { return h.path }

// Identity returns an unset identity.
func (h *Handle) Identity() core.FilesystemID { return core.FilesystemID{} }

// ProcPath returns the original path; there is no handle to refer to.
func (h *Handle) ProcPath() string { return h.path }

// Linked reports that liveness cannot be determined.
func (h *Handle) Linked() (bool, error) {
	return false, errors.New("safety: handle-based validation is not supported on this platform")
}

// Close is a no-op.
func (h *Handle) Close() error { return nil }
