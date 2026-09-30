//go:build !linux

package action

import (
	"errors"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Deletion is Linux-only (see deleteAnchored), so there is never a marker.
func writeDeletionMarker(_ core.CleanupItem) error {
	return errors.New("anchored quarantine deletion is not supported on this platform")
}

func hasDeletionMarker(_ core.CleanupItem) bool { return false }
