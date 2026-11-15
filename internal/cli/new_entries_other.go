//go:build !linux

package cli

import (
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// entryCreatedAt is unknown on platforms this release does not target.
func entryCreatedAt(string, core.FilesystemID) (*time.Time, string) {
	return nil, "unavailable"
}
