//go:build !linux

package cli

import (
	"context"
	"errors"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// trimCargoTarget needs Linux cargo-lock flocks and anchored removal.
func trimCargoTarget(_ context.Context, _ string, _ config.CacheTrim, _ core.FilesystemID, report cacheTrimReport) cacheTrimReport {
	report.Status, report.Error = cacheTrimFailed, "cargo-target trims require Linux"
	return report
}

type cargoMatch struct {
	path string
	id   core.FilesystemID
	err  error
}

func discoverCargoTargets(string, string, map[string]bool) ([]cargoMatch, error) {
	return nil, errors.New("cargo-target trims require Linux")
}
