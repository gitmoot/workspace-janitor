//go:build !linux

package cli

import (
	"context"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// trimCargoTarget needs Linux cargo-lock flocks and anchored removal.
func trimCargoTarget(_ context.Context, _ string, _ config.CacheTrim, report cacheTrimReport) cacheTrimReport {
	report.Status, report.Error = cacheTrimFailed, "cargo-target trims require Linux"
	return report
}
