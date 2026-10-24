//go:build !linux

package exportarchive

import (
	"context"
	"errors"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

var errUnsupported = errors.New("verified export archives require Linux descriptor-anchored file operations; retain the original")

func Create(context.Context, config.EvidenceExportRule, core.Entry, func() error) (Manifest, *core.ExportArchiveBinding, error) {
	return Manifest{}, nil, errUnsupported
}
func Check(context.Context, config.EvidenceExportRule, string, bool) (Manifest, *core.ExportArchiveBinding, error) {
	return Manifest{}, nil, errUnsupported
}
func Restore(context.Context, config.EvidenceExportRule, string) (Manifest, error) {
	return Manifest{}, errUnsupported
}
