//go:build !linux

package workspacearchive

import (
	"context"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

type scratchInventory struct{}

// ScratchDir is unavailable off Linux.
type ScratchDir struct{}

func OpenScratch(string) (*ScratchDir, error) { return nil, errUnsupported }

func (s *ScratchDir) Close() {}

func (s *ScratchDir) Names(int) ([]string, error) { return nil, errUnsupported }

func (s *ScratchDir) Unchanged(ScratchEntry) error { return errUnsupported }

// SensitiveMember cannot screen off Linux, so every entry stays local.
func (e ScratchEntry) SensitiveMember(string, []string) string { return e.Name }

func (s *ScratchDir) Observe(context.Context, string, []string, int) (ScratchEntry, error) {
	return ScratchEntry{}, errUnsupported
}

func ScratchReferences(context.Context, string, string) (map[string]string, error) {
	return nil, errUnsupported
}

func (s *ScratchDir) CreateScratch(context.Context, config.WorkspaceArchiveCategoryDestination, string, []ScratchEntry, func() error) (ScratchManifest, *Binding, error) {
	return ScratchManifest{}, nil, errUnsupported
}

func CheckScratch(context.Context, config.WorkspaceArchiveCategoryDestination, Binding) (ScratchManifest, error) {
	return ScratchManifest{}, errUnsupported
}

func RestoreScratch(context.Context, config.WorkspaceArchiveCategoryDestination, Binding, string, string) (ScratchManifest, error) {
	return ScratchManifest{}, errUnsupported
}
