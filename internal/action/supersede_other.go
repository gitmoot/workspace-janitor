//go:build !linux

package action

import (
	"context"
	"errors"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

type identicalTrees struct{}

func compareTrees(context.Context, string, string, core.FilesystemID, int) (*identicalTrees, error) {
	return nil, errors.New("comparing a quarantined copy with its original is supported on Linux only")
}

func (*identicalTrees) unchanged(context.Context) error {
	return errors.New("comparing a quarantined copy with its original is supported on Linux only")
}
