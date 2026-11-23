//go:build !linux

package action

import (
	"context"
	"errors"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

type supersedeProof struct{}

func compareTrees(context.Context, string, string, core.FilesystemID, int) (*supersedeProof, error) {
	return nil, errors.New("comparing a quarantined copy with its original is supported on Linux only")
}

func (*supersedeProof) reason() string {
	return supersededReason
}

func (*supersedeProof) unchanged(context.Context) error {
	return errors.New("comparing a quarantined copy with its original is supported on Linux only")
}
