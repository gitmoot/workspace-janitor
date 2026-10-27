//go:build !linux

package workspacearchive

import (
	"context"
	"errors"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

var errUnsupported = errors.New("verified workspace archives require Linux descriptor-anchored file operations; retain the original")

func Inspect(context.Context, config.WorkspaceArchiveRule, Scope) (Inspection, error) {
	return Inspection{}, errUnsupported
}
func Create(context.Context, config.WorkspaceArchiveRule, Scope, func() error) (Manifest, *Binding, error) {
	return Manifest{}, nil, errUnsupported
}
func Check(context.Context, config.WorkspaceArchiveRule, bool) (Manifest, *Binding, error) {
	return Manifest{}, nil, errUnsupported
}
func Restore(context.Context, config.WorkspaceArchiveRule, string) (Manifest, error) {
	return Manifest{}, errUnsupported
}
