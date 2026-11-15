//go:build !linux

package collect

import (
	"context"
	"errors"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func proveWorktreeContents(context.Context, gitRunner, string, *Options, *core.GitState, time.Time) ([]string, error) {
	return nil, errors.New("bounded no-follow worktree contents proof is unavailable on this platform")
}
