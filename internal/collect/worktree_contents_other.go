//go:build !linux

package collect

import (
	"context"
	"errors"
)

func proveWorktreeContents(context.Context, gitRunner, string, *Options) error {
	return errors.New("bounded no-follow worktree contents proof is unavailable on this platform")
}
