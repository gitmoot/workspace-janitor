//go:build !linux

package action

import "errors"

type gitMetadata struct{}

func captureGitMetadata(_ string) (gitMetadata, error) {
	return gitMetadata{}, errors.New("durable Git worktree moves are not supported on this platform")
}
func restoreGitMetadata(_ string, _ gitMetadata) error {
	return errors.New("durable Git worktree moves are not supported on this platform")
}
