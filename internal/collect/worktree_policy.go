package collect

import "fmt"

// A policy refusal is a completed observation, not broken Git metadata.
type worktreePolicyRefusal struct{ reason string }

func (e *worktreePolicyRefusal) Error() string { return e.reason }

func protectedWorktreeName(relative, pattern string) error {
	return &worktreePolicyRefusal{fmt.Sprintf("worktree descendant %q matches protected name %q without a current exact source-content approval", relative, pattern)}
}
