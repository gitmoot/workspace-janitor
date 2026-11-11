package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// ArtifactRulePrefix marks the cleanup actions of omp_session_artifacts
// batches: one of the action's Rules is this prefix plus the batch name.
// Such a receipt is one archived file of that batch; its quarantine and
// expiry are decided by the batch's verified archive (ArtifactGuard), not by
// a workspace archive rule.
const ArtifactRulePrefix = "category.omp_session_artifacts:"

// ArtifactBatch returns the batch a cleanup receipt's file was archived in.
func ArtifactBatch(item core.CleanupItem) (string, bool) {
	for _, rule := range item.Action.Rules {
		if name, ok := strings.CutPrefix(rule, ArtifactRulePrefix); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

// ArtifactGuard applies the expiry guards of one quarantined session
// artifact: its batch archive still verifies and still has authority, the
// quarantined copy is the archived file, policy does not protect its
// original path, and no process uses the copy or the original path.
type ArtifactGuard interface {
	Eligible(ctx context.Context, item core.CleanupItem) error
}

// ErrArtifactKept reports a session artifact that was left in place: its
// receipt is journaled as restored without having moved.
var ErrArtifactKept = errors.New("left in place")

// QuarantineArtifact journals one archived session artifact and moves it
// into its receipt directory. recheck runs after the receipt is durable and
// immediately before the rename; it must re-establish that the file is still
// the archived one and unused. A file that fails it, or that is not where
// the rename expects it, stays in place and its receipt is closed as
// restored (ErrArtifactKept), so it never fails the rest of its batch.
func (e *Engine) QuarantineArtifact(ctx context.Context, item core.CleanupItem, recheck func() error) (core.CleanupItem, error) {
	if _, ok := ArtifactBatch(item); !ok || item.Entry.Kind != core.EntryKindFile {
		return item, errors.New("only a regular file of a session artifact batch is quarantined this way")
	}
	item, err := e.Prepare(ctx, item)
	if err != nil {
		return item, err
	}
	if err := recheck(); err != nil {
		return e.leaveArtifact(ctx, item, err)
	}
	if err := renameNoReplace(item.Source, item.Destination, item.Entry.FilesystemID); err != nil {
		if unmoved(item) {
			return e.leaveArtifact(ctx, item, err)
		}
		// Reconcile settles a rename whose outcome is unknown.
		return item, err
	}
	if err := absent(item.Source); err != nil {
		return item, fmt.Errorf("source reappeared after move: %w", err)
	}
	info, err := os.Lstat(item.Destination)
	if err != nil || !info.Mode().IsRegular() || !identityMatches(info, item.Entry.FilesystemID) {
		return item, fmt.Errorf("moved file changed identity; investigate receipt: %v", err)
	}
	moved := e.now()
	fresh := item.Entry
	fresh.Path, fresh.ObservedAt = item.Destination, moved
	item.State, item.UpdatedAt, item.MovedAt = core.CleanupQuarantined, moved, &moved
	item.Quarantined = &fresh
	if expiry, ok := e.Retention(item).ExpiresAt(moved); ok {
		item.ExpiresAt = &expiry
	}
	if err := e.update(ctx, item, core.CleanupPrepared); err != nil {
		return item, err
	}
	return item, nil
}

// leaveArtifact closes a prepared artifact receipt whose file did not move.
func (e *Engine) leaveArtifact(ctx context.Context, item core.CleanupItem, cause error) (core.CleanupItem, error) {
	item.State, item.UpdatedAt, item.Reason = core.CleanupRestored, e.now(), "left in place: "+cause.Error()
	if err := e.update(ctx, item, core.CleanupPrepared); err != nil {
		return item, errors.Join(cause, err)
	}
	return item, fmt.Errorf("%w: %v", ErrArtifactKept, cause)
}

// artifactEligible holds a quarantined session artifact to its batch's
// guards; without them it is never deleted.
func (e *Engine) artifactEligible(ctx context.Context, item core.CleanupItem) error {
	if e.Artifacts == nil {
		return errors.New("session artifact expiry guards are unavailable")
	}
	return e.Artifacts.Eligible(ctx, item)
}
