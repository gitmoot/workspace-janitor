package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// supersededReason is the receipt reason of a copy removed because an
// identical original was back at its source.
const supersededReason = "an object identical to the quarantined copy is back at the original path; only the redundant copy was removed and the original was not touched"

// expiryEligible applies the guards a confirmed expiry of item would. When an
// object identical to the quarantined copy is back at the original path, it
// returns proof of that and applies only the guards on the copy itself: the
// copy is redundant, and its removal never touches the original, so
// references to and protections of the original pathname do not hold it.
// Otherwise (no object there, or one that is not provably identical) it
// returns nil proof and every expiry guard (Eligible) applies, as it always
// has.
func (e *Engine) expiryEligible(ctx context.Context, item core.CleanupItem) (*identicalTrees, error) {
	if err := e.expiryReady(item); err != nil {
		return nil, err
	}
	proof := e.identicalOriginal(ctx, item)
	if proof == nil {
		return nil, e.Eligible(ctx, item)
	}
	if err := e.eligible(ctx, item, false); err != nil {
		return proof, err
	}
	return proof, e.copyInUse(ctx, item)
}

// copyInUse refuses a quarantined copy that any process uses through its
// working directory, root, executable, an open descriptor or a mapped file,
// or when any process cannot be inspected. With the original identical, a
// process still holding the copy may be in the middle of reading it.
func (e *Engine) copyInUse(ctx context.Context, item core.CleanupItem) error {
	used, err := workspacearchive.ScratchReferences(ctx, e.Collect.ProcRoot, filepath.Dir(item.Destination))
	if err != nil {
		return fmt.Errorf("live process check of the quarantined copy: %w", err)
	}
	if use, ok := used[filepath.Base(item.Destination)]; ok {
		return fmt.Errorf("quarantined copy is in use (%s)", use)
	}
	return nil
}

// identicalOriginal compares the object at item.Source, if there is one, with
// the quarantined copy, and returns proof only when they are identical. A
// unit with a bound companion never qualifies: its two parts expire together
// under every guard.
func (e *Engine) identicalOriginal(ctx context.Context, item core.CleanupItem) *identicalTrees {
	if suffix, _ := companionOf(item); suffix != "" {
		return nil
	}
	if _, err := os.Lstat(item.Source); err != nil {
		return nil
	}
	proof, err := compareTrees(ctx, item.Source, item.Destination, item.Entry.FilesystemID, e.Collect.Limits.DeepSizeMaxEntries)
	if err != nil {
		return nil
	}
	return proof
}

// supersede removes a quarantined copy that expiryEligible found redundant
// and records it superseded_by_original. Both trees must still carry every
// stamp the comparison saw, so a change to either after it was compared
// keeps the copy. The removal is the anchored deletion expiry always uses:
// it starts from the copy's recorded identity, never follows a symlink and
// never leaves the copy's filesystem, so it cannot reach the original.
func (e *Engine) supersede(ctx context.Context, item core.CleanupItem, proof *identicalTrees) (core.CleanupItem, error) {
	if err := proof.unchanged(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return item, err
		}
		return e.investigate(ctx, item, "identical original no longer proven: "+err.Error())
	}
	if err := writeRemovalMarker(item, core.CleanupSuperseded); err != nil {
		return item, fmt.Errorf("record removal intent: %w", err)
	}
	if err := deleteAnchored(item.Destination, item.Entry.FilesystemID); err != nil {
		return item, err
	}
	item.State, item.UpdatedAt, item.Reason = core.CleanupSuperseded, e.now(), supersededReason
	if err := e.update(ctx, item, core.CleanupQuarantined); err != nil {
		return item, err
	}
	return item, nil
}
