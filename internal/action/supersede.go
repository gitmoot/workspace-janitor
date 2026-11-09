package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/gitmoot/workspace-janitor/internal/config"
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
	if _, ok := ArtifactBatch(item); ok {
		return nil, e.artifactEligible(ctx, item)
	}
	proof := e.identicalOriginal(ctx, item)
	if proof == nil {
		return nil, e.Eligible(ctx, item)
	}
	if err := e.eligible(ctx, item, false); err != nil {
		return proof, err
	}
	if err := e.copyInUse(ctx, item); err != nil {
		return proof, err
	}
	return proof, e.copyArchiveReferences(ctx, item)
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

// archiveRulesAt lists the workspace archive rules configured for exactly
// source.
func (e *Engine) archiveRulesAt(source string) []config.WorkspaceArchiveRule {
	if e.Collect.WorktreePolicy == nil {
		return nil
	}
	var out []config.WorkspaceArchiveRule
	for _, rule := range e.Collect.WorktreePolicy.WorkspaceArchives {
		if rule.Path == source {
			out = append(out, rule)
		}
	}
	return out
}

// withoutArchiveRulesAt is e observing without the workspace archive rules
// for exactly source. Binding the quarantined copy to such a rule asks
// whether the archive may stand in for it, and checks live use of the
// original names as well as the copy's; with an identical original standing
// in, that question is moot, and a process using only the original must not
// hold the redundant copy. Every other rule still applies, including a
// rule's protection of the trees that contain it, and copyArchiveReferences
// repeats the dropped rules' checks against the copy's own names.
func (e *Engine) withoutArchiveRulesAt(source string) *Engine {
	if len(e.archiveRulesAt(source)) == 0 {
		return e
	}
	policy := *e.Collect.WorktreePolicy
	policy.WorkspaceArchives = slices.DeleteFunc(slices.Clone(policy.WorkspaceArchives), func(rule config.WorkspaceArchiveRule) bool {
		return rule.Path == source
	})
	observer := *e
	observer.Collect.WorktreePolicy = &policy
	return &observer
}

// copyArchiveReferences holds the quarantined copy to the live-use and
// external-dependent checks a binding to an archive rule for its source
// would apply, against the copy's own names only: a process, gitdir,
// alternates file or symlink reaching into the copy keeps it, or any that
// cannot be examined. The rule's original names and its mentions (which are
// derived from the original names) describe the original, which stays. The
// scope is the one binding uses (workspacearchive.BindingScope), so a
// category rule searches through the shared dependent index under its own
// bound, as its binding and ordinary expiry do.
func (e *Engine) copyArchiveReferences(ctx context.Context, item core.CleanupItem) error {
	var categoryDependents *workspacearchive.DependentIndex
	for _, rule := range e.archiveRulesAt(item.Source) {
		scope := workspacearchive.BindingScope(ctx, *e.Collect.WorktreePolicy, rule, e.Collect.ProcRoot, &categoryDependents)
		if err := workspacearchive.LocalReferences(ctx, rule, scope, item.Destination); err != nil {
			return fmt.Errorf("quarantined copy: %w", err)
		}
	}
	return nil
}

// identicalOriginal compares the object at item.Source, if there is one, with
// the quarantined copy, and returns proof only when they are identical. A
// unit with a companion (bound, or named by a rule for its source) never
// qualifies: its two parts expire together under every guard.
func (e *Engine) identicalOriginal(ctx context.Context, item core.CleanupItem) *identicalTrees {
	if suffix, _ := companionOf(item); suffix != "" {
		return nil
	}
	for _, rule := range e.archiveRulesAt(item.Source) {
		if rule.Companion != "" {
			return nil
		}
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
