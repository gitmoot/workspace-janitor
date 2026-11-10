package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// recollect refuses incomplete reference observation, rather than interpreting
// a partial or skipped collector as proof that nobody uses a path.
func (e *Engine) recollect(ctx context.Context, path string) (core.Entry, error) {
	return e.recollectWithSize(ctx, path, false)
}

// Reinspect the actual receipt location while matching descendant policy at
// its original pathname. This never grants a quarantine-root cache approval.
func (e *Engine) recollectReceipt(ctx context.Context, path, source string) (core.Entry, error) {
	copy := *e
	copy.Collect.WorktreeOrigins = map[string]string{path: source}
	return copy.recollect(ctx, path)
}

func (e *Engine) recollectWithSize(ctx context.Context, path string, deep bool) (core.Entry, error) {
	result, err := e.observeAround(ctx, path, deep)
	if err != nil {
		return core.Entry{}, err
	}
	for _, entry := range result.Entries {
		if entry.Path == path {
			return entry, nil
		}
	}
	return core.Entry{}, fmt.Errorf("%s not found in fresh collection", path)
}

// observeAround collects path's directory one level deep and refuses a
// result whose reference collectors did not all complete.
func (e *Engine) observeAround(ctx context.Context, path string, deep bool) (collect.Result, error) {
	opts := e.Collect
	opts.DeepSize = deep
	opts.VerifyArchiveContents = true
	// Only path is used; bind (and fully verify) its archive alone.
	opts.ArchiveBindPaths = map[string]bool{path: true}
	// Resolve a live source symlink only to check containment; quarantine
	// snapshots never follow links because a relative target may be absent
	// until restore. In both cases the filesystem move operates on the link.
	opts.Roots = []collect.RootSpec{{Path: filepath.Dir(path), MaxDepth: 1, FollowSymlinks: !within(path, e.QuarantineDir)}}
	opts.Prior, opts.PriorScanID = nil, ""
	result, err := collect.Run(ctx, opts)
	if err != nil {
		return collect.Result{}, err
	}
	if err := collect.EvidenceGap(result.Reports, len(opts.AgentSources) != 0); err != nil {
		return collect.Result{}, fmt.Errorf("%s %w", path, err)
	}
	return result, nil
}

// originalReferences re-checks the original pathname, because services or
// jobs can begin referring to it after the quarantine move. Only references
// at or under the source count: its siblings say nothing about this item,
// and a home directory's parent always has some live reference.
//
// Something may have recreated the source since, such as a service
// regenerating its cache directory. That new object is not the quarantined
// one and expiry never touches it, so occupancy alone does not block; a
// reference into it still does, because it may be waiting for the
// original content.
func (e *Engine) originalReferences(ctx context.Context, source string) error {
	result, err := e.observeAround(ctx, source, false)
	if err != nil {
		return err
	}
	var found []string
	for _, ref := range result.References {
		// A Subtree reference protects everything inside its path, so it
		// covers a source anywhere below it as well.
		if core.PathWithin(ref.Path, source) || (ref.Subtree && core.PathWithin(source, ref.Path)) {
			found = append(found, fmt.Sprintf("%s (%s)", ref.Protection, ref.Detail))
		}
	}
	if len(found) > 0 {
		return fmt.Errorf("original source has new protected references: %s", strings.Join(found, "; "))
	}
	return nil
}

// Eligible performs a second complete observation and guard evaluation. It
// never deletes. An expired timestamp alone is not an authorization.
func (e *Engine) Eligible(ctx context.Context, item core.CleanupItem) error {
	return e.eligible(ctx, item, true)
}

// expiryReady holds the receipt facts every expiry outcome needs.
func (e *Engine) expiryReady(item core.CleanupItem) error {
	if item.State != core.CleanupQuarantined {
		return fmt.Errorf("%s is not quarantined", item.ActionID)
	}
	if item.MovedAt == nil || !item.Action.Retention.Expired(*item.MovedAt, e.now()) {
		return errors.New("retention has not expired")
	}
	if item.Quarantined == nil {
		return errors.New("missing post-move safety snapshot")
	}
	return nil
}

// eligible is Eligible; without original it skips the two checks of the
// original pathname (new references there, and the policy verdict on that
// name), keeping every guard on the quarantined copy itself.
//
// Without original it also leaves the workspace archive binding out of the
// copy's identity, and observes the copy without the archive rules for its
// source (withoutArchiveRulesAt). That binding recorded that a verified
// archive stood in for the copy; an identical original stands in for it
// now, and putting the original back (an archive restore, a KEEP record) is
// what withdraws the archive's authority, so the fresh copy no longer binds.
// The saved snapshot must still be one this build can verify, and every
// other fact of the copy must be unchanged.
func (e *Engine) eligible(ctx context.Context, item core.CleanupItem, original bool) error {
	if err := e.expiryReady(item); err != nil {
		return err
	}
	if original {
		if err := e.originalReferences(ctx, item.Source); err != nil {
			return err
		}
	}
	if err := e.eligibleCompanion(ctx, item); err != nil {
		return err
	}
	handle, err := safety.Open(item.Destination)
	if err != nil {
		return err
	}
	defer handle.Close()
	policy := e.receiptPolicy()
	planned := *item.Quarantined
	planned.Root = item.Entry.Root // symlink containment is judged against its original discovery root
	if !original {
		if _, known := collect.SnapshotFingerprint(planned); !known {
			return errors.New("saved fingerprint of the quarantined copy has an unknown format")
		}
		planned.WorkspaceArchive, planned.Fingerprint = nil, ""
	}
	observer := e
	if !original {
		observer = e.withoutArchiveRulesAt(item.Source)
	}
	var observed core.Entry
	probe := func(ctx context.Context, path string) (core.Entry, error) {
		fresh, err := observer.recollectReceipt(ctx, path, item.Source)
		fresh.Root = item.Entry.Root
		if !original {
			fresh.WorkspaceArchive = nil
		}
		observed = fresh
		return fresh, err
	}
	action := item.Action
	action.Path, action.Kind, action.FilesystemID = item.Destination, core.ActionDeleteCandidate, planned.FilesystemID
	verdict := safety.Revalidate(ctx, safety.RevalidateInput{
		Planned: planned, Action: action, Policy: policy, Now: e.now(), Handle: handle, Recollect: probe,
	})
	if !verdict.Allows(core.ActionDeleteCandidate) {
		return fmt.Errorf("deletion safety refused: %s", verdict.Detail())
	}
	// Re-evaluate the *original* pathname as well. Names and protected-path
	// rules can change after quarantine; evaluating only the receipt's generic
	// name \"item\" would silently lose those protections.
	if original {
		mirror := observed
		mirror.Path, mirror.Root, mirror.CanonicalPath = item.Source, item.Entry.Root, item.Entry.CanonicalPath
		verdict := safety.Evaluate(safety.Input{Entry: mirror, Policy: e.Policy, Now: e.now()})
		if !verdict.Allows(core.ActionDeleteCandidate) {
			return fmt.Errorf("original source safety refused: %s", verdict.Detail())
		}
	}
	// Inspect the full tree for mount boundaries before deleting any child.
	// This streams directory names without the estimator's entry cap or
	// per-inode accounting: large valid receipts must still be eligible.
	if err := verifyDeletionTree(ctx, item.Destination, planned.FilesystemID); err != nil {
		return fmt.Errorf("deletion footprint is unproven: %w", err)
	}
	return nil
}

// Delete is a distinct, explicit operation, never part of Quarantine. The
// caller must gate it on both policy opt-in and operator confirmation.
func (e *Engine) Delete(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if item.State != core.CleanupQuarantined || item.MovedAt == nil || !item.Action.Retention.Expired(*item.MovedAt, e.now()) {
		return item, errors.New("retention has not expired or item is not quarantined")
	}
	// Deleting comes before journaling it, so a crash or a failed journal
	// write in between leaves an expired receipt whose object is already
	// gone. The deletion marker written below proves this expiry started
	// deleting it; record the outcome instead of flagging the receipt for
	// investigation on every later run. An object back at its source means a
	// restore stopped before its journal write; Reconcile records it restored.
	switch e.settleAbsent(item) {
	case absentDeleted:
		// Expiry may have stopped between the primary and its companion,
		// which is held to the expiry guards again before it goes.
		if err := e.eligibleLeftoverCompanion(ctx, item); err != nil {
			return e.investigate(ctx, item, "leftover companion: "+err.Error())
		}
		if err := removeLeftoverCompanion(item); err != nil {
			return item, fmt.Errorf("remove leftover companion: %w", err)
		}
		item.State, item.UpdatedAt = core.CleanupDeleted, e.now()
		item.Reason = "expiry had already deleted the quarantined object but not journaled it; recorded as deleted"
		if err := e.update(ctx, item, core.CleanupQuarantined); err != nil {
			return item, err
		}
		return item, nil
	case absentSuperseded:
		item.State, item.UpdatedAt = core.CleanupSuperseded, e.now()
		item.Reason = "expiry had already removed the quarantined copy an identical original superseded but not journaled it; recorded as superseded"
		if err := e.update(ctx, item, core.CleanupQuarantined); err != nil {
			return item, err
		}
		return item, nil
	case absentRestored:
		return e.Reconcile(ctx, item)
	}
	proof, err := e.expiryEligible(ctx, item)
	if err != nil {
		return e.investigate(ctx, item, err.Error())
	}
	if proof != nil {
		return e.supersede(ctx, item, proof)
	}
	if err := writeDeletionMarker(item); err != nil {
		return item, fmt.Errorf("record deletion intent: %w", err)
	}
	if err := deleteAnchored(item.Destination, item.Entry.FilesystemID); err != nil {
		return item, err
	}
	// The companion goes after its primary. Stopping in between leaves an
	// absent primary with this receipt's marker, which settleAbsent records
	// as deleted after removing the leftover companion.
	if suffix, id := companionOf(item); suffix != "" && !id.Zero() {
		if err := deleteAnchored(item.Destination+suffix, id); err != nil {
			return item, fmt.Errorf("delete companion: %w", err)
		}
	}
	item.State, item.UpdatedAt = core.CleanupDeleted, e.now()
	if err := e.update(ctx, item, core.CleanupQuarantined); err != nil {
		return item, err
	}
	return item, nil
}

// eligibleCompanion applies the expiry guards to a bound companion as well:
// new references to its original name keep it, and the quarantined copy
// must still be the bound regular file (or still absent if it was recorded
// absent).
func (e *Engine) eligibleCompanion(ctx context.Context, item core.CleanupItem) error {
	suffix, id := companionOf(item)
	if suffix == "" {
		return nil
	}
	if err := e.originalReferences(ctx, item.Source+suffix); err != nil {
		return fmt.Errorf("companion: %w", err)
	}
	path := item.Destination + suffix
	info, err := os.Lstat(path)
	if id.Zero() {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("companion was recorded absent but %s exists or cannot be inspected: %v", path, err)
	}
	if err != nil || !info.Mode().IsRegular() || !identityMatches(info, id) {
		return fmt.Errorf("quarantined companion %s is not the bound regular file: %v", path, err)
	}
	return nil
}

// receiptPolicy is e.Policy for an object inside a receipt, which lies
// within our own state/quarantine directory. Those self-protections are not
// evidence about the object; all configured path, name, Git, live-reference,
// identity and unknown-evidence guards remain.
func (e *Engine) receiptPolicy() safety.Policy {
	policy := e.Policy
	policy.StateDir, policy.QuarantineDir = "", ""
	policy.ProtectedPaths = make([]string, 0, len(e.Policy.ProtectedPaths))
	for _, protected := range e.Policy.ProtectedPaths {
		if filepath.Clean(protected) != filepath.Clean(e.Policy.StateDir) &&
			filepath.Clean(protected) != filepath.Clean(e.Policy.QuarantineDir) {
			policy.ProtectedPaths = append(policy.ProtectedPaths, protected)
		}
	}
	return policy
}

// eligibleLeftoverCompanion holds a bound companion that an interrupted
// expiry left behind its deleted primary to the expiry guards again before
// removeLeftoverCompanion deletes it. Its identity alone is not enough: an
// append keeps it. It must still equal the archived companion in every fact
// and in content (workspacearchive.VerifyCompanion), the bound rule's current
// local expiry setting and retention must allow it exactly as binding would
// (collect.LocalExpiryRefusal, measured from the verified manifest's
// creation), no new reference may name its original path, and a fresh,
// complete observation must be the bound regular file allowed by every
// guard, at its receipt and at its original name, apart from its unit
// protections (unitCompanion). Nothing for removeLeftoverCompanion to delete
// is nil.
func (e *Engine) eligibleLeftoverCompanion(ctx context.Context, item core.CleanupItem) error {
	suffix, id := companionOf(item)
	if suffix == "" || id.Zero() {
		return nil
	}
	path, source := item.Destination+suffix, item.Source+suffix
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !identityMatches(info, id) {
		return nil
	}
	if err := e.originalReferences(ctx, source); err != nil {
		return err
	}
	rule, err := e.boundRule(item)
	if err != nil {
		return err
	}
	scope := workspacearchive.PolicyScope(*e.Collect.WorktreePolicy, rule)
	scope.ProcRoot = e.Collect.ProcRoot
	created, err := workspacearchive.VerifyCompanion(ctx, rule, scope, path)
	if err != nil {
		return err
	}
	// The archive hash excludes these settings: a retention raised or local
	// expiry disabled after the interruption keeps the companion.
	if refusal := collect.LocalExpiryRefusal(rule, created, e.now()); refusal != "" {
		return errors.New(refusal)
	}
	fresh, err := e.recollectReceipt(ctx, path, source)
	if err != nil {
		return err
	}
	if fresh.Kind != core.EntryKindFile || fresh.FilesystemID != id {
		return fmt.Errorf("%s is no longer the bound regular file", path)
	}
	fresh = unitCompanion(fresh, item.Source)
	fresh.Root = item.Entry.Root
	verdict := safety.Evaluate(safety.Input{Entry: fresh, Policy: e.receiptPolicy(), Now: e.now()})
	if !verdict.Allows(core.ActionDeleteCandidate) {
		return fmt.Errorf("deletion safety refused: %s", verdict.Detail())
	}
	fresh.Path = source
	if original := safety.Evaluate(safety.Input{Entry: fresh, Policy: e.Policy, Now: e.now()}); !original.Allows(core.ActionDeleteCandidate) {
		return fmt.Errorf("original source safety refused: %s", original.Detail())
	}
	return nil
}

// boundRule is the configured workspace archive rule that bound item's unit:
// its original path, companion suffix and the manifest pinned at binding.
func (e *Engine) boundRule(item core.CleanupItem) (config.WorkspaceArchiveRule, error) {
	if b := item.Entry.WorkspaceArchive; b != nil && e.Collect.WorktreePolicy != nil {
		for _, rule := range e.Collect.WorktreePolicy.WorkspaceArchives {
			if rule.Path == item.Source && rule.CompanionSuffix() == b.CompanionSuffix &&
				rule.Archive.Manifest == b.Manifest && rule.Archive.ManifestSHA256 == b.ManifestSHA256 {
				return rule, nil
			}
		}
	}
	return config.WorkspaceArchiveRule{}, errors.New("no configured workspace archive rule pins the archive that bound this unit")
}

// removeLeftoverCompanion finishes an expiry that deleted the primary but
// stopped before its companion. It removes only the bound companion
// identity, never anything else at that name.
func removeLeftoverCompanion(item core.CleanupItem) error {
	suffix, id := companionOf(item)
	if suffix == "" || id.Zero() {
		return nil
	}
	path := item.Destination + suffix
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !identityMatches(info, id) {
		return nil
	}
	return deleteAnchored(path, id)
}

// absentOutcome is what an expired receipt's missing object turned out to be.
type absentOutcome int

const (
	// absentUnproven: the object may still exist, or its fate is unknown.
	// The normal guarded path runs and investigates if it cannot proceed.
	absentUnproven absentOutcome = iota
	// absentDeleted: the object is gone and nowhere else to be found.
	absentDeleted
	// absentSuperseded: expiry removed the copy because an identical
	// original was back at its source.
	absentSuperseded
	// absentRestored: the object is back at its source with its identity.
	absentRestored
)

// settleAbsent decides, without guessing, whether a receipt's object is gone.
// Absence alone proves nothing: the receipt directory may have been moved or
// replaced with the object still inside. An object back at its source with its
// recorded identity was restored. Otherwise it counts as deleted (or
// superseded) only when this receipt's marker shows that expiry itself
// started removing it with that outcome and the source is provably not the
// object (absent, or another identity). Any other error leaves the outcome
// unproven.
func (e *Engine) settleAbsent(item core.CleanupItem) absentOutcome {
	if _, err := os.Lstat(item.Destination); !errors.Is(err, os.ErrNotExist) {
		return absentUnproven
	}
	src, err := os.Lstat(item.Source)
	switch {
	case err == nil && identityMatches(src, item.Entry.FilesystemID):
		return absentRestored
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return absentUnproven
	}
	switch deletionMarker(item) {
	case core.CleanupDeleted:
		return absentDeleted
	case core.CleanupSuperseded:
		return absentSuperseded
	default:
		return absentUnproven
	}
}

// ExpiryPreview reports what a confirmed expiry would do with a receipt,
// without changing anything: an absent object is settled, not refused,
// unless the companion it left behind would be.
func (e *Engine) ExpiryPreview(ctx context.Context, item core.CleanupItem) error {
	switch e.settleAbsent(item) {
	case absentDeleted:
		return e.eligibleLeftoverCompanion(ctx, item)
	case absentSuperseded, absentRestored:
		return nil
	}
	_, err := e.expiryEligible(ctx, item)
	return err
}

func filesystemID(info os.FileInfo) core.FilesystemID {
	return fileIdentity(info)
}

func identityMatches(info os.FileInfo, id core.FilesystemID) bool {
	return info != nil && !id.Zero() && fileIdentity(info) == id
}
