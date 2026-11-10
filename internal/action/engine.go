package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// Engine owns each move's durable receipt and revalidates before mutations.
// Every item has its own journal row: a failed batch does not hide earlier moves.
type Engine struct {
	DB            *store.Store
	QuarantineDir string
	Policy        safety.Policy
	Collect       collect.Options
	Now           func() time.Time
	// Artifacts decides the expiry of quarantined omp_session_artifacts
	// files (ArtifactBatch); nil refuses it.
	Artifacts ArtifactGuard
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) update(ctx context.Context, item core.CleanupItem, expected core.CleanupState) error {
	return e.DB.Write(ctx, func(tx *store.Tx) error { return tx.UpdateCleanup(ctx, item, expected) })
}

// Items returns all durable receipts for a cleanup id, or all receipts for an
// empty id. The database journal, not an in-memory batch counter, is canonical.
func (e *Engine) Items(ctx context.Context, cleanupID string) ([]core.CleanupItem, error) {
	var items []core.CleanupItem
	err := e.DB.Read(ctx, func(tx *store.Tx) error { var err error; items, err = tx.CleanupItems(ctx, cleanupID); return err })
	return items, err
}

// Prepare creates a reconstructable receipt before any filesystem mutation.
func (e *Engine) Prepare(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if e.DB == nil || e.QuarantineDir == "" {
		return item, errors.New("quarantine store and directory are required")
	}
	root, err := filepath.Abs(e.QuarantineDir)
	if err != nil {
		return item, err
	}
	base := filepath.Join(root, item.CleanupID, item.ActionID)
	item.Destination = filepath.Join(base, "item")
	item.State = core.CleanupPrepared
	item.CreatedAt = e.now()
	item.UpdatedAt = item.CreatedAt
	item.Normalize()
	if err := item.Validate(); err != nil {
		return item, err
	}
	if within(item.Source, root) || within(root, item.Source) {
		return item, fmt.Errorf("quarantine overlaps source %s", item.Source)
	}
	// The destination may not move across devices, even when planning offered
	// an optional copy. v0.1 never copies and never follows a final symlink.
	if err := createReceiptDir(base); err != nil {
		return item, fmt.Errorf("create receipt directory: %w", err)
	}
	if err := sameFilesystem(item.Source, base); err != nil {
		return item, err
	}
	if err := syncDir(filepath.Dir(base)); err != nil {
		return item, err
	}
	if err := e.DB.Write(ctx, func(tx *store.Tx) error { return tx.InsertCleanup(ctx, item) }); err != nil {
		return item, err
	}
	if err := ensureManifest(item); err != nil {
		return item, err
	}
	return item, nil
}

// PreflightOfficial reruns the complete safety decision immediately before a
// provider-owned prune. An approved plan alone is never mutation permission.
func (e *Engine) PreflightOfficial(ctx context.Context, entry core.Entry, action core.Action) error {
	if action.Kind != core.ActionDeleteCandidate || action.Path != entry.Path ||
		entry.Kind != core.EntryKindDirectory || entry.Git != nil {
		return fmt.Errorf("official prune requires an exact approved cache directory, not a repository")
	}
	return e.preflightEntry(ctx, entry, action, "official prune")
}

// PreflightExport reuses mutation-time reference, identity and policy guards
// before copying an exact export. Only its missing-archive gate is deferred.
func (e *Engine) PreflightExport(ctx context.Context, entry core.Entry, action core.Action) error {
	if entry.Kind != core.EntryKindFile || entry.Git != nil || action.Path != entry.Path ||
		action.Kind != core.ActionQuarantine || e.Collect.ArchiveCreationPath != entry.Path {
		return errors.New("archive requires an exact owner-approved regular export")
	}
	initial := safety.Evaluate(safety.Input{Entry: entry, Policy: e.Policy, Now: e.now()})
	if !initial.Allows(action.Kind) {
		return fmt.Errorf("archive source remains protected: %s", initial.Detail())
	}
	return e.preflightEntry(ctx, entry, action, "export archive")
}

func (e *Engine) preflightEntry(ctx context.Context, entry core.Entry, action core.Action, label string) error {
	handle, err := safety.Open(entry.Path)
	if err != nil {
		return err
	}
	defer handle.Close()
	verdict := safety.Revalidate(ctx, safety.RevalidateInput{
		Planned: entry, Action: action, Policy: e.Policy,
		Now: e.now(), Handle: handle,
		Recollect: func(ctx context.Context, path string) (core.Entry, error) {
			return e.recollectWithSize(ctx, path, entry.SizeIsDeep)
		},
	})
	if !verdict.Allows(action.Kind) {
		return fmt.Errorf("%s refused %s: %s", label, entry.Path, verdict.Detail())
	}
	return nil
}

// Quarantine moves one prepared item, with a fresh complete safety verdict.
func (e *Engine) Quarantine(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if item.State != core.CleanupPrepared {
		return item, fmt.Errorf("item %s is not prepared", item.ActionID)
	}
	if err := ensureManifest(item); err != nil {
		return item, err
	}
	if err := sameFilesystem(item.Source, filepath.Dir(item.Destination)); err != nil {
		return item, err
	}
	handle, err := safety.Open(item.Source)
	if err != nil {
		return item, err
	}
	defer handle.Close()
	if verdict := e.revalidatePrepared(ctx, item, handle); !verdict.Allows(item.Action.Kind) {
		return item, fmt.Errorf("revalidation refused %s: %s", item.Source, verdict.Detail())
	}
	if err := e.moveUnit(ctx, item, handle.Identity()); err != nil {
		return item, err
	}
	// Once renamed, never roll back on an error: recovery can identify this
	// exact object from the prepared receipt and its original filesystem ID.
	if err := syncDir(filepath.Dir(item.Destination)); err != nil {
		return item, err
	}
	if err := syncDir(filepath.Dir(item.Source)); err != nil {
		return item, err
	}
	return e.finishMove(ctx, item)
}

// QuarantineCheck runs the revalidation Quarantine performs on a prepared
// item, without installing its manifest or moving anything: the fresh
// verdict on the item, and the refusal a bound companion would meet when it
// moves. It shows an operator exactly which check keeps a receipt prepared.
func (e *Engine) QuarantineCheck(ctx context.Context, item core.CleanupItem) (core.Verdict, error) {
	if item.State != core.CleanupPrepared {
		return core.Verdict{}, fmt.Errorf("item %s is not prepared", item.ActionID)
	}
	if err := sameFilesystem(item.Source, filepath.Dir(item.Destination)); err != nil {
		return core.Verdict{}, err
	}
	handle, err := safety.Open(item.Source)
	if err != nil {
		return core.Verdict{}, err
	}
	defer handle.Close()
	verdict := e.revalidatePrepared(ctx, item, handle)
	if suffix, id := companionOf(item); verdict.Allows(item.Action.Kind) && suffix != "" && !id.Zero() {
		return verdict, e.revalidateCompanion(ctx, item, item.Source+suffix, id)
	}
	return verdict, nil
}

// revalidatePrepared is the fresh complete safety verdict on a prepared item
// opened through handle, immediately before its move.
func (e *Engine) revalidatePrepared(ctx context.Context, item core.CleanupItem, handle *safety.Handle) core.Verdict {
	target := safety.ResolveTarget(filepath.Dir(item.Destination))
	return safety.Revalidate(ctx, safety.RevalidateInput{
		Planned: item.Entry, Action: item.Action, Policy: e.Policy,
		Target: &target, Now: e.now(), Handle: handle,
		Recollect: func(ctx context.Context, path string) (core.Entry, error) {
			return e.recollectWithSize(ctx, path, item.Entry.SizeIsDeep)
		},
	})
}

// moveUnit renames the prepared object, and a bound companion before it, into
// the receipt directory. The companion is revalidated immediately before its
// rename and follows the primary: if the primary did not move, the companion
// is moved back so the unit is never split.
func (e *Engine) moveUnit(ctx context.Context, item core.CleanupItem, primary core.FilesystemID) error {
	if err := absent(item.Destination); err != nil {
		return err
	}
	suffix, companionID := companionOf(item)
	companionMoved := false
	if suffix != "" {
		if err := absent(item.Destination + suffix); err != nil {
			return fmt.Errorf("companion destination: %w", err)
		}
		if companionID.Zero() {
			if err := absent(item.Source + suffix); err != nil {
				return fmt.Errorf("companion was recorded absent: %w", err)
			}
		} else {
			if err := e.revalidateCompanion(ctx, item, item.Source+suffix, companionID); err != nil {
				return err
			}
			if err := renameNoReplace(item.Source+suffix, item.Destination+suffix, companionID); err != nil {
				return fmt.Errorf("move companion: %w", err)
			}
			companionMoved = true
		}
	}
	var err error
	if item.Entry.Git != nil && item.Entry.Git.WorktreeOf != "" {
		err = MoveLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Source, item.Destination)
	} else {
		err = renameNoReplace(item.Source, item.Destination, primary)
	}
	if err != nil && companionMoved && unmoved(item) {
		if back := renameNoReplace(item.Destination+suffix, item.Source+suffix, companionID); back != nil {
			return fmt.Errorf("%w; companion could not be moved back and is left in quarantine: %v", err, back)
		}
	}
	return err
}

// revalidateCompanion gives a bound companion the primary's mutation-time
// check. Collection attaches cron, systemd, PM2, service, process and Git
// references to the entry they name, so those on the companion are on its
// own entry, never on the primary's verdict. A fresh, complete observation
// must still be the bound regular file, and every guard must allow the move
// apart from the protections it carries as part of the unit (unitCompanion).
func (e *Engine) revalidateCompanion(ctx context.Context, item core.CleanupItem, path string, id core.FilesystemID) error {
	fresh, err := e.recollect(ctx, path)
	if err != nil {
		return fmt.Errorf("companion revalidation refused %s: %w", path, err)
	}
	if fresh.Kind != core.EntryKindFile || fresh.FilesystemID != id {
		return fmt.Errorf("companion revalidation refused %s: it is no longer the bound regular file", path)
	}
	target := safety.ResolveTarget(filepath.Dir(item.Destination))
	verdict := safety.Evaluate(safety.Input{Entry: unitCompanion(fresh, item.Source), Policy: e.Policy, Target: &target, Now: e.now()})
	if !verdict.Allows(item.Action.Kind) {
		return fmt.Errorf("companion revalidation refused %s: %s", path, verdict.Detail())
	}
	return nil
}

func (e *Engine) finishMove(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if err := absent(item.Source); err != nil {
		return item, fmt.Errorf("source reappeared after move: %w", err)
	}
	if err := companionMoved(item); err != nil {
		return item, err
	}
	fresh, err := e.recollectReceipt(ctx, item.Destination, item.Source)
	if err != nil {
		return item, fmt.Errorf("moved object requires investigation: %w", err)
	}
	if fresh.FilesystemID != item.Entry.FilesystemID {
		return item, errors.New("moved object identity changed; investigate receipt")
	}
	if item.Entry.Git != nil && item.Entry.Git.WorktreeOf != "" {
		if err := VerifyLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Destination); err != nil {
			return item, err
		}
	}
	moved := e.now()
	item.State, item.UpdatedAt, item.MovedAt = core.CleanupQuarantined, moved, &moved
	if expiry, ok := item.Action.Retention.ExpiresAt(moved); ok {
		item.ExpiresAt = &expiry
	}
	item.Quarantined = &fresh
	if err := e.update(ctx, item, core.CleanupPrepared); err != nil {
		return item, err
	}
	return item, nil
}

// RetryPreview reports, without changing anything, what a confirmed expiry
// would do with an investigated receipt: Reconcile's guard returns it to
// quarantine, then Delete applies retention and the expiry guards.
func (e *Engine) RetryPreview(ctx context.Context, item core.CleanupItem) error {
	candidate := item
	candidate.State = core.CleanupQuarantined
	if e.settleAbsent(item) == absentUnproven {
		if _, err := e.expiryEligible(ctx, candidate); err != nil {
			return err
		}
	}
	if candidate.MovedAt == nil || !candidate.Action.Retention.Expired(*candidate.MovedAt, e.now()) {
		return errors.New("retention has not expired")
	}
	return e.ExpiryPreview(ctx, candidate)
}

// Reconcile resolves a crash between durable journal writes and either rename.
// It never guesses when both names exist, identity differs, or the Git
// registration cannot be verified.
func (e *Engine) Reconcile(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if item.State == core.CleanupInvestigate && item.Quarantined != nil && item.MovedAt != nil {
		// An investigation is not a permanent tombstone. Recheck every expiry
		// guard before allowing an explicitly retried deletion; an unchanged
		// reason (new reference, changed bytes, unknown collector) stays put.
		// A copy an identical original now supersedes is held to the guards
		// on the copy alone, as Delete holds it.
		candidate := item
		candidate.State = core.CleanupQuarantined
		// With the object gone there is nothing for the guards to protect;
		// Delete records the outcome, or a restore that stopped short.
		if e.settleAbsent(item) == absentUnproven {
			if _, err := e.expiryEligible(ctx, candidate); err != nil {
				return item, err
			}
		}
		item.State, item.UpdatedAt, item.Reason = core.CleanupQuarantined, e.now(), ""
		if err := e.update(ctx, item, core.CleanupInvestigate); err != nil {
			return item, err
		}
		return item, nil
	}
	if item.State != core.CleanupPrepared && item.State != core.CleanupQuarantined {
		return item, nil
	}
	src, srcErr := os.Lstat(item.Source)
	dst, dstErr := os.Lstat(item.Destination)
	sourcePresent := srcErr == nil && identityMatches(src, item.Entry.FilesystemID)
	destinationPresent := dstErr == nil && identityMatches(dst, item.Entry.FilesystemID)
	if item.State == core.CleanupPrepared {
		if sourcePresent && errors.Is(dstErr, os.ErrNotExist) {
			// A move that stopped between its companion and its primary is
			// undone: the companion follows the primary back.
			if err := followCompanion(item, item.Source); err != nil {
				return e.investigate(ctx, item, companionReason(err))
			}
			return item, nil
		}
		if errors.Is(srcErr, os.ErrNotExist) && destinationPresent {
			if err := followCompanion(item, item.Destination); err != nil {
				return e.investigate(ctx, item, companionReason(err))
			}
			recovered, err := e.finishMove(ctx, item)
			if err != nil {
				return e.investigate(ctx, item, "post-move observation failed: "+err.Error())
			}
			return recovered, nil
		}
		return e.investigate(ctx, item, "prepared move has conflicting or changed source and destination")
	}
	// A different new object at the original path is an ordinary restore
	// collision. Keep the quarantined receipt recoverable rather than
	// promoting a harmless occupied source to an irreversible status.
	if destinationPresent && (srcErr == nil || errors.Is(srcErr, os.ErrNotExist)) {
		if err := followCompanion(item, item.Destination); err != nil {
			return e.investigate(ctx, item, companionReason(err))
		}
		return item, nil
	}
	if sourcePresent && errors.Is(dstErr, os.ErrNotExist) {
		if item.Entry.Git != nil && item.Entry.Git.WorktreeOf != "" {
			if err := VerifyLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Source); err != nil {
				return e.investigate(ctx, item, "restored Git registration is invalid")
			}
		}
		// A restore that stopped between its primary and its companion is
		// completed: the companion follows the primary home.
		if err := followCompanion(item, item.Source); err != nil {
			return e.investigate(ctx, item, companionReason(err))
		}
		item.State, item.UpdatedAt = core.CleanupRestored, e.now()
		if err := e.update(ctx, item, core.CleanupQuarantined); err != nil {
			return item, err
		}
		return item, nil
	}
	return e.investigate(ctx, item, "quarantined move has conflicting or changed source and destination")
}

func (e *Engine) investigate(ctx context.Context, item core.CleanupItem, reason string) (core.CleanupItem, error) {
	before := item.State
	item.State, item.UpdatedAt, item.Reason = core.CleanupInvestigate, e.now(), reason
	if err := e.update(ctx, item, before); err != nil {
		return item, err
	}
	return item, fmt.Errorf("%s: %s", item.ActionID, reason)
}

// Restore never overwrites an occupied original path, including a symlink.
func (e *Engine) Restore(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	var err error
	if item, err = e.Reconcile(ctx, item); err != nil && item.State != core.CleanupInvestigate {
		return item, err
	}
	if item.State == core.CleanupRestored {
		return item, nil
	}
	if item.State == core.CleanupPrepared {
		src, srcErr := os.Lstat(item.Source)
		if srcErr != nil || !identityMatches(src, item.Entry.FilesystemID) {
			return item, fmt.Errorf("prepared source changed: %v", srcErr)
		}
		if err := absent(item.Destination); err != nil {
			return item, fmt.Errorf("prepared destination is occupied: %w", err)
		}
		item.State, item.UpdatedAt = core.CleanupRestored, e.now()
		if err := e.update(ctx, item, core.CleanupPrepared); err != nil {
			return item, err
		}
		return item, nil
	}
	if item.State != core.CleanupQuarantined && item.State != core.CleanupInvestigate {
		return item, fmt.Errorf("%s is %s, not recoverable", item.ActionID, item.State)
	}
	before := item.State
	if item.State == core.CleanupInvestigate {
		src, srcErr := os.Lstat(item.Source)
		_, dstErr := os.Lstat(item.Destination)
		if srcErr == nil && identityMatches(src, item.Entry.FilesystemID) && errors.Is(dstErr, os.ErrNotExist) {
			if item.Entry.Git != nil && item.Entry.Git.WorktreeOf != "" {
				if err := VerifyLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Source); err != nil {
					return item, err
				}
			}
			if err := followCompanion(item, item.Source); err != nil {
				return item, err
			}
			item.State, item.UpdatedAt = core.CleanupRestored, e.now()
			if err := e.update(ctx, item, before); err != nil {
				return item, err
			}
			return item, nil
		}
	}
	if err := absent(item.Source); err != nil {
		return item, fmt.Errorf("occupied original source: %w", err)
	}
	// The companion comes home after its primary, so its name must be free
	// before the primary moves: a unit is never restored half. Only the
	// companion itself may already be there (an investigated split).
	suffix, companionID := companionOf(item)
	companionHome := false
	if suffix != "" && !companionID.Zero() {
		home, err := os.Lstat(item.Source + suffix)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err == nil && identityMatches(home, companionID):
			companionHome = true
		case err == nil:
			return item, fmt.Errorf("occupied companion source: %s is occupied", item.Source+suffix)
		default:
			return item, fmt.Errorf("occupied companion source: %w", err)
		}
	}
	if err := sameFilesystem(item.Destination, filepath.Dir(item.Source)); err != nil {
		return item, err
	}
	info, err := os.Lstat(item.Destination)
	if err != nil || !identityMatches(info, item.Entry.FilesystemID) {
		if before == core.CleanupInvestigate {
			return item, errors.New("investigated object disappeared or changed identity")
		}
		return e.investigate(ctx, item, "quarantined object disappeared or changed identity")
	}
	if suffix != "" {
		companion, err := os.Lstat(item.Destination + suffix)
		inPlace := errors.Is(err, os.ErrNotExist)
		if !companionID.Zero() && !companionHome {
			inPlace = err == nil && identityMatches(companion, companionID)
		}
		if !inPlace {
			if before == core.CleanupInvestigate {
				return item, errors.New("investigated companion disappeared or changed identity")
			}
			return e.investigate(ctx, item, "quarantined companion disappeared or changed identity")
		}
	}
	if item.Entry.Git != nil && item.Entry.Git.WorktreeOf != "" {
		if err := VerifyLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Destination); err != nil {
			return item, err
		}
		err = MoveLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Destination, item.Source)
	} else {
		err = renameNoReplace(item.Destination, item.Source, item.Entry.FilesystemID)
	}
	if err != nil {
		return item, err
	}
	if err := syncDir(filepath.Dir(item.Source)); err != nil {
		return item, err
	}
	// Stopping here leaves the primary home and its companion in quarantine;
	// Reconcile completes that restore by the same follow rule.
	if err := followCompanion(item, item.Source); err != nil {
		return item, fmt.Errorf("restored %s but not its companion: %w", item.Source, err)
	}
	item.State, item.UpdatedAt = core.CleanupRestored, e.now()
	if err := e.update(ctx, item, before); err != nil {
		return item, err
	}
	return item, nil
}

func sameFilesystem(source, destDir string) error {
	object, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("inspect source: %w", err)
	}
	parent, err := os.Stat(destDir)
	if err != nil {
		return fmt.Errorf("inspect destination parent: %w", err)
	}
	if !parent.IsDir() {
		return errors.New("destination parent is not a directory")
	}
	a, b := filesystemID(object), filesystemID(parent)
	if a.Zero() || b.Zero() || a.Device != b.Device {
		return errors.New("cross-filesystem rename is unsupported")
	}
	return nil
}

func absent(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%s is occupied", path)
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// companionOf returns the suffix and identity of the companion bound with
// the item's primary (an OMP session's "<stem>.jsonl"), or "" when the
// primary moves alone. A zero identity means the companion was recorded
// absent and must stay absent: there is nothing to move.
func companionOf(item core.CleanupItem) (string, core.FilesystemID) {
	if b := item.Entry.WorkspaceArchive; b != nil && b.CompanionSuffix != "" {
		return b.CompanionSuffix, b.CompanionID
	}
	return "", core.FilesystemID{}
}

// unitCompanion drops the two collected protections a bound companion of
// the unit at source carries as part of that unit rather than as evidence
// about itself: the marker that it moves only with its primary
// (collect.CompanionMarker), and an archive_only root, which
// only the primary's exact verified category binding, covering the
// companion, lifts. Its sibling primary lies in every archive_only root it
// does, and the primary's own verdict is what authorizes the unit. Every
// other protection still refuses.
func unitCompanion(fresh core.Entry, source string) core.Entry {
	marker := collect.CompanionMarker(source)
	fresh.Protections = slices.DeleteFunc(slices.Clone(fresh.Protections), func(p core.Protection) bool {
		return p.Kind == core.ProtectArchiveOnlyRoot ||
			p.Kind == core.ProtectDurableEvidence && p.Source == core.SourcePolicy && p.Reason == marker
	})
	return fresh
}

// unmoved reports whether the primary is still exactly at its source and
// its destination name is free.
func unmoved(item core.CleanupItem) bool {
	src, err := os.Lstat(item.Source)
	return err == nil && identityMatches(src, item.Entry.FilesystemID) && absent(item.Destination) == nil
}

// followCompanion makes a bound companion follow its primary, which is now
// at primary (item.Source or item.Destination): the companion belongs at
// primary plus its suffix. If a move or restore stopped between the two, it
// is moved there from the other location with an identity-checked
// no-replace rename. Already in place is success. It never guesses: the
// companion at both names, missing or replaced, or its place occupied by
// something else is an error. A companion recorded absent must not appear
// in quarantine.
func followCompanion(item core.CleanupItem, primary string) error {
	suffix, id := companionOf(item)
	if suffix == "" {
		return nil
	}
	if id.Zero() {
		if err := absent(item.Destination + suffix); err != nil {
			return fmt.Errorf("companion was recorded absent: %w", err)
		}
		return nil
	}
	other := item.Destination
	if primary == item.Destination {
		other = item.Source
	}
	target, from := primary+suffix, other+suffix
	t, targetErr := os.Lstat(target)
	o, fromErr := os.Lstat(from)
	atTarget := targetErr == nil && identityMatches(t, id)
	atOther := fromErr == nil && identityMatches(o, id)
	switch {
	case atTarget && atOther:
		return fmt.Errorf("companion is linked at both %s and %s", target, from)
	case atTarget:
		return nil
	case atOther && errors.Is(targetErr, os.ErrNotExist):
		if err := renameNoReplace(from, target, id); err != nil {
			return fmt.Errorf("move companion to %s: %w", target, err)
		}
		return nil
	case atOther:
		if targetErr == nil {
			targetErr = fmt.Errorf("%s is occupied", target)
		}
		return fmt.Errorf("companion cannot follow its primary: %w", targetErr)
	default:
		return fmt.Errorf("companion %s disappeared or changed identity", target)
	}
}

// companionReason is the investigation reason for a unit whose companion
// could not be brought to its primary.
func companionReason(err error) string {
	return "companion did not follow its primary: " + err.Error()
}

// companionMoved is finishMove's companion check: it left its source and is
// in quarantine with its bound identity, or stays absent if recorded absent.
func companionMoved(item core.CleanupItem) error {
	suffix, id := companionOf(item)
	if suffix == "" {
		return nil
	}
	if id.Zero() {
		if err := absent(item.Destination + suffix); err != nil {
			return fmt.Errorf("companion was recorded absent: %w", err)
		}
		return nil
	}
	if err := absent(item.Source + suffix); err != nil {
		return fmt.Errorf("companion source reappeared after move: %w", err)
	}
	info, err := os.Lstat(item.Destination + suffix)
	if err != nil || !identityMatches(info, id) {
		return fmt.Errorf("moved companion is missing or changed identity; investigate receipt: %v", err)
	}
	return nil
}
