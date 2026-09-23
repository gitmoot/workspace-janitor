package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	target := safety.ResolveTarget(filepath.Dir(item.Destination))
	verdict := safety.Revalidate(ctx, safety.RevalidateInput{
		Planned: item.Entry, Action: item.Action, Policy: e.Policy,
		Target: &target, Now: e.now(), Handle: handle, Recollect: e.recollect,
	})
	if !verdict.Allows(item.Action.Kind) {
		return item, fmt.Errorf("revalidation refused %s: %s", item.Source, verdict.Summary())
	}
	if err := absent(item.Destination); err != nil {
		return item, err
	}
	if item.Entry.Git != nil && item.Entry.Git.WorktreeOf != "" {
		err = MoveLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Source, item.Destination)
	} else {
		err = renameNoReplace(item.Source, item.Destination, handle.Identity())
	}
	if err != nil {
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

func (e *Engine) finishMove(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if err := absent(item.Source); err != nil {
		return item, fmt.Errorf("source reappeared after move: %w", err)
	}
	fresh, err := e.recollect(ctx, item.Destination)
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

// Reconcile resolves a crash between durable journal writes and either rename.
// It never guesses when both names exist, identity differs, or the Git
// registration cannot be verified.
func (e *Engine) Reconcile(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if item.State == core.CleanupInvestigate && item.Quarantined != nil && item.MovedAt != nil {
		// An investigation is not a permanent tombstone. Recheck every expiry
		// guard before allowing an explicitly retried deletion; an unchanged
		// reason (new reference, changed bytes, unknown collector) stays put.
		candidate := item
		candidate.State = core.CleanupQuarantined
		if err := e.Eligible(ctx, candidate); err != nil {
			return item, err
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
			return item, nil
		}
		if errors.Is(srcErr, os.ErrNotExist) && destinationPresent {
			recovered, err := e.finishMove(ctx, item)
			if err != nil {
				return e.investigate(ctx, item, "post-move observation failed: "+err.Error())
			}
			return recovered, nil
		}
		return e.investigate(ctx, item, "prepared move has conflicting or changed source and destination")
	}
	if errors.Is(srcErr, os.ErrNotExist) && destinationPresent {
		return item, nil
	}
	// A different new object at the original path is an ordinary restore
	// collision. Keep the quarantined receipt recoverable rather than
	// promoting a harmless occupied source to an irreversible status.
	if destinationPresent && srcErr == nil {
		return item, nil
	}
	if sourcePresent && errors.Is(dstErr, os.ErrNotExist) {
		if item.Entry.Git != nil && item.Entry.Git.WorktreeOf != "" {
			if err := VerifyLinkedWorktree(ctx, item.Entry.Git.WorktreeOf, item.Source); err != nil {
				return e.investigate(ctx, item, "restored Git registration is invalid")
			}
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
