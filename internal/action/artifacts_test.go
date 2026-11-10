//go:build linux

package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

func artifactItem(t *testing.T, e *Engine, source, actionID string) core.CleanupItem {
	t.Helper()
	if err := os.WriteFile(source, []byte("tool output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := e.now()
	entry := core.Entry{ContractVersion: core.ContractVersion, Path: source, Root: filepath.Dir(source), Kind: core.EntryKindFile,
		Class: core.ClassEvidence, SizeBytes: 12, FilesystemID: idOf(t, source), ObservedAt: now}
	return core.CleanupItem{CleanupID: "cleanup-batch", PlanID: "batch", ActionID: actionID, Source: source, Entry: entry,
		Action: core.Action{ID: actionID, PlanID: "batch", Path: source, Kind: core.ActionQuarantine, Class: core.ClassEvidence,
			Retention: core.RetentionNone, Status: core.ActionApplied, FilesystemID: entry.FilesystemID, CreatedAt: now,
			Rules: []string{ArtifactRulePrefix + "batch"}}}
}

// The last re-check before a session artifact's rename decides: a file that
// fails it stays where it is and its receipt is closed as never moved,
// while a file that passes moves into its receipt.
func TestQuarantineArtifactRechecksImmediatelyBeforeTheMove(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	kept, err := e.QuarantineArtifact(ctx, artifactItem(t, e, filepath.Join(root, "changed.log"), "file-00000"), func() error { return errors.New("it changed") })
	if !errors.Is(err, ErrArtifactKept) || kept.State != core.CleanupRestored || kept.MovedAt != nil {
		t.Fatalf("re-check failure did not leave the file in place: %+v %v", kept.State, err)
	}
	if _, err := os.Lstat(kept.Source); err != nil {
		t.Fatalf("file that failed its re-check moved: %v", err)
	}
	moved, err := e.QuarantineArtifact(ctx, artifactItem(t, e, filepath.Join(root, "idle.log"), "file-00001"), func() error { return nil })
	if err != nil || moved.State != core.CleanupQuarantined {
		t.Fatalf("verified file not quarantined: %+v %v", moved.State, err)
	}
	if _, err := os.Lstat(moved.Source); !os.IsNotExist(err) {
		t.Fatalf("quarantined file still at its source: %v", err)
	}
	var items []core.CleanupItem
	if err := e.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		items, err = tx.CleanupItems(ctx, "cleanup-batch")
		return err
	}); err != nil || len(items) != 2 {
		t.Fatalf("one receipt per file: %d %v", len(items), err)
	}
}

// Another Janitor process (the watcher persisting an inventory) can hold the
// database's write lock for several seconds while a batch moves files. The
// receipt write that follows a rename waits for that lock: the batch goes on
// and no receipt is left prepared behind a file that has already moved.
func TestQuarantineArtifactJournalWaitsOutALongWriteLock(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	other, err := store.Open(ctx, e.DB.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// Longer than the five seconds a writer used to wait (2026-11-10 cycle).
	const hold = 6 * time.Second
	held := make(chan error, 1)
	lockAfterPrepare := func() error {
		locked := make(chan struct{})
		go func() {
			held <- other.Write(ctx, func(*store.Tx) error {
				close(locked)
				time.Sleep(hold)
				return nil
			})
		}()
		select {
		case <-locked:
			return nil
		case err := <-held:
			return fmt.Errorf("take the write lock: %w", err)
		}
	}
	if _, err := e.QuarantineArtifact(ctx, artifactItem(t, e, filepath.Join(root, "1.grep.log"), "file-00000"), lockAfterPrepare); err != nil {
		t.Fatalf("receipt write behind a %v write lock: %v", hold, err)
	}
	if _, err := e.QuarantineArtifact(ctx, artifactItem(t, e, filepath.Join(root, "2.grep.log"), "file-00001"), func() error { return nil }); err != nil {
		t.Fatalf("next file of the batch: %v", err)
	}
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	var items []core.CleanupItem
	if err := e.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		items, err = tx.CleanupItems(ctx, "cleanup-batch")
		return err
	}); err != nil || len(items) != 2 {
		t.Fatalf("one receipt per file: %d %v", len(items), err)
	}
	for _, item := range items {
		if item.State != core.CleanupQuarantined || item.MovedAt == nil {
			t.Fatalf("%s receipt is %s after its move", item.Source, item.State)
		}
		if _, err := os.Lstat(item.Destination); err != nil {
			t.Fatalf("%s not in quarantine: %v", item.Source, err)
		}
	}
}
