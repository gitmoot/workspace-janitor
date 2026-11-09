//go:build linux

package action

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
