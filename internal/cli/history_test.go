package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// seedHistory stores count completed scans a month old, one minute apart,
// each with entries inventory rows, and returns the database path.
func seedHistory(t *testing.T, f *fixture, count, entries int, edit func(i int, scan *core.Scan)) string {
	t.Helper()
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Now().UTC().AddDate(0, -1, 0)
	if err := db.Write(ctx, func(tx *store.Tx) error {
		for i := range count {
			at := base.Add(time.Duration(i) * time.Minute)
			scan := core.Scan{ID: fmt.Sprintf("scan-%03d", i), Roots: []string{f.home},
				Status: core.ScanCompleted, StartedAt: at, FinishedAt: &at, EntryCount: entries}
			if edit != nil {
				edit(i, &scan)
			}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
			for j := range entries {
				if err := tx.PutEntry(ctx, scan.ID, historyEntry(fmt.Sprintf("%s/item-%03d-%04d", f.home, i, j), f.home, at)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return paths.DatabaseFile
}

func historyEntry(path, root string, at time.Time) core.Entry {
	return core.Entry{Path: path, Root: root, Kind: core.EntryKindDirectory, Class: core.ClassTaskWorktree,
		FilesystemID: core.FilesystemID{Device: 64, Inode: 4242}, SizeBytes: 4096,
		ModifiedAt: at, AccessedAt: at, ObservedAt: at,
		Evidence: []core.Evidence{{Source: core.SourceFilesystem, Signal: "fixture", Detail: strings.Repeat("x", 512), ObservedAt: at}}}
}

func historyReceipt(cleanupID, planID, source, root string, at time.Time) core.CleanupItem {
	entry := historyEntry(source, root, at)
	destination := filepath.Join(root, ".quarantine", cleanupID)
	return core.CleanupItem{CleanupID: cleanupID, PlanID: planID, ActionID: "action-" + cleanupID,
		Source: source, Destination: destination, State: core.CleanupPrepared, Entry: entry,
		Action: core.Action{ID: "action-" + cleanupID, PlanID: planID, Path: source,
			Kind: core.ActionQuarantine, Class: entry.Class, Retention: core.Retention7Days,
			Status: core.ActionPending, FilesystemID: entry.FilesystemID, Destination: destination, CreatedAt: at},
		CreatedAt: at, UpdatedAt: at, Reason: "approved plan"}
}

func execSQL(t *testing.T, path string, statements ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// TestHistoryRetentionKeepsOnlyPinnedScans trims a month-old history to the
// scans live records still need, with the default retention bounds.
func TestHistoryRetentionKeepsOnlyPinnedScans(t *testing.T) {
	f := newFixture(t)
	const scans = 40
	dbPath := seedHistory(t, f, scans, 1, func(i int, scan *core.Scan) {
		// Three deep scans; scan-002 completed first, so only the two
		// latest completed deep scans (003, 004) are growth baselines.
		if i >= 2 && i <= 4 {
			scan.Collectors = []core.CollectorReport{{Name: "deep_size", Status: core.CollectorRan}}
			finished := scan.StartedAt.Add(time.Duration(10+i) * time.Hour)
			scan.FinishedAt = &finished
		}
	})
	ctx := context.Background()
	db, err := store.OpenExisting(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().AddDate(0, -1, 0)
	if err := db.Write(ctx, func(tx *store.Tx) error {
		if err := tx.InsertCleanup(ctx, historyReceipt("cleanup-active", "plan-active", f.home+"/item-000-0000", f.home, at)); err != nil {
			return err
		}
		return tx.InsertCleanup(ctx, historyReceipt("cleanup-done", "plan-done", f.home+"/item-001-0000", f.home, at))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// scan-000's plan has an active receipt, scan-001's only a terminal one;
	// the latest plan is on the newest scan. scan-005 is named by a cycle
	// record, whose foreign key keeps the scan row.
	execSQL(t, dbPath,
		`INSERT INTO plans (id,scan_id,contract_version,status,created_at) VALUES ('plan-active','scan-000',1,'ready','2026-01-01T00:00:00Z')`,
		`INSERT INTO plans (id,scan_id,contract_version,status,created_at) VALUES ('plan-done','scan-001',1,'ready','2026-01-02T00:00:00Z')`,
		`INSERT INTO plans (id,scan_id,contract_version,status,created_at) VALUES ('plan-latest','scan-039',1,'ready','2026-01-03T00:00:00Z')`,
		`UPDATE cleanup_items SET state = 'deleted' WHERE cleanup_id = 'cleanup-done'`,
		`INSERT INTO completed_cycles (day,scan_id,completed_at_ns) VALUES ('2026-01-01','scan-005',1)`,
	)
	call := func(args ...string) historyReport {
		t.Helper()
		out, stderr, code := f.run(t, append([]string{"--format", "json", "history"}, args...)...)
		if code != ExitOK {
			t.Fatalf("history %v: exit=%d stderr=%s", args, code, stderr)
		}
		var doc struct {
			Data historyReport `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("decode history: %v: %s", err, out)
		}
		return doc.Data
	}
	// Deleted: 001, 002, 006..027. Kept: 000 (active receipt), 003 and 004
	// (latest deep), 005 (cycle record, inventory released), 028..039 (the
	// twelve most recent).
	const deleted = 24
	if preview := call(); !preview.DryRun || preview.Eligible.Scans != deleted {
		t.Fatalf("preview: %+v", preview)
	}
	if trimmed := call("--confirm"); trimmed.Eligible.Scans != deleted {
		t.Fatalf("confirmed trim: %+v", trimmed)
	}
	db, err = store.OpenExisting(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(ctx, func(tx *store.Tx) error {
		for _, id := range []string{"scan-000", "scan-003", "scan-004", "scan-028", "scan-039"} {
			if entries, err := tx.Entries(ctx, id); err != nil || len(entries) != 1 {
				return fmt.Errorf("pinned scan %s lost its inventory: %d %v", id, len(entries), err)
			}
		}
		for _, id := range []string{"scan-001", "scan-002", "scan-006", "scan-027"} {
			if _, err := tx.Scan(ctx, id); !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("unpinned scan %s survived: %v", id, err)
			}
		}
		if _, err := tx.Scan(ctx, "scan-005"); err != nil {
			return fmt.Errorf("cycle record lost its scan: %w", err)
		}
		if _, err := tx.Entries(ctx, "scan-005"); err == nil || !strings.Contains(err.Error(), "released") {
			return fmt.Errorf("audited scan kept its inventory: %v", err)
		}
		for _, id := range []string{"cleanup-active", "cleanup-done"} {
			if items, err := tx.CleanupItems(ctx, id); err != nil || len(items) != 1 {
				return fmt.Errorf("receipt %s changed: %d %v", id, len(items), err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Both receipts still preview from their own snapshots.
	for id, state := range map[string]core.CleanupState{"cleanup-active": core.CleanupPrepared, "cleanup-done": core.CleanupDeleted} {
		out, stderr, code := f.run(t, "--format", "json", "restore", id)
		if code != ExitOK {
			t.Fatalf("restore %s preview: exit=%d %s %s", id, code, out, stderr)
		}
		var doc struct {
			Data cleanupReport `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Data.Items) != 1 ||
			doc.Data.Items[0].State != state || doc.Data.Items[0].Entry.Path != doc.Data.Items[0].Source {
			t.Fatalf("restore %s preview: %v %s", id, err, out)
		}
	}
}

func TestScanPersistsWhenClockFallsBehindHistory(t *testing.T) {
	f := newFixture(t)
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(24 * time.Hour)
	if err := db.Write(ctx, func(tx *store.Tx) error {
		for i := range 300 {
			at := future.Add(time.Duration(i) * time.Minute)
			scan := core.Scan{ID: fmt.Sprintf("future-%03d", i), Roots: []string{f.home},
				Status: core.ScanCompleted, StartedAt: at, FinishedAt: &at}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := f.run(t, "--format", "json", "scan", "--no-git", "--no-processes", "--no-services")
	if code != ExitOK {
		t.Fatalf("scan: exit=%d stderr=%s", code, stderr)
	}
	var doc struct {
		Data scanReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("scan result: %v", err)
	}
	if !doc.Data.Persisted || doc.Data.Scan.ID == "" {
		t.Fatalf("scan did not report a persisted ID: %+v", doc.Data)
	}
	db, err = store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(ctx, func(tx *store.Tx) error {
		_, err := tx.Scan(ctx, doc.Data.Scan.ID)
		return err
	}); err != nil {
		t.Fatalf("new scan self-trimmed under clock skew: %v", err)
	}
}
