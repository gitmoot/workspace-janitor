package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// openFixture opens a store inside an isolated fixture state directory. No
// test in this package touches the operator's real state.
func openFixture(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "janitor.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func fixtureScan(id string, at time.Time) core.Scan {
	return core.Scan{
		ID:        id,
		Roots:     []string{"/repos"},
		Status:    core.ScanRunning,
		StartedAt: at,
	}
}

func fixtureEntry(path string, at time.Time) core.Entry {
	return core.Entry{
		Path:         path,
		Root:         "/repos",
		Kind:         core.EntryKindDirectory,
		FilesystemID: core.FilesystemID{Device: 64, Inode: 4242},
		Ownership:    core.Ownership{UID: 1000, GID: 1000, Mode: "0755"},
		SizeBytes:    4096,
		ModifiedAt:   at,
		AccessedAt:   at,
		ObservedAt:   at,
		Class:        core.ClassTaskWorktree,
		Git: &core.GitState{
			RepoRoot:           path,
			Branch:             "feature/x",
			Head:               "0123456789abcdef",
			UpstreamKnown:      true,
			DirtyFiles:         2,
			UnpublishedCommits: 1,
		},
		Evidence: []core.Evidence{
			{Source: core.SourceGit, Signal: "dirty_worktree", Detail: "2 modified files", ObservedAt: at},
		},
		Protections: []core.Protection{
			{Kind: core.ProtectDirtyRepository, Reason: "2 modified files", Source: core.SourceGit, Blocking: true},
		},
		Recommendation: &core.Recommendation{
			Action:     core.ActionKeep,
			Class:      core.ClassTaskWorktree,
			Retention:  core.RetentionNone,
			Confidence: 0.9,
			Origin:     core.OriginRules,
			Reasons:    []string{"unpublished local work"},
			DecidedAt:  at,
		},
	}
}

func TestOpenAppliesMigrations(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)

	stats, err := db.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.SchemaVersion != SchemaVersion() {
		t.Errorf("schema version = %d, want %d", stats.SchemaVersion, SchemaVersion())
	}

	var applied []AppliedMigration
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		applied, err = tx.AppliedMigrations(ctx)
		return err
	}); err != nil {
		t.Fatalf("AppliedMigrations: %v", err)
	}
	if len(applied) != len(migrations) {
		t.Fatalf("recorded %d migrations, want %d", len(applied), len(migrations))
	}

	// Reopening must be a no-op rather than re-running a migration.
	reopened, err := Open(ctx, db.Path())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	reopenedStats, err := reopened.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats after reopen: %v", err)
	}
	if reopenedStats.SchemaVersion != SchemaVersion() {
		t.Errorf("schema version after reopen = %d", reopenedStats.SchemaVersion)
	}
}

func TestOpenExistingReportsUninitializedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "janitor.db")
	_, err := OpenExisting(context.Background(), path)
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}

// Acceptance for issue #2: an isolated fixture config can create the store
// and round-trip one inventory record without loss.
func TestInventoryRecordRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	entry := fixtureEntry("/repos/app", at)

	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		return tx.PutEntry(ctx, "scan-1", entry)
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	var loaded core.Entry
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		loaded, err = tx.Entry(ctx, "scan-1", "/repos/app")
		return err
	}); err != nil {
		t.Fatalf("read: %v", err)
	}

	entry.Normalize()
	want, err := core.MarshalJSON(entry)
	if err != nil {
		t.Fatalf("marshal expected: %v", err)
	}
	got, err := core.MarshalJSON(loaded)
	if err != nil {
		t.Fatalf("marshal loaded: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("round trip changed the record:\n got: %s\nwant: %s", got, want)
	}
	if !loaded.Protected() {
		t.Error("protections were lost in the round trip")
	}
}

func TestPutEntryRejectsInvalidRecord(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Now().UTC()
	err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		bad := fixtureEntry("relative/path", at)
		return tx.PutEntry(ctx, "scan-1", bad)
	})
	if err == nil {
		t.Fatal("expected an invalid entry to be rejected")
	}
}

// A failing write must leave no partial state behind.
func TestWriteRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Now().UTC()
	sentinel := errors.New("collector failed")

	err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		if err := tx.PutEntry(ctx, "scan-1", fixtureEntry("/repos/app", at)); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the sentinel", err)
	}
	stats, err := db.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Scans != 0 || stats.InventoryEntries != 0 {
		t.Errorf("rollback left state behind: %d scan(s), %d entrie(s)", stats.Scans, stats.InventoryEntries)
	}
}

func TestPutEntryUpsertsAndScanUpdates(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		if err := tx.PutEntry(ctx, "scan-1", fixtureEntry("/repos/app", at)); err != nil {
			return err
		}
		updated := fixtureEntry("/repos/app", at)
		updated.SizeBytes = 8192
		return tx.PutEntry(ctx, "scan-1", updated)
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	finished := at.Add(time.Minute)
	if err := db.Write(ctx, func(tx *Tx) error {
		scan, err := tx.Scan(ctx, "scan-1")
		if err != nil {
			return err
		}
		scan.Status = core.ScanCompleted
		scan.FinishedAt = &finished
		scan.EntryCount = 1
		return tx.UpdateScan(ctx, scan)
	}); err != nil {
		t.Fatalf("update scan: %v", err)
	}

	if err := db.Read(ctx, func(tx *Tx) error {
		entries, err := tx.Entries(ctx, "scan-1")
		if err != nil {
			return err
		}
		if len(entries) != 1 {
			t.Fatalf("entries = %d, want 1 after upsert", len(entries))
		}
		if entries[0].SizeBytes != 8192 {
			t.Errorf("size = %d, want the updated value", entries[0].SizeBytes)
		}
		scan, err := tx.Scan(ctx, "scan-1")
		if err != nil {
			return err
		}
		if scan.Status != core.ScanCompleted || scan.EntryCount != 1 {
			t.Errorf("scan = %+v, want a completed scan with one entry", scan)
		}
		if scan.FinishedAt == nil || !scan.FinishedAt.Equal(finished) {
			t.Errorf("finished_at = %v, want %v", scan.FinishedAt, finished)
		}
		if len(scan.Roots) != 1 || scan.Roots[0] != "/repos" {
			t.Errorf("roots = %v", scan.Roots)
		}
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestPlanAndActionsRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	plan := core.Plan{
		ID:        "plan-1",
		ScanID:    "scan-1",
		Status:    core.PlanReady,
		CreatedAt: at,
		Actions: []core.Action{
			{
				ID: "action-2", Path: "/repos/zeta", Kind: core.ActionQuarantine,
				Retention: core.Retention30Days, Confidence: 0.7, CreatedAt: at,
				FilesystemID: core.FilesystemID{Device: 64, Inode: 11},
				Reasons:      []string{"regenerable build output"},
				Guards:       []string{"identity_revalidated"},
			},
			{
				ID: "action-1", Path: "/repos/alpha", Kind: core.ActionKeep,
				Confidence: 1, CreatedAt: at,
			},
		},
	}

	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		return tx.SavePlan(ctx, plan)
	}); err != nil {
		t.Fatalf("save plan: %v", err)
	}

	applied := at.Add(time.Hour)
	if err := db.Write(ctx, func(tx *Tx) error {
		return tx.UpdateActionStatus(ctx, "action-2", core.ActionApplied, &applied)
	}); err != nil {
		t.Fatalf("update action: %v", err)
	}

	if err := db.Read(ctx, func(tx *Tx) error {
		loaded, err := tx.Plan(ctx, "plan-1")
		if err != nil {
			return err
		}
		if loaded.Status != core.PlanReady || !loaded.CreatedAt.Equal(at) {
			t.Errorf("plan = %+v", loaded)
		}
		if len(loaded.Actions) != 2 {
			t.Fatalf("actions = %d, want 2", len(loaded.Actions))
		}
		if loaded.Actions[0].Path != "/repos/alpha" {
			t.Errorf("actions are not ordered by path: %+v", loaded.Actions)
		}
		quarantine := loaded.Actions[1]
		if quarantine.Status != core.ActionApplied {
			t.Errorf("status = %q, want applied", quarantine.Status)
		}
		if quarantine.AppliedAt == nil || !quarantine.AppliedAt.Equal(applied) {
			t.Errorf("applied_at = %v, want %v", quarantine.AppliedAt, applied)
		}
		if len(quarantine.Reasons) != 1 || quarantine.Reasons[0] != "regenerable build output" {
			t.Errorf("reasons = %v", quarantine.Reasons)
		}
		if quarantine.FilesystemID.Inode != 11 {
			t.Errorf("filesystem identity lost: %+v", quarantine.FilesystemID)
		}
		plans, err := tx.ListPlans(ctx, 0)
		if err != nil {
			return err
		}
		if len(plans) != 1 {
			t.Errorf("ListPlans returned %d plans, want 1", len(plans))
		}
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestUpdateActionStatusUnknownIDIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	err := db.Write(ctx, func(tx *Tx) error {
		return tx.UpdateActionStatus(ctx, "missing", core.ActionApplied, nil)
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestSavePlanReplacesActionSet(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	plan := core.Plan{
		ID: "plan-1", ScanID: "scan-1", CreatedAt: at,
		Actions: []core.Action{{ID: "a", Path: "/repos/a", Kind: core.ActionKeep, CreatedAt: at}},
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		return tx.SavePlan(ctx, plan)
	}); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	plan.Actions = []core.Action{{ID: "b", Path: "/repos/b", Kind: core.ActionInvestigate, CreatedAt: at}}
	if err := db.Write(ctx, func(tx *Tx) error { return tx.SavePlan(ctx, plan) }); err != nil {
		t.Fatalf("resave plan: %v", err)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		loaded, err := tx.Plan(ctx, "plan-1")
		if err != nil {
			return err
		}
		if len(loaded.Actions) != 1 || loaded.Actions[0].ID != "b" {
			t.Errorf("actions = %+v, want only the new action", loaded.Actions)
		}
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// A row whose enum no longer matches the contract is corruption. Reading it
// must fail loudly rather than hand back a silently wrong action kind.
func TestPlanRejectsUnknownStoredEnum(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	plan := core.Plan{
		ID: "plan-1", ScanID: "scan-1", CreatedAt: at,
		Actions: []core.Action{{ID: "a", Path: "/repos/a", Kind: core.ActionKeep, CreatedAt: at}},
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		if err := tx.SavePlan(ctx, plan); err != nil {
			return err
		}
		_, err := tx.tx.ExecContext(ctx, `UPDATE actions SET kind = 'delete' WHERE id = 'a'`)
		return err
	}); err != nil {
		t.Fatalf("seed corrupt row: %v", err)
	}
	err := db.Read(ctx, func(tx *Tx) error {
		_, err := tx.Plan(ctx, "plan-1")
		return err
	})
	if err == nil {
		t.Fatal("expected an unknown stored action kind to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown action kind") {
		t.Errorf("error = %v, want an unknown action kind complaint", err)
	}
}

func TestModelUsageIsRecordedAndTotalled(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		if err := tx.RecordModelUsage(ctx, core.ModelUsage{
			ID: "usage-1", ScanID: "scan-1", Provider: "typesafe", Model: "jev-small",
			RequestKind: "classify", PromptTokens: 1200, CompletionTokens: 80,
			EstimatedCostUSD: 0.004, CreatedAt: at,
		}); err != nil {
			return err
		}
		// Usage without a scan must still be attributable.
		return tx.RecordModelUsage(ctx, core.ModelUsage{
			ID: "usage-2", Provider: "typesafe", Model: "jev-small",
			RequestKind: "probe", PromptTokens: 10, CompletionTokens: 5,
			EstimatedCostUSD: 0.001, CreatedAt: at,
		})
	}); err != nil {
		t.Fatalf("record usage: %v", err)
	}

	var totals UsageTotals
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		totals, err = tx.UsageTotals(ctx)
		return err
	}); err != nil {
		t.Fatalf("totals: %v", err)
	}
	if totals.Records != 2 || totals.PromptTokens != 1210 || totals.CompletionTokens != 85 {
		t.Errorf("totals = %+v", totals)
	}
	if totals.EstimatedCostUSD < 0.0049 || totals.EstimatedCostUSD > 0.0051 {
		t.Errorf("estimated cost = %v, want ~0.005", totals.EstimatedCostUSD)
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Now().UTC()
	err := db.Write(ctx, func(tx *Tx) error {
		return tx.PutEntry(ctx, "missing-scan", fixtureEntry("/repos/app", at))
	})
	if err == nil {
		t.Fatal("expected an entry for an unknown scan to be rejected by the foreign key")
	}
}

func TestOpenRejectsRelativePath(t *testing.T) {
	if _, err := Open(context.Background(), "relative/janitor.db"); err == nil {
		t.Fatal("expected a relative database path to be rejected")
	}
}
