package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
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

// A plan is immutable once written: reviews, approvals, and apply
// decisions are all made against a specific document, so changing one
// behind its id would invalidate every one of them. Saving the identical
// document again is allowed and does nothing.
func TestSavePlanIsImmutable(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	plan := core.Plan{
		ID: "plan-1", ScanID: "scan-1", CreatedAt: at,
		EvidenceDigest: "evidence-1", PolicyDigest: "policy-1",
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

	// Saving the same document again is a no-op, not an error: replaying a
	// planning run must not fail.
	if err := db.Write(ctx, func(tx *Tx) error { return tx.SavePlan(ctx, plan) }); err != nil {
		t.Fatalf("re-saving an identical plan failed: %v", err)
	}

	changed := plan
	changed.Actions = []core.Action{{ID: "b", Path: "/repos/b", Kind: core.ActionQuarantine, CreatedAt: at}}
	err := db.Write(ctx, func(tx *Tx) error { return tx.SavePlan(ctx, changed) })
	if !errors.Is(err, ErrImmutable) {
		t.Fatalf("error = %v, want ErrImmutable", err)
	}

	if err := db.Read(ctx, func(tx *Tx) error {
		loaded, err := tx.Plan(ctx, "plan-1")
		if err != nil {
			return err
		}
		if len(loaded.Actions) != 1 || loaded.Actions[0].ID != "a" {
			t.Errorf("actions = %+v, want the original set", loaded.Actions)
		}
		if loaded.EvidenceDigest != "evidence-1" || loaded.PolicyDigest != "policy-1" {
			t.Errorf("plan = %+v, want its bindings preserved", loaded)
		}
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// Approvals live beside the plan so approving never edits it.
func TestApprovalsAreRecordedBesideTheImmutablePlan(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	plan := core.Plan{
		ID: "plan-1", ScanID: "scan-1", CreatedAt: at,
		EvidenceDigest: "evidence-1", PolicyDigest: "policy-1",
		Actions: []core.Action{
			{ID: "a", Path: "/repos/a", Kind: core.ActionQuarantine, Retention: core.Retention30Days, CreatedAt: at},
			{ID: "b", Path: "/repos/b", Kind: core.ActionKeep, CreatedAt: at},
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

	approved := at.Add(time.Hour)
	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.Approve(ctx, core.Approval{
			PlanID: "plan-1", ActionID: "a", Approver: "operator",
			ApprovedAt: approved, Note: "reviewed the diff",
		}); err != nil {
			return err
		}
		// Approving twice must not error or rewrite the first record.
		return tx.Approve(ctx, core.Approval{
			PlanID: "plan-1", ActionID: "a", Approver: "someone-else",
			ApprovedAt: approved.Add(time.Hour),
		})
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if err := db.Read(ctx, func(tx *Tx) error {
		approvals, err := tx.Approvals(ctx, "plan-1")
		if err != nil {
			return err
		}
		if len(approvals) != 1 {
			t.Fatalf("approvals = %+v, want exactly one", approvals)
		}
		if approvals[0].ActionID != "a" || approvals[0].Approver != "operator" {
			t.Errorf("approval = %+v, want the first one kept", approvals[0])
		}
		if !approvals[0].ApprovedAt.Equal(approved) {
			t.Errorf("approved_at = %v, want %v", approvals[0].ApprovedAt, approved)
		}
		loaded, err := tx.Plan(ctx, "plan-1")
		if err != nil {
			return err
		}
		if len(loaded.Actions) != 2 {
			t.Errorf("approving changed the plan: %+v", loaded.Actions)
		}
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// A plan must survive a restart unchanged, including its rationale.
func TestPlanSurvivesReopenWithItsRationale(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "janitor.db")
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	plan := core.Plan{
		ID: "plan-1", ScanID: "scan-1", Status: core.PlanReady, CreatedAt: at,
		EvidenceDigest: "evidence-1", PolicyDigest: "policy-1",
		Actions: []core.Action{{
			ID: "a", Path: "/repos/app/node_modules", Kind: core.ActionQuarantine,
			Class: core.ClassGeneratedArtifact, Retention: core.Retention30Days,
			Confidence: 0.9, Fingerprint: "fingerprint-1", CreatedAt: at,
			Reasons:  []string{"node_modules matches a generated artifact name"},
			Rules:    []string{"classify.generated", "builtin.generated_artifact"},
			Rejected: []core.RejectedAction{{Kind: core.ActionKeep, Rule: "builtin.unknown", Reason: "classified"}},
			Guards:   []string{"git_state"},
		}},
	}

	first, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := first.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		return tx.SavePlan(ctx, plan)
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	var loaded core.Plan
	if err := reopened.Read(ctx, func(tx *Tx) error {
		var err error
		loaded, err = tx.LatestPlan(ctx, "scan-1")
		return err
	}); err != nil {
		t.Fatalf("read after restart: %v", err)
	}

	plan.Normalize()
	want, err := core.MarshalJSON(plan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := core.MarshalJSON(loaded)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("plan changed across a restart:\n got: %s\nwant: %s", got, want)
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
			ID: "usage-1", ScanID: "scan-1", Provider: "openrouter", Model: "typesafe/jev-1.13",
			RequestKind: "classify", PromptTokens: 1200, CompletionTokens: 80,
			EstimatedCostUSD: 0.004, CreatedAt: at,
		}); err != nil {
			return err
		}
		// Usage without a scan must still be attributable.
		return tx.RecordModelUsage(ctx, core.ModelUsage{
			ID: "usage-2", Provider: "openrouter", Model: "typesafe/jev-1.13",
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

// Stats carries both versions a consumer needs. Publishing a zero contract
// version next to a valid schema version would be contradictory metadata.
func TestStatsReportsBothVersions(t *testing.T) {
	stats, err := openFixture(t).Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.ContractVersion != core.ContractVersion {
		t.Errorf("contract version = %d, want %d", stats.ContractVersion, core.ContractVersion)
	}
	if stats.SchemaVersion != SchemaVersion() {
		t.Errorf("schema version = %d, want %d", stats.SchemaVersion, SchemaVersion())
	}
}

func TestScanCollectorReportsRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

	scan := fixtureScan("scan-1", at)
	scan.Collectors = []core.CollectorReport{
		{Name: "git", Status: core.CollectorPartial, Detail: "one repository timed out", Visited: 3, Recorded: 2, Unknowns: 1},
		{Name: "filesystem", Status: core.CollectorRan, Visited: 12, Recorded: 12},
	}
	if err := db.Write(ctx, func(tx *Tx) error { return tx.CreateScan(ctx, scan) }); err != nil {
		t.Fatalf("create scan: %v", err)
	}

	var loaded core.Scan
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		loaded, err = tx.Scan(ctx, "scan-1")
		return err
	}); err != nil {
		t.Fatalf("read scan: %v", err)
	}
	if len(loaded.Collectors) != 2 {
		t.Fatalf("collectors = %+v, want 2 reports", loaded.Collectors)
	}
	// Normalize sorts reports by name, so the order is part of the contract.
	if loaded.Collectors[0].Name != "filesystem" || loaded.Collectors[1].Name != "git" {
		t.Errorf("collector order = %+v, want name order", loaded.Collectors)
	}
	git := loaded.Collectors[1]
	if git.Status != core.CollectorPartial || git.Unknowns != 1 || git.Detail == "" {
		t.Errorf("git report = %+v", git)
	}

	// An updated scan must replace the reports rather than keep the old set.
	scan = loaded
	scan.Status = core.ScanCompleted
	scan.Collectors = []core.CollectorReport{{Name: "filesystem", Status: core.CollectorRan, Visited: 12, Recorded: 12}}
	if err := db.Write(ctx, func(tx *Tx) error { return tx.UpdateScan(ctx, scan) }); err != nil {
		t.Fatalf("update scan: %v", err)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		updated, err := tx.Scan(ctx, "scan-1")
		if err != nil {
			return err
		}
		if len(updated.Collectors) != 1 {
			t.Errorf("collectors after update = %+v, want only the new report", updated.Collectors)
		}
		return nil
	}); err != nil {
		t.Fatalf("read scan: %v", err)
	}
}

func TestScanRejectsUnknownStoredCollectorStatus(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Now().UTC()
	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		_, err := tx.tx.ExecContext(ctx,
			`UPDATE scans SET collectors = '[{"name":"git","status":"probably-fine"}]' WHERE id = 'scan-1'`)
		return err
	}); err != nil {
		t.Fatalf("seed corrupt row: %v", err)
	}
	err := db.Read(ctx, func(tx *Tx) error {
		_, err := tx.Scan(ctx, "scan-1")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "unknown collector status") {
		t.Fatalf("error = %v, want an unknown collector status complaint", err)
	}
}

func TestLatestScanFiltersByStatus(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	base := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

	older := fixtureScan("scan-old", base)
	older.Status = core.ScanCompleted
	newer := fixtureScan("scan-new", base.Add(time.Hour))
	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, older); err != nil {
			return err
		}
		return tx.CreateScan(ctx, newer)
	}); err != nil {
		t.Fatalf("create scans: %v", err)
	}

	if err := db.Read(ctx, func(tx *Tx) error {
		completed, err := tx.LatestScan(ctx, core.ScanCompleted)
		if err != nil {
			return err
		}
		if completed.ID != "scan-old" {
			t.Errorf("latest completed = %q, want scan-old", completed.ID)
		}
		if _, err := tx.LatestScan(ctx, core.ScanFailed); !errors.Is(err, ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound when no scan has that status", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// The indexed fingerprint column exists so a later scan can find unchanged
// entries without decoding every document; it must actually be populated.
func TestPutEntryPopulatesFingerprintColumn(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	entry := fixtureEntry("/repos/app", at)
	entry.Fingerprint = "abc123"

	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.CreateScan(ctx, fixtureScan("scan-1", at)); err != nil {
			return err
		}
		return tx.PutEntry(ctx, "scan-1", entry)
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := db.Read(ctx, func(tx *Tx) error {
		var stored string
		if err := tx.tx.QueryRowContext(ctx,
			`SELECT fingerprint FROM inventories WHERE scan_id = 'scan-1' AND path = '/repos/app'`).Scan(&stored); err != nil {
			return err
		}
		if stored != "abc123" {
			t.Errorf("fingerprint column = %q, want the entry fingerprint", stored)
		}
		loaded, err := tx.Entry(ctx, "scan-1", "/repos/app")
		if err != nil {
			return err
		}
		if loaded.Fingerprint != "abc123" {
			t.Errorf("document fingerprint = %q", loaded.Fingerprint)
		}
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// A reporting-only command must leave the database byte-identical: no
// migration, no journal-mode change, no permission change.
func TestOpenReadOnlyDoesNotMutateTheDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "janitor.db")
	writable, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	at := time.Now().UTC()
	if err := writable.Write(ctx, func(tx *Tx) error {
		return tx.CreateScan(ctx, fixtureScan("scan-1", at))
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writable.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	before := digestOf(t, path)

	readOnly, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	if !readOnly.ReadOnly() {
		t.Error("handle does not report itself read-only")
	}
	var scans int
	if err := readOnly.Read(ctx, func(tx *Tx) error {
		scan, err := tx.LatestScan(ctx, core.ScanRunning)
		if err != nil {
			return err
		}
		if scan.ID != "scan-1" {
			t.Errorf("scan = %q, want scan-1", scan.ID)
		}
		scans++
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	if scans != 1 {
		t.Errorf("read %d scans, want 1", scans)
	}

	// A write through a read-only handle must be refused, not attempted.
	if err := readOnly.Write(ctx, func(tx *Tx) error {
		return tx.CreateScan(ctx, fixtureScan("scan-2", at))
	}); err == nil {
		t.Error("a read-only handle accepted a write")
	}
	if err := readOnly.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if after := digestOf(t, path); after != before {
		t.Errorf("database changed during a read-only open:\n before %s\n after  %s", before, after)
	}
	// A WAL reader has to map the shared-memory index, so the -shm and -wal
	// sidecars may appear. They must stay empty: no data was written and no
	// transaction was committed.
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() != 0 {
		t.Errorf("write-ahead log is %d bytes after a read-only open, want empty", info.Size())
	}
	version := userVersionOf(t, path)
	if version != SchemaVersion() {
		t.Errorf("schema version = %d after a read-only open, want %d", version, SchemaVersion())
	}
}

// userVersionOf reads the schema version through a fresh writable handle.
func userVersionOf(t *testing.T, path string) int {
	t.Helper()
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	version, err := db.userVersion(context.Background())
	if err != nil {
		t.Fatalf("user_version: %v", err)
	}
	return version
}

// An out-of-date database must be reported, never silently migrated, by a
// read-only open.
func TestOpenReadOnlyRefusesSchemaMismatchInsteadOfMigrating(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "janitor.db")
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		_, err := tx.tx.ExecContext(ctx, "PRAGMA user_version = 1")
		return err
	}); err != nil {
		t.Fatalf("downgrade version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = OpenReadOnly(ctx, path)
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("error = %v, want ErrSchemaMismatch", err)
	}
	reopened, err := OpenReadOnly(ctx, path)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("second open error = %v, want ErrSchemaMismatch: the first must not have migrated", err)
	}
}

func TestOpenReadOnlyReportsUninitializedState(t *testing.T) {
	_, err := OpenReadOnly(context.Background(), filepath.Join(t.TempDir(), "janitor.db"))
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}

// digestOf fingerprints the database file and its mode, so any write to the
// durable database or change of its permissions is visible.
func digestOf(t *testing.T, path string) string {
	t.Helper()
	parts := make([]string, 0, 1)
	for _, candidate := range []string{path} {
		info, err := os.Stat(candidate)
		if err != nil {
			parts = append(parts, filepath.Base(candidate)+":absent")
			continue
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			t.Fatalf("read %s: %v", candidate, err)
		}
		parts = append(parts, fmt.Sprintf("%s:%o:%x", filepath.Base(candidate), info.Mode().Perm(), sha256.Sum256(data)))
	}
	return strings.Join(parts, " ")
}

// A cached model answer is served until it expires, and never after: a
// stale answer must not be reused as if it were fresh.
func TestModelDecisionIsCachedUntilItExpires(t *testing.T) {
	db := openFixture(t)
	ctx := context.Background()
	at := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	want := core.Recommendation{
		Action: core.ActionKeep, Class: core.ClassOperationalTool, Retention: core.RetentionNone,
		Confidence: 0.9, Origin: core.OriginModel, Reasons: []string{"model: keep"}, DecidedAt: at,
	}
	decision := ModelDecision{
		Key: "key-1", Fingerprint: "fp-1", SchemaVersion: 1, Model: "typesafe/jev-1.13",
		PolicyDigest: "policy-1", ResolvedModel: "typesafe/jev-1.13", Recommendation: want,
		CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour),
	}
	if err := db.Write(ctx, func(tx *Tx) error { return tx.PutModelDecision(ctx, decision) }); err != nil {
		t.Fatalf("put: %v", err)
	}

	lookup := func(key string, now time.Time) (core.Recommendation, bool) {
		t.Helper()
		var (
			got   core.Recommendation
			found bool
		)
		if err := db.Read(ctx, func(tx *Tx) error {
			var err error
			got, found, err = tx.ModelDecision(ctx, key, now)
			return err
		}); err != nil {
			t.Fatalf("lookup: %v", err)
		}
		return got, found
	}

	got, found := lookup("key-1", at.Add(time.Hour))
	if !found || got.Action != want.Action || got.Class != want.Class || got.Origin != core.OriginModel {
		t.Errorf("fresh lookup = %+v, %t; want %+v", got, found, want)
	}
	if _, found := lookup("key-1", at.Add(24*time.Hour)); found {
		t.Error("an expired decision was served")
	}
	if _, found := lookup("key-2", at); found {
		t.Error("an unknown key was served")
	}

	// A newer answer under the same key replaces the old one.
	decision.Recommendation.Action = core.ActionInvestigate
	decision.ExpiresAt = at.Add(48 * time.Hour)
	if err := db.Write(ctx, func(tx *Tx) error { return tx.PutModelDecision(ctx, decision) }); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got, found := lookup("key-1", at.Add(30*time.Hour)); !found || got.Action != core.ActionInvestigate {
		t.Errorf("replaced lookup = %+v, %t; want the newer investigate", got, found)
	}
}
