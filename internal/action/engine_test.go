//go:build linux

package action

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

func fixtureEngine(t *testing.T) (*Engine, string, *time.Time) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	state := filepath.Join(base, "state")
	proc := filepath.Join(base, "proc")
	units := filepath.Join(base, "units")
	for _, p := range []string{root, state, proc, units} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(context.Background(), filepath.Join(state, "janitor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now().UTC()
	quarantine := filepath.Join(state, "quarantine")
	return &Engine{DB: db, QuarantineDir: quarantine, Policy: safety.Policy{StateDir: state, QuarantineDir: quarantine, ProtectedPaths: []string{state, quarantine}},
		Collect: collect.Options{Git: true, Processes: true, Services: true, ProcRoot: proc, ServiceSources: collect.ServiceSources{SystemdDirs: []string{units}},
			Limits: collect.Limits{GitTimeout: 5 * time.Second, CommandTimeout: 5 * time.Second, MaxEntries: 300, MaxDirEntries: 300, DeepSizeMaxEntries: 300, DeepSizeMaxDepth: 5}},
		Now: func() time.Time { return now }}, root, &now
}

func prepareFixture(t *testing.T, e *Engine, source string, retention core.Retention) core.CleanupItem {
	t.Helper()
	ctx := context.Background()
	entry, err := e.recollect(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	act := core.Action{ID: "action-1", PlanID: "plan-1", Path: source, Kind: core.ActionQuarantine, Status: core.ActionPending, Retention: retention, FilesystemID: entry.FilesystemID, CreatedAt: e.now(), Fingerprint: entry.Fingerprint}
	item, err := e.Prepare(ctx, core.CleanupItem{CleanupID: "cleanup-fixture", PlanID: act.PlanID, ActionID: act.ID, Source: source, Entry: entry, Action: act})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestQuarantineRestorePreservesObjectAndRefusesCollision(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink", "standalone_repo"} {
		t.Run(kind, func(t *testing.T) {
			e, root, _ := fixtureEngine(t)
			ctx := context.Background()
			source := filepath.Join(root, "artifact")
			switch kind {
			case "file":
				if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, "child"), []byte("data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.WriteFile(filepath.Join(root, "target"), []byte("target"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", source); err != nil {
					t.Fatal(err)
				}
			case "standalone_repo":
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
				fixtureGit(t, root, source, "init")
				if err := os.WriteFile(filepath.Join(source, "README"), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				fixtureGit(t, root, source, "add", "README")
				fixtureGit(t, root, source, "commit", "-m", "fixture")
				remote := filepath.Join(root, "upstream.git")
				if err := os.Mkdir(remote, 0700); err != nil {
					t.Fatal(err)
				}
				fixtureGit(t, root, remote, "init", "--bare")
				fixtureGit(t, root, source, "remote", "add", "origin", remote)
				fixtureGit(t, root, source, "push", "-u", "origin", "HEAD")
			}
			before, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			item := prepareFixture(t, e, source, core.Retention30Days)
			item, err = e.Quarantine(ctx, item)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(source); !os.IsNotExist(err) {
				t.Fatalf("source after move: %v", err)
			}
			moved, err := os.Lstat(item.Destination)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, moved) || before.Mode() != moved.Mode() || !before.ModTime().Equal(moved.ModTime()) {
				t.Fatal("rename changed object identity, mode or timestamp")
			}
			if kind == "symlink" {
				link, err := os.Readlink(item.Destination)
				if err != nil || link != "target" {
					t.Fatalf("symlink changed: %q %v", link, err)
				}
			}
			if err := os.WriteFile(source, []byte("occupied"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Restore(ctx, item); err == nil {
				t.Fatal("restore overwrote occupied source")
			}
			if raw, err := os.ReadFile(source); err != nil || string(raw) != "occupied" {
				t.Fatalf("occupied source changed: %q %v", raw, err)
			}
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			item, err = e.Restore(ctx, item)
			if err != nil {
				t.Fatal(err)
			}
			if item.State != core.CleanupRestored {
				t.Fatalf("state %s", item.State)
			}
			restored, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, restored) || before.Mode() != restored.Mode() || !before.ModTime().Equal(restored.ModTime()) {
				t.Fatal("restore did not preserve object metadata")
			}
		})
	}
}

func TestQuarantineRestoresRegisteredLinkedWorktree(t *testing.T) {
	owner, linked, _, home := linkedFixture(t)
	e, _, _ := fixtureEngine(t)
	remote := filepath.Join(filepath.Dir(owner), "upstream.git")
	if err := os.Mkdir(remote, 0700); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, home, remote, "init", "--bare")
	fixtureGit(t, home, owner, "remote", "add", "origin", remote)
	fixtureGit(t, home, linked, "push", "-u", "origin", "HEAD")
	ctx := context.Background()
	item := prepareFixture(t, e, linked, core.Retention30Days)
	if item.Entry.Git == nil || item.Entry.Git.WorktreeOf != owner {
		t.Fatalf("not a registered linked worktree: %+v", item.Entry.Git)
	}
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLinkedWorktree(ctx, owner, item.Destination); err != nil {
		t.Fatalf("moved worktree lost Git registration: %v", err)
	}
	item, err = e.Restore(ctx, item)
	if err != nil || item.State != core.CleanupRestored {
		t.Fatalf("restore linked worktree: %+v %v", item, err)
	}
	if err := VerifyLinkedWorktree(ctx, owner, linked); err != nil {
		t.Fatalf("restored worktree lost Git registration: %v", err)
	}
}

func TestQuarantineRefusesOccupiedDestinationWithoutMovingSource(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	if err := os.WriteFile(item.Destination, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Quarantine(context.Background(), item); err == nil {
		t.Fatal("overwrote occupied destination")
	}
	for path, want := range map[string]string{source: "source", item.Destination: "occupied"} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != want {
			t.Fatalf("%s changed: %q %v", path, raw, err)
		}
	}
}

func TestPreparedManifestRecoversAfterInterruptedWrite(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	path := filepath.Join(filepath.Dir(item.Destination), "manifest.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	} // crash between journal commit and manifest install
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || !strings.Contains(string(raw), item.Source) {
		t.Fatalf("recovered manifest cannot reconstruct moved source: %v", err)
	}
	if item.State != core.CleanupQuarantined {
		t.Fatalf("move state: %s", item.State)
	}
}

func TestFailedJournalInsertLeavesNoBlockingManifest(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	active := prepareFixture(t, e, source, core.Retention30Days)
	entry, err := e.recollect(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	act := active.Action
	act.ID, act.PlanID = "action-2", "plan-2"
	attempt := core.CleanupItem{CleanupID: "cleanup-new", PlanID: act.PlanID, ActionID: act.ID, Source: source, Entry: entry, Action: act}
	if _, err := e.Prepare(ctx, attempt); err == nil {
		t.Fatal("duplicate active source was accepted")
	}
	manifest := filepath.Join(e.QuarantineDir, attempt.CleanupID, attempt.ActionID, "manifest.json")
	if _, err := os.Lstat(manifest); !os.IsNotExist(err) {
		t.Fatalf("failed insert left an orphan manifest: %v", err)
	}
	if _, err := e.Restore(ctx, active); err != nil {
		t.Fatal(err)
	}
	retry, err := e.Prepare(ctx, attempt)
	if err != nil || retry.State != core.CleanupPrepared {
		t.Fatalf("failed insert blocked retry: %+v %v", retry, err)
	}
}

func TestPrepareRejectsReceiptPathTraversal(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	entry, err := e.recollect(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][2]string{{"cleanup-fixture", "../../escaped"}, {"../../escaped", "action-safe"}} {
		act := core.Action{ID: ids[1], PlanID: "plan-1", Path: source, Kind: core.ActionQuarantine, Status: core.ActionPending,
			Retention: core.Retention30Days, FilesystemID: entry.FilesystemID, CreatedAt: e.now()}
		_, err := e.Prepare(context.Background(), core.CleanupItem{CleanupID: ids[0], PlanID: act.PlanID, ActionID: act.ID, Source: source, Entry: entry, Action: act})
		if err == nil || !strings.Contains(err.Error(), "single safe path component") {
			t.Fatalf("unsafe ID accepted: %v", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(e.QuarantineDir), "escaped")); !os.IsNotExist(err) {
		t.Fatalf("ID escaped receipt root: %v", err)
	}
}

func TestQuarantineRefusesSymlinkedDestination(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, e.QuarantineDir); err != nil {
		t.Fatal(err)
	}
	entry, err := e.recollect(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	act := core.Action{ID: "action-1", PlanID: "plan-1", Path: source, Kind: core.ActionQuarantine, Status: core.ActionPending, Retention: core.Retention30Days, FilesystemID: entry.FilesystemID, CreatedAt: e.now()}
	_, err = e.Prepare(context.Background(), core.CleanupItem{CleanupID: "cleanup-fixture", PlanID: act.PlanID, ActionID: act.ID, Source: source, Entry: entry, Action: act})
	if err == nil || !strings.Contains(err.Error(), "without symlinks") {
		t.Fatalf("symlinked quarantine directory not refused: %v", err)
	}
	if _, err := os.Lstat(source); err != nil {
		t.Fatal("refusal mutated source")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target changed: %v %v", entries, err)
	}
}

func TestCrossFilesystemQuarantineRefusesBeforeMove(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	shm, err := os.MkdirTemp("/dev/shm", "janitor-cross-device-")
	if err != nil {
		t.Skipf("no independent fixture filesystem: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(shm) })
	left, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.Stat(shm)
	if err != nil {
		t.Fatal(err)
	}
	if filesystemID(left).Device == filesystemID(right).Device {
		t.Skip("fixture filesystems are the same device")
	}
	e.QuarantineDir = filepath.Join(shm, "quarantine")
	entry, err := e.recollect(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	act := core.Action{ID: "action-1", PlanID: "plan-1", Path: source, Kind: core.ActionQuarantine, Status: core.ActionPending, Retention: core.Retention30Days, FilesystemID: entry.FilesystemID, CreatedAt: e.now()}
	_, err = e.Prepare(context.Background(), core.CleanupItem{CleanupID: "cleanup-fixture", PlanID: act.PlanID, ActionID: act.ID, Source: source, Entry: entry, Action: act})
	if err == nil || !strings.Contains(err.Error(), "cross-filesystem") {
		t.Fatalf("cross-device move not refused: %v", err)
	}
	if _, err := os.Lstat(source); err != nil {
		t.Fatal("refusal mutated original")
	}
}

func TestRestartReconcilesMovedButUnjournaledItem(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	if err := renameNoReplace(source, item.Destination, item.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	path := e.DB.Path()
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e.DB = db
	items, err := e.Items(ctx, item.CleanupID)
	if err != nil || len(items) != 1 || items[0].State != core.CleanupPrepared {
		t.Fatalf("restart lost prepared receipt: %+v %v", items, err)
	}
	item, err = e.Reconcile(ctx, items[0])
	if err != nil {
		t.Fatal(err)
	}
	if item.State != core.CleanupQuarantined || item.Quarantined == nil {
		t.Fatalf("move not recovered: %+v", item)
	}
	item, err = e.Restore(ctx, item)
	if err != nil || item.State != core.CleanupRestored {
		t.Fatalf("restoration after crash: %+v %v", item, err)
	}
}

func TestPreparedReceiptCanBeCancelledAndSourceReplanned(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	first := prepareFixture(t, e, source, core.Retention30Days)
	cancelled, err := e.Restore(ctx, first)
	if err != nil || cancelled.State != core.CleanupRestored {
		t.Fatalf("cancel prepared receipt: %+v %v", cancelled, err)
	}
	if raw, err := os.ReadFile(source); err != nil || string(raw) != "unchanged" {
		t.Fatalf("source changed: %q %v", raw, err)
	}
	entry, err := e.recollect(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	act := first.Action
	act.ID, act.PlanID, act.CreatedAt = "action-2", "plan-2", e.now()
	act.FilesystemID, act.Fingerprint = entry.FilesystemID, entry.Fingerprint
	second, err := e.Prepare(ctx, core.CleanupItem{CleanupID: "cleanup-new", PlanID: act.PlanID, ActionID: act.ID, Source: source, Entry: entry, Action: act})
	if err != nil || second.State != core.CleanupPrepared {
		t.Fatalf("cancelled receipt still claims source: %+v %v", second, err)
	}
}

func TestRestartRecoversPartiallyAppliedBatchIndependently(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	for _, path := range []string{first, second} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	a := prepareFixture(t, e, first, core.Retention30Days)
	entry, err := e.recollect(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	act := core.Action{ID: "action-2", PlanID: "plan-1", Path: second, Kind: core.ActionQuarantine,
		Status: core.ActionPending, Retention: core.Retention30Days, FilesystemID: entry.FilesystemID,
		Fingerprint: entry.Fingerprint, CreatedAt: e.now()}
	b, err := e.Prepare(ctx, core.CleanupItem{CleanupID: a.CleanupID, PlanID: act.PlanID, ActionID: act.ID,
		Source: second, Entry: entry, Action: act})
	if err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(first, a.Destination, a.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	path := e.DB.Path()
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e.DB = db
	items, err := e.Items(ctx, a.CleanupID)
	if err != nil || len(items) != 2 {
		t.Fatalf("partial batch journal: %+v %v", items, err)
	}
	for _, item := range items {
		item, err = e.Reconcile(ctx, item)
		if err != nil {
			t.Fatal(err)
		}
		if item.ActionID == a.ActionID && item.State != core.CleanupQuarantined {
			t.Fatalf("moved item not recovered: %s", item.State)
		}
		if item.ActionID == b.ActionID {
			if item.State != core.CleanupPrepared {
				t.Fatalf("unmoved item changed: %s", item.State)
			}
			item, err = e.Quarantine(ctx, item)
			if err != nil {
				t.Fatal(err)
			}
		}
		item, err = e.Restore(ctx, item)
		if err != nil || item.State != core.CleanupRestored {
			t.Fatalf("independent restore: %+v %v", item, err)
		}
	}
}

func TestPartialMoveCanRestoreWithoutCollectorAfterRestart(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	if err := renameNoReplace(source, item.Destination, item.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	path := e.DB.Path()
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e.DB = db
	e.Collect.ProcRoot = filepath.Join(root, "unavailable-proc")
	items, err := e.Items(ctx, item.CleanupID)
	if err != nil || len(items) != 1 {
		t.Fatalf("missing receipt: %v", err)
	}
	item, err = e.Restore(ctx, items[0])
	if err != nil || item.State != core.CleanupRestored {
		t.Fatalf("partial restore refused: %+v %v", item, err)
	}
	if raw, err := os.ReadFile(source); err != nil || string(raw) != "payload" {
		t.Fatalf("recovered content: %q %v", raw, err)
	}
}

func TestRestartReconcilesCompletedRestore(t *testing.T) {
	e, root, _ := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(item.Destination, source, item.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	path := e.DB.Path()
	if err := e.DB.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e.DB = db
	items, err := e.Items(ctx, item.CleanupID)
	if err != nil || len(items) != 1 {
		t.Fatalf("missing receipt after restart: %v", err)
	}
	item, err = e.Restore(ctx, items[0])
	if err != nil || item.State != core.CleanupRestored {
		t.Fatalf("restore reconciliation: %+v %v", item, err)
	}
}

func TestExpiredUnchangedItemDeletesOnlyAfterSecondEvaluation(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "child"), []byte("nested"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if early, err := e.Delete(ctx, item); err == nil || early.State != core.CleanupQuarantined {
		t.Fatalf("early deletion changed state: %+v %v", early, err)
	}
	if _, err := os.Lstat(item.Destination); err != nil {
		t.Fatal("early deletion removed receipt")
	}
	*clock = clock.Add(31 * 24 * time.Hour)
	item, err = e.Delete(ctx, item)
	if err != nil || item.State != core.CleanupDeleted {
		t.Fatalf("expired deletion: %+v %v", item, err)
	}
	if _, err := os.Lstat(item.Destination); !os.IsNotExist(err) {
		t.Fatalf("expired receipt still exists: %v", err)
	}
}

func TestExpiryOfLargeReceiptDoesNotDependOnEstimateEntryLimit(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	source := filepath.Join(root, "candidate")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three", "four"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	// Estimates may be unavailable for a large receipt, but the anchored
	// deletion verifier streams the entire tree and still enforces mounts.
	e.Collect.Limits.DeepSizeMaxEntries = 2
	*clock = clock.Add(31 * 24 * time.Hour)
	deleted, err := e.Delete(context.Background(), item)
	if err != nil || deleted.State != core.CleanupDeleted {
		t.Fatalf("valid expired receipt was trapped by estimate limit: %+v %v", deleted, err)
	}
	if _, err := os.Lstat(item.Destination); !os.IsNotExist(err) {
		t.Fatalf("receipt still exists after deletion: %v", err)
	}
}

func TestExpiryNeedsTimeAndFreshUnreferencedEvidence(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Eligible(ctx, item); err == nil {
		t.Fatal("eligible before retention expiry")
	}
	*clock = clock.Add(31 * 24 * time.Hour)
	if err := e.Eligible(ctx, item); err != nil {
		t.Fatalf("unchanged expired receipt rejected: %v", err)
	}
	if err := os.WriteFile(item.Destination, []byte("changed content"), 0600); err != nil {
		t.Fatal(err)
	}
	item, err = e.Delete(ctx, item)
	if err == nil || item.State != core.CleanupInvestigate {
		t.Fatalf("changed evidence must investigate: %+v %v", item, err)
	}
	if _, err := os.Lstat(item.Destination); err != nil {
		t.Fatal("changed receipt was deleted")
	}
	item, err = e.Restore(ctx, item)
	if err != nil || item.State != core.CleanupRestored {
		t.Fatalf("investigated item not restorable: %+v %v", item, err)
	}
	if raw, err := os.ReadFile(source); err != nil || string(raw) != "changed content" {
		t.Fatalf("restored changed contents: %q %v", raw, err)
	}
}

func TestExpiryRechecksOriginalNameAgainstChangedPolicy(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(31 * 24 * time.Hour)
	e.Policy.NamePatterns = []string{"candidate"}
	if err := e.Eligible(ctx, item); err == nil || !strings.Contains(err.Error(), "original source safety") {
		t.Fatalf("new protected name did not block deletion: %v", err)
	}
	if _, err := os.Lstat(item.Destination); err != nil {
		t.Fatal("receipt disappeared")
	}
}

func TestExpiryRefusesNewSourceReference(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(31 * 24 * time.Hour)
	units := e.Collect.ServiceSources.SystemdDirs[0]
	if err := os.WriteFile(filepath.Join(units, "new.service"), []byte("[Service]\nWorkingDirectory="+source+"\nExecStart=/bin/true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.Eligible(ctx, item); err == nil || !strings.Contains(err.Error(), "reference") {
		t.Fatalf("new reference did not block expiry: %v", err)
	}
}

func TestInvestigatedReceiptRechecksBeforeExpiryRetry(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "candidate")
	if err := os.WriteFile(source, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(31 * 24 * time.Hour)
	unit := filepath.Join(e.Collect.ServiceSources.SystemdDirs[0], "new.service")
	if err := os.WriteFile(unit, []byte("[Service]\nWorkingDirectory="+source+"\nExecStart=/bin/true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	item, err = e.Delete(ctx, item)
	if err == nil || item.State != core.CleanupInvestigate {
		t.Fatalf("new reference did not investigate: %+v %v", item, err)
	}
	if _, err = e.Reconcile(ctx, item); err == nil {
		t.Fatal("unresolved reference left investigate")
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	item, err = e.Reconcile(ctx, item)
	if err != nil || item.State != core.CleanupQuarantined {
		t.Fatalf("cleared reference did not revalidate: %+v %v", item, err)
	}
	item, err = e.Delete(ctx, item)
	if err != nil || item.State != core.CleanupDeleted {
		t.Fatalf("revalidated expiry did not delete: %+v %v", item, err)
	}
}
