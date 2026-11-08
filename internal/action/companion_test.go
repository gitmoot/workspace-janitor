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
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// companionFixture prepares an OMP-session-like unit: a directory whose
// "<name>.jsonl" sibling is bound with it as its companion.
func companionFixture(t *testing.T) (*Engine, core.CleanupItem, *time.Time) {
	t.Helper()
	e, root, clock := fixtureEngine(t)
	source := filepath.Join(root, "session")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "artifact"), []byte("tool output"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source+".jsonl", []byte("{\"type\":\"session\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	entry, err := e.recollect(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	entry.WorkspaceArchive = &core.WorkspaceArchiveBinding{
		Manifest: "/archive/session.manifest.json", ManifestSHA256: strings.Repeat("a", 64), MemberCount: 2,
		TreeDigest: strings.Repeat("b", 64), CreatedAt: e.now().Add(-time.Hour),
		CompanionSuffix: ".jsonl", CompanionID: idOf(t, source+".jsonl"),
	}
	entry.Fingerprint = collect.Fingerprint(entry)
	act := core.Action{ID: "action-1", PlanID: "plan-1", Path: source, Kind: core.ActionQuarantine, Status: core.ActionPending, Retention: core.Retention30Days, FilesystemID: entry.FilesystemID, CreatedAt: e.now(), Fingerprint: entry.Fingerprint}
	item, err := e.Prepare(ctx, core.CleanupItem{CleanupID: "cleanup-fixture", PlanID: act.PlanID, ActionID: act.ID, Source: source, Entry: entry, Action: act})
	if err != nil {
		t.Fatal(err)
	}
	return e, item, clock
}

// quarantineUnit moves the prepared unit exactly as Quarantine does after
// its safety revalidation, and journals it.
func quarantineUnit(t *testing.T, e *Engine, item core.CleanupItem) core.CleanupItem {
	t.Helper()
	if err := e.moveUnit(context.Background(), item, item.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	item, err := e.finishMove(context.Background(), item)
	if err != nil || item.State != core.CleanupQuarantined {
		t.Fatalf("compound move: %+v %v", item.State, err)
	}
	return item
}

func idOf(t *testing.T, path string) core.FilesystemID {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fileIdentity(info)
}

// requireUnitAt requires the primary and its companion, with their bound
// identities, at at and at+".jsonl", and nothing left at the other place.
func requireUnitAt(t *testing.T, item core.CleanupItem, at string) {
	t.Helper()
	other := item.Source
	if at == item.Source {
		other = item.Destination
	}
	if id := idOf(t, at); id != item.Entry.FilesystemID {
		t.Fatalf("primary at %s has identity %s", at, id)
	}
	if id := idOf(t, at+".jsonl"); id != item.Entry.WorkspaceArchive.CompanionID {
		t.Fatalf("companion at %s.jsonl has identity %s", at, id)
	}
	for _, path := range []string{other, other + ".jsonl"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", path, err)
		}
	}
}

func TestCompanionQuarantinesAndRestoresWithItsPrimary(t *testing.T) {
	e, item, _ := companionFixture(t)
	item = quarantineUnit(t, e, item)
	requireUnitAt(t, item, item.Destination)
	item, err := e.Restore(context.Background(), item)
	if err != nil || item.State != core.CleanupRestored {
		t.Fatalf("restore: %+v %v", item.State, err)
	}
	requireUnitAt(t, item, item.Source)
}

// The whole unit goes through Quarantine's mutation-time revalidation, whose
// fresh archive binding pins the companion, and through expiry.
func TestArchivedCompanionUnitQuarantinesAndExpiresTogether(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "session")
	archive := filepath.Join(filepath.Dir(root), "archive")
	for _, dir := range []string{source, archive} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "artifact"), []byte("tool output"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source+".jsonl", []byte("{\"type\":\"session\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rule := config.WorkspaceArchiveRule{Name: "session", Path: source, Companion: source + ".jsonl", Owner: "seat-a", Release: "release-msg-1",
		DependentRoots: []string{root}, LocalExpiryEnabled: true, LocalRetention: core.RetentionNone,
		Archive: config.WorkspaceArchiveDestination{Directory: archive}}
	_, pin, err := workspacearchive.Create(ctx, rule, workspacearchive.Scope{ProcRoot: e.Collect.ProcRoot, SearchRoots: []string{root}}, func() error { return nil })
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = pin.Manifest, pin.ManifestSHA256
	e.Collect.WorktreePolicy = &config.Policy{WorkspaceArchives: []config.WorkspaceArchiveRule{rule}}
	item := prepareFixture(t, e, source, core.Retention30Days)
	if b := item.Entry.WorkspaceArchive; b == nil || b.CompanionSuffix != ".jsonl" || b.CompanionID != idOf(t, source+".jsonl") {
		t.Fatalf("unit binding = %+v", b)
	}
	item, err = e.Quarantine(ctx, item)
	if err != nil || item.State != core.CleanupQuarantined {
		t.Fatalf("quarantine: %+v %v", item.State, err)
	}
	requireUnitAt(t, item, item.Destination)
	*clock = clock.Add(31 * 24 * time.Hour)
	item, err = e.Delete(ctx, item)
	if err != nil || item.State != core.CleanupDeleted {
		t.Fatalf("expiry: %+v %v", item.State, err)
	}
	for _, path := range []string{item.Destination, item.Destination + ".jsonl"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived expiry: %v", path, err)
		}
	}
}

// A companion moves first. If its primary then cannot move, the companion
// must go back rather than leave the unit split.
func TestFailedPrimaryMoveReturnsItsCompanion(t *testing.T) {
	e, item, _ := companionFixture(t)
	wrong := item.Entry.FilesystemID
	wrong.Inode++
	if err := e.moveUnit(context.Background(), item, wrong); err == nil {
		t.Fatal("primary with another identity moved")
	}
	requireUnitAt(t, item, item.Source)
}

func TestCompoundMoveRefusesAnOccupiedCompanionDestination(t *testing.T) {
	e, item, _ := companionFixture(t)
	if err := os.WriteFile(item.Destination+".jsonl", []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.moveUnit(context.Background(), item, item.Entry.FilesystemID); err == nil {
		t.Fatal("companion destination collision moved the unit")
	}
	if id := idOf(t, item.Source+".jsonl"); id != item.Entry.WorkspaceArchive.CompanionID {
		t.Fatal("companion left its source")
	}
	if _, err := os.Lstat(item.Destination); !os.IsNotExist(err) {
		t.Fatalf("primary moved: %v", err)
	}
}

// A crash after the companion moved but before its primary did leaves a
// prepared receipt with its primary at the source: the companion follows it
// back and the move can be retried.
func TestReconcileReturnsTheCompanionOfAnInterruptedMove(t *testing.T) {
	e, item, _ := companionFixture(t)
	if err := renameNoReplace(item.Source+".jsonl", item.Destination+".jsonl", item.Entry.WorkspaceArchive.CompanionID); err != nil {
		t.Fatal(err)
	}
	item, err := e.Reconcile(context.Background(), item)
	if err != nil || item.State != core.CleanupPrepared {
		t.Fatalf("interrupted move: %+v %v, want prepared", item.State, err)
	}
	requireUnitAt(t, item, item.Source)
	quarantineUnit(t, e, item)
}

// A crash after the primary moved but before it was journaled is recovered
// as quarantined; a companion still at its source follows it.
func TestReconcileCompletesAMovedButUnjournaledUnit(t *testing.T) {
	e, item, _ := companionFixture(t)
	if err := renameNoReplace(item.Source, item.Destination, item.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	item, err := e.Reconcile(context.Background(), item)
	if err != nil || item.State != core.CleanupQuarantined {
		t.Fatalf("moved primary: %+v %v, want quarantined", item.State, err)
	}
	requireUnitAt(t, item, item.Destination)
}

// A crash after the primary was restored but before its companion leaves a
// quarantined receipt: reconciliation completes the restore.
func TestReconcileCompletesAnInterruptedCompoundRestore(t *testing.T) {
	e, item, _ := companionFixture(t)
	item = quarantineUnit(t, e, item)
	if err := renameNoReplace(item.Destination, item.Source, item.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	item, err := e.Reconcile(context.Background(), item)
	if err != nil || item.State != core.CleanupRestored {
		t.Fatalf("interrupted restore: %+v %v, want restored", item.State, err)
	}
	requireUnitAt(t, item, item.Source)
}

func TestRestoreRefusesAnOccupiedCompanionSource(t *testing.T) {
	e, item, _ := companionFixture(t)
	item = quarantineUnit(t, e, item)
	if err := os.WriteFile(item.Source+".jsonl", []byte("a new session log"), 0600); err != nil {
		t.Fatal(err)
	}
	item, err := e.Restore(context.Background(), item)
	if err == nil || !strings.Contains(err.Error(), "occupied companion source") || item.State != core.CleanupQuarantined {
		t.Fatalf("occupied companion source: %+v %v", item.State, err)
	}
	if id := idOf(t, item.Destination); id != item.Entry.FilesystemID {
		t.Fatal("primary left quarantine without its companion")
	}
	if id := idOf(t, item.Destination+".jsonl"); id != item.Entry.WorkspaceArchive.CompanionID {
		t.Fatal("quarantined companion moved")
	}
	if data, err := os.ReadFile(item.Source + ".jsonl"); err != nil || string(data) != "a new session log" {
		t.Fatalf("occupying file changed: %q %v", data, err)
	}
}

// A quarantined companion replaced by another file is not guessed about.
func TestReconcileInvestigatesAReplacedCompanion(t *testing.T) {
	e, item, _ := companionFixture(t)
	item = quarantineUnit(t, e, item)
	companion := item.Destination + ".jsonl"
	// Write the replacement before it takes the name, so it cannot reuse the
	// bound companion's inode.
	replacement := filepath.Join(filepath.Dir(item.Destination), "replacement")
	if err := os.WriteFile(replacement, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, companion); err != nil {
		t.Fatal(err)
	}
	item, err := e.Reconcile(context.Background(), item)
	if err == nil || item.State != core.CleanupInvestigate || !strings.Contains(item.Reason, "companion") {
		t.Fatalf("replaced companion: %+v %q %v, want investigate", item.State, item.Reason, err)
	}
	if _, err := os.Lstat(item.Source + ".jsonl"); !os.IsNotExist(err) {
		t.Fatalf("replacement was moved: %v", err)
	}
}

func TestExpiryDeletesPrimaryAndCompanion(t *testing.T) {
	e, item, clock := companionFixture(t)
	item = quarantineUnit(t, e, item)
	*clock = clock.Add(31 * 24 * time.Hour)
	item, err := e.Delete(context.Background(), item)
	if err != nil || item.State != core.CleanupDeleted {
		t.Fatalf("expiry: %+v %v", item.State, err)
	}
	for _, path := range []string{item.Destination, item.Destination + ".jsonl"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived expiry: %v", path, err)
		}
	}
}

func TestExpiryRefusesAChangedCompanion(t *testing.T) {
	e, item, clock := companionFixture(t)
	item = quarantineUnit(t, e, item)
	companion := item.Destination + ".jsonl"
	if err := os.Remove(companion); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", companion); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(31 * 24 * time.Hour)
	item, err := e.Delete(context.Background(), item)
	if err == nil || item.State != core.CleanupInvestigate {
		t.Fatalf("changed companion: %+v %v, want investigate", item.State, err)
	}
	if _, err := os.Lstat(item.Destination); err != nil {
		t.Fatalf("primary deleted without its companion check: %v", err)
	}
}

// Expiry deletes the primary, then the companion. A crash in between is
// settled as deleted, removing the bound companion and nothing else.
func TestExpiryFinishesTheCompanionOfAnInterruptedDeletion(t *testing.T) {
	e, item, clock := companionFixture(t)
	item = quarantineUnit(t, e, item)
	*clock = clock.Add(31 * 24 * time.Hour)
	if err := writeDeletionMarker(item); err != nil {
		t.Fatal(err)
	}
	if err := deleteAnchored(item.Destination, item.Entry.FilesystemID); err != nil {
		t.Fatal(err)
	}
	item, err := e.Delete(context.Background(), item)
	if err != nil || item.State != core.CleanupDeleted {
		t.Fatalf("interrupted expiry: %+v %v, want deleted", item.State, err)
	}
	if _, err := os.Lstat(item.Destination + ".jsonl"); !os.IsNotExist(err) {
		t.Fatalf("leftover companion survived: %v", err)
	}
}
