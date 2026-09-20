package safety

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// collectOptions builds bounded collector options over one fixture root,
// with every collector that would read real machine state switched off.
func collectOptions(root string) collect.Options {
	return collect.Options{
		Roots: []collect.RootSpec{{Path: root, MaxDepth: 1}},
		Limits: collect.Limits{
			GitTimeout:         5 * time.Second,
			CommandTimeout:     5 * time.Second,
			MaxEntries:         100,
			MaxDirEntries:      100,
			DeepSizeMaxEntries: 100,
			DeepSizeMaxDepth:   4,
		},
	}
}

// observe runs the collectors over root and returns the entry for path,
// which is what a planner would have recorded.
func observe(t *testing.T, root, path string) core.Entry {
	t.Helper()
	recollect := CollectRecollector(collectOptions(root))
	entry, err := recollect(context.Background(), path)
	if err != nil {
		t.Fatalf("observe %s: %v", path, err)
	}
	return entry
}

func revalidatePolicy(root string) Policy {
	return Policy{
		StateDir:      filepath.Join(root, ".state"),
		QuarantineDir: filepath.Join(root, ".state", "quarantine"),
		MinFreeBytes:  0,
	}
}

// The race the apply step exists to lose: the path is replaced between
// planning and applying. The planned action described a different object,
// so it authorizes nothing.
func TestRevalidateRefusesWhenThePathIsReplacedAfterPlanning(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	planned := observe(t, root, path)
	if planned.FilesystemID.Zero() {
		t.Fatal("fixture entry has no filesystem identity")
	}
	// An apply engine opens the object it is about to mutate. Without that
	// handle a replacement is undetectable here: this filesystem reuses the
	// inode and the timestamps, so device, inode, mtime, and the whole
	// fingerprint come back identical.
	handle, err := Open(path)
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	action := core.Action{
		ID: "action-1", Path: path, Kind: core.ActionQuarantine,
		FilesystemID: planned.FilesystemID, CreatedAt: evaluatedAt,
	}

	// Between plan and apply, something replaces the directory with a new
	// one of the same name.
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("recreate: %v", err)
	}

	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned:   planned,
		Action:    action,
		Policy:    revalidatePolicy(root),
		Now:       evaluatedAt,
		Recollect: CollectRecollector(collectOptions(root)),
		Handle:    handle,
	})

	if !verdict.Refused() {
		t.Fatalf("verdict = %+v, want a refusal after the path was replaced", verdict)
	}
	if !hasKind(verdict, core.ProtectIdentityChanged) {
		t.Fatalf("protections = %+v, want identity_changed", verdict.Protections)
	}
	if verdict.Allows(core.ActionQuarantine) {
		t.Error("a replaced path must not be quarantined")
	}
	found := false
	for _, protection := range verdict.Protections {
		if protection.Kind != core.ProtectIdentityChanged {
			continue
		}
		found = true
		if !containsAny(protection.Reason, "identity", "metadata", "removed after planning") {
			t.Errorf("reason = %q, want the exact change named", protection.Reason)
		}
		if protection.Remediation == "" {
			t.Error("an identity change must come with a remedy")
		}
	}
	if !found {
		t.Error("no identity protection carried evidence")
	}
}

// A metadata change with the same inode — a file written in place — must
// also refuse: the plan measured something that no longer holds.
func TestRevalidateRefusesWhenMetadataChangedInPlace(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(path, []byte("before"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	planned := observe(t, root, path)

	if err := os.WriteFile(path, []byte("after, and longer than before"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned:   planned,
		Action:    core.Action{ID: "action-2", Path: path, Kind: core.ActionDeleteCandidate, CreatedAt: evaluatedAt},
		Policy:    revalidatePolicy(root),
		Now:       evaluatedAt,
		Recollect: CollectRecollector(collectOptions(root)),
	})
	if !verdict.Refused() || !hasKind(verdict, core.ProtectIdentityChanged) {
		t.Fatalf("verdict = %+v, want identity_changed after an in-place rewrite", verdict)
	}
}

// An unchanged path revalidates cleanly, or the guard would be useless: it
// would refuse everything and teach operators to bypass it.
func TestRevalidateAllowsAnUnchangedPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	planned := observe(t, root, path)

	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned:   planned,
		Action:    core.Action{ID: "action-3", Path: path, Kind: core.ActionQuarantine, FilesystemID: planned.FilesystemID, CreatedAt: evaluatedAt},
		Policy:    revalidatePolicy(root),
		Now:       evaluatedAt,
		Recollect: CollectRecollector(collectOptions(root)),
	})
	if verdict.Refused() {
		t.Fatalf("unchanged path was refused: %+v", verdict.Protections)
	}
}

// A path that became protected after planning must refuse, even though its
// identity is unchanged: revalidation re-runs every guard, not just the
// identity comparison.
func TestRevalidateRerunsEveryGuardNotJustIdentity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "worktree")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	planned := observe(t, root, path)

	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned: planned,
		Action:  core.Action{ID: "action-4", Path: path, Kind: core.ActionQuarantine, FilesystemID: planned.FilesystemID, CreatedAt: evaluatedAt},
		Policy:  revalidatePolicy(root),
		// A job claimed the directory after the plan was made.
		Jobs:      []JobRef{{ID: "job-7", State: JobRunning, Path: path, Owner: "gitmoot"}},
		Now:       evaluatedAt,
		Recollect: CollectRecollector(collectOptions(root)),
	})
	if !verdict.Refused() || !hasKind(verdict, core.ProtectOwningJob) {
		t.Fatalf("verdict = %+v, want the newly owning job to refuse", verdict)
	}
}

// A vanished path cannot be revalidated, and an unrevalidatable path is
// never mutated.
func TestRevalidateRefusesWhenThePathDisappeared(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "gone")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	planned := observe(t, root, path)
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned:   planned,
		Action:    core.Action{ID: "action-5", Path: path, Kind: core.ActionQuarantine, CreatedAt: evaluatedAt},
		Policy:    revalidatePolicy(root),
		Now:       evaluatedAt,
		Recollect: CollectRecollector(collectOptions(root)),
	})
	if !verdict.Refused() || !hasKind(verdict, core.ProtectCollectorFailure) {
		t.Fatalf("verdict = %+v, want a collector failure refusal", verdict)
	}
}

// Revalidation without a re-observation would only restate the plan, so it
// must refuse rather than pretend to have checked.
func TestRevalidateWithoutARecollectorRefuses(t *testing.T) {
	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned: core.Entry{Path: "/repos/app"},
		Action:  core.Action{ID: "action-6", Path: "/repos/app", Kind: core.ActionQuarantine, CreatedAt: evaluatedAt},
		Now:     evaluatedAt,
	})
	if !verdict.Refused() || !hasKind(verdict, core.ProtectCollectorFailure) {
		t.Fatalf("verdict = %+v, want a refusal when nothing re-observed the path", verdict)
	}
}

// A re-observation that fails is an unknown, and unknowns refuse.
func TestRevalidateRefusesWhenReobservationFails(t *testing.T) {
	sentinel := errors.New("procfs unavailable")
	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned: core.Entry{Path: "/repos/app"},
		Action:  core.Action{ID: "action-7", Path: "/repos/app", Kind: core.ActionQuarantine, CreatedAt: evaluatedAt},
		Now:     evaluatedAt,
		Recollect: func(context.Context, string) (core.Entry, error) {
			return core.Entry{}, sentinel
		},
	})
	if !verdict.Refused() {
		t.Fatalf("verdict = %+v, want a refusal", verdict)
	}
	if !strings.Contains(verdict.Protections[0].Reason, sentinel.Error()) {
		t.Errorf("reason = %q, want the collector error quoted", verdict.Protections[0].Reason)
	}
}

// The action's own recorded identity is checked too: that is the value an
// apply engine would act on.
func TestRevalidateRefusesWhenTheActionIdentityDisagrees(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	planned := observe(t, root, path)

	verdict := Revalidate(context.Background(), RevalidateInput{
		Planned: planned,
		Action: core.Action{
			ID: "action-8", Path: path, Kind: core.ActionQuarantine, CreatedAt: evaluatedAt,
			FilesystemID: core.FilesystemID{Device: planned.FilesystemID.Device, Inode: planned.FilesystemID.Inode + 1},
		},
		Policy:    revalidatePolicy(root),
		Now:       evaluatedAt,
		Recollect: CollectRecollector(collectOptions(root)),
	})
	if !verdict.Refused() || !hasKind(verdict, core.ProtectIdentityChanged) {
		t.Fatalf("verdict = %+v, want identity_changed for a stale action identity", verdict)
	}
}

// The re-observation must not be more permissive than the scan that
// produced the plan: a root that forbids following symlinks still forbids
// it at apply time.
func TestRecollectorInheritsRootBounds(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	strict := observe(t, root, link)
	if strict.CanonicalPath != "" {
		t.Errorf("canonical path = %q, want the link left unresolved", strict.CanonicalPath)
	}

	permissive := collectOptions(root)
	permissive.Roots[0].FollowSymlinks = true
	entry, err := CollectRecollector(permissive)(context.Background(), link)
	if err != nil {
		t.Fatalf("recollect: %v", err)
	}
	if entry.CanonicalPath != target {
		t.Errorf("canonical path = %q, want %q when the root permits following", entry.CanonicalPath, target)
	}
}

// The measurement behind the handle check: on this filesystem a removed and
// recreated directory can be metadata-identical, so a metadata-only
// revalidation would approve mutating the replacement.
func TestReplacementCanBeMetadataIdenticalWhichIsWhyHandlesExist(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "artifact")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	planned := observe(t, root, path)
	handle, err := Open(path)
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	defer handle.Close()

	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	fresh := observe(t, root, path)

	metadataIdentical := fresh.FilesystemID == planned.FilesystemID && fresh.Fingerprint == planned.Fingerprint
	linked, err := handle.Linked()
	if err != nil {
		t.Fatalf("handle liveness: %v", err)
	}
	if linked {
		t.Fatal("the handle must report the planned object as unlinked after it was removed")
	}
	if !metadataIdentical {
		t.Logf("this filesystem distinguished the replacement by metadata (identity %s vs %s); "+
			"the handle check still refuses, and is required where it does not",
			planned.FilesystemID, fresh.FilesystemID)
	}
}

func containsAny(text string, wanted ...string) bool {
	for _, want := range wanted {
		if strings.Contains(text, want) {
			return true
		}
	}
	return false
}
