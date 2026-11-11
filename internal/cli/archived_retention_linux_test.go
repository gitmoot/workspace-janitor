//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// archivedDue runs the expiry preview and returns the sources it reports as
// due because of retention.archived.
func (x *workspaceExpiryFixture) archivedDue(t *testing.T) map[string]bool {
	t.Helper()
	preview := x.data(t, "apply", "--expire")
	var due []struct {
		Source string `json:"source"`
	}
	if raw, ok := preview["archived_retention_due"]; ok {
		if err := json.Unmarshal(raw, &due); err != nil {
			t.Fatalf("archived_retention_due: %v (%s)", err, raw)
		}
	}
	out := map[string]bool{}
	for _, item := range due {
		out[item.Source] = true
	}
	return out
}

// quarantineAll approves and moves every proposed quarantine of the latest plan.
func (x *workspaceExpiryFixture) quarantineAll(t *testing.T, sources ...string) {
	t.Helper()
	plan, _ := x.action(t)
	for _, source := range sources {
		var id string
		for _, action := range plan.Actions {
			if action.Path == source && action.Kind == core.ActionQuarantine {
				id = action.ID
			}
		}
		if id == "" {
			t.Fatalf("%s not proposed for quarantine: %+v", source, plan.Actions)
		}
		x.data(t, "plan", "--plan", plan.ID, "--approve", id, "--no-jev")
		x.data(t, "apply", "--quarantine", "--action", id, "--dry-run=false", "--confirm")
		if _, err := os.Lstat(source); !os.IsNotExist(err) {
			t.Fatalf("quarantine left %s in place: %v", source, err)
		}
	}
}

// expiresAfter requires a receipt's recorded expiry to be its move plus window.
func expiresAfter(t *testing.T, receipt core.CleanupItem, window time.Duration) {
	t.Helper()
	if receipt.MovedAt == nil || receipt.ExpiresAt == nil || !receipt.ExpiresAt.Equal(receipt.MovedAt.Add(window)) {
		t.Fatalf("%s expires_at = %v, want moved_at %v + %s", receipt.Source, receipt.ExpiresAt, receipt.MovedAt, window)
	}
}

// retention.archived none: a quarantined workspace whose receipt binds its
// verified archive is deleted by the next expiry, while an item without an
// archive copy keeps retention.default (3d) under the same policy.
func TestArchivedRetentionExpiresArchiveBackedItemsAtOnce(t *testing.T) {
	x := newWorkspaceExpiryFixture(t)
	x.defaultRetention, x.archivedRetention = "3d", "none"
	cache := filepath.Join(x.work, "build-cache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "object.o"), []byte("regenerable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	x.extra = fmt.Sprintf("caches:\n  - name: build\n    path: %s\n    action: quarantine\n", cache)
	x.archiveAndPin(t, pastRetention, true)
	x.quarantineAll(t, x.source, cache)
	archived, plain := x.receipt(t), x.receiptOf(t, cache)
	expiresAfter(t, archived, 0)
	expiresAfter(t, plain, 3*24*time.Hour)

	due := x.archivedDue(t)
	if !due[x.source] || due[cache] {
		t.Fatalf("preview due by retention.archived = %v, want only %s", due, x.source)
	}
	if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("expiry of the archive-backed workspace failed: exit %d", code)
	}
	if _, err := os.Lstat(archived.Destination); !os.IsNotExist(err) {
		t.Fatalf("archive-backed copy kept despite retention.archived none: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(plain.Destination, "object.o")); err != nil {
		t.Fatalf("item without an archive copy deleted inside retention.default: %v", err)
	}
	if still := x.receiptOf(t, cache); still.State != core.CleanupQuarantined {
		t.Fatalf("unarchived receipt state = %s, want quarantined", still.State)
	}
}

// The current retention.archived decides for receipts already in
// quarantine, in both directions: a longer value (or unsetting it, back to
// the recorded retention.default) holds an item quarantined under none, and
// setting none again releases it.
func TestArchivedRetentionAppliesToExistingReceipts(t *testing.T) {
	x := newWorkspaceExpiryFixture(t)
	x.defaultRetention, x.archivedRetention = "3d", "none"
	x.archiveAndPin(t, pastRetention, true)
	receipt := x.quarantine(t)
	expiresAfter(t, receipt, 0)
	for _, held := range []string{"3d", ""} {
		x.archivedRetention = held
		x.write(t)
		if due := x.archivedDue(t); due[x.source] {
			t.Fatalf("retention.archived %q: preview still reports the item due", held)
		}
		if code := x.expire(t, receipt); code != ExitOK {
			t.Fatalf("retention.archived %q: expiry failed: exit %d", held, code)
		}
		x.preserved(t, receipt.Destination)
	}
	x.archivedRetention = "none"
	x.write(t)
	if code := x.expire(t, receipt); code != ExitOK {
		t.Fatalf("retention.archived none again: expiry failed: exit %d", code)
	}
	if _, err := os.Lstat(receipt.Destination); !os.IsNotExist(err) {
		t.Fatalf("retention.archived none again did not release the copy: %v", err)
	}
}

// retention.archived only shortens the wait: an archive-backed item whose
// archive no longer verifies is refused exactly as before, and restorable.
func TestArchivedRetentionRefusesAnArchiveThatNoLongerVerifies(t *testing.T) {
	x := newWorkspaceExpiryFixture(t)
	x.defaultRetention, x.archivedRetention = "3d", "none"
	x.archiveAndPin(t, pastRetention, true)
	receipt := x.quarantine(t)
	x.corruptTar(t)
	if code := x.expire(t, receipt); code == ExitOK {
		t.Fatal("corrupted archive authorized deleting the quarantined copy")
	}
	x.preserved(t, receipt.Destination)
	x.data(t, "restore", "--confirm", receipt.CleanupID)
	x.preserved(t, x.source)
}

// Session artifact files are archive-backed by their verified batch: under
// retention.default 3d and retention.archived none their copies are due at
// once and the next expiry deletes them; raising retention.archived holds
// copies already in quarantine.
func TestArchivedRetentionExpiresSessionArtifactsAtOnce(t *testing.T) {
	x := newArtifactFixture(t)
	x.defaultRetention, x.archivedRetention = "3d", "none"
	x.writeArtifacts(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"a.log": oldArtifact, "b.log": oldArtifact})
	item := categoryItem(t, x.categories(t, false), session)
	x.quarantineArtifacts(t)
	receipts := x.artifactReceipts(t, item.CleanupID)
	if len(receipts) != 2 {
		t.Fatalf("receipts: %v", receipts)
	}
	x.archivedRetention = "3d"
	x.writeArtifacts(t)
	if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("expiry under retention.archived 3d failed: exit %d", code)
	}
	for name, destination := range receipts {
		if _, err := os.Lstat(destination); err != nil {
			t.Fatalf("%s deleted inside a raised retention.archived: %v", name, err)
		}
	}
	x.archivedRetention = "none"
	x.writeArtifacts(t)
	if _, _, code := x.run(t, "apply", "--expire", "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("expiry of archive-backed session artifacts failed: exit %d", code)
	}
	for name, destination := range receipts {
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Fatalf("%s kept despite retention.archived none: %v", name, err)
		}
	}
}
