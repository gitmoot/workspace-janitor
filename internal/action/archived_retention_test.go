package action

import (
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// ArchivedRetention replaces the recorded retention only for receipts that
// record a verified archive, and is measured from the move like any other.
func TestArchivedRetentionAppliesOnlyToArchiveBackedReceipts(t *testing.T) {
	moved := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	item := func(quarantined *core.Entry, rules ...string) core.CleanupItem {
		return core.CleanupItem{State: core.CleanupQuarantined, MovedAt: &moved, Quarantined: quarantined,
			Action: core.Action{Retention: core.Retention3Days, Rules: rules}}
	}
	bound := &core.Entry{WorkspaceArchive: &core.WorkspaceArchiveBinding{Manifest: "/archive/w.manifest.json", ManifestSHA256: "abc"}}
	unpinned := &core.Entry{WorkspaceArchive: &core.WorkspaceArchiveBinding{Manifest: "/archive/w.manifest.json"}}
	workspace, artifact := item(bound), item(&core.Entry{}, ArtifactRulePrefix+"batch")
	plain, unbound := item(&core.Entry{}), item(unpinned)

	at := func(archived core.Retention, offset time.Duration) *Engine {
		return &Engine{ArchivedRetention: archived, Now: func() time.Time { return moved.Add(offset) }}
	}
	for _, tc := range []struct {
		name     string
		engine   *Engine
		item     core.CleanupItem
		due, byA bool
	}{
		{"workspace binding, archived none", at(core.RetentionNone, 0), workspace, true, true},
		{"artifact batch, archived none", at(core.RetentionNone, 0), artifact, true, true},
		{"no archive, archived none", at(core.RetentionNone, 0), plain, false, false},
		{"binding without sha, archived none", at(core.RetentionNone, 0), unbound, false, false},
		{"no archive at 3d", at(core.RetentionNone, 3*24*time.Hour-time.Second), plain, false, false},
		{"no archive past 3d", at(core.RetentionNone, 3*24*time.Hour), plain, true, false},
		{"archived raised to 7d holds past recorded 3d", at(core.Retention7Days, 3*24*time.Hour), workspace, false, false},
		{"archived 7d elapsed", at(core.Retention7Days, 7*24*time.Hour), workspace, true, false},
		{"archived unset keeps recorded", at("", 0), workspace, false, false},
	} {
		if got := tc.engine.Due(tc.item); got != tc.due {
			t.Errorf("%s: Due = %t, want %t", tc.name, got, tc.due)
		}
		if got := tc.engine.DueByArchivedRetention(tc.item); got != tc.byA {
			t.Errorf("%s: DueByArchivedRetention = %t, want %t", tc.name, got, tc.byA)
		}
	}
}
