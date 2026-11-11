package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Scratch receipts are the only record of what a run deleted: the database
// refuses to rewrite or erase them, a deletion needs a recorded run, and the
// newest run of a path schedules the next one.
func TestScratchReceiptsAreAppendOnly(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	start := time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC)
	err := db.Write(ctx, func(tx *Tx) error {
		for i, runID := range []string{"run-a", "run-b"} {
			run := ScratchRun{RunID: runID, Path: "/tmp", StartedAt: start.Add(time.Duration(i) * 48 * time.Hour), RecordedAt: start,
				ArchiveDirectory: "/srv/archive", ArchiveManifest: "/srv/archive/scratch-" + runID + ".manifest.json",
				ArchiveManifestSHA256: strings.Repeat("a", 64), ArchivedCount: 1}
			if err := tx.RecordScratchRun(ctx, run); err != nil {
				return err
			}
		}
		return tx.RecordScratchDeletion(ctx, ScratchDeletion{RunID: "run-a", Path: "/tmp", Entry: "old", Disposition: ScratchArchived,
			SizeBytes: 10, ArchiveManifest: "/srv/archive/scratch-run-a.manifest.json", DeletedAt: start})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE scratch_runs SET path = '/var/tmp'`,
		`DELETE FROM scratch_runs`,
		`UPDATE scratch_deletions SET entry = 'other'`,
		`DELETE FROM scratch_deletions`,
	} {
		err := db.Write(ctx, func(tx *Tx) error {
			_, err := tx.tx.ExecContext(ctx, statement)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s was not refused as immutable: %v", statement, err)
		}
	}
	err = db.Write(ctx, func(tx *Tx) error {
		return tx.RecordScratchDeletion(ctx, ScratchDeletion{RunID: "run-a", Path: "/tmp", Entry: "regen", Disposition: ScratchArchived, DeletedAt: start})
	})
	if err == nil {
		t.Error("an archived deletion without its archive was recorded")
	}
	var last time.Time
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		last, err = tx.LastScratchRun(ctx, "/tmp", "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !last.Equal(start.Add(48 * time.Hour)) {
		t.Fatalf("last scratch run = %s, want the newer run", last)
	}
	if read, err := ReadLastScratchRun(ctx, db.path, "/tmp", ""); err != nil || !read.Equal(last) {
		t.Fatalf("read-only last run = %s, %v", read, err)
	}
}

// A receipt of an earlier version lists its archived entries by name instead
// of counting them. It still reads back as a valid run of that many entries,
// so its archive stays restorable.
func TestScratchRunReceiptOfAnEarlierVersionStillReads(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	legacy := `{"run_id":"20261101T160000.000000000Z","path":"/tmp","started_at":"2026-11-01T16:00:00Z",` +
		`"archive_directory":"/srv/archive","archive_manifest":"/srv/archive/scratch-20261101T160000.000000000Z.manifest.json",` +
		`"archive_manifest_sha256":"` + strings.Repeat("b", 64) + `","archived_entries":["one","two"],"recorded_at":"2026-11-01T16:05:00Z"}`
	var (
		run   ScratchRun
		found bool
	)
	if err := db.Write(ctx, func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO scratch_runs (run_id, path, started_at, document) VALUES (?, ?, ?, ?)`,
			"20261101T160000.000000000Z", "/tmp", "2026-11-01T16:00:00Z", legacy); err != nil {
			return err
		}
		var err error
		run, found, err = tx.ScratchRunByID(ctx, "20261101T160000.000000000Z")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !found || run.ArchivedCount != 2 || run.ArchiveManifestSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("legacy receipt = %+v found=%v, want 2 archived entries", run, found)
	}
}
