package store

import (
	"context"
	"encoding/json"
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
				ArchiveManifestSHA256: strings.Repeat("a", 64), ArchivedEntries: []string{"old"}}
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

// The run receipt is recorded after archiving, at a later time whose encoding
// can be up to ten bytes longer than a whole-second start. The size estimate
// used for selection must never be smaller than the receipt actually stored.
func TestScratchRunReceiptBytesCoversALaterRecordedAt(t *testing.T) {
	start := time.Date(2026, 11, 1, 16, 0, 0, 0, time.UTC)
	r := ScratchRun{RunID: "20261101T160000Z", Path: "/tmp", StartedAt: start, RecordedAt: start,
		ArchiveDirectory: "/a", ArchiveManifest: "/a/m.json", ArchiveManifestSHA256: strings.Repeat("0", 64)}
	estimate := ScratchRunReceiptBytes(r)
	r.RecordedAt = start.Add(987654321 * time.Nanosecond)
	r.ArchivedEntries = []string{}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > estimate {
		t.Fatalf("estimate %d bytes is below the recorded receipt %d bytes", estimate, len(data))
	}
}
