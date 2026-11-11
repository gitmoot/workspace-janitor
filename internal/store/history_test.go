package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// TestScanHistoryRetentionPins covers the pins a CLI-level test does not:
// recent and daily bounds, audited scans released in place, running and
// malformed scans, and oldest-first batches.
func TestScanHistoryRetentionPins(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	retention := HistoryRetention{KeepRecent: 3, KeepDays: 2}
	create := func(tx *Tx, id string, at time.Time, status core.ScanStatus) error {
		scan := fixtureScan(id, at)
		scan.EntryCount = 1
		if status != core.ScanRunning {
			scan.Status, scan.FinishedAt = status, &at
		}
		if err := tx.CreateScan(ctx, scan); err != nil {
			return err
		}
		return tx.PutEntry(ctx, id, fixtureEntry("/repos/"+id, at))
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		for i := range 6 {
			// Days ago: 9..4, outside the daily window.
			if err := create(tx, fmt.Sprintf("old-%d", i), now.AddDate(0, 0, i-9), core.ScanCompleted); err != nil {
				return err
			}
		}
		// Yesterday: an earlier and the newest completed scan of the day.
		for i, id := range []string{"yesterday-early", "yesterday-late"} {
			if err := create(tx, id, now.Add(-24*time.Hour+time.Duration(i)*time.Hour), core.ScanCompleted); err != nil {
				return err
			}
		}
		if err := create(tx, "running", now.AddDate(0, 0, -8).Add(time.Hour), core.ScanRunning); err != nil {
			return err
		}
		for i := range 4 {
			if err := create(tx, fmt.Sprintf("today-%d", i), now.Add(time.Duration(i-4)*time.Hour), core.ScanCompleted); err != nil {
				return err
			}
		}
		if _, err := tx.tx.ExecContext(ctx, `UPDATE scans SET collectors = '{broken' WHERE id = 'old-1'`); err != nil {
			return err
		}
		return tx.RecordCompletedCycle(ctx, "old-2", now.AddDate(0, 0, -7))
	}); err != nil {
		t.Fatal(err)
	}
	var batch ScanHistoryReduction
	if err := db.Write(ctx, func(tx *Tx) error {
		var err error
		batch, err = tx.TrimScanHistory(ctx, HistoryTrim{Retention: retention, Now: now, MaxScans: 2})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Oldest first: old-0 is deleted, old-1 is malformed and kept, old-2 is
	// released in place.
	if batch.Scans != 1 || batch.Released != 1 || batch.Entries != 2 {
		t.Fatalf("first batch %+v", batch)
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		_, err := tx.TrimScanHistory(ctx, HistoryTrim{Retention: retention, Now: now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		for _, id := range []string{"old-1", "running", "yesterday-late", "today-1", "today-2", "today-3"} {
			if entries, err := tx.Entries(ctx, id); err != nil || len(entries) != 1 {
				return fmt.Errorf("pinned scan %s lost its inventory: %d %v", id, len(entries), err)
			}
		}
		for _, id := range []string{"old-0", "old-3", "old-4", "old-5", "yesterday-early", "today-0"} {
			if _, err := tx.Scan(ctx, id); !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("unpinned scan %s survived: %v", id, err)
			}
		}
		if _, err := tx.Scan(ctx, "old-2"); err != nil {
			return fmt.Errorf("audited scan row removed: %w", err)
		}
		if _, err := tx.Entries(ctx, "old-2"); !errors.Is(err, ErrInventoryReleased) {
			return fmt.Errorf("released inventory must not read as empty: %v", err)
		}
		again, err := tx.ScanHistoryPreview(ctx, retention, now)
		if err != nil {
			return err
		}
		if again != (ScanHistoryReduction{}) {
			return fmt.Errorf("trim left eligible history: %+v", again)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScanHistoryOrdersSubsecondRecentScans(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	base := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	if err := db.Write(ctx, func(tx *Tx) error {
		for i := range 3 {
			at := base.Add(time.Duration(i) * time.Second)
			if i == 1 {
				at = base.Add(500 * time.Millisecond)
			}
			scan := fixtureScan(fmt.Sprintf("scan-%03d", i), at)
			scan.Status, scan.FinishedAt = core.ScanCompleted, &at
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		_, err := tx.TrimScanHistory(ctx, HistoryTrim{Retention: HistoryRetention{KeepRecent: 2}, Now: base})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		if _, err := tx.Scan(ctx, "scan-000"); !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("older whole-second scan must trim: %v", err)
		}
		_, err := tx.Scan(ctx, "scan-001")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScanHistoryPinsSubsecondDeepCompletion(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	base := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	if err := db.Write(ctx, func(tx *Tx) error {
		for i := range 6 {
			at := base.Add(time.Duration(i) * time.Minute)
			scan := fixtureScan(fmt.Sprintf("scan-%03d", i), at)
			scan.Status, scan.FinishedAt = core.ScanCompleted, &at
			if i < 3 {
				scan.Collectors = []core.CollectorReport{{Name: "deep_size", Status: core.CollectorRan}}
				finished := base.Add(10*time.Hour + time.Duration(i)*500*time.Millisecond)
				scan.FinishedAt = &finished
			}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		_, err := tx.TrimScanHistory(ctx, HistoryTrim{Retention: HistoryRetention{KeepRecent: 1}, Now: base})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		if _, err := tx.Scan(ctx, "scan-000"); !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("earlier deep completion must trim: %v", err)
		}
		if _, err := tx.Scan(ctx, "scan-001"); err != nil {
			return err
		}
		_, err := tx.Scan(ctx, "scan-002")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
