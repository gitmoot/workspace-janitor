package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

func TestHistoryPreviewAndConfirmedTrim(t *testing.T) {
	f := newFixture(t)
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	if err := db.Write(ctx, func(tx *store.Tx) error {
		for i := 0; i < store.RecentScanLimit+2; i++ {
			started := at.Add(time.Duration(i) * time.Minute)
			scan := core.Scan{ID: fmt.Sprintf("scan-%03d", i), Roots: []string{f.home},
				Status: core.ScanCompleted, StartedAt: started, FinishedAt: &started}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	call := func(args ...string) historyReport {
		t.Helper()
		out, stderr, code := f.run(t, append([]string{"--format", "json", "history"}, args...)...)
		if code != ExitOK {
			t.Fatalf("history %v: exit=%d stderr=%s", args, code, stderr)
		}
		var doc struct {
			Data historyReport `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("decode history: %v: %s", err, out)
		}
		return doc.Data
	}
	preview := call()
	if !preview.DryRun || preview.Eligible.Scans != 2 {
		t.Fatalf("preview should identify but not remove two old scans: %+v", preview)
	}
	if again := call(); again.Eligible.Scans != 2 {
		t.Fatalf("preview mutated history: %+v", again)
	}
	trimmed := call("--confirm")
	if trimmed.DryRun || trimmed.Eligible.Scans != 2 {
		t.Fatalf("confirmed trim did not remove old snapshots: %+v", trimmed)
	}
	if after := call(); after.Eligible.Scans != 0 {
		t.Fatalf("trim left old snapshots eligible: %+v", after)
	}
	db, err = store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(ctx, func(tx *store.Tx) error {
		scans, err := tx.ListScans(ctx, 0)
		if err != nil {
			return err
		}
		if len(scans) != store.RecentScanLimit || scans[0].ID != "scan-257" || scans[len(scans)-1].ID != "scan-002" {
			return fmt.Errorf("retained wrong recent history: count=%d first=%s last=%s", len(scans), scans[0].ID, scans[len(scans)-1].ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A later ordinary scan enforces the same limit without an operator
	// issuing the maintenance command again.
	if err := db.Write(ctx, func(tx *store.Tx) error {
		for i := 0; i < 2; i++ {
			started := at.Add(-time.Duration(i+1) * time.Minute)
			scan := core.Scan{ID: fmt.Sprintf("older-%d", i), Roots: []string{f.home},
				Status: core.ScanCompleted, StartedAt: started, FinishedAt: &started}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := f.run(t, "scan", "--no-git", "--no-processes", "--no-services"); code != ExitOK {
		t.Fatalf("ordinary scan failed to enforce retention: %d %s", code, stderr)
	}
	db, err = store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(ctx, func(tx *store.Tx) error {
		scans, err := tx.ListScans(ctx, 0)
		if err != nil {
			return err
		}
		if len(scans) != store.RecentScanLimit || scans[0].ID == "scan-257" {
			return fmt.Errorf("ordinary scan did not bound history: count=%d newest=%s", len(scans), scans[0].ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScanPersistsWhenClockFallsBehindHistory(t *testing.T) {
	f := newFixture(t)
	paths, err := config.ResolvePaths(config.MapLookup(f.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(24 * time.Hour)
	if err := db.Write(ctx, func(tx *store.Tx) error {
		for i := 0; i < store.RecentScanLimit; i++ {
			at := future.Add(time.Duration(i) * time.Minute)
			scan := core.Scan{ID: fmt.Sprintf("future-%03d", i), Roots: []string{f.home},
				Status: core.ScanCompleted, StartedAt: at, FinishedAt: &at}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := f.run(t, "--format", "json", "scan", "--no-git", "--no-processes", "--no-services")
	if code != ExitOK {
		t.Fatalf("scan: exit=%d stderr=%s", code, stderr)
	}
	var doc struct {
		Data scanReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("scan result: %v", err)
	}
	if !doc.Data.Persisted || doc.Data.Scan.ID == "" {
		t.Fatalf("scan did not report a persisted ID: %+v", doc.Data)
	}
	db, err = store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(ctx, func(tx *store.Tx) error {
		_, err := tx.Scan(ctx, doc.Data.Scan.ID)
		return err
	}); err != nil {
		t.Fatalf("new scan self-trimmed under clock skew: %v", err)
	}
}
