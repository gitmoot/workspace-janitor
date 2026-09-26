package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func TestScanHistoryKeepsAuditReferencesAndLastDeep(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	base := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	id := func(i int) string { return fmt.Sprintf("scan-%03d", i) }
	if err := db.Write(ctx, func(tx *Tx) error {
		for i := 0; i < RecentScanLimit+8; i++ {
			at := base.Add(time.Duration(i) * time.Minute)
			scan := fixtureScan(id(i), at)
			if i != 6 {
				scan.Status = core.ScanCompleted
				scan.FinishedAt = &at
			}
			if i == 5 || i == 7 {
				scan.Collectors = []core.CollectorReport{{Name: "deep_size", Status: core.CollectorRan}}
			}
			if i == 5 {
				// Its later completion advanced the deep clock even though
				// another deep scan started afterwards.
				completed := base.Add(10 * time.Hour)
				scan.FinishedAt = &completed
			}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
			if i < 8 {
				path := fmt.Sprintf("/repos/old-%d", i)
				if i == 7 {
					path = "/repos/café"
				}
				if err := tx.PutEntry(ctx, id(i), fixtureEntry(path, at)); err != nil {
					return err
				}
			}
		}
		// Each audit relation pins a distinct old scan. The advisory attempt
		// deliberately references another scan than its parent run.
		statements := []string{
			`INSERT INTO plans (id,scan_id,contract_version,status,created_at) VALUES ('plan', 'scan-000',1,'ready','2026-09-24T00:00:00Z')`,
			`INSERT INTO actions (id,plan_id,path,kind,retention,confidence,status,created_at) VALUES ('action','plan','/repos/old-0','keep','none',1,'pending','2026-09-24T00:00:00Z')`,
			`INSERT INTO completed_cycles (day,scan_id,completed_at_ns) VALUES ('2026-09-24','scan-001',1)`,
			`INSERT INTO advisory_runs (day,scan_id,status,report,started_at_ns) VALUES ('2026-09-25','scan-002','completed','{}',1)`,
			`INSERT INTO advisory_attempts (day,scan_id,entries,estimated_tokens,estimated_cost_micro_usd,reserved_at_ns) VALUES ('2026-09-25','scan-003',1,1,1,1)`,
			`INSERT INTO model_usage (id,scan_id,provider,model,request_kind,prompt_tokens,completion_tokens,estimated_cost_usd,created_at) VALUES ('usage','scan-004','test','test','plan',1,1,0,'2026-09-24T00:00:00Z')`,
		}
		for _, statement := range statements {
			if _, err := tx.tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var preview, trimmed ScanHistoryReduction
	var document string
	if err := db.Read(ctx, func(tx *Tx) error {
		if err := tx.tx.QueryRowContext(ctx, `SELECT document FROM inventories WHERE scan_id = ?`, id(7)).Scan(&document); err != nil {
			return err
		}
		var err error
		preview, err = tx.ScanHistoryPreview(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if preview.Scans != 1 || preview.Entries != 1 || preview.Documents != int64(len(document)) {
		t.Fatalf("old unreferenced snapshot or UTF-8 byte count wrong: %+v, want %d bytes", preview, len(document))
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		var err error
		trimmed, err = tx.TrimScanHistory(ctx, "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if trimmed != preview {
		t.Fatalf("trimmed %+v, previewed %+v", trimmed, preview)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		if _, err := tx.Scan(ctx, id(7)); !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("unreferenced old scan survived: %v", err)
		}
		for i := 0; i < 7; i++ {
			if _, err := tx.Scan(ctx, id(i)); err != nil {
				return fmt.Errorf("pinned scan %s lost: %w", id(i), err)
			}
			if _, err := tx.Entry(ctx, id(i), fmt.Sprintf("/repos/old-%d", i)); err != nil {
				return fmt.Errorf("pinned inventory %s lost: %w", id(i), err)
			}
		}
		var plans, actions, attempts, usage int
		if err := tx.tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM plans),(SELECT count(*) FROM actions),(SELECT count(*) FROM advisory_attempts),(SELECT count(*) FROM model_usage)`).Scan(&plans, &actions, &attempts, &usage); err != nil {
			return err
		}
		if plans != 1 || actions != 1 || attempts != 1 || usage != 1 {
			return fmt.Errorf("audit changed: plans=%d actions=%d attempts=%d usage=%d", plans, actions, attempts, usage)
		}
		again, err := tx.ScanHistoryPreview(ctx)
		if err != nil {
			return err
		}
		if again.Scans != 0 {
			return fmt.Errorf("trim left eligible snapshots: %+v", again)
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
		for i := 0; i < RecentScanLimit+1; i++ {
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
		_, err := tx.TrimScanHistory(ctx, "")
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
		for i := 0; i < RecentScanLimit+2; i++ {
			at := base.Add(time.Duration(i) * time.Minute)
			scan := fixtureScan(fmt.Sprintf("scan-%03d", i), at)
			scan.Status, scan.FinishedAt = core.ScanCompleted, &at
			if i < 2 {
				scan.Collectors = []core.CollectorReport{{Name: "deep_size", Status: core.CollectorRan}}
				finished := base.Add(10 * time.Hour)
				if i == 1 {
					finished = finished.Add(500 * time.Millisecond)
				}
				scan.FinishedAt = &finished
			}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		_, err := tx.TrimScanHistory(ctx, "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		if _, err := tx.Scan(ctx, "scan-000"); !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("earlier deep completion must trim: %v", err)
		}
		_, err := tx.Scan(ctx, "scan-001")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScanHistoryRetainsMalformedCollectorWithoutBlockingTrim(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	base := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	if err := db.Write(ctx, func(tx *Tx) error {
		for i := 0; i < RecentScanLimit+3; i++ {
			at := base.Add(time.Duration(i) * time.Minute)
			scan := fixtureScan(fmt.Sprintf("scan-%03d", i), at)
			scan.Status, scan.FinishedAt = core.ScanCompleted, &at
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
		}
		if _, err := tx.tx.ExecContext(ctx, `UPDATE scans SET collectors = '{broken' WHERE id = 'scan-000'`); err != nil {
			return err
		}
		_, err := tx.tx.ExecContext(ctx, `UPDATE scans SET collectors = '["unexpected"]' WHERE id = 'scan-001'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		reduction, err := tx.TrimScanHistory(ctx, "")
		if err != nil {
			return err
		}
		if reduction.Scans != 1 {
			return fmt.Errorf("expected only the safe old scan trimmed, got %+v", reduction)
		}
		at := base.Add(-time.Hour)
		scan := fixtureScan("new-clock-skewed", at)
		scan.Status, scan.FinishedAt = core.ScanCompleted, &at
		if err := tx.CreateScan(ctx, scan); err != nil {
			return err
		}
		_, err = tx.TrimScanHistory(ctx, scan.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		var count int
		if err := tx.tx.QueryRowContext(ctx,
			`SELECT count(*) FROM scans WHERE id IN ('scan-000', 'scan-001')`).Scan(&count); err != nil {
			return err
		}
		if count != 2 {
			return fmt.Errorf("invalid old collector documents were discarded")
		}
		if _, err := tx.Scan(ctx, "scan-002"); !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("safe old scan survived: %v", err)
		}
		_, err := tx.Scan(ctx, "new-clock-skewed")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
