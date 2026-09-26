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
			if i == 5 {
				scan.Collectors = []core.CollectorReport{{Name: "deep_size", Status: core.CollectorRan}}
			}
			if err := tx.CreateScan(ctx, scan); err != nil {
				return err
			}
			if i < 8 {
				if err := tx.PutEntry(ctx, id(i), fixtureEntry(fmt.Sprintf("/repos/old-%d", i), at)); err != nil {
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
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		preview, err = tx.ScanHistoryPreview(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if preview.Scans != 1 || preview.Entries != 1 || preview.Documents == 0 {
		t.Fatalf("old unreferenced snapshot not isolated: %+v", preview)
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		var err error
		trimmed, err = tx.TrimScanHistory(ctx)
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
