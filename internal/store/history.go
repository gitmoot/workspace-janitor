package store

import (
	"context"
	"fmt"
)

// RecentScanLimit bounds unreferenced inventory history. Audited scans and the
// latest completed deep-size scan are retained outside this count.
const RecentScanLimit = 256

// ScanHistoryReduction describes rows that can be discarded without removing
// a referenced scan or any audit record. It is a row count, not disk savings:
// SQLite keeps freed pages until a separately coordinated offline compaction.
type ScanHistoryReduction struct {
	Scans     int64 `json:"scans"`
	Entries   int64 `json:"entries"`
	Documents int64 `json:"document_bytes"`
}

// historyCandidates selects only snapshots with no durable audit reference.
// Keep the latest completed deep scan even if its cadence clock has since
// advanced; the clock itself is independent of inventory retention.
const historyCandidates = `WITH recent AS (
    SELECT id FROM scans ORDER BY started_at DESC, id DESC LIMIT 256
), last_deep AS (
    SELECT s.id FROM scans s WHERE s.status = 'completed'
      AND EXISTS (SELECT 1 FROM json_each(s.collectors) c
        WHERE json_extract(c.value, '$.name') = 'deep_size'
          AND json_extract(c.value, '$.status') = 'ran')
    ORDER BY s.started_at DESC, s.id DESC LIMIT 1
), candidates AS (
    SELECT s.id FROM scans s
    WHERE s.status != 'running'
      AND NOT EXISTS (SELECT 1 FROM recent WHERE recent.id = s.id)
      AND NOT EXISTS (SELECT 1 FROM last_deep WHERE last_deep.id = s.id)
      AND NOT EXISTS (SELECT 1 FROM plans p WHERE p.scan_id = s.id)
      AND NOT EXISTS (SELECT 1 FROM completed_cycles c WHERE c.scan_id = s.id)
      AND NOT EXISTS (SELECT 1 FROM advisory_runs a WHERE a.scan_id = s.id)
      AND NOT EXISTS (SELECT 1 FROM advisory_attempts a WHERE a.scan_id = s.id)
      AND NOT EXISTS (SELECT 1 FROM model_usage m WHERE m.scan_id = s.id)
)
`

// ScanHistoryPreview measures eligible rows in the current transaction. A
// preview never writes; a later trim recalculates eligibility under its own
// write transaction rather than trusting a stale list of IDs.
func (t *Tx) ScanHistoryPreview(ctx context.Context) (ScanHistoryReduction, error) {
	var out ScanHistoryReduction
	err := t.tx.QueryRowContext(ctx, historyCandidates+`SELECT
      (SELECT COUNT(*) FROM candidates),
      (SELECT COUNT(*) FROM inventories WHERE scan_id IN (SELECT id FROM candidates)),
      (SELECT COALESCE(SUM(length(document)), 0) FROM inventories WHERE scan_id IN (SELECT id FROM candidates))`).
		Scan(&out.Scans, &out.Entries, &out.Documents)
	if err != nil {
		return ScanHistoryReduction{}, fmt.Errorf("store: preview scan history: %w", err)
	}
	return out, nil
}

// TrimScanHistory discards only unreferenced old snapshots. The caller must
// hold a Store.Write transaction; FK cascades may remove inventories but never
// plans/actions, receipts, advisory ledgers or model usage. No VACUUM occurs.
func (t *Tx) TrimScanHistory(ctx context.Context) (ScanHistoryReduction, error) {
	eligible, err := t.ScanHistoryPreview(ctx)
	if err != nil || eligible.Scans == 0 {
		return eligible, err
	}
	result, err := t.tx.ExecContext(ctx, historyCandidates+`DELETE FROM scans WHERE id IN (SELECT id FROM candidates)`)
	if err != nil {
		return ScanHistoryReduction{}, fmt.Errorf("store: trim scan history: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return ScanHistoryReduction{}, fmt.Errorf("store: count trimmed scans: %w", err)
	}
	if deleted != eligible.Scans {
		return ScanHistoryReduction{}, fmt.Errorf("store: scan history changed during trim: deleted %d of %d", deleted, eligible.Scans)
	}
	return eligible, nil
}
