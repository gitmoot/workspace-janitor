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
// Persisted timestamps are UTC RFC3339Nano: pad the optional fraction before
// ordering, since ":00Z" otherwise sorts after the later ":00.5Z".
// Invalid collector JSON or non-object array elements remain pinned without
// blocking future scans.
const historyCandidates = `WITH recent AS (
    SELECT id FROM scans ORDER BY substr(started_at, 1, 19) DESC,
      substr(replace(substr(started_at, 21, 9), 'Z', '') || '000000000', 1, 9) DESC,
      id DESC LIMIT ?
), last_deep AS (
    SELECT s.id FROM scans s WHERE s.status = 'completed'
      AND CASE WHEN json_valid(s.collectors) THEN
        CASE WHEN json_type(s.collectors) = 'array' THEN
          EXISTS (SELECT 1 FROM json_each(s.collectors) c
            WHERE CASE WHEN json_valid(c.value) THEN
              CASE WHEN json_type(c.value) = 'object' THEN
                json_extract(c.value, '$.name') = 'deep_size'
                  AND json_extract(c.value, '$.status') = 'ran'
              ELSE 0 END
            ELSE 0 END)
        ELSE 0 END
      ELSE 0 END
    ORDER BY substr(s.finished_at, 1, 19) DESC,
      substr(replace(substr(s.finished_at, 21, 9), 'Z', '') || '000000000', 1, 9) DESC,
      s.id DESC LIMIT 1
), candidates AS (
    SELECT s.id FROM scans s
    WHERE s.status != 'running' AND s.id != ?
      AND CASE WHEN json_valid(s.collectors) THEN
        CASE WHEN json_type(s.collectors) = 'array' THEN
          NOT EXISTS (SELECT 1 FROM json_each(s.collectors) c
            WHERE CASE WHEN json_valid(c.value) THEN json_type(c.value) != 'object' ELSE 1 END)
        ELSE 0 END
      ELSE 0 END
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
	return t.scanHistoryPreview(ctx, "")
}

func (t *Tx) scanHistoryPreview(ctx context.Context, preserveID string) (ScanHistoryReduction, error) {
	var out ScanHistoryReduction
	err := t.tx.QueryRowContext(ctx, historyCandidates+`SELECT
      (SELECT COUNT(*) FROM candidates),
      (SELECT COUNT(*) FROM inventories WHERE scan_id IN (SELECT id FROM candidates)),
      (SELECT COALESCE(SUM(length(CAST(document AS BLOB))), 0) FROM inventories WHERE scan_id IN (SELECT id FROM candidates))`,
		RecentScanLimit, preserveID).
		Scan(&out.Scans, &out.Entries, &out.Documents)
	if err != nil {
		return ScanHistoryReduction{}, fmt.Errorf("store: preview scan history: %w", err)
	}
	return out, nil
}

// TrimScanHistory discards only unreferenced old snapshots. The caller must
// hold a Store.Write transaction. preserveID prevents a just-persisted scan
// from self-trimming when the host clock moves backwards; pass "" for explicit
// maintenance. FK cascades may remove inventories but never audit records.
func (t *Tx) TrimScanHistory(ctx context.Context, preserveID string) (ScanHistoryReduction, error) {
	eligible, err := t.scanHistoryPreview(ctx, preserveID)
	if err != nil || eligible.Scans == 0 {
		return eligible, err
	}
	result, err := t.tx.ExecContext(ctx, historyCandidates+`DELETE FROM scans WHERE id IN (SELECT id FROM candidates)`,
		RecentScanLimit, preserveID)
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
