package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// HistoryRetention bounds the scan history that no live record needs. Pinned
// scans are kept outside these bounds: the latest scan, running or malformed
// scans, the two most recently completed deep scans, the scans the growth
// report compares, the latest plan's scan, and every scan whose plan an
// active (prepared, quarantined or investigate) cleanup receipt came from.
type HistoryRetention struct {
	// KeepRecent is how many of the newest scans are kept.
	KeepRecent int
	// KeepDays keeps the newest completed scan of each of the last KeepDays
	// UTC days, today included.
	KeepDays int
}

// HistoryTrim describes one trim.
type HistoryTrim struct {
	Retention HistoryRetention
	// Now anchors the daily window.
	Now time.Time
	// PreserveID prevents a just-persisted scan from self-trimming when the
	// host clock moves backwards; "" for explicit maintenance.
	PreserveID string
	// MaxScans bounds how many scans one trim removes or releases, oldest
	// first, so a backlog never holds the write lock for one long
	// transaction; 0 removes every eligible scan.
	MaxScans int
}

// ScanHistoryReduction describes rows that can be discarded without removing
// a pinned scan or any audit record. It is a row count, not disk savings:
// SQLite keeps freed pages until the database is vacuumed.
type ScanHistoryReduction struct {
	// Scans are removed with their inventory, plans and measurements.
	Scans int64 `json:"scans"`
	// Released scans stay as rows because a cycle, advisory or model usage
	// record names them; only their inventory, plans and measurements go.
	Released int64 `json:"released_scans"`
	// Plans counts plans removed with their actions and approvals. Cleanup
	// receipts keep their own entry and action snapshots.
	Plans     int64 `json:"plans"`
	Entries   int64 `json:"entries"`
	Documents int64 `json:"document_bytes"`
}

// ErrInventoryReleased reports a scan whose inventory history retention
// discarded; its row remains only for the audit record naming it.
var ErrInventoryReleased = errors.New("store: scan inventory was released by history retention")

// activeCleanupStates are the receipt states whose items still sit in, or
// are moving to, quarantine. Restored, deleted and superseded receipts are
// terminal and carry their own entry and action snapshots.
const activeCleanupStates = `'prepared', 'quarantined', 'investigate'`

type historyScan struct {
	id       string
	status   string
	started  time.Time
	finished time.Time
	// malformed scans (unparseable timestamps or collector documents) stay
	// for investigation rather than blocking or being silently discarded.
	malformed bool
	// deep scans ran the deep_size collector or were measured as deep.
	deep bool
	// audited scans are named by completed_cycles, advisory or model usage
	// records. The cycle and advisory foreign keys forbid deleting the scan
	// row; model usage would lose its scan id to ON DELETE SET NULL.
	audited bool
	// holdsData is false once a released scan has nothing left to discard.
	holdsData bool
}

// ScanHistoryPreview measures the rows a trim would discard in the current
// transaction. A preview never writes; a later trim recalculates eligibility
// under its own write transaction rather than trusting a stale list of IDs.
func (t *Tx) ScanHistoryPreview(ctx context.Context, retention HistoryRetention, now time.Time) (ScanHistoryReduction, error) {
	out, _, err := t.scanHistoryPlan(ctx, HistoryTrim{Retention: retention, Now: now})
	return out, err
}

// TrimScanHistory discards the inventory history no pinned scan or retention
// bound keeps. The caller must hold a Store.Write transaction. Cascades remove
// inventories, plans, actions, approvals and measurements; audit records and
// cleanup receipts are never removed.
func (t *Tx) TrimScanHistory(ctx context.Context, trim HistoryTrim) (ScanHistoryReduction, error) {
	out, eligible, err := t.scanHistoryPlan(ctx, trim)
	if err != nil {
		return ScanHistoryReduction{}, err
	}
	for _, scan := range eligible {
		if !scan.audited {
			if _, err := t.tx.ExecContext(ctx, `DELETE FROM scans WHERE id = ?`, scan.id); err != nil {
				return ScanHistoryReduction{}, fmt.Errorf("store: trim scan %s: %w", scan.id, err)
			}
			continue
		}
		for _, statement := range []string{
			`DELETE FROM inventories WHERE scan_id = ?`,
			`DELETE FROM plans WHERE scan_id = ?`,
			`DELETE FROM inventory_measurements WHERE scan_id = ?`,
		} {
			if _, err := t.tx.ExecContext(ctx, statement, scan.id); err != nil {
				return ScanHistoryReduction{}, fmt.Errorf("store: release scan %s: %w", scan.id, err)
			}
		}
	}
	return out, nil
}

// scanHistoryPlan selects the scans a trim discards, oldest first, and
// measures what discarding them removes.
func (t *Tx) scanHistoryPlan(ctx context.Context, trim HistoryTrim) (ScanHistoryReduction, []historyScan, error) {
	scans, err := t.historyScans(ctx)
	if err != nil {
		return ScanHistoryReduction{}, nil, err
	}
	pinned, err := t.pinnedScans(ctx, scans, trim)
	if err != nil {
		return ScanHistoryReduction{}, nil, err
	}
	var eligible []historyScan
	// scans are newest first; trim the oldest first.
	for i := len(scans) - 1; i >= 0; i-- {
		scan := scans[i]
		if pinned[scan.id] || scan.audited && !scan.holdsData {
			continue
		}
		if trim.MaxScans > 0 && len(eligible) == trim.MaxScans {
			break
		}
		eligible = append(eligible, scan)
	}
	var out ScanHistoryReduction
	for _, scan := range eligible {
		var entries, documents, plans int64
		if err := t.tx.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM inventories WHERE scan_id = ?),
			(SELECT COALESCE(SUM(length(CAST(document AS BLOB))), 0) FROM inventories WHERE scan_id = ?),
			(SELECT COUNT(*) FROM plans WHERE scan_id = ?)`, scan.id, scan.id, scan.id).
			Scan(&entries, &documents, &plans); err != nil {
			return ScanHistoryReduction{}, nil, fmt.Errorf("store: measure scan %s: %w", scan.id, err)
		}
		if scan.audited {
			out.Released++
		} else {
			out.Scans++
		}
		out.Entries += entries
		out.Documents += documents
		out.Plans += plans
	}
	return out, eligible, nil
}

// historyScans lists every scan newest first.
func (t *Tx) historyScans(ctx context.Context) ([]historyScan, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT s.id, s.status, s.started_at, s.finished_at, s.collectors,
		COALESCE(m.deep, 0) = 1,
		EXISTS (SELECT 1 FROM completed_cycles c WHERE c.scan_id = s.id)
		  OR EXISTS (SELECT 1 FROM advisory_runs a WHERE a.scan_id = s.id)
		  OR EXISTS (SELECT 1 FROM advisory_attempts a WHERE a.scan_id = s.id)
		  OR EXISTS (SELECT 1 FROM model_usage u WHERE u.scan_id = s.id),
		m.scan_id IS NOT NULL
		  OR EXISTS (SELECT 1 FROM inventories i WHERE i.scan_id = s.id)
		  OR EXISTS (SELECT 1 FROM plans p WHERE p.scan_id = s.id)
		FROM scans s LEFT JOIN inventory_measurements m ON m.scan_id = s.id`)
	if err != nil {
		return nil, fmt.Errorf("store: list scan history: %w", err)
	}
	defer rows.Close()
	var out []historyScan
	for rows.Next() {
		var scan historyScan
		var started, collectors string
		var finished sql.NullString
		if err := rows.Scan(&scan.id, &scan.status, &started, &finished, &collectors,
			&scan.deep, &scan.audited, &scan.holdsData); err != nil {
			return nil, fmt.Errorf("store: read scan history: %w", err)
		}
		var deepRan bool
		deepRan, scan.malformed = deepCollectorRan(collectors)
		scan.deep = scan.deep || deepRan
		if scan.started, err = parseTime(started); err != nil {
			scan.malformed = true
		}
		if finished.Valid {
			if scan.finished, err = parseTime(finished.String); err != nil {
				scan.malformed = true
			}
		}
		out = append(out, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read scan history: %w", err)
	}
	slices.SortFunc(out, func(a, b historyScan) int {
		if c := b.started.Compare(a.started); c != 0 {
			return c
		}
		return strings.Compare(b.id, a.id)
	})
	return out, nil
}

// deepCollectorRan reports whether the deep_size collector ran, and whether
// the collector document is malformed: not an array of objects.
func deepCollectorRan(document string) (ran, malformed bool) {
	var reports []json.RawMessage
	if err := json.Unmarshal([]byte(document), &reports); err != nil || reports == nil {
		return false, true
	}
	for _, raw := range reports {
		var report struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &report) != nil {
			return false, true
		}
		ran = ran || report.Name == "deep_size" && report.Status == "ran"
	}
	return ran, false
}

// pinnedScans returns the scans a trim must keep.
func (t *Tx) pinnedScans(ctx context.Context, scans []historyScan, trim HistoryTrim) (map[string]bool, error) {
	pinned := map[string]bool{}
	if trim.PreserveID != "" {
		pinned[trim.PreserveID] = true
	}
	recent, days := 0, map[string]bool{}
	firstDay := trim.Now.UTC().AddDate(0, 0, 1-trim.Retention.KeepDays).Format(time.DateOnly)
	for i, scan := range scans {
		if i == 0 || scan.malformed || scan.status == "running" {
			pinned[scan.id] = true
		}
		if recent < trim.Retention.KeepRecent {
			recent++
			pinned[scan.id] = true
		}
		if day := scan.started.UTC().Format(time.DateOnly); trim.Retention.KeepDays > 0 &&
			scan.status == "completed" && day >= firstDay && !days[day] {
			days[day] = true
			pinned[scan.id] = true
		}
	}
	// The two most recently completed deep scans, by completion.
	deep := slices.DeleteFunc(slices.Clone(scans), func(scan historyScan) bool {
		return !scan.deep || scan.status != "completed" || scan.finished.IsZero()
	})
	slices.SortFunc(deep, func(a, b historyScan) int {
		if c := b.finished.Compare(a.finished); c != 0 {
			return c
		}
		return strings.Compare(b.id, a.id)
	})
	for _, scan := range deep[:min(2, len(deep))] {
		pinned[scan.id] = true
	}
	// The scans the growth report compares now.
	comparison, err := t.inventoryComparisonIDs(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	pinned[comparison.current] = true
	pinned[comparison.previous] = true
	// The latest plan, which explain and apply load by default, and every
	// plan an active cleanup receipt came from.
	rows, err := t.tx.QueryContext(ctx, `SELECT scan_id FROM (SELECT scan_id FROM plans ORDER BY created_at DESC, id DESC LIMIT 1)
		UNION SELECT p.scan_id FROM plans p WHERE EXISTS (SELECT 1 FROM cleanup_items c
		  WHERE c.plan_id = p.id AND c.state IN (`+activeCleanupStates+`))`)
	if err != nil {
		return nil, fmt.Errorf("store: list pinned plan scans: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: read pinned plan scan: %w", err)
		}
		pinned[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read pinned plan scans: %w", err)
	}
	return pinned, nil
}
