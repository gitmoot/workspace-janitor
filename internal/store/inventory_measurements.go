package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// InventoryPair contains observations, not a claim that either tree is complete.
// Callers must check each entry's size bounds and identity before subtracting.
type InventoryPair struct {
	Current         core.Scan
	Previous        *core.Scan
	CurrentEntries  []core.Entry
	PreviousEntries []core.Entry
	Scope           string
	Deep            bool
}

func (t *Tx) RecordInventoryMeasurement(ctx context.Context, scanID, scope string, deep bool) error {
	if len(scope) != 64 {
		return fmt.Errorf("inventory measurement scope must be a SHA256 digest")
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO inventory_measurements(scan_id, scope, deep) VALUES (?, ?, ?)`, scanID, scope, deep)
	return err
}

// UTC timestamps have an optional fractional component. Lexical ordering of
// RFC3339Nano itself would put a whole second after its fractional successors.
const inventoryStartedKey = `substr(s.started_at, 1, 19) || '.' || substr(replace(substr(s.started_at, 21, 9), 'Z', '') || '000000000', 1, 9)`
const inventoryFinishedKey = `substr(s.finished_at, 1, 19) || '.' || substr(replace(substr(s.finished_at, 21, 9), 'Z', '') || '000000000', 1, 9)`

// InventoryComparison prefers the latest deep observation; frequent metadata
// scans must not hide the last measured tree sizes. Its timestamps remain visible
// to callers. Legacy observations without scope metadata have no growth baseline.
func (t *Tx) InventoryComparison(ctx context.Context) (InventoryPair, error) {
	var out InventoryPair
	ids, err := t.inventoryComparisonIDs(ctx)
	if err != nil {
		return out, err
	}
	out.Scope, out.Deep = ids.scope, ids.deep
	out.Current, err = t.Scan(ctx, ids.current)
	if err != nil {
		return out, err
	}
	out.CurrentEntries, err = t.Entries(ctx, ids.current)
	if err != nil || ids.previous == "" {
		return out, err
	}
	previous, err := t.Scan(ctx, ids.previous)
	if err != nil {
		return out, err
	}
	out.Previous = &previous
	out.PreviousEntries, err = t.Entries(ctx, ids.previous)
	return out, err
}

// comparisonIDs names the scans InventoryComparison reads; history retention
// pins both.
type comparisonIDs struct {
	current, previous string
	scope             string
	deep              bool
}

func (t *Tx) inventoryComparisonIDs(ctx context.Context) (comparisonIDs, error) {
	var out comparisonIDs
	err := t.tx.QueryRowContext(ctx, `SELECT s.id FROM scans s JOIN inventory_measurements m ON m.scan_id=s.id
		WHERE s.status='completed' AND m.deep=1 ORDER BY `+inventoryStartedKey+` DESC, s.id DESC LIMIT 1`).Scan(&out.current)
	if errors.Is(err, sql.ErrNoRows) {
		err = t.tx.QueryRowContext(ctx, `SELECT s.id FROM scans s WHERE s.status='completed'
			ORDER BY `+inventoryStartedKey+` DESC, s.id DESC LIMIT 1`).Scan(&out.current)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	var started string
	err = t.tx.QueryRowContext(ctx, `SELECT s.started_at, m.scope, m.deep FROM scans s
		JOIN inventory_measurements m ON m.scan_id=s.id WHERE s.id=?`, out.current).Scan(&started, &out.scope, &out.deep)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	startedAt, err := parseTime(started)
	if err != nil {
		return out, err
	}
	cutoff := startedAt.Format("2006-01-02T15:04:05.000000000")
	err = t.tx.QueryRowContext(ctx, `SELECT s.id FROM scans s JOIN inventory_measurements m ON m.scan_id=s.id
		WHERE s.status='completed' AND m.scope=? AND `+inventoryStartedKey+` < ? AND `+inventoryFinishedKey+` <= ?
		ORDER BY `+inventoryStartedKey+` DESC, s.id DESC LIMIT 1`, out.scope, cutoff, cutoff).Scan(&out.previous)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	return out, err
}
