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
	var id string
	err := t.tx.QueryRowContext(ctx, `SELECT s.id FROM scans s JOIN inventory_measurements m ON m.scan_id=s.id
		WHERE s.status='completed' AND m.deep=1 ORDER BY `+inventoryStartedKey+` DESC, s.id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = t.tx.QueryRowContext(ctx, `SELECT s.id FROM scans s WHERE s.status='completed'
			ORDER BY `+inventoryStartedKey+` DESC, s.id DESC LIMIT 1`).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.Current, err = t.Scan(ctx, id)
	if err != nil {
		return out, err
	}
	out.CurrentEntries, err = t.Entries(ctx, id)
	if err != nil {
		return out, err
	}
	err = t.tx.QueryRowContext(ctx, `SELECT scope, deep FROM inventory_measurements WHERE scan_id=?`, id).Scan(&out.Scope, &out.Deep)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	cutoff := out.Current.StartedAt.UTC().Format("2006-01-02T15:04:05.000000000")
	err = t.tx.QueryRowContext(ctx, `SELECT s.id FROM scans s JOIN inventory_measurements m ON m.scan_id=s.id
		WHERE s.status='completed' AND m.scope=? AND `+inventoryStartedKey+` < ? AND `+inventoryFinishedKey+` <= ?
		ORDER BY `+inventoryStartedKey+` DESC, s.id DESC LIMIT 1`, out.Scope, cutoff, cutoff).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	previous, err := t.Scan(ctx, id)
	if err != nil {
		return out, err
	}
	out.Previous = &previous
	out.PreviousEntries, err = t.Entries(ctx, id)
	return out, err
}
