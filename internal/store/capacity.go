package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// CapacitySnapshot returns the last bounded filesystem sample. The singleton
// avoids accumulating a new row for each poll or policy revision.
func (t *Tx) CapacitySnapshot(ctx context.Context) (core.CapacitySnapshot, error) {
	var snapshot core.CapacitySnapshot
	var data string
	err := t.tx.QueryRowContext(ctx, `SELECT snapshot FROM capacity_snapshot WHERE id = 1`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	err = json.Unmarshal([]byte(data), &snapshot)
	return snapshot, err
}

func (t *Tx) SaveCapacitySnapshot(ctx context.Context, snapshot core.CapacitySnapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO capacity_snapshot (id, snapshot) VALUES (1, ?)
  ON CONFLICT(id) DO UPDATE SET snapshot = excluded.snapshot`, string(data))
	return err
}
