package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// ActivityHistoryLimit bounds reporting metadata, not authoritative audit data.
const ActivityHistoryLimit = 256

func (t *Tx) RecordCapacityActivity(ctx context.Context, activity core.CapacityActivity) error {
	if activity.ID == "" || activity.Kind == "" || activity.State == "" || activity.StartedAt.IsZero() {
		return fmt.Errorf("incomplete capacity activity")
	}
	data, err := json.Marshal(activity)
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return fmt.Errorf("capacity activity exceeds reporting bound")
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO capacity_activity(id, document) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET document=excluded.document`, activity.ID, string(data))
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, `DELETE FROM capacity_activity WHERE sequence NOT IN
		(SELECT sequence FROM capacity_activity ORDER BY sequence DESC LIMIT ?)`, ActivityHistoryLimit)
	return err
}

func (t *Tx) CapacityActivities(ctx context.Context) ([]core.CapacityActivity, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT document FROM capacity_activity ORDER BY sequence DESC LIMIT ?`, ActivityHistoryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.CapacityActivity{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var activity core.CapacityActivity
		if err := json.Unmarshal([]byte(data), &activity); err != nil {
			return nil, fmt.Errorf("invalid capacity activity: %w", err)
		}
		out = append(out, activity)
	}
	return out, rows.Err()
}
