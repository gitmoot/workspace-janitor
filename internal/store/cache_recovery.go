package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ClaimCacheRecovery runs inside the existing immediate writer transaction.
// An interrupted/failed provider is never automatically retried under the same
// approval. The minimum interval also survives process restart and policy edits.
func (t *Tx) ClaimCacheRecovery(ctx context.Context, path, approval string, now time.Time, interval time.Duration) (string, error) {
	var oldApproval, at, outcome string
	err := t.tx.QueryRowContext(ctx, `SELECT approval, attempted_at, outcome FROM cache_recovery_attempts WHERE path = ?`, path).Scan(&oldApproval, &at, &outcome)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if err == nil {
		previous, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return "", fmt.Errorf("invalid recovery attempt time: %w", err)
		}
		if (outcome == "starting" || outcome == "failed") && oldApproval == approval {
			return "previous provider attempt failed or is uncertain; owner must reconcile it and issue a new approval", nil
		}
		if now.Before(previous.Add(interval)) {
			return "store recovery cooldown remains active", nil
		}
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO cache_recovery_attempts(path, approval, attempted_at, outcome) VALUES (?, ?, ?, 'starting')
  ON CONFLICT(path) DO UPDATE SET approval=excluded.approval, attempted_at=excluded.attempted_at, outcome=excluded.outcome`, path, approval, now.UTC().Format(time.RFC3339Nano))
	return "", err
}

func (t *Tx) FinishCacheRecovery(ctx context.Context, path, approval, outcome string) error {
	if outcome != "completed" && outcome != "failed" && outcome != "refused" {
		return fmt.Errorf("invalid recovery outcome %q", outcome)
	}
	result, err := t.tx.ExecContext(ctx, `UPDATE cache_recovery_attempts SET outcome=? WHERE path=? AND approval=? AND outcome='starting'`, outcome, path, approval)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("recovery attempt ownership changed for %s", path)
	}
	return nil
}
