package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// LastDeepScan returns the last completed scheduler deep scan, or zero when
// none has succeeded. Event-driven metadata scans never advance this clock.
func (t *Tx) LastDeepScan(ctx context.Context) (time.Time, error) {
	var ns int64
	err := t.tx.QueryRowContext(ctx,
		`SELECT last_completed_ns FROM prevention_state WHERE key = 'deep_scan'`).Scan(&ns)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, ns).UTC(), nil
}

// RecordDeepScan only follows a completed scan whose deep-size collector ran.
// MAX prevents a concurrent older scan from moving the cadence clock back.
func (t *Tx) RecordDeepScan(ctx context.Context, completed time.Time) error {
	if completed.IsZero() {
		return errors.New("deep scan completion time is required")
	}
	_, err := t.tx.ExecContext(ctx,
		`INSERT INTO prevention_state (key, last_completed_ns) VALUES ('deep_scan', ?)
		 ON CONFLICT(key) DO UPDATE SET last_completed_ns = max(prevention_state.last_completed_ns, excluded.last_completed_ns)`,
		completed.UTC().UnixNano())
	return err
}
