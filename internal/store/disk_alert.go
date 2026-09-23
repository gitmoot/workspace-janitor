package store

import (
	"context"
	"errors"
	"time"
)

// ClaimDiskAlert atomically admits at most one alert per filesystem within the
// cooldown, even when two background janitor processes run concurrently. The
// summary is the exact deterministic payload last emitted.
func (t *Tx) ClaimDiskAlert(ctx context.Context, filesystem, summary string, now time.Time, cooldown time.Duration) (bool, error) {
	if filesystem == "" || summary == "" || cooldown <= 0 {
		return false, errors.New("invalid disk alert claim")
	}
	result, err := t.tx.ExecContext(ctx, `INSERT INTO disk_alerts (filesystem_key, last_emitted_ns, summary)
		VALUES (?, ?, ?) ON CONFLICT(filesystem_key) DO UPDATE SET
		last_emitted_ns = excluded.last_emitted_ns, summary = excluded.summary
		WHERE disk_alerts.last_emitted_ns <= ?`,
		filesystem, now.UTC().UnixNano(), summary, now.UTC().Add(-cooldown).UnixNano())
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}
