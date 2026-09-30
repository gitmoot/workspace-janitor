package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Two processes write the same database: the cycle's apply journals cleanup
// items while the watcher records a scan. A write transaction that reads
// before it writes must wait for the other writer (busy_timeout), not fail
// with SQLITE_BUSY the moment it tries to upgrade its read lock (#50).
func TestConcurrentReadThenWriteTransactionsWaitInsteadOfFailing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "janitor.db")
	a, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, s := range []*Store{a, b} {
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			errs <- s.Write(ctx, func(tx *Tx) error {
				// Read first, as the cleanup journal does before updating.
				var n int
				if err := tx.tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
					return err
				}
				// Hold the read lock long enough for the other writer to start.
				time.Sleep(200 * time.Millisecond)
				_, err := tx.tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS busy_probe_`+string(rune('a'+i))+` (x INTEGER)`)
				return err
			})
		}(i, s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write failed instead of waiting: %v", err)
		}
	}
}
