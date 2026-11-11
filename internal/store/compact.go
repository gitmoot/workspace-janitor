package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// TrimHistoryBatch bounds the scans one maintenance transaction discards, so
// a large backlog never holds the write lock for one long transaction.
const TrimHistoryBatch = 16

// VacuumMinFreeRatio is the free-page share of the database file above which
// the cycle rewrites it. Deleted rows leave free pages that later inserts
// reuse; below this share the rewrite costs more than it returns.
const VacuumMinFreeRatio = 0.25

// TrimHistory discards eligible scan history in transactions of at most
// TrimHistoryBatch scans, until nothing is eligible. Each transaction
// recalculates the pins, so a scan persisted meanwhile is never trimmed.
func (s *Store) TrimHistory(ctx context.Context, retention HistoryRetention, now time.Time) (ScanHistoryReduction, error) {
	var total ScanHistoryReduction
	for {
		var batch ScanHistoryReduction
		err := s.Write(ctx, func(tx *Tx) error {
			var err error
			batch, err = tx.TrimScanHistory(ctx, HistoryTrim{Retention: retention, Now: now, MaxScans: TrimHistoryBatch})
			return err
		})
		if err != nil {
			return total, err
		}
		total.Scans += batch.Scans
		total.Released += batch.Released
		total.Plans += batch.Plans
		total.Entries += batch.Entries
		total.Documents += batch.Documents
		if batch.Scans+batch.Released < TrimHistoryBatch {
			return total, nil
		}
	}
}

// SpaceUsage is the database file's page accounting.
type SpaceUsage struct {
	PageSize  int64 `json:"page_size"`
	Pages     int64 `json:"pages"`
	FreePages int64 `json:"free_pages"`
}

// Bytes is the database file size.
func (u SpaceUsage) Bytes() int64 { return u.Pages * u.PageSize }

// LiveBytes is the size of the pages holding data.
func (u SpaceUsage) LiveBytes() int64 { return (u.Pages - u.FreePages) * u.PageSize }

// FreeRatio is the share of the file that is free pages.
func (u SpaceUsage) FreeRatio() float64 {
	if u.Pages == 0 {
		return 0
	}
	return float64(u.FreePages) / float64(u.Pages)
}

// SpaceUsage reads the page accounting of the main database file.
func (s *Store) SpaceUsage(ctx context.Context) (SpaceUsage, error) {
	var u SpaceUsage
	for _, pragma := range []struct {
		name string
		dest *int64
	}{{"page_size", &u.PageSize}, {"page_count", &u.Pages}, {"freelist_count", &u.FreePages}} {
		if err := s.db.QueryRowContext(ctx, "PRAGMA "+pragma.name).Scan(pragma.dest); err != nil {
			return SpaceUsage{}, fmt.Errorf("store: read %s: %w", pragma.name, err)
		}
	}
	return u, nil
}

// VacuumRequiredBytes is the free filesystem space a VACUUM may consume plus
// margin. VACUUM copies the live pages into a temporary database and, in WAL
// mode, writes them again into the WAL before the checkpoint truncates the
// file; the requirement is also never below the current file size.
func VacuumRequiredBytes(usage SpaceUsage, margin uint64) uint64 {
	return uint64(max(usage.Bytes(), 2*usage.LiveBytes())) + margin
}

// VacuumRefusal returns why the database must not be vacuumed now, or "".
func VacuumRefusal(usage SpaceUsage, availableBytes, margin uint64) string {
	if usage.FreeRatio() < VacuumMinFreeRatio {
		return fmt.Sprintf("free pages %.1f%% below %.0f%%", 100*usage.FreeRatio(), 100*VacuumMinFreeRatio)
	}
	if required := VacuumRequiredBytes(usage, margin); availableBytes < required {
		return fmt.Sprintf("filesystem has %d bytes free; vacuum needs %d", availableBytes, required)
	}
	return ""
}

// SpaceReclaim reports one guarded VACUUM decision.
type SpaceReclaim struct {
	Before         SpaceUsage  `json:"before"`
	After          *SpaceUsage `json:"after,omitempty"`
	AvailableBytes uint64      `json:"available_bytes"`
	RequiredBytes  uint64      `json:"required_bytes"`
	Vacuumed       bool        `json:"vacuumed"`
	Skipped        string      `json:"skipped,omitempty"`
	DurationMS     int64       `json:"duration_ms"`
}

// ReclaimSpace rewrites the database file when free pages are at least
// VacuumMinFreeRatio of it and the filesystem has VacuumRequiredBytes free.
// availableBytes is the free space of the database's filesystem; margin is
// headroom that must remain free afterwards. VACUUM needs the write lock; when
// another writer holds it past busy_timeout the vacuum is skipped, not failed,
// and the next cycle tries again.
func (s *Store) ReclaimSpace(ctx context.Context, availableBytes, margin uint64) (SpaceReclaim, error) {
	if s.readOnly {
		return SpaceReclaim{}, fmt.Errorf("store: %s is open read-only", s.path)
	}
	usage, err := s.SpaceUsage(ctx)
	if err != nil {
		return SpaceReclaim{}, err
	}
	out := SpaceReclaim{Before: usage, AvailableBytes: availableBytes, RequiredBytes: VacuumRequiredBytes(usage, margin)}
	if out.Skipped = VacuumRefusal(usage, availableBytes, margin); out.Skipped != "" {
		return out, nil
	}
	started := time.Now()
	if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code()&0xff == sqlite3.SQLITE_BUSY {
			out.Skipped = "database busy"
			return out, nil
		}
		return out, fmt.Errorf("store: vacuum: %w", err)
	}
	// Return the WAL, which now holds a copy of every page, to zero bytes.
	// A reader still holding a snapshot makes this a no-op until a later
	// checkpoint; that is not an error.
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return out, fmt.Errorf("store: checkpoint after vacuum: %w", err)
	}
	out.Vacuumed = true
	out.DurationMS = time.Since(started).Milliseconds()
	after, err := s.SpaceUsage(ctx)
	if err != nil {
		return out, err
	}
	out.After = &after
	return out, nil
}
