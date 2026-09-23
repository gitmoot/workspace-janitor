// Package store persists inventories, scans, plans, actions, and model usage
// in a local SQLite database.
//
// The driver is pure Go (modernc.org/sqlite), so the CLI builds statically
// with CGO_ENABLED=0. Every write goes through a transaction: a partially
// written plan would be indistinguishable from a complete one.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	_ "modernc.org/sqlite" // pure-Go SQLite driver; no cgo
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("store: record not found")

// ErrNotInitialized is returned by OpenExisting when no database file exists.
var ErrNotInitialized = errors.New("store: database has not been initialized")

// DirMode and FileMode keep local state owner-only: it records the layout of
// a machine, which is not public information.
const (
	DirMode  os.FileMode = 0o700
	FileMode os.FileMode = 0o600
)

// Store is an open database handle with the current schema applied.
type Store struct {
	db       *sql.DB
	path     string
	readOnly bool
}

// Open opens the database at path, creating the file and its parent directory
// when needed, and applies all pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: database path must not be empty")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("store: database path must be absolute, got %q", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), DirMode); err != nil {
		return nil, fmt.Errorf("store: create state directory: %w", err)
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One connection keeps write transactions strictly serialized, which is
	// the right trade for a CLI: no lock contention, no surprise retries.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := os.Chmod(path, FileMode); err != nil && !errors.Is(err, os.ErrNotExist) {
		db.Close()
		return nil, fmt.Errorf("store: secure %s: %w", path, err)
	}
	s := &Store{db: db, path: path}
	if _, err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenExisting opens an already-created database. It returns
// ErrNotInitialized when the file does not exist, so reporting commands can
// say "no state yet" instead of silently creating one.
func OpenExisting(ctx context.Context, path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInitialized
		}
		return nil, fmt.Errorf("store: stat %s: %w", path, err)
	}
	return Open(ctx, path)
}

// ErrSchemaMismatch reports a database whose schema version differs from
// this build's, encountered on a read-only open that may not migrate it.
var ErrSchemaMismatch = errors.New("store: database schema version differs from this build")

// OpenReadOnly opens an existing database for reading only.
//
// Unlike Open it creates nothing, changes no permissions, sets no journal
// mode, and applies no migration: a reporting-only command must leave the
// durable database byte-identical. A schema that does not match this build
// is reported as ErrSchemaMismatch rather than upgraded behind the
// operator's back.
//
// One caveat is inherent to SQLite: reading a database in WAL mode requires
// mapping the shared-memory index, so empty "-wal" and "-shm" sidecars may
// appear. No transaction is committed and the database file itself is
// unchanged.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInitialized
		}
		return nil, fmt.Errorf("store: stat %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s read-only: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open %s read-only: %w", path, err)
	}
	s := &Store{db: db, path: path, readOnly: true}
	version, err := s.userVersion(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	if version != SchemaVersion() {
		db.Close()
		return nil, fmt.Errorf("%w: database is at %d, this build expects %d", ErrSchemaMismatch, version, SchemaVersion())
	}
	return s, nil
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// ReadOnly reports whether this handle may not write.
func (s *Store) ReadOnly() bool { return s.readOnly }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Tx is a transaction scope exposing every persistence operation.
type Tx struct{ tx *sql.Tx }

// Write runs fn inside a transaction, committing on success and rolling back
// on any error or panic.
func (s *Store) Write(ctx context.Context, fn func(*Tx) error) error {
	if s.readOnly {
		return fmt.Errorf("store: %s is open read-only", s.path)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(&Tx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}

// Read runs fn inside a read-only transaction.
func (s *Store) Read(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("store: begin read transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	return fn(&Tx{tx: tx})
}

// Stats summarizes stored state for reporting commands.
type Stats struct {
	SchemaVersion    int        `json:"schema_version"`
	ContractVersion  int        `json:"contract_version"`
	Scans            int64      `json:"scans"`
	InventoryEntries int64      `json:"inventory_entries"`
	Plans            int64      `json:"plans"`
	Actions          int64      `json:"actions"`
	ModelUsageRows   int64      `json:"model_usage_rows"`
	DatabaseBytes    int64      `json:"database_bytes"`
	LatestScanID     string     `json:"latest_scan_id,omitempty"`
	LatestScanAt     *time.Time `json:"latest_scan_at,omitempty"`
}

// Stats collects row counts and the most recent scan.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	stats := Stats{ContractVersion: core.ContractVersion}
	err := s.Read(ctx, func(tx *Tx) error {
		version, err := tx.schemaVersion(ctx)
		if err != nil {
			return err
		}
		stats.SchemaVersion = version
		counts := []struct {
			table string
			into  *int64
		}{
			{"scans", &stats.Scans},
			{"inventories", &stats.InventoryEntries},
			{"plans", &stats.Plans},
			{"actions", &stats.Actions},
			{"model_usage", &stats.ModelUsageRows},
		}
		for _, c := range counts {
			// Table names are compile-time constants, never user input.
			if err := tx.tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+c.table).Scan(c.into); err != nil {
				return fmt.Errorf("store: count %s: %w", c.table, err)
			}
		}
		var (
			id        sql.NullString
			startedAt sql.NullString
		)
		row := tx.tx.QueryRowContext(ctx, `SELECT id, started_at FROM scans ORDER BY started_at DESC, id DESC LIMIT 1`)
		switch err := row.Scan(&id, &startedAt); {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return fmt.Errorf("store: latest scan: %w", err)
		default:
			stats.LatestScanID = id.String
			if startedAt.Valid {
				t, err := parseTime(startedAt.String)
				if err != nil {
					return err
				}
				stats.LatestScanAt = &t
			}
		}
		return nil
	})
	if err != nil {
		return Stats{}, err
	}
	if info, statErr := os.Stat(s.path); statErr == nil {
		stats.DatabaseBytes = info.Size()
	}
	return stats, nil
}

// readOnlyDSN opens the database strictly for reading: no journal-mode
// change, no recovery write, and the connection itself refuses writes.
func readOnlyDSN(path string) string {
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	q.Add("mode", "ro")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "query_only(1)")
	u.RawQuery = q.Encode()
	return u.String()
}

func dsn(path string) string {
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(wal)")
	q.Add("_pragma", "synchronous(full)")
	u.RawQuery = q.Encode()
	return u.String()
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: parse timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}
