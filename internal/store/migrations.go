package store

import (
	"context"
	"fmt"
	"time"
)

// migration is one forward-only schema step. Steps are never edited after
// release: a changed step would leave existing databases silently divergent.
type migration struct {
	version    int
	name       string
	statements []string
}

var migrations = []migration{
	{
		version: 1,
		name:    "initial_schema",
		statements: []string{
			`CREATE TABLE schema_migrations (
				version    INTEGER PRIMARY KEY,
				name       TEXT NOT NULL,
				applied_at TEXT NOT NULL
			)`,
			`CREATE TABLE scans (
				id               TEXT PRIMARY KEY,
				contract_version INTEGER NOT NULL,
				roots            TEXT NOT NULL,
				status           TEXT NOT NULL,
				started_at       TEXT NOT NULL,
				finished_at      TEXT,
				entry_count      INTEGER NOT NULL DEFAULT 0,
				error            TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE inventories (
				scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
				path        TEXT NOT NULL,
				root        TEXT NOT NULL,
				kind        TEXT NOT NULL,
				class       TEXT NOT NULL,
				device      INTEGER NOT NULL,
				inode       INTEGER NOT NULL,
				size_bytes  INTEGER NOT NULL,
				modified_at TEXT NOT NULL,
				observed_at TEXT NOT NULL,
				protected   INTEGER NOT NULL,
				document    TEXT NOT NULL,
				PRIMARY KEY (scan_id, path)
			)`,
			`CREATE INDEX inventories_path_idx ON inventories(path)`,
			`CREATE INDEX inventories_identity_idx ON inventories(device, inode)`,
			`CREATE TABLE plans (
				id               TEXT PRIMARY KEY,
				scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
				contract_version INTEGER NOT NULL,
				status           TEXT NOT NULL,
				created_at       TEXT NOT NULL
			)`,
			`CREATE INDEX plans_scan_idx ON plans(scan_id)`,
			`CREATE TABLE actions (
				id          TEXT PRIMARY KEY,
				plan_id     TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
				path        TEXT NOT NULL,
				kind        TEXT NOT NULL,
				retention   TEXT NOT NULL,
				confidence  REAL NOT NULL,
				status      TEXT NOT NULL,
				destination TEXT NOT NULL DEFAULT '',
				device      INTEGER NOT NULL DEFAULT 0,
				inode       INTEGER NOT NULL DEFAULT 0,
				reasons     TEXT NOT NULL DEFAULT '[]',
				guards      TEXT NOT NULL DEFAULT '[]',
				created_at  TEXT NOT NULL,
				applied_at  TEXT
			)`,
			`CREATE INDEX actions_plan_idx ON actions(plan_id)`,
			`CREATE INDEX actions_path_idx ON actions(path)`,
			`CREATE TABLE model_usage (
				id                 TEXT PRIMARY KEY,
				scan_id            TEXT REFERENCES scans(id) ON DELETE SET NULL,
				provider           TEXT NOT NULL,
				model              TEXT NOT NULL,
				request_kind       TEXT NOT NULL,
				prompt_tokens      INTEGER NOT NULL,
				completion_tokens  INTEGER NOT NULL,
				estimated_cost_usd REAL NOT NULL,
				created_at         TEXT NOT NULL
			)`,
			`CREATE INDEX model_usage_scan_idx ON model_usage(scan_id)`,
		},
	},
	{
		version: 2,
		name:    "collector_reports_and_fingerprints",
		statements: []string{
			// Which collectors ran, failed, or were skipped is part of the
			// scan's meaning: without it a sparse inventory is
			// indistinguishable from a clean machine.
			`ALTER TABLE scans ADD COLUMN collectors TEXT NOT NULL DEFAULT '[]'`,
			// The metadata fingerprint is indexed so a later scan can detect
			// unchanged entries without decoding every stored document.
			`ALTER TABLE inventories ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''`,
			`CREATE INDEX inventories_fingerprint_idx ON inventories(fingerprint)`,
		},
	},
}

// SchemaVersion is the schema version this build expects.
func SchemaVersion() int { return migrations[len(migrations)-1].version }

// migrate applies every pending migration and returns the resulting version.
// Each step runs in its own transaction together with its bookkeeping row, so
// an interrupted upgrade never leaves a half-applied step recorded as done.
func (s *Store) migrate(ctx context.Context) (int, error) {
	current, err := s.userVersion(ctx)
	if err != nil {
		return 0, err
	}
	if current > SchemaVersion() {
		return 0, fmt.Errorf("store: database schema version %d is newer than this build supports (%d); upgrade workspace-janitor", current, SchemaVersion())
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return 0, err
		}
		current = m.version
	}
	return current, nil
}

func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration %d: %w", m.version, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, stmt := range m.statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: migration %d (%s): %w", m.version, m.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, formatTime(time.Now()),
	); err != nil {
		return fmt.Errorf("store: record migration %d: %w", m.version, err)
	}
	// PRAGMA does not accept bound parameters; the value is an int constant
	// from this file, never user input.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		return fmt.Errorf("store: set user_version %d: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migration %d: %w", m.version, err)
	}
	committed = true
	return nil
}

func (s *Store) userVersion(ctx context.Context) (int, error) {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("store: read user_version: %w", err)
	}
	return version, nil
}

func (t *Tx) schemaVersion(ctx context.Context) (int, error) {
	var version int
	if err := t.tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("store: read user_version: %w", err)
	}
	return version, nil
}

// AppliedMigration describes one recorded migration.
type AppliedMigration struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	AppliedAt time.Time `json:"applied_at"`
}

// AppliedMigrations lists the migrations recorded in the database.
func (t *Tx) AppliedMigrations(ctx context.Context) ([]AppliedMigration, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT version, name, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("store: list migrations: %w", err)
	}
	defer rows.Close()
	var out []AppliedMigration
	for rows.Next() {
		var (
			m  AppliedMigration
			at string
		)
		if err := rows.Scan(&m.Version, &m.Name, &at); err != nil {
			return nil, fmt.Errorf("store: scan migration row: %w", err)
		}
		if m.AppliedAt, err = parseTime(at); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list migrations: %w", err)
	}
	return out, nil
}
