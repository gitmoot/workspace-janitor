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
	{
		version: 3,
		name:    "plan_bindings_and_approvals",
		statements: []string{
			// A plan is only meaningful against the evidence and policy it
			// was built from, so both digests are part of the record.
			`ALTER TABLE plans ADD COLUMN evidence_digest TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE plans ADD COLUMN policy_digest TEXT NOT NULL DEFAULT ''`,
			// The rationale is what makes an action reviewable: its class,
			// the rules that produced it, and the alternatives rejected.
			`ALTER TABLE actions ADD COLUMN class TEXT NOT NULL DEFAULT 'unknown'`,
			`ALTER TABLE actions ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE actions ADD COLUMN rules TEXT NOT NULL DEFAULT '[]'`,
			`ALTER TABLE actions ADD COLUMN rejected TEXT NOT NULL DEFAULT '[]'`,
			// Approvals live beside the plan: approving must never require
			// editing an immutable plan.
			`CREATE TABLE approvals (
				plan_id     TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
				action_id   TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
				approver    TEXT NOT NULL,
				approved_at TEXT NOT NULL,
				note        TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (plan_id, action_id)
			)`,
			`CREATE INDEX approvals_plan_idx ON approvals(plan_id)`,
		},
	},
	{
		version: 4,
		name:    "plan_advisor_and_model_decisions",
		statements: []string{
			// Which advisor shaped a plan is part of its identity.
			`ALTER TABLE plans ADD COLUMN advisor TEXT NOT NULL DEFAULT 'rules-only'`,
			// Model decisions are cached by everything that could change
			// the answer: the entry's metadata fingerprint, the question
			// schema, the model, and the policy. Any of them changing is a
			// cache miss, not a stale hit.
			`CREATE TABLE model_decisions (
				cache_key        TEXT PRIMARY KEY,
				fingerprint      TEXT NOT NULL,
				schema_version   INTEGER NOT NULL,
				model            TEXT NOT NULL,
				policy_digest    TEXT NOT NULL,
				resolved_model   TEXT NOT NULL,
				recommendation   TEXT NOT NULL,
				created_at       TEXT NOT NULL,
				expires_at       TEXT NOT NULL
			)`,
			`CREATE INDEX model_decisions_expiry_idx ON model_decisions(expires_at)`,
		},
	},
	{
		version: 5,
		name:    "durable_cleanup_journal",
		statements: []string{
			`CREATE TABLE cleanup_items (
				cleanup_id       TEXT NOT NULL,
				plan_id          TEXT NOT NULL,
				action_id        TEXT NOT NULL,
				source           TEXT NOT NULL,
				destination      TEXT NOT NULL,
				state            TEXT NOT NULL CHECK (state IN ('prepared', 'quarantined', 'restored', 'deleted', 'investigate')),
				entry_json       TEXT NOT NULL,
				action_json      TEXT NOT NULL,
				quarantined_json TEXT,
				created_at       TEXT NOT NULL,
				updated_at       TEXT NOT NULL,
				moved_at         TEXT,
				expires_at       TEXT,
				reason           TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (cleanup_id, action_id)
			)`,
			// Terminal records retain their history without claiming the
			// source path; active records must never race to move one source.
			`CREATE UNIQUE INDEX cleanup_items_active_source_idx ON cleanup_items(source)
			 WHERE state IN ('prepared', 'quarantined', 'investigate')`,
			`CREATE INDEX cleanup_items_cleanup_idx ON cleanup_items(cleanup_id, created_at, action_id)`,
			`CREATE INDEX cleanup_items_pending_idx ON cleanup_items(state, updated_at)`,
			`CREATE TABLE cleanup_events (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				cleanup_id  TEXT NOT NULL,
				action_id   TEXT NOT NULL,
				from_state  TEXT,
				to_state    TEXT NOT NULL,
				occurred_at TEXT NOT NULL,
				reason      TEXT NOT NULL,
				FOREIGN KEY (cleanup_id, action_id) REFERENCES cleanup_items(cleanup_id, action_id)
			)`,
			`CREATE INDEX cleanup_events_item_idx ON cleanup_events(cleanup_id, action_id, id)`,
			// Triggers make the item mutation and its event indivisible even
			// when a caller ignores an error before committing the outer Tx.
			`CREATE TRIGGER cleanup_items_insert_event AFTER INSERT ON cleanup_items
			 BEGIN
			   INSERT INTO cleanup_events (cleanup_id, action_id, from_state, to_state, occurred_at, reason)
			   VALUES (NEW.cleanup_id, NEW.action_id, NULL, NEW.state, NEW.updated_at, NEW.reason);
			 END`,
			`CREATE TRIGGER cleanup_items_transition_event AFTER UPDATE OF state ON cleanup_items
			 WHEN OLD.state != NEW.state
			 BEGIN
			   INSERT INTO cleanup_events (cleanup_id, action_id, from_state, to_state, occurred_at, reason)
			   VALUES (NEW.cleanup_id, NEW.action_id, OLD.state, NEW.state, NEW.updated_at, NEW.reason);
			 END`,
			`CREATE TRIGGER cleanup_events_no_update BEFORE UPDATE ON cleanup_events
			 BEGIN SELECT RAISE(ABORT, 'cleanup events are immutable'); END`,
			`CREATE TRIGGER cleanup_events_no_delete BEFORE DELETE ON cleanup_events
			 BEGIN SELECT RAISE(ABORT, 'cleanup events are immutable'); END`,
		},
	},
	{
		version: 6,
		name:    "prevention_state",
		statements: []string{
			`CREATE TABLE disk_alerts (
				filesystem_key  TEXT PRIMARY KEY,
				last_emitted_ns INTEGER NOT NULL,
				summary         TEXT NOT NULL
			)`,
			`CREATE TABLE prevention_state (
				key               TEXT PRIMARY KEY,
				last_completed_ns INTEGER NOT NULL
			)`,
		},
	},
	{
		version: 7,
		name:    "daily_advisory",
		statements: []string{
			`CREATE TABLE completed_cycles (
				day TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL REFERENCES scans(id),
				completed_at_ns INTEGER NOT NULL
			)`,
			`CREATE TABLE advisory_runs (
				day TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL REFERENCES scans(id),
				status TEXT NOT NULL,
				report TEXT NOT NULL,
				started_at_ns INTEGER NOT NULL,
				finished_at_ns INTEGER
			)`,
			`CREATE TABLE advisory_attempts (
				id INTEGER PRIMARY KEY,
				day TEXT NOT NULL REFERENCES advisory_runs(day),
				scan_id TEXT NOT NULL REFERENCES scans(id),
				entries INTEGER NOT NULL CHECK (entries > 0),
				estimated_tokens INTEGER NOT NULL CHECK (estimated_tokens > 0),
				estimated_cost_micro_usd INTEGER NOT NULL CHECK (estimated_cost_micro_usd > 0),
				reserved_at_ns INTEGER NOT NULL
			)`,
			`CREATE TRIGGER advisory_attempts_no_update BEFORE UPDATE ON advisory_attempts
			 BEGIN SELECT RAISE(ABORT, 'advisory attempts are immutable'); END`,
			`CREATE TRIGGER advisory_attempts_no_delete BEFORE DELETE ON advisory_attempts
			 BEGIN SELECT RAISE(ABORT, 'advisory attempts are immutable'); END`,
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
