package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// categoryArchivesVersion is the schema step that added category_archives.
const categoryArchivesVersion = 11

// CategoryArchive is the immutable receipt of one archive Janitor created for
// an owner-approved archive category. It holds everything needed to rebuild
// the pinned workspace archive rule: the archive's rule hash binds Name, Path,
// Owner, Release and ArchiveDirectory, and the manifest is pinned by path and
// SHA-256. A later archive of the same path appends a new receipt; the newest
// receipt per path is the active one.
type CategoryArchive struct {
	Name             string    `json:"name"`
	Category         string    `json:"category"`
	Kind             string    `json:"kind"`
	Path             string    `json:"path"`
	Owner            string    `json:"owner"`
	Release          string    `json:"release"`
	RunID            string    `json:"run_id"`
	ArchiveDirectory string    `json:"archive_directory"`
	Manifest         string    `json:"manifest"`
	ManifestSHA256   string    `json:"manifest_sha256"`
	ContentBytes     int64     `json:"content_bytes"`
	Members          int       `json:"members"`
	CreatedAt        time.Time `json:"created_at"`
	RecordedAt       time.Time `json:"recorded_at"`
	// TreeModifiedAt is the newest modification time among the archived
	// members, root directory included: the same set and precision the deep
	// walk reports. Receipts recorded before it existed hold the zero time.
	TreeModifiedAt time.Time `json:"tree_modified_at"`
	// RestoredByOwner is derived, never stored: a quarantine of this path was
	// restored after the archive was created. The owner's undo withdraws the
	// receipt's expiry authority until the path changes and is archived anew.
	// Only a receipt whose move was recorded (moved_at) counts: a receipt that
	// never moved, whatever route it took to restored (a cancelled prepare, or
	// investigate after the source went away and came back), is not an undo,
	// so the item keeps its archive's expiry authority.
	RestoredByOwner bool `json:"-"`
	// Withdrawn is derived from category_archive_withdrawals: the archive was
	// restored from (for example after expiry), so it no longer authorizes
	// removing the local tree.
	Withdrawn bool `json:"-"`
}

// Unchanged reports whether a tree whose deep walk found newest as its latest
// modification still looks like this archive. It compares file timestamps
// with the archived files' timestamps, never with the wall-clock CreatedAt:
// the kernel stamps files from a coarse clock that can lag the wall clock, so
// an edit made just after archiving can carry an earlier timestamp than
// CreatedAt. An unknown newest (a partial walk) counts as unchanged; Bind
// still decides expiry by content. Older receipts fall back to CreatedAt.
func (a CategoryArchive) Unchanged(newest time.Time) bool {
	bound := a.TreeModifiedAt
	if bound.IsZero() {
		bound = a.CreatedAt
	}
	return newest.IsZero() || !newest.After(bound)
}

func (a CategoryArchive) validate() error {
	for _, value := range []struct{ name, value string }{
		{"name", a.Name}, {"category", a.Category}, {"kind", a.Kind}, {"path", a.Path}, {"owner", a.Owner},
		{"release", a.Release}, {"run_id", a.RunID}, {"archive_directory", a.ArchiveDirectory}, {"manifest", a.Manifest},
	} {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("store: category archive %s must not be empty", value.name)
		}
	}
	if len(a.ManifestSHA256) != 64 || strings.Trim(a.ManifestSHA256, "0123456789abcdef") != "" {
		return errors.New("store: category archive manifest_sha256 must be a lowercase SHA-256")
	}
	if a.CreatedAt.IsZero() || a.RecordedAt.IsZero() {
		return errors.New("store: category archive times must be set")
	}
	return nil
}

// RecordCategoryArchive appends one receipt. Receipts are never updated or
// deleted; a duplicate name is refused.
func (t *Tx) RecordCategoryArchive(ctx context.Context, a CategoryArchive) error {
	a.CreatedAt, a.RecordedAt = a.CreatedAt.UTC(), a.RecordedAt.UTC()
	if err := a.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("store: category archive receipt exceeds its size bound")
	}
	if _, err := t.tx.ExecContext(ctx, `INSERT INTO category_archives (name, path, document) VALUES (?, ?, ?)`, a.Name, a.Path, string(data)); err != nil {
		return fmt.Errorf("store: record category archive %s: %w", a.Name, err)
	}
	return nil
}

// WithdrawCategoryArchive appends an immutable withdrawal of one receipt's
// local expiry authority. It is recorded before an archive restore so the
// restored tree is never quarantined or expired again on that receipt; the
// path regains authority only through a new receipt.
func (t *Tx) WithdrawCategoryArchive(ctx context.Context, name, reason string, at time.Time) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(reason) == "" || at.IsZero() {
		return errors.New("store: category archive withdrawal requires a name, reason and time")
	}
	if _, err := t.tx.ExecContext(ctx, `INSERT INTO category_archive_withdrawals (name, reason, withdrawn_at) VALUES (?, ?, ?)`,
		name, reason, formatTime(at)); err != nil {
		return fmt.Errorf("store: withdraw category archive %s: %w", name, err)
	}
	return nil
}

// CategoryArchives returns the newest receipt of every archived path,
// ordered by path, with RestoredByOwner derived from cleanup receipts and
// Withdrawn from recorded withdrawals.
func (t *Tx) CategoryArchives(ctx context.Context) ([]CategoryArchive, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT document FROM category_archives AS c
		WHERE sequence = (SELECT MAX(sequence) FROM category_archives WHERE path = c.path)
		ORDER BY path`)
	if err != nil {
		return nil, fmt.Errorf("store: list category archives: %w", err)
	}
	defer rows.Close()
	out := []CategoryArchive{}
	index := map[string]int{}
	byName := map[string]int{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("store: scan category archive: %w", err)
		}
		var a CategoryArchive
		if err := json.Unmarshal([]byte(data), &a); err != nil {
			return nil, fmt.Errorf("store: invalid category archive receipt: %w", err)
		}
		if err := a.validate(); err != nil {
			return nil, err
		}
		index[a.Path] = len(out)
		byName[a.Name] = len(out)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list category archives: %w", err)
	}
	rows.Close()
	// finishMove sets moved_at exactly when a move is journaled, and restore
	// keeps it, so it is the evidence that the item actually left. A move
	// interrupted before its journal update is indistinguishable from one
	// that never happened; its undo is not counted (the archive is verified,
	// so a later quarantine loses nothing).
	restored, err := t.tx.QueryContext(ctx, `SELECT source, updated_at FROM cleanup_items
		WHERE state = 'restored' AND moved_at IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("store: list restored cleanup items: %w", err)
	}
	defer restored.Close()
	for restored.Next() {
		var source, updated string
		if err := restored.Scan(&source, &updated); err != nil {
			return nil, fmt.Errorf("store: scan restored cleanup item: %w", err)
		}
		i, ok := index[source]
		if !ok {
			continue
		}
		at, err := parseTime(updated)
		if err != nil {
			return nil, err
		}
		if at.After(out[i].CreatedAt) {
			out[i].RestoredByOwner = true
		}
	}
	if err := restored.Err(); err != nil {
		return nil, fmt.Errorf("store: list restored cleanup items: %w", err)
	}
	restored.Close()
	withdrawn, err := t.tx.QueryContext(ctx, `SELECT DISTINCT name FROM category_archive_withdrawals`)
	if err != nil {
		return nil, fmt.Errorf("store: list category archive withdrawals: %w", err)
	}
	defer withdrawn.Close()
	for withdrawn.Next() {
		var name string
		if err := withdrawn.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scan category archive withdrawal: %w", err)
		}
		if i, ok := byName[name]; ok {
			out[i].Withdrawn = true
		}
	}
	if err := withdrawn.Err(); err != nil {
		return nil, fmt.Errorf("store: list category archive withdrawals: %w", err)
	}
	return out, nil
}

// ReadCategoryArchives reads the active receipts without creating, migrating
// or writing the database. A missing database, or one from before category
// archives existed, holds no receipts. A newer schema is refused.
func ReadCategoryArchives(ctx context.Context, path string) ([]CategoryArchive, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []CategoryArchive{}, nil
		}
		return nil, fmt.Errorf("store: stat %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s read-only: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, path: path, readOnly: true}
	defer s.Close()
	version, err := s.userVersion(ctx)
	if err != nil {
		return nil, err
	}
	if version > SchemaVersion() {
		return nil, fmt.Errorf("%w: database is at %d, this build expects %d", ErrSchemaMismatch, version, SchemaVersion())
	}
	if version < categoryArchivesVersion {
		return []CategoryArchive{}, nil
	}
	var out []CategoryArchive
	err = s.Read(ctx, func(tx *Tx) error {
		var err error
		out, err = tx.CategoryArchives(ctx)
		return err
	})
	return out, err
}
