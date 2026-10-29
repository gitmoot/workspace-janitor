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

// scratchCleanupVersion is the schema step that added the scratch receipts.
const scratchCleanupVersion = 13

// Scratch deletion dispositions.
const (
	ScratchArchived    = "archived"
	ScratchRegenerable = "regenerable"
)

// ScratchRun is the immutable receipt of one acting scratch cleanup run. It
// is recorded once the run's archive (if any) is published and verified, and
// before anything is deleted; its start time schedules the next run.
type ScratchRun struct {
	RunID     string    `json:"run_id"`
	Path      string    `json:"path"`
	StartedAt time.Time `json:"started_at"`
	// The archive binding is empty when the run archived nothing.
	ArchiveDirectory      string    `json:"archive_directory,omitempty"`
	ArchiveManifest       string    `json:"archive_manifest,omitempty"`
	ArchiveManifestSHA256 string    `json:"archive_manifest_sha256,omitempty"`
	ArchivedEntries       []string  `json:"archived_entries"`
	RecordedAt            time.Time `json:"recorded_at"`
}

// ScratchDeletion is the immutable receipt of one deleted scratch entry.
type ScratchDeletion struct {
	RunID       string `json:"run_id"`
	Path        string `json:"path"`
	Entry       string `json:"entry"`
	Disposition string `json:"disposition"`
	SizeBytes   int64  `json:"size_bytes"`
	// ArchiveManifest is set for archived entries.
	ArchiveManifest string    `json:"archive_manifest,omitempty"`
	DeletedAt       time.Time `json:"deleted_at"`
}

func (r ScratchRun) validate() error {
	if strings.TrimSpace(r.RunID) == "" || strings.TrimSpace(r.Path) == "" || r.StartedAt.IsZero() || r.RecordedAt.IsZero() {
		return errors.New("store: scratch run requires a run id, path and times")
	}
	if (r.ArchiveManifest == "") != (r.ArchiveManifestSHA256 == "") || (r.ArchiveManifest == "") != (len(r.ArchivedEntries) == 0) {
		return errors.New("store: a scratch run archive needs its manifest, checksum and entries together")
	}
	if r.ArchiveManifestSHA256 != "" && (len(r.ArchiveManifestSHA256) != 64 || strings.Trim(r.ArchiveManifestSHA256, "0123456789abcdef") != "") {
		return errors.New("store: scratch run manifest_sha256 must be a lowercase SHA-256")
	}
	return nil
}

func (d ScratchDeletion) validate() error {
	if strings.TrimSpace(d.RunID) == "" || strings.TrimSpace(d.Path) == "" || strings.TrimSpace(d.Entry) == "" || d.DeletedAt.IsZero() || d.SizeBytes < 0 {
		return errors.New("store: scratch deletion requires a run, path, entry, size and time")
	}
	switch d.Disposition {
	case ScratchArchived:
		if d.ArchiveManifest == "" {
			return errors.New("store: an archived scratch deletion names its archive")
		}
	case ScratchRegenerable:
		if d.ArchiveManifest != "" {
			return errors.New("store: a regenerable scratch deletion has no archive")
		}
	default:
		return fmt.Errorf("store: unknown scratch disposition %q", d.Disposition)
	}
	return nil
}

// RecordScratchRun appends one run receipt; a duplicate run id is refused.
func (t *Tx) RecordScratchRun(ctx context.Context, r ScratchRun) error {
	r.StartedAt, r.RecordedAt = r.StartedAt.UTC(), r.RecordedAt.UTC()
	if r.ArchivedEntries == nil {
		r.ArchivedEntries = []string{}
	}
	if err := r.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("store: scratch run receipt exceeds its size bound")
	}
	if _, err := t.tx.ExecContext(ctx, `INSERT INTO scratch_runs (run_id, path, started_at, document) VALUES (?, ?, ?, ?)`,
		r.RunID, r.Path, formatTime(r.StartedAt), string(data)); err != nil {
		return fmt.Errorf("store: record scratch run %s: %w", r.RunID, err)
	}
	return nil
}

// RecordScratchDeletion appends one deletion receipt of a recorded run.
func (t *Tx) RecordScratchDeletion(ctx context.Context, d ScratchDeletion) error {
	d.DeletedAt = d.DeletedAt.UTC()
	if err := d.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err := t.tx.ExecContext(ctx, `INSERT INTO scratch_deletions (run_id, entry, disposition, document) VALUES (?, ?, ?, ?)`,
		d.RunID, d.Entry, d.Disposition, string(data)); err != nil {
		return fmt.Errorf("store: record scratch deletion %s/%s: %w", d.RunID, d.Entry, err)
	}
	return nil
}

// LastScratchRun returns the start of the newest recorded run of path, or
// the zero time.
func (t *Tx) LastScratchRun(ctx context.Context, path string) (time.Time, error) {
	var started sql.NullString
	if err := t.tx.QueryRowContext(ctx, `SELECT MAX(started_at) FROM scratch_runs WHERE path = ?`, path).Scan(&started); err != nil {
		return time.Time{}, fmt.Errorf("store: last scratch run: %w", err)
	}
	if !started.Valid {
		return time.Time{}, nil
	}
	return parseTime(started.String)
}

// ScratchRunByID returns one recorded run.
func (t *Tx) ScratchRunByID(ctx context.Context, runID string) (ScratchRun, bool, error) {
	var data string
	err := t.tx.QueryRowContext(ctx, `SELECT document FROM scratch_runs WHERE run_id = ?`, runID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return ScratchRun{}, false, nil
	}
	if err != nil {
		return ScratchRun{}, false, fmt.Errorf("store: scratch run %s: %w", runID, err)
	}
	var r ScratchRun
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return ScratchRun{}, false, fmt.Errorf("store: invalid scratch run receipt: %w", err)
	}
	return r, true, r.validate()
}

// ScratchDeletions returns the deletion receipts of one run in order.
func (t *Tx) ScratchDeletions(ctx context.Context, runID string) ([]ScratchDeletion, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT document FROM scratch_deletions WHERE run_id = ? ORDER BY sequence`, runID)
	if err != nil {
		return nil, fmt.Errorf("store: list scratch deletions: %w", err)
	}
	defer rows.Close()
	out := []ScratchDeletion{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("store: scan scratch deletion: %w", err)
		}
		var d ScratchDeletion
		if err := json.Unmarshal([]byte(data), &d); err != nil {
			return nil, fmt.Errorf("store: invalid scratch deletion receipt: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ReadLastScratchRun reads the newest run start of path without creating,
// migrating or writing the database. A missing database, or one from before
// scratch receipts existed, has none. A newer schema is refused.
func ReadLastScratchRun(ctx context.Context, dbPath, path string) (time.Time, error) {
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("store: stat %s: %w", dbPath, err)
	}
	db, err := sql.Open("sqlite", readOnlyDSN(dbPath))
	if err != nil {
		return time.Time{}, fmt.Errorf("store: open %s read-only: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, path: dbPath, readOnly: true}
	defer s.Close()
	version, err := s.userVersion(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if version > SchemaVersion() {
		return time.Time{}, fmt.Errorf("%w: database is at %d, this build expects %d", ErrSchemaMismatch, version, SchemaVersion())
	}
	if version < scratchCleanupVersion {
		return time.Time{}, nil
	}
	var last time.Time
	err = s.Read(ctx, func(tx *Tx) error {
		var err error
		last, err = tx.LastScratchRun(ctx, path)
		return err
	})
	return last, err
}
