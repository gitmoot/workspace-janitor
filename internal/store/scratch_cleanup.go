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

// scratchRunDocumentMaxBytes mirrors the scratch_runs document CHECK. A run
// receipt no longer grows with the entries it archived, so it stays far
// below this.
const scratchRunDocumentMaxBytes = 65536

// ScratchRun is the immutable receipt of one acting scratch cleanup run. It
// is recorded once the run's archive (if any) is published and verified, and
// before anything is deleted; its start time schedules the next run.
//
// The receipt pins the run's archive manifest by path and SHA-256. That
// manifest, durable and read back before the receipt is written, names every
// archived entry, so a run may archive more entries than one database row
// could list. Receipts recorded by earlier versions also list the names, in
// archived_entries; they decode with ArchivedCount set from that list.
type ScratchRun struct {
	RunID     string    `json:"run_id"`
	Path      string    `json:"path"`
	StartedAt time.Time `json:"started_at"`
	// The archive binding is empty when the run archived nothing.
	ArchiveDirectory      string `json:"archive_directory,omitempty"`
	ArchiveManifest       string `json:"archive_manifest,omitempty"`
	ArchiveManifestSHA256 string `json:"archive_manifest_sha256,omitempty"`
	// ArchivedCount is the number of entries the pinned manifest names.
	ArchivedCount int       `json:"archived_count,omitempty"`
	RecordedAt    time.Time `json:"recorded_at"`
	// Kind is empty for a full sweep and ScratchRunRegenerable for a pass
	// that only deletes regenerable entries. Each kind has its own cadence.
	Kind string `json:"kind,omitempty"`
}

// ScratchRunRegenerable marks a run that only deleted regenerable entries.
const ScratchRunRegenerable = "regenerable"

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
	if (r.ArchiveManifest == "") != (r.ArchiveManifestSHA256 == "") || (r.ArchiveManifest == "") != (r.ArchivedCount == 0) || r.ArchivedCount < 0 {
		return errors.New("store: a scratch run archive needs its manifest, checksum and entry count together")
	}
	if r.Kind != "" && r.Kind != ScratchRunRegenerable {
		return fmt.Errorf("store: unknown scratch run kind %q", r.Kind)
	}
	if r.Kind == ScratchRunRegenerable && r.ArchiveManifest != "" {
		return errors.New("store: a regenerable scratch run archives nothing")
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
	if err := r.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > scratchRunDocumentMaxBytes {
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

// LastScratchRun returns the start of the newest recorded run of path and
// kind ("" for full sweeps), or the zero time.
func (t *Tx) LastScratchRun(ctx context.Context, path, kind string) (time.Time, error) {
	var started sql.NullString
	if err := t.tx.QueryRowContext(ctx, `SELECT MAX(started_at) FROM scratch_runs
		WHERE path = ? AND COALESCE(json_extract(document, '$.kind'), '') = ?`, path, kind).Scan(&started); err != nil {
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
	// archived_entries is only present in receipts of earlier versions.
	var r struct {
		ScratchRun
		LegacyEntries []string `json:"archived_entries"`
	}
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return ScratchRun{}, false, fmt.Errorf("store: invalid scratch run receipt: %w", err)
	}
	if r.ArchivedCount == 0 {
		r.ArchivedCount = len(r.LegacyEntries)
	}
	return r.ScratchRun, true, r.ScratchRun.validate()
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

// readScratch runs fn on a read-only view of the database without creating,
// migrating or writing it. A missing database, or one from before scratch
// receipts existed, holds no scratch receipts: fn is not called and found is
// false. A newer schema is refused.
func readScratch(ctx context.Context, dbPath string, fn func(*Tx) error) (bool, error) {
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("store: stat %s: %w", dbPath, err)
	}
	db, err := sql.Open("sqlite", readOnlyDSN(dbPath))
	if err != nil {
		return false, fmt.Errorf("store: open %s read-only: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, path: dbPath, readOnly: true}
	defer s.Close()
	version, err := s.userVersion(ctx)
	if err != nil {
		return false, err
	}
	if version > SchemaVersion() {
		return false, fmt.Errorf("%w: database is at %d, this build expects %d", ErrSchemaMismatch, version, SchemaVersion())
	}
	if version < scratchCleanupVersion {
		return false, nil
	}
	return true, s.Read(ctx, fn)
}

// ReadLastScratchRun reads the newest run start of path read-only; see
// readScratch.
func ReadLastScratchRun(ctx context.Context, dbPath, path, kind string) (time.Time, error) {
	var last time.Time
	_, err := readScratch(ctx, dbPath, func(tx *Tx) error {
		var err error
		last, err = tx.LastScratchRun(ctx, path, kind)
		return err
	})
	return last, err
}

// ReadScratchRun reads one run receipt read-only; see readScratch.
func ReadScratchRun(ctx context.Context, dbPath, runID string) (ScratchRun, bool, error) {
	var (
		run   ScratchRun
		found bool
	)
	_, err := readScratch(ctx, dbPath, func(tx *Tx) error {
		var err error
		run, found, err = tx.ScratchRunByID(ctx, runID)
		return err
	})
	return run, found, err
}
