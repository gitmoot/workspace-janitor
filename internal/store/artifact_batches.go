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

// artifactBatchesVersion is the schema step that added the
// omp_session_artifacts batch receipts.
const artifactBatchesVersion = 15

// ArtifactBatch is the immutable receipt of one verified batch archive of an
// omp_session_artifacts category: the eligible files of one session folder,
// archived in one tar whose manifest is pinned by path and SHA-256. Its
// files are listed separately (ArtifactFile). CleanupID is the cleanup
// receipt id its quarantine uses, so `janitor restore <CleanupID>` restores
// the batch. Settled is derived: the batch's quarantine has run.
type ArtifactBatch struct {
	Name             string    `json:"name"`
	Category         string    `json:"category"`
	Root             string    `json:"root"`
	Session          string    `json:"session"`
	RunID            string    `json:"run_id"`
	CleanupID        string    `json:"cleanup_id"`
	ArchiveDirectory string    `json:"archive_directory"`
	Manifest         string    `json:"manifest"`
	ManifestSHA256   string    `json:"manifest_sha256"`
	Files            int       `json:"files"`
	ContentBytes     int64     `json:"content_bytes"`
	CreatedAt        time.Time `json:"created_at"`
	RecordedAt       time.Time `json:"recorded_at"`
	Settled          bool      `json:"-"`
}

// ArtifactFile is one archived file of a batch: its cleanup action id within
// the batch's cleanup receipt, path, and the size and mtime it was archived
// with.
type ArtifactFile struct {
	ActionID   string
	Path       string
	Size       int64
	ModifiedNS int64
}

// ArchivedArtifact is the newest batch record of one path. Pending means its
// batch has not been quarantined yet; Moved means its batch's quarantine
// journaled moving this file (whatever happened to it afterwards).
type ArchivedArtifact struct {
	Batch      string
	Size       int64
	ModifiedNS int64
	Pending    bool
	Moved      bool
}

// ArtifactSettlement is the outcome of one batch's quarantine: how many files
// moved, and why the others stayed in place (bounded).
type ArtifactSettlement struct {
	Moved int      `json:"moved"`
	Kept  int      `json:"kept"`
	Notes []string `json:"notes,omitempty"`
}

func (b ArtifactBatch) validate() error {
	for _, value := range []struct{ name, value string }{
		{"name", b.Name}, {"category", b.Category}, {"root", b.Root}, {"session", b.Session}, {"run_id", b.RunID},
		{"cleanup_id", b.CleanupID}, {"archive_directory", b.ArchiveDirectory}, {"manifest", b.Manifest},
	} {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("store: artifact batch %s must not be empty", value.name)
		}
	}
	if len(b.ManifestSHA256) != 64 || strings.Trim(b.ManifestSHA256, "0123456789abcdef") != "" {
		return errors.New("store: artifact batch manifest_sha256 must be a lowercase SHA-256")
	}
	if b.Files < 1 || b.ContentBytes < 0 {
		return errors.New("store: artifact batch must hold at least one file")
	}
	if b.CreatedAt.IsZero() || b.RecordedAt.IsZero() {
		return errors.New("store: artifact batch times must be set")
	}
	return nil
}

// RecordArtifactBatch appends one batch receipt and its files. Receipts are
// never updated or deleted; a duplicate name or cleanup id is refused.
func (t *Tx) RecordArtifactBatch(ctx context.Context, b ArtifactBatch, files []ArtifactFile) error {
	b.CreatedAt, b.RecordedAt = b.CreatedAt.UTC(), b.RecordedAt.UTC()
	if err := b.validate(); err != nil {
		return err
	}
	if len(files) != b.Files {
		return fmt.Errorf("store: artifact batch %s lists %d files, its receipt %d", b.Name, len(files), b.Files)
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if _, err := t.tx.ExecContext(ctx, `INSERT INTO artifact_batches (name, cleanup_id, session, document) VALUES (?, ?, ?, ?)`,
		b.Name, b.CleanupID, b.Session, string(data)); err != nil {
		return fmt.Errorf("store: record artifact batch %s: %w", b.Name, err)
	}
	for _, f := range files {
		if strings.TrimSpace(f.ActionID) == "" || !strings.HasPrefix(f.Path, b.Session+"/") {
			return fmt.Errorf("store: artifact batch %s file %q is invalid", b.Name, f.Path)
		}
		if _, err := t.tx.ExecContext(ctx, `INSERT INTO artifact_batch_files (batch, action_id, path, size, mtime_ns) VALUES (?, ?, ?, ?, ?)`,
			b.Name, f.ActionID, f.Path, f.Size, f.ModifiedNS); err != nil {
			return fmt.Errorf("store: record artifact batch %s file %s: %w", b.Name, f.Path, err)
		}
	}
	return nil
}

// SettleArtifactBatch records, once, that a batch's quarantine has run.
func (t *Tx) SettleArtifactBatch(ctx context.Context, name string, at time.Time, s ArtifactSettlement) error {
	if strings.TrimSpace(name) == "" || at.IsZero() {
		return errors.New("store: artifact batch settlement requires a name and time")
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := t.tx.ExecContext(ctx, `INSERT INTO artifact_batch_settlements (name, settled_at, document) VALUES (?, ?, ?)`,
		name, formatTime(at), string(data)); err != nil {
		return fmt.Errorf("store: settle artifact batch %s: %w", name, err)
	}
	return nil
}

// ArtifactBatches returns every batch receipt in recording order, with
// Settled derived from the settlements.
func (t *Tx) ArtifactBatches(ctx context.Context) ([]ArtifactBatch, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT b.document, s.name IS NOT NULL FROM artifact_batches AS b
		LEFT JOIN artifact_batch_settlements AS s ON s.name = b.name ORDER BY b.sequence`)
	if err != nil {
		return nil, fmt.Errorf("store: list artifact batches: %w", err)
	}
	defer rows.Close()
	out := []ArtifactBatch{}
	for rows.Next() {
		var data string
		var settled bool
		if err := rows.Scan(&data, &settled); err != nil {
			return nil, fmt.Errorf("store: scan artifact batch: %w", err)
		}
		var b ArtifactBatch
		if err := json.Unmarshal([]byte(data), &b); err != nil {
			return nil, fmt.Errorf("store: invalid artifact batch receipt: %w", err)
		}
		if err := b.validate(); err != nil {
			return nil, err
		}
		b.Settled = settled
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list artifact batches: %w", err)
	}
	return out, nil
}

// ArtifactBatchFiles lists one batch's files in action id order.
func (t *Tx) ArtifactBatchFiles(ctx context.Context, name string) ([]ArtifactFile, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT action_id, path, size, mtime_ns FROM artifact_batch_files WHERE batch = ? ORDER BY action_id`, name)
	if err != nil {
		return nil, fmt.Errorf("store: list artifact batch files: %w", err)
	}
	defer rows.Close()
	var out []ArtifactFile
	for rows.Next() {
		var f ArtifactFile
		if err := rows.Scan(&f.ActionID, &f.Path, &f.Size, &f.ModifiedNS); err != nil {
			return nil, fmt.Errorf("store: scan artifact batch file: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list artifact batch files: %w", err)
	}
	return out, nil
}

// ArchivedArtifacts returns the newest batch record of every archived path.
// Moved counts only a journaled move (moved_at), so a quarantine that was
// refused before its rename is not an archived-away file.
func (t *Tx) ArchivedArtifacts(ctx context.Context) (map[string]ArchivedArtifact, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT f.path, f.batch, f.size, f.mtime_ns,
		NOT EXISTS (SELECT 1 FROM artifact_batch_settlements AS s WHERE s.name = f.batch),
		EXISTS (SELECT 1 FROM cleanup_items AS c WHERE c.cleanup_id = b.cleanup_id AND c.action_id = f.action_id AND c.moved_at IS NOT NULL)
		FROM artifact_batch_files AS f JOIN artifact_batches AS b ON b.name = f.batch
		ORDER BY b.sequence`)
	if err != nil {
		return nil, fmt.Errorf("store: list archived artifacts: %w", err)
	}
	defer rows.Close()
	out := map[string]ArchivedArtifact{}
	for rows.Next() {
		var path string
		var a ArchivedArtifact
		if err := rows.Scan(&path, &a.Batch, &a.Size, &a.ModifiedNS, &a.Pending, &a.Moved); err != nil {
			return nil, fmt.Errorf("store: scan archived artifact: %w", err)
		}
		out[path] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list archived artifacts: %w", err)
	}
	return out, nil
}

// ReadArchivedArtifacts is ArchivedArtifacts without creating, migrating or
// writing the database. A missing database, or one from before artifact
// batches existed, holds none. A newer schema is refused.
func ReadArchivedArtifacts(ctx context.Context, path string) (map[string]ArchivedArtifact, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]ArchivedArtifact{}, nil
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
	if version < artifactBatchesVersion {
		return map[string]ArchivedArtifact{}, nil
	}
	var out map[string]ArchivedArtifact
	err = s.Read(ctx, func(tx *Tx) error {
		var err error
		out, err = tx.ArchivedArtifacts(ctx)
		return err
	})
	return out, err
}
