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

// reportRepliesVersion is the schema step that added report_replies.
const reportRepliesVersion = 12

// Stale report reply kinds.
const (
	ReportReplyRelease = "release"
	ReportReplyKeep    = "keep"
)

// ReportReply is the immutable record of one owner's reply to a stale
// workspace report entry. It snapshots the item as the reply saw it, so a
// later change of the item invalidates the reply instead of acting on content
// the owner never saw. The newest reply per path is the effective one.
type ReportReply struct {
	// Sequence is assigned by the database; it is not part of the document.
	Sequence int64  `json:"sequence,omitempty"`
	Path     string `json:"path"`
	Reply    string `json:"reply"`
	// Role is the replying role. Owner is the owner attribution of the entry
	// at reply time: the same role, or "unknown" when the coordinator replied.
	Role  string     `json:"role"`
	Owner string     `json:"owner"`
	Note  string     `json:"note,omitempty"`
	Until *time.Time `json:"until,omitempty"`
	// The item snapshot: newest modification anywhere in the tree, deep size
	// and filesystem identity.
	NewestModifiedAt time.Time `json:"newest_modified_at"`
	SizeBytes        int64     `json:"size_bytes"`
	SizeIsLowerBound bool      `json:"size_is_lower_bound,omitempty"`
	Device           uint64    `json:"device"`
	Inode            uint64    `json:"inode"`
	RecordedAt       time.Time `json:"recorded_at"`
}

func (r ReportReply) validate() error {
	for _, value := range []struct{ name, value string }{{"path", r.Path}, {"role", r.Role}, {"owner", r.Owner}} {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("store: report reply %s must not be empty", value.name)
		}
	}
	switch r.Reply {
	case ReportReplyRelease:
		if r.Until != nil {
			return errors.New("store: a release reply has no until date")
		}
	case ReportReplyKeep:
	default:
		return fmt.Errorf("store: report reply must be %s or %s, got %q", ReportReplyRelease, ReportReplyKeep, r.Reply)
	}
	if len(r.Note) > 1024 {
		return errors.New("store: report reply note exceeds 1024 bytes")
	}
	if r.NewestModifiedAt.IsZero() || r.RecordedAt.IsZero() {
		return errors.New("store: report reply snapshot and record times must be set")
	}
	return nil
}

// RecordReportReply appends one reply and returns its sequence. Replies are
// never updated or deleted.
func (t *Tx) RecordReportReply(ctx context.Context, r ReportReply) (int64, error) {
	r.Sequence = 0
	r.NewestModifiedAt, r.RecordedAt = r.NewestModifiedAt.UTC(), r.RecordedAt.UTC()
	if r.Until != nil {
		until := r.Until.UTC()
		r.Until = &until
	}
	if err := r.validate(); err != nil {
		return 0, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	if len(data) > 65536 {
		return 0, errors.New("store: report reply exceeds its size bound")
	}
	result, err := t.tx.ExecContext(ctx, `INSERT INTO report_replies (path, reply, document) VALUES (?, ?, ?)`, r.Path, r.Reply, string(data))
	if err != nil {
		return 0, fmt.Errorf("store: record report reply for %s: %w", r.Path, err)
	}
	return result.LastInsertId()
}

// ReportReplies returns the newest reply of every path, ordered by path.
func (t *Tx) ReportReplies(ctx context.Context) ([]ReportReply, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT sequence, document FROM report_replies AS r
		WHERE sequence = (SELECT MAX(sequence) FROM report_replies WHERE path = r.path)
		ORDER BY path`)
	if err != nil {
		return nil, fmt.Errorf("store: list report replies: %w", err)
	}
	defer rows.Close()
	out := []ReportReply{}
	for rows.Next() {
		var (
			sequence int64
			data     string
		)
		if err := rows.Scan(&sequence, &data); err != nil {
			return nil, fmt.Errorf("store: scan report reply: %w", err)
		}
		var r ReportReply
		if err := json.Unmarshal([]byte(data), &r); err != nil {
			return nil, fmt.Errorf("store: invalid report reply: %w", err)
		}
		if err := r.validate(); err != nil {
			return nil, err
		}
		r.Sequence = sequence
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list report replies: %w", err)
	}
	return out, nil
}

// ReadReportReplies reads the effective replies without creating, migrating
// or writing the database. A missing database, or one from before report
// replies existed, holds none. A newer schema is refused.
func ReadReportReplies(ctx context.Context, path string) ([]ReportReply, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []ReportReply{}, nil
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
	if version < reportRepliesVersion {
		return []ReportReply{}, nil
	}
	var out []ReportReply
	err = s.Read(ctx, func(tx *Tx) error {
		var err error
		out, err = tx.ReportReplies(ctx)
		return err
	})
	return out, err
}
