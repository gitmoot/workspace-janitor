package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// ErrCleanupStateMismatch reports a stale optimistic transition.
var ErrCleanupStateMismatch = errors.New("store: cleanup state mismatch")

const cleanupColumns = `cleanup_id, plan_id, action_id, source, destination, state,
	entry_json, action_json, quarantined_json, created_at, updated_at, moved_at, expires_at, reason`

// InsertCleanup journals a prepared item before its filesystem mutation. The
// insert trigger records the initial event in the very same SQLite statement.
func (t *Tx) InsertCleanup(ctx context.Context, item core.CleanupItem) error {
	item.Normalize()
	if err := item.ValidateInitial(); err != nil {
		return fmt.Errorf("store: invalid cleanup item: %w", err)
	}
	entry, action, err := cleanupSnapshots(item)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx,
		`INSERT INTO cleanup_items (`+cleanupColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, ?, ?)`,
		item.CleanupID, item.PlanID, item.ActionID, item.Source, item.Destination,
		item.State, entry, action, formatTime(item.CreatedAt), formatTime(item.UpdatedAt),
		nullableTime(item.ExpiresAt), item.Reason)
	if err != nil {
		return fmt.Errorf("store: insert cleanup %s/%s (duplicate ID or active source collision): %w", item.CleanupID, item.ActionID, err)
	}
	return nil
}

// UpdateCleanup performs an optimistic state transition. Immutable original
// evidence, paths and IDs may not be rewritten by a later caller. SQL's state
// predicate protects against stale writes, while a trigger journals only
// successful transitions in the same statement.
func (t *Tx) UpdateCleanup(ctx context.Context, item core.CleanupItem, expected core.CleanupState) error {
	item.Normalize()
	if err := item.Validate(); err != nil {
		return fmt.Errorf("store: invalid cleanup item: %w", err)
	}
	if !expected.CanTransitionTo(item.State) {
		return fmt.Errorf("store: invalid cleanup transition %q to %q", expected, item.State)
	}
	old, err := t.cleanupItem(ctx, item.CleanupID, item.ActionID)
	if err != nil {
		return err
	}
	if old.State != expected {
		return fmt.Errorf("%w: cleanup %s/%s is %q, expected %q", ErrCleanupStateMismatch, item.CleanupID, item.ActionID, old.State, expected)
	}
	if err := checkCleanupImmutable(old, item); err != nil {
		return fmt.Errorf("store: cleanup %s/%s: %w", item.CleanupID, item.ActionID, err)
	}
	if item.UpdatedAt.Before(old.UpdatedAt) {
		return fmt.Errorf("store: cleanup %s/%s: updated_at precedes previous transition", item.CleanupID, item.ActionID)
	}
	if old.Quarantined == nil && item.Quarantined != nil && item.State != core.CleanupQuarantined {
		return fmt.Errorf("store: cleanup %s/%s: quarantine evidence may only be set on entering quarantined state", item.CleanupID, item.ActionID)
	}
	entry, action, err := cleanupSnapshots(item)
	if err != nil {
		return err
	}
	var quarantined any
	if item.Quarantined != nil {
		data, err := core.MarshalJSON(item.Quarantined)
		if err != nil {
			return fmt.Errorf("store: marshal quarantine evidence: %w", err)
		}
		quarantined = string(data)
	}
	res, err := t.tx.ExecContext(ctx,
		`UPDATE cleanup_items SET state = ?, quarantined_json = ?, updated_at = ?, moved_at = ?, expires_at = ?, reason = ?
		 WHERE cleanup_id = ? AND action_id = ? AND state = ? AND entry_json = ? AND action_json = ?`,
		item.State, quarantined, formatTime(item.UpdatedAt), nullableTime(item.MovedAt),
		nullableTime(item.ExpiresAt), item.Reason, item.CleanupID, item.ActionID, expected,
		entry, action)
	if err != nil {
		return fmt.Errorf("store: update cleanup %s/%s: %w", item.CleanupID, item.ActionID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: cleanup rows affected: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("%w: cleanup %s/%s changed during transition", ErrCleanupStateMismatch, item.CleanupID, item.ActionID)
	}
	return nil
}

// CleanupItems lists all items for one cleanup. An empty cleanup ID lists all
// items, including terminal states, for retention and audit work.
func (t *Tx) CleanupItems(ctx context.Context, cleanupID string) ([]core.CleanupItem, error) {
	query := `SELECT ` + cleanupColumns + ` FROM cleanup_items`
	var args []any
	if cleanupID != "" {
		query += ` WHERE cleanup_id = ?`
		args = []any{cleanupID}
	}
	query += ` ORDER BY created_at, cleanup_id, action_id`
	return t.listCleanup(ctx, query, args...)
}

// PendingCleanupItems returns records needing recovery or retention review.
func (t *Tx) PendingCleanupItems(ctx context.Context) ([]core.CleanupItem, error) {
	return t.listCleanup(ctx,
		`SELECT `+cleanupColumns+` FROM cleanup_items
		 WHERE state IN ('prepared', 'quarantined', 'investigate')
		 ORDER BY updated_at, cleanup_id, action_id`)
}

func (t *Tx) listCleanup(ctx context.Context, query string, args ...any) ([]core.CleanupItem, error) {
	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list cleanup items: %w", err)
	}
	defer rows.Close()
	items := []core.CleanupItem{}
	for rows.Next() {
		item, err := scanCleanup(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list cleanup items: %w", err)
	}
	return items, nil
}

func (t *Tx) cleanupItem(ctx context.Context, cleanupID, actionID string) (core.CleanupItem, error) {
	row := t.tx.QueryRowContext(ctx,
		`SELECT `+cleanupColumns+` FROM cleanup_items WHERE cleanup_id = ? AND action_id = ?`, cleanupID, actionID)
	item, err := scanCleanup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return core.CleanupItem{}, fmt.Errorf("%w: cleanup %s/%s", ErrNotFound, cleanupID, actionID)
	}
	return item, err
}

// The scanner works for a single row and a list cursor alike.
type cleanupScanner interface{ Scan(...any) error }

func scanCleanup(row cleanupScanner) (core.CleanupItem, error) {
	var item core.CleanupItem
	var entry, action string
	var quarantined, moved, expires sql.NullString
	var created, updated string
	if err := row.Scan(&item.CleanupID, &item.PlanID, &item.ActionID, &item.Source,
		&item.Destination, &item.State, &entry, &action, &quarantined,
		&created, &updated, &moved, &expires, &item.Reason); err != nil {
		return core.CleanupItem{}, fmt.Errorf("store: scan cleanup item: %w", err)
	}
	if err := json.Unmarshal([]byte(entry), &item.Entry); err != nil {
		return core.CleanupItem{}, fmt.Errorf("store: decode cleanup entry: %w", err)
	}
	if err := json.Unmarshal([]byte(action), &item.Action); err != nil {
		return core.CleanupItem{}, fmt.Errorf("store: decode cleanup action: %w", err)
	}
	if quarantined.Valid {
		item.Quarantined = new(core.Entry)
		if err := json.Unmarshal([]byte(quarantined.String), item.Quarantined); err != nil {
			return core.CleanupItem{}, fmt.Errorf("store: decode quarantine evidence: %w", err)
		}
	}
	var err error
	if item.CreatedAt, err = parseTime(created); err != nil {
		return core.CleanupItem{}, err
	}
	if item.UpdatedAt, err = parseTime(updated); err != nil {
		return core.CleanupItem{}, err
	}
	if item.MovedAt, err = optionalCleanupTime(moved); err != nil {
		return core.CleanupItem{}, err
	}
	if item.ExpiresAt, err = optionalCleanupTime(expires); err != nil {
		return core.CleanupItem{}, err
	}
	if err := item.Validate(); err != nil {
		return core.CleanupItem{}, fmt.Errorf("store: stored cleanup %s/%s is invalid: %w", item.CleanupID, item.ActionID, err)
	}
	return item, nil
}

func optionalCleanupTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	at, err := parseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &at, nil
}

func cleanupSnapshots(item core.CleanupItem) (string, string, error) {
	entry, err := core.MarshalJSON(item.Entry)
	if err != nil {
		return "", "", fmt.Errorf("store: marshal cleanup entry: %w", err)
	}
	action, err := core.MarshalJSON(item.Action)
	if err != nil {
		return "", "", fmt.Errorf("store: marshal cleanup action: %w", err)
	}
	return string(entry), string(action), nil
}

func checkCleanupImmutable(old, next core.CleanupItem) error {
	if old.PlanID != next.PlanID || old.Source != next.Source || old.Destination != next.Destination || !old.CreatedAt.Equal(next.CreatedAt) {
		return errors.New("immutable cleanup identity or paths changed")
	}
	if old.MovedAt != nil && (next.MovedAt == nil || !old.MovedAt.Equal(*next.MovedAt)) {
		return errors.New("original move time changed")
	}
	if old.ExpiresAt != nil && (next.ExpiresAt == nil || !old.ExpiresAt.Equal(*next.ExpiresAt)) {
		return errors.New("original retention deadline changed")
	}
	oldEntry, oldAction, err := cleanupSnapshots(old)
	if err != nil {
		return err
	}
	entry, action, err := cleanupSnapshots(next)
	if err != nil {
		return err
	}
	if oldEntry != entry || oldAction != action {
		return errors.New("immutable entry or action snapshot changed")
	}
	if old.Quarantined != nil {
		if next.Quarantined == nil {
			return errors.New("quarantine evidence was removed")
		}
		before, err := core.MarshalJSON(old.Quarantined)
		if err != nil {
			return err
		}
		after, err := core.MarshalJSON(next.Quarantined)
		if err != nil {
			return err
		}
		if !bytes.Equal(before, after) {
			return errors.New("immutable quarantine evidence changed")
		}
	}
	return nil
}
