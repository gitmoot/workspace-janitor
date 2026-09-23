package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func cleanupFixture(cleanupID, actionID, source string, at time.Time) core.CleanupItem {
	entry := fixtureEntry(source, at)
	destination := "/repos/.quarantine/" + actionID
	return core.CleanupItem{
		CleanupID:   cleanupID,
		PlanID:      "plan-1",
		ActionID:    actionID,
		Source:      source,
		Destination: destination,
		State:       core.CleanupPrepared,
		Entry:       entry,
		Action: core.Action{
			ID: actionID, PlanID: "plan-1", Path: source,
			Kind: core.ActionQuarantine, Class: entry.Class,
			Retention: core.Retention7Days, Status: core.ActionPending,
			FilesystemID: entry.FilesystemID, Destination: destination,
			CreatedAt: at,
		},
		CreatedAt: at,
		UpdatedAt: at,
		Reason:    "approved plan",
	}
}

func quarantineFixture(item core.CleanupItem, at time.Time) core.CleanupItem {
	item.State = core.CleanupQuarantined
	item.UpdatedAt = at
	item.MovedAt = &at
	expires := at.Add(7 * 24 * time.Hour)
	item.ExpiresAt = &expires
	snapshot := item.Entry
	snapshot.Path = item.Destination
	snapshot.Git = nil
	snapshot.Evidence = nil
	snapshot.Protections = nil
	snapshot.Recommendation = nil
	item.Quarantined = &snapshot
	item.Reason = "moved and inspected"
	return item
}

func TestCleanupJournalSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "janitor.db")
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	at := time.Date(2026, 9, 23, 11, 0, 0, 0, time.UTC)
	prepared := cleanupFixture("run-1", "action-1", "/repos/one", at)
	moved := cleanupFixture("run-1", "action-2", "/repos/two", at)
	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.InsertCleanup(ctx, prepared); err != nil {
			return err
		}
		if err := tx.InsertCleanup(ctx, moved); err != nil {
			return err
		}
		return tx.UpdateCleanup(ctx, quarantineFixture(moved, at.Add(time.Minute)), core.CleanupPrepared)
	}); err != nil {
		t.Fatalf("record cleanup: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := OpenExisting(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	var all, pending []core.CleanupItem
	if err := reopened.Read(ctx, func(tx *Tx) error {
		var err error
		all, err = tx.CleanupItems(ctx, "run-1")
		if err != nil {
			return err
		}
		pending, err = tx.PendingCleanupItems(ctx)
		return err
	}); err != nil {
		t.Fatalf("recover cleanup: %v", err)
	}
	want := []core.CleanupItem{prepared, quarantineFixture(moved, at.Add(time.Minute))}
	for i := range want {
		want[i].Normalize()
	}
	if !reflect.DeepEqual(all, want) {
		t.Errorf("recovered items changed:\n got: %#v\nwant: %#v", all, want)
	}
	if !reflect.DeepEqual(pending, want) {
		t.Errorf("pending after restart = %#v, want %#v", pending, want)
	}
	if all[1].Entry.Path != moved.Source || all[1].Action.Path != moved.Source || all[1].Quarantined.Path != moved.Destination {
		t.Error("recovery lost original action/entry or post-move evidence")
	}
	var synchronous int
	if err := reopened.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous mode: %v", err)
	}
	if synchronous != 2 { // SQLITE_SYNC_FULL
		t.Errorf("SQLite synchronous mode = %d, want FULL (2)", synchronous)
	}
}

func TestCleanupEventsAreAtomicAndImmutable(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 9, 23, 11, 0, 0, 0, time.UTC)
	item := cleanupFixture("run-1", "action-1", "/repos/one", at)
	if err := db.Write(ctx, func(tx *Tx) error {
		return tx.InsertCleanup(ctx, item)
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	moved := quarantineFixture(item, at.Add(time.Minute))
	if err := db.Write(ctx, func(tx *Tx) error {
		return tx.UpdateCleanup(ctx, moved, core.CleanupPrepared)
	}); err != nil {
		t.Fatalf("transition: %v", err)
	}
	investigate := moved
	investigate.State = core.CleanupInvestigate
	investigate.UpdatedAt = at.Add(2 * time.Minute)
	investigate.Reason = "destination inspection inconclusive"
	abort := errors.New("interrupt before commit")
	if err := db.Write(ctx, func(tx *Tx) error {
		if err := tx.UpdateCleanup(ctx, investigate, core.CleanupQuarantined); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatalf("rollback error = %v, want sentinel", err)
	}
	var states, from, reasons []string
	if err := db.Read(ctx, func(tx *Tx) error {
		rows, err := tx.tx.QueryContext(ctx,
			`SELECT COALESCE(from_state, ''), to_state, reason FROM cleanup_events ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var previous, state, reason string
			if err := rows.Scan(&previous, &state, &reason); err != nil {
				return err
			}
			from = append(from, previous)
			states = append(states, state)
			reasons = append(reasons, reason)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read events: %v", err)
	}
	if !reflect.DeepEqual(from, []string{"", "prepared"}) ||
		!reflect.DeepEqual(states, []string{"prepared", "quarantined"}) ||
		!reflect.DeepEqual(reasons, []string{"approved plan", "moved and inspected"}) {
		t.Errorf("events = %v -> %v (reasons %v)", from, states, reasons)
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		items, err := tx.CleanupItems(ctx, "run-1")
		if err != nil {
			return err
		}
		if len(items) != 1 || items[0].State != core.CleanupQuarantined {
			t.Errorf("rolled-back state = %#v", items)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after rollback: %v", err)
	}
	if err := db.Write(ctx, func(tx *Tx) error {
		_, err := tx.tx.ExecContext(ctx, `UPDATE cleanup_events SET reason = 'rewritten' WHERE id = 1`)
		return err
	}); err == nil {
		t.Fatal("cleanup event history allowed rewriting")
	}
}

func TestCleanupTransitionsFailClosed(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	at := time.Date(2026, 9, 23, 11, 0, 0, 0, time.UTC)
	item := cleanupFixture("run-1", "action-1", "/repos/one", at)
	if err := db.Write(ctx, func(tx *Tx) error { return tx.InsertCleanup(ctx, item) }); err != nil {
		t.Fatalf("insert: %v", err)
	}
	other := cleanupFixture("run-2", "action-2", item.Source, at)
	for name, attempted := range map[string]core.CleanupItem{
		"duplicate ID":            item,
		"active source collision": other,
	} {
		if err := db.Write(ctx, func(tx *Tx) error { return tx.InsertCleanup(ctx, attempted) }); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	moved := quarantineFixture(item, at.Add(time.Minute))
	cases := []struct {
		name     string
		item     core.CleanupItem
		expected core.CleanupState
		mismatch bool
	}{
		{"stale expected state", moved, core.CleanupInvestigate, true},
		{"invalid direct deletion", func() core.CleanupItem { next := moved; next.State = core.CleanupDeleted; return next }(), core.CleanupPrepared, false},
		{"original evidence changed", func() core.CleanupItem { next := moved; next.Entry.SizeBytes++; return next }(), core.CleanupPrepared, false},
		{"destination changed", func() core.CleanupItem { next := moved; next.Destination += "-wrong"; return next }(), core.CleanupPrepared, false},
		{"missing post-move evidence", func() core.CleanupItem { next := moved; next.Quarantined = nil; return next }(), core.CleanupPrepared, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := db.Write(ctx, func(tx *Tx) error { return tx.UpdateCleanup(ctx, tc.item, tc.expected) })
			if err == nil || tc.mismatch && !errors.Is(err, ErrCleanupStateMismatch) {
				t.Fatalf("UpdateCleanup error = %v", err)
			}
		})
	}
	missing := moved
	missing.CleanupID = "not-recorded"
	if err := db.Write(ctx, func(tx *Tx) error {
		return tx.UpdateCleanup(ctx, missing, core.CleanupPrepared)
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing cleanup error = %v, want ErrNotFound", err)
	}
	if err := db.Write(ctx, func(tx *Tx) error { return tx.UpdateCleanup(ctx, moved, core.CleanupPrepared) }); err != nil {
		t.Fatalf("valid move: %v", err)
	}
	tampered := moved
	tampered.State = core.CleanupInvestigate
	tampered.UpdatedAt = at.Add(2 * time.Minute)
	changedEvidence := *moved.Quarantined
	changedEvidence.SizeBytes++
	tampered.Quarantined = &changedEvidence
	if err := db.Write(ctx, func(tx *Tx) error {
		return tx.UpdateCleanup(ctx, tampered, core.CleanupQuarantined)
	}); err == nil {
		t.Fatal("post-move evidence was rewritten")
	}
	investigate := moved
	investigate.State = core.CleanupInvestigate
	investigate.UpdatedAt = at.Add(2 * time.Minute)
	if err := db.Write(ctx, func(tx *Tx) error { return tx.UpdateCleanup(ctx, investigate, core.CleanupQuarantined) }); err != nil {
		t.Fatalf("investigate: %v", err)
	}
	deleted := investigate
	deleted.State = core.CleanupDeleted
	deleted.UpdatedAt = at.Add(3 * time.Minute)
	if err := db.Write(ctx, func(tx *Tx) error { return tx.UpdateCleanup(ctx, deleted, core.CleanupInvestigate) }); err == nil || !strings.Contains(err.Error(), "invalid cleanup transition") {
		t.Fatalf("Investigate -> Deleted error = %v", err)
	}
	if err := db.Write(ctx, func(tx *Tx) error { return tx.UpdateCleanup(ctx, moved, core.CleanupPrepared) }); !errors.Is(err, ErrCleanupStateMismatch) {
		t.Fatalf("stale retry error = %v, want state mismatch", err)
	}
	var all []core.CleanupItem
	if err := db.Read(ctx, func(tx *Tx) error {
		var err error
		all, err = tx.CleanupItems(ctx, "")
		return err
	}); err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 1 || all[0].State != core.CleanupInvestigate {
		t.Errorf("failed transitions changed stored state: %#v", all)
	}
}
