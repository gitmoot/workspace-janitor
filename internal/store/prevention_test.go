package store

import (
	"context"
	"testing"
	"time"
)

func TestDeepScanClockCannotMoveBackward(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	completed := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{completed, completed.Add(-time.Hour)} {
		if err := db.Write(ctx, func(tx *Tx) error { return tx.RecordDeepScan(ctx, at) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Read(ctx, func(tx *Tx) error {
		last, err := tx.LastDeepScan(ctx)
		if err != nil {
			return err
		}
		if !last.Equal(completed) {
			t.Fatalf("older concurrent scan moved cadence backward: got %s want %s", last, completed)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
