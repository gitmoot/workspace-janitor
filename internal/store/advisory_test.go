package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func seedAdvisory(t *testing.T, db *Store, now time.Time) (string, string) {
	t.Helper()
	ctx := context.Background()
	day, scanID := advisoryDay(now), "scan-advice"
	err := db.Write(ctx, func(tx *Tx) error {
		scan := fixtureScan(scanID, now.Add(-time.Minute))
		if err := tx.CreateScan(ctx, scan); err != nil {
			return err
		}
		scan.Status = core.ScanCompleted
		scan.FinishedAt = &now
		if err := tx.UpdateScan(ctx, scan); err != nil {
			return err
		}
		if err := tx.RecordCompletedCycle(ctx, scanID, now); err != nil {
			return err
		}
		return tx.ClaimAdvisory(ctx, day, scanID, `{"status":"running"}`, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	return day, scanID
}

func TestAdvisoryBudgetReservesAttemptsEntriesTokensAndCost(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name                                 string
		firstEntries, firstTokens, firstCost int64
		laterEntries, laterTokens, laterCost int64
		firstCount                           int
	}{
		{"attempts", 1, 100, 1, 1, 100, 1, 7},
		{"entries", 140, 100, 1, 1, 100, 1, 1},
		{"tokens", 1, 100000, 1, 1, 1, 1, 1},
		{"cost", 1, 100, 10000, 1, 100, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openFixture(t)
			day, scanID := seedAdvisory(t, db, now)
			ctx := context.Background()
			for range tc.firstCount {
				if err := db.Write(ctx, func(tx *Tx) error {
					return tx.ReserveAdvisoryAttempt(ctx, day, scanID, tc.firstEntries, tc.firstTokens, tc.firstCost, now)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Write(ctx, func(tx *Tx) error {
				return tx.ReserveAdvisoryAttempt(ctx, day, scanID, tc.laterEntries, tc.laterTokens, tc.laterCost, now)
			}); !errors.Is(err, ErrAdvisoryBudget) {
				t.Fatalf("extra reservation = %v, want budget refusal", err)
			}
			if err := db.Write(ctx, func(tx *Tx) error {
				return tx.ReserveAdvisoryAttempt(ctx, day, scanID, 1, 1, 1, now.Add(24*time.Hour))
			}); !errors.Is(err, ErrAdvisoryBudget) {
				t.Fatalf("UTC-day rollover = %v, want refusal", err)
			}
			var budget AdvisoryBudget
			if err := db.Read(ctx, func(tx *Tx) error { var err error; budget, err = tx.AdvisoryBudget(ctx, day); return err }); err != nil {
				t.Fatal(err)
			}
			if budget.Attempts != int64(tc.firstCount) {
				t.Fatalf("failed attempt refunded: %+v", budget)
			}
		})
	}
}

func TestAdvisoryClaimIsSingleAcrossStoresAndInterruptedRuns(t *testing.T) {
	now := time.Now().UTC()
	db := openFixture(t)
	day, scanID := seedAdvisory(t, db, now)
	other, err := Open(context.Background(), db.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, handle := range []*Store{db, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- handle.Write(ctx, func(tx *Tx) error { return tx.ClaimAdvisory(ctx, day, scanID, `{}`, now) })
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, ErrAdvisoryAlreadyRun) {
			t.Fatalf("replayed claim = %v", err)
		}
	}
	// A running report after a crash remains reviewable. Reservations and
	// the claim must not disappear on a new process/connection.
	var record AdvisoryRecord
	if err := other.Read(ctx, func(tx *Tx) error { var err error; record, err = tx.Advisory(ctx, day); return err }); err != nil {
		t.Fatal(err)
	}
	if record.Status != "running" || record.ScanID != scanID {
		t.Fatalf("interrupted run lost: %+v", record)
	}
}
