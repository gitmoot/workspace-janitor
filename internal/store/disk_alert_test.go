package store

import (
	"context"
	"testing"
	"time"
)

func TestDiskAlertCooldownSurvivesTransactions(t *testing.T) {
	ctx := context.Background()
	db := openFixture(t)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	claim := func(at time.Time, summary string) bool {
		t.Helper()
		var admitted bool
		if err := db.Write(ctx, func(tx *Tx) error {
			var err error
			admitted, err = tx.ClaimDiskAlert(ctx, "device-17", summary, at, 24*time.Hour)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return admitted
	}
	if !claim(now, "first") || claim(now.Add(time.Hour), "changed") || !claim(now.Add(24*time.Hour), "later") {
		t.Fatal("alert was not deduplicated within the cooldown and re-admitted at its boundary")
	}
}
