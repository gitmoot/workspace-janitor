package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type historyReport struct {
	DryRun     bool                       `json:"dry_run"`
	KeepRecent int                        `json:"keep_recent"`
	KeepDays   int                        `json:"keep_days"`
	Eligible   store.ScanHistoryReduction `json:"eligible"`
	Note       string                     `json:"note"`
	Inventory  *inventoryReport           `json:"inventory_report"`
}

func historyRetention(policy config.Policy) store.HistoryRetention {
	return store.HistoryRetention{KeepRecent: policy.Prevention.History.KeepRecent, KeepDays: policy.Prevention.History.KeepDays}
}

// runHistory previews by default. Confirmed trimming removes only unpinned
// scan history beyond prevention.history; it never deletes an audit record
// or cleanup receipt. The next cycle reclaims the freed file space.
func runHistory(ctx context.Context, e *env, args []string, confirm bool) error {
	if len(args) != 0 {
		return &usageError{msg: "history takes no arguments"}
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	format, err := e.format()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy(ctx)
	if err != nil {
		return err
	}
	var db *store.Store
	if confirm {
		db, err = store.OpenExisting(ctx, paths.DatabaseFile)
	} else {
		db, err = store.OpenReadOnly(ctx, paths.DatabaseFile)
	}
	if err != nil {
		return err
	}
	defer db.Close()
	retention := historyRetention(policy)
	report := historyReport{DryRun: !confirm, KeepRecent: retention.KeepRecent, KeepDays: retention.KeepDays,
		Note: "freed SQLite pages are reclaimed by the next cycle's guarded VACUUM"}
	now := time.Now().UTC()
	if confirm {
		report.Eligible, err = db.TrimHistory(ctx, retention, now)
	} else {
		err = db.Read(ctx, func(tx *store.Tx) error {
			report.Eligible, err = tx.ScanHistoryPreview(ctx, retention, now)
			return err
		})
	}
	if err != nil {
		return err
	}
	if err := db.Read(ctx, func(tx *store.Tx) error {
		inventory, err := buildInventoryReport(ctx, tx, policy, time.Now().UTC())
		report.Inventory = &inventory
		return err
	}); err != nil {
		return err
	}
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "history", report)
	}
	_, err = fmt.Fprintf(e.stdout, "dry run: %t\nkeep recent scans: %d\nkeep daily scans for days: %d\neligible scans: %d\nreleased audited scans: %d\neligible plans: %d\neligible inventory rows: %d\nsource document bytes: %d\n%s\n",
		report.DryRun, report.KeepRecent, report.KeepDays, report.Eligible.Scans, report.Eligible.Released,
		report.Eligible.Plans, report.Eligible.Entries, report.Eligible.Documents, report.Note)
	if err == nil {
		err = output.WriteFields(e.stdout, appendInventoryFields(nil, report.Inventory))
	}
	return err
}

// historyMaintenance reports the cycle's history trim and space reclaim.
type historyMaintenance struct {
	Trimmed store.ScanHistoryReduction `json:"trimmed"`
	Space   *store.SpaceReclaim        `json:"space,omitempty"`
}

// maintainHistory drains the scan history the retention bounds no longer keep
// and then, when free pages and free disk space allow it, vacuums the
// database file. It runs only in the cycle: the rewrite holds SQLite's write
// lock for its duration. It holds the scan lock meanwhile so watcher scans
// wait for it rather than time out on the write lock; other writers wait up
// to the store's write-lock bound. safety.min_free_bytes is the headroom the
// vacuum must leave on the database's filesystem.
//
// The vacuum also holds the apply lock. A confirmed quarantine, restore or
// archive moves files before it journals the move; if a long vacuum held the
// write lock past that journal write's wait, the file would be moved under a
// receipt left prepared. A mutation already holding the lock skips the
// vacuum until the next cycle instead. The cycle calls this after every
// apply it runs has returned, so it never holds the apply lock itself here.
func maintainHistory(ctx context.Context, db *store.Store, paths config.Paths, policy config.Policy) (*historyMaintenance, error) {
	unlock, err := lockScan(ctx, paths.StateDir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	out := &historyMaintenance{}
	if out.Trimmed, err = db.TrimHistory(ctx, historyRetention(policy), time.Now().UTC()); err != nil {
		return out, err
	}
	volume, err := measureDisk(filepath.Dir(paths.DatabaseFile))
	if err != nil {
		// An unmeasured filesystem never risks a rewrite.
		out.Space = &store.SpaceReclaim{Skipped: "free space unmeasured: " + err.Error()}
		return out, nil
	}
	unlockApply, held, err := tryLockApply(paths.StateDir)
	if err != nil {
		return out, err
	}
	if !held {
		out.Space = &store.SpaceReclaim{Skipped: "apply lock held by a confirmed filesystem mutation; retried next cycle"}
		return out, nil
	}
	defer unlockApply()
	space, err := db.ReclaimSpace(ctx, volume.FreeBytes, uint64(policy.Safety.MinFreeBytes))
	out.Space = &space
	return out, err
}
