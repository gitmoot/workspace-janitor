package cli

import (
	"context"
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type historyReport struct {
	DryRun      bool                       `json:"dry_run"`
	RecentLimit int                        `json:"recent_limit"`
	Eligible    store.ScanHistoryReduction `json:"eligible"`
	Note        string                     `json:"note"`
}

// runHistory previews by default. Confirmed trimming removes only old,
// unreferenced scan snapshots; it never compacts the SQLite file or deletes
// an audit record. Offline DB compaction is a separate operator procedure.
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
	report := historyReport{DryRun: !confirm, RecentLimit: store.RecentScanLimit,
		Note: "SQLite file bytes are not reclaimed until separately verified offline compaction"}
	if confirm {
		err = db.Write(ctx, func(tx *store.Tx) error {
			report.Eligible, err = tx.TrimScanHistory(ctx)
			return err
		})
	} else {
		err = db.Read(ctx, func(tx *store.Tx) error {
			report.Eligible, err = tx.ScanHistoryPreview(ctx)
			return err
		})
	}
	if err != nil {
		return err
	}
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "history", report)
	}
	_, err = fmt.Fprintf(e.stdout, "dry run: %t\nrecent scan limit: %d\neligible scans: %d\neligible inventory rows: %d\nsource document bytes: %d\n%s\n",
		report.DryRun, report.RecentLimit, report.Eligible.Scans, report.Eligible.Entries, report.Eligible.Documents, report.Note)
	return err
}
