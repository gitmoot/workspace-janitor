package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type cycleReport struct {
	ScanID           string                 `json:"scan_id"`
	Deep             bool                   `json:"deep"`
	Quarantine       string                 `json:"quarantine"`
	QuarantineReport string                 `json:"quarantine_report,omitempty"`
	Expiry           string                 `json:"expiry"`
	DiskAlerts       []diskAlert            `json:"disk_alerts"`
	ExpiryReport     string                 `json:"expiry_report,omitempty"`
	Capacity         *core.CapacitySnapshot `json:"capacity,omitempty"`
	Recovery         *recoveryReport        `json:"recovery,omitempty"`
	CategoryArchives *categoryArchiveReport `json:"category_archives,omitempty"`
	Inventory        *inventoryReport       `json:"inventory_report"`
}

// runCycle is the one-shot daily timer target. A deep scan subsumes that day's
// metadata scan; watcher scans never mutate and do not advance the deep clock.
func runCycle(ctx context.Context, e *env, args []string) error {
	if len(args) != 0 {
		return &usageError{msg: "cycle takes no arguments"}
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy()
	if err != nil {
		return err
	}
	if policy.Prevention.AutoExpire && !policy.Retention.DeleteEnabled {
		return errors.New("prevention.auto_expire requires retention.delete_enabled")
	}
	deep, err := deepScanDue(ctx, paths.DatabaseFile, policy.Prevention.DeepInterval.Duration(), time.Now().UTC())
	if err != nil {
		return err
	}
	deep = deep || policy.Prevention.Recovery.Enabled
	// Category archives are created before the scan, so the scan, plan and
	// quarantine below see their freshly recorded pins (local_retention none
	// proposes quarantine in this same cycle). Item failures do not stop the
	// cycle; they are reported and returned once the cycle has finished.
	var categories *categoryArchiveReport
	var categoryErr error
	if len(policy.WorkspaceArchiveCategories) != 0 {
		categories, categoryErr = cycleCategoryArchives(ctx, e, paths)
		if categoryErr != nil {
			categoryErr = fmt.Errorf("scheduled category archives: %w", categoryErr)
		}
		e.policy = nil
		if policy, err = e.loadPolicy(); err != nil {
			return errors.Join(categoryErr, err)
		}
	}
	// Hold the scan lock from this scan through the quarantine apply, so no
	// watcher scan lands between the plan and the apply's binding check.
	unlockScan, err := lockScan(ctx, paths.StateDir)
	if err != nil {
		return err
	}
	scanLocked := true
	releaseScan := func() {
		if scanLocked {
			scanLocked = false
			unlockScan()
		}
	}
	defer releaseScan()
	quiet := *e
	quiet.stdout = io.Discard
	var scanID string
	if err := runScan(ctx, &quiet, nil, scanOptions{deepSize: deep, noDeepSize: !deep, recordScanID: &scanID}); err != nil {
		return err
	}
	if deep {
		if err := recordCompletedDeepScan(ctx, paths.DatabaseFile, scanID); err != nil {
			return err
		}
	}
	capacity, err := sampleCapacity(ctx, policy, paths, time.Now().UTC(), false)
	if err != nil {
		return err
	}
	alerts, err := reportDiskPressure(ctx, policy, paths, scanID, time.Now().UTC())
	if err != nil {
		return err
	}
	report := cycleReport{ScanID: scanID, Deep: deep, Quarantine: "disabled", Expiry: "disabled", DiskAlerts: alerts}
	report.Capacity = capacity
	report.CategoryArchives = categories
	reportDB, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	err = reportDB.Read(ctx, func(tx *store.Tx) error {
		inventory, err := buildInventoryReport(ctx, tx, policy, time.Now().UTC())
		report.Inventory = &inventory
		return err
	})
	defer reportDB.Close()
	if err != nil {
		return err
	}
	recoveryStarted := time.Now().UTC()
	report.Recovery, report.Capacity, err = runCapacityRecovery(ctx, e, paths, policy, scanID, capacity)
	if report.Recovery != nil {
		err = errors.Join(err, recordRecoveryDecision(ctx, reportDB, report.Recovery, recoveryStarted, err))
		// Include the decision and any provider outcomes even when recovery
		// returns an error before the normal end-of-cycle refresh.
		refreshErr := reportDB.Read(ctx, func(tx *store.Tx) error {
			var err error
			report.Inventory.Activities, err = tx.CapacityActivities(ctx)
			return err
		})
		err = errors.Join(err, refreshErr)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("scheduled capacity recovery: %w", err), categoryErr, writeCycleReport(e.stdout, report))
	}
	var quarantineErr error
	if policy.Prevention.AutoQuarantine {
		report.Quarantine, report.QuarantineReport, quarantineErr = autoQuarantine(ctx, e, scanID)
	}
	// Expiry does not depend on the latest scan; the watcher may resume.
	releaseScan()
	if policy.Prevention.AutoExpire {
		// Reuse the interactive path and retain its item-level outcome.
		var expiryOutput bytes.Buffer
		applyEnv := *e
		applyEnv.stdout = &expiryOutput
		err := runApply(ctx, &applyEnv, nil, applyOptions{expire: true, confirm: true, dryRun: false})
		report.Expiry = "checked"
		report.ExpiryReport = strings.TrimSpace(expiryOutput.String())
		if err != nil {
			return errors.Join(quarantineErr, categoryErr, fmt.Errorf("scheduled expiry: %w; %s", err, report.ExpiryReport))
		}
	}
	if quarantineErr != nil {
		return errors.Join(quarantineErr, categoryErr)
	}
	if policy.Prevention.Recovery.Enabled && policy.Prevention.AutoExpire {
		report.Capacity, err = sampleCapacity(ctx, policy, paths, time.Now().UTC(), true)
		if err != nil {
			return errors.Join(err, writeCycleReport(e.stdout, report))
		}
		report.Recovery.After = report.Capacity
		if capacityRecovered(report.Capacity) {
			report.Recovery.Stopped = "target_recovered"
		}
	}
	// The daily advisory accepts only a cycle that completed its scan and
	// enabled post-scan actions. Watcher/standalone scans cannot trigger it.
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	err = db.Write(ctx, func(tx *store.Tx) error {
		return tx.RecordCompletedCycle(ctx, scanID, time.Now().UTC())
	})
	if err == nil {
		err = db.Read(ctx, func(tx *store.Tx) error {
			var err error
			report.Inventory.Activities, err = tx.CapacityActivities(ctx)
			return err
		})
	}
	closeErr := db.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if categoryErr != nil {
		return errors.Join(categoryErr, writeCycleReport(e.stdout, report))
	}
	return writeCycleReport(e.stdout, report)
}

func writeCycleReport(out io.Writer, report cycleReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

// autoQuarantine plans the cycle's scan from rules alone, approves the
// quarantine actions, and moves them. Apply still revalidates every target
// against a fresh observation before moving it, so anything that became
// referenced, dirty, or changed since the scan stays where it is.
func autoQuarantine(ctx context.Context, e *env, scanID string) (string, string, error) {
	planEnv := *e
	var planned bytes.Buffer
	planEnv.stdout = &planned
	opts := *e.opts
	opts.format = string(output.FormatJSON)
	planEnv.opts = &opts
	if err := runPlan(ctx, &planEnv, nil, planOptions{scanID: scanID, noJev: true, approveQuarantine: true,
		approver: "janitor cycle", note: "prevention.auto_quarantine"}); err != nil {
		return "failed", "", fmt.Errorf("scheduled quarantine plan: %w", err)
	}
	var result struct {
		Data planReport `json:"data"`
	}
	if err := json.Unmarshal(planned.Bytes(), &result); err != nil {
		return "failed", "", fmt.Errorf("scheduled quarantine plan output: %w", err)
	}
	var skipped string
	if len(result.Data.Skipped) > 0 {
		data, err := json.Marshal(result.Data.Skipped)
		if err != nil {
			return "failed", "", err
		}
		skipped = "skipped active receipts: " + string(data)
	}
	if len(result.Data.Approvals) == 0 {
		return "none", skipped, nil
	}
	var applied bytes.Buffer
	applyEnv := *e
	applyEnv.stdout = &applied
	err := runApply(ctx, &applyEnv, nil, applyOptions{planID: result.Data.Plan.ID, quarantine: true, confirm: true, dryRun: false})
	out := strings.TrimSpace(applied.String())
	if skipped != "" {
		out = skipped + "\n" + out
	}
	if err != nil {
		return "applied", out, fmt.Errorf("scheduled quarantine: %w; %s", err, out)
	}
	return "applied", out, nil
}

func deepScanDue(ctx context.Context, database string, interval time.Duration, now time.Time) (bool, error) {
	db, err := store.OpenExisting(ctx, database)
	if errors.Is(err, store.ErrNotInitialized) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer db.Close()
	var last time.Time
	err = db.Read(ctx, func(tx *store.Tx) error {
		var err error
		last, err = tx.LastDeepScan(ctx)
		return err
	})
	if err != nil {
		return false, err
	}
	return last.IsZero() || !last.Add(interval).After(now), nil
}

func recordCompletedDeepScan(ctx context.Context, database, scanID string) error {
	db, err := store.OpenExisting(ctx, database)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Write(ctx, func(tx *store.Tx) error {
		scan, err := tx.Scan(ctx, scanID)
		if err != nil {
			return err
		}
		if scan.FinishedAt == nil {
			return nil
		}
		for _, report := range scan.Collectors {
			if report.Name == collect.CollectorDeepSize && report.Status == core.CollectorRan {
				return tx.RecordDeepScan(ctx, *scan.FinishedAt)
			}
		}
		return nil
	})
}
