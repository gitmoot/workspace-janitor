package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// Low-disk run outcomes.
const (
	lowDiskRan  = "ran"
	lowDiskBusy = "skipped_cycle_running"
)

// lowDiskReport is one low-disk trigger run: the standing cache trims (in
// the watch report's cache_trims) and the size-bounded cache rules.
type lowDiskReport struct {
	Path         string  `json:"path"`
	FreeBytes    uint64  `json:"free_bytes"`
	MinFreeBytes int64   `json:"min_free_bytes"`
	FreeAfter    *uint64 `json:"free_after_bytes,omitempty"`
	Status       string  `json:"status"`
	// CacheRules names the size-bounded cache rules the run applied.
	CacheRules       []string `json:"cache_rules,omitempty"`
	ScanID           string   `json:"scan_id,omitempty"`
	Quarantine       string   `json:"quarantine,omitempty"`
	QuarantineReport string   `json:"quarantine_report,omitempty"`
	Expiry           string   `json:"expiry,omitempty"`
	ExpiryReport     string   `json:"expiry_report,omitempty"`
	// Refusals are items a safety guard declined; they are not errors.
	Refusals []string `json:"refusals,omitempty"`
}

// lowDiskState is the trigger's persisted rate limit, so a restarted
// watcher does not run it again early.
type lowDiskState struct {
	LastRun time.Time `json:"last_run"`
}

const lowDiskStateFile = "low-disk.json"

// lowDiskLoop checks free space on prevention.low_disk.path every
// check_interval. Below min_free_bytes it runs the low-disk trims
// (runLowDisk) at most once per min_interval. A run skipped because a cycle
// or an apply holds its lock does not count; the next check retries it. A
// run's problems are reported and the loop goes on; a report that cannot be
// written ends it, as for cacheTrimLoop.
func lowDiskLoop(ctx context.Context, e *env, paths config.Paths, policy config.Policy) error {
	low := policy.Prevention.LowDisk
	timer := time.NewTimer(0)
	defer timer.Stop()
	statePath := filepath.Join(paths.StateDir, lowDiskStateFile)
	busyReported := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		timer.Reset(low.CheckInterval.Duration())
		volume, err := measureDisk(low.Path)
		if err != nil {
			if err := writeWatchReport(e, watchReport{Reason: "low_disk", Error: "measure " + low.Path + ": " + err.Error()}); err != nil {
				return fmt.Errorf("low-disk report: %w", err)
			}
			continue
		}
		if volume.FreeBytes >= uint64(low.MinFreeBytes) {
			busyReported = false
			continue
		}
		var state lowDiskState
		if err := readStateJSON(statePath, &state); err != nil {
			if err := writeWatchReport(e, watchReport{Reason: "low_disk", Error: err.Error()}); err != nil {
				return fmt.Errorf("low-disk report: %w", err)
			}
			continue
		}
		now := time.Now().UTC()
		if !state.LastRun.IsZero() && now.Before(state.LastRun.Add(low.MinInterval.Duration())) {
			continue
		}
		report, trims, runErr := runLowDisk(ctx, e, paths, policy, volume)
		if report.Status == lowDiskBusy {
			if busyReported {
				continue
			}
			busyReported = true
		} else {
			busyReported = false
			if after, err := measureDisk(low.Path); err == nil {
				report.FreeAfter = &after.FreeBytes
			}
			runErr = errors.Join(runErr, writeStateJSON(statePath, lowDiskState{LastRun: now}))
		}
		watch := watchReport{Reason: "low_disk", LowDisk: &report, CacheTrims: trims}
		if runErr != nil && ctx.Err() == nil {
			watch.Error = runErr.Error()
		}
		// Report before honouring cancellation: the run may have freed bytes.
		if err := writeWatchReport(e, watch); err != nil {
			return fmt.Errorf("low-disk report: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

// lowDiskTrims are the standing cache trims the low-disk trigger runs:
// every one but docker-images, which removes images, not a rebuildable
// cache.
func lowDiskTrims(policy config.Policy) []config.CacheTrim {
	var trims []config.CacheTrim
	for _, trim := range policy.Prevention.CacheTrims {
		if trim.Kind != config.CacheTrimDockerImages {
			trims = append(trims, trim)
		}
	}
	return trims
}

// lowDiskRules are the plan rules of the size-bounded cache rules.
func lowDiskRules(policy config.Policy) (names, rules []string) {
	for _, rule := range policy.Caches {
		if rule.SizeBounded() {
			names = append(names, rule.Name)
			rules = append(rules, "policy.cache:"+rule.Name)
		}
	}
	return names, rules
}

// runLowDisk runs, unless a cycle or an apply holds its lock, the low-disk
// trims, then the size-bounded cache rules exactly as the daily cycle runs
// them: a deep scan, a rules-only plan approving only those rules'
// quarantine actions (with prevention.auto_quarantine), the guarded
// quarantine apply, and (with prevention.auto_expire) the guarded expiry of
// the receipts that quarantine created. Every guard of those paths applies.
// It holds the scan lock from the scan through the quarantine, as the cycle
// does. Refused items are reported, not returned.
func runLowDisk(ctx context.Context, e *env, paths config.Paths, policy config.Policy, volume diskVolume) (lowDiskReport, []cacheTrimReport, error) {
	low := policy.Prevention.LowDisk
	report := lowDiskReport{Path: low.Path, FreeBytes: volume.FreeBytes, MinFreeBytes: low.MinFreeBytes, Status: lowDiskBusy}
	unlockScan, held, err := tryLockScan(paths.StateDir)
	if err != nil || !held {
		return report, nil, err
	}
	scanLocked := true
	releaseScan := func() {
		if scanLocked {
			scanLocked = false
			unlockScan()
		}
	}
	defer releaseScan()
	unlockApply, held, err := tryLockApply(paths.StateDir)
	if err != nil || !held {
		return report, nil, err
	}
	// Only a probe: apply takes the lock itself below.
	unlockApply()
	report.Status = lowDiskRan
	trims, trimErr := runCacheTrims(ctx, policy, lowDiskTrims(policy), paths.StateDir)
	names, rules := lowDiskRules(policy)
	if len(rules) == 0 || ctx.Err() != nil {
		return report, trims, trimErr
	}
	report.CacheRules = names
	if !policy.Prevention.AutoQuarantine {
		report.Quarantine = "disabled"
		return report, trims, trimErr
	}
	quiet, err := watchEnv(ctx, e, paths)
	if err != nil {
		return report, trims, errors.Join(trimErr, err)
	}
	if err := runScan(ctx, quiet, nil, scanOptions{deepSize: true, recordScanID: &report.ScanID}); err != nil {
		return report, trims, errors.Join(trimErr, fmt.Errorf("low-disk scan: %w", err))
	}
	var planID string
	report.Quarantine, report.QuarantineReport, planID, err = autoQuarantine(ctx, quiet, report.ScanID,
		planOptions{approver: "janitor low-disk", note: "prevention.low_disk", quarantineRules: rules})
	if items, ok := onlyRefusals(err); ok {
		report.Refusals, err = append(report.Refusals, items...), nil
	}
	releaseScan()
	if err != nil || report.Quarantine != "applied" {
		return report, trims, errors.Join(trimErr, err)
	}
	if !policy.Prevention.AutoExpire || !policy.Retention.DeleteEnabled {
		report.Expiry = "disabled"
		return report, trims, trimErr
	}
	cleanups, err := planCleanups(ctx, paths, planID)
	if err != nil {
		return report, trims, errors.Join(trimErr, err)
	}
	report.Expiry = "checked"
	var expiryOutputs []string
	var expiryErr error
	for _, cleanupID := range cleanups {
		var out strings.Builder
		applyEnv := *quiet
		applyEnv.stdout = &out
		err := runApply(ctx, &applyEnv, nil, applyOptions{expire: true, cleanupID: cleanupID, confirm: true, dryRun: false})
		expiryOutputs = append(expiryOutputs, strings.TrimSpace(out.String()))
		if items, ok := onlyRefusals(err); ok {
			report.Refusals = append(report.Refusals, items...)
		} else if err != nil {
			expiryErr = errors.Join(expiryErr, fmt.Errorf("low-disk expiry %s: %w", cleanupID, err))
		}
	}
	report.ExpiryReport = strings.Join(expiryOutputs, "\n")
	return report, trims, errors.Join(trimErr, expiryErr)
}

// planCleanups lists the cleanup batches holding a quarantined receipt of
// planID: the batches a low-disk quarantine created or resumed.
func planCleanups(ctx context.Context, paths config.Paths, planID string) ([]string, error) {
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var cleanups []string
	err = db.Read(ctx, func(tx *store.Tx) error {
		items, err := tx.PendingCleanupItems(ctx)
		seen := map[string]bool{}
		for _, item := range items {
			if item.PlanID == planID && item.State == core.CleanupQuarantined && !seen[item.CleanupID] {
				seen[item.CleanupID] = true
				cleanups = append(cleanups, item.CleanupID)
			}
		}
		return err
	})
	return cleanups, err
}

// watchEnv is e with its output discarded and, when the policy file has
// archive categories, the category archive pins read afresh: they live in
// Janitor's state and change between cycles, while the watcher reads the
// policy file once.
func watchEnv(ctx context.Context, e *env, paths config.Paths) (*env, error) {
	quiet := *e
	quiet.stdout = io.Discard
	if e.filePolicy != nil && e.filePolicy.HasArchiveCategories() {
		refreshed, err := withCategoryArchives(ctx, paths, *e.filePolicy)
		if err != nil {
			return nil, err
		}
		quiet.policy = &refreshed
	}
	return &quiet, nil
}

// readStateJSON decodes the state file at path into v; a missing file
// leaves v unchanged.
func readStateJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// writeStateJSON replaces the state file at path with v, atomically.
func writeStateJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := config.EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}
