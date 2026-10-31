package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type recoveryAction struct {
	Owner       string      `json:"owner"`
	Approval    string      `json:"approval"`
	RebuildCost string      `json:"rebuild_cost"`
	Prune       pruneReport `json:"prune"`
	Error       string      `json:"error,omitempty"`
}

type recoveryReport struct {
	Stopped            string                 `json:"stopped"`
	ConsideredStores   int                    `json:"considered_stores"`
	AttemptedStores    int                    `json:"attempted_stores"`
	BudgetBytes        uint64                 `json:"budget_bytes"`
	BudgetChargedBytes uint64                 `json:"budget_charged_bytes"`
	Before             *core.CapacitySnapshot `json:"before"`
	After              *core.CapacitySnapshot `json:"after"`
	Actions            []recoveryAction       `json:"actions"`
	Skipped            []core.CapacitySkip    `json:"skipped"`
}

// runCapacityRecovery is called only while cycle holds the scan lock. It never
// invents delete candidates: existing rules, approvals, apply and fresh provider
// preflight remain the only mutation path. Whole-store upper bounds are charged,
// not provider estimates or same-filesystem quarantine bytes.
func runCapacityRecovery(ctx context.Context, e *env, paths config.Paths, policy config.Policy, scanID string, capacity *core.CapacitySnapshot) (*recoveryReport, *core.CapacitySnapshot, error) {
	if !policy.Prevention.Recovery.Enabled {
		return nil, capacity, nil
	}
	limits := policy.Prevention.Recovery
	report := &recoveryReport{Stopped: "no_safe_candidates", BudgetBytes: uint64(limits.MaxBytes), Actions: []recoveryAction{}, Skipped: []core.CapacitySkip{}}
	capacity, err := sampleCapacity(ctx, policy, paths, time.Now().UTC(), true)
	if err != nil {
		return report, capacity, err
	}
	report.Before, report.After = capacity, capacity
	if capacityRecovered(capacity) {
		report.Stopped = "target_recovered"
		return report, capacity, nil
	}
	bounded, cancel := context.WithTimeout(ctx, limits.TimeBudget.Duration())
	defer cancel()
	planEnv := *e
	opts := *e.opts
	opts.format = "json"
	planEnv.opts = &opts
	var out bytes.Buffer
	planEnv.stdout = &out
	if err := runPlan(bounded, &planEnv, nil, planOptions{scanID: scanID, noJev: true}); err != nil {
		return report, capacity, err
	}
	var built struct {
		Data planReport `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &built); err != nil {
		return report, capacity, err
	}
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return report, capacity, err
	}
	defer db.Close()
	var entries []core.Entry
	if err := db.Read(ctx, func(tx *store.Tx) error { var err error; entries, err = tx.Entries(ctx, scanID); return err }); err != nil {
		return report, capacity, err
	}
	byPath := make(map[string]*core.Entry, len(entries))
	for i := range entries {
		byPath[entries[i].Path] = &entries[i]
	}
	actions := make(map[string]*core.Action, len(built.Data.Plan.Actions))
	for i := range built.Data.Plan.Actions {
		a := &built.Data.Plan.Actions[i]
		actions[a.Path] = a
	}
	type candidate struct {
		rule   *config.CacheRule
		entry  *core.Entry
		action *core.Action
	}
	var candidates []candidate
	skip := func(rule *config.CacheRule, reason string) {
		owner := rule.Recovery.Owner
		if owner == "" {
			owner = "unknown"
		}
		report.Skipped = append(report.Skipped, core.CapacitySkip{Path: rule.Path, Owner: owner, Reason: reason})
	}
	for i := range policy.Caches {
		rule := &policy.Caches[i]
		entry, selected := byPath[rule.Path], actions[rule.Path]
		if rule.Recovery.Owner == "" {
			skip(rule, "no owner-approved recovery rule")
			continue
		}
		if entry == nil || selected == nil {
			skip(rule, "cache root was not inventoried and planned")
			continue
		}
		if selected.Kind != core.ActionDeleteCandidate {
			skip(rule, string(selected.Kind)+": "+strings.Join(selected.Reasons, "; "))
			continue
		}
		adapter, known := plan.DescribeAdapter(*entry, policy)
		if !known || (adapter.Provider != "uv" && adapter.Provider != "npm" && adapter.Provider != "go-build") {
			skip(rule, "no supported scoped official prune adapter")
			continue
		}
		if !entry.SizeIsDeep || entry.SizeIsLowerBound || entry.LatestModifiedAt.IsZero() {
			skip(rule, "complete recursive idle and size evidence is required")
			continue
		}
		if time.Since(entry.LatestModifiedAt) < rule.Recovery.MinIdle.Duration() {
			skip(rule, "store is too recently modified or its clock is ahead")
			continue
		}
		candidates = append(candidates, candidate{rule, entry, selected})
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i].entry, candidates[j].entry
		if a.LatestModifiedAt.Equal(b.LatestModifiedAt) {
			return a.Path < b.Path
		}
		return a.LatestModifiedAt.Before(b.LatestModifiedAt)
	})
	var runErr error
	for _, candidate := range candidates {
		rule, entry, selected := candidate.rule, candidate.entry, candidate.action
		if bounded.Err() != nil {
			report.Stopped = "time_budget"
			break
		}
		if report.ConsideredStores >= limits.MaxStores {
			report.Stopped = "store_budget"
			break
		}
		if report.BudgetChargedBytes >= report.BudgetBytes {
			report.Stopped = "byte_budget"
			break
		}
		var volume *core.CapacityState
		for i := range capacity.Volumes {
			if capacity.Volumes[i].Device == entry.FilesystemID.Device {
				volume = &capacity.Volumes[i]
				break
			}
		}
		if volume == nil || volume.AvailableBytes == nil {
			skip(rule, "filesystem pressure measurement is unknown or not configured")
			continue
		}
		measured, err := measureDisk(entry.Path)
		if err != nil || measured.Device != volume.Device {
			skip(rule, "fresh filesystem identity/availability could not be measured")
			continue
		}
		if measured.FreeBytes >= volume.RecoveryBytes {
			skip(rule, "filesystem recovery target already met")
			continue
		}
		report.ConsideredStores++
		estimate, err := action.EstimateReclaim(bounded, []core.Entry{*entry}, policy.Limits.DeepSizeMaxEntries)
		if err != nil || estimate.Bytes <= 0 || estimate.SharedInodes != 0 {
			skip(rule, "allocated-byte upper bound incomplete or shared; no prune authorized")
			continue
		}
		remaining := report.BudgetBytes - report.BudgetChargedBytes
		if uint64(rule.Recovery.MaxPruneBytes) < remaining {
			remaining = uint64(rule.Recovery.MaxPruneBytes)
		}
		if uint64(estimate.Bytes) > remaining {
			skip(rule, "whole store exceeds per-store or remaining byte budget")
			continue
		}
		var refusal string
		err = db.Write(ctx, func(tx *store.Tx) error {
			var err error
			refusal, err = tx.ClaimCacheRecovery(ctx, rule.Path, rule.Recovery.Approval, time.Now().UTC(), limits.Interval.Duration())
			return err
		})
		if err != nil {
			runErr = err
			report.Stopped = "attempt_journal_error"
			break
		}
		if refusal != "" {
			skip(rule, refusal)
			continue
		}
		report.AttemptedStores++
		result := recoveryAction{Owner: rule.Recovery.Owner, Approval: rule.Recovery.Approval, RebuildCost: rule.Recovery.RebuildCost}
		_, err = applyApprovals(bounded, db, built.Data.Plan, planOptions{approve: selected.ID, approver: "capacity:" + rule.Recovery.Owner, note: rule.Recovery.Approval}, nil)
		if err == nil {
			applyEnv := *e
			applyEnv.stdout = io.Discard
			err = runApply(bounded, &applyEnv, nil, applyOptions{planID: built.Data.Plan.ID, actionID: selected.ID, prune: true, confirm: true, pruneLimitBytes: uint64(estimate.Bytes), pruneResult: &result.Prune})
		}
		outcome := "refused"
		if result.Prune.Status == "completed" {
			outcome = "completed"
		} else if result.Prune.Status != "" && result.Prune.Status != "preview" {
			outcome = "failed"
		}
		if result.Prune.StoreBeforeBytes != nil && outcome != "refused" {
			report.BudgetChargedBytes += uint64(*result.Prune.StoreBeforeBytes)
		}
		finishErr := db.Write(ctx, func(tx *store.Tx) error {
			return tx.FinishCacheRecovery(ctx, rule.Path, rule.Recovery.Approval, outcome)
		})
		err = errors.Join(err, finishErr)
		if err == nil && result.Prune.MeasurementError != "" {
			err = fmt.Errorf("provider completed with uncertain measurements: %s", result.Prune.MeasurementError)
		}
		if err != nil {
			result.Error = err.Error()
		}
		report.Actions = append(report.Actions, result)
		capacity, runErr = sampleCapacity(ctx, policy, paths, time.Now().UTC(), true)
		report.After = capacity
		runErr = errors.Join(err, runErr)
		if runErr != nil {
			report.Stopped = "provider_or_measurement_failure"
			break
		}
		if capacityRecovered(capacity) {
			report.Stopped = "target_recovered"
			break
		}
	}
	if !capacityRecovered(capacity) {
		err := db.Write(ctx, func(tx *store.Tx) error {
			latest, err := tx.CapacitySnapshot(ctx)
			if err != nil {
				return err
			}
			if latest.PolicyHash != capacityPolicyHash(policy) {
				return errors.New("pressure policy changed during recovery")
			}
			latest = latest.Expire(time.Now().UTC())
			for i := range latest.Volumes {
				volume := &latest.Volumes[i]
				if volume.RecoveryBytes != volume.ReserveBytes && volume.State != core.PressureRecovered && volume.State != core.PressureUnknown {
					volume.State = core.PressureNoSafeReclaim
					volume.AdmissionHold = true
					volume.Reason = "bounded recovery stopped: " + report.Stopped + "; inspect skipped owners and approval limits"
				}
			}
			if err := tx.SaveCapacitySnapshot(ctx, latest); err != nil {
				return err
			}
			capacity = &latest
			return nil
		})
		runErr = errors.Join(runErr, err)
	}
	report.After = capacity
	return report, capacity, runErr
}

func capacityRecovered(snapshot *core.CapacitySnapshot) bool {
	if snapshot == nil || len(snapshot.Volumes) == 0 {
		return false
	}
	for _, volume := range snapshot.Volumes {
		if volume.State != core.PressureRecovered {
			return false
		}
	}
	return true
}
