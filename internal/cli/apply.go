package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/google/uuid"
)

type applyOptions struct {
	planID, cleanupID, actionID                string
	quarantine, expire, prune, dryRun, confirm bool
}

type officialCommandHint struct {
	Path    string   `json:"path"`
	Argv    []string `json:"argv"`
	Timeout string   `json:"timeout"`
	Note    string   `json:"note"`
}

type cleanupReport struct {
	ID            string                  `json:"cleanup_id,omitempty"`
	Mode          string                  `json:"mode"`
	DryRun        bool                    `json:"dry_run"`
	Items         []core.CleanupItem      `json:"items"`
	Official      []officialCommandHint   `json:"official_commands,omitempty"`
	Estimate      *action.ReclaimEstimate `json:"expected_reclaim,omitempty"`
	EstimateError string                  `json:"estimate_unavailable,omitempty"`
	Errors        []string                `json:"errors"`
}

func cleanupEngine(e *env, db *store.Store, paths config.Paths, policy config.Policy) *action.Engine {
	return &action.Engine{
		DB: db, QuarantineDir: policy.Retention.QuarantineDir,
		Policy: enginePolicy(paths, policy),
		Collect: collect.Options{
			Limits: collectLimits(policy, scanOptions{}), Git: true, Processes: true, Services: true,
			GitmootHome: policy.Gitmoot.Home, GitmootDatabase: policy.Gitmoot.Database,
			ProcRoot: policy.Collectors.ProcRoot, ProjectMarkers: policy.Classification.ProjectMarkers,
			ServiceSources: collect.ServiceSources{
				SystemdDirs: policy.Collectors.SystemdDirs, CronPaths: policy.Collectors.CronPaths, PM2Dumps: policy.Collectors.PM2Dumps,
			}, AgentSources: e.agentSources,
		},
	}
}

func runApply(ctx context.Context, e *env, args []string, opts applyOptions) error {
	if len(args) != 0 {
		return &usageError{msg: "apply takes no arguments"}
	}
	modes := 0
	for _, selected := range []bool{opts.quarantine, opts.expire, opts.prune} {
		if selected {
			modes++
		}
	}
	if modes != 1 {
		return &usageError{msg: "choose exactly one of --quarantine, --expire or --prune"}
	}
	if !opts.dryRun && !opts.confirm {
		return &usageError{msg: "--confirm is required with --dry-run=false"}
	}
	if opts.prune && opts.actionID == "" {
		return &usageError{msg: "--prune requires --action"}
	}
	if opts.expire && (opts.planID != "" || opts.actionID != "") {
		return &usageError{msg: "--plan and --action do not apply to expiry"}
	}
	if !opts.expire && opts.cleanupID != "" {
		return &usageError{msg: "--cleanup applies only to expiry"}
	}
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy()
	if err != nil {
		return err
	}
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	engine := cleanupEngine(e, db, paths, policy)
	if opts.expire {
		return runExpiry(ctx, e.stdout, format, engine, policy, opts)
	}

	var stored core.Plan
	var entries []core.Entry
	var approvals []core.Approval
	err = db.Read(ctx, func(tx *store.Tx) error {
		var err error
		if opts.planID == "" {
			stored, err = tx.LatestPlan(ctx, "")
		} else {
			stored, err = tx.Plan(ctx, opts.planID)
		}
		if err != nil {
			return err
		}
		current, err := tx.LatestScan(ctx, core.ScanCompleted)
		if err != nil {
			return err
		}
		entries, err = tx.Entries(ctx, current.ID)
		if err != nil {
			return err
		}
		if err = plan.VerifyBinding(stored, current.ID, entries, policy); err != nil {
			return err
		}
		approvals, err = tx.Approvals(ctx, stored.ID)
		return err
	})
	if err != nil {
		return err
	}
	approved := make(map[string]bool, len(approvals))
	for _, approval := range approvals {
		approved[approval.ActionID] = true
	}
	byPath := make(map[string]core.Entry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	selected := make([]core.Action, 0)
	for _, act := range stored.Actions {
		if opts.actionID != "" && act.ID != opts.actionID {
			continue
		}
		if approved[act.ID] && act.Kind.Mutating() {
			if act.Kind == core.ActionRelocate {
				return fmt.Errorf("approved relocate action %s targets %s; --quarantine cannot honor a relocation destination", act.ID, act.Destination)
			}
			if act.Kind != core.ActionQuarantine && act.Kind != core.ActionDeleteCandidate {
				return fmt.Errorf("unsupported approved action %s: %s", act.ID, act.Kind)
			}
			selected = append(selected, act)
		}
	}
	if len(selected) == 0 {
		return errors.New("no approved mutating actions in stored plan")
	}
	for i, a := range selected {
		if _, ok := byPath[a.Path]; !ok {
			return fmt.Errorf("approved action %s has no current inventory entry", a.ID)
		}
		for _, b := range selected[i+1:] {
			if pathContains(a.Path, b.Path) || pathContains(b.Path, a.Path) {
				return fmt.Errorf("approved actions overlap: %s and %s", a.Path, b.Path)
			}
		}
	}
	if opts.prune {
		if len(selected) != 1 {
			return fmt.Errorf("official prune requires one approved cache action")
		}
		return runOfficialPrune(ctx, e, format, paths.StateDir, policy, engine, selected[0], byPath[selected[0].Path], opts)
	}
	report := cleanupReport{Mode: "quarantine", DryRun: opts.dryRun, Items: []core.CleanupItem{}, Errors: []string{}}
	for _, selectedAction := range selected {
		if adapter, ok := plan.DescribeAdapter(byPath[selectedAction.Path], policy); ok && len(adapter.OfficialCommand) > 0 {
			report.Official = append(report.Official, officialCommandHint{
				Path: selectedAction.Path, Argv: adapter.OfficialCommand,
				Timeout: policy.Limits.CommandTimeout.String(),
				Note:    "advisory only; never executed by janitor; run only for an exclusively owned, idle cache under an external timeout",
			})
		}
	}
	prior, err := engine.Items(ctx, "")
	if err != nil {
		return err
	}
	byAction := make(map[string]core.CleanupItem)
	for _, item := range prior {
		if item.PlanID != stored.ID || item.State == core.CleanupRestored || item.State == core.CleanupDeleted {
			continue
		}
		if report.ID != "" && item.CleanupID != report.ID {
			return errors.New("plan has multiple active cleanup batches; investigate before continuing")
		}
		report.ID = item.CleanupID
		byAction[item.ActionID] = item
	}
	if report.ID == "" {
		report.ID = "cleanup-" + uuid.NewString()
	}
	for _, a := range selected {
		item, exists := byAction[a.ID]
		if !exists {
			item = core.CleanupItem{CleanupID: report.ID, PlanID: stored.ID, ActionID: a.ID, Source: a.Path, Entry: byPath[a.Path], Action: a,
				Destination: filepath.Join(policy.Retention.QuarantineDir, report.ID, a.ID, "item"), State: core.CleanupPrepared}
		}
		if opts.dryRun {
			report.Items = append(report.Items, item)
			continue
		}
		if !exists {
			item, err = engine.Prepare(ctx, item)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", a.Path, err))
				continue
			}
		}
		item, err = engine.Reconcile(ctx, item)
		if err == nil && item.State == core.CleanupPrepared {
			item, err = engine.Quarantine(ctx, item)
		}
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", a.Path, err))
		}
		report.Items = append(report.Items, item)
	}
	if opts.dryRun {
		candidates := make([]core.Entry, 0, len(report.Items))
		for _, item := range report.Items {
			if item.State == core.CleanupPrepared {
				candidates = append(candidates, item.Entry)
			}
		}
		addReclaimEstimate(ctx, &report, candidates, policy.Limits.DeepSizeMaxEntries)
	}
	if err := writeCleanup(e.stdout, format, report); err != nil {
		return err
	}
	if len(report.Errors) != 0 {
		return fmt.Errorf("%d cleanup action(s) need investigation", len(report.Errors))
	}
	return nil
}

func runRestore(ctx context.Context, e *env, args []string, confirm bool) error {
	if len(args) != 1 || !strings.HasPrefix(args[0], "cleanup-") {
		return &usageError{msg: "restore requires one cleanup id"}
	}
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy()
	if err != nil {
		return err
	}
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	engine := cleanupEngine(e, db, paths, policy)
	items, err := engine.Items(ctx, args[0])
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("no receipt %s", args[0])
	}
	report := cleanupReport{ID: args[0], Mode: "restore", DryRun: !confirm, Items: []core.CleanupItem{}, Errors: []string{}}
	for _, item := range items {
		if confirm && (item.State == core.CleanupQuarantined || item.State == core.CleanupPrepared || item.State == core.CleanupInvestigate) {
			item, err = engine.Restore(ctx, item)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", item.Source, err))
			}
		}
		report.Items = append(report.Items, item)
	}
	if err := writeCleanup(e.stdout, format, report); err != nil {
		return err
	}
	if len(report.Errors) != 0 {
		return fmt.Errorf("%d restore action(s) refused", len(report.Errors))
	}
	return nil
}

func runExpiry(ctx context.Context, out io.Writer, format output.Format, engine *action.Engine, policy config.Policy, opts applyOptions) error {
	if !opts.dryRun && !policy.Retention.DeleteEnabled {
		return errors.New("deletion is disabled by policy; set retention.delete_enabled and confirm in a separate expiry invocation")
	}
	items, err := engine.Items(ctx, opts.cleanupID)
	if err != nil {
		return err
	}
	if opts.cleanupID != "" && len(items) == 0 {
		return fmt.Errorf("no receipt %s", opts.cleanupID)
	}
	report := cleanupReport{ID: opts.cleanupID, Mode: "expiry", DryRun: opts.dryRun, Items: []core.CleanupItem{}, Errors: []string{}}
	eligible := make([]core.Entry, 0)
	for _, item := range items {
		if item.State == core.CleanupInvestigate {
			if opts.dryRun {
				probe := item
				probe.State = core.CleanupQuarantined
				err = engine.Eligible(ctx, probe)
				if err != nil {
					report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", item.Source, err))
				}
				report.Items = append(report.Items, item)
				continue
			}
			item, err = engine.Reconcile(ctx, item)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", item.Source, err))
				report.Items = append(report.Items, item)
				continue
			}
		}
		if item.State != core.CleanupQuarantined {
			continue
		}
		if item.MovedAt == nil || !item.Action.Retention.Expired(*item.MovedAt, time.Now().UTC()) {
			report.Items = append(report.Items, item)
			continue
		}
		if opts.dryRun {
			err = engine.Eligible(ctx, item)
		} else {
			item, err = engine.Delete(ctx, item)
		}
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", item.Source, err))
		}
		if opts.dryRun && err == nil {
			entry := item.Entry
			entry.Path = item.Destination
			eligible = append(eligible, entry)
		}
		report.Items = append(report.Items, item)
	}
	if opts.dryRun {
		addReclaimEstimate(ctx, &report, eligible, policy.Limits.DeepSizeMaxEntries)
	}
	if err := writeCleanup(out, format, report); err != nil {
		return err
	}
	if len(report.Errors) != 0 {
		return fmt.Errorf("%d expired item(s) refused revalidation", len(report.Errors))
	}
	return nil
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func addReclaimEstimate(ctx context.Context, report *cleanupReport, entries []core.Entry, limit int) {
	if len(entries) == 0 {
		return
	}
	estimate, err := action.EstimateReclaim(ctx, entries, limit)
	if err != nil {
		report.EstimateError = err.Error()
		return
	}
	report.Estimate = &estimate
}

func writeCleanup(out io.Writer, format output.Format, report cleanupReport) error {
	if format == output.FormatJSON {
		return output.WriteJSON(out, report.Mode, report)
	}
	if _, err := fmt.Fprintf(out, "cleanup: %s\nmode: %s\ndry run: %t\n", report.ID, report.Mode, report.DryRun); err != nil {
		return err
	}
	for _, hint := range report.Official {
		if _, err := fmt.Fprintf(out, "  official maintenance (not executed): %q; max runtime if run: %s; %s\n", hint.Argv, hint.Timeout, hint.Note); err != nil {
			return err
		}
	}
	for _, item := range report.Items {
		if _, err := fmt.Fprintf(out, "  %s %s -> %s (%s)\n", item.ActionID, item.Source, item.Destination, item.State); err != nil {
			return err
		}
	}
	for _, reason := range report.Errors {
		if _, err := fmt.Fprintf(out, "  refused: %s\n", reason); err != nil {
			return err
		}
	}
	if report.Estimate != nil {
		if _, err := fmt.Fprintf(out, "  expected reclaim after deletion: %d allocated byte(s) (%d externally hardlinked inode(s) excluded; conditional on safety revalidation)\n", report.Estimate.Bytes, report.Estimate.SharedInodes); err != nil {
			return err
		}
	} else if report.EstimateError != "" {
		if _, err := fmt.Fprintf(out, "  reclaim estimate unavailable: %s\n", report.EstimateError); err != nil {
			return err
		}
	}
	return nil
}
