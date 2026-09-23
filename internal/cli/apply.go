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
	planID, cleanupID                   string
	quarantine, expire, dryRun, confirm bool
}

type cleanupReport struct {
	ID     string             `json:"cleanup_id,omitempty"`
	Mode   string             `json:"mode"`
	DryRun bool               `json:"dry_run"`
	Items  []core.CleanupItem `json:"items"`
	Errors []string           `json:"errors"`
}

func cleanupEngine(e *env, db *store.Store, paths config.Paths, policy config.Policy) *action.Engine {
	return &action.Engine{
		DB: db, QuarantineDir: policy.Retention.QuarantineDir,
		Policy: enginePolicy(paths, policy),
		Collect: collect.Options{
			Limits: collectLimits(policy, scanOptions{}), Git: true, Processes: true, Services: true,
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
	if opts.quarantine == opts.expire {
		return &usageError{msg: "choose exactly one of --quarantine or --expire"}
	}
	if !opts.dryRun && !opts.confirm {
		return &usageError{msg: "--confirm is required with --dry-run=false"}
	}
	if opts.expire && opts.planID != "" || opts.quarantine && opts.cleanupID != "" {
		return &usageError{msg: "--plan applies only to quarantine; --cleanup only to expiry"}
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
		if approved[act.ID] && act.Kind.Mutating() {
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
	report := cleanupReport{Mode: "quarantine", DryRun: opts.dryRun, Items: []core.CleanupItem{}, Errors: []string{}}
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
	for _, item := range items {
		if item.State == core.CleanupInvestigate {
			report.Items = append(report.Items, item)
			continue
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
		report.Items = append(report.Items, item)
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

func writeCleanup(out io.Writer, format output.Format, report cleanupReport) error {
	if format == output.FormatJSON {
		return output.WriteJSON(out, report.Mode, report)
	}
	if _, err := fmt.Fprintf(out, "cleanup: %s\nmode: %s\ndry run: %t\n", report.ID, report.Mode, report.DryRun); err != nil {
		return err
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
	return nil
}
