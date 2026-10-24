package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/plan"
)

type pruneReport struct {
	Mode                 string                 `json:"mode"`
	DryRun               bool                   `json:"dry_run"`
	PlanID               string                 `json:"plan_id"`
	ActionID             string                 `json:"action_id"`
	Path                 string                 `json:"path"`
	Provider             string                 `json:"provider"`
	Argv                 []string               `json:"argv"`
	Timeout              string                 `json:"timeout"`
	Status               string                 `json:"status"`
	Timestamp            time.Time              `json:"timestamp"`
	StoreBeforeBytes     *int64                 `json:"store_before_bytes,omitempty"`
	StoreAfterBytes      *int64                 `json:"store_after_bytes,omitempty"`
	AvailableBeforeBytes *uint64                `json:"available_before_bytes,omitempty"`
	AvailableAfterBytes  *uint64                `json:"available_after_bytes,omitempty"`
	AvailableChangeBytes *int64                 `json:"available_change_bytes,omitempty"`
	MeasurementError     string                 `json:"measurement_error,omitempty"`
	Attribution          string                 `json:"attribution,omitempty"`
	Activity             *core.CapacityActivity `json:"activity,omitempty"`
}

// runOfficialPrune is deliberately narrower than generic quarantine. Only a
// dedicated, exact-root, approved cache may be pruned. The official provider
// owns the internal cache layout; janitor never recursively deletes it.
func runOfficialPrune(ctx context.Context, e *env, format output.Format, stateDir string, policy config.Policy, engine *action.Engine, selected core.Action, entry core.Entry, opts applyOptions) error {
	if selected.Kind != core.ActionDeleteCandidate || selected.Path != entry.Path || entry.Kind != core.EntryKindDirectory || entry.Git != nil {
		return fmt.Errorf("official prune requires an approved cache directory, not a repository")
	}
	var rule *config.CacheRule
	for i := range policy.Caches {
		if policy.Caches[i].Path == selected.Path && policy.Caches[i].Dedicated && policy.Caches[i].Action == core.ActionDeleteCandidate {
			rule = &policy.Caches[i]
			break
		}
	}
	if rule == nil {
		return fmt.Errorf("%s has no exact dedicated cache rule", selected.Path)
	}
	adapter, known := plan.DescribeAdapter(entry, policy)
	if !known || len(adapter.OfficialCommand) == 0 || (adapter.Provider != "uv" && adapter.Provider != "npm" && adapter.Provider != "go-build") {
		return fmt.Errorf("%s has no supported offline official prune", selected.Path)
	}
	if filepath.Base(rule.OfficialBinary) != adapter.OfficialCommand[0] {
		return fmt.Errorf("official binary must be a configured %s executable", adapter.OfficialCommand[0])
	}
	info, err := os.Stat(rule.OfficialBinary)
	if err != nil {
		return fmt.Errorf("official binary: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("official binary %s is not executable", rule.OfficialBinary)
	}
	if observed, err := os.Lstat(entry.Path); err != nil || !observed.IsDir() {
		return fmt.Errorf("dedicated cache root is not a real directory: %s", entry.Path)
	}
	argv := append([]string(nil), adapter.OfficialCommand...)
	argv[0] = rule.OfficialBinary
	report := pruneReport{Mode: "official_prune", DryRun: opts.dryRun, PlanID: selected.PlanID,
		ActionID: selected.ID, Path: entry.Path, Provider: adapter.Provider, Argv: argv,
		Timeout: policy.Limits.CommandTimeout.String(), Status: "preview"}
	defer func() {
		if opts.pruneResult != nil {
			*opts.pruneResult = report
		}
	}()
	if opts.dryRun {
		return writePrune(e.stdout, format, report)
	}
	// stderr is emitted and checked before the irreversible command starts.
	if _, err := fmt.Fprintf(e.stderr, "official prune (irreversible): %q; timeout: %s\n", argv, report.Timeout); err != nil {
		return err
	}
	unlock, err := lockOfficialPrune(stateDir)
	if err != nil {
		return fmt.Errorf("official prune lock: %w", err)
	}
	defer unlock()
	if err := engine.PreflightOfficial(ctx, entry, selected); err != nil {
		return err
	}
	estimate, estimateErr := action.EstimateReclaim(ctx, []core.Entry{entry}, policy.Limits.DeepSizeMaxEntries)
	if opts.pruneLimitBytes > 0 {
		if estimateErr != nil {
			return fmt.Errorf("recovery budget measurement: %w", estimateErr)
		}
		if estimate.Bytes < 0 || estimate.SharedInodes != 0 || uint64(estimate.Bytes) > opts.pruneLimitBytes {
			return fmt.Errorf("cache exceeds remaining recovery budget or has shared inodes")
		}
	}
	if estimateErr == nil && estimate.SharedInodes == 0 && estimate.Bytes >= 0 {
		report.StoreBeforeBytes = &estimate.Bytes
	}
	// A missing cache root must not borrow its ancestor's sample to pass a
	// budgeted prune gate. Destinations that do not exist yet use a different
	// sampler; this pre-operation sample requires the exact cache path.
	monitor, err := startCapacityActivity(ctx, engine.DB, "official_prune", selected.ID, entry.Path, rule.Recovery.Owner, entry.Path, measureDisk)
	if err != nil {
		return fmt.Errorf("cannot record prune start: %w", err)
	}
	report.Activity = &monitor.activity
	if monitor.activity.AvailableBeforeBytes != nil && monitor.activity.Device != entry.FilesystemID.Device {
		monitor.activity.AvailableBeforeBytes = nil
		monitor.activity.MeasurementError = "cache filesystem identity changed"
	}
	if opts.pruneLimitBytes > 0 && monitor.activity.AvailableBeforeBytes == nil {
		return monitor.finish(ctx, fmt.Errorf("before-prune capacity measurement: %s", monitor.activity.MeasurementError))
	}
	report.AvailableBeforeBytes = monitor.activity.AvailableBeforeBytes
	monitor.activity.StoreBeforeBytes = report.StoreBeforeBytes
	report.Status, report.Timestamp = "starting", time.Now().UTC()
	if err := recordOfficialPrune(stateDir, report); err != nil {
		return monitor.finish(ctx, fmt.Errorf("cannot journal official prune: %w", err))
	}
	monitor.activity.Attempted = 1
	runErr := executeOfficialPrune(ctx, argv, policy.Limits.CommandTimeout.Duration())
	report.Timestamp = time.Now().UTC()
	afterEstimate, afterErr := action.EstimateReclaim(ctx, []core.Entry{entry}, policy.Limits.DeepSizeMaxEntries)
	if afterErr != nil || afterEstimate.SharedInodes != 0 || afterEstimate.Bytes < 0 {
		monitor.activity.MeasurementError = "post-prune store accounting is incomplete or shared"
	} else {
		report.StoreAfterBytes = &afterEstimate.Bytes
		monitor.activity.StoreAfterBytes = report.StoreAfterBytes
	}
	if runErr == nil {
		monitor.activity.Completed = 1
	}
	outcomeErr := monitor.finish(ctx, runErr)
	report.AvailableAfterBytes = monitor.activity.AvailableAfterBytes
	report.AvailableChangeBytes = monitor.activity.AvailableChangeBytes
	report.MeasurementError = monitor.activity.MeasurementError
	report.Attribution = monitor.activity.Attribution
	if runErr != nil {
		report.Status = "failed: " + runErr.Error()
	} else {
		report.Status = "completed"
	}
	if err := recordOfficialPrune(stateDir, report); err != nil {
		return fmt.Errorf("official command outcome uncertain; cannot journal result: %w", err)
	}
	if outcomeErr != nil {
		return outcomeErr
	}
	return writePrune(e.stdout, format, report)
}

func writePrune(out io.Writer, format output.Format, report pruneReport) error {
	if format == output.FormatJSON {
		return output.WriteJSON(out, report.Mode, report)
	}
	_, err := fmt.Fprintf(out, "mode: %s\nplan: %s\naction: %s\nprovider: %s\npath: %s\ncommand: %q\ntimeout: %s\nstatus: %s\n", report.Mode, report.PlanID, report.ActionID, report.Provider, report.Path, report.Argv, report.Timeout, report.Status)
	if err == nil && report.AvailableChangeBytes != nil {
		_, err = fmt.Fprintf(out, "available change: %d bytes (%s)\n", *report.AvailableChangeBytes, report.Attribution)
	}
	if err == nil && report.MeasurementError != "" {
		_, err = fmt.Fprintf(out, "measurement unknown: %s\n", report.MeasurementError)
	}
	return err
}

// executeOfficialPrune is platform-specific so Linux can terminate a whole
// subprocess group on timeout, not only the provider CLI's parent process.
