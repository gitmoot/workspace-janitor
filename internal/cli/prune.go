package cli

import (
	"context"
	"fmt"
	"io"
	"math"
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
	Mode                 string    `json:"mode"`
	DryRun               bool      `json:"dry_run"`
	PlanID               string    `json:"plan_id"`
	ActionID             string    `json:"action_id"`
	Path                 string    `json:"path"`
	Provider             string    `json:"provider"`
	Argv                 []string  `json:"argv"`
	Timeout              string    `json:"timeout"`
	Status               string    `json:"status"`
	Timestamp            time.Time `json:"timestamp"`
	StoreBeforeBytes     *int64    `json:"store_before_bytes,omitempty"`
	StoreAfterBytes      *int64    `json:"store_after_bytes,omitempty"`
	AvailableBeforeBytes *uint64   `json:"available_before_bytes,omitempty"`
	AvailableAfterBytes  *uint64   `json:"available_after_bytes,omitempty"`
	AvailableChangeBytes *int64    `json:"available_change_bytes,omitempty"`
	MeasurementError     string    `json:"measurement_error,omitempty"`
	Attribution          string    `json:"attribution,omitempty"`
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
	if opts.pruneLimitBytes > 0 {
		estimate, err := action.EstimateReclaim(ctx, []core.Entry{entry}, policy.Limits.DeepSizeMaxEntries)
		if err != nil {
			return fmt.Errorf("recovery budget measurement: %w", err)
		}
		if estimate.Bytes < 0 || estimate.SharedInodes != 0 || uint64(estimate.Bytes) > opts.pruneLimitBytes {
			return fmt.Errorf("cache exceeds remaining recovery budget or has shared inodes")
		}
		report.StoreBeforeBytes = &estimate.Bytes
	}
	before, measureErr := measureDisk(entry.Path)
	if measureErr == nil && before.Device != entry.FilesystemID.Device {
		measureErr = fmt.Errorf("cache filesystem identity changed")
	}
	if measureErr != nil {
		if opts.pruneLimitBytes > 0 {
			return fmt.Errorf("before-prune capacity measurement: %w", measureErr)
		}
		report.MeasurementError = measureErr.Error()
	} else {
		report.AvailableBeforeBytes = &before.FreeBytes
	}
	report.Status, report.Timestamp = "starting", time.Now().UTC()
	if err := recordOfficialPrune(stateDir, report); err != nil {
		return fmt.Errorf("cannot journal official prune: %w", err)
	}
	runErr := executeOfficialPrune(ctx, argv, policy.Limits.CommandTimeout.Duration())
	report.Timestamp = time.Now().UTC()
	after, measureErr := measureDisk(entry.Path)
	if measureErr != nil {
		report.MeasurementError = measureErr.Error()
	} else if report.AvailableBeforeBytes != nil && after.Device == before.Device {
		report.AvailableAfterBytes = &after.FreeBytes
		if before.FreeBytes <= math.MaxInt64 && after.FreeBytes <= math.MaxInt64 {
			change := int64(after.FreeBytes) - int64(before.FreeBytes)
			report.AvailableChangeBytes = &change
		}
		report.Attribution = "net filesystem change; concurrent writers may contribute"
	} else {
		report.MeasurementError = "before/after filesystem observations are not comparable"
	}
	if opts.pruneLimitBytes > 0 {
		estimate, err := action.EstimateReclaim(ctx, []core.Entry{entry}, policy.Limits.DeepSizeMaxEntries)
		if err != nil || estimate.SharedInodes != 0 || estimate.Bytes < 0 {
			report.MeasurementError = "post-prune store accounting is incomplete or shared"
		} else {
			report.StoreAfterBytes = &estimate.Bytes
		}
	}
	if runErr != nil {
		report.Status = "failed: " + runErr.Error()
	} else {
		report.Status = "completed"
	}
	if err := recordOfficialPrune(stateDir, report); err != nil {
		return fmt.Errorf("official command outcome uncertain; cannot journal result: %w", err)
	}
	if runErr != nil {
		return runErr
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
