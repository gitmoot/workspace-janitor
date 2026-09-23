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
	Mode      string    `json:"mode"`
	DryRun    bool      `json:"dry_run"`
	PlanID    string    `json:"plan_id"`
	ActionID  string    `json:"action_id"`
	Path      string    `json:"path"`
	Provider  string    `json:"provider"`
	Argv      []string  `json:"argv"`
	Timeout   string    `json:"timeout"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
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
	if !known || len(adapter.OfficialCommand) == 0 || (adapter.Provider != "uv" && adapter.Provider != "npm") {
		return fmt.Errorf("%s has no supported offline official prune", selected.Path)
	}
	if filepath.Base(rule.OfficialBinary) != adapter.Provider {
		return fmt.Errorf("official binary must be a configured %s executable", adapter.Provider)
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
	report.Status, report.Timestamp = "starting", time.Now().UTC()
	if err := recordOfficialPrune(stateDir, report); err != nil {
		return fmt.Errorf("cannot journal official prune: %w", err)
	}
	runErr := executeOfficialPrune(ctx, argv, policy.Limits.CommandTimeout.Duration())
	report.Timestamp = time.Now().UTC()
	if runErr != nil {
		report.Status = "failed: " + runErr.Error()
	} else {
		report.Status = "completed; reclaimed bytes unknown until rescan"
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
	return err
}

// executeOfficialPrune is platform-specific so Linux can terminate a whole
// subprocess group on timeout, not only the provider CLI's parent process.
