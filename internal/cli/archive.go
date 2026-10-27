package cli

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/exportarchive"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type archiveOptions struct {
	rule, workspace, restoreTo, categoryItem string
	verify, dryRun, confirm, categories      bool
}
type archiveReport struct {
	Mode                 string                     `json:"mode"`
	Rule                 string                     `json:"rule"`
	Source               string                     `json:"source"`
	DryRun               bool                       `json:"dry_run"`
	Status               string                     `json:"status"`
	Binding              *core.ExportArchiveBinding `json:"binding,omitempty"`
	Manifest             *exportarchive.Manifest    `json:"manifest,omitempty"`
	RestoredTo           string                     `json:"restored_to,omitempty"`
	LocalFreedBytes      uint64                     `json:"local_freed_bytes"`
	SameFilesystem       bool                       `json:"same_filesystem_at_archive_creation"`
	AvailableBeforeBytes *uint64                    `json:"available_before_bytes,omitempty"`
	AvailableAfterBytes  *uint64                    `json:"available_after_bytes,omitempty"`
	AvailableChangeBytes *int64                     `json:"available_change_bytes,omitempty"`
	Attribution          string                     `json:"attribution"`
	Activity             *core.CapacityActivity     `json:"activity,omitempty"`
}

func archiveCommand() *command {
	return &command{name: "archive", usage: "janitor archive (--rule NAME | --workspace NAME | --restore-category-item PATH | --categories) [--verify | --restore-to PATH] [--dry-run=false --confirm]", summary: "Archive or restore one approved evidence export, released workspace or category item, or archive owner-approved categories; never delete a source or archive", register: func(fs *flag.FlagSet) func(context.Context, *env, []string) error {
		opts := archiveOptions{}
		fs.StringVar(&opts.rule, "rule", "", "exact evidence_exports rule name")
		fs.StringVar(&opts.workspace, "workspace", "", "exact workspace_archives rule name (copy-only directory archive)")
		fs.BoolVar(&opts.categories, "categories", false, "select and archive idle items of every workspace_archive_categories entry (copy-only)")
		fs.StringVar(&opts.categoryItem, "restore-category-item", "", "original path of a category-archived item to verify or restore from its newest archive")
		fs.BoolVar(&opts.verify, "verify", false, "verify the pinned archive payload and restore integrity")
		fs.StringVar(&opts.restoreTo, "restore-to", "", "restore to a new, nonexisting absolute path")
		fs.BoolVar(&opts.dryRun, "dry-run", true, "preview without creating archive or restored files")
		fs.BoolVar(&opts.confirm, "confirm", false, "confirm archive creation or restoration")
		return func(ctx context.Context, e *env, args []string) error { return runArchive(ctx, e, args, opts) }
	}}
}

func runArchive(ctx context.Context, e *env, args []string, opts archiveOptions) error {
	modes := 0
	for _, selected := range []bool{opts.rule != "", opts.workspace != "", opts.categories, opts.categoryItem != ""} {
		if selected {
			modes++
		}
	}
	if len(args) != 0 || modes != 1 || (opts.verify && opts.restoreTo != "") {
		return &usageError{msg: "archive requires exactly one of --rule, --workspace, --categories or --restore-category-item and at most one of --verify or --restore-to"}
	}
	if opts.categories && (opts.verify || opts.restoreTo != "") {
		return &usageError{msg: "--categories only creates archives; verify or restore one item with --restore-category-item"}
	}
	if opts.categoryItem != "" && (!core.IsCanonicalPath(opts.categoryItem) || (!opts.verify && opts.restoreTo == "")) {
		return &usageError{msg: "--restore-category-item requires a canonical absolute path and --verify or --restore-to"}
	}
	if opts.restoreTo != "" && !core.IsCanonicalPath(opts.restoreTo) {
		return &usageError{msg: "--restore-to must be a canonical absolute path"}
	}
	if !opts.verify && !opts.dryRun && !opts.confirm {
		return &usageError{msg: "--confirm is required with --dry-run=false"}
	}
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy(ctx)
	if err != nil {
		return err
	}
	if opts.workspace != "" {
		return runWorkspaceArchive(ctx, e, opts, format, paths, policy)
	}
	if opts.categories {
		return runCategoryArchives(ctx, e, opts, format, paths)
	}
	if opts.categoryItem != "" {
		return runCategoryItemRestore(ctx, e, opts, format, paths, policy)
	}
	var rule *config.EvidenceExportRule
	for i := range policy.EvidenceExports {
		if policy.EvidenceExports[i].Name == opts.rule {
			rule = &policy.EvidenceExports[i]
			break
		}
	}
	if rule == nil {
		return fmt.Errorf("no exact evidence export rule %q", opts.rule)
	}
	bounded, cancel := context.WithTimeout(ctx, policy.Limits.CommandTimeout.Duration())
	defer cancel()
	report := archiveReport{Mode: "archive_export", Rule: rule.Name, Source: rule.Path, DryRun: opts.dryRun, Status: "preview", Attribution: "Archive creation copies data and frees no source bytes. Same-filesystem storage costs count against eventual net recovery; filesystem movement may include concurrent writers."}
	emit := func() error {
		if format == output.FormatJSON {
			return output.WriteJSON(e.stdout, report.Mode, report)
		}
		_, err := fmt.Fprintf(e.stdout, "mode: %s\nrule: %s\nsource: %s\nstatus: %s\nlocal freed bytes: %d\n%s\n", report.Mode, report.Rule, report.Source, report.Status, report.LocalFreedBytes, report.Attribution)
		if err == nil && report.Binding != nil {
			_, err = fmt.Fprintf(e.stdout, "manifest: %s\nmanifest SHA256: %s\n", report.Binding.Manifest, report.Binding.ManifestSHA256)
		}
		if err == nil && report.RestoredTo != "" {
			_, err = fmt.Fprintf(e.stdout, "restored to: %s\n", report.RestoredTo)
		}
		return err
	}
	if opts.verify || opts.restoreTo != "" {
		report.Mode = "archive_verify"
		m, binding, err := exportarchive.Check(bounded, *rule, "", true)
		if err != nil {
			return err
		}
		report.Manifest, report.Binding, report.Status = &m, binding, "verified"
		report.SameFilesystem = m.Source.Identity.Device == m.ArchiveDirectory.Device
		if opts.restoreTo != "" {
			report.Mode, report.RestoredTo, report.Status = "archive_restore", opts.restoreTo, "preview"
			if !opts.dryRun {
				unlock, err := lockApply(paths.StateDir)
				if err != nil {
					return err
				}
				defer unlock()
				db, err := store.Open(ctx, paths.DatabaseFile)
				if err != nil {
					return err
				}
				defer db.Close()
				monitor, err := startCapacityActivity(ctx, db, "archive_restore", rule.Name, opts.restoreTo, rule.Owner, filepath.Dir(opts.restoreTo), activityVolume)
				if err != nil {
					return err
				}
				report.Activity = &monitor.activity
				monitor.activity.Attempted = 1
				_, err = exportarchive.Restore(bounded, *rule, opts.restoreTo)
				if err == nil {
					monitor.activity.Completed = 1
				}
				if err := monitor.finish(ctx, err); err != nil {
					return err
				}
				report.Status = "restored"
			}
		}
		return emit()
	}
	if !opts.dryRun {
		unlock, err := lockApply(paths.StateDir)
		if err != nil {
			return err
		}
		defer unlock()
	}
	engine := cleanupEngine(e, nil, paths, policy)
	engine.Collect.ArchiveCreationPath = rule.Path
	options := engine.Collect
	options.Roots = []collect.RootSpec{{Path: filepath.Dir(rule.Path), MaxDepth: 1}}
	observed, err := collect.Run(bounded, options)
	if err != nil {
		return err
	}
	var entry *core.Entry
	for i := range observed.Entries {
		if observed.Entries[i].Path == rule.Path {
			entry = &observed.Entries[i]
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("export %s is absent from its exact inventory", rule.Path)
	}
	entry.Class = plan.Classify(*entry, policy).Class
	selected := core.Action{Path: entry.Path, Kind: core.ActionQuarantine, Class: entry.Class, Retention: rule.LocalRetention, Confidence: 1, FilesystemID: entry.FilesystemID, Fingerprint: entry.Fingerprint}
	preflight := func() error { return engine.PreflightExport(bounded, *entry, selected) }
	if err = preflight(); err != nil {
		return err
	}
	if opts.dryRun {
		return emit()
	}
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	monitor, err := startCapacityActivity(ctx, db, "verified_archive", rule.Name, rule.Path, rule.Owner, rule.Archive.Directory, activityVolume)
	if err != nil {
		return err
	}
	report.Activity = &monitor.activity
	monitor.activity.Attempted = 1
	m, binding, err := exportarchive.Create(bounded, *rule, *entry, preflight)
	if err == nil {
		monitor.activity.Completed = 1
	}
	if err := monitor.finish(ctx, err); err != nil {
		return err
	}
	report.Manifest, report.Binding, report.Status = &m, binding, "archived_and_restore_verified"
	report.SameFilesystem = m.Source.Identity.Device == m.ArchiveDirectory.Device
	report.AvailableBeforeBytes = monitor.activity.AvailableBeforeBytes
	report.AvailableAfterBytes = monitor.activity.AvailableAfterBytes
	report.AvailableChangeBytes = monitor.activity.AvailableChangeBytes
	return emit()
}
