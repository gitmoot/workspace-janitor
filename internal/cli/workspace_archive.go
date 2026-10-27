package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// workspaceArchiveSummary reports a manifest without its member list, which
// can be far larger than a terminal report; the manifest file keeps it.
type workspaceArchiveSummary struct {
	Name           string                   `json:"name"`
	SourcePath     string                   `json:"source_path"`
	TarFile        string                   `json:"tar_file"`
	TarBytes       int64                    `json:"tar_bytes"`
	StreamSHA256   string                   `json:"stream_sha256"`
	ReadbackSHA256 string                   `json:"readback_sha256"`
	Members        int                      `json:"members"`
	ContentBytes   int64                    `json:"content_bytes"`
	MountSource    string                   `json:"mount_source"`
	FSType         string                   `json:"fstype"`
	Bundle         *workspacearchive.Bundle `json:"bundle,omitempty"`
	CreatedAt      time.Time                `json:"created_at"`
	VerifiedAt     time.Time                `json:"verified_at"`
}

type workspaceArchiveReport struct {
	Mode            string                       `json:"mode"`
	Workspace       string                       `json:"workspace"`
	Source          string                       `json:"source"`
	DryRun          bool                         `json:"dry_run"`
	Status          string                       `json:"status"`
	Inspection      *workspacearchive.Inspection `json:"inspection,omitempty"`
	Binding         *workspacearchive.Binding    `json:"binding,omitempty"`
	Manifest        *workspaceArchiveSummary     `json:"manifest,omitempty"`
	RestoredTo      string                       `json:"restored_to,omitempty"`
	LocalFreedBytes uint64                       `json:"local_freed_bytes"`
	SameFilesystem  bool                         `json:"same_filesystem_at_archive_creation"`
	Attribution     string                       `json:"attribution"`
	Activity        *core.CapacityActivity       `json:"activity,omitempty"`
}

func summarizeWorkspaceArchive(m workspacearchive.Manifest) *workspaceArchiveSummary {
	return &workspaceArchiveSummary{Name: m.Name, SourcePath: m.SourcePath, TarFile: m.TarFile, TarBytes: m.TarBytes,
		StreamSHA256: m.StreamSHA256, ReadbackSHA256: m.ReadbackSHA256, Members: len(m.Members), ContentBytes: m.ContentBytes,
		MountSource: m.MountSource, FSType: m.FSType, Bundle: m.Bundle, CreatedAt: m.CreatedAt, VerifiedAt: m.VerifiedAt}
}

// runWorkspaceArchive is the copy-only directory counterpart of runArchive.
// It never removes the source or an archive; local removal stays with
// quarantine and expiry. Active category archive items are listed under
// their synthesized names and may be verified or restored, never re-created.
func runWorkspaceArchive(ctx context.Context, e *env, opts archiveOptions, format output.Format, paths config.Paths, policy config.Policy) error {
	for _, rule := range policy.WorkspaceArchives {
		if rule.Name != opts.workspace {
			continue
		}
		if strings.HasPrefix(rule.Owner, config.CategoryOwnerPrefix) && !opts.verify && opts.restoreTo == "" {
			return errors.New("category archive items are created only by `janitor archive --categories`; use --verify or --restore-to with this name")
		}
		return runWorkspaceArchiveRule(ctx, e, opts, format, paths, policy, &rule)
	}
	return fmt.Errorf("no exact workspace archive rule %q", opts.workspace)
}

// runWorkspaceArchiveRule previews, creates, verifies or restores the archive
// of one workspace archive rule.
func runWorkspaceArchiveRule(ctx context.Context, e *env, opts archiveOptions, format output.Format, paths config.Paths, policy config.Policy, rule *config.WorkspaceArchiveRule) error {
	if core.PathsOverlap(rule.Archive.Directory, paths.StateDir) {
		return errors.New("workspace archive directory overlaps Janitor's state directory")
	}
	scope := workspacearchive.PolicyScope(policy, *rule)
	report := workspaceArchiveReport{Mode: "workspace_archive", Workspace: rule.Name, Source: rule.Path, DryRun: opts.dryRun, Status: "preview",
		Attribution: "Workspace archive creation copies data and frees no source bytes. Local removal remains with quarantine and expiry; archive storage on the same filesystem counts against eventual net recovery."}
	emit := func() error {
		if format == output.FormatJSON {
			return output.WriteJSON(e.stdout, report.Mode, report)
		}
		_, err := fmt.Fprintf(e.stdout, "mode: %s\nworkspace: %s\nsource: %s\nstatus: %s\nlocal freed bytes: %d\n%s\n", report.Mode, report.Workspace, report.Source, report.Status, report.LocalFreedBytes, report.Attribution)
		if err == nil && report.Binding != nil {
			_, err = fmt.Fprintf(e.stdout, "manifest: %s\nmanifest SHA256: %s\n", report.Binding.Manifest, report.Binding.ManifestSHA256)
		}
		if err == nil && report.RestoredTo != "" {
			_, err = fmt.Fprintf(e.stdout, "restored to: %s\n", report.RestoredTo)
		}
		return err
	}
	record := func(kind, path, sample string, run func() error) error {
		if err := config.EnsureDir(paths.StateDir); err != nil {
			return err
		}
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
		monitor, err := startCapacityActivity(ctx, db, kind, rule.Name, path, rule.Owner, sample, activityVolume)
		if err != nil {
			return err
		}
		report.Activity = &monitor.activity
		monitor.activity.Attempted = 1
		err = run()
		if err == nil {
			monitor.activity.Completed = 1
		}
		return monitor.finish(ctx, err)
	}
	if opts.verify || opts.restoreTo != "" {
		report.Mode = "workspace_archive_verify"
		m, binding, err := workspacearchive.Check(ctx, *rule, true)
		if err != nil {
			return err
		}
		report.Manifest, report.Binding, report.Status = summarizeWorkspaceArchive(m), binding, "verified"
		report.SameFilesystem = m.Source.Device == m.ArchiveDirectory.Device
		if opts.restoreTo != "" {
			report.Mode, report.RestoredTo, report.Status = "workspace_archive_restore", opts.restoreTo, "preview"
			if !opts.dryRun {
				if err := record("archive_restore", opts.restoreTo, filepath.Dir(opts.restoreTo), func() error {
					_, err := workspacearchive.Restore(ctx, *rule, opts.restoreTo)
					return err
				}); err != nil {
					return err
				}
				report.Status = "restored"
			}
		}
		return emit()
	}
	inspection, err := workspacearchive.Inspect(ctx, *rule, scope)
	if err != nil {
		return err
	}
	report.Inspection = &inspection
	if opts.dryRun {
		return emit()
	}
	// The policy is re-read from disk before and after the slow work: a KEEP
	// record, withdrawn release or changed rule added meanwhile refuses.
	preflight := func() error {
		current, err := config.LoadPolicy(paths)
		if err != nil {
			return fmt.Errorf("policy recheck refused workspace archive: %w", err)
		}
		for _, candidate := range current.WorkspaceArchives {
			if candidate.Name != rule.Name {
				continue
			}
			if workspacearchive.RuleHash(candidate) != workspacearchive.RuleHash(*rule) || candidate.Archive.Manifest != rule.Archive.Manifest {
				return errors.New("workspace archive rule changed during archiving; original retained")
			}
			return nil
		}
		return fmt.Errorf("workspace archive rule %q was withdrawn during archiving; original retained", rule.Name)
	}
	var m workspacearchive.Manifest
	var binding *workspacearchive.Binding
	if err = record("verified_archive", rule.Path, rule.Archive.Directory, func() error {
		var err error
		m, binding, err = workspacearchive.Create(ctx, *rule, scope, preflight)
		return err
	}); err != nil {
		return err
	}
	report.Manifest, report.Binding, report.Status = summarizeWorkspaceArchive(m), binding, "archived_and_readback_verified"
	report.SameFilesystem = m.Source.Device == m.ArchiveDirectory.Device
	report.Inspection = nil
	return emit()
}
