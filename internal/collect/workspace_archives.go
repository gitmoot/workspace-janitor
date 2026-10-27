package collect

import (
	"context"
	"fmt"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// collectWorkspaceArchives is the directory counterpart of
// collectEvidenceExports. A released workspace named by a rule stays retained
// behind a blocking durable-evidence protection unless local expiry is
// enabled, its pinned archive exactly matches the current local tree, and the
// local retention measured from the manifest's creation has elapsed. Only
// then does the entry carry a WorkspaceArchive binding. Mutation-time
// recollection sets VerifyArchiveContents, so the move and the expiry both
// re-hash the archive and the local tree, including a quarantined copy.
func collectWorkspaceArchives(ctx context.Context, opts *Options, entries []core.Entry, now time.Time) core.CollectorReport {
	type candidate struct {
		index     int
		path      string
		kind      core.EntryKind
		protected bool
		rule      config.WorkspaceArchiveRule
	}
	policy := opts.WorktreePolicy
	var candidates []candidate
	for i := range entries {
		original := entries[i].Path
		if source, ok := opts.WorktreeOrigins[original]; ok {
			original = source
		}
		for _, rule := range policy.WorkspaceArchives {
			if original != rule.Path {
				if core.PathWithin(rule.Path, original) {
					addProtection(&entries[i], core.Protection{Kind: core.ProtectDurableEvidence, Source: core.SourcePolicy, Blocking: true, Reason: "contains a released workspace; only its exact verified archive binding may expire it"})
				}
				continue
			}
			protected := protectedExportPath(original, policy)
			for _, protection := range entries[i].Protections {
				protected = protected || protection.Blocking
			}
			candidates = append(candidates, candidate{i, entries[i].Path, entries[i].Kind, protected, rule})
		}
	}
	refs, report := runBounded(ctx, opts, CollectorWorkspaceArchives, func(ctx context.Context, _ *Options) ([]Reference, core.CollectorReport) {
		report := core.CollectorReport{Name: CollectorWorkspaceArchives, Status: core.CollectorRan}
		refs := make([]Reference, 0, len(candidates))
		for _, item := range candidates {
			rule := item.rule
			ref := Reference{Path: item.path, Source: core.SourcePolicy, Protection: core.ProtectDurableEvidence, Signal: "workspace_archive", Detail: "released workspace remains retained"}
			switch {
			case ctx.Err() != nil:
				ref.Detail = "archive observation deadline expired"
			case item.protected:
				ref.Detail = "existing protection prevents binding or expiring this released workspace"
			case item.kind != core.EntryKindDirectory:
				ref.Detail = "only an ordinary released directory may expire; symlinks and other types remain protected"
			case !rule.LocalExpiryEnabled:
				ref.Detail = "local expiry is disabled; the released workspace remains retained"
			default:
				scope := workspacearchive.PolicyScope(*policy, rule)
				scope.ProcRoot = opts.ProcRoot
				binding, err := workspacearchive.Bind(ctx, rule, scope, item.path, opts.VerifyArchiveContents)
				switch {
				case err != nil:
					ref.Detail = fmt.Sprintf("verified workspace archive does not bind the local tree: %v", err)
				case !rule.LocalRetention.Expired(binding.CreatedAt, now):
					ref.Detail = "the local retention window measured from archive creation has not elapsed"
				default:
					ref.Protection = ""
					ref.WorkspaceArchive = binding
					ref.Detail = "pinned archive manifest exactly matches the local tree"
				}
			}
			refs = append(refs, ref)
		}
		return refs, report
	})
	byPath := make(map[string]Reference, len(refs))
	for _, ref := range refs {
		byPath[ref.Path] = ref
	}
	for _, item := range candidates {
		ref, ok := byPath[item.path]
		if !ok || report.Status != core.CollectorRan {
			addUnknown(&entries[item.index], core.SourcePolicy, core.ProtectDurableEvidence, "archive_observation", "workspace archive evidence could not be observed completely", now)
			continue
		}
		entries[item.index].WorkspaceArchive = ref.WorkspaceArchive
		addEvidence(&entries[item.index], core.Evidence{Source: ref.Source, Signal: ref.Signal, Detail: ref.Detail, ObservedAt: now})
		if ref.Protection != "" {
			addProtection(&entries[item.index], core.Protection{Kind: ref.Protection, Source: ref.Source, Blocking: true, Reason: ref.Detail})
		}
		report.Recorded++
	}
	return report
}
