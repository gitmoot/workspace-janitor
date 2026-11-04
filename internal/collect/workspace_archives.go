package collect

import (
	"context"
	"fmt"
	"slices"
	"strings"
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
			category := strings.HasPrefix(rule.Owner, config.CategoryOwnerPrefix)
			for _, protection := range entries[i].Protections {
				if category && protection.Kind == core.ProtectArchiveOnlyRoot {
					continue // lifted below only if the archive exactly binds
				}
				protected = protected || protection.Blocking
			}
			candidates = append(candidates, candidate{i, entries[i].Path, entries[i].Kind, protected, rule})
		}
	}
	refs, report := runBounded(ctx, opts, CollectorWorkspaceArchives, func(ctx context.Context, _ *Options) ([]Reference, core.CollectorReport) {
		report := core.CollectorReport{Name: CollectorWorkspaceArchives, Status: core.CollectorRan}
		refs := make([]Reference, 0, len(candidates))
		// The collector's result is dropped whole if it misses its deadline,
		// so stop starting binds at a budget short of it and answer the rest
		// as deferred (still protected). Each scan then binds what it can
		// and a later scan continues, instead of every scan timing out with
		// nothing bound (live 2026-11-04: 155 binds at ~0.6 s against 60 s).
		budgetCtx, cancelBudget := context.WithDeadline(ctx, bindingBudget(ctx))
		defer cancelBudget()
		deferred := 0
		// Category archives search every inventory root for dependents; one
		// snapshot walk serves all of them in this collection instead of one
		// bounded walk per item. Explicit rules keep their own walk.
		var categoryDependents *workspacearchive.DependentIndex
		for _, item := range candidates {
			rule := item.rule
			ref := Reference{Path: item.path, Source: core.SourcePolicy, Protection: core.ProtectDurableEvidence, Signal: "workspace_archive", Detail: "released workspace remains retained"}
			switch {
			case ctx.Err() != nil:
				ref.Detail = "archive observation deadline expired"
			case budgetCtx.Err() != nil && !item.protected:
				deferred++
				ref.Detail = "archive binding deferred: this scan's binding budget is spent; a later scan binds it"
			case item.protected:
				ref.Detail = "existing protection prevents binding or expiring this released workspace"
			case item.kind != core.EntryKindDirectory:
				ref.Detail = "only an ordinary released directory may expire; symlinks and other types remain protected"
			case !rule.LocalExpiryEnabled:
				ref.Detail = "local expiry is disabled; the released workspace remains retained"
			default:
				scope := workspacearchive.PolicyScope(*policy, rule)
				scope.ProcRoot = opts.ProcRoot
				if strings.HasPrefix(rule.Owner, config.CategoryOwnerPrefix) {
					if categoryDependents == nil {
						categoryDependents = workspacearchive.BuildDependentIndex(budgetCtx, scope.SearchRoots, policy.Limits.DependentIndexMaxEntries)
					}
					scope.Dependents = categoryDependents
				}
				if BeforeWorkspaceArchiveBind != nil {
					BeforeWorkspaceArchiveBind()
				}
				binding, err := workspacearchive.Bind(budgetCtx, rule, scope, item.path, opts.VerifyArchiveContents)
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
		if deferred > 0 {
			report.Detail = fmt.Sprintf("%d archive binding(s) deferred to a later scan by the binding budget", deferred)
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
		if ref.WorkspaceArchive != nil && strings.HasPrefix(item.rule.Owner, config.CategoryOwnerPrefix) {
			// An exact verified category archive is the one authority an
			// archive_only root accepts: lift that protection for this tree.
			entries[item.index].Protections = slices.DeleteFunc(entries[item.index].Protections, func(p core.Protection) bool {
				return p.Kind == core.ProtectArchiveOnlyRoot
			})
		}
		addEvidence(&entries[item.index], core.Evidence{Source: ref.Source, Signal: ref.Signal, Detail: ref.Detail, ObservedAt: now})
		if ref.Protection != "" {
			addProtection(&entries[item.index], core.Protection{Kind: ref.Protection, Source: ref.Source, Blocking: true, Reason: ref.Detail})
		}
		report.Recorded++
	}
	return report
}

// bindingBudget is when workspace archive binding stops starting new work:
// a fifth of the remaining collector time (at least 2 s, at most 15 s)
// before its deadline, so the collector publishes in time. A bind or index
// walk cut off by it fails, which refuses that tree, never binds it.
func bindingBudget(ctx context.Context) time.Time {
	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Now().Add(24 * time.Hour)
	}
	remaining := time.Until(deadline)
	margin := min(max(remaining/5, 2*time.Second), 15*time.Second, remaining/2)
	return deadline.Add(-margin)
}

// BeforeWorkspaceArchiveBind is a test seam called before each archive
// bind, so a test can make binding slow. Nil outside tests.
var BeforeWorkspaceArchiveBind func()
