package collect

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/exportarchive"
)

func collectEvidenceExports(ctx context.Context, opts *Options, entries []core.Entry, now time.Time) core.CollectorReport {
	type candidate struct {
		index     int
		path      string
		kind      core.EntryKind
		modified  time.Time
		protected bool
		rule      config.EvidenceExportRule
	}
	var candidates []candidate
	for i := range entries {
		original := entries[i].Path
		if source, ok := opts.WorktreeOrigins[original]; ok {
			original = source
		}
		for _, rule := range opts.WorktreePolicy.EvidenceExports {
			if original == rule.Path {
				protected := protectedExportPath(original, opts.WorktreePolicy)
				for _, protection := range entries[i].Protections {
					protected = protected || protection.Blocking
				}
				candidates = append(candidates, candidate{i, entries[i].Path, entries[i].Kind, entries[i].ModifiedAt, protected, rule})
			} else if core.PathWithin(rule.Path, original) {
				addProtection(&entries[i], core.Protection{Kind: core.ProtectDurableEvidence, Source: core.SourcePolicy, Blocking: true, Reason: "contains an owned evidence export; only an exact verified export may expire"})
			}
		}
	}
	refs, report := runBounded(ctx, opts, CollectorExports, func(ctx context.Context, _ *Options) ([]Reference, core.CollectorReport) {
		report := core.CollectorReport{Name: CollectorExports, Status: core.CollectorRan}
		refs := make([]Reference, 0, len(candidates))
		for _, item := range candidates {
			rule := item.rule
			ref := Reference{Path: item.path, Source: core.SourcePolicy, Protection: core.ProtectDurableEvidence, Signal: "evidence_export", Detail: "exact export remains retained"}
			switch {
			case ctx.Err() != nil:
				ref.Detail = "archive observation deadline expired"
			case item.protected:
				ref.Detail = "existing protection prevents inspecting or archiving this export"
			case item.kind != core.EntryKindFile:
				ref.Detail = "only ordinary regular export files are eligible; directories and symlinks remain protected"
			case rule.CompletedAt.IsZero() || rule.CompletedAt.After(now) || !rule.CredentialFree:
				ref.Detail = "owner completion or credential-free proof is missing or in the future"
			case item.modified.IsZero() || item.modified.After(rule.CompletedAt):
				ref.Detail = "export changed after verified completion; a new owner completion declaration is required"
			case opts.ArchiveCreationPath == item.path:
				ref.Protection = ""
				ref.Detail = "exact owner-approved export may be copied; existing protections still apply"
			case !rule.LocalExpiryEnabled || !rule.LocalRetention.Expired(rule.CompletedAt, now):
				ref.Detail = "local expiry is disabled or the verified-completion retention window has not elapsed"
			default:
				_, binding, err := exportarchive.Check(ctx, rule, item.path, opts.VerifyArchiveContents)
				if err != nil {
					ref.Detail = fmt.Sprintf("verified independent archive unavailable: %v", err)
				} else {
					ref.Protection = ""
					ref.ExportArchive = binding
					ref.Detail = "approved archive manifest and restore proof bind this exact export"
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
			addUnknown(&entries[item.index], core.SourcePolicy, core.ProtectDurableEvidence, "archive_observation", "archive evidence could not be observed completely", now)
			continue
		}
		entries[item.index].ExportArchive = ref.ExportArchive
		addEvidence(&entries[item.index], core.Evidence{Source: ref.Source, Signal: ref.Signal, Detail: ref.Detail, ObservedAt: now})
		if ref.Protection != "" {
			addProtection(&entries[item.index], core.Protection{Kind: ref.Protection, Source: ref.Source, Blocking: true, Reason: ref.Detail})
		}
		report.Recorded++
	}
	return report
}

func protectedExportPath(path string, policy *config.Policy) bool {
	for _, protected := range policy.Protect.Paths {
		if core.PathsOverlap(path, protected) {
			return true
		}
	}
	for part := range strings.SplitSeq(filepath.ToSlash(path), "/") {
		for _, pattern := range policy.Protect.NamePatterns {
			matched, err := filepath.Match(pattern, part)
			if err != nil || matched {
				return true
			}
		}
	}
	return false
}
