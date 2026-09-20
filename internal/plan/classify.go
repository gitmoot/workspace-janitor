// Package plan turns inventory evidence into deterministic, reviewable
// cleanup plans.
//
// Three rules shape it:
//
//   - Deterministic rules run first and alone. A model classifier is
//     consulted only for entries the rules could not decide, only after
//     they have run, and never in a way that can increase risk.
//   - Conflicts resolve to the safer action. Two rules that disagree cannot
//     produce a more destructive outcome than either would alone.
//   - Every recommendation is traceable. Each action records the rules that
//     contributed, the evidence behind them, and the alternatives rejected.
package plan

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Classification is the built-in class of an entry plus its justification.
type Classification struct {
	Class  core.ArtifactClass
	Rule   string
	Reason string
}

// Classify sorts an entry into one of the built-in classes.
//
// The order below is the precedence: the first match wins, so a path that
// is both a cache name and a project marker is treated as the more
// significant thing. Nothing here decides an action; classification only
// describes what a path appears to be.
func Classify(entry core.Entry, policy config.Policy) Classification {
	name := filepath.Base(entry.Path)
	rules := policy.Classification

	if matchAny(name, rules.EvidenceNames) {
		return Classification{core.ClassEvidence, "classify.evidence",
			fmt.Sprintf("%s matches a durable evidence name", name)}
	}
	if matchAny(name, rules.OperationalNames) {
		return Classification{core.ClassOperationalTool, "classify.operational",
			fmt.Sprintf("%s matches an operational tooling name", name)}
	}
	if matchAny(name, rules.BackupNames) {
		return Classification{core.ClassBackup, "classify.backup",
			fmt.Sprintf("%s matches a backup or archive name", name)}
	}
	if entry.Git != nil {
		if entry.Git.WorktreeOf != "" {
			return Classification{core.ClassTaskWorktree, "classify.git_worktree",
				fmt.Sprintf("linked Git worktree of %s", entry.Git.WorktreeOf)}
		}
		return Classification{core.ClassPrimaryProject, "classify.git_repository",
			"contains a Git repository"}
	}
	if matchAny(name, rules.WorktreeMarkers) {
		return Classification{core.ClassTaskWorktree, "classify.worktree_name",
			fmt.Sprintf("%s matches a task worktree name", name)}
	}
	if matchAny(name, rules.GeneratedNames) {
		return Classification{core.ClassGeneratedArtifact, "classify.generated",
			fmt.Sprintf("%s matches a generated artifact name", name)}
	}
	if matchAny(name, rules.CacheNames) {
		return Classification{core.ClassCache, "classify.cache_name",
			fmt.Sprintf("%s matches a cache name", name)}
	}
	if entry.Kind == core.EntryKindDirectory && hasProjectMarker(entry, rules.ProjectMarkers) {
		return Classification{core.ClassPrimaryProject, "classify.project_marker",
			"contains a project marker"}
	}
	return Classification{core.ClassUnknown, "classify.unknown",
		"no built-in classification matched"}
}

// hasProjectMarker reports whether a collector recorded a project marker
// for this entry. The planner reads evidence; it does not touch the disk.
func hasProjectMarker(entry core.Entry, markers []string) bool {
	for _, evidence := range entry.Evidence {
		if evidence.Signal != "project_marker" {
			continue
		}
		if matchAny(evidence.Detail, markers) {
			return true
		}
	}
	return false
}

// matchAny reports whether name matches any pattern. An invalid pattern
// never matches: policy validation rejects those, and silently treating one
// as a match would classify unrelated paths.
func matchAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if matched, err := filepath.Match(pattern, name); err == nil && matched {
			return true
		}
		// A literal directory name can also appear as a path segment, which
		// is how caches and build outputs are usually recognised.
		if !strings.ContainsAny(pattern, "*?[") && pattern == name {
			return true
		}
	}
	return false
}
