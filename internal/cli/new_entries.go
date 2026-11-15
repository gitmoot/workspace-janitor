package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// newEntriesLimit bounds the listed new root entries; the rest are counted.
const newEntriesLimit = 100

// newEntryProcessLimit bounds the process attributions kept per entry.
const newEntryProcessLimit = 8

// Attribution sources of a new root entry. None of them proves who created
// the entry: each is evidence of who owns, produced or works in it.
const (
	newEntryByPolicyOwner    = "policy_owner"
	newEntryByGitmootLedger  = "gitmoot_ledger"
	newEntryByLinkedWorktree = "linked_worktree"
	newEntryByOMPSession     = "omp_session_process"
	newEntryByProcess        = "process_cwd"
	newEntryByNone           = "none"
)

type newEntryAttribution struct {
	Source string `json:"source"`
	Value  string `json:"value"`
	Detail string `json:"detail,omitempty"`
}

type newRootEntry struct {
	Path string `json:"path"`
	Root string `json:"root"`
	// Type is dir, file, symlink, repo, worktree or special.
	Type string `json:"type"`
	// CreatedAt is the entry's birth time where the filesystem records one,
	// else its inode change time; CreatedAtSource says which.
	CreatedAt        *time.Time            `json:"created_at"`
	CreatedAtSource  string                `json:"created_at_source"`
	ApparentBytes    *int64                `json:"apparent_bytes"`
	SizeIsLowerBound bool                  `json:"size_is_lower_bound,omitempty"`
	Attributions     []newEntryAttribution `json:"attributions"`
}

// newEntriesReport lists the direct children of report_new_entries roots
// that the latest deep scan saw and its comparable predecessor did not.
type newEntriesReport struct {
	Status         string         `json:"status"`
	Roots          []string       `json:"roots"`
	ScanID         string         `json:"scan_id,omitempty"`
	PreviousScanID string         `json:"previous_scan_id,omitempty"`
	Total          int            `json:"total"`
	OmittedEntries int            `json:"omitted_entries"`
	Entries        []newRootEntry `json:"entries"`
	// Attribution reports what each attribution source could observe.
	Attribution []string `json:"attribution"`
	Limitations string   `json:"limitations"`
}

const newEntriesLimitations = "Entries are direct children absent by path from the comparable previous deep scan; nothing is listed without one. Attribution is best effort and does not prove who created an entry: owners entries are policy information, the Gitmoot ledger names roles of jobs/tasks whose worktree_path is exactly the entry, a linked worktree names its main repository, and processes are live working directories at report time. created_at is birth time where the filesystem records it, else inode change time, which later changes also move."

// buildNewEntries reports new direct children of the policy's
// report_new_entries roots against the growth comparison's baseline, or nil
// when no root opts in. Without a comparable baseline it lists nothing.
func buildNewEntries(ctx context.Context, policy config.Policy, pair store.InventoryPair, growth *inventoryGrowth) *newEntriesReport {
	roots := map[string]bool{}
	report := &newEntriesReport{Status: growth.Status, Roots: []string{}, Entries: []newRootEntry{}, Attribution: []string{}, Limitations: newEntriesLimitations}
	for _, root := range policy.Roots {
		if root.ReportNewEntries {
			roots[root.Path] = true
			report.Roots = append(report.Roots, root.Path)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	sort.Strings(report.Roots)
	if report.Status != "compared" {
		return report
	}
	// With no deep scan the comparison falls back to metadata-only scans,
	// which run often: a child would be new against minutes-old state.
	if !pair.Deep {
		report.Status = "no_comparable_deep_baseline"
		return report
	}
	report.ScanID, report.PreviousScanID = pair.Current.ID, pair.Previous.ID
	// An absent path in a bounded or failed walk is unobserved, not new.
	if !completeDiscovery(*pair.Previous) {
		report.Status = "previous_discovery_incomplete"
		return report
	}
	previous := make(map[string]bool)
	for i := range pair.PreviousEntries {
		if path := pair.PreviousEntries[i].Path; roots[filepath.Dir(path)] {
			previous[path] = true
		}
	}
	var fresh []*core.Entry
	for i := range pair.CurrentEntries {
		entry := &pair.CurrentEntries[i]
		if roots[filepath.Dir(entry.Path)] && !previous[entry.Path] {
			fresh = append(fresh, entry)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Path < fresh[j].Path })
	report.Total = len(fresh)
	if len(fresh) > newEntriesLimit {
		fresh = fresh[:newEntriesLimit]
	}
	report.OmittedEntries = report.Total - len(fresh)
	if len(fresh) == 0 {
		return report
	}
	index := make(map[string]int, len(fresh))
	paths := make([]string, len(fresh))
	for i, entry := range fresh {
		index[entry.Path], paths[i] = i, entry.Path
		row := newRootEntry{Path: entry.Path, Root: filepath.Dir(entry.Path), Type: newEntryType(entry), Attributions: []newEntryAttribution{}}
		row.CreatedAt, row.CreatedAtSource = entryCreatedAt(entry.Path, entry.FilesystemID)
		if entry.SizeBytes >= 0 && (entry.Kind == core.EntryKindFile || (entry.Kind == core.EntryKindDirectory && entry.SizeIsDeep)) {
			size := entry.SizeBytes
			row.ApparentBytes, row.SizeIsLowerBound = &size, entry.SizeIsLowerBound
		}
		if owner := resolveDecisionOwner(entry.Path, policy); owner.Owner != unassignedOwner {
			row.Attributions = append(row.Attributions, newEntryAttribution{Source: newEntryByPolicyOwner, Value: owner.Owner, Detail: owner.Source})
		}
		report.Entries = append(report.Entries, row)
	}
	owners, status, err := collect.GitmootOwners(ctx, policy.Gitmoot, paths, policy.Limits.MaxEntries, policy.Limits.CommandTimeout.Duration())
	if err != nil {
		report.Attribution = append(report.Attribution, "Gitmoot ledger unavailable: "+err.Error())
	} else {
		report.Attribution = append(report.Attribution, "Gitmoot ledger: "+status)
		for i := range report.Entries {
			row := &report.Entries[i]
			if owner, ok := owners[row.Path]; ok {
				role := owner.Role
				switch {
				case owner.Contested:
					role = "contested"
				case role == "":
					role = config.UnknownOwner
				}
				row.Attributions = append(row.Attributions, newEntryAttribution{Source: newEntryByGitmootLedger, Value: role, Detail: strings.Join(owner.Evidence, "; ")})
			}
		}
	}
	for i, entry := range fresh {
		if entry.Git != nil && entry.Git.WorktreeOf != "" {
			report.Entries[i].Attributions = append(report.Entries[i].Attributions, newEntryAttribution{Source: newEntryByLinkedWorktree, Value: entry.Git.WorktreeOf, Detail: "main repository of this linked Git worktree"})
		}
	}
	if !policy.Collectors.Processes {
		report.Attribution = append(report.Attribution, "processes: process collector disabled")
	} else {
		report.Attribution = append(report.Attribution, attributeNewEntryProcesses(ctx, policy, paths, index, report.Entries))
	}
	for i := range report.Entries {
		if len(report.Entries[i].Attributions) == 0 {
			report.Entries[i].Attributions = append(report.Entries[i].Attributions, newEntryAttribution{Source: newEntryByNone, Value: config.UnknownOwner})
		}
	}
	return report
}

func newEntryType(entry *core.Entry) string {
	switch {
	case entry.Kind == core.EntryKindSymlink:
		return "symlink"
	case entry.Git != nil && entry.Git.WorktreeOf != "":
		return "worktree"
	case entry.Git != nil:
		return "repo"
	case entry.Kind == core.EntryKindDirectory:
		return "dir"
	default:
		return string(entry.Kind)
	}
}

// attributeNewEntryProcesses adds, to each entry holding a live process's
// working directory, that process's OMP session directory or else its
// command name. It runs under the process collector's bounds and returns
// what it could inspect; a bounded or late observation is incomplete.
func attributeNewEntryProcesses(ctx context.Context, policy config.Policy, paths []string, index map[string]int, entries []newRootEntry) string {
	opts := collect.Options{Processes: true, ProcRoot: policy.Collectors.ProcRoot, Limits: collectLimits(policy, scanOptions{})}
	processes, observed := collect.ProcessWorkdirs(ctx, opts, paths)
	for _, process := range processes {
		at, ok := enclosingEntry(index, process.Cwd)
		if !ok {
			continue
		}
		attribution := newEntryAttribution{Source: newEntryByProcess, Value: process.Name, Detail: "pid " + process.PID + " cwd " + process.Cwd}
		if process.OMPSession != "" {
			attribution.Source, attribution.Value = newEntryByOMPSession, process.OMPSession
		}
		row := &entries[at]
		count, duplicate := 0, false
		for _, other := range row.Attributions {
			if other.Source == newEntryByOMPSession || other.Source == newEntryByProcess {
				count++
				duplicate = duplicate || (other.Source == attribution.Source && other.Value == attribution.Value)
			}
		}
		if !duplicate && count < newEntryProcessLimit {
			row.Attributions = append(row.Attributions, attribution)
		}
	}
	if observed.Status != core.CollectorRan {
		return fmt.Sprintf("processes: incomplete (%s): %s", observed.Status, observed.Detail)
	}
	return "processes: live working directories at report time; " + observed.Detail
}

// enclosingEntry is the index of the entry that is path or its nearest
// ancestor.
func enclosingEntry(index map[string]int, path string) (int, bool) {
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		if i, ok := index[dir]; ok {
			return i, true
		}
		if dir == filepath.Dir(dir) {
			return 0, false
		}
	}
}
